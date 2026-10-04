//! `packetframe flow-synth`: synthetic flow telemetry for collector testing.
//!
//! Sends what PacketFrame's flow export will send — sFlow v5 samples, NetFlow
//! v9 or IPFIX flows aggregated from samples, or IPFIX packet reports — for a
//! modelled stream of packets towards one destination, so a collector's
//! handling of each format can be checked against known numbers: does it
//! scale by the sampling rate exactly once, read AS numbers from the records,
//! cope with a record without a source address, and what does it do when the
//! telemetry stops (stop the tool).
//!
//! Development only (`dev-tools` feature) and deliberately low-rate: one
//! datagram per few milliseconds at most. It models load; it does not
//! generate it.

#![cfg(feature = "dev-tools")]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, ValueEnum};
use packetframe_flow_encode::{
    flow_fields,
    ipfix::{self, Announce, PacketReport, Selector},
    netflow9::{self, SamplerOptions},
    sflow::{self, Agent, FlowSample},
    Family, FlowRecord, Profile, SamplingSignal,
};

use crate::{parse_duration, EXIT_OK, EXIT_RUNTIME_ERROR, EXIT_STARTUP_ERROR};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Format {
    /// sFlow v5 flow samples with raw packet headers.
    Sflow,
    /// NetFlow v9 flows aggregated from samples, per second.
    Nfv9,
    /// IPFIX flows aggregated from samples, per second.
    Ipfix,
    /// IPFIX PSAMP packet reports, one per sample.
    Psamp,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ProfileArg {
    /// Source and destination addresses, ports and AS numbers.
    Full,
    /// Everything but the source address.
    NoSource,
    /// No addresses: AS numbers, ports and protocol.
    AsOnly,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SignalArg {
    /// Sampling interval in every flow record.
    InRecord,
    /// Sampling interval in an options record, none in flow records.
    Options,
}

#[derive(Args, Debug)]
pub struct FlowSynthArgs {
    /// Collector address.
    #[arg(long)]
    to: SocketAddr,
    #[arg(long, value_enum, default_value = "sflow")]
    format: Format,
    /// Which fields flow records carry (NetFlow v9 and IPFIX flows only).
    #[arg(long, value_enum, default_value = "full")]
    profile: ProfileArg,
    /// Where flow records carry the sampling rate (NetFlow v9 and IPFIX
    /// flows only).
    #[arg(long, value_enum, default_value = "in-record")]
    sampling_signal: SignalArg,
    /// 1-in-N packet sampling rate the telemetry reports.
    #[arg(long, default_value_t = 1000)]
    sampling: u32,
    /// Packets per second the telemetry represents, before sampling.
    #[arg(long, default_value_t = 100_000)]
    pps: u64,
    /// Destination of the modelled packets.
    #[arg(long, default_value = "198.51.100.10")]
    dst: Ipv4Addr,
    /// Sources are drawn from this /24.
    #[arg(long, default_value = "203.0.113.0")]
    src_net: Ipv4Addr,
    /// IP protocol: 17 (UDP) or 6 (TCP SYN).
    #[arg(long, default_value_t = 17)]
    protocol: u8,
    /// Source port of every packet (53 models DNS reflection).
    #[arg(long, default_value_t = 53)]
    src_port: u16,
    /// Destination ports are drawn from [dst-port, dst-port + 1023].
    #[arg(long, default_value_t = 30000)]
    dst_port: u16,
    /// Length of every modelled frame on the wire, in bytes.
    #[arg(long, default_value_t = 1000)]
    frame_size: u16,
    /// Origin AS reported for the sources (default: documentation range).
    #[arg(long, default_value_t = 64500)]
    src_as: u32,
    /// Origin AS reported for the destination.
    #[arg(long, default_value_t = 64501)]
    dst_as: u32,
    /// ifIndex the packets arrive on.
    #[arg(long, default_value_t = 3)]
    input_if: u32,
    /// ifIndex they leave by; 0 = unknown (ingress sampling).
    #[arg(long, default_value_t = 0)]
    output_if: u32,
    /// sFlow agent address.
    #[arg(long, default_value = "192.0.2.1")]
    agent: Ipv4Addr,
    /// How long to send for. Stopping is the telemetry-loss test.
    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    duration: Duration,
    /// Print a line per second.
    #[arg(long)]
    verbose: bool,
}

/// Templates and options are re-announced this often (v9 and IPFIX over
/// UDP have no other way to reach a collector that started late).
const ANNOUNCE_EVERY: Duration = Duration::from_secs(10);
/// Samples, flow records or packet reports per datagram.
const PER_DATAGRAM: usize = 10;
/// Bytes of each frame carried as its header (sFlow, packet reports).
const HEADER_BYTES: usize = 128;
const FLOW_TEMPLATE: u16 = 256;
const OPTIONS_TEMPLATE: u16 = 257;
const REPORT_TEMPLATE: u16 = 258;

pub fn run(args: FlowSynthArgs) -> ExitCode {
    if args.sampling == 0 || !matches!(args.protocol, 6 | 17) {
        eprintln!("flow-synth: --sampling must be >= 1 and --protocol 6 or 17");
        return ExitCode::from(EXIT_STARTUP_ERROR);
    }
    let bind: SocketAddr = match args.to {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    // Unconnected on purpose: a connected UDP socket turns the ICMP
    // port-unreachable of a collector that is down or restarting into an
    // error on the next send. Export never depends on the collector.
    let sock = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("flow-synth: socket to {}: {e}", args.to);
            return ExitCode::from(EXIT_STARTUP_ERROR);
        }
    };
    match Synth::new(&args).run(&args, &sock) {
        Ok(totals) => {
            println!(
                "flow-synth: sent {} samples ({} datagrams) representing {} packets to {}",
                totals.samples, totals.datagrams, totals.represented, args.to
            );
            ExitCode::from(EXIT_OK)
        }
        Err(e) => {
            eprintln!("flow-synth: send to {}: {e}", args.to);
            ExitCode::from(EXIT_RUNTIME_ERROR)
        }
    }
}

#[derive(Default)]
struct Totals {
    samples: u64,
    datagrams: u64,
    represented: u64,
}

/// One modelled sampled packet.
#[derive(Clone, Copy)]
struct Pkt {
    src: Ipv4Addr,
    dst_port: u16,
}

struct Synth {
    rng: u64,
    boot: Instant,
    sflow_seq: u32,
    sample_seq: u32,
    sample_pool: u32,
    nf9: netflow9::Exporter,
    ipfix: ipfix::Exporter,
    last_announce: Option<Instant>,
    buf: Vec<u8>,
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Synth {
    fn new(args: &FlowSynthArgs) -> Self {
        let boot_epoch_ms = epoch_ms();
        Self {
            rng: boot_epoch_ms | 1,
            boot: Instant::now(),
            sflow_seq: 0,
            sample_seq: 0,
            sample_pool: 0,
            nf9: netflow9::Exporter {
                source_id: args.input_if,
                sequence: 0,
                boot_epoch_ms,
            },
            ipfix: ipfix::Exporter {
                observation_domain_id: args.input_if,
                sequence: 0,
            },
            last_announce: None,
            buf: Vec::with_capacity(1500),
        }
    }

    fn rand(&mut self) -> u64 {
        // xorshift64*: deterministic enough for modelling, no dependency.
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn run(&mut self, args: &FlowSynthArgs, sock: &UdpSocket) -> std::io::Result<Totals> {
        let mut t = Totals::default();
        let end = Instant::now() + args.duration;
        let mut carry = 0u64; // represented packets not yet worth a sample
        let mut second = Instant::now();
        while second < end {
            carry += args.pps;
            let n = carry / u64::from(args.sampling);
            carry %= u64::from(args.sampling);
            let base = u32::from(args.src_net) & 0xffff_ff00;
            let pkts: Vec<Pkt> = (0..n)
                .map(|_| Pkt {
                    src: Ipv4Addr::from(base | (1 + self.rand() % 254) as u32),
                    dst_port: args.dst_port.wrapping_add((self.rand() % 1024) as u16),
                })
                .collect();

            let announce = self
                .last_announce
                .is_none_or(|at| at.elapsed() >= ANNOUNCE_EVERY);
            if announce {
                self.last_announce = Some(Instant::now());
            }
            let sent = match args.format {
                Format::Sflow => self.send_sflow(args, sock, &pkts, second)?,
                Format::Psamp => self.send_psamp(args, sock, &pkts, announce)?,
                Format::Nfv9 | Format::Ipfix => self.send_flows(args, sock, &pkts, announce)?,
            };
            t.samples += n;
            t.datagrams += sent;
            t.represented += n * u64::from(args.sampling);
            if args.verbose {
                println!(
                    "{:>5}s  {n} samples ({} packets)  {sent} datagrams",
                    self.boot.elapsed().as_secs(),
                    n * u64::from(args.sampling)
                );
            }
            second += Duration::from_secs(1);
            if let Some(wait) = second.checked_duration_since(Instant::now()) {
                sleep(wait);
            }
        }
        Ok(t)
    }

    /// sFlow sends samples through the second as they would be taken, a
    /// datagram per [`PER_DATAGRAM`] samples.
    fn send_sflow(
        &mut self,
        a: &FlowSynthArgs,
        sock: &UdpSocket,
        pkts: &[Pkt],
        second: Instant,
    ) -> std::io::Result<u64> {
        let chunks = pkts.chunks(PER_DATAGRAM).count().max(1) as u32;
        let agent = Agent {
            address: IpAddr::V4(a.agent),
            sub_agent_id: 0,
        };
        let mut sent = 0;
        for (i, chunk) in pkts.chunks(PER_DATAGRAM).enumerate() {
            let headers: Vec<Vec<u8>> = chunk.iter().map(|p| frame_header(a, p)).collect();
            let samples: Vec<FlowSample<'_>> = headers
                .iter()
                .map(|h| {
                    self.sample_seq = self.sample_seq.wrapping_add(1);
                    self.sample_pool = self.sample_pool.wrapping_add(a.sampling);
                    FlowSample {
                        sequence: self.sample_seq,
                        source_if: a.input_if,
                        sampling_rate: a.sampling,
                        sample_pool: self.sample_pool,
                        drops: 0,
                        input_if: a.input_if,
                        output_if: a.output_if,
                        frame_length: u32::from(a.frame_size),
                        header: h,
                    }
                })
                .collect();
            self.sflow_seq = self.sflow_seq.wrapping_add(1);
            let uptime = self.boot.elapsed().as_millis() as u32;
            sflow::encode_datagram(&mut self.buf, &agent, self.sflow_seq, uptime, &samples);
            sock.send_to(&self.buf, a.to)?;
            sent += 1;
            // Spread the datagrams over the second.
            let at = second + Duration::from_secs(1) * (i as u32 + 1) / chunks;
            if let Some(wait) = at.checked_duration_since(Instant::now()) {
                sleep(wait);
            }
        }
        Ok(sent)
    }

    fn send_psamp(
        &mut self,
        a: &FlowSynthArgs,
        sock: &UdpSocket,
        pkts: &[Pkt],
        announce: bool,
    ) -> std::io::Result<u64> {
        let selector = Selector {
            template_id: OPTIONS_TEMPLATE,
            selector_id: 1,
            interval: a.sampling,
        };
        let mut sent = 0;
        let mut first = announce;
        let headers: Vec<Vec<u8>> = pkts.iter().map(|p| frame_header(a, p)).collect();
        let now = epoch_ms();
        let reports: Vec<PacketReport<'_>> = headers
            .iter()
            .map(|h| PacketReport {
                selector_id: 1,
                observation_ms: now,
                input_if: a.input_if,
                output_if: a.output_if,
                frame_size: a.frame_size,
                frame_section: h,
            })
            .collect();
        for chunk in reports.chunks(PER_DATAGRAM) {
            let ann = if first {
                Announce {
                    templates: &[],
                    selector: Some(selector),
                    packet_report_template: Some(REPORT_TEMPLATE),
                }
            } else {
                Announce::default()
            };
            first = false;
            self.ipfix.encode_packet_reports(
                &mut self.buf,
                (now / 1000) as u32,
                &ann,
                REPORT_TEMPLATE,
                chunk,
            );
            sock.send_to(&self.buf, a.to)?;
            sent += 1;
        }
        Ok(sent)
    }

    /// NetFlow v9 and IPFIX: the second's samples aggregated into one record
    /// per (source, destination port), as a flow cache fed by samples would
    /// export them at a one-second active timeout.
    fn send_flows(
        &mut self,
        a: &FlowSynthArgs,
        sock: &UdpSocket,
        pkts: &[Pkt],
        announce: bool,
    ) -> std::io::Result<u64> {
        let profile = match a.profile {
            ProfileArg::Full => Profile::Full,
            ProfileArg::NoSource => Profile::NoSource,
            ProfileArg::AsOnly => Profile::AsOnly,
        };
        let signal = match a.sampling_signal {
            SignalArg::InRecord => SamplingSignal::InRecord,
            SignalArg::Options => SamplingSignal::Options,
        };
        let fields = flow_fields(Family::V4, profile, signal);
        let now = epoch_ms();
        let mut flows: BTreeMap<(Ipv4Addr, u16), u64> = BTreeMap::new();
        for p in pkts {
            *flows.entry((p.src, p.dst_port)).or_default() += 1;
        }
        let records: Vec<FlowRecord> = flows
            .into_iter()
            .map(|((src, dport), n)| FlowRecord {
                src: IpAddr::V4(src),
                dst: IpAddr::V4(a.dst),
                protocol: a.protocol,
                src_port: a.src_port,
                dst_port: dport,
                input_if: a.input_if,
                output_if: a.output_if,
                src_as: a.src_as,
                dst_as: a.dst_as,
                packets: n,
                // IP-layer octets, header included (RFC 5102 octetDeltaCount;
                // v9's IN_BYTES likewise): the frame less its Ethernet header,
                // which is also what collectors derive from sFlow headers.
                octets: n * u64::from(a.frame_size.saturating_sub(14)),
                start_ms: now.saturating_sub(1000),
                end_ms: now,
                sampling_interval: a.sampling,
            })
            .collect();

        let mut sent = 0;
        let mut first = announce;
        let chunks: Vec<&[FlowRecord]> = if records.is_empty() && announce {
            vec![&[]] // still announce templates on a quiet second
        } else {
            records.chunks(PER_DATAGRAM).collect()
        };
        for chunk in chunks {
            let with_options = first && signal == SamplingSignal::Options;
            match a.format {
                Format::Nfv9 => {
                    let t = netflow9::Template {
                        id: FLOW_TEMPLATE,
                        fields: &fields,
                    };
                    let templates = if first { std::slice::from_ref(&t) } else { &[] };
                    let sampler = with_options.then_some(SamplerOptions {
                        template_id: OPTIONS_TEMPLATE,
                        interval: a.sampling,
                    });
                    self.nf9
                        .encode(&mut self.buf, now, templates, sampler, &t, chunk);
                }
                _ => {
                    let t = ipfix::Template {
                        id: FLOW_TEMPLATE,
                        fields: &fields,
                    };
                    let ann = Announce {
                        templates: if first { std::slice::from_ref(&t) } else { &[] },
                        selector: with_options.then_some(Selector {
                            template_id: OPTIONS_TEMPLATE,
                            selector_id: 1,
                            interval: a.sampling,
                        }),
                        packet_report_template: None,
                    };
                    self.ipfix
                        .encode_flows(&mut self.buf, (now / 1000) as u32, &ann, &t, chunk);
                }
            }
            first = false;
            sock.send_to(&self.buf, a.to)?;
            sent += 1;
        }
        Ok(sent)
    }
}

/// The first [`HEADER_BYTES`] (or fewer) of a modelled frame: Ethernet,
/// IPv4, then UDP or a TCP SYN, zero payload.
fn frame_header(a: &FlowSynthArgs, p: &Pkt) -> Vec<u8> {
    let frame = usize::from(a.frame_size).max(64);
    let mut h = Vec::with_capacity(HEADER_BYTES);
    h.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // dst MAC
    h.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // src MAC
    h.extend_from_slice(&0x0800u16.to_be_bytes());
    let ip_len = (frame - 14) as u16;
    let ip_at = h.len();
    h.extend_from_slice(&[0x45, 0]);
    h.extend_from_slice(&ip_len.to_be_bytes());
    h.extend_from_slice(&[0, 0, 0x40, 0, 64, a.protocol, 0, 0]);
    h.extend_from_slice(&p.src.octets());
    h.extend_from_slice(&a.dst.octets());
    let csum = ipv4_checksum(&h[ip_at..ip_at + 20]);
    h[ip_at + 10..ip_at + 12].copy_from_slice(&csum.to_be_bytes());
    h.extend_from_slice(&a.src_port.to_be_bytes());
    h.extend_from_slice(&p.dst_port.to_be_bytes());
    if a.protocol == 6 {
        h.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
    } else {
        h.extend_from_slice(&(ip_len - 20).to_be_bytes());
        h.extend_from_slice(&[0, 0]);
    }
    h.resize(frame.min(HEADER_BYTES), 0);
    h
}

fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = hdr
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrap {
        #[command(flatten)]
        args: FlowSynthArgs,
    }

    #[test]
    fn header_is_a_valid_ipv4_udp_frame() {
        let w = Wrap::parse_from(["x", "--to", "127.0.0.1:6343"]);
        let p = Pkt {
            src: Ipv4Addr::new(203, 0, 113, 9),
            dst_port: 30001,
        };
        let h = frame_header(&w.args, &p);
        assert_eq!(h.len(), HEADER_BYTES);
        assert_eq!(&h[12..14], &[0x08, 0x00]);
        assert_eq!(ipv4_checksum(&h[14..34]), 0, "checksum verifies");
        assert_eq!(u16::from_be_bytes([h[16], h[17]]), 1000 - 14);
        assert_eq!(&h[26..30], &[203, 0, 113, 9]);
        assert_eq!(&h[30..34], &[198, 51, 100, 10]);
        assert_eq!(u16::from_be_bytes([h[34], h[35]]), 53);
        assert_eq!(u16::from_be_bytes([h[36], h[37]]), 30001);
    }
}
