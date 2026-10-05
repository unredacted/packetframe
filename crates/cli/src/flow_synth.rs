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
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, ValueEnum};
use packetframe_flow_encode::{
    flow_fields,
    ipfix::{self, Announce, PacketReport, PacketReporting, SelectionSequence, Selector},
    netflow9::{self, SamplerOptions},
    sflow::{self, Agent, Encoding, FlowSample},
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
    /// Length of every modelled Ethernet frame, FCS excluded (sFlow adds
    /// the 4 FCS octets to its on-wire length). At least 60.
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
    /// How long to send for; a part second sends that part's share.
    /// Stopping is the telemetry-loss test.
    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    duration: Duration,
    /// Print a line per second.
    #[arg(long)]
    verbose: bool,
}

/// Templates and options are re-announced this often (v9 and IPFIX over
/// UDP have no other way to reach a collector that started late), in a
/// message of their own when there is nothing else to send.
const ANNOUNCE_EVERY: Duration = Duration::from_secs(10);
/// Bytes of each frame carried as its header (sFlow, packet reports).
const HEADER_BYTES: usize = 128;
/// The smallest Ethernet frame, FCS excluded (64 octets on the wire).
const MIN_FRAME: u16 = 60;
/// Ethernet FCS octets: on the wire, never in a captured header.
const FCS: u16 = 4;
/// Every datagram fits this path MTU with its IP and UDP headers, so none
/// is fragmented on the way to the collector.
const PATH_MTU: usize = 1500;
const FLOW_TEMPLATE: u16 = 256;
const OPTIONS_TEMPLATE: u16 = 257;
const REPORT_TEMPLATE: u16 = 258;
const SEQUENCE_TEMPLATE: u16 = 259;
/// The one selector, and the one selection sequence (it, at the input
/// interface), that the modelled sampling uses.
const SELECTOR_ID: u64 = 1;
const SEQUENCE_ID: u64 = 1;

fn validate(args: &FlowSynthArgs) -> Result<(), String> {
    if args.sampling == 0 {
        return Err("--sampling must be >= 1".into());
    }
    if !matches!(args.protocol, 6 | 17) {
        return Err("--protocol must be 6 or 17".into());
    }
    if args.frame_size < MIN_FRAME {
        return Err(format!("--frame-size must be >= {MIN_FRAME}"));
    }
    Ok(())
}

pub fn run(args: FlowSynthArgs) -> ExitCode {
    if let Err(e) = validate(&args) {
        eprintln!("flow-synth: {e}");
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
    /// Largest UDP payload that fits [`PATH_MTU`] towards the collector.
    max_len: usize,
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
            max_len: PATH_MTU
                - 8
                - match args.to {
                    SocketAddr::V4(_) => 20,
                    SocketAddr::V6(_) => 40,
                },
            buf: Vec::with_capacity(PATH_MTU),
        }
    }

    fn rand(&mut self) -> u64 {
        // xorshift64*: deterministic enough for modelling, no dependency.
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn run(&mut self, args: &FlowSynthArgs, sock: &UdpSocket) -> io::Result<Totals> {
        let mut t = Totals::default();
        let mut start = Instant::now();
        let end = start + args.duration;
        let mut carry = 0;
        while start < end {
            let span = end.duration_since(start).min(Duration::from_secs(1));
            let n = samples_in(&mut carry, args.pps, span, args.sampling);
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
            let sent = self.send(args, sock, &pkts, start, span, announce)?;
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
            start += span;
            if let Some(wait) = start.checked_duration_since(Instant::now()) {
                sleep(wait);
            }
        }
        Ok(t)
    }

    /// Sends one span's samples; returns the datagrams sent.
    fn send(
        &mut self,
        a: &FlowSynthArgs,
        sock: &UdpSocket,
        pkts: &[Pkt],
        start: Instant,
        span: Duration,
        announce: bool,
    ) -> io::Result<u64> {
        match a.format {
            Format::Sflow => self.send_sflow(a, sock, pkts, start, span),
            Format::Psamp => self.send_psamp(a, sock, pkts, announce),
            Format::Nfv9 | Format::Ipfix => self.send_flows(a, sock, pkts, span, announce),
        }
    }

    /// sFlow sends samples through the span as they would be taken, each
    /// datagram as full as the path MTU allows.
    fn send_sflow(
        &mut self,
        a: &FlowSynthArgs,
        sock: &UdpSocket,
        pkts: &[Pkt],
        start: Instant,
        span: Duration,
    ) -> io::Result<u64> {
        let agent = Agent {
            address: IpAddr::V4(a.agent),
            sub_agent_id: 0,
            encoding: if a.input_if.max(a.output_if) >= sflow::COMPACT_IF_LIMIT {
                Encoding::Expanded
            } else {
                Encoding::Compact
            },
        };
        let headers: Vec<Vec<u8>> = pkts.iter().map(|p| frame_header(a, p)).collect();
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
                    frame_length: u32::from(a.frame_size + FCS),
                    stripped: u32::from(FCS),
                    header: h,
                }
            })
            .collect();
        let mut sent = 0;
        let mut done = 0;
        while done < samples.len() {
            self.sflow_seq = self.sflow_seq.wrapping_add(1);
            let uptime = self.boot.elapsed().as_millis() as u32;
            done += sflow::encode_datagram(
                &mut self.buf,
                &agent,
                self.sflow_seq,
                uptime,
                &samples[done..],
                self.max_len,
            )
            .map_err(io::Error::other)?;
            sock.send_to(&self.buf, a.to)?;
            sent += 1;
            // Spread the datagrams over the span by the samples they hold.
            let at = start + span.mul_f64(done as f64 / samples.len() as f64);
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
    ) -> io::Result<u64> {
        let sequences = [SelectionSequence {
            id: SEQUENCE_ID,
            ingress_if: a.input_if,
            selector_id: SELECTOR_ID,
        }];
        let headers: Vec<Vec<u8>> = pkts.iter().map(|p| frame_header(a, p)).collect();
        let now = epoch_ms();
        let reports: Vec<PacketReport<'_>> = headers
            .iter()
            .map(|h| PacketReport {
                selection_sequence_id: SEQUENCE_ID,
                selector_id: SELECTOR_ID,
                observation_ms: now,
                input_if: a.input_if,
                output_if: a.output_if,
                frame_size: a.frame_size,
                frame_section: h,
            })
            .collect();
        let mut sent = 0;
        let mut first = announce;
        let mut rest = &reports[..];
        // An announcing span sends even without reports, so the templates
        // reach the collector before the next report does.
        while first || !rest.is_empty() {
            let ann = if first {
                Announce {
                    templates: &[],
                    selector: Some(Selector {
                        template_id: OPTIONS_TEMPLATE,
                        selector_id: SELECTOR_ID,
                        interval: a.sampling,
                    }),
                    packet_reports: Some(PacketReporting {
                        template_id: REPORT_TEMPLATE,
                        sequence_template_id: SEQUENCE_TEMPLATE,
                        sequences: &sequences,
                    }),
                }
            } else {
                Announce::default()
            };
            first = false;
            let n = self
                .ipfix
                .encode_packet_reports(
                    &mut self.buf,
                    (now / 1000) as u32,
                    &ann,
                    REPORT_TEMPLATE,
                    rest,
                    self.max_len,
                )
                .map_err(io::Error::other)?;
            sock.send_to(&self.buf, a.to)?;
            sent += 1;
            rest = &rest[n..];
        }
        Ok(sent)
    }

    /// NetFlow v9 and IPFIX: the span's samples aggregated into one record
    /// per (source, destination port), as a flow cache fed by samples would
    /// export them at an active timeout of the span.
    fn send_flows(
        &mut self,
        a: &FlowSynthArgs,
        sock: &UdpSocket,
        pkts: &[Pkt],
        span: Duration,
        announce: bool,
    ) -> io::Result<u64> {
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
                octets: n * u64::from(a.frame_size - 14),
                start_ms: now.saturating_sub(span.as_millis() as u64),
                end_ms: now,
                sampling_interval: a.sampling,
            })
            .collect();

        let mut sent = 0;
        let mut first = announce;
        let mut rest = &records[..];
        // An announcing span sends even without records (see send_psamp).
        while first || !rest.is_empty() {
            let with_options = first && signal == SamplingSignal::Options;
            let n = match a.format {
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
                    self.nf9.encode(
                        &mut self.buf,
                        now,
                        templates,
                        sampler,
                        &t,
                        rest,
                        self.max_len,
                    )
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
                            selector_id: SELECTOR_ID,
                            interval: a.sampling,
                        }),
                        packet_reports: None,
                    };
                    self.ipfix.encode_flows(
                        &mut self.buf,
                        (now / 1000) as u32,
                        &ann,
                        &t,
                        rest,
                        self.max_len,
                    )
                }
            }
            .map_err(io::Error::other)?;
            first = false;
            sock.send_to(&self.buf, a.to)?;
            sent += 1;
            rest = &rest[n..];
        }
        Ok(sent)
    }
}

/// Samples a span of `pps` traffic yields at 1-in-`sampling`. `carry` keeps
/// the remainder, in packet-nanoseconds, for the next span, so part
/// seconds and rates below the sampling rate add up exactly over time.
fn samples_in(carry: &mut u128, pps: u64, span: Duration, sampling: u32) -> u64 {
    let per_sample = u128::from(sampling) * 1_000_000_000;
    *carry += u128::from(pps) * span.as_nanos();
    let n = *carry / per_sample;
    *carry %= per_sample;
    n as u64
}

/// The first [`HEADER_BYTES`] (or fewer) of a modelled frame: Ethernet,
/// IPv4, then UDP or a TCP SYN, zero payload, every checksum valid.
fn frame_header(a: &FlowSynthArgs, p: &Pkt) -> Vec<u8> {
    let frame = usize::from(a.frame_size); // >= MIN_FRAME, from validate()
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
    let csum = checksum(&h[ip_at..ip_at + 20]);
    h[ip_at + 10..ip_at + 12].copy_from_slice(&csum.to_be_bytes());

    let l4_at = h.len();
    let l4_len = ip_len - 20;
    h.extend_from_slice(&a.src_port.to_be_bytes());
    h.extend_from_slice(&p.dst_port.to_be_bytes());
    let csum_at = if a.protocol == 6 {
        // seq 1, ack 0, data offset 5, SYN, window 65535, checksum, urgent 0.
        h.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        l4_at + 16
    } else {
        h.extend_from_slice(&l4_len.to_be_bytes());
        h.extend_from_slice(&[0, 0]);
        l4_at + 6
    };
    let csum = l4_checksum(p.src, a.dst, a.protocol, l4_len, &h[l4_at..]);
    h[csum_at..csum_at + 2].copy_from_slice(&csum.to_be_bytes());
    h.resize(frame.min(HEADER_BYTES), 0);
    h
}

/// The TCP or UDP checksum (RFC 9293 §3.1, RFC 768) of a segment whose
/// header is `l4` and whose payload is `l4_len` less that of zeros: zeros
/// add nothing to the sum, so the header and the pseudo-header carry it.
fn l4_checksum(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, l4_len: u16, l4: &[u8]) -> u16 {
    let mut b = Vec::with_capacity(12 + l4.len());
    b.extend_from_slice(&src.octets());
    b.extend_from_slice(&dst.octets());
    b.extend_from_slice(&[0, protocol]);
    b.extend_from_slice(&l4_len.to_be_bytes());
    b.extend_from_slice(l4);
    match checksum(&b) {
        0 if protocol == 17 => 0xffff, // UDP sends a computed zero as all ones
        c => c,
    }
}

/// The Internet checksum (RFC 1071) of an even number of bytes.
fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = b
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

    fn args(extra: &[&str]) -> FlowSynthArgs {
        let mut v = vec!["x", "--to", "127.0.0.1:6343"];
        v.extend_from_slice(extra);
        Wrap::parse_from(v).args
    }

    fn pkt(dst_port: u16) -> Pkt {
        Pkt {
            src: Ipv4Addr::new(203, 0, 113, 9),
            dst_port,
        }
    }

    /// The pseudo-header and segment header sum to zero once the checksum
    /// is in place.
    fn l4_verifies(h: &[u8], protocol: u8, l4_len: u16) -> bool {
        let src = Ipv4Addr::new(h[26], h[27], h[28], h[29]);
        let dst = Ipv4Addr::new(h[30], h[31], h[32], h[33]);
        let l4_hdr = if protocol == 6 { 20 } else { 8 };
        let mut b = Vec::new();
        b.extend_from_slice(&src.octets());
        b.extend_from_slice(&dst.octets());
        b.extend_from_slice(&[0, protocol]);
        b.extend_from_slice(&l4_len.to_be_bytes());
        b.extend_from_slice(&h[34..34 + l4_hdr]);
        checksum(&b) == 0
    }

    #[test]
    fn header_is_a_valid_ipv4_udp_frame() {
        let h = frame_header(&args(&[]), &pkt(30001));
        assert_eq!(h.len(), HEADER_BYTES);
        assert_eq!(&h[12..14], &[0x08, 0x00]);
        assert_eq!(checksum(&h[14..34]), 0, "IPv4 checksum verifies");
        assert_eq!(u16::from_be_bytes([h[16], h[17]]), 1000 - 14);
        assert_eq!(&h[26..30], &[203, 0, 113, 9]);
        assert_eq!(&h[30..34], &[198, 51, 100, 10]);
        assert_eq!(u16::from_be_bytes([h[34], h[35]]), 53);
        assert_eq!(u16::from_be_bytes([h[36], h[37]]), 30001);
        assert_eq!(u16::from_be_bytes([h[38], h[39]]), 1000 - 14 - 20);
        assert_ne!(&h[40..42], &[0, 0], "UDP checksum present");
        assert!(l4_verifies(&h, 17, 1000 - 14 - 20));
    }

    #[test]
    fn tcp_syn_carries_a_valid_checksum() {
        for size in ["60", "1000"] {
            let a = args(&["--protocol", "6", "--frame-size", size]);
            let h = frame_header(&a, &pkt(443));
            let ip_len = u16::from_be_bytes([h[16], h[17]]);
            assert_eq!(usize::from(ip_len) + 14, size.parse::<usize>().unwrap());
            assert_eq!(h[47], 0x02, "SYN");
            assert_ne!(&h[50..52], &[0, 0], "TCP checksum present");
            assert!(l4_verifies(&h, 6, ip_len - 20), "frame size {size}");
        }
    }

    #[test]
    fn frames_below_the_ethernet_minimum_are_refused() {
        assert!(validate(&args(&["--frame-size", "59"])).is_err());
        assert!(validate(&args(&["--frame-size", "60", "--protocol", "6"])).is_ok());
        assert!(validate(&args(&["--sampling", "0"])).is_err());
        assert!(validate(&args(&["--protocol", "1"])).is_err());
    }

    #[test]
    fn part_seconds_send_their_share() {
        let half = Duration::from_millis(500);
        let mut carry = 0;
        assert_eq!(samples_in(&mut carry, 100_000, half, 1000), 50);
        let mut carry = 0;
        let n = samples_in(&mut carry, 100_000, Duration::from_secs(1), 1000)
            + samples_in(&mut carry, 100_000, half, 1000);
        assert_eq!(n, 150, "1.5 s");
        // Below the sampling rate, the remainder carries: 1 pps at 1-in-10.
        let mut carry = 0;
        let n: u64 = (0..30)
            .map(|_| samples_in(&mut carry, 1, Duration::from_secs(1), 10))
            .sum();
        assert_eq!(n, 3);
    }

    /// Sends one span and returns the datagrams the collector got.
    fn collect(format: &str, pkts: &[Pkt], announce: bool) -> Vec<Vec<u8>> {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let to = rx.local_addr().unwrap().to_string();
        let a = Wrap::parse_from(["x", "--to", &to, "--format", format]).args;
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut s = Synth::new(&a);
        let sent = s
            .send(&a, &tx, pkts, Instant::now(), Duration::ZERO, announce)
            .unwrap();
        let mut buf = [0u8; 65536];
        (0..sent)
            .map(|_| {
                let n = rx.recv(&mut buf).unwrap();
                buf[..n].to_vec()
            })
            .collect()
    }

    /// IPFIX set ids in a message.
    fn set_ids(m: &[u8]) -> Vec<u16> {
        let mut at = 16;
        let mut ids = Vec::new();
        while at < m.len() {
            ids.push(u16::from_be_bytes([m[at], m[at + 1]]));
            at += usize::from(u16::from_be_bytes([m[at + 2], m[at + 3]]));
        }
        ids
    }

    #[test]
    fn a_quiet_span_still_announces() {
        for format in ["psamp", "ipfix"] {
            let got = collect(format, &[], true);
            assert_eq!(got.len(), 1, "{format}");
            let ids = set_ids(&got[0]);
            assert!(ids.contains(&2), "{format}: template set in {ids:?}");
            assert!(collect(format, &[], false).is_empty(), "{format}");
        }
        let got = collect("psamp", &[], true);
        let ids = set_ids(&got[0]);
        assert!(
            ids.contains(&3) && ids.contains(&SEQUENCE_TEMPLATE),
            "{ids:?}"
        );
    }

    #[test]
    fn every_datagram_fits_the_path_mtu() {
        let pkts: Vec<Pkt> = (0..200).map(|i| pkt(30000 + i)).collect();
        for format in ["sflow", "psamp", "ipfix", "nfv9"] {
            let got = collect(format, &pkts, true);
            assert!(got.len() > 1, "{format}: split across datagrams");
            for d in &got {
                assert!(d.len() <= PATH_MTU - 20 - 8, "{format}: {} bytes", d.len());
            }
        }
    }
}
