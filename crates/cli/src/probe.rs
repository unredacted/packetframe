//! `packetframe probe` subcommand, one-shot XDP diagnostic.
//!
//! Purpose per SPEC.md §11.1(c): let operators answer "what does this
//! driver actually hand to XDP?" without editing and redeploying a
//! custom BPF program. Attaches `packetframe-probe`'s minimal XDP
//! program to the requested iface for `duration`, drains its ringbuf,
//! and prints the collected samples.
//!
//! The formatted output is deliberately plain text keyed on the first
//! 16 bytes of each sample, an operator scanning for `01 23 45 67 89
//! ab 0b 16 17 c8 52 01 08 00` (six dst MAC, six src MAC, Ethernet
//! type = IPv4) is the happy path; seeing a consistent 16-byte header
//! that doesn't match that shape is the §11.1(c) smoking gun.

use std::process::ExitCode;
use std::time::Duration;

use packetframe_probe::{AttachMode, ProbeError, ProbeEvent, ProbeOutput};

use crate::{EXIT_OK, EXIT_RUNTIME_ERROR, EXIT_STARTUP_ERROR};

/// Max samples to show in full detail in the per-packet table. Beyond
/// this, the summary statistics still reflect every sample; the table
/// just truncates. Picked so a 10-second probe on a typical mid-rate
/// iface (hundreds to low thousands pps) doesn't fill the terminal.
const MAX_TABLE_ROWS: usize = 64;

pub fn run(iface: String, mode: AttachMode, duration: Duration, offset: u16) -> ExitCode {
    match packetframe_probe::run(&iface, mode, duration, offset) {
        Ok(out) => {
            print_report(&iface, duration, &out);
            ExitCode::from(EXIT_OK)
        }
        Err(ProbeError::NoBpf) => {
            eprintln!(
                "packetframe probe: this build has no BPF object embedded. \
                 Install rustup + nightly + bpf-linker and rebuild, or use a \
                 binary produced by the CI/release pipeline."
            );
            ExitCode::from(EXIT_STARTUP_ERROR)
        }
        Err(ProbeError::Unsupported(msg)) => {
            eprintln!("packetframe probe: {msg}");
            ExitCode::from(EXIT_STARTUP_ERROR)
        }
        Err(e @ ProbeError::OffsetTooLarge { .. }) => {
            eprintln!("packetframe probe: {e}");
            ExitCode::from(EXIT_STARTUP_ERROR)
        }
        Err(ProbeError::Other(msg)) => {
            eprintln!("packetframe probe: {msg}");
            ExitCode::from(EXIT_RUNTIME_ERROR)
        }
    }
}

fn print_report(iface: &str, duration: Duration, out: &ProbeOutput) {
    println!(
        "PacketFrame probe on {iface} (mode={} offset={} duration={:?})",
        out.effective_mode.as_str(),
        out.offset,
        duration
    );
    println!("{} samples collected", out.samples.len());
    if out.samples.is_empty() {
        println!(
            "No traffic observed. If the iface is idle, bump --duration or \
             generate test traffic. If traffic is expected, the driver may \
             not be delivering frames to XDP at all."
        );
        return;
    }
    if !out.saw_traffic {
        println!("(ringbuf was empty throughout, duration exceeded packet arrival)");
    }

    println!();
    println!(
        "Per-packet head bytes (first {MAX_TABLE_ROWS} of {}):",
        out.samples.len()
    );
    println!("  #     t_ns_rel       len   head (16 bytes, hex)");
    let base_ts = out.samples[0].ts_ns;
    for (i, ev) in out.samples.iter().take(MAX_TABLE_ROWS).enumerate() {
        let rel_ns = ev.ts_ns.wrapping_sub(base_ts);
        println!(
            "  {:<5} {:>11}   {:>5}  {}",
            i,
            rel_ns,
            ev.pkt_len,
            format_head_hex(&ev.head),
        );
    }

    println!();
    println!("{}", summarize(&out.samples));
}

fn format_head_hex(head: &[u8; 16]) -> String {
    let mut s = String::with_capacity(16 * 3 + 2);
    for (i, b) in head.iter().enumerate() {
        if i == 6 || i == 12 {
            s.push(' '); // visual break at Ethernet field boundaries
        }
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Heuristic summary: tries to tell the operator in one line whether
/// the head bytes look like a standard Ethernet frame. False positives
/// are fine, the operator still has the raw bytes above to inspect.
/// False negatives would be worse, but given we only flag "definitely
/// looks like Ethernet" positively, the fallback is just "unknown"
/// which is the honest thing to say on a non-conformant driver.
fn summarize(samples: &[ProbeEvent]) -> String {
    if samples.is_empty() {
        return "No samples to summarise.".into();
    }

    let n = samples.len();

    // Count how many samples have a plausible Ethernet ethertype at
    // bytes 12..14, 0x0800 (IPv4), 0x86dd (IPv6), 0x8100 (802.1Q),
    // 0x88a8 (802.1ad), 0x0806 (ARP). If most samples match, the
    // driver is probably conformant. If almost none match, the first
    // 16 bytes likely include a descriptor prefix rather than the
    // Ethernet header, the §11.1(c) signature.
    let ethertype_plausible = samples
        .iter()
        .filter(|s| {
            matches!(
                u16::from_be_bytes([s.head[12], s.head[13]]),
                0x0800 | 0x86dd | 0x8100 | 0x88a8 | 0x0806
            )
        })
        .count();
    let pct = ethertype_plausible * 100 / n;

    // Common-prefix signature: every sample sharing a fixed first-k
    // bytes. On its own this is not descriptor evidence: ingress from
    // a single L2 neighbour repeats dst MAC, src MAC, ethertype and
    // often the first IP header bytes, so a conformant driver can share
    // all 16. It only corroborates a descriptor alongside implausible
    // ethertypes at [12..14].
    let common_prefix_len = common_prefix_len(samples);

    let mut lines = Vec::new();
    lines.push(format!(
        "Summary: {pct}% of samples have a plausible Ethernet ethertype at [12..14]"
    ));
    if pct >= 90 {
        lines.push(
            "  → head bytes look like a standard Ethernet frame; driver delivery is likely \
             conformant."
                .into(),
        );
    } else if pct <= 10 {
        lines.push(
            "  → head bytes DO NOT look like Ethernet. This matches the SPEC §11.1(c) signature \
             for a driver that prepends a descriptor prefix before the Ethernet header in native \
             XDP mode. Compare against a generic-mode run (`--mode generic`) to confirm."
                .into(),
        );
    } else {
        lines.push(
            "  → mixed. Inspect the per-packet rows above; traffic may include a mix of \
             protocols or the sampling window caught a transition."
                .into(),
        );
    }
    if common_prefix_len >= 8 && n >= 4 {
        let prefix = samples[0].head[..common_prefix_len]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        if pct <= 10 {
            lines.push(format!(
                "  Common {common_prefix_len}-byte prefix across all {n} samples: {prefix} \
                , with no plausible ethertype behind it; suggests a driver descriptor."
            ));
        } else if pct >= 90 {
            lines.push(format!(
                "  Common {common_prefix_len}-byte prefix across all {n} samples: {prefix} \
                , ethertypes look plausible, so this fits traffic from a single L2 neighbour \
                (fixed MACs) rather than a descriptor."
            ));
        } else {
            lines.push(format!(
                "  Common {common_prefix_len}-byte prefix across all {n} samples: {prefix} \
                ; with mixed ethertypes this is inconclusive, compare against `--mode generic`."
            ));
        }
    }

    lines.join("\n")
}

/// Length of the common byte prefix across every sample's `head`. 0 if
/// the first byte already differs; up to 16 if every sample is
/// identical.
fn common_prefix_len(samples: &[ProbeEvent]) -> usize {
    let Some(first) = samples.first() else {
        return 0;
    };
    for (i, &b) in first.head.iter().enumerate() {
        if !samples.iter().all(|s| s.head[i] == b) {
            return i;
        }
    }
    16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(head: [u8; 16]) -> ProbeEvent {
        ProbeEvent {
            ts_ns: 0,
            pkt_len: 64,
            head,
            _pad: [0; 4],
        }
    }

    #[test]
    fn single_neighbour_ipv4_is_not_flagged_as_descriptor() {
        // One neighbour: fixed dst/src MAC, ethertype 0x0800, IPv4
        // version/IHL 0x45 and DSCP 0, so the first 16 bytes match on
        // every frame. Only the total-length bytes that follow differ.
        let samples: Vec<_> = (0..8)
            .map(|_| {
                event([
                    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst MAC
                    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src MAC
                    0x08, 0x00, // IPv4
                    0x45, 0x00, // version/IHL, DSCP/ECN
                ])
            })
            .collect();
        let out = summarize(&samples);
        assert!(out.contains("100% of samples"), "{out}");
        assert!(out.contains("Common 16-byte prefix"), "{out}");
        assert!(!out.contains("suggests a driver descriptor"), "{out}");
        assert!(out.contains("single L2 neighbour"), "{out}");
    }

    #[test]
    fn fixed_prefix_with_mixed_ethertypes_stays_inconclusive() {
        // A descriptor-prefixed stream where one sample in four happens
        // to carry 0x0800 at [12..14]: neither verdict may be claimed.
        let samples: Vec<_> = (0u8..4)
            .map(|i| {
                let mut head = [
                    0xde, 0xad, 0xbe, 0xef, 0x00, 0x10, 0x00, 0x00, // descriptor
                    i, i, i, i, // varying
                    0x12, i, // implausible "ethertype"
                    i, i,
                ];
                if i == 0 {
                    head[12..14].copy_from_slice(&[0x08, 0x00]);
                }
                event(head)
            })
            .collect();
        let out = summarize(&samples);
        assert!(out.contains("Summary: 25% of samples"), "{out}");
        assert!(out.contains("Common 8-byte prefix"), "{out}");
        assert!(out.contains("inconclusive"), "{out}");
        assert!(!out.contains("suggests a driver descriptor"), "{out}");
        assert!(!out.contains("single L2 neighbour"), "{out}");
    }

    #[test]
    fn fixed_prefix_with_implausible_ethertypes_is_flagged() {
        // A driver descriptor: the first 8 bytes are constant, the rest
        // vary per packet and never land a plausible ethertype at
        // [12..14].
        let samples: Vec<_> = (0u8..8)
            .map(|i| {
                event([
                    0xde, 0xad, 0xbe, 0xef, 0x00, 0x10, 0x00, 0x00, // descriptor
                    i, i, i, i, // varying
                    0x12, i, // implausible "ethertype"
                    i, i,
                ])
            })
            .collect();
        let out = summarize(&samples);
        assert!(out.contains("Summary: 0% of samples"), "{out}");
        assert!(out.contains("Common 8-byte prefix"), "{out}");
        assert!(out.contains("suggests a driver descriptor."), "{out}");
    }
}
