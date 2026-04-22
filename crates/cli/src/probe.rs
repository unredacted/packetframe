//! `packetframe probe` subcommand — one-shot XDP diagnostic.
//!
//! Purpose per SPEC.md §11.1(c): let operators answer "what does this
//! driver actually hand to XDP?" without editing and redeploying a
//! custom BPF program. Attaches `packetframe-probe`'s minimal XDP
//! program to the requested iface for `duration`, drains its ringbuf,
//! and prints the collected samples.
//!
//! The formatted output is deliberately plain text keyed on the first
//! 16 bytes of each sample — an operator scanning for `01 23 45 67 89
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

pub fn run(iface: String, mode: AttachMode, duration: Duration) -> ExitCode {
    match packetframe_probe::run(&iface, mode, duration) {
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
        Err(ProbeError::Other(msg)) => {
            eprintln!("packetframe probe: {msg}");
            ExitCode::from(EXIT_RUNTIME_ERROR)
        }
    }
}

fn print_report(iface: &str, duration: Duration, out: &ProbeOutput) {
    println!(
        "PacketFrame probe on {iface} (mode={} duration={:?})",
        out.effective_mode.as_str(),
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
        println!("(ringbuf was empty throughout — duration exceeded packet arrival)");
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
/// are fine — the operator still has the raw bytes above to inspect.
/// False negatives would be worse, but given we only flag "definitely
/// looks like Ethernet" positively, the fallback is just "unknown" —
/// which is the honest thing to say on a non-conformant driver.
fn summarize(samples: &[ProbeEvent]) -> String {
    if samples.is_empty() {
        return "No samples to summarise.".into();
    }

    let n = samples.len();

    // Count how many samples have a plausible Ethernet ethertype at
    // bytes 12..14 — 0x0800 (IPv4), 0x86dd (IPv6), 0x8100 (802.1Q),
    // 0x88a8 (802.1ad), 0x0806 (ARP). If most samples match, the
    // driver is probably conformant. If almost none match, the first
    // 16 bytes likely include a descriptor prefix rather than the
    // Ethernet header — the §11.1(c) signature.
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

    // Check for a common-prefix signature: if all N samples share a
    // fixed first-k-bytes prefix, that prefix is almost certainly a
    // driver descriptor and not a variable MAC address — which would
    // differ per-flow. k of 8 is enough to distinguish (two hosts
    // rarely share the whole first 8 bytes of an Ethernet frame).
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
        lines.push(format!(
            "  Common {common_prefix_len}-byte prefix across all {n} samples: {prefix} \
             — unusual for real Ethernet (MACs would vary); suggests a driver descriptor."
        ));
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
