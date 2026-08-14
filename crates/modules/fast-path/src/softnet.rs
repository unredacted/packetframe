//! `/proc/net/softnet_stat` totals — the early warning for silent
//! generic-XDP TX drops.
//!
//! Found the hard way (2026-08-13, w12–w19 on the reference EFG):
//! under CPU pressure the kernel truncates NAPI polls
//! (`time_squeeze`), TX-completion reaping falls behind, the egress
//! ring fills, and `generic_xdp_tx()` drops redirected frames on a
//! stopped queue — with **no counter anywhere on a 5.15 kernel**
//! (per-device core-stats accounting for that path arrived in 5.18),
//! no qdisc visibility, and no tcpdump visibility in either
//! direction. `fwd_ok` keeps climbing because it counts redirect
//! *acceptance*, not delivery. The one kernel signal that moves in
//! step with the condition is `time_squeeze`, so the metrics exporter
//! ships it. Mechanism and triage:
//! `docs/runbooks/generic-mode-performance.md`, "Silent TX drops
//! under generic XDP".
//!
//! The parser is pure so it unit-tests on any host; only the `/proc`
//! read is Linux-gated.

/// Sums of the first three `/proc/net/softnet_stat` columns across
/// every CPU line. The columns have been stable since long before
/// 5.15: `processed`, `dropped`, `time_squeeze`, all cumulative
/// since boot, all hex.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SoftnetTotals {
    pub processed: u64,
    pub dropped: u64,
    pub time_squeeze: u64,
    /// Lines summed = online CPUs. Not exported; kept so a parse of
    /// the wrong file (0 lines) can't masquerade as a quiet host.
    pub cpus: usize,
}

/// Parse the full text of `/proc/net/softnet_stat`.
///
/// This is a system-boundary read, so it validates: any line that
/// does not start with three hex fields fails the whole parse rather
/// than contributing a partial sum — a sum over half the CPUs would
/// read as a counter going backwards after the format hiccup clears.
pub fn parse(text: &str) -> Result<SoftnetTotals, String> {
    let mut totals = SoftnetTotals::default();
    for (n, line) in text.lines().enumerate() {
        let mut fields = line.split_whitespace();
        let mut col = |name: &str| -> Result<u64, String> {
            let f = fields
                .next()
                .ok_or_else(|| format!("line {}: missing column {name}", n + 1))?;
            u64::from_str_radix(f, 16)
                .map_err(|e| format!("line {}: column {name} not hex ({e}): {f:?}", n + 1))
        };
        totals.processed = totals.processed.wrapping_add(col("processed")?);
        totals.dropped = totals.dropped.wrapping_add(col("dropped")?);
        totals.time_squeeze = totals.time_squeeze.wrapping_add(col("time_squeeze")?);
        totals.cpus += 1;
    }
    if totals.cpus == 0 {
        return Err("empty softnet_stat".into());
    }
    Ok(totals)
}

/// Read and parse `/proc/net/softnet_stat`.
#[cfg(target_os = "linux")]
pub fn from_proc() -> Result<SoftnetTotals, String> {
    let text = std::fs::read_to_string("/proc/net/softnet_stat")
        .map_err(|e| format!("read /proc/net/softnet_stat: {e}"))?;
    parse(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verbatim shape of a 5.15 softnet_stat (13 columns; the last is
    // the CPU index). Two CPUs, one with squeeze.
    const SAMPLE_5_15: &str = "\
00358f37 00000000 000049e0 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
0000000a 00000002 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001
";

    #[test]
    fn sums_across_cpu_lines() {
        let t = parse(SAMPLE_5_15).unwrap();
        assert_eq!(t.processed, 0x0035_8f37 + 0xa);
        assert_eq!(t.dropped, 2);
        assert_eq!(t.time_squeeze, 0x49e0 + 1);
        assert_eq!(t.cpus, 2);
    }

    #[test]
    fn short_columns_are_tolerated_beyond_the_first_three() {
        // Very old kernels print fewer trailing columns; only the
        // first three matter and only they are required.
        let t = parse("00000001 00000000 00000003\n").unwrap();
        assert_eq!(t.processed, 1);
        assert_eq!(t.time_squeeze, 3);
        assert_eq!(t.cpus, 1);
    }

    #[test]
    fn a_malformed_line_fails_the_whole_parse() {
        let bad = "00000001 00000000 00000003\nnot hex at all\n";
        let err = parse(bad).unwrap_err();
        assert!(err.contains("line 2"), "unexpected error: {err}");
    }

    #[test]
    fn a_truncated_line_fails_rather_than_partially_summing() {
        let err = parse("00000001 00000000\n").unwrap_err();
        assert!(err.contains("time_squeeze"), "unexpected error: {err}");
    }

    #[test]
    fn empty_input_is_an_error_not_a_quiet_host() {
        assert!(parse("").is_err());
    }
}
