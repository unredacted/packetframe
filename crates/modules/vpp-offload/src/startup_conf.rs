//! startup.conf rendering + memory arithmetic (plan v5, slice 1).
//!
//! **Route count is the independent variable.** The DFZ's size decides
//! VPP's main-heap requirement (mtrie + fib_entry_t + path-list +
//! adjacency objects), which decides the hugepage reservation — never
//! the other way around. A configured `hugepages` below the derived
//! minimum is a clean load-time error instead of a cryptic VPP init
//! abort.
//!
//! **The main heap is not the only thing that scales with route
//! count.** VPP keeps per-FIB-entry counters in a separate `statseg`
//! with its own fixed size, invisible to `show memory main-heap`. Gate
//! 0b established that the default 31.94 MiB segment is exhausted at
//! roughly 380k routes and VPP then aborts with a bare
//! `Out-of-memory, calling os_panic()` — while the main heap sits 87%
//! free, which points every diagnostic at the wrong allocator. Sizing
//! that omits the stats segment does not run VPP short; it kills it
//! partway through its first full-table resync.
//!
//! ## Measured, gate 0b item 10 (2026-08-03, shadow)
//!
//! 1,053,360 v4 prefixes from the live bird `master4`, loaded into
//! v26.06/octeon9 on a 4 GiB main heap:
//!
//! | | baseline | full table | per route |
//! |---|---|---|---|
//! | main heap (used) | 337.86 MiB | 803.49 MiB | **463 B** |
//! | stat segment (populated) | 1.19 MiB | 101.94 MiB | **97 B** |
//! | hugepages in use | 9 × 512 MiB | 10 × 512 MiB | — |
//!
//! Per-chunk increments ranged 82 B–2,058 B/route because mtrie
//! interior nodes allocate in blocks, so the full-table **average** is
//! the figure to size from — no single marginal is meaningful.
//!
//! The stats segment is sized from *populated* pages, not `used`: the
//! allocator reported 75.04 MiB used while the OS had backed 101.94
//! MiB. Sizing from `used` would under-provision by a third.
//!
//! Constants carry roughly 2× margin over measurement. Memory is the
//! cheapest resource here (64 GB), and the failure mode of being wrong
//! low is a mid-resync abort.

/// Main-heap bytes per installed route: mtrie nodes, `fib_entry`,
/// path-list, adjacency.
///
/// Measured **463 B** on the v4 table (see module docs). 1024 is ~2.2×
/// that. The previous value was 2,048 — a pre-measurement guess that
/// turned out ~4.4× high, which mattered only because it also implied
/// the stats segment was covered. It was not.
pub const HEAP_BYTES_PER_ROUTE: u64 = 1_024;

/// Fixed main-heap floor independent of table size: VPP's own
/// allocations, API rings, plugin overhead.
///
/// Measured **337.86 MiB** with an empty FIB. 512 MiB is ~1.5×. The
/// previous 1 GiB predates the measurement and did NOT cover the stats
/// segment despite claiming to.
pub const HEAP_FLOOR_BYTES: u64 = 512 << 20;

/// Hugepage-backed memory beyond the main heap: buffers, and whatever
/// else VPP maps on hugepages.
///
/// Measured as **1 GiB**: at full table, 10 × 512 MiB pages were in
/// use with a 4 GiB main heap declared — two pages beyond the heap's
/// eight. The previous 512 MiB would have left the reservation one page
/// short at full table.
pub const BUFFER_BYTES: u64 = 1 << 30;

/// Stats-segment bytes per installed route.
///
/// Measured **97 B/route** from populated pages. 192 is ~2×.
///
/// This term did not exist before gate 0b, and its absence is what
/// aborted VPP at ~380k routes on the default segment.
pub const STATSEG_BYTES_PER_ROUTE: u64 = 192;

/// Stats-segment floor. VPP's own counters exist before any route does,
/// and its own default is 32 MiB — no reason to go below that.
pub const STATSEG_FLOOR_BYTES: u64 = 32 << 20;

/// Derived sizing: what the config's `expected-routes` implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sizing {
    pub expected_routes: u64,
    pub main_heap_bytes: u64,
    /// The **hugepage** budget: main heap + buffers.
    ///
    /// Deliberately excludes the stats segment, which VPP backs with
    /// ordinary 64 K pages (verified at gate 0b) — counting it here
    /// would inflate the hugepage reservation by hundreds of MiB that
    /// hugepages never satisfy.
    pub total_bytes: u64,
    /// Stats-segment size. **Locked RAM, outside the hugepage
    /// reservation** — a separate budget line, not part of
    /// `total_bytes`.
    pub statseg_bytes: u64,
}

/// Compute the sizing from the route count. Errors on inputs that
/// would overflow or that are plainly nonsensical (0 is rejected at
/// parse; this guards the arithmetic itself).
pub fn derive_sizing(expected_routes: u64) -> Result<Sizing, String> {
    let table = expected_routes
        .checked_mul(HEAP_BYTES_PER_ROUTE)
        .ok_or_else(|| format!("expected-routes {expected_routes} overflows sizing math"))?;
    let main_heap_bytes = table
        .checked_add(HEAP_FLOOR_BYTES)
        .ok_or_else(|| "heap sizing overflow".to_string())?;
    let total_bytes = main_heap_bytes
        .checked_add(BUFFER_BYTES)
        .ok_or_else(|| "total sizing overflow".to_string())?;
    let statseg_bytes = expected_routes
        .checked_mul(STATSEG_BYTES_PER_ROUTE)
        .ok_or_else(|| "stats-segment sizing overflow".to_string())?
        .max(STATSEG_FLOOR_BYTES);
    Ok(Sizing {
        expected_routes,
        main_heap_bytes,
        total_bytes,
        statseg_bytes,
    })
}

/// Validate a configured hugepage count against the derived need.
/// `hugepage_bytes == 0` means the page size is unknown (non-Linux
/// hosts, unreadable meminfo): skip the byte comparison — feasibility
/// separately reports the platform state.
pub fn check_hugepage_budget(
    sizing: &Sizing,
    configured_pages: u32,
    hugepage_bytes: u64,
) -> Result<(), String> {
    if hugepage_bytes == 0 {
        return Ok(());
    }
    let configured = u64::from(configured_pages) * hugepage_bytes;
    if configured < sizing.total_bytes {
        let need_pages = sizing.total_bytes.div_ceil(hugepage_bytes);
        return Err(format!(
            "hugepages {configured_pages} ({} MiB at {} MiB pages) is below the minimum \
             derived from expected-routes {} ({} MiB needed: {} MiB heap + {} MiB buffers); \
             set `hugepages {need_pages}` or lower `expected-routes`",
            configured >> 20,
            hugepage_bytes >> 20,
            sizing.expected_routes,
            sizing.total_bytes >> 20,
            sizing.main_heap_bytes >> 20,
            BUFFER_BYTES >> 20,
        ));
    }
    Ok(())
}

/// One VPP dataplane port: the VF's PCI address plus the worker count
/// the operator promised for it.
///
/// Input to the **runtime attach step**, not to [`render`]. Before the
/// v7 driver pivot this was config: a `dpdk { dev <pci> }` stanza. The
/// native octeon driver takes device identity at runtime instead
/// (`dev_attach` with the PCI address, then `dev_create_port_if` with
/// the port number and `num_rx_queues`), which is the better shape
/// anyway — detach and reattach need no config rewrite, and the
/// supervisor can sequence attach inside its resync pipeline.
///
/// `cores` still means what it meant: the operator's promise, rendered
/// explicitly rather than left to the scheduler's round-robin default
/// (plan v5, "cores promises are honored by rendering explicit
/// rx-placement"). It now lands as `num_rx_queues` at attach.
#[derive(Debug, Clone)]
pub struct PortSpec {
    pub pci_addr: String,
    pub cores: u16,
}

/// Render startup.conf. Pure function of its inputs so the exact
/// bytes handed to VPP are unit-tested on host CI. `worker_cores` is
/// the explicit CPU list for VPP workers (the plan's core-map set B);
/// `api_socket`/`stats_socket` live under packetframe's runtime dir so
/// supervision and metrics know where to look without guessing.
///
/// **Devices are deliberately absent.** After the v7 driver pivot the
/// dataplane is VPP's native octeon driver, and devices attach at
/// RUNTIME (`dev_attach` → `dev_create_port_if` over the binary API)
/// rather than from a config stanza. There is no `dpdk {}` block
/// because the DPDK PMD path cannot allocate NPA buffers on this NIC
/// at any version, and no `devices {}` block either — an empty one is
/// a parse error, and a populated one would duplicate what the
/// supervisor attaches. That makes [`PortSpec`] input to the attach
/// step, not to this function.
///
/// Shape matches what actually came up on the shadow (runbook §2,
/// round 3). It is deliberately not "improved" beyond that: the one
/// tempting change — keeping `plugin default { disable }` and enabling
/// plugins explicitly — is untested against the native driver's
/// loading path, and deviating from a hardware-proven config on an
/// untested theory is how bring-up rounds get spent.
pub fn render(
    sizing: &Sizing,
    worker_cores: &[u16],
    main_core: u16,
    api_socket: &str,
    hugepage_bytes: u64,
) -> String {
    let mut out = String::with_capacity(2048);
    let workers = worker_cores
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");

    out.push_str("# Generated by packetframe vpp-offload — do not edit; the module\n");
    out.push_str("# re-renders on attach. Sizing derives from `expected-routes`.\n");
    out.push_str("unix {\n  nodaemon\n  log /var/log/packetframe/vpp.log\n  full-coredump\n");
    out.push_str(&format!("  cli-listen {api_socket}.cli\n"));
    out.push_str("}\n");
    out.push_str("api-segment { prefix packetframe-vpp }\n");
    out.push_str(&format!("socksvr {{ socket-name {api_socket} }}\n"));
    out.push_str(&format!(
        "cpu {{\n  main-core {main_core}\n  corelist-workers {workers}\n}}\n"
    ));
    // 64K-page kernel: state the page sizes explicitly rather than
    // letting VPP's init assume 4K-host defaults (plan v5 gate-0b
    // item; rendering it unconditionally is harmless on 4K hosts).
    // Ceiling, not truncation: the hugepage budget is checked against
    // the exact byte figure, so a floor-rounded MiB value would hand
    // VPP a smaller heap than the reservation advertises (the default
    // 1.4M-route sizing loses 384 KiB to `>> 20`). Always round up —
    // over-reserving is free, under-heaping is a runtime failure.
    out.push_str(&format!(
        "memory {{\n  main-heap-size {}M\n  main-heap-page-size default-hugepage\n}}\n",
        sizing.main_heap_bytes.div_ceil(1 << 20)
    ));
    let _ = hugepage_bytes; // recorded in the header comment path later; kept as input for stability
                            // The stats segment. NOT optional and NOT covered by
                            // main-heap-size: VPP keeps per-FIB-entry counters here, the
                            // default is 32 MiB, and gate 0b watched it exhaust at ~380k
                            // routes and abort the process with an OOM that named no
                            // segment. Emitting nothing here — which is what this
                            // renderer did before — means the first full-table resync
                            // kills VPP partway through.
                            //
                            // Ceiling for the same reason as the heap: a floor-rounded
                            // MiB value hands VPP less than the arithmetic promised.
    out.push_str(&format!(
        "statseg {{\n  size {}M\n}}\n",
        sizing.statseg_bytes.div_ceil(1 << 20)
    ));
    out.push_str("buffers {\n  buffers-per-numa 65536\n  default data-size 2048\n}\n");
    // dpdk_plugin OFF. Round 2 on the shadow established that both the
    // otx2 and cnxk PMDs hard-require NPA mempool ops that VPP's buffer
    // manager does not provide, so the DPDK path cannot allocate
    // buffers on this NIC at ANY version — leaving the plugin enabled
    // would only load a driver that cannot work and can bind the VF
    // out from under the native one.
    //
    // linux-cp also deliberately ABSENT: it cannot pair kernel-owned
    // PFs (plan v3 correction). Routes and neighbors arrive over the
    // binary API from the RouteController's VppSink.
    out.push_str("plugins {\n  plugin dpdk_plugin.so { disable }\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Routes measured at gate 0b, and what each heap actually used, so
    /// the constants can be checked against reality rather than against
    /// each other.
    const MEASURED_ROUTES: u64 = 1_053_360;
    const MEASURED_HEAP_USED: u64 = 803 * (1 << 20); // 803.49 MiB
    const MEASURED_STATSEG_POPULATED: u64 = 102 * (1 << 20); // 101.94 MiB

    #[test]
    fn sizing_scales_with_routes() {
        let small = derive_sizing(1_000).unwrap();
        let full = derive_sizing(1_400_000).unwrap();
        assert!(full.main_heap_bytes > small.main_heap_bytes);
        assert!(full.statseg_bytes > small.statseg_bytes);
        // Post-measurement band: 1.4M × 1 KiB + 512 MiB floor + 1 GiB
        // buffers ≈ 2.8 GiB. The pre-measurement arithmetic put this at
        // ~4.4 GiB off a 2 KiB/route guess.
        assert!(full.total_bytes > 2 << 30, "{}", full.total_bytes);
        assert!(full.total_bytes < 4 << 30, "{}", full.total_bytes);
    }

    /// The constants must cover what the hardware actually consumed,
    /// with margin — the point of measuring. Guards against a future
    /// "tidy up the constants" that quietly drops below reality.
    #[test]
    fn the_constants_cover_the_measured_full_table() {
        let s = derive_sizing(MEASURED_ROUTES).unwrap();
        assert!(
            s.main_heap_bytes > MEASURED_HEAP_USED,
            "derived heap {} must exceed the measured {MEASURED_HEAP_USED}",
            s.main_heap_bytes
        );
        assert!(
            s.statseg_bytes > MEASURED_STATSEG_POPULATED,
            "derived statseg {} must exceed the measured {MEASURED_STATSEG_POPULATED}",
            s.statseg_bytes
        );
        // And with real margin, not by a hair.
        assert!(s.main_heap_bytes >= MEASURED_HEAP_USED * 3 / 2);
        assert!(s.statseg_bytes >= MEASURED_STATSEG_POPULATED * 3 / 2);
    }

    /// The default `expected-routes` must cover the measured table plus
    /// DFZ growth — that is what the default is for.
    #[test]
    fn the_default_route_count_covers_the_measured_table() {
        // Both sides are constants, so this is checkable at compile
        // time — a default that stopped covering the measured table
        // should fail the build, not a test run.
        const { assert!(crate::DEFAULT_EXPECTED_ROUTES > MEASURED_ROUTES) };
        let s = derive_sizing(crate::DEFAULT_EXPECTED_ROUTES).unwrap();
        assert!(s.statseg_bytes > MEASURED_STATSEG_POPULATED);
        assert!(s.main_heap_bytes > MEASURED_HEAP_USED);
    }

    /// The stats segment is 64 K-backed locked RAM, not hugepages
    /// (verified at gate 0b). Folding it into the hugepage budget would
    /// demand hundreds of MiB of reservation that hugepages never
    /// satisfy.
    #[test]
    fn the_stats_segment_is_not_in_the_hugepage_budget() {
        let s = derive_sizing(1_600_000).unwrap();
        assert_eq!(s.total_bytes, s.main_heap_bytes + BUFFER_BYTES);
        assert!(s.statseg_bytes > 0);
        assert!(
            s.total_bytes < s.main_heap_bytes + BUFFER_BYTES + s.statseg_bytes,
            "statseg must not be counted in the hugepage total"
        );
    }

    #[test]
    fn the_stats_segment_respects_its_floor() {
        // A tiny table still needs VPP's own counters.
        let s = derive_sizing(1_000).unwrap();
        assert_eq!(s.statseg_bytes, STATSEG_FLOOR_BYTES);
        // A large one scales past it.
        let big = derive_sizing(1_600_000).unwrap();
        assert_eq!(big.statseg_bytes, 1_600_000 * STATSEG_BYTES_PER_ROUTE);
        assert!(big.statseg_bytes > STATSEG_FLOOR_BYTES);
    }

    #[test]
    fn hugepage_budget_enforced() {
        let sizing = derive_sizing(1_400_000).unwrap();
        let page = 512u64 << 20; // the EFG's 512 MiB default pages
                                 // 5 pages = 2.5 GiB: below the ~2.8 GiB need → rejected with
                                 // the corrective count in the message.
        let err = check_hugepage_budget(&sizing, 5, page).unwrap_err();
        assert!(err.contains("hugepages"), "{err}");
        // 6 pages = 3 GiB: enough.
        check_hugepage_budget(&sizing, 6, page).unwrap();
        // Unknown page size: byte check skipped.
        check_hugepage_budget(&sizing, 1, 0).unwrap();
    }

    #[test]
    fn render_is_deterministic_and_complete() {
        let sizing = derive_sizing(1_400_000).unwrap();
        let conf = render(
            &sizing,
            &[14, 15],
            13,
            "/run/packetframe/vpp/api.sock",
            512 << 20,
        );
        let again = render(
            &sizing,
            &[14, 15],
            13,
            "/run/packetframe/vpp/api.sock",
            512 << 20,
        );
        assert_eq!(conf, again, "renderer must be pure");
        assert!(conf.contains("corelist-workers 14,15"));
        assert!(conf.contains("main-heap-page-size default-hugepage"));
        assert!(
            !conf.contains("linux-cp") && !conf.contains("lcp"),
            "linux-cp must stay out (cannot pair kernel-owned PFs)"
        );
        // Heap renders in MiB, rounded UP so VPP never gets less than
        // the reservation promised.
        let rendered_mib = sizing.main_heap_bytes.div_ceil(1 << 20);
        assert!(conf.contains(&format!("main-heap-size {rendered_mib}M")));
        assert!(
            (rendered_mib << 20) >= sizing.main_heap_bytes,
            "rendered heap {rendered_mib} MiB must not be below the derived {} bytes",
            sizing.main_heap_bytes
        );
    }

    /// The stanza whose absence aborted VPP at ~380k routes. Asserted,
    /// not described — a renderer that silently stops emitting it looks
    /// fine until the first full-table resync dies.
    #[test]
    fn a_stats_segment_stanza_is_always_emitted() {
        for routes in [1_000u64, 1_053_360, 1_600_000] {
            let s = derive_sizing(routes).unwrap();
            let conf = render(&s, &[14], 13, "/run/packetframe/vpp/api.sock", 0);
            assert!(conf.contains("statseg {"), "routes={routes}:\n{conf}");
            let want = s.statseg_bytes.div_ceil(1 << 20);
            assert!(
                conf.contains(&format!("size {want}M")),
                "routes={routes} want size {want}M:\n{conf}"
            );
            // Never below VPP's own default, which is what the old
            // implicit behaviour gave us.
            assert!(want >= (STATSEG_FLOOR_BYTES >> 20));
        }
    }

    /// Rounding UP, for the same reason as the heap: a floor-rounded
    /// MiB value hands VPP less than the arithmetic promised, and the
    /// shortfall shows up as an OOM mid-resync.
    #[test]
    fn the_stats_segment_rounds_up_never_down() {
        // 1,000,001 × 192 = 192,000,192 B = 183.10… MiB
        let s = derive_sizing(1_000_001).unwrap();
        let mib = s.statseg_bytes.div_ceil(1 << 20);
        assert!(
            (mib << 20) >= s.statseg_bytes,
            "rendered {mib} MiB is below the derived {} bytes",
            s.statseg_bytes
        );
    }

    /// The v7 driver pivot, asserted rather than described. Round 2 on
    /// the shadow proved the DPDK PMD path cannot allocate NPA buffers
    /// on this NIC at any version, so a rendered `dpdk {}` stanza — or
    /// an enabled dpdk_plugin — is not a style question, it is a
    /// dataplane that will not come up.
    #[test]
    fn no_dpdk_and_no_device_stanzas() {
        let sizing = derive_sizing(1_000).unwrap();
        let conf = render(&sizing, &[14], 13, "/run/packetframe/vpp/api.sock", 0);

        assert!(
            conf.contains("plugin dpdk_plugin.so { disable }"),
            "dpdk_plugin must be disabled:\n{conf}"
        );
        assert!(
            !conf.contains("dpdk {"),
            "no dpdk stanza — the PMD cannot drive this NIC:\n{conf}"
        );
        // An empty `devices {}` is a VPP parse error, and a populated
        // one would duplicate what the supervisor attaches at runtime
        // over dev_attach/dev_create_port_if.
        assert!(
            !conf.contains("devices {"),
            "devices attach at runtime, not from config:\n{conf}"
        );
        // No PCI address may appear anywhere: device identity now
        // lives in the attach step, not the config file.
        assert!(
            !conf.contains("0002:"),
            "no device identity in startup.conf:\n{conf}"
        );
    }

    #[test]
    fn heap_render_never_rounds_below_derived() {
        // Sweep route counts that produce non-MiB-aligned heaps; the
        // rendered value must always cover the derived requirement.
        for routes in [1u64, 7, 1_399_999, 1_400_000, 1_400_001, 2_000_003] {
            let s = derive_sizing(routes).unwrap();
            let mib = s.main_heap_bytes.div_ceil(1 << 20);
            assert!(
                (mib << 20) >= s.main_heap_bytes,
                "routes={routes}: rendered {mib} MiB < derived {} bytes",
                s.main_heap_bytes
            );
        }
    }
}
