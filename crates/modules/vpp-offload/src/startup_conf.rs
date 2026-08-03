//! startup.conf rendering + memory arithmetic (plan v5, slice 1).
//!
//! **Route count is the independent variable.** The DFZ's size decides
//! VPP's main-heap requirement (mtrie + fib_entry_t + path-list +
//! adjacency objects), which decides the hugepage reservation — never
//! the other way around. A configured `hugepages` below the derived
//! minimum is a clean load-time error instead of a cryptic VPP init
//! abort.
//!
//! The per-route constant below is a deliberately generous
//! **pre-measurement placeholder**: gate 0b loads a real table into a
//! real VPP and replaces it with the measured number (plan: "measure
//! actual heap consumption at gate 0b rather than trusting anyone's
//! rule of thumb"). Memory is the cheapest resource on the reference
//! platform (64 GB); headroom errs large.

/// Estimated main-heap bytes per installed route (v4/v6 blended),
/// covering mtrie nodes, fib_entry, path-list sharing, adjacencies.
/// Generous by design; replaced by the gate-0b measurement.
pub const HEAP_BYTES_PER_ROUTE: u64 = 2_048;

/// Fixed main-heap floor independent of table size: VPP's own
/// allocations, stats segment, API rings, plugin overhead.
pub const HEAP_FLOOR_BYTES: u64 = 1 << 30; // 1 GiB

/// Buffer memory independent of the main heap (buffers-per-numa ×
/// ~2.5 KB each, plus descriptor overhead). One conservative number
/// until gate 0b measures per-port needs.
pub const BUFFER_BYTES: u64 = 512 << 20; // 512 MiB

/// Derived sizing: what the config's `expected-routes` implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sizing {
    pub expected_routes: u64,
    pub main_heap_bytes: u64,
    pub total_bytes: u64,
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
    Ok(Sizing {
        expected_routes,
        main_heap_bytes,
        total_bytes,
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

    #[test]
    fn sizing_scales_with_routes() {
        let small = derive_sizing(1_000).unwrap();
        let full = derive_sizing(1_400_000).unwrap();
        assert!(full.main_heap_bytes > small.main_heap_bytes);
        // The default full-table sizing lands in the plan's "couple of
        // GB" band: floor + ~2.9G table + buffers ≈ 4.4 GiB total.
        assert!(full.total_bytes > 3 << 30, "{}", full.total_bytes);
        assert!(full.total_bytes < 8 << 30, "{}", full.total_bytes);
    }

    #[test]
    fn hugepage_budget_enforced() {
        let sizing = derive_sizing(1_400_000).unwrap();
        let page = 512u64 << 20; // the EFG's 512 MiB default pages
                                 // 8 pages = 4 GiB: below the ~4.4 GiB need → rejected with the
                                 // corrective count in the message.
        let err = check_hugepage_budget(&sizing, 8, page).unwrap_err();
        assert!(err.contains("hugepages"), "{err}");
        // 10 pages = 5 GiB: enough.
        check_hugepage_budget(&sizing, 10, page).unwrap();
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
