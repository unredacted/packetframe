//! Guard feasibility probes, grafted into `packetframe feasibility` by
//! the CLI (the `Module` trait has no feasibility method; free
//! functions are the established shape).
//!
//! All probes are **non-required**: feasibility informs, the module's
//! attach enforces (the vpp-offload precedent). A guard-specific
//! failure here should read as "attach will refuse and tell you why",
//! not "the host is infeasible".

use packetframe_common::probe::Capability;

/// Run the guard's feasibility probes for the configured interfaces.
pub fn run_feasibility_probes(ifaces: &[String]) -> Vec<Capability> {
    #[cfg(target_os = "linux")]
    {
        run(ifaces)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ifaces;
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn run(ifaces: &[String]) -> Vec<Capability> {
    use packetframe_common::probe::{kconfig_flag_set, read_kconfig};

    let mut caps = Vec::new();

    caps.push(if crate::GUARD_BPF_AVAILABLE {
        Capability::pass(
            "guard.bpf.embedded",
            format!("guard BPF ELF embedded ({} bytes)", crate::GUARD_BPF.len()),
            false,
        )
    } else {
        Capability::fail(
            "guard.bpf.embedded",
            "guard BPF ELF is an empty stub (built without the BPF toolchain); \
             attach will refuse",
            false,
        )
    });

    caps.push(match read_kconfig() {
        Ok(contents) => {
            let missing: Vec<&str> = ["CONFIG_NET_CLS_BPF", "CONFIG_NET_SCH_INGRESS"]
                .into_iter()
                .filter(|f| !kconfig_flag_set(&contents, f))
                .collect();
            if missing.is_empty() {
                Capability::pass(
                    "guard.kernel.cls_bpf",
                    "CONFIG_NET_CLS_BPF and CONFIG_NET_SCH_INGRESS present \
                     (clsact + cls_bpf available)",
                    false,
                )
            } else {
                Capability::fail(
                    "guard.kernel.cls_bpf",
                    format!("missing or disabled: {}", missing.join(", ")),
                    false,
                )
            }
        }
        Err(e) => Capability::unknown(
            "guard.kernel.cls_bpf",
            format!("could not read kernel config ({e}); attach will find out"),
            false,
        ),
    });

    for iface in ifaces {
        let sys = std::path::Path::new("/sys/class/net").join(iface);
        let name = format!("guard.iface.{iface}");
        if !sys.exists() {
            caps.push(Capability::fail(
                name,
                format!("{iface} does not exist under /sys/class/net"),
                false,
            ));
            continue;
        }
        match std::fs::read_to_string(sys.join("address")) {
            Ok(mac) => caps.push(Capability::pass(
                name,
                format!("exists, MAC {}", mac.trim()),
                false,
            )),
            Err(e) => caps.push(Capability::warn(
                name,
                format!("exists but MAC unreadable ({e}); foreign-src needs it at attach"),
                false,
            )),
        }
    }

    caps
}
