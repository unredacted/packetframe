//! B3 v1: the bridge-FDB tripwire for `local-route` port declarations.
//!
//! A `local-route` names THE member port a service VLAN's hosts sit
//! behind, and B1's attached route delivers every packet for the
//! prefix onto that one port's subif. That is correct for the
//! reference topology (every service host behind the eth4 trunk) and
//! wrong the day a host moves behind another member of the same
//! bridge — the kernel's per-VLAN FDB would deliver to the new port,
//! VPP would keep transmitting out the declared one, and nothing
//! would say so.
//!
//! v1 is OBSERVABILITY ONLY, by decision (2026-08-15): a periodic
//! AF_BRIDGE FDB scan that flags any non-permanent entry for a
//! declared VLAN learned on a different member port, named host by
//! host on the health surface. Per-host subif selection (v2) is real
//! work deliberately deferred until this tripwire ever fires — the
//! user's topology says hosts could straddle eth4/eth5, and this is
//! what turns "could" into a fact before inbound goes always-on.
//!
//! The scan is kernel-side and read-only: one RTM_GETNEIGH dump on a
//! blocking netlink socket, no tokio (this crate's control plane is
//! the supervision loop, not a runtime), rate-limited by the caller
//! the same way the steering audit is. A scan failure costs a log
//! line and keeps the previous verdict; it must never escalate into
//! supervision.

/// One AF_BRIDGE FDB entry, reduced to what the comparison needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdbEntry {
    pub mac: [u8; 6],
    /// NDA_VLAN; `None` for VLAN-unaware entries.
    pub vlan: Option<u16>,
    /// The member port the kernel learned the MAC on.
    pub port: u32,
    /// NDA_MASTER — the bridge whose FDB this is. Entries without one
    /// are port-local ("self") records, not bridge paths.
    pub master: Option<u32>,
    /// NUD_PERMANENT: interface addresses and static plumbing, not
    /// learned hosts. A bridge holds its own MAC as permanent on a
    /// member; flagging those would page on every box ever built.
    pub permanent: bool,
}

/// One declared scope, resolved to ifindexes for comparison: hosts on
/// `vlan` (in `master`'s FDB) must be learned on `port`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclaredScope {
    pub vlan: u16,
    pub port: u32,
    pub master: u32,
}

/// The pure half: which entries contradict a declaration.
///
/// An entry is misplaced iff it is a learned (non-permanent) bridge
/// path for a declared VLAN, in the declared bridge's FDB, on a port
/// other than the declared one. Everything else — other VLANs, other
/// bridges, self entries, permanent entries, the declared port itself
/// — is somebody else's business.
pub fn misplaced_entries<'a>(
    entries: &'a [FdbEntry],
    declared: &[DeclaredScope],
) -> Vec<(&'a FdbEntry, DeclaredScope)> {
    let mut out = Vec::new();
    for e in entries {
        if e.permanent {
            continue;
        }
        let (Some(vlan), Some(master)) = (e.vlan, e.master) else {
            continue;
        };
        if let Some(scope) = declared
            .iter()
            .find(|d| d.vlan == vlan && d.master == master)
        {
            if e.port != scope.port {
                out.push((e, *scope));
            }
        }
    }
    out
}

/// The scan seam the runtime holds, mirroring [`crate::runtime::RxModeKick`]:
/// a trait so tests record calls and non-Linux builds never pretend.
pub trait FdbWatch {
    /// Human-readable line per misplaced host, empty when the
    /// declarations hold. `Err` = the kernel would not answer; the
    /// caller keeps its previous verdict.
    fn misplaced(&mut self) -> Result<Vec<String>, String>;
}

/// The production scan: resolve each declared `(vlan, port)` against
/// the live interface table, dump the bridge FDB, compare.
///
/// Resolution happens per scan, not at construction — a UniFi
/// provisioning cycle can recreate interfaces, and a cached ifindex
/// would compare against a table it no longer names. A declared port
/// with no bridge master is skipped rather than an error: on a
/// non-bridge deployment there is no FDB to disagree with.
#[cfg(target_os = "linux")]
pub struct KernelFdbWatch {
    /// `(vlan, port name)` straight from the resolved local-routes.
    pub declared: Vec<(u16, String)>,
}

#[cfg(target_os = "linux")]
impl FdbWatch for KernelFdbWatch {
    fn misplaced(&mut self) -> Result<Vec<String>, String> {
        let mut scopes = Vec::with_capacity(self.declared.len());
        for (vlan, port) in &self.declared {
            let Some(port_idx) = ifindex(port) else {
                // The declared port vanished — a louder fact than a
                // misplaced host, but the attach that depends on it
                // is the surface that reports it. Skip here.
                continue;
            };
            let Some(master_idx) = master_ifindex(port) else {
                continue; // not enslaved: no bridge FDB to scan
            };
            scopes.push(DeclaredScope {
                vlan: *vlan,
                port: port_idx,
                master: master_idx,
            });
        }
        if scopes.is_empty() {
            return Ok(Vec::new());
        }
        let entries = dump_bridge_fdb()?;
        Ok(misplaced_entries(&entries, &scopes)
            .into_iter()
            .map(|(e, scope)| {
                format!(
                    "{} vlan {} learned on {} (local-route declares {})",
                    hex_mac(&e.mac),
                    scope.vlan,
                    ifname(e.port),
                    ifname(scope.port),
                )
            })
            .collect())
    }
}

#[cfg(target_os = "linux")]
fn ifindex(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is NUL-terminated and outlives the call.
    match unsafe { libc::if_nametoindex(c.as_ptr()) } {
        0 => None,
        n => Some(n),
    }
}

#[cfg(target_os = "linux")]
fn ifname(index: u32) -> String {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes as the contract requires.
    let ret = unsafe { libc::if_indextoname(index, buf.as_mut_ptr().cast()) };
    if ret.is_null() {
        return format!("ifindex {index}");
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

#[cfg(target_os = "linux")]
fn master_ifindex(port: &str) -> Option<u32> {
    // The master symlink's target name, resolved to an index — the
    // same sysfs fact `port_macs` reads the address through.
    let link = std::fs::read_link(format!("/sys/class/net/{port}/master")).ok()?;
    ifindex(link.file_name()?.to_str()?)
}

#[cfg(target_os = "linux")]
fn hex_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// One blocking AF_BRIDGE RTM_GETNEIGH dump.
///
/// Hand-rolled on `netlink-sys` rather than `rtnetlink` because this
/// crate has no async runtime to park a connection on, and one dump
/// per minute does not earn one. The message shapes are the same
/// crates fast-path's resolver decodes with.
#[cfg(target_os = "linux")]
pub fn dump_bridge_fdb() -> Result<Vec<FdbEntry>, String> {
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
    use netlink_packet_route::neighbour::{NeighbourAttribute, NeighbourMessage, NeighbourState};
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;

    let mut neigh = NeighbourMessage::default();
    neigh.header.family = AddressFamily::Bridge;
    let mut msg = NetlinkMessage::from(RouteNetlinkMessage::GetNeighbour(neigh));
    msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.header.sequence_number = 1;
    msg.finalize();
    let mut send_buf = vec![0u8; msg.header.length as usize];
    msg.serialize(&mut send_buf);
    socket
        .send(&send_buf, 0)
        .map_err(|e| format!("netlink send: {e}"))?;

    let mut out = Vec::new();
    let mut recv_buf = vec![0u8; 64 * 1024];
    'dump: loop {
        let n = socket
            .recv(&mut &mut recv_buf[..], 0)
            .map_err(|e| format!("netlink recv: {e}"))?;
        let mut offset = 0usize;
        while offset < n {
            let pkt = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[offset..n])
                .map_err(|e| format!("netlink parse: {e}"))?;
            let len = pkt.header.length as usize;
            if len == 0 {
                break;
            }
            match pkt.payload {
                NetlinkPayload::Done(_) => break 'dump,
                NetlinkPayload::Error(e) => return Err(format!("netlink error: {e}")),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(m)) => {
                    let mut mac = None;
                    let mut vlan = None;
                    let mut master = None;
                    for attr in &m.attributes {
                        match attr {
                            NeighbourAttribute::LinkLayerAddress(bytes) if bytes.len() == 6 => {
                                let mut m6 = [0u8; 6];
                                m6.copy_from_slice(bytes);
                                mac = Some(m6);
                            }
                            NeighbourAttribute::Vlan(v) => vlan = Some(*v),
                            NeighbourAttribute::Controller(idx) => master = Some(*idx),
                            _ => {}
                        }
                    }
                    if let Some(mac) = mac {
                        out.push(FdbEntry {
                            mac,
                            vlan,
                            port: m.header.ifindex,
                            master,
                            permanent: m.header.state == NeighbourState::Permanent,
                        });
                    }
                }
                _ => {}
            }
            offset += len;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(mac_last: u8, vlan: Option<u16>, port: u32, master: Option<u32>) -> FdbEntry {
        FdbEntry {
            mac: [0x02, 0, 0, 0, 0, mac_last],
            vlan,
            port,
            master,
            permanent: false,
        }
    }

    /// The tripwire fires on exactly the moved-host shape and nothing
    /// else: other VLANs, other bridges, self entries, permanent
    /// entries and the declared port are all somebody else's business.
    #[test]
    fn only_learned_entries_for_a_declared_scope_on_the_wrong_port_fire() {
        let declared = [DeclaredScope {
            vlan: 1337,
            port: 4, // eth4
            master: 10,
        }];
        let moved = entry(7, Some(1337), 5, Some(10)); // behind eth5: fires
        let mut permanent = entry(1, Some(1337), 5, Some(10));
        permanent.permanent = true;
        let entries = vec![
            entry(7, Some(1337), 4, Some(10)), // declared port: fine
            moved.clone(),                     // wrong port: fires
            entry(8, Some(88), 5, Some(10)),   // undeclared vlan: fine
            entry(9, Some(1337), 5, Some(11)), // other bridge: fine
            entry(10, Some(1337), 5, None),    // self entry: fine
            entry(11, None, 5, Some(10)),      // vlan-unaware: fine
            permanent,                         // interface address: fine
        ];
        let hits = misplaced_entries(&entries, &declared);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].0, &moved);
        assert_eq!(hits[0].1, declared[0]);
    }

    /// No declarations, no verdicts — the scan must be inert on a
    /// config without local-routes.
    #[test]
    fn no_declarations_flags_nothing() {
        let entries = vec![entry(7, Some(1337), 5, Some(10))];
        assert!(misplaced_entries(&entries, &[]).is_empty());
    }
}
