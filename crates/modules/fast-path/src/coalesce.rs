//! Attach-time NIC interrupt coalescing (`coalesce` directive) and its
//! reversal.
//!
//! `attach` applies the configured parameters to every interface it
//! attached; `detach` — in-process or `packetframe detach`, a separate
//! process — writes the prior values back. The prior values live in
//! `<state-dir>/coalesce.json` (sibling of `tc-links.json`, same
//! atomic write-then-rename discipline), written BEFORE the NIC is
//! touched: a crash between the write and the record would otherwise
//! leave a change nothing knows how to undo.
//!
//! Every failure here is a WARN. Coalescing is a performance knob; a
//! driver that refuses it must not cost an attach, and a restore that
//! fails keeps its record for the next `detach` instead of failing
//! the teardown.
//!
//! The ioctl comes in through [`CoalesceIo`] so all of this runs
//! against a fake on any host.

use std::path::{Path, PathBuf};

use packetframe_common::ethtool::{CoalesceField, CoalesceIo, CoalesceSpec, EthtoolCoalesce};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

const COALESCE_FILENAME: &str = "coalesce.json";

#[derive(Debug, Error)]
pub enum CoalesceFileError {
    #[error("I/O error on {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON error on {path:?}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalesceFile {
    /// `/proc/sys/kernel/random/boot_id` when the records were written.
    /// A reboot resets every NIC to its driver default, so records from
    /// another boot describe nothing that still exists — restoring them
    /// could only clobber whatever set the NIC since (an operator, a
    /// oneshot unit). Empty when unreadable; treated as "same boot".
    pub boot_id: String,
    pub ifaces: Vec<CoalesceRecord>,
}

/// One interface PacketFrame changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalesceRecord {
    pub iface: String,
    /// The device's ifindex at attach. A same-name recreated device
    /// came up with driver defaults, so its record is stale (the
    /// `tc-links.json` rule, review finding PR #205).
    pub ifindex: u32,
    /// What the NIC held before PacketFrame first touched each field.
    pub prior: CoalesceSpec,
    /// What the NIC reported after the write, per field. A field of
    /// `prior` missing here was written but never confirmed, so restore
    /// writes it back unconditionally; a confirmed field is restored
    /// only while the NIC still holds it.
    pub applied: CoalesceSpec,
}

pub fn file_path(state_dir: &Path) -> PathBuf {
    state_dir.join(COALESCE_FILENAME)
}

// The daemon writing these is root and `state-dir` may be writable by
// someone who is not, so on Linux every write, read and unlink goes
// through `packetframe_common::statefile`'s no-follow directory walk: a
// symlink planted at `coalesce.json`, `coalesce.json.tmp` or any
// intermediate component cannot redirect it (review finding, P1). The
// non-Linux arms exist for the macOS dev loop's unit tests only, the
// same split as the CLI's `atomic::write`.

/// Atomic write-then-rename.
pub fn save(state_dir: &Path, file: &CoalesceFile) -> Result<(), CoalesceFileError> {
    let path = file_path(state_dir);
    let json = serde_json::to_string_pretty(file).map_err(|source| CoalesceFileError::Json {
        path: path.clone(),
        source,
    })?;
    write_record(&path, json.as_bytes()).map_err(|source| CoalesceFileError::Io { path, source })
}

#[cfg(target_os = "linux")]
fn write_record(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    packetframe_common::statefile::write_atomic(path, contents)
}

#[cfg(not(target_os = "linux"))]
fn write_record(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
}

/// `Ok(None)` when nothing is recorded.
pub fn load(state_dir: &Path) -> Result<Option<CoalesceFile>, CoalesceFileError> {
    let path = file_path(state_dir);
    let raw = match read_record(&path) {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(None),
        Err(source) => return Err(CoalesceFileError::Io { path, source }),
    };
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|source| CoalesceFileError::Json { path, source })
}

#[cfg(target_os = "linux")]
fn read_record(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    packetframe_common::statefile::read_no_follow(path)
}

#[cfg(not(target_os = "linux"))]
fn read_record(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(r) => Ok(Some(r)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Missing file is fine (idempotent teardown).
pub fn remove(state_dir: &Path) -> Result<(), CoalesceFileError> {
    let path = file_path(state_dir);
    #[cfg(target_os = "linux")]
    let r = packetframe_common::statefile::remove_state_record(&path);
    #[cfg(not(target_os = "linux"))]
    let r = std::fs::remove_file(&path);
    match r {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CoalesceFileError::Io { path, source }),
    }
}

/// The running kernel's boot id; empty when unreadable (non-Linux, or
/// a /proc without it).
pub fn current_boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn same_boot(recorded: &str, now: &str) -> bool {
    recorded.is_empty() || now.is_empty() || recorded == now
}

/// What happened on one interface at attach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Written and read back as requested.
    Applied,
    /// Written, but the driver holds different values: `(field,
    /// wanted, got)`. Recorded like `Applied`; the read-back is the
    /// truth `detach` compares against.
    Clamped(Vec<(CoalesceField, u32, u32)>),
    /// The NIC already held the requested values; nothing written.
    /// With no carried record there is nothing to reverse and nothing
    /// is recorded; a carried record keeps its confirmation unchanged.
    AlreadySet,
    /// Written, but the read-back failed; `detach` restores the prior
    /// values unconditionally.
    Unconfirmed,
    /// Left untouched, with the reason.
    Skipped(String),
}

/// Apply `spec` to each attached `(iface, ifindex)`, recording prior
/// values first. Never fails; each interface's outcome is logged and
/// returned.
///
/// Records carried over from earlier in the SAME boot (a restore that
/// failed at the last `detach`) keep their `prior`: the NIC may still
/// hold PacketFrame's values, and re-reading "prior" now would record
/// our own setting as the thing to restore.
pub fn apply_on_attach(
    io: &dyn CoalesceIo,
    state_dir: &Path,
    boot_id: &str,
    ifaces: &[(String, u32)],
    spec: &CoalesceSpec,
) -> Vec<(String, ApplyOutcome)> {
    let mut records = match load(state_dir) {
        Ok(Some(f)) if same_boot(&f.boot_id, boot_id) => f.ifaces,
        Ok(Some(_)) => {
            info!("coalesce.json is from a previous boot (NICs reset since); starting fresh");
            Vec::new()
        }
        Ok(None) => Vec::new(),
        Err(e) => {
            warn!(error = %e, "coalesce.json unreadable; starting fresh (earlier restore records are lost)");
            Vec::new()
        }
    };
    let persist = |records: &[CoalesceRecord]| {
        save(
            state_dir,
            &CoalesceFile {
                boot_id: boot_id.to_string(),
                ifaces: records.to_vec(),
            },
        )
    };

    let mut out = Vec::new();
    for (iface, ifindex) in ifaces {
        if out.iter().any(|(i, _)| i == iface) {
            continue;
        }
        let outcome = apply_one(io, &mut records, &persist, iface, *ifindex, spec);
        out.push((iface.clone(), outcome));
    }
    out
}

fn apply_one(
    io: &dyn CoalesceIo,
    records: &mut Vec<CoalesceRecord>,
    persist: &dyn Fn(&[CoalesceRecord]) -> Result<(), CoalesceFileError>,
    iface: &str,
    ifindex: u32,
    spec: &CoalesceSpec,
) -> ApplyOutcome {
    let before = match io.get(iface) {
        Ok(v) => v,
        Err(e) => {
            warn!(iface, error = %e, "coalesce: driver does not report coalescing; left as is");
            return ApplyOutcome::Skipped(format!("get: {e}"));
        }
    };
    // A record for a different ifindex belongs to a device that no
    // longer exists; this one started from driver defaults.
    let old_pos = records.iter().position(|r| r.iface == iface);
    let old = old_pos
        .map(|p| records.remove(p))
        .filter(|r| r.ifindex == ifindex);

    let mut want = before;
    spec.merge_into(&mut want);
    if want == before && old.is_none() {
        info!(iface, current = %spec.snapshot(&before), "coalesce: already set; nothing to change");
        return ApplyOutcome::AlreadySet;
    }

    // Write-ahead: the record that can undo the change exists before
    // the change does.
    let prior = old
        .as_ref()
        .map(|o| o.prior.or(&spec.snapshot(&before)))
        .unwrap_or_else(|| spec.snapshot(&before));
    let carried_applied = old.as_ref().map(|o| o.applied).unwrap_or_default();
    // A write makes the requested fields' confirmation unknown until the
    // read-back lands, so they are cleared first. With no write (the NIC
    // already holds the requested values under a carried record) nothing
    // changes on the NIC, and clearing would turn a confirmed field into
    // an unconfirmed one — which restore writes back unconditionally,
    // over any operator change made since (review finding).
    let wrote = want != before;
    let pending_applied = if wrote {
        carried_applied.without(spec)
    } else {
        carried_applied
    };
    records.push(CoalesceRecord {
        iface: iface.to_string(),
        ifindex,
        prior,
        applied: pending_applied,
    });
    let revert = |records: &mut Vec<CoalesceRecord>| {
        records.pop();
        if let Some(o) = &old {
            records.push(o.clone());
        }
        if let Err(e) = persist(records) {
            warn!(iface, error = %e, "coalesce.json rewrite failed");
        }
    };
    if let Err(e) = persist(records) {
        warn!(
            iface,
            error = %e,
            "coalesce: cannot record prior values; not applying (the change could not be reversed)"
        );
        revert(records);
        return ApplyOutcome::Skipped(format!("record: {e}"));
    }

    if !wrote {
        info!(
            iface,
            current = %spec.snapshot(&before),
            "coalesce: already set; carried restore record kept as is"
        );
        return ApplyOutcome::AlreadySet;
    }
    if let Err(e) = io.set(iface, &want) {
        warn!(
            iface,
            requested = %spec,
            error = %e,
            "coalesce: driver refused; attach continues with the driver's values"
        );
        revert(records);
        return ApplyOutcome::Skipped(format!("set: {e}"));
    }

    let readback = match io.get(iface) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                iface,
                requested = %spec,
                error = %e,
                "coalesce: written but read-back failed; detach will restore the prior values"
            );
            return ApplyOutcome::Unconfirmed;
        }
    };
    let rec = records.last_mut().expect("pushed above");
    rec.applied = spec.snapshot(&readback).or(&carried_applied);
    if let Err(e) = persist(records) {
        warn!(iface, error = %e, "coalesce.json update failed; detach will restore unconditionally");
    }
    let mismatches = spec.mismatches(&readback);
    info!(
        iface,
        ifindex,
        before = %spec.snapshot(&before),
        after = %spec.snapshot(&readback),
        adaptive_rx = readback.use_adaptive_rx_coalesce != 0,
        "coalesce applied"
    );
    if mismatches.is_empty() {
        ApplyOutcome::Applied
    } else {
        warn!(
            iface,
            requested = %spec,
            after = %spec.snapshot(&readback),
            "coalesce: driver holds different values than requested (clamped or rx/tx-coupled); \
             the read-back is what is in effect"
        );
        ApplyOutcome::Clamped(mismatches)
    }
}

/// Counts from one restore pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RestoreSummary {
    /// Interfaces written back to their prior values.
    pub restored: usize,
    /// Records dropped with nothing to write (device gone or
    /// recreated, every field moved by someone else, already at prior).
    pub dropped: usize,
    /// Records kept for a later `detach`: the write failed, or landed
    /// without the NIC holding the prior values afterwards.
    pub retained: usize,
}

/// Write recorded prior values back. Never fails: problems are WARNs
/// and a failed interface keeps its record.
pub fn restore_from_state_dir(
    io: &dyn CoalesceIo,
    state_dir: &Path,
    boot_id: &str,
    ifindex_of: &dyn Fn(&str) -> Option<u32>,
) -> RestoreSummary {
    let mut summary = RestoreSummary::default();
    let file = match load(state_dir) {
        Ok(Some(f)) => f,
        Ok(None) => return summary,
        Err(e) => {
            warn!(error = %e, "coalesce.json unreadable; coalescing not restored (file left for inspection)");
            return summary;
        }
    };
    if !same_boot(&file.boot_id, boot_id) {
        info!("coalesce.json is from a previous boot; the reboot already reset those NICs");
        summary.dropped = file.ifaces.len();
        if let Err(e) = remove(state_dir) {
            warn!(error = %e, "coalesce.json remove failed");
        }
        return summary;
    }

    let mut retained = Vec::new();
    for rec in file.ifaces {
        match restore_one(io, &rec, ifindex_of) {
            RestoreStep::Restored => summary.restored += 1,
            RestoreStep::Dropped => summary.dropped += 1,
            RestoreStep::Retain => retained.push(rec),
            RestoreStep::RetainAs(updated) => retained.push(updated),
        }
    }
    summary.retained = retained.len();
    let result = if retained.is_empty() {
        remove(state_dir)
    } else {
        warn!(
            count = retained.len(),
            "coalescing not restored on some interfaces; records kept in coalesce.json for the next detach"
        );
        save(
            state_dir,
            &CoalesceFile {
                boot_id: file.boot_id,
                ifaces: retained,
            },
        )
    };
    if let Err(e) = result {
        warn!(error = %e, "coalesce.json rewrite failed");
    }
    summary
}

enum RestoreStep {
    Restored,
    Dropped,
    /// Keep the record as it was (nothing was written).
    Retain,
    /// Keep an updated record: a restore write landed but the driver
    /// does not hold the prior values, so `applied` now names what the
    /// NIC holds after OUR write — otherwise the next detach would read
    /// those fields as moved by someone else and never retry them.
    RetainAs(CoalesceRecord),
}

fn restore_one(
    io: &dyn CoalesceIo,
    rec: &CoalesceRecord,
    ifindex_of: &dyn Fn(&str) -> Option<u32>,
) -> RestoreStep {
    let iface = rec.iface.as_str();
    match ifindex_of(iface) {
        None => {
            info!(iface, "coalesce: interface gone; nothing to restore");
            return RestoreStep::Dropped;
        }
        Some(now) if now != rec.ifindex => {
            info!(
                iface,
                recorded = rec.ifindex,
                now,
                "coalesce: interface recreated since attach (driver defaults); nothing to restore"
            );
            return RestoreStep::Dropped;
        }
        Some(_) => {}
    }
    let current = match io.get(iface) {
        Ok(v) => v,
        Err(e) => {
            warn!(iface, error = %e, "coalesce: cannot read current values; restore deferred");
            return RestoreStep::Retain;
        }
    };
    let (plan, moved) = CoalesceSpec::restore_plan(&rec.prior, &rec.applied, &current);
    if !moved.is_empty() {
        let names: Vec<&str> = moved.iter().map(|f| f.keyword()).collect();
        warn!(
            iface,
            fields = ?names,
            "coalesce: changed by something else since attach; left as found"
        );
    }
    let mut want: EthtoolCoalesce = current;
    plan.merge_into(&mut want);
    if want == current {
        return RestoreStep::Dropped;
    }
    if let Err(e) = io.set(iface, &want) {
        warn!(iface, restore = %plan, error = %e, "coalesce: restore refused; record kept");
        return RestoreStep::Retain;
    }
    match io.get(iface) {
        Ok(rb) if !plan.mismatches(&rb).is_empty() => {
            warn!(
                iface,
                wanted = %plan,
                got = %plan.snapshot(&rb),
                "coalesce: restore written but the driver holds different values; \
                 record kept for the next detach"
            );
            let mut updated = rec.clone();
            updated.applied = plan.snapshot(&rb).or(&rec.applied);
            RestoreStep::RetainAs(updated)
        }
        Ok(_) => {
            info!(iface, restored = %plan, "coalesce restored");
            RestoreStep::Restored
        }
        Err(e) => {
            info!(iface, restored = %plan, error = %e, "coalesce restored (read-back failed)");
            RestoreStep::Restored
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io;

    /// An in-memory NIC table. `refuse_set` makes SCOALESCE fail for an
    /// interface; `clamp_usecs` caps both timers the way a driver with
    /// a hardware limit does; `floor_usecs` raises them to a minimum.
    #[derive(Default)]
    struct FakeNic {
        nics: RefCell<HashMap<String, EthtoolCoalesce>>,
        refuse_set: RefCell<Vec<String>>,
        clamp_usecs: Option<u32>,
        floor_usecs: RefCell<Option<u32>>,
        sets: RefCell<usize>,
    }

    impl FakeNic {
        fn with(ifaces: &[&str]) -> Self {
            let f = FakeNic::default();
            for i in ifaces {
                f.nics.borrow_mut().insert(i.to_string(), stock());
            }
            f
        }
        fn now(&self, iface: &str) -> EthtoolCoalesce {
            self.nics.borrow()[iface]
        }
    }

    impl CoalesceIo for FakeNic {
        fn get(&self, iface: &str) -> io::Result<EthtoolCoalesce> {
            self.nics
                .borrow()
                .get(iface)
                .copied()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOPNOTSUPP))
        }
        fn set(&self, iface: &str, v: &EthtoolCoalesce) -> io::Result<()> {
            if self.refuse_set.borrow().iter().any(|i| i == iface) {
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            *self.sets.borrow_mut() += 1;
            let mut v = *v;
            if let Some(c) = self.clamp_usecs {
                v.rx_coalesce_usecs = v.rx_coalesce_usecs.min(c);
                v.tx_coalesce_usecs = v.tx_coalesce_usecs.min(c);
            }
            if let Some(f) = *self.floor_usecs.borrow() {
                v.rx_coalesce_usecs = v.rx_coalesce_usecs.max(f);
                v.tx_coalesce_usecs = v.tx_coalesce_usecs.max(f);
            }
            self.nics.borrow_mut().insert(iface.to_string(), v);
            Ok(())
        }
    }

    fn stock() -> EthtoolCoalesce {
        EthtoolCoalesce {
            rx_coalesce_usecs: 1,
            rx_max_coalesced_frames: 10,
            tx_coalesce_usecs: 1,
            tx_max_coalesced_frames: 10,
            rx_coalesce_usecs_irq: 3,
            ..Default::default()
        }
    }

    fn tuned() -> CoalesceSpec {
        CoalesceSpec {
            rx_usecs: Some(50),
            rx_frames: Some(32),
            tx_usecs: Some(50),
            tx_frames: Some(32),
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pf-coalesce-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn attached(names: &[&str]) -> Vec<(String, u32)> {
        names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.to_string(), i as u32 + 2))
            .collect()
    }

    fn index_of(names: &'static [&'static str]) -> impl Fn(&str) -> Option<u32> {
        move |n| names.iter().position(|x| *x == n).map(|i| i as u32 + 2)
    }

    #[test]
    fn apply_then_restore_round_trips_and_leaves_others_alone() {
        let dir = tmpdir("round-trip");
        // eth9 is present on the host but not attached (an HA link).
        let nic = FakeNic::with(&["eth0", "eth1", "eth9"]);
        let out = apply_on_attach(&nic, &dir, "boot-a", &attached(&["eth0", "eth1"]), &tuned());
        assert_eq!(
            out,
            vec![
                ("eth0".into(), ApplyOutcome::Applied),
                ("eth1".into(), ApplyOutcome::Applied)
            ]
        );
        for i in ["eth0", "eth1"] {
            let now = nic.now(i);
            assert_eq!(
                (now.rx_coalesce_usecs, now.rx_max_coalesced_frames),
                (50, 32)
            );
            assert_eq!(now.rx_coalesce_usecs_irq, 3, "unmanaged field carried");
        }
        assert_eq!(nic.now("eth9"), stock(), "never touch an unattached iface");

        let f = load(&dir).unwrap().expect("recorded");
        assert_eq!(f.boot_id, "boot-a");
        assert_eq!(f.ifaces[0].prior, tuned().snapshot(&stock()));
        assert_eq!(f.ifaces[0].applied, tuned());

        let s = restore_from_state_dir(&nic, &dir, "boot-a", &index_of(&["eth0", "eth1"]));
        assert_eq!(
            s,
            RestoreSummary {
                restored: 2,
                dropped: 0,
                retained: 0
            }
        );
        assert_eq!(nic.now("eth0"), stock());
        assert_eq!(nic.now("eth1"), stock());
        assert!(load(&dir).unwrap().is_none(), "file removed once restored");
        // Idempotent.
        let s = restore_from_state_dir(&nic, &dir, "boot-a", &index_of(&["eth0", "eth1"]));
        assert_eq!(s, RestoreSummary::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unnamed_fields_are_neither_written_nor_restored() {
        let dir = tmpdir("partial");
        let nic = FakeNic::with(&["eth0"]);
        let spec = CoalesceSpec {
            rx_usecs: Some(50),
            ..Default::default()
        };
        apply_on_attach(&nic, &dir, "b", &attached(&["eth0"]), &spec);
        let f = load(&dir).unwrap().unwrap();
        assert_eq!(
            f.ifaces[0].prior,
            CoalesceSpec {
                rx_usecs: Some(1),
                ..Default::default()
            }
        );
        // An operator moves tx-usecs while running; restore must not
        // know about it, let alone undo it.
        nic.nics
            .borrow_mut()
            .get_mut("eth0")
            .unwrap()
            .tx_coalesce_usecs = 7;
        restore_from_state_dir(&nic, &dir, "b", &index_of(&["eth0"]));
        assert_eq!(nic.now("eth0").rx_coalesce_usecs, 1);
        assert_eq!(nic.now("eth0").tx_coalesce_usecs, 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn driver_refusal_warns_and_records_nothing() {
        let dir = tmpdir("refuse");
        let nic = FakeNic::with(&["eth0", "eth1"]);
        nic.refuse_set.borrow_mut().push("eth0".into());
        let out = apply_on_attach(&nic, &dir, "b", &attached(&["eth0", "eth1"]), &tuned());
        assert!(matches!(&out[0].1, ApplyOutcome::Skipped(r) if r.starts_with("set:")));
        assert_eq!(
            out[1].1,
            ApplyOutcome::Applied,
            "one refusal does not stop the rest"
        );
        let f = load(&dir).unwrap().unwrap();
        assert_eq!(f.ifaces.len(), 1);
        assert_eq!(f.ifaces[0].iface, "eth1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsupported_get_is_skipped() {
        let dir = tmpdir("noget");
        let nic = FakeNic::with(&["eth0"]);
        let out = apply_on_attach(&nic, &dir, "b", &attached(&["veth0"]), &tuned());
        assert!(matches!(&out[0].1, ApplyOutcome::Skipped(r) if r.starts_with("get:")));
        assert!(load(&dir).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clamped_values_are_reported_and_restore_still_works() {
        let dir = tmpdir("clamp");
        let nic = FakeNic {
            clamp_usecs: Some(25),
            ..FakeNic::with(&["eth0"])
        };
        let out = apply_on_attach(&nic, &dir, "b", &attached(&["eth0"]), &tuned());
        assert_eq!(
            out[0].1,
            ApplyOutcome::Clamped(vec![
                (CoalesceField::RxUsecs, 50, 25),
                (CoalesceField::TxUsecs, 50, 25)
            ])
        );
        let f = load(&dir).unwrap().unwrap();
        assert_eq!(f.ifaces[0].applied.rx_usecs, Some(25), "read-back recorded");
        restore_from_state_dir(&nic, &dir, "b", &index_of(&["eth0"]));
        assert_eq!(nic.now("eth0"), stock());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn already_set_nic_is_not_recorded() {
        let dir = tmpdir("already");
        let nic = FakeNic::with(&["eth0"]);
        let mut v = stock();
        tuned().merge_into(&mut v);
        nic.nics.borrow_mut().insert("eth0".into(), v);
        let out = apply_on_attach(&nic, &dir, "b", &attached(&["eth0"]), &tuned());
        assert_eq!(out[0].1, ApplyOutcome::AlreadySet);
        assert_eq!(*nic.sets.borrow(), 0);
        assert!(
            load(&dir).unwrap().is_none(),
            "nothing changed, nothing to reverse"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_restore_is_retained_and_its_prior_survives_the_next_attach() {
        let dir = tmpdir("retain");
        let nic = FakeNic::with(&["eth0"]);
        apply_on_attach(&nic, &dir, "b", &attached(&["eth0"]), &tuned());
        nic.refuse_set.borrow_mut().push("eth0".into());
        let s = restore_from_state_dir(&nic, &dir, "b", &index_of(&["eth0"]));
        assert_eq!(s.retained, 1);
        assert!(load(&dir).unwrap().is_some());
        nic.refuse_set.borrow_mut().clear();

        // Same boot, NIC still at 50/32: a re-read "prior" would be our
        // own value. The carried record must win.
        apply_on_attach(&nic, &dir, "b", &attached(&["eth0"]), &tuned());
        let f = load(&dir).unwrap().unwrap();
        assert_eq!(f.ifaces[0].prior, tuned().snapshot(&stock()));
        restore_from_state_dir(&nic, &dir, "b", &index_of(&["eth0"]));
        assert_eq!(nic.now("eth0"), stock());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn records_from_another_boot_are_never_restored() {
        let dir = tmpdir("reboot");
        let nic = FakeNic::with(&["eth0"]);
        apply_on_attach(&nic, &dir, "boot-a", &attached(&["eth0"]), &tuned());
        // Reboot: the NIC is back at stock; a oneshot unit then sets
        // exactly our values. A stale restore would undo it.
        let mut v = stock();
        tuned().merge_into(&mut v);
        nic.nics.borrow_mut().insert("eth0".into(), v);
        let s = restore_from_state_dir(&nic, &dir, "boot-b", &index_of(&["eth0"]));
        assert_eq!(s.dropped, 1);
        assert_eq!(nic.now("eth0"), v);
        assert!(load(&dir).unwrap().is_none());

        // And at attach, a previous boot's prior is not carried.
        apply_on_attach(&nic, &dir, "boot-a", &attached(&["eth0"]), &tuned());
        nic.nics.borrow_mut().insert("eth0".into(), stock());
        let spec = CoalesceSpec {
            rx_usecs: Some(40),
            ..Default::default()
        };
        apply_on_attach(&nic, &dir, "boot-c", &attached(&["eth0"]), &spec);
        let f = load(&dir).unwrap().unwrap();
        assert_eq!(f.boot_id, "boot-c");
        assert_eq!(f.ifaces[0].prior.rx_usecs, Some(1));
        assert_eq!(f.ifaces[0].prior.rx_frames, None, "stale fields dropped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recreated_or_vanished_devices_are_dropped_without_writes() {
        let dir = tmpdir("recreated");
        let nic = FakeNic::with(&["eth0", "eth1"]);
        apply_on_attach(&nic, &dir, "b", &attached(&["eth0", "eth1"]), &tuned());
        let sets_before = *nic.sets.borrow();
        // eth0 now has a different ifindex; eth1 is gone.
        let s = restore_from_state_dir(&nic, &dir, "b", &|n: &str| (n == "eth0").then_some(99));
        assert_eq!(s.dropped, 2);
        assert_eq!(*nic.sets.borrow(), sets_before);
        assert!(load(&dir).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A write whose read-back never landed leaves `applied` without
    /// the field, and restore then writes the prior back regardless of
    /// what the NIC holds.
    #[test]
    fn an_unconfirmed_write_restores_unconditionally() {
        let dir = tmpdir("unconfirmed");
        let nic = FakeNic::with(&["eth0"]);
        save(
            &dir,
            &CoalesceFile {
                boot_id: "b".into(),
                ifaces: vec![CoalesceRecord {
                    iface: "eth0".into(),
                    ifindex: 2,
                    prior: CoalesceSpec {
                        rx_usecs: Some(1),
                        ..Default::default()
                    },
                    applied: CoalesceSpec::default(),
                }],
            },
        )
        .unwrap();
        nic.nics
            .borrow_mut()
            .get_mut("eth0")
            .unwrap()
            .rx_coalesce_usecs = 77;
        let s = restore_from_state_dir(&nic, &dir, "b", &index_of(&["eth0"]));
        assert_eq!(s.restored, 1);
        assert_eq!(nic.now("eth0").rx_coalesce_usecs, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restore the driver only partly honours is not a restore: the
    /// record stays, naming what OUR write left on the NIC, so the next
    /// detach retries those fields instead of reading them as someone
    /// else's change.
    #[test]
    fn a_mismatched_restore_is_retained_and_retried() {
        let dir = tmpdir("restore-mismatch");
        let nic = FakeNic::with(&["eth0"]);
        apply_on_attach(&nic, &dir, "b", &attached(&["eth0"]), &tuned());
        *nic.floor_usecs.borrow_mut() = Some(10);
        let s = restore_from_state_dir(&nic, &dir, "b", &index_of(&["eth0"]));
        assert_eq!(s.retained, 1);
        assert_eq!(s.restored, 0);
        let f = load(&dir).unwrap().expect("record kept");
        assert_eq!(
            f.ifaces[0].applied.rx_usecs,
            Some(10),
            "what our write left"
        );
        assert_eq!(nic.now("eth0").rx_coalesce_usecs, 10);

        *nic.floor_usecs.borrow_mut() = None;
        let s = restore_from_state_dir(&nic, &dir, "b", &index_of(&["eth0"]));
        assert_eq!(s.restored, 1);
        assert_eq!(nic.now("eth0"), stock());
        assert!(load(&dir).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A carried record meets a NIC already holding the requested
    /// values: no write happens, so the record's confirmation must not
    /// be cleared — a cleared field is restored unconditionally, over
    /// an operator change made afterwards.
    #[test]
    fn no_write_keeps_the_carried_confirmation() {
        let dir = tmpdir("no-write");
        let nic = FakeNic::with(&["eth0"]);
        apply_on_attach(&nic, &dir, "b", &attached(&["eth0"]), &tuned());
        nic.refuse_set.borrow_mut().push("eth0".into());
        restore_from_state_dir(&nic, &dir, "b", &index_of(&["eth0"]));
        nic.refuse_set.borrow_mut().clear();
        let confirmed = load(&dir).unwrap().unwrap().ifaces[0].applied;
        assert_eq!(confirmed, tuned());

        let sets = *nic.sets.borrow();
        let out = apply_on_attach(&nic, &dir, "b", &attached(&["eth0"]), &tuned());
        assert_eq!(out[0].1, ApplyOutcome::AlreadySet);
        assert_eq!(*nic.sets.borrow(), sets, "nothing written");
        let f = load(&dir).unwrap().unwrap();
        assert_eq!(
            f.ifaces[0].applied, confirmed,
            "confirmation intact on disk"
        );

        // The operator retunes rx-usecs; detach restores the rest and
        // leaves theirs alone.
        nic.nics
            .borrow_mut()
            .get_mut("eth0")
            .unwrap()
            .rx_coalesce_usecs = 70;
        restore_from_state_dir(&nic, &dir, "b", &index_of(&["eth0"]));
        let now = nic.now("eth0");
        assert_eq!(now.rx_coalesce_usecs, 70);
        assert_eq!(now.rx_max_coalesced_frames, 10);
        assert_eq!(now.tx_coalesce_usecs, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The root daemon writes `coalesce.json` into a state dir that may
    /// be writable by someone else; a symlink planted at the record name
    /// must be replaced, never written through, and never read through.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_planted_symlink_does_not_capture_coalesce_json() {
        let dir = tmpdir("symlink");
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "do not truncate me").unwrap();
        std::os::unix::fs::symlink(&victim, file_path(&dir)).unwrap();

        assert!(
            load(&dir).is_err(),
            "a symlinked record is refused, not read"
        );
        let nic = FakeNic::with(&["eth0"]);
        apply_on_attach(&nic, &dir, "b", &attached(&["eth0"]), &tuned());
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "do not truncate me"
        );
        let meta = std::fs::symlink_metadata(file_path(&dir)).unwrap();
        assert!(
            meta.file_type().is_file(),
            "the rename replaced the symlink"
        );
        assert_eq!(load(&dir).unwrap().unwrap().ifaces[0].iface, "eth0");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
