//! Minimal "does the kernel verifier accept guard_egress" gate,
//! mirroring fast-path's tests/verifier.rs. Runs on every qemu CI
//! kernel (5.15 + 6.6); the production 5.15-ui verifier is stricter
//! than either, so this is a necessary-not-sufficient gate — the
//! hardware-artifacts bundle carries the same test to the router.

#![cfg(target_os = "linux")]

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn guard_egress_passes_the_verifier() {
    if !packetframe_guard::GUARD_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping verifier test.");
        return;
    }
    let bytes = packetframe_guard::aligned_bpf_copy();
    let mut bpf = aya::Ebpf::load(&bytes).expect("Ebpf::load");
    let prog: &mut aya::programs::tc::SchedClassifier = bpf
        .program_mut("guard_egress")
        .expect("guard_egress present in ELF")
        .try_into()
        .expect("guard_egress is sched_cls");
    prog.load().expect("verifier accepts guard_egress");
}
