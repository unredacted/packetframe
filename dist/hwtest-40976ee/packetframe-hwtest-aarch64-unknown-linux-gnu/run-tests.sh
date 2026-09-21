#!/bin/sh
# On-router driver for PacketFrame's staged test binaries.
#
#   ./run-tests.sh              # safe suite: no interface is touched
#   ./run-tests.sh bench        # just the ns/packet microbenchmark
#   ./run-tests.sh tc_attach    # invasive: creates veths (see below)
#   ./run-tests.sh --list       # what is in this bundle
#
# Every test binary here is #[ignore]d by default (they need
# CAP_BPF/CAP_NET_ADMIN), so the driver passes --ignored.
#
# SAFE BY DEFAULT, including on a forwarding production router:
# every test in the default suite only uses BPF_PROG_TEST_RUN —
# programs are loaded and fed synthetic packets in-kernel.
# Nothing is attached to a NIC, no route/neighbour/sysctl state
# is touched, nothing is written outside the test process, and no
# live traffic is affected.
#
# Excluded from the default run, name them explicitly to opt in:
#   attach, tc_attach, netns, local_prefix_netns,
#   neigh_resolver_netns, guard_tc_attach, guard_netns
#     — create interfaces or netns
#   fib_comparison, fib_programmer_integration — pin maps into a
#     scratch /sys/fs/bpf/pftestcmp-<pid>-<n> dir (removed on
#     exit) and mount bpffs if it isn't already mounted
# All of them clean up after themselves; they're excluded so the
# default run's "writes nothing" property holds without caveats.
set -u
cd "$(dirname "$0")/tests" || exit 1

SAFE="verifier fixtures tc_fixtures feature_gates mss_clamp_gate fib_fixtures fib_hash_vectors bench guard_verifier guard_fixtures"

if [ "${1:-}" = "--list" ]; then
  ls -1
  exit 0
fi

if [ "$(id -u)" != 0 ]; then
  echo "error: run as root — these tests need CAP_BPF + CAP_NET_ADMIN" >&2
  exit 1
fi

# Detect a noexec mount before reporting anything as missing.
# Every binary here is staged 0755, and Linux access(X_OK) —
# which `test -x` uses — honours mount flags, so on a noexec
# filesystem a perfectly good binary tests as non-executable.
# /tmp is noexec on UniFi OS, so unpacking there makes the whole
# suite look absent, which is a maddening thing to debug from a
# "not in this bundle" message. Diagnose it once, properly.
for probe in ${SAFE}; do
  if [ -f "./${probe}" ] && [ ! -x "./${probe}" ]; then
    bundle=$(dirname "$(pwd)")
    echo "error: ./${probe} exists but is not executable." >&2
    echo "  cwd:            $(pwd)" >&2
    echo "  mount options:  $(findmnt -no OPTIONS -T . 2>/dev/null || echo 'unknown (no findmnt)')" >&2
    echo "  A noexec mount makes every test look missing. /tmp is noexec on" >&2
    echo "  UniFi OS — copy the bundle somewhere exec-capable and rerun:" >&2
    echo "    cp -r ${bundle} /root/ && /root/$(basename "${bundle}")/run-tests.sh" >&2
    exit 1
  fi
done

# The microbenchmark times the JIT-compiled program; with the
# JIT off it would time the interpreter and the numbers would be
# meaningless. Warn rather than refuse: correctness tests are
# unaffected.
if [ -r /proc/sys/net/core/bpf_jit_enable ]; then
  jit=$(cat /proc/sys/net/core/bpf_jit_enable)
  [ "${jit}" = "0" ] && \
    echo "WARNING: net.core.bpf_jit_enable=0 — bench numbers would measure the BPF interpreter" >&2
fi

suite="${*:-${SAFE}}"
rc=0
ran=0
for t in ${suite}; do
  # A missing binary is a failure, not a skip. Silently passing
  # here would let a typo, or a staging bug that dropped a
  # target, report a clean pre-canary validation that in fact
  # exercised nothing.
  if [ ! -x "./${t}" ]; then
    echo "!! ${t}: not in this bundle (run --list to see what is)" >&2
    rc=1
    continue
  fi
  echo "== ${t}"
  ran=$((ran + 1))
  # --include-ignored, not --ignored: the *-unittests
  # harnesses staged here hold mostly ORDINARY tests, and
  # --ignored would filter every one of them out — zero
  # tests, exit 0, a silent fake pass. For the integration
  # binaries the two flags are equivalent (every test there
  # is #[ignore]-gated), so one flag serves all binaries.
  ./"${t}" --include-ignored --nocapture || rc=1
done
if [ "${ran}" -eq 0 ]; then
  echo "!! no tests ran" >&2
  rc=1
fi
echo "== ${ran} test binaries ran, exit ${rc}"
exit "${rc}"
