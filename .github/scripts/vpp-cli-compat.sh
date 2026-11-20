#!/usr/bin/env bash
# Does vpp-offload still read the installed VPP's CLI output as it means?
#
#   .github/scripts/vpp-cli-compat.sh
#
# vpp-offload parses the text of a few CLI commands (the FIB summaries,
# `show errors`, `show ip neighbor-stats`, `show interface`), and a VPP
# release can change those formats with no binary-API change, so
# vpp-api-drift.sh cannot see it. This starts a scratch VPP with no NIC
# (4 KiB pages, dpdk disabled, one worker for the packet generator) and
# runs crates/modules/vpp-offload/tests/vpp_cli_compat.rs against it:
# routes and traffic go in, and each parser must recover them.
#
# Run from the repo root, as root, with VPP installed. CI runs it against
# the release SOURCE.json names; unredacted/vpp-unifi runs it on every
# VPP it is about to publish (.github/actions/vpp-cli-compat).
set -euo pipefail

test_args=(--locked -p packetframe-vpp-offload --test vpp_cli_compat)
# Built before VPP starts, so a compile error never reads as a VPP failure.
cargo test "${test_args[@]}" --no-run

work=$(mktemp -d)
api=$work/api.sock
cli=$work/cli.sock
vpp_pid=
cleanup() {
  if [ -n "$vpp_pid" ]; then kill "$vpp_pid" 2>/dev/null && wait "$vpp_pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

cat > "$work/startup.conf" <<EOF
unix { nodaemon log $work/vpp.log cli-listen $cli }
socksvr { socket-name $api }
cpu { main-core 0 corelist-workers 1 }
memory { main-heap-size 1G main-heap-page-size 4k }
buffers { buffers-per-numa 16384 page-size 4k }
statseg { size 64M page-size 4k }
plugins { plugin dpdk_plugin.so { disable } }
EOF
vpp -c "$work/startup.conf" > "$work/vpp.out" 2>&1 &
vpp_pid=$!
vpp_died() { cat "$work/vpp.out"; echo "::error::VPP $1"; exit 1; }
for _ in $(seq 100); do
  [ -S "$api" ] && vppctl -s "$cli" show version >/dev/null 2>&1 && break
  kill -0 "$vpp_pid" 2>/dev/null || vpp_died "exited at startup"
  sleep 0.1
done
[ -S "$api" ] || vpp_died "did not open its API socket"
vpp --version

rc=0
PACKETFRAME_VPP_CLI_SOCK=$api cargo test "${test_args[@]}" -- --ignored --nocapture || rc=$?
if [ "$rc" != 0 ]; then
  kill -0 "$vpp_pid" 2>/dev/null || echo "::error::VPP died during the test"
  cat "$work/vpp.out"
  echo "::error::vpp-offload does not parse this VPP's CLI output; see the test's message above, and the README's \"The gate\" in crates/modules/vpp-offload/vpp-api"
fi
exit "$rc"
