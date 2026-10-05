#!/bin/bash
# End-to-end checks of the sampler plugin in a real VPP: CI's arm64 VPP
# job, or a privileged bullseye container with the vpp-unifi debs. Needs
# root (a tmpfs mount, and VPP itself).
#
#   smoke.sh <plugin.so> <refused-plugin.so> <sampler-smoke>
#
# <refused-plugin.so> is the same plugin built with
# PF_SAMPLER_VERSION_REQUIRED=00.00-never, which VPP's loader must refuse.
set -euo pipefail

SO=$1 REFUSED=$2 SMOKE=$3
WORK=$(mktemp -d)
export PF_SAMPLER_DIR=/run/packetframe/vpp/sampler
CLI=/run/vpp/cli.sock
VPP_PID=

mkdir -p "$PF_SAMPLER_DIR" /run/vpp "$WORK/present" "$WORK/empty" "$WORK/refused"
mount -t tmpfs -o size=64m,mode=0700 tmpfs "$PF_SAMPLER_DIR"
cp "$SO" "$WORK/present/pf_sampler_plugin.so"
cp "$REFUSED" "$WORK/refused/pf_sampler_plugin.so"

cleanup() {
  [ -n "$VPP_PID" ] && kill "$VPP_PID" 2>/dev/null && wait "$VPP_PID" 2>/dev/null || true
  umount -l "$PF_SAMPLER_DIR" 2>/dev/null || true
}
trap cleanup EXIT

vppctl() { command vppctl -s "$CLI" "$@"; }

# A small VPP: one worker, 4 KiB pages everywhere, and the plugin directory
# under test added the way PacketFrame adds it.
start_vpp() {
  cat > "$WORK/startup.conf" <<EOF
unix { nodaemon log $WORK/vpp.log cli-listen $CLI }
cpu { main-core 0 corelist-workers 1 }
memory { main-heap-size 1G main-heap-page-size 4k }
buffers { buffers-per-numa 16384 page-size 4k }
statseg { size 64M page-size 4k }
plugins {
  plugin dpdk_plugin.so { disable }
  add-path $1
}
EOF
  rm -f "$CLI"
  vpp -c "$WORK/startup.conf" > "$WORK/vpp.out" 2>&1 &
  VPP_PID=$!
  for _ in $(seq 100); do
    vppctl show version >/dev/null 2>&1 && return 0
    kill -0 "$VPP_PID" 2>/dev/null || { cat "$WORK/vpp.out"; echo "FAIL: VPP exited"; exit 1; }
    sleep 0.1
  done
  cat "$WORK/vpp.out"; echo "FAIL: VPP did not answer"; exit 1
}

stop_vpp() {
  kill "$VPP_PID"; wait "$VPP_PID" || true; VPP_PID=
}

plugin_loaded() { vppctl show plugins | grep -q pf_sampler_plugin.so; }

send() { # name packets: 64-byte frames (14 + 20 + 8 + 22 of payload)
  vppctl "packet-generator new { name $1 limit $2 rate 100000 size 64-64 worker 0 node ethernet-input interface pg0 data { IP4: 0200.0000.0001 -> 0200.0000.0002 UDP: 192.0.2.1 -> 198.51.100.1 UDP: 1024 -> 53 incrementing 22 } }"
  vppctl packet-generator enable-stream "$1"
}

features_on_pg0() { vppctl show interface features pg0 | grep -c pf-sampler-rx || true; }

echo "== present: samples flow end to end"
start_vpp "$WORK/present"
plugin_loaded || { echo "FAIL: plugin not loaded"; exit 1; }
vppctl create packet-generator interface pg0
vppctl set interface state pg0 up
"$SMOKE" desired 1 10 64 pg0
"$SMOKE" wait-applied 1 10
[ "$(features_on_pg0)" = 2 ] || { vppctl show interface features pg0; echo "FAIL: want one feature per arc"; exit 1; }
send s1 20000
"$SMOKE" drain pg0 20000 10 64 02:00:00:00:00:02 30
vppctl show pf-sampler
vppctl show errors | grep -i pf-sampler || true

echo "== reconfigured: applied once more, never enabled twice"
"$SMOKE" desired 2 100 64 pg0
"$SMOKE" wait-applied 2 10
[ "$(features_on_pg0)" = 2 ] || { vppctl show interface features pg0; echo "FAIL: feature duplicated"; exit 1; }
FIRST_EPOCH=$(sed -n 's/^epoch //p' "$PF_SAMPLER_DIR/current")
stop_vpp

echo "== restarted: a new epoch, the previous one kept"
start_vpp "$WORK/present"
vppctl create packet-generator interface pg0
vppctl set interface state pg0 up
"$SMOKE" wait-applied 2 10
SECOND_EPOCH=$(sed -n 's/^epoch //p' "$PF_SAMPLER_DIR/current")
[ "$FIRST_EPOCH" != "$SECOND_EPOCH" ] || { echo "FAIL: epoch not renewed"; exit 1; }
[ -e "$PF_SAMPLER_DIR/epoch-$FIRST_EPOCH.shm" ] || { echo "FAIL: previous epoch reclaimed"; exit 1; }
send s2 20000
"$SMOKE" drain pg0 20000 100 64 02:00:00:00:00:02 30
stop_vpp

echo "== absent: an empty plugin directory"
start_vpp "$WORK/empty"
! plugin_loaded || { echo "FAIL: plugin loaded from an empty directory"; exit 1; }
stop_vpp

echo "== refused: built for another VPP"
start_vpp "$WORK/refused"
! plugin_loaded || { echo "FAIL: VPP loaded a plugin built for another VPP"; exit 1; }
vppctl show version
stop_vpp

echo "smoke: all passed"
