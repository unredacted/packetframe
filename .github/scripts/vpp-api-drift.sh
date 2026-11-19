#!/usr/bin/env bash
# Does a candidate VPP speak the binary API this checkout was generated for?
#
#   .github/scripts/vpp-api-drift.sh <vpp-api-json.tar.gz>
#
# Takes the .api.json files vendored under crates/modules/vpp-offload/vpp-api
# from the candidate's bundle instead, runs the codegen, and compares the
# result with the committed generated.rs. Identical: every message
# vpp-offload speaks has the same shape and CRC, so this checkout's
# binaries attach to the candidate (the handshake at attach checks the same
# CRCs). Different: the candidate changed a message vpp-offload speaks, and
# it needs a re-vendor (and a PacketFrame release) before any gateway can
# run it. A vendored file missing from the bundle fails too.
#
# Run from the repo root. unredacted/vpp-unifi runs it on every VPP it is
# about to publish; see crates/modules/vpp-offload/vpp-api/README.md.
set -euo pipefail

bundle=${1:?usage: $0 <vpp-api-json.tar.gz>}
vendored=crates/modules/vpp-offload/vpp-api
generated=crates/modules/vpp-offload/src/vpp_api/generated.rs
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bundle" "$work/api"

tar xzf "$bundle" -C "$work/bundle"
for f in "$vendored"/*.api.json; do
  name=$(basename "$f")
  src=$(find "$work/bundle" -name "$name" -print -quit)
  [ -n "$src" ] || { echo "::error::$name is vendored here but absent from the candidate's API bundle"; exit 1; }
  cp "$src" "$work/api/$name"
done

cargo run -q -p packetframe-vpp-api-codegen -- "$work/api" "$work/generated.rs"

if ! diff -u "$generated" "$work/generated.rs" > "$work/drift.diff"; then
  echo "::error::wire drift: the candidate VPP changed messages vpp-offload speaks, so this PacketFrame would refuse it at attach. Re-vendor against it first (crates/modules/vpp-offload/vpp-api/README.md)."
  head -200 "$work/drift.diff"
  exit 1
fi
echo "no wire drift: generated.rs regenerates byte-identical from the candidate's $(ls "$work/api" | wc -l | tr -d " ") vendored .api.json files"
