# Vendored VPP API definitions

The `.api.json` files here are the **wire-format source of truth** for
the vpp-offload binary-API codegen: `generated.rs` is produced from
them, and the transport's CRC handshake refuses, at attach time, any
VPP whose messages disagree with what they describe. The module is
generic over VPPs — it does not care who built the one on the router,
only that the CRCs match.

`SOURCE.json` is the provenance: the verbatim `manifest.json` of the
release this bundle was extracted from. Nothing here attests itself —
CI downloads that release's `vpp-api-json.tar.gz` and byte-compares
every vendored file against it (and `SOURCE.json` against the
release's manifest), so a half-done re-vendor cannot merge in either
direction. The whitelist of which files are vendored lives in the
codegen (`crates/tools/vpp-api-codegen`), which loads exact
`<name>.api.json` filenames and therefore ignores `SOURCE.json` and
this README.

Builds for our UniFi fleet publish from
[unredacted/vpp-unifi](https://github.com/unredacted/vpp-unifi); any
release that ships a `vpp-api-json.tar.gz` + `manifest.json` +
`SHA256SUMS` in the same shape would do.

## Re-vendoring (a VPP version bump)

Order matters — the artifact must exist before this repo can bind to
it:

1. Bump the gateway pin in vpp-unifi (`pins/efg.toml`), merge; its CI
   builds, verifies and publishes the new tag (~45 min).
2. Here, from the repo root:

   ```sh
   tag=vpp-<ref>-<platform>-bullseye-arm64
   dir=$(mktemp -d)
   gh release download "$tag" -R unredacted/vpp-unifi -D "$dir" \
     -p vpp-api-json.tar.gz -p manifest.json -p SHA256SUMS
   (cd "$dir" && sha256sum -c SHA256SUMS --ignore-missing)
   mkdir "$dir/api" && tar xzf "$dir/vpp-api-json.tar.gz" -C "$dir/api"
   for f in crates/modules/vpp-offload/vpp-api/*.api.json; do
     cp "$(find "$dir/api" -name "$(basename "$f")")" "$f"
   done
   cp "$dir/manifest.json" crates/modules/vpp-offload/vpp-api/SOURCE.json
   cargo run -p packetframe-vpp-api-codegen -- \
     crates/modules/vpp-offload/vpp-api \
     crates/modules/vpp-offload/src/vpp_api/generated.rs
   ```

3. Commit all of it together. Read the `generated.rs` diff — a moved
   field is a wire-format change and deserves a look, not a rubber
   stamp. CI re-runs the byte-binding and the regenerate-and-diff.

No cross-version adoption on routers: upgrading a box is
detach → install → attach (see `docs/runbooks/vpp-offload.md`).
