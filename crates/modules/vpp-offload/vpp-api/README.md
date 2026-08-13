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

## Version compatibility — what "works with" means

The version in `SOURCE.json` is the **attested** VPP: the one these
definitions verifiably came from. The **compatible** set is wider and
defined operationally: any VPP whose CRCs for the whitelisted messages
match — the handshake answers that per box, at attach, before a single
route is programmed. Two consequences that are easy to miss:

- **The whitelist is the contract, not the VPP release.** A new VPP
  can change a hundred messages this module never speaks and remain
  fully compatible; compatibility is defined over the ~36 messages the
  module actually uses. This is why the vendored bundle stays a small
  whitelist rather than the whole API surface — every vendored file
  widens what counts as a breaking change.
- **Incompatibility is loud and early, never adaptive.** One build of
  packetframe speaks exactly one wire format. There is no version
  negotiation and no "close enough": a mismatched CRC is refused by
  message name at attach, so an old packetframe against a new VPP (or
  vice versa) fails with a sentence naming the message, not with
  mis-encoded routes.

## When a new VPP version releases

Nothing moves on its own — pins are release tags, and the fleet keeps
running what it runs until someone performs the sequence below.
Adopting a new version has exactly two possible shapes, distinguished
by the `generated.rs` diff at step 3 of the re-vendor:

- **No wire drift** (diff empty): the bump is pure paperwork.
  Existing packetframe binaries already speak the new VPP — the
  handshake passes with either side upgraded first.
- **Wire drift** (diff shows moved fields / changed CRCs): the diff is
  the review surface — it shows exactly which messages changed shape.
  A new packetframe release is required, and existing binaries refuse
  the new VPP by name at attach until it ships.

Rollback in either direction is independent — old release tags stay
published, and VPP's cadence is deliberately decoupled from
packetframe's (this is why VPP was never bundled into packetframe's
.deb).

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
