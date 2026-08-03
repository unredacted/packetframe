//! VPP binary-API client (phase 4, slice 3).
//!
//! Three layers, deliberately separated:
//! - [`codec`] — hand-written framing and primitives. The wire's
//!   big-endianness and the per-message header geometry live here and
//!   nowhere else.
//! - [`generated`] — message and type shapes, produced from the
//!   pinned release's `.api.json` by `packetframe-vpp-api-codegen`.
//!   Never edited by hand; CI regenerates and diffs.
//! - [`transport`] — blocking unix socket, handshake, message
//!   table, CRC verification, request/reply correlation.
//!
//! The split exists because the shapes churn with the VPP pin while
//! the framing does not; mixing them would make every pin bump a
//! review of hand-written parsing.
//!
//! # Why not an existing crate
//!
//! Surveyed 2026-08-03. Two real options exist; both were rejected,
//! and the reasons are recorded here so nobody re-runs the search.
//!
//! **`ayourtch/vpp-api`** — `vpp-api-transport` + `vpp-api-gen` and
//! friends, by a VPP core maintainer, so the pedigree is genuine.
//! Rejected on four counts:
//! 1. *Scope is inverted.* `vpp-api-gen` emits the whole API surface
//!    (its companion `latest-vpp-api` ships 89+ modules). We whitelist
//!    22 messages precisely so a CRC change in something we speak is
//!    loud rather than buried in ~900 messages of churn.
//! 2. *Dependency posture.* Wildcard versions (`strum = "*"`,
//!    `log = "*"`, `convert_case = "*"`) defeat our `--locked` builds,
//!    and the encoding crate pulls `minreq` + rustls — an HTTP client
//!    — into a process that supervises a router dataplane.
//! 3. *Pin coupling is backwards.* `latest-vpp-api` tracks VPP master
//!    daily; our whole design is "generate from the PINNED release,
//!    CI regenerate-and-diff". We would end up running the generator
//!    against our own `.api.json` regardless, which is what we do.
//! 4. `shm` is a default feature and links `libvppapiclient.so`. The
//!    plan is socket-only, never SVM from Rust.
//!
//! **`justindthomas/vpp-api`** — async/tokio, MPL-2.0 (GPL-compatible),
//! lean deps. Architecturally the closer fit, but two months old,
//! unpublished, zero external users, and still gaining bindings daily.
//! **Revisit trigger:** if it publishes to crates.io and stabilises,
//! its *transport* layer (not its codegen) is worth reconsidering —
//! that is the part of this module least coupled to our whitelist.
//!
//! What the survey did buy us: the wire facts this client depends on
//! are now triangulated across three independent implementations.
//! govpp, `ayourtch/vpp-api` and `justindthomas/vpp-api` all agree on
//! the 16-byte frame header, big-endian throughout, and the magic
//! `sockclnt_create` id of 15 — the one constant no schema can give
//! us, because it is needed *before* the message table exists.
//!
//! Worth remembering if the question is reopened: neither crate would
//! have prevented the header-geometry bug this module was reviewed
//! for. Both encode from the same `.api.json` we do, and the mistake
//! was in hand-written framing — the layer a library would have
//! replaced. That cuts in both directions honestly.

pub mod codec;
#[rustfmt::skip]
pub mod generated;
pub mod transport;

pub use codec::{Decode, Decoder, Encode, Message, MessageMeta, WireError};
pub use transport::{Transport, TransportError};
