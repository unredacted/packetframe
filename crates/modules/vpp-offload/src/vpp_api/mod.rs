//! VPP binary-API client (phase 4, slice 3).
//!
//! Three layers, deliberately separated:
//! - [`codec`] — hand-written framing and primitives. The wire's
//!   big-endianness and the request/reply header asymmetry live here
//!   and nowhere else.
//! - [`generated`] — message and type shapes, produced from the
//!   pinned release's `.api.json` by `packetframe-vpp-api-codegen`.
//!   Never edited by hand; CI regenerates and diffs.
//! - the transport (next commit) — socket, handshake, message table.
//!
//! The split exists because the shapes churn with the VPP pin while
//! the framing does not; mixing them would make every pin bump a
//! review of hand-written parsing.

pub mod codec;
#[rustfmt::skip]
pub mod generated;

pub use codec::{Decode, Decoder, Encode, WireError};
