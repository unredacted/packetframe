//! Custom-FIB userspace subsystem (Option F).
//!
//! Phase 1 Slice 1A: type mirrors only (`types`). The XDP dispatch path
//! lands in Slice 1B; the BMP station, neighbor resolver, and fib
//! programmer land in Phases 2-3.
//!
//! Trait shapes shared with future modules live in
//! `crates/common/src/fib/` (Phase 1 Slice 1C). Concrete impls of
//! those traits live here.

pub mod hash;
pub mod types;

#[cfg(target_os = "linux")]
pub mod controller;

#[cfg(target_os = "linux")]
pub mod inspect;

#[cfg(target_os = "linux")]
pub mod netlink_neigh;

#[cfg(target_os = "linux")]
pub mod programmer;

#[cfg(target_os = "linux")]
pub mod route_source_bmp;

pub use types::{
    EcmpGroup, FibValue, FpFibCfg, NexthopEntry, ECMP_NH_UNUSED, FIB_KIND_ECMP, FIB_KIND_SINGLE,
    MAX_ECMP_PATHS, NH_FAMILY_V4, NH_FAMILY_V6, NH_STATE_FAILED, NH_STATE_INCOMPLETE,
    NH_STATE_RESOLVED, NH_STATE_STALE,
};
