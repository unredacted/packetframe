//! PacketFrame common crate.
//!
//! Shared types used across userspace crates:
//! - [`config`]: line-based config parser (see SPEC.md §6)
//! - [`ethtool`]: NIC interrupt coalescing over `SIOCETHTOOL`
//! - [`module`]: the [`Module`] trait and support types (see SPEC.md §3.2)
//! - [`probe`]: kernel capability probes (see SPEC.md §2.1)

pub mod config;
pub mod ethtool;
pub mod fib;
#[cfg(feature = "frr")]
pub mod frr;
pub mod module;
pub mod probe;
#[cfg(target_os = "linux")]
pub mod statefile;

pub use config::{Config, ConfigError, GlobalConfig, ModuleSection};
pub use module::{
    Attachment, HealthCtx, HealthReport, HookType, HookUse, LoaderCtx, MetricsWriter, Module,
    ModuleConfig, SubsystemHealth,
};
pub use probe::{Capability, CapabilityStatus, FeasibilityReport};
