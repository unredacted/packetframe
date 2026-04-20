//! PacketFrame common crate.
//!
//! Shared types used across userspace crates:
//! - [`config`]: line-based config parser (see SPEC.md §6)
//! - [`module`]: the [`Module`] trait and support types (see SPEC.md §3.2)
//! - [`probe`]: kernel capability probes (see SPEC.md §2.1)

pub mod config;
pub mod module;
pub mod probe;

pub use config::{Config, ConfigError, GlobalConfig, ModuleSection};
pub use module::{
    Attachment, HealthCtx, HookType, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
};
pub use probe::{Capability, CapabilityStatus, FeasibilityReport};
