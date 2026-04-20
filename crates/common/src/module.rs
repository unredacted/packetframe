//! Module trait and support types (SPEC.md §3.2).
//!
//! v0.0.1 defines the shapes without populating the runtime. Contexts
//! (`LoaderCtx`, `HealthCtx`, `MetricsWriter`) carry only what v0.0.1 needs;
//! v0.1 grows the bpffs handle, pin registry, counter snapshots, etc.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::config::{GlobalConfig, ModuleSection};

pub type ModuleResult<T> = std::result::Result<T, ModuleError>;

#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("module `{module}`: {message}")]
    Other { module: String, message: String },

    #[error("module `{module}`: not implemented in v0.0.1")]
    NotImplemented { module: String },
}

impl ModuleError {
    pub fn other(module: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Other {
            module: module.into(),
            message: message.into(),
        }
    }

    pub fn not_implemented(module: impl Into<String>) -> Self {
        Self::NotImplemented {
            module: module.into(),
        }
    }
}

/// Hook taxonomy from SPEC.md §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookType {
    NativeXdp,
    GenericXdp,
    TcIngress,
    TcEgress,
}

/// A single hook use declared by a module. Priority ordering per SPEC.md §3.2
/// (lower = runs earlier under the future dispatcher). In v0.0.1 with a
/// single-module deployment, priorities are recorded but not consulted —
/// SPEC.md §3.4.
#[derive(Debug, Clone, Copy)]
pub struct HookUse {
    pub hook: HookType,
    pub priority: u16,
}

/// Concrete attachment a module returns from `attach`. The loader records
/// these in the pin registry so `detach` / `detach --all` can tear them
/// down deterministically. Paths point inside `bpffs_root`.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub iface: String,
    pub hook: HookType,
    pub prog_id: u32,
    pub pinned_path: PathBuf,
}

/// Slice of the parsed config relevant to a specific module. Borrows from the
/// top-level [`Config`][crate::config::Config] so the loader can pass each
/// module its directives plus the shared global block without copying.
#[derive(Debug)]
pub struct ModuleConfig<'a> {
    pub section: &'a ModuleSection,
    pub global: &'a GlobalConfig,
}

impl<'a> ModuleConfig<'a> {
    pub fn new(section: &'a ModuleSection, global: &'a GlobalConfig) -> Self {
        Self { section, global }
    }
}

/// Loader-side context available during `Module::load` / `Module::attach`.
/// v0.0.1 carries paths only; v0.1 adds an aya `Bpf` handle, pin registry
/// reference, and ringbuf-drain registration.
#[derive(Debug)]
pub struct LoaderCtx<'a> {
    pub bpffs_root: &'a Path,
    pub state_dir: &'a Path,
}

/// Context supplied to `Module::health_check` when circuit breakers evaluate.
/// v0.0.1 is empty — populated with per-counter deltas in v0.1.
#[derive(Debug, Default)]
pub struct HealthCtx {
    // Deliberately empty until v0.1 wires in counter samples.
    _private: (),
}

impl HealthCtx {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

/// Destination for Prometheus textfile emission from
/// `Module::sample_metrics`. In v0.0.1 this wraps a `String` the loader
/// flushes; v0.1 adds labels, timestamps, and the textfile atomic-rename.
#[derive(Debug)]
pub struct MetricsWriter<'a> {
    pub out: &'a mut String,
    pub module: &'a str,
}

impl<'a> MetricsWriter<'a> {
    pub fn new(out: &'a mut String, module: &'a str) -> Self {
        Self { out, module }
    }
}

/// Every PacketFrame module implements this. The shape is stable across
/// modules so the loader can drive them polymorphically; see SPEC.md §3.2 for
/// the per-method contract (notably: `detach` must complete in under 1s, and
/// `reconfigure` must not reload programs — only mutate maps).
pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;

    fn hook_spec(&self) -> Vec<HookUse>;

    fn load(&mut self, cfg: &ModuleConfig<'_>, ctx: &LoaderCtx<'_>) -> ModuleResult<()>;

    fn attach(&mut self, cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>>;

    fn reconfigure(&mut self, cfg: &ModuleConfig<'_>) -> ModuleResult<()>;

    fn detach(&mut self) -> ModuleResult<()>;

    fn sample_metrics(&self, out: &mut MetricsWriter<'_>) -> ModuleResult<()>;

    fn health_check(&self, ctx: &HealthCtx) -> ModuleResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyModule;

    impl Module for DummyModule {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn hook_spec(&self) -> Vec<HookUse> {
            vec![HookUse {
                hook: HookType::NativeXdp,
                priority: 1000,
            }]
        }
        fn load(&mut self, _: &ModuleConfig<'_>, _: &LoaderCtx<'_>) -> ModuleResult<()> {
            Ok(())
        }
        fn attach(&mut self, _: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
            Ok(vec![])
        }
        fn reconfigure(&mut self, _: &ModuleConfig<'_>) -> ModuleResult<()> {
            Ok(())
        }
        fn detach(&mut self) -> ModuleResult<()> {
            Ok(())
        }
        fn sample_metrics(&self, _: &mut MetricsWriter<'_>) -> ModuleResult<()> {
            Ok(())
        }
        fn health_check(&self, _: &HealthCtx) -> ModuleResult<()> {
            Ok(())
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let boxed: Box<dyn Module> = Box::new(DummyModule);
        assert_eq!(boxed.name(), "dummy");
        assert_eq!(boxed.hook_spec().len(), 1);
    }
}
