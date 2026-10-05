//! The PacketFrame VPP sampler plugin's logic, kept free of VPP.
//!
//! The plugin itself (`crates/vpp-plugins/pf-sampler`, a cdylib built
//! against one VPP's headers) is glue: its node calls [`pass::advance`],
//! [`select::Selector`] and the rings, its process node calls [`driver::Driver::tick`], and it
//! implements [`control::Vpp`] and [`driver::Host`] with VPP's barrier and
//! feature calls. Everything that decides anything lives here, where it is
//! tested on any host without VPP.

pub mod control;
#[cfg(target_os = "linux")]
pub mod driver;
pub mod pass;
pub mod pools;
pub mod select;
