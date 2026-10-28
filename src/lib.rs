//! Library behind the `rs-l2tpd` daemon: a reconciling controller for
//! kernel L2TPv3 tunnels and Ethernet pseudowire sessions on Linux.
//!
//! The crate is being rewritten against `docs/spec`; the module tree is
//! the one of `docs/architecture.md`, filled in phase by phase
//! (`docs/plan.md`). Until a module is filled, it is empty.
//!
//! - [`config`]: the configuration types and conversions (spec C1–C17).
//! - [`kernel`]: the one boundary to the host, with a fake for tests.
//! - [`reconciler`]: the policy: planning, applying, events, timers.
//! - [`runtime`], [`service`], [`blocking`]: what a program drives.

#![cfg(target_os = "linux")]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod blocking;
pub mod config;
pub mod error;
pub mod kernel;
pub mod reconciler;
pub mod runtime;
pub mod service;

pub use error::{Error, Result};
