//! Library behind the `rs-l2tpd` daemon: a reconciling controller for
//! kernel L2TPv3 tunnels and Ethernet pseudowire sessions on Linux.
//!
//! Use [`service::Service`] in Tokio, [`blocking::Service`] in synchronous
//! programs, or [`runtime::Runtime`] to drive the event loop yourself.
//! Configuration is format-independent; process policy belongs to the caller.
//!
//! ```no_run
//! use rs_l2tpd::{blocking::Service, config::Config};
//! # fn example() -> rs_l2tpd::Result<()> {
//! let mut service = Service::new(Config::new(), vec![]).map_err(|(e, _)| e)?;
//! service.converge()?;
//! // An application normally requests this from its shutdown adapter.
//! service.control().shutdown();
//! service.run(Ok, |_| Ok(()))?;
//! # Ok(()) }
//! ```
//!
//! - [`config`]: the configuration types and conversions (spec C1–C17).
//! - [`kernel`]: the one boundary to the host, with a fake for tests.
//! - [`reconciler`]: the policy: planning, applying, events, timers.
//! - [`runtime`], [`service`], [`blocking`]: what a program drives.

#![cfg(target_os = "linux")]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
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
pub use runtime::{AdoptedSocket, Control, ControlEvent, Runtime};
