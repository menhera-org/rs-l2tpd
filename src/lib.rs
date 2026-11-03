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

#[cfg(all(test, feature = "serde", feature = "fake-kernel"))]
extern crate self as rs_l2tpd;

// Share the public rule cases with private cases in the same generic instantiation.
#[cfg(all(test, feature = "serde", feature = "fake-kernel"))]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "../tests/rules/main.rs"]
mod rule_tests;

// Child launch must be isolated from concurrent fake descriptor owners.
#[cfg(all(test, coverage_nightly, feature = "serde", feature = "fake-kernel"))]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(unsafe_code)]
#[path = "../tests/startup.rs"]
mod startup_tests;

// Share live cases with private cases in the instrumented library instance.
#[cfg(all(test, coverage_nightly, feature = "serde", feature = "fake-kernel"))]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(unsafe_code)]
#[path = "../tests/kernel/linux.rs"]
mod live_kernel_tests;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "../tests/tools/testdir.rs"]
mod testdir;

#[cfg(test)]
use crate::kernel::linux::syscall_fault;

// Share public service cases with private cases in the instrumented library instance.
#[cfg(all(test, coverage_nightly, feature = "serde", feature = "fake-kernel"))]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "../tests/service.rs"]
mod service_tests;
