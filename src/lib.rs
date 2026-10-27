//! Library behind the `rs-l2tpd` daemon: a reconciling controller for
//! kernel L2TPv3 tunnels and Ethernet pseudowire sessions on Linux.
//!
//! The crate is organised in layers, from the outside in:
//!
//! - [`config`] describes the desired tunnels and sessions. It is built in
//!   code, or deserialised with serde when the `serde` feature is on.
//! - [`service::Service`] is the whole daemon minus process management: it
//!   applies a configuration, retries transient kernel failures, reloads and
//!   reacts to DNS, link and address changes until it is told to shut down.
//!   [`blocking::Service`] is the same for programs without Tokio.
//! - [`runtime::Runtime`] is the reconciler underneath, for programs that
//!   want to drive the event loop themselves.
//!
//! The library does no file or terminal I/O and installs no signal
//! handlers; it logs through the [`log`] facade. The `rs-l2tpd` binary adds
//! configuration files, logging output, signals, daemonisation, the PID
//! file and the optional `--setup` installer on top.
//!
//! Every type from another crate that appears in this API is re-exported
//! next to where it is used, so no dependency of a matching version is
//! needed to name it: [`config::IpHost`] and [`config::FQDN`] (the remote
//! endpoint), [`config::L2tpIfName`] and [`config::L2tpIfNameExt`]
//! (interface names), [`error::L2tpError`] (the kernel-level error) and
//! [`runtime::mpsc`] (the channel a [`runtime::Runtime`] is driven from).
//!
//! Everything here needs `CAP_NET_ADMIN` (and `CAP_NET_RAW` for binding
//! sockets to devices) and a kernel with `l2tp_ip6` and `l2tp_eth`.
//!
//! # Example
//!
//! ```no_run
//! use rs_l2tpd::blocking::{Service, Startup};
//! use rs_l2tpd::config::{Config, IpVersion, SessionConfig, TunnelConfig};
//!
//! # fn run() -> rs_l2tpd::Result<()> {
//! let mut config = Config::new();
//! config.insert_tunnel(
//!     "uplink",
//!     TunnelConfig::new(10, IpVersion::V6, "peer.example.org".parse().unwrap()),
//! )?;
//! config.insert_session(
//!     "lan",
//!     SessionConfig::new("uplink", 100, "l2tp0".parse().unwrap()),
//! )?;
//!
//! let mut service = Service::new(config.clone())?;
//! let control = service.control();
//! // Call control.reload() or control.shutdown() from a signal handler,
//! // another thread, or wherever such requests originate.
//! if service.converge()? == Startup::Converged {
//!     service.run(move || Ok(config.clone()))?;
//! }
//! # let _ = control;
//! # Ok(())
//! # }
//! ```

#![cfg(target_os = "linux")]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod blocking;
pub mod config;
pub mod error;
mod netlink;
pub mod runtime;
pub mod service;
mod state;

pub use error::{Error, Result};
