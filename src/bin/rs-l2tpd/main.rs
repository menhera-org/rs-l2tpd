//! The `rs-l2tpd` binary: the process around the library (spec P1–P27,
//! O1, O7, O8; `docs/architecture.md`, `bin/`). Filled in phase 5.

mod args;
mod caps;
mod check;
mod daemon;
mod fdstore;
mod files;
mod logger;
mod pidfile;
mod restart;
mod signals;
mod tunable;

fn main() -> std::process::ExitCode {
    // shortcut: the rewrite is in phase 0; the binary exists so that the
    // crate's targets and features build. Replaced in phase 5.
    eprintln!("rs-l2tpd: the rewrite is in progress; this build does nothing");
    std::process::ExitCode::from(2)
}
