//! Reporting (O2–O6): a lasting condition is reported once when it begins
//! and once when it ends, keyed by the entry and the condition; kernel
//! errors carry their errno names; cookies never appear.

use std::collections::BTreeMap;
use std::io;

/// Open episodes; true means their error-level report was emitted.
#[derive(Default)]
pub(crate) struct Report {
    open: BTreeMap<(String, &'static str), bool>,
}

impl Report {
    pub fn cannot_create(&mut self, entry: &str, condition: &'static str, error: &io::Error) {
        let message = || format!("cannot be created: {}", describe(error));
        match error.raw_os_error().map(nix::errno::Errno::from_raw) {
            Some(
                nix::errno::Errno::EPERM
                | nix::errno::Errno::EACCES
                | nix::errno::Errno::EPROTONOSUPPORT
                | nix::errno::Errno::EOPNOTSUPP,
            ) => {
                self.begin_error(entry, condition, message);
            }
            _ => self.begin(entry, condition, message),
        }
    }

    /// Reports `message` at warning level unless the episode is open.
    pub fn begin(
        &mut self,
        entry: &str,
        condition: &'static str,
        message: impl FnOnce() -> String,
    ) {
        if let std::collections::btree_map::Entry::Vacant(slot) =
            self.open.entry((entry.to_owned(), condition))
        {
            slot.insert(false);
            log::warn!("{entry}: {}", message());
        } else {
            log::debug!("{entry}: {}", message());
        }
    }

    /// Like [`begin`](Self::begin), at error level (host defects, M13).
    pub fn begin_error(
        &mut self,
        entry: &str,
        condition: &'static str,
        message: impl FnOnce() -> String,
    ) {
        if !std::mem::replace(
            self.open.entry((entry.to_owned(), condition)).or_default(),
            true,
        ) {
            log::error!("{entry}: {}", message());
        }
    }

    /// Ends the episode with an information message, if it was open.
    pub fn end(&mut self, entry: &str, condition: &'static str, message: impl FnOnce() -> String) {
        if self.open.remove(&(entry.to_owned(), condition)).is_some() {
            log::info!("{entry}: {}", message());
        }
    }

    /// Ends the episode silently, the caller having reported the success.
    pub fn forget_condition(&mut self, entry: &str, condition: &'static str) {
        self.open.remove(&(entry.to_owned(), condition));
    }

    #[cfg(test)]
    pub fn is_open(&self, entry: &str, condition: &'static str) -> bool {
        self.open.contains_key(&(entry.to_owned(), condition))
    }

    /// Forgets every episode of an entry that left the configuration or
    /// changed (O3).
    pub fn forget(&mut self, entry: &str) {
        self.open.retain(|(e, _), _| e != entry);
    }
}

/// An error with its errno name first (O6): `EEXIST: File exists`.
pub(crate) fn describe(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(errno) => {
            let name = nix::errno::Errno::from_raw(errno);
            format!("{name:?}: {}", name.desc())
        }
        None => error.to_string(),
    }
}

/// How messages name a tunnel (O4).
pub(crate) fn tunnel(name: &str, tunnel_id: u32) -> String {
    format!("tunnel {name} (tunnel_id={tunnel_id})")
}

/// How messages name a session (O4).
pub(crate) fn session(name: &str, tunnel_id: u32, session_id: u32) -> String {
    format!("session {name} (tunnel_id={tunnel_id}, session_id={session_id})")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// spec: O6
    #[test]
    fn errors_carry_their_errno_names() {
        let text = describe(&io::Error::from_raw_os_error(nix::libc::EEXIST));
        assert!(text.starts_with("EEXIST: "), "{text}");
    }

    /// spec: O3
    #[test]
    fn an_episode_is_reported_once() {
        let mut report = Report::default();
        report.begin("tunnel a", "pending", String::new);
        assert!(report.is_open("tunnel a", "pending"));
        report.begin("tunnel a", "pending", String::new);
        report.end("tunnel a", "pending", String::new);
        assert!(!report.is_open("tunnel a", "pending"));
    }
}
