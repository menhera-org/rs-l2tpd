//! The one error type of the library (spec L11).

/// Every failure the library reports. Non-exhaustive: variants are added
/// compatibly (L3).
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A configuration that cannot be used, with the reason.
    InvalidConfig(String),
    /// A kernel or socket error, with its errno where the kernel gave one.
    Io(std::io::Error),
    /// The reload callback panicked; cleanup was attempted before returning.
    ReloadPanicked,
    /// The restart callback panicked; cleanup was attempted before returning.
    RestartPanicked,
    /// Any other failure, with a message.
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidConfig(msg) => write!(f, "invalid configuration: {msg}"),
            Error::Io(err) => match err.raw_os_error() {
                Some(errno) => write!(f, "{:?}: {err}", nix::errno::Errno::from_raw(errno)),
                None => err.fmt(f),
            },
            Error::ReloadPanicked => f.write_str("reload callback panicked"),
            Error::RestartPanicked => f.write_str("restart callback panicked"),
            Error::Other(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

/// `Result` with the library's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    /// spec: O6, L3
    #[test]
    fn propagated_io_errors_keep_their_errno_name_and_original_source() {
        let error = super::Error::from(std::io::Error::from_raw_os_error(nix::libc::EPERM));
        assert!(error.to_string().starts_with("EPERM: "));
        assert_eq!(
            std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(nix::libc::EPERM)
        );
        assert_eq!(
            super::Error::from(std::io::Error::other("controlled failure")).to_string(),
            "controlled failure"
        );
    }
}
