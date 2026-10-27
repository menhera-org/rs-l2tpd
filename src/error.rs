//! The error type shared by every part of the library.

use std::fmt::Display;

/// The error type of the `l2tp` crate, carried by [`Error::L2tp`].
/// Re-exported so that it can be matched on without a dependency of a
/// matching version.
pub use l2tp::Error as L2tpError;

/// Errors reported by the library.
///
/// The enum is `#[non_exhaustive]`: more variants may be added in a minor
/// release, so always keep a wildcard arm when matching on it.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The configuration is syntactically or semantically invalid.
    InvalidConfig(String),
    /// The kernel L2TP subsystem or the tunnel socket reported an error.
    L2tp(L2tpError),
    /// Any other failure, with a human-readable description.
    Other(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Error::L2tp(err) => write!(f, "{err}"),
            Error::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::L2tp(err) => Some(err),
            _ => None,
        }
    }
}

impl From<L2tpError> for Error {
    fn from(err: L2tpError) -> Self {
        Error::L2tp(err)
    }
}

/// A `Result` whose error type is [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
