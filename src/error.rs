use std::fmt::Display;

use l2tp::Error as L2tpError;

#[derive(Debug)]
pub(crate) enum Error {
    InvalidConfig(String),
    L2tp(L2tpError),
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

impl std::error::Error for Error {}

pub(crate) type Result<T> = std::result::Result<T, Error>;
