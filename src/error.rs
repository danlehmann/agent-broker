//! The error type of tool calls.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Expected; the message is written for the agent.
    Refused(String),
    /// Unexpected; the detail goes to the daemon's log only.
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Shorthand for an expected refusal.
pub fn refuse<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Refused(message.into()))
}

impl Error {
    /// What the caller is told. Never carries internal detail.
    pub fn public(&self) -> &str {
        match self {
            Error::Refused(m) => m,
            Error::Internal(_) => "internal error in agent-broker; ask the human to check its log",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Refused(m) => f.write_str(m),
            Error::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Internal(format!("database: {e}"))
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Internal(format!("i/o: {e}"))
    }
}
