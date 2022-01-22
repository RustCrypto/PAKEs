//! Error types.

use core::fmt;

/// [`Result`][`core::result::Result`] type with `spake2`'s [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// SPAKE2 errors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Bad side
    BadSide,

    /// Corrupt message
    CorruptMessage,

    /// Wrong length
    WrongLength,
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSide => fmt.write_str("bad side"),
            Error::CorruptMessage => fmt.write_str("corrupt message"),
            Error::WrongLength => fmt.write_str("invalid length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
