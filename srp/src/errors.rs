//! Error types.

use core::{error, fmt};

/// SRP authentication error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AuthError {
    IllegalParameter {
        /// Parameter name
        name: &'static str,
    },
    BadRecordMac {
        /// Which peer's proof is invalid
        peer: &'static str,
    },
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalParameter { name } => {
                write!(f, "illegal_parameter: bad '{name}' value")
            }
            Self::BadRecordMac { peer } => {
                write!(f, "bad_record_mac: incorrect '{peer}' proof")
            }
        }
    }
}

impl error::Error for AuthError {}
