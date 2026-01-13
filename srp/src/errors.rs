//! Error types.

use alloc::string::String;
use core::{error, fmt};

/// SRP authentication error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SrpAuthError {
    IllegalParameter(String),
    BadRecordMac(String),
}

impl fmt::Display for SrpAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalParameter(param) => {
                write!(f, "illegal_parameter: bad '{param}' value")
            }
            Self::BadRecordMac(param) => {
                write!(f, "bad_record_mac: incorrect '{param}'  proof")
            }
        }
    }
}

impl error::Error for SrpAuthError {}
