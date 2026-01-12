//! Additional SRP types.

use alloc::string::String;
use core::{error, fmt};
use crypto_bigint::{
    BoxedUint, Odd, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};

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

/// Group used for SRP computations
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SrpGroup {
    /// A large safe prime (N = 2q+1, where q is prime)
    pub n: BoxedMontyParams,
    /// A generator modulo N
    pub g: BoxedMontyForm,
}

impl SrpGroup {
    /// Initialize a new group from the given boxed integers.
    pub fn new(n: BoxedUint, g: BoxedUint) -> Self {
        let n = BoxedMontyParams::new(Odd::new(n).expect("n should be odd"));
        let g = BoxedMontyForm::new(g.resize(n.bits_precision()), &n);
        Self { n, g }
    }
}

#[cfg(test)]
mod tests {
    use crate::groups::G_1024;
    use crate::utils::compute_k;
    use sha1::Sha1;

    #[test]
    fn test_k_1024_sha1() {
        let k = compute_k::<Sha1>(&G_1024).to_be_bytes_trimmed_vartime();
        assert_eq!(&*k, include_bytes!("test/k_sha1_1024.bin"));
    }
}
