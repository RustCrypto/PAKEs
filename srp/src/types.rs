//! Additional SRP types.
use num_bigint::BigUint;
use std::{error, fmt};

/// SRP authentication error.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SrpAuthError {
    pub(crate) description: &'static str,
}

impl fmt::Display for SrpAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SRP authentication error")
    }
}

impl error::Error for SrpAuthError {
    fn description(&self) -> &str {
        self.description
    }
}

/// Group used for SRP computations
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SrpGroup {
    /// A large safe prime (N = 2q+1, where q is prime)
    pub n: BigUint,
    /// A generator modulo N
    pub g: BigUint,
}

#[cfg(test)]
mod tests {
    use crate::groups::G_1024;
    use crate::utils::compute_k;
    use sha1::Sha1;

    #[test]
    fn test_k_1024_sha1() {
        let k = compute_k::<Sha1>(&G_1024).to_bytes_be();
        assert_eq!(&k, include_bytes!("test/k_sha1_1024.bin"));
    }
}
