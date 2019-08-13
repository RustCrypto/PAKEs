//! Additional SRP types.
use crate::tools::powm;
use digest::Digest;
use num::bigint::Sign;
use num::BigInt;
use std::{error, fmt};

/// SRP authentification error.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SrpAuthError {
    pub(crate) description: &'static str,
}

impl fmt::Display for SrpAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SRP authentification error")
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
    pub n: BigInt,
    /// A generator modulo N
    pub g: BigInt,
}

impl SrpGroup {
    pub(crate) fn powm(&self, v: &BigInt) -> BigInt {
        powm(&self.g, v, &self.n)
    }

    /// Compute `k` with given hash function and return SRP parameters
    pub(crate) fn compute_k<D: Digest>(&self) -> BigInt {
        let n = self.n.to_bytes_be().1;
        let g = self.g.to_bytes_be().1;

        let mut d = D::new();
        d.input(&n);
        d.input(&g);
        BigInt::from_bytes_be(Sign::Plus, &d.result())
    }
}

#[cfg(test)]
mod tests {
    // use crate::groups::G_1024;
    // use sha1::Sha1;

    // #[test]
    // fn test_k_1024_sha1() {
    //     let k = G_1024.compute_k::<Sha1>().to_bytes_be().1;
    //     assert_eq!(&k, include_bytes!("k_sha1_1024.bin"));
    // }
}
