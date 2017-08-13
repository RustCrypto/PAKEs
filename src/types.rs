//! Additional SRP types.
use std::{fmt, error};
use num::BigUint;
use tools::powm;

/// SRP authentification error.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SrpAuthError {
    pub(crate) description: &'static str
}

impl fmt::Display for SrpAuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SRP authentification error")
    }
}

impl error::Error for SrpAuthError {
    fn description(&self) -> &str {
        self.description
    }
}

/// Parameters of SRP shared between client and server.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SrpParams {
    /// A large safe prime (N = 2q+1, where q is prime)
    pub n: BigUint,
    /// A generator modulo N (e.g. 2)
    pub g: BigUint,
    /// Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
    pub k: BigUint,
}

impl SrpParams {
    pub(crate) fn powm(&self, v: &BigUint) -> BigUint {
        powm(&self.g, v, &self.n)
    }
}
