//! Additional SRP types.
use digest::Digest;
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

impl SrpGroup {
    pub(crate) fn powm(&self, v: &BigUint) -> BigUint {
        self.g.modpow( v, &self.n)
    }

    /// Compute `k` with given hash function and return SRP parameters
    pub(crate) fn compute_k<D: Digest>(&self) -> BigUint {
        let n = self.n.to_bytes_be();
        let g_bytes = self.g.to_bytes_be();
        let mut buf = vec![0u8; n.len()];
        let l = n.len() - g_bytes.len();
        buf[l..].copy_from_slice(&g_bytes);

        let mut d = D::new();
        d.update(&n);
        d.update(&buf);
        BigUint::from_bytes_be(&d.finalize().as_slice())
    }

    /// Compute `Hash(N) xor Hash(g)` with given hash function and return SRP parameters
    pub(crate) fn compute_hash_n_xor_hash_g<D: Digest>(&self) -> Vec<u8> {
        let n = self.n.to_bytes_be();
        let g_bytes = self.g.to_bytes_be();
        let mut buf = vec![0u8; n.len()];
        let l = n.len() - g_bytes.len();
        buf[l..].copy_from_slice(&g_bytes);

        let mut d = D::new();
        d.update(&n);
        let h = d.finalize_reset();
        let h_n: &[u8] = h.as_slice();
        d.update(&buf);
        let h = d.finalize_reset();
        let h_g: &[u8] = h.as_slice();

        h_n.iter()
            .zip(h_g.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::groups::G_1024;
    use sha1::Sha1;

    #[test]
    fn test_k_1024_sha1() {
        let k = G_1024.compute_k::<Sha1>().to_bytes_be();
        assert_eq!(&k, include_bytes!("k_sha1_1024.bin"));
    }
}
