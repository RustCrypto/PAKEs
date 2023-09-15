use digest::{Digest, Output};
use num_bigint::BigUint;

use crate::types::SrpGroup;

// u = H(PAD(A) | PAD(B))
#[must_use]
pub fn compute_u<D: Digest>(a_pub: &[u8], b_pub: &[u8]) -> BigUint {
    let mut u = D::new();
    u.update(a_pub);
    u.update(b_pub);
    BigUint::from_bytes_be(&u.finalize())
}

// k = H(N | PAD(g))
#[must_use]
pub fn compute_k<D: Digest>(params: &SrpGroup) -> BigUint {
    let n = params.n.to_bytes_be();
    let g_bytes = params.g.to_bytes_be();
    let mut buf = vec![0u8; n.len()];
    let l = n.len() - g_bytes.len();
    buf[l..].copy_from_slice(&g_bytes);

    let mut d = D::new();
    d.update(&n);
    d.update(&buf);
    BigUint::from_bytes_be(d.finalize().as_slice())
}

// H(N) XOR H(PAD(g))
#[must_use]
pub fn compute_hash_n_xor_hash_g<D: Digest>(params: &SrpGroup) -> Vec<u8> {
    let n = params.n.to_bytes_be();
    let g_bytes = params.g.to_bytes_be();
    let mut buf = vec![0u8; n.len()];
    let l = n.len() - g_bytes.len();
    buf[l..].copy_from_slice(&g_bytes);

    let h_n = compute_hash::<D>(&n).to_vec();
    let h_g = compute_hash::<D>(&buf).to_vec();

    h_n.iter()
        .zip(h_g.iter())
        .map(|(&x1, &x2)| x1 ^ x2)
        .collect()
}

// M1 = H(A, B, K) this doesn't follow the spec but apparently no one does for M1
#[must_use]
pub fn compute_m1<D: Digest>(a_pub: &[u8], b_pub: &[u8], key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(a_pub);
    d.update(b_pub);
    d.update(key);
    d.finalize()
}

#[must_use]
pub fn compute_hash<D: Digest>(data: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(data);
    d.finalize()
}

// M1 = H(H(N) XOR H(g) | H(U) | s | A | B | K) this follows the spec
#[must_use]
pub fn compute_m1_std<D: Digest>(
    params: &SrpGroup,
    username: &[u8],
    salt: &[u8],
    a_pub: &[u8],
    b_pub: &[u8],
    key: &[u8],
) -> Output<D> {
    let mut d = D::new();
    d.update(compute_hash_n_xor_hash_g::<D>(params));
    d.update(compute_hash::<D>(username));
    d.update(salt);
    d.update(a_pub);
    d.update(b_pub);
    d.update(key);
    d.finalize()
}

// M2 = H(A, M1, K)
#[must_use]
pub fn compute_m2<D: Digest>(a_pub: &[u8], m1: &Output<D>, key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(a_pub);
    d.update(m1);
    d.update(key);
    d.finalize()
}
