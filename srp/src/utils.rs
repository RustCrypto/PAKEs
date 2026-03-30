use alloc::vec::Vec;
use bigint::{
    BoxedUint, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use digest::{Digest, Output};

/// `u = H(PAD(A) | PAD(B))`
#[must_use]
pub fn compute_u<D: Digest>(a_pub: &[u8], b_pub: &[u8]) -> BoxedUint {
    let mut u = D::new();
    u.update(a_pub);
    u.update(b_pub);
    BoxedUint::from_be_slice_vartime(&u.finalize())
}

/// `k = H(N | PAD(g))`
#[must_use]
pub fn compute_k<D: Digest>(g: &BoxedMontyForm) -> BoxedUint {
    let n = g.params().modulus().to_be_bytes();
    let g_bytes = g.retrieve().to_be_bytes();
    let mut buf = vec![0u8; n.len()];
    let l = n.len() - g_bytes.len();
    buf[l..].copy_from_slice(&g_bytes);

    let mut d = D::new();
    d.update(&n);
    d.update(&buf);
    BoxedUint::from_be_slice_vartime(d.finalize().as_slice())
}

/// `H(N) XOR H(PAD(g))`
#[must_use]
pub fn compute_hash_n_xor_hash_g<D: Digest>(g: &BoxedMontyForm) -> Vec<u8> {
    let n = g.params().modulus().to_be_bytes();
    let g_bytes = g.retrieve().to_be_bytes();
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

#[must_use]
pub fn compute_hash<D: Digest>(data: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(data);
    d.finalize()
}

/// `M1 = H(H(N) XOR H(g) | H(U) | s | A | B | K)` following RFC5054
#[must_use]
pub fn compute_m1_rfc5054<D: Digest>(
    g: &BoxedMontyForm,
    username: &[u8],
    salt: &[u8],
    a_pub: &[u8],
    b_pub: &[u8],
    key: &[u8],
) -> Output<D> {
    let mut d = D::new();
    d.update(compute_hash_n_xor_hash_g::<D>(g));
    d.update(compute_hash::<D>(username));
    d.update(salt);
    d.update(a_pub);
    d.update(b_pub);
    d.update(key);
    d.finalize()
}

/// `M1 = H(A, B, K)`
#[must_use]
pub fn compute_m1_legacy<D: Digest>(a_pub: &[u8], b_pub: &[u8], key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(a_pub);
    d.update(b_pub);
    d.update(key);
    d.finalize()
}

/// `M2 = H(A, M1, K)`
#[must_use]
pub fn compute_m2<D: Digest>(a_pub: &[u8], m1: &Output<D>, key: &[u8]) -> Output<D> {
    let mut d = D::new();
    d.update(a_pub);
    d.update(m1);
    d.update(key);
    d.finalize()
}

/// Convert the given value into Montgomery form, resizing it in the process.
/// Convert an integer into the Montgomery domain, returning a [`BoxedMontyForm`] modulo `N`.
pub(crate) fn monty_form(x: &BoxedUint, n: &BoxedMontyParams) -> BoxedMontyForm {
    let precision = n.modulus().bits_precision();
    BoxedMontyForm::new(x.resize(precision), n)
}
