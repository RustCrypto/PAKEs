//! Group trait.

use alloc::vec::Vec;
use rand_core::{CryptoRng, Rng};

/// Group trait.
// TODO(tarcieri): replace with `group` crate?
pub trait Group {
    /// Scalar element
    type Scalar;

    /// Base field element
    type Element;

    /// Transcript hash
    type TranscriptHash;

    /// Name
    fn name() -> &'static str;

    /// `m` constant
    fn const_m() -> Self::Element;

    /// `n` constant
    fn const_n() -> Self::Element;

    /// `s` constant
    fn const_s() -> Self::Element;

    /// Hash to scalar
    fn hash_to_scalar(s: &[u8]) -> Self::Scalar;

    /// Generate a random scalar
    fn random_scalar<T>(cspring: &mut T) -> Self::Scalar
    where
        T: Rng + CryptoRng;

    /// Scalar negation
    fn scalar_neg(s: &Self::Scalar) -> Self::Scalar;

    /// Convert base field element to bytes
    fn element_to_bytes(e: &Self::Element) -> Vec<u8>;

    /// Convert bytes to base field element
    fn bytes_to_element(b: &[u8]) -> Option<Self::Element>;

    /// Length of a base field element
    fn element_length() -> usize;

    /// Fixed-base scalar multiplication
    fn basepoint_mult(s: &Self::Scalar) -> Self::Element;

    /// Variable-base scalar multiplication
    fn scalarmult(e: &Self::Element, s: &Self::Scalar) -> Self::Element;

    /// Group operation
    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element;
}
