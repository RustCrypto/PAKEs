//! Password derivation and integer encodings for public values and proofs.

use crate::{
    AuthError,
    utils::{compute_m1_rfc5054, compute_m2},
};
use alloc::borrow::Cow;
use bigint::{BitOps, BoxedUint, Resize, modular::BoxedMontyForm};
use digest::{Digest, Output};

/// Unsigned big-endian encoding of an integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerEncoding {
    /// Remove leading zero bytes, as in [RFC 2945 section 2]'s integer conversion.
    ///
    /// [RFC 2945 section 2]: https://www.rfc-editor.org/rfc/rfc2945.html#section-2
    Minimal,
    /// Left-pad to the modulus width, as in [RFC 5054 section 2.1]'s `PAD()` operation.
    ///
    /// [RFC 5054 section 2.1]: https://www.rfc-editor.org/rfc/rfc5054.html#section-2.1
    Padded,
}

/// Password-derivation and encoding choices for SRP-6a and RFC 2945-style proofs.
///
/// Configure both peers consistently. These options do not change the SRP-6a
/// computations `k = H(N | PAD(g))` and `u = H(PAD(A) | PAD(B))`, or the session
/// key `K = H(MIN(S))`. Salt and digest bytes are always preserved.
///
/// [RFC 2945 section 3] supplies the proof formulas, but also specifies an earlier SRP
/// construction and SHA-1 interleaving. These options do not select that protocol.
/// [RFC 5054 section 2.6] uses TLS Finished messages rather than standalone proofs.
///
/// Proof options apply to the non-deprecated `process_reply` methods only.
///
/// [RFC 2945 section 3]: https://www.rfc-editor.org/rfc/rfc2945.html#section-3
/// [RFC 5054 section 2.6]: https://www.rfc-editor.org/rfc/rfc5054.html#section-2.6
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingOptions {
    /// Include the username in `x = H(s | H(I | ":" | P))`. Defaults to `true`.
    /// With `false`, use `x = H(s | H(":" | P))`, retaining the colon.
    ///
    /// Applies to client verifier generation and both client reply methods.
    /// Does not affect the static identity-hash helper or `H(I)` in `M1`.
    /// Ignored by the server, which uses the registered verifier instead of `x`.
    pub username_in_x: bool,
    /// Encoding of `g` in `H(g)` in `M1`. Defaults to [`IntegerEncoding::Padded`].
    /// This does not affect the multiplier `k`.
    pub m1_generator: IntegerEncoding,
    /// Encoding of `A` and `B` in `M1`. Defaults to [`IntegerEncoding::Minimal`].
    pub m1_public_values: IntegerEncoding,
    /// Encoding of `A` in `M2`. Defaults to [`IntegerEncoding::Minimal`].
    pub m2_public_value: IntegerEncoding,
    /// Encoding returned by `compute_public_ephemeral`.
    /// Defaults to [`IntegerEncoding::Minimal`]. This does not change the
    /// proof encodings, which are configured independently above.
    pub public_ephemeral: IntegerEncoding,
}

impl EncodingOptions {
    /// Password derivation and integer encodings used by Apple's HomeKit ADK.
    ///
    /// Includes the username in `x`, uses minimal `g`, `A`, and `B` in `M1`,
    /// padded `A` in `M2`, and padded public ephemeral values. HomeKit Pair Setup
    /// additionally requires the 3072-bit group, SHA-512, and username `Pair-Setup`.
    /// See the crate-level example.
    pub const HOMEKIT: Self = Self {
        username_in_x: true,
        m1_generator: IntegerEncoding::Minimal,
        m1_public_values: IntegerEncoding::Minimal,
        m2_public_value: IntegerEncoding::Padded,
        public_ephemeral: IntegerEncoding::Padded,
    };
}

impl Default for EncodingOptions {
    fn default() -> Self {
        Self {
            username_in_x: true,
            m1_generator: IntegerEncoding::Padded,
            m1_public_values: IntegerEncoding::Minimal,
            m2_public_value: IntegerEncoding::Minimal,
            public_ephemeral: IntegerEncoding::Minimal,
        }
    }
}

/// Reject oversized peer values before integer conversion and padding.
pub(crate) fn validate_public_len(
    g: &BoxedMontyForm,
    public: &[u8],
    name: &'static str,
) -> Result<(), AuthError> {
    if public.len() > g.params().modulus().bytes_precision() {
        return Err(AuthError::IllegalParameter { name });
    }
    Ok(())
}

/// Strip leading zeros from a public integer, never from a salt or digest.
fn trim_public(public: &[u8]) -> &[u8] {
    let first = public.iter().position(|&b| b != 0).unwrap_or(public.len());
    &public[first..]
}

/// Encode public proof inputs independently of their wire representation.
/// Callers must first validate the peer's public value length.
fn encode_proof_public<'a>(
    g: &BoxedMontyForm,
    encoding: IntegerEncoding,
    public: &'a [u8],
) -> Cow<'a, [u8]> {
    match encoding {
        IntegerEncoding::Minimal => Cow::Borrowed(trim_public(public)),
        IntegerEncoding::Padded => Cow::Owned(
            BoxedUint::from_be_slice_vartime(public)
                .resize(g.params().modulus().bits_precision())
                .to_be_bytes()
                .into(),
        ),
    }
}

/// Compute RFC 2945-style proofs with the selected integer encodings.
pub(crate) fn compute_proofs<D: Digest>(
    g: &BoxedMontyForm,
    encoding: EncodingOptions,
    username: &[u8],
    salt: &[u8],
    a_pub: &[u8],
    b_pub: &[u8],
    key: &[u8],
) -> (Output<D>, Output<D>) {
    let m1_a = encode_proof_public(g, encoding.m1_public_values, a_pub);
    let m1_b = encode_proof_public(g, encoding.m1_public_values, b_pub);
    let m1 = compute_m1_rfc5054::<D>(
        g,
        encoding.m1_generator == IntegerEncoding::Minimal,
        username,
        salt,
        &m1_a,
        &m1_b,
        key,
    );
    let m2_a = encode_proof_public(g, encoding.m2_public_value, a_pub);
    let m2 = compute_m2::<D>(&m2_a, &m1, key);
    (m1, m2)
}
