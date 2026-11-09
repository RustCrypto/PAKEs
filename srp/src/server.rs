use crate::{errors::AuthError, groups::*, utils::*};
use alloc::vec::Vec;
use bigint::{BoxedUint, Odd, Resize, modular::BoxedMontyForm};
use core::marker::PhantomData;
use digest::{Digest, Output};
use subtle::ConstantTimeEq;

/// SRP server configured with a standard [`G1024`] group.
#[deprecated(since = "0.7.0", note = "too small to be secure; use a larger group")]
#[allow(deprecated)]
pub type ServerG1024<D> = Server<G1024, D>;
/// SRP server configured with a standard [`G1536`] group.
#[deprecated(since = "0.7.0", note = "too small to be secure; use a larger group")]
#[allow(deprecated)]
pub type ServerG1536<D> = Server<G1536, D>;
/// SRP server configured with a standard [`G2048`] group.
pub type ServerG2048<D> = Server<G2048, D>;
/// SRP server configured with a standard [`G3072`] group.
pub type ServerG3072<D> = Server<G3072, D>;
/// SRP server configured with a standard [`G4096`] group.
pub type ServerG4096<D> = Server<G4096, D>;

/// SRP-6a server implementation.
///
/// # Usage
/// First receive user's username and public value `a_pub`, retrieve from a
/// database the salt and verifier for a given username. Generate `b` and public value `b_pub`.
//
#[cfg_attr(feature = "getrandom", doc = "```")]
#[cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
/// // NOTE: requires `getrandom` crate feature is enabled
///
/// use sha2::Sha256;
/// use srp::{EphemeralSecret, Generate};
/// # fn get_client_request()-> (Vec<u8>, Vec<u8>) { (vec![], vec![])}
/// # fn get_user(_: &[u8])-> (Vec<u8>, Vec<u8>) { (vec![], vec![])}
///
/// let server = srp::ServerG2048::<Sha256>::new();
/// let (username, a_pub) = get_client_request();
/// let (salt, v) = get_user(&username);
/// let mut b = EphemeralSecret::generate();
/// let b_pub = server.compute_public_ephemeral(&b, &v);
/// ```
///
/// Next send to user `b_pub` and `salt` from user record
///
/// Next process the user response:
///
/// ```rust
/// # let server = srp::ServerG2048::<sha2::Sha256>::new();
/// # fn get_client_response() -> Vec<u8> { vec![1] }
/// # let b = [0u8; 64];
/// # let v = b"";
/// # let username = b"user";
/// # let salt = b"nacl";
/// let a_pub = get_client_response();
/// let verifier = server.process_reply(username, salt, &b, v, &a_pub).unwrap();
/// ```
///
///
/// And finally receive user proof, verify it and send server proof in the
/// reply:
///
/// ```ignore
/// # let server = srp::ServerG2048::<sha2::Sha256>::new();
/// # let verifier = server.process_reply(b"", b"", b"", b"", b"1").unwrap();
/// # fn get_client_proof()-> Vec<u8> { vec![26, 80, 8, 243, 111, 162, 238, 171, 208, 237, 207, 46, 46, 137, 44, 213, 105, 208, 84, 224, 244, 216, 103, 145, 14, 103, 182, 56, 242, 4, 179, 57] };
/// # fn send_proof(_: &[u8]) { };
/// let client_proof = get_client_proof();
/// let session_key = verifier.verify_client(&client_proof).unwrap();
/// send_proof(verifier.proof());
/// ```
///
/// Successful verification returns the session key `K = H(S)`.
/// [`ServerVerifier::key`] instead exposes the unhashed premaster secret `S`
/// without authenticating the client.

#[derive(Debug)]
pub struct Server<G: Group, D: Digest> {
    g: BoxedMontyForm,
    g_no_pad: bool,
    d: PhantomData<(G, D)>,
}

impl<G: Group, D: Digest> Server<G, D> {
    /// Create an SRP-6a server which uses `H(PAD(g))` in the client proof.
    #[must_use]
    pub fn new() -> Self {
        Self {
            g: G::generator(),
            g_no_pad: false,
            d: PhantomData,
        }
    }

    /// Create an SRP-6a server with a choice of generator encoding in `M1`.
    ///
    /// Set `g_no_pad` to `true` to hash the minimal big-endian encoding of `g`,
    /// as required by HomeKit. With `false` (the default), `g` is left-padded to
    /// the byte length of `N`. The multiplier `k` always uses padded `g`.
    ///
    /// This option alone does not provide complete HomeKit compatibility: the
    /// received `A` is hashed unchanged in both proofs, whereas Apple's ADK
    /// trims it for `M1` and pads it for `M2`. See the crate-level HomeKit section.
    #[must_use]
    pub fn new_with_options(g_no_pad: bool) -> Self {
        Self {
            g_no_pad,
            g: G::generator(),
            d: PhantomData,
        }
    }

    /// Compute the server's public ephemeral: `(k*v + g^b) % N`.
    #[must_use]
    pub fn compute_b_pub(&self, b: &BoxedUint, k: &BoxedUint, v: &BoxedUint) -> BoxedUint {
        let k = monty_form(k, self.g.params());
        let v = monty_form(v, self.g.params());
        (k * v + self.g.pow(b)).retrieve()
    }

    /// Compute the premaster secret: `(A * v^u) ^ b % N`.
    #[must_use]
    pub fn compute_premaster_secret(
        &self,
        a_pub: &BoxedUint,
        v: &BoxedUint,
        u: &BoxedUint,
        b: &BoxedUint,
    ) -> BoxedUint {
        let a_pub = monty_form(a_pub, self.g.params());
        let v = monty_form(v, self.g.params());

        // (A * v^u)
        (a_pub * v.pow(u)).pow(b).retrieve()
    }

    /// Get public ephemeral value for sending to the client.
    ///
    /// This returns an unsigned big-endian serialization without leading zeros.
    /// The enclosing protocol may require left-padding it to the group width.
    #[must_use]
    pub fn compute_public_ephemeral(&self, b: &[u8], v: &[u8]) -> Vec<u8> {
        self.compute_b_pub(
            &BoxedUint::from_be_slice_vartime(b),
            &compute_k::<D>(&self.g),
            &BoxedUint::from_be_slice_vartime(v),
        )
        .to_be_bytes_trimmed_vartime()
        .into()
    }

    /// Process the client's SRP-6a reply and prepare RFC 2945-style proofs.
    ///
    /// Derives `K = H(S)` and uses the generator encoding selected by
    /// [`Self::new_with_options`] in `M1`. Call [`ServerVerifier::verify_client`]
    /// before sending the server proof or using `K`.
    ///
    /// # Params
    /// - `b` is a random value,
    /// - `v` is the verifier established during registration
    /// - `username` and `salt` correspond to that verifier
    /// - `a_pub_bytes` is the client's public ephemeral value
    ///
    /// # Panics
    /// May panic if `a_pub_bytes` is longer than the group modulus encoding.
    /// Validate the received public value's length before calling this method.
    pub fn process_reply(
        &self,
        username: &[u8],
        salt: &[u8],
        b: &[u8],
        v: &[u8],
        a_pub_bytes: &[u8],
    ) -> Result<ServerVerifier<D>, AuthError> {
        let b = BoxedUint::from_be_slice_vartime(b);
        let v = BoxedUint::from_be_slice_vartime(v);
        let a_pub = BoxedUint::from_be_slice_vartime(a_pub_bytes);

        let k = compute_k::<D>(&self.g);
        let b_pub_bytes = self.compute_b_pub(&b, &k, &v).to_be_bytes_trimmed_vartime();

        // Safeguard against malicious A
        self.validate_a_pub(&a_pub)?;

        // [RFC5054]: Section 2.6.
        let u = compute_u_padded::<D>(&self.g, a_pub_bytes, &b_pub_bytes);

        let premaster_secret = self
            .compute_premaster_secret(&a_pub, &v, &u, &b)
            .to_be_bytes_trimmed_vartime();

        let session_key = compute_hash::<D>(&premaster_secret);

        let m1 = compute_m1_rfc5054::<D>(
            &self.g,
            self.g_no_pad,
            username,
            salt,
            a_pub_bytes,
            &b_pub_bytes,
            session_key.as_slice(),
        );
        let m2 = compute_m2::<D>(a_pub_bytes, &m1, session_key.as_slice());

        Ok(ServerVerifier {
            m1,
            m2,
            key: premaster_secret.into(),
            session_key: session_key.to_vec(),
        })
    }

    /// Process client reply to the handshake using the legacy implementation.
    ///
    /// This implementation is compatible with `srp` v0.6 and earlier. It hashes
    /// unpadded public values for `u` and uses `M1 = H(A | B | S)` and
    /// `M2 = H(A | M1 | S)`, with the unhashed premaster secret `S`.
    ///
    /// # Params
    /// - `b` is a random value,
    /// - `v` is the provided during initial user registration
    #[deprecated(since = "0.7.0", note = "please use `Server::process_reply`")]
    #[allow(deprecated)]
    pub fn process_reply_legacy(
        &self,
        b: &[u8],
        v: &[u8],
        a_pub_bytes: &[u8],
    ) -> Result<LegacyServerVerifier<D>, AuthError> {
        let b = BoxedUint::from_be_slice_vartime(b);
        let v = BoxedUint::from_be_slice_vartime(v);
        let a_pub = BoxedUint::from_be_slice_vartime(a_pub_bytes);

        let k = compute_k::<D>(&self.g);
        let b_pub_bytes = self.compute_b_pub(&b, &k, &v).to_be_bytes_trimmed_vartime();

        // Safeguard against malicious A
        self.validate_a_pub(&a_pub)?;

        let u = compute_u::<D>(a_pub_bytes, &b_pub_bytes);

        let key = self.compute_premaster_secret(&a_pub, &v, &u, &b);

        let m1 = compute_m1_legacy::<D>(
            a_pub_bytes,
            &b_pub_bytes,
            &key.to_be_bytes_trimmed_vartime(),
        );

        let m2 = compute_m2::<D>(a_pub_bytes, &m1, &key.to_be_bytes_trimmed_vartime());

        Ok(LegacyServerVerifier {
            m1,
            m2,
            key: key.to_be_bytes_trimmed_vartime().into(),
        })
    }

    /// Get the modulus `N`.
    fn n(&self) -> &Odd<BoxedUint> {
        self.g.params().modulus()
    }

    /// Ensure `a_pub` is non-zero and therefore not maliciously crafted.
    fn validate_a_pub(&self, a_pub: &BoxedUint) -> Result<(), AuthError> {
        let n = self.n().as_nz_ref();

        if (a_pub.resize(n.bits_precision()) % n).is_zero().into() {
            return Err(AuthError::IllegalParameter { name: "a_pub" });
        }

        Ok(())
    }
}

impl<G: Group, D: Digest> Default for Server<G, D> {
    fn default() -> Self {
        Self::new()
    }
}

/// SRP-6a server state with RFC 2945-style authentication proofs.
///
/// The client is not authenticated until [`Self::verify_client`] succeeds.
#[derive(Debug)]
pub struct ServerVerifier<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
    session_key: Vec<u8>,
}

impl<D: Digest> ServerVerifier<D> {
    /// Return the unhashed premaster secret `S`, encoded without leading zeros.
    ///
    /// This does not authenticate the client or return the session key `K`.
    /// Prefer [`Self::verify_client`], which returns `K = H(S)` on success.
    /// Use `S` directly only when the enclosing protocol specifies its own key
    /// derivation and authentication.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Server proof `M2` to send only after [`Self::verify_client`] succeeds.
    pub fn proof(&self) -> &[u8] {
        // TODO not Output
        self.m2.as_slice()
    }

    /// Verify the client's proof `M1` and return the session key `K = H(S)`.
    pub fn verify_client(&self, reply: &[u8]) -> Result<&[u8], AuthError> {
        if self.m1.ct_eq(reply).unwrap_u8() == 1 {
            Ok(self.session_key.as_slice())
        } else {
            Err(AuthError::BadRecordMac { peer: "client" })
        }
    }
}

/// Legacy SRP server state after handshake with the client, compatible with `srp` v0.6 and earlier.
#[deprecated(since = "0.7.0", note = "please switch to `ServerVerifier`")]
#[derive(Debug)]
pub struct LegacyServerVerifier<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
}

#[allow(deprecated)]
impl<D: Digest> LegacyServerVerifier<D> {
    /// Get shared secret between user and the server. (do not forget to verify
    /// that keys are the same!)
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Verification data for sending to the client.
    pub fn proof(&self) -> &[u8] {
        // TODO not Output
        self.m2.as_slice()
    }

    /// Process user proof of having the same shared secret.
    pub fn verify_client(&self, reply: &[u8]) -> Result<(), AuthError> {
        if self.m1.ct_eq(reply).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(AuthError::BadRecordMac { peer: "client" })
        }
    }
}
