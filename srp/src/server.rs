use alloc::vec::Vec;
use core::marker::PhantomData;
use crypto_bigint::{BoxedUint, Odd, Resize, modular::BoxedMontyForm};
use digest::{Digest, Output};
use subtle::ConstantTimeEq;

use crate::{
    Group,
    errors::AuthError,
    utils::{compute_hash, compute_k, compute_m1, compute_m1_rfc5054, compute_m2, compute_u},
};

/// SRP server implementation.
///
/// # Usage
/// First receive user's username and public value `a_pub`, retrieve from a
/// database the salt and verifier for a given username. Generate `b` and public value `b_pub`.
///
///
/// ```rust
/// use srp::{G2048, Server};
/// use sha2::Sha256;
/// # fn get_client_request()-> (Vec<u8>, Vec<u8>) { (vec![], vec![])}
/// # fn get_user(_: &[u8])-> (Vec<u8>, Vec<u8>) { (vec![], vec![])}
///
/// let server = Server::<G2048, Sha256>::new();
/// let (username, a_pub) = get_client_request();
/// let (salt, v) = get_user(&username);
/// let mut b = [0u8; 64];
/// // rng.fill_bytes(&mut b);
/// let b_pub = server.compute_public_ephemeral(&b, &v);
/// ```
///
/// Next send to user `b_pub` and `salt` from user record
///
/// Next process the user response:
///
/// ```rust
/// # let server = srp::Server::<srp::G2048, sha2::Sha256>::new();
/// # fn get_client_response() -> Vec<u8> { vec![1] }
/// # let b = [0u8; 64];
/// # let v = b"";
///
/// let a_pub = get_client_response();
/// let verifier = server.process_reply_legacy(&b, v, &a_pub).unwrap();
/// ```
///
///
/// And finally receive user proof, verify it and send server proof in the
/// reply:
///
/// ```rust
/// # let server = srp::Server::<srp::G2048, sha2::Sha256>::new();
/// # let verifier = server.process_reply_legacy(b"", b"", b"1").unwrap();
/// # fn get_client_proof()-> Vec<u8> { vec![26, 80, 8, 243, 111, 162, 238, 171, 208, 237, 207, 46, 46, 137, 44, 213, 105, 208, 84, 224, 244, 216, 103, 145, 14, 103, 182, 56, 242, 4, 179, 57] };
/// # fn send_proof(_: &[u8]) { };
///
/// let client_proof = get_client_proof();
/// verifier.verify_client(&client_proof).unwrap();
/// send_proof(verifier.proof());
/// ```
///
///
/// `key` contains shared secret key between user and the server. You can extract shared secret
/// key using `key()` method.
/// ```rust
/// # let server = srp::Server::<srp::G2048, sha2::Sha256>::new();
/// # let verifier = server.process_reply_legacy(b"", b"", b"1").unwrap();
///
/// verifier.key();
/// ```
///
///
/// Alternatively, you can use `process_reply_rfc5054` method to process parameters
/// according to RFC 5054 if the client is using it. You need to pass `username` and
/// `salt` in addition to other parameters to this method. This way, it generates M1
/// and M2 differently and also the `verify_client` method will return a shared session
/// key in case of correct server data.
///
/// ```ident
/// # let server = srp::Server::<srp::G2048, sha2::Sha256>::new();
/// # let verifier = server.process_reply_rfc5054(b"", b"", b"", b"", b"1").unwrap();
/// # fn get_client_proof()-> Vec<u8> { vec![53, 91, 252, 129, 223, 201, 97, 145, 208, 243, 229, 232, 20, 118, 108, 126, 244, 68, 237, 38, 121, 24, 181, 53, 155, 103, 134, 44, 107, 204, 56, 50] };
/// # fn send_proof(_: &[u8]) { };
///
/// let client_proof = get_client_proof();
/// let session_key = verifier.verify_client(&client_proof).unwrap();
/// send_proof(verifier.proof());
/// ```
pub struct Server<G: Group, D: Digest> {
    g: BoxedMontyForm,
    d: PhantomData<(G, D)>,
}

impl<G: Group, D: Digest> Server<G, D> {
    /// Create new server state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            g: G::generator(),
            d: PhantomData,
        }
    }

    /// Compute the server's public ephemeral: `k*v + g^b % N`.
    #[must_use]
    pub fn compute_b_pub(&self, b: &BoxedUint, k: &BoxedUint, v: &BoxedUint) -> BoxedUint {
        let k = self.monty_form(k);
        let v = self.monty_form(v);
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
        let a_pub = self.monty_form(a_pub);
        let v = self.monty_form(v);

        // (A * v^u)
        (a_pub * v.pow(u)).pow(b).retrieve()
    }

    /// Get public ephemeral value for sending to the client.
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

    /// Process client reply to the handshake according to [RFC5054].
    ///
    /// # Params
    /// - `b` is a random value,
    /// - `v` is the provided during initial user registration
    ///
    /// [RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054
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

        let u = compute_u::<D>(a_pub_bytes, &b_pub_bytes);

        let premaster_secret = self
            .compute_premaster_secret(&a_pub, &v, &u, &b)
            .to_be_bytes_trimmed_vartime();

        let session_key = compute_hash::<D>(&premaster_secret);

        let m1 = compute_m1_rfc5054::<D>(
            &self.g,
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
    /// This implementation is compatible with `srp` v0.6 and earlier. Note the default
    /// implementation is now RFC5054 compatible.
    ///
    /// # Params
    /// - `b` is a random value,
    /// - `v` is the provided during initial user registration
    #[deprecated(
        since = "0.7.0",
        note = "please switch to `Server::process_reply_rfc5054`"
    )]
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

        let m1 = compute_m1::<D>(
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

    /// Convert an integer into the Montgomery domain, returning a [`BoxedMontyForm`] modulo `N`.
    fn monty_form(&self, x: &BoxedUint) -> BoxedMontyForm {
        let precision = self.n().bits_precision();
        BoxedMontyForm::new(x.resize(precision), self.g.params())
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

/// [RFC5054] SRP server state after handshake with the client.
///
/// [RFC5054]: https://datatracker.ietf.org/doc/html/rfc5054
pub struct ServerVerifier<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
    session_key: Vec<u8>,
}

impl<D: Digest> ServerVerifier<D> {
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

    /// Process user proof of having the same shared secret and return shared session key.
    pub fn verify_client(&self, reply: &[u8]) -> Result<&[u8], AuthError> {
        if self.m1.ct_eq(reply).unwrap_u8() == 1 {
            Ok(self.session_key.as_slice())
        } else {
            Err(AuthError::BadRecordMac { peer: "client" })
        }
    }
}

/// Legacy SRP server state after handshake with the client, compatible with `srp` v0.6 and earlier.
#[deprecated(since = "0.7.0", note = "please switch to `ServerVerifierRfc5054`")]
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
