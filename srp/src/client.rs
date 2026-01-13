//! SRP client implementation.
//!
//! # Usage
//! First create SRP client struct by passing to it SRP parameters (shared
//! between client and server).
//!
//! You can use SHA1 from SRP-6a, but it's highly recommended to use specialized
//! password hashing algorithm instead (e.g. PBKDF2, argon2 or scrypt).
//!
//! ```rust
//! use srp::groups::G2048;
//! use sha2::Sha256; // Note: You should probably use a proper password KDF
//! # use srp::client::Client;
//!
//! let client = Client::<G2048, Sha256>::new();
//! ```
//!
//! Next send handshake data (username and `a_pub`) to the server and receive
//! `salt` and `b_pub`:
//!
//! ```rust
//! # let client = srp::Client::<srp::G2048, sha2::Sha256>::new();
//! # fn server_response()-> (Vec<u8>, Vec<u8>) { (vec![], vec![]) }
//!
//! let mut a = [0u8; 64];
//! // rng.fill_bytes(&mut a);
//! let a_pub = client.compute_public_ephemeral(&a);
//! let (salt, b_pub) = server_response();
//! ```
//!
//! Process the server response and create verifier instance.
//! `process_reply` can return error in case of malicious `b_pub`.
//!
//! ```rust
//! # let client = srp::Client::<srp::G2048, sha2::Sha256>::new();
//! # let a = [0u8; 64];
//! # let username = b"username";
//! # let password = b"password";
//! # let salt = b"salt";
//! # let b_pub = b"b_pub";
//!
//! let private_key = (username, password, salt);
//! let verifier = client.process_reply_legacy(&a, username, password, salt, b_pub);
//! ```
//!
//! Finally verify the server: first generate user proof,
//! send it to the server and verify server proof in the reply. Note that
//! `verify_server` method will return error in case of incorrect server reply.
//!
//! ```ignore
//! # let client = srp::Client::<srp::G2048, sha2::Sha256>::new();
//! # let verifier = client.process_reply(b"", b"", b"", b"", b"1").unwrap();
//! # fn send_proof(_: &[u8]) -> Vec<u8> { vec![173, 202, 13, 26, 207, 73, 0, 46, 121, 238, 48, 170, 96, 146, 60, 49, 88, 76, 12, 184, 152, 76, 207, 220, 140, 205, 190, 189, 117, 6, 131, 63]   }
//!
//! let client_proof = verifier.proof();
//! let server_proof = send_proof(client_proof);
//! verifier.verify_server(&server_proof).unwrap();
//! ```
//!
//! `key` contains shared secret key between user and the server. You can extract shared secret
//! key using `key()` method.
//! ```rust
//! # let client = srp::Client::<srp::G2048, sha2::Sha256>::new();
//! # let verifier = client.process_reply_legacy(b"", b"", b"", b"", b"1").unwrap();
//!
//! verifier.key();
//! ```
//!
//!
//! Alternatively, you can use `process_reply_rfc5054` method to process parameters
//! according to RFC 5054 if the server is using it. This way, it generates M1 and
//! M2 differently and also the `verify_server` method will return a shared session
//! key in case of correct server data.
//!
//! ```ignore
//! # let client = srp::Client::<srp::G2048, sha2::Sha256>::new();
//! # let verifier = client.process_reply_rfc5054(b"", b"", b"", b"", b"1").unwrap();
//! # fn send_proof(_: &[u8]) -> Vec<u8> { vec![10, 215, 214, 40, 136, 200, 122, 121, 68, 160, 38, 32, 85, 82, 128, 30, 199, 194, 126, 222, 61, 55, 2, 28, 120, 181, 155, 102, 141, 65, 17, 64]   }
//!
//! let client_proof = verifier.proof();
//! let server_proof = send_proof(client_proof);
//! let session_key = verifier.verify_server(&server_proof).unwrap();
//! ```
//!
//!
//! For user registration on the server first generate salt (e.g. 32 bytes long)
//! and get password verifier which depends on private key. Send username, salt
//! and password verifier over protected channel to protect against
//! Man-in-the-middle (MITM) attack for registration.
//!
//! ```rust
//! # let client = srp::Client::<srp::G2048, sha2::Sha256>::new();
//! # let username = b"username";
//! # let password = b"password";
//! # let salt = b"salt";
//! # fn send_registration_data(_: &[u8], _: &[u8], _: &[u8]) {}
//!
//! let pwd_verifier = client.compute_verifier(username, password, salt);
//! send_registration_data(username, salt, &pwd_verifier);
//! ```
//!

use alloc::vec::Vec;
use core::marker::PhantomData;
use crypto_bigint::{BoxedUint, ConcatenatingMul, Odd, Resize, modular::BoxedMontyForm};
use digest::{Digest, Output};
use subtle::ConstantTimeEq;

use crate::{
    Group,
    errors::AuthError,
    utils::{compute_hash, compute_k, compute_m1, compute_m1_rfc5054, compute_m2, compute_u},
};

/// SRP client state before handshake with the server.
pub struct Client<G: Group, D: Digest> {
    g: BoxedMontyForm,
    username_in_x: bool,
    d: PhantomData<(G, D)>,
}

impl<G: Group, D: Digest> Client<G, D> {
    /// Create new SRP client instance.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_options(true)
    }

    #[must_use]
    pub fn new_with_options(username_in_x: bool) -> Self {
        Self {
            g: G::generator(),
            username_in_x,
            d: PhantomData,
        }
    }

    // v = g^x % N
    #[must_use]
    pub fn compute_g_x(&self, x: &BoxedUint) -> BoxedUint {
        self.g.pow(x).retrieve()
    }

    //  H(<username> | ":" | <raw password>)
    #[must_use]
    pub fn compute_identity_hash(username: &[u8], password: &[u8]) -> Output<D> {
        let mut d = D::new();
        d.update(username);
        d.update(b":");
        d.update(password);
        d.finalize()
    }

    // x = H(<salt> | H(<username> | ":" | <raw password>))
    #[must_use]
    pub fn compute_x(identity_hash: &[u8], salt: &[u8]) -> BoxedUint {
        let mut x = D::new();
        x.update(salt);
        x.update(identity_hash);
        BoxedUint::from_be_slice_vartime(&x.finalize())
    }

    // (B - (k * g^x)) ^ (a + (u * x)) % N
    #[must_use]
    pub fn compute_premaster_secret(
        &self,
        b_pub: &BoxedUint,
        k: &BoxedUint,
        x: &BoxedUint,
        a: &BoxedUint,
        u: &BoxedUint,
    ) -> BoxedUint {
        let b_pub = self.monty_form(b_pub);
        let k = self.monty_form(k);

        // B - kg^x
        let base = b_pub - k * self.g.pow(x);

        // S = (B - kg^x) ^ (a + ux)
        // or
        // S = base ^ exp
        let exp = a.concatenating_add(&u.concatenating_mul(x));
        base.pow(&exp).retrieve()
    }

    /// Get password verifier (v in RFC5054) for user registration on the server.
    #[must_use]
    pub fn compute_verifier(&self, username: &[u8], password: &[u8], salt: &[u8]) -> Vec<u8> {
        let identity_hash = Self::compute_identity_hash(self.identity_username(username), password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);
        self.compute_g_x(&x).to_be_bytes_trimmed_vartime().into()
    }

    /// Get public ephemeral value for handshaking with the server.
    /// g^a % N
    #[must_use]
    pub fn compute_public_ephemeral(&self, a: &[u8]) -> Vec<u8> {
        self.compute_g_x(&BoxedUint::from_be_slice_vartime(a))
            .to_be_bytes_trimmed_vartime()
            .into()
    }

    /// Process server reply to the handshake according to RFC 5054.
    ///
    /// # Params
    /// `a` is a random value,
    /// `username`, `password` is supplied by the user
    /// `salt` and `b_pub` come from the server
    pub fn process_reply_rfc5054(
        &self,
        a: &[u8],
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        b_pub: &[u8],
    ) -> Result<ClientVerifierRfc5054<D>, AuthError> {
        let a = BoxedUint::from_be_slice_vartime(a);
        let a_pub = self.compute_g_x(&a);
        let b_pub = BoxedUint::from_be_slice_vartime(b_pub);

        // Safeguard against malicious B
        self.validate_b_pub(&b_pub)?;

        let u = compute_u::<D>(
            &a_pub.to_be_bytes_trimmed_vartime(),
            &b_pub.to_be_bytes_trimmed_vartime(),
        );
        let k = compute_k::<D>(&self.g);
        let identity_hash = Self::compute_identity_hash(self.identity_username(username), password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);

        let premaster_secret = self
            .compute_premaster_secret(&b_pub, &k, &x, &a, &u)
            .to_be_bytes_trimmed_vartime();

        let session_key = compute_hash::<D>(&premaster_secret);

        let m1 = compute_m1_rfc5054::<D>(
            &self.g,
            username,
            salt,
            &a_pub.to_be_bytes_trimmed_vartime(),
            &b_pub.to_be_bytes_trimmed_vartime(),
            session_key.as_slice(),
        );

        let m2 = compute_m2::<D>(
            &a_pub.to_be_bytes_trimmed_vartime(),
            &m1,
            session_key.as_slice(),
        );

        Ok(ClientVerifierRfc5054 {
            m1,
            m2,
            key: premaster_secret.to_vec(),
            session_key: session_key.to_vec(),
        })
    }

    /// Process server reply to the handshake using the legacy implementation.
    ///
    /// This implementation is compatible with `srp` v0.6 and earlier. Note the default
    /// implementation is now RFC5054 compatible.
    ///
    /// # Params
    /// - `a` is a random value,
    /// - `username`, `password` is supplied by the user
    /// - `salt` and `b_pub` come from the server
    #[deprecated(
        since = "0.7.0",
        note = "please switch to `Client::process_reply_rfc5054`"
    )]
    #[allow(deprecated)]
    pub fn process_reply_legacy(
        &self,
        a: &[u8],
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        b_pub: &[u8],
    ) -> Result<LegacyClientVerifier<D>, AuthError> {
        let a = BoxedUint::from_be_slice_vartime(a);
        let a_pub = self.compute_g_x(&a);
        let b_pub = BoxedUint::from_be_slice_vartime(b_pub);

        // Safeguard against malicious B
        self.validate_b_pub(&b_pub)?;

        let u = compute_u::<D>(
            &a_pub.to_be_bytes_trimmed_vartime(),
            &b_pub.to_be_bytes_trimmed_vartime(),
        );
        let k = compute_k::<D>(&self.g);
        let identity_hash = Self::compute_identity_hash(self.identity_username(username), password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);

        let key = self.compute_premaster_secret(&b_pub, &k, &x, &a, &u);

        let m1 = compute_m1::<D>(
            &a_pub.to_be_bytes_trimmed_vartime(),
            &b_pub.to_be_bytes_trimmed_vartime(),
            &key.to_be_bytes_trimmed_vartime(),
        );

        let m2 = compute_m2::<D>(
            &a_pub.to_be_bytes_trimmed_vartime(),
            &m1,
            &key.to_be_bytes_trimmed_vartime(),
        );

        Ok(LegacyClientVerifier {
            m1,
            m2,
            key: key.to_be_bytes_trimmed_vartime().to_vec(),
        })
    }

    /// Conditionally include username in the computation of `x`.
    fn identity_username<'a>(&self, username: &'a [u8]) -> &'a [u8] {
        if self.username_in_x { username } else { &[] }
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

    /// Ensure `b_pub` is non-zero and therefore not maliciously crafted.
    fn validate_b_pub(&self, b_pub: &BoxedUint) -> Result<(), AuthError> {
        let n = self.n().as_nz_ref();

        if (b_pub.resize(n.bits_precision()) % n).is_zero().into() {
            return Err(AuthError::IllegalParameter { name: "b_pub" });
        }

        Ok(())
    }
}

impl<G: Group, D: Digest> Default for Client<G, D> {
    fn default() -> Self {
        Self::new()
    }
}

/// RFC 5054 SRP client state after handshake with the server.
pub struct ClientVerifierRfc5054<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
    session_key: Vec<u8>,
}

impl<D: Digest> ClientVerifierRfc5054<D> {
    /// Get shared secret key without authenticating server, e.g. for using with
    /// authenticated encryption modes. DO NOT USE this method without
    /// some kind of secure authentication
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Verification data for sending to the server.
    pub fn proof(&self) -> &[u8] {
        self.m1.as_slice()
    }

    /// Verify server reply to verification data and return shared session key.
    pub fn verify_server(&self, reply: &[u8]) -> Result<&[u8], AuthError> {
        if self.m2.ct_eq(reply).unwrap_u8() == 1 {
            Ok(self.session_key.as_slice())
        } else {
            Err(AuthError::BadRecordMac { peer: "server" })
        }
    }
}

/// Legacy SRP client state after handshake with the server, compatible with `srp` v0.6 and earlier.
#[deprecated(since = "0.7.0", note = "please switch to `ClientVerifierRfc5054`")]
pub struct LegacyClientVerifier<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
}

#[allow(deprecated)]
impl<D: Digest> LegacyClientVerifier<D> {
    /// Get shared secret key without authenticating server, e.g. for using with
    /// authenticated encryption modes. DO NOT USE this method without
    /// some kind of secure authentication
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Verification data for sending to the server.
    pub fn proof(&self) -> &[u8] {
        self.m1.as_slice()
    }

    /// Verify server reply to verification data.
    pub fn verify_server(&self, reply: &[u8]) -> Result<(), AuthError> {
        if self.m2.ct_eq(reply).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(AuthError::BadRecordMac { peer: "server" })
        }
    }
}
