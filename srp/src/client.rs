use crate::{
    EncodingOptions, IntegerEncoding,
    encoding::{compute_proofs, validate_public_len},
    errors::AuthError,
    groups::*,
    utils::*,
};
use alloc::vec::Vec;
use bigint::{BoxedUint, ConcatenatingMul, Odd, Resize, modular::BoxedMontyForm};
use core::marker::PhantomData;
use digest::{Digest, Output};
use subtle::ConstantTimeEq;

/// SRP client configured with a standard 1024-bit group.
#[deprecated(since = "0.7.0", note = "too small to be secure; use a larger group")]
#[allow(deprecated)]
pub type ClientG1024<D> = Client<G1024, D>;
/// SRP client configured with a standard 1536-bit group.
#[deprecated(since = "0.7.0", note = "too small to be secure; use a larger group")]
#[allow(deprecated)]
pub type ClientG1536<D> = Client<G1536, D>;
/// SRP client configured with a standard 2048-bit group.
pub type ClientG2048<D> = Client<G2048, D>;
/// SRP client configured with a standard 3072-bit group.
pub type ClientG3072<D> = Client<G3072, D>;
/// SRP client configured with a standard 4096-bit group.
pub type ClientG4096<D> = Client<G4096, D>;

/// SRP-6a client implementation.
///
/// # Usage
/// First create SRP client struct by passing to it SRP parameters (shared
/// between client and server).
///
/// Choose the group and digest required by the peer's protocol. The digest is
/// used throughout SRP, including `x = H(s | H(I | ":" | P))`; it is not a
/// configurable password-hardening KDF. Changing password derivation requires
/// agreement between peers and is not compatible with HomeKit Pair Setup.
///
/// ```rust
/// use sha2::Sha256;
///
/// let client = srp::ClientG2048::<Sha256>::new();
/// ```
///
/// Next send handshake data (username and `a_pub`) to the server and receive
/// `salt` and `b_pub`:
///
#[cfg_attr(feature = "getrandom", doc = "```")]
#[cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
/// # let client = srp::ClientG2048::<sha2::Sha256>::new();
/// # fn server_response()-> (Vec<u8>, Vec<u8>) { (vec![], vec![]) }
/// // NOTE: requires `getrandom` crate feature is enabled
///
/// use srp::{EphemeralSecret, Generate};
///
/// let mut a = EphemeralSecret::generate();
/// let a_pub = client.compute_public_ephemeral(&a);
/// let (salt, b_pub) = server_response();
/// ```
///
/// Process the server response and create verifier instance.
/// `process_reply` can return error in case of malicious `b_pub`.
///
/// ```rust
/// # let client = srp::ClientG2048::<sha2::Sha256>::new();
/// # let a = [0u8; 64];
/// # let username = b"username";
/// # let password = b"password";
/// # let salt = b"salt";
/// # let b_pub = b"b_pub";
/// let private_key = (username, password, salt);
/// let verifier = client.process_reply(&a, username, password, salt, b_pub);
/// ```
///
/// Finally verify the server: first generate user proof,
/// send it to the server and verify server proof in the reply. Note that
/// `verify_server` method will return error in case of incorrect server reply.
///
/// ```ignore
/// # let client = srp::ClientG2048::<sha2::Sha256>::new();
/// # let verifier = client.process_reply(b"", b"", b"", b"", b"1").unwrap();
/// # fn send_proof(_: &[u8]) -> Vec<u8> { vec![173, 202, 13, 26, 207, 73, 0, 46, 121, 238, 48, 170, 96, 146, 60, 49, 88, 76, 12, 184, 152, 76, 207, 220, 140, 205, 190, 189, 117, 6, 131, 63]   }
/// let client_proof = verifier.proof();
/// let server_proof = send_proof(client_proof);
/// let session_key = verifier.verify_server(&server_proof).unwrap();
/// ```
///
/// Successful verification returns the session key `K = H(S)`.
/// [`ClientVerifier::key`] instead exposes the unhashed premaster secret `S`
/// without authenticating the server.
///
/// For user registration on the server first generate salt (e.g. 32 bytes long)
/// and get password verifier which depends on private key. Send username, salt
/// and password verifier over a protected channel to protect against Man-in-the-middle
/// (MITM) attack for registration.
///
/// ```rust
/// # let client = srp::ClientG2048::<sha2::Sha256>::new();
/// # let username = b"username";
/// # let password = b"password";
/// # let salt = b"salt";
/// # fn send_registration_data(_: &[u8], _: &[u8], _: &[u8]) {}
/// let pwd_verifier = client.compute_verifier(username, password, salt);
/// send_registration_data(username, salt, &pwd_verifier);
/// ```
#[derive(Debug)]
pub struct Client<G: Group, D: Digest> {
    g: BoxedMontyForm,
    encoding: EncodingOptions,
    d: PhantomData<(G, D)>,
}

impl<G: Group, D: Digest> Client<G, D> {
    /// Create an SRP-6a client with default encoding options.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_options(EncodingOptions::default())
    }

    /// Create an SRP-6a client with the selected password derivation and encodings.
    ///
    /// See [`EncodingOptions`], including [`EncodingOptions::HOMEKIT`] for
    /// HomeKit Pair Setup.
    #[must_use]
    pub fn new_with_options(encoding: EncodingOptions) -> Self {
        Self {
            g: G::generator(),
            encoding,
            d: PhantomData,
        }
    }

    /// Compute `g^x % N`, which can be used when computing e.g. `v`.
    #[must_use]
    pub fn compute_g_x(&self, x: &BoxedUint) -> BoxedUint {
        self.g.pow(x).retrieve()
    }

    /// Get public ephemeral value for handshaking with the server: `g^a % N`.
    ///
    /// Returns a minimal big-endian encoding by default. Set
    /// [`EncodingOptions::public_ephemeral`] to [`IntegerEncoding::Padded`]
    /// via [`Self::new_with_options`] to pad it to the group width.
    #[must_use]
    pub fn compute_public_ephemeral(&self, a: &[u8]) -> Vec<u8> {
        let a_pub = self.compute_g_x(&BoxedUint::from_be_slice_vartime(a));
        if self.encoding.public_ephemeral == IntegerEncoding::Padded {
            a_pub.to_be_bytes().into()
        } else {
            a_pub.to_be_bytes_trimmed_vartime().into()
        }
    }

    /// Compute the identity hash: `H(<username> | ":" | <raw password>)`.
    #[must_use]
    pub fn compute_identity_hash(username: &[u8], password: &[u8]) -> Output<D> {
        let mut d = D::new();
        d.update(username);
        d.update(b":");
        d.update(password);
        d.finalize()
    }

    /// Compute `x = H(salt | identity_hash)`.
    ///
    /// Normally `identity_hash` is the output of [`Self::compute_identity_hash`].
    /// The salt is hashed exactly as supplied, including leading zero bytes;
    /// it is not converted to an integer, trimmed, or padded. Integer conversion
    /// applies only to the resulting digest `x`.
    ///
    /// See [RFC 5054 section 2.4](https://datatracker.ietf.org/doc/html/rfc5054#section-2.4)
    /// for the derivation.
    #[must_use]
    pub fn compute_x(identity_hash: &[u8], salt: &[u8]) -> BoxedUint {
        let mut x = D::new();
        x.update(salt);
        x.update(identity_hash);
        BoxedUint::from_be_slice_vartime(&x.finalize())
    }

    /// Compute the premaster secret: `(B - (k * g^x)) ^ (a + (u * x)) % N`.
    #[must_use]
    pub fn compute_premaster_secret(
        &self,
        b_pub: &BoxedUint,
        k: &BoxedUint,
        x: &BoxedUint,
        a: &BoxedUint,
        u: &BoxedUint,
    ) -> BoxedUint {
        let b_pub = monty_form(b_pub, self.g.params());
        let k = monty_form(k, self.g.params());

        // B - kg^x
        let base = b_pub - k * self.g.pow(x);

        // S = (B - kg^x) ^ (a + ux)
        // or
        // S = base ^ exp
        let exp = a.concatenating_add(u.concatenating_mul(x));
        base.pow(&exp).retrieve()
    }

    /// Compute the password verifier `v = g^x mod N` for registration on the server.
    ///
    /// The salt is used verbatim, including leading zero bytes. Retain the same
    /// salt bytes for authentication.
    #[must_use]
    pub fn compute_verifier(&self, username: &[u8], password: &[u8], salt: &[u8]) -> Vec<u8> {
        let identity_hash = Self::compute_identity_hash(self.identity_username(username), password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);
        self.compute_g_x(&x).to_be_bytes_trimmed_vartime().into()
    }

    /// Process the server's SRP-6a reply and prepare RFC 2945-style proofs.
    ///
    /// Derives `K = H(S)` and uses the encodings selected by [`Self::new_with_options`].
    /// This does not implement TLS-SRP. Call [`ClientVerifier::verify_server`]
    /// to authenticate the server and obtain `K`.
    ///
    /// # Params
    /// - `a` is a random value,
    /// - `username`, `password` is supplied by the user
    /// - `salt` and `b_pub` come from the server
    ///
    /// # Errors
    /// Returns [`AuthError::IllegalParameter`] if `b_pub_bytes` exceeds the group
    /// width or its integer value is zero modulo `N`.
    pub fn process_reply(
        &self,
        a: &[u8],
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        b_pub_bytes: &[u8],
    ) -> Result<ClientVerifier<D>, AuthError> {
        validate_public_len(&self.g, b_pub_bytes, "b_pub")?;
        let a = BoxedUint::from_be_slice_vartime(a);
        let a_pub_bytes = self.compute_g_x(&a).to_be_bytes_trimmed_vartime();
        let b_pub = BoxedUint::from_be_slice_vartime(b_pub_bytes);

        // Safeguard against malicious B
        self.validate_b_pub(&b_pub)?;

        let u = compute_u_padded::<D>(&self.g, &a_pub_bytes, b_pub_bytes);
        let k = compute_k::<D>(&self.g);
        let identity_hash = Self::compute_identity_hash(self.identity_username(username), password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);

        let premaster_secret = self
            .compute_premaster_secret(&b_pub, &k, &x, &a, &u)
            .to_be_bytes_trimmed_vartime();

        let session_key = compute_hash::<D>(&premaster_secret);

        let (m1, m2) = compute_proofs::<D>(
            &self.g,
            self.encoding,
            username,
            salt,
            &a_pub_bytes,
            b_pub_bytes,
            session_key.as_slice(),
        );

        Ok(ClientVerifier {
            m1,
            m2,
            key: premaster_secret.to_vec(),
            session_key: session_key.to_vec(),
        })
    }

    /// Process server reply to the handshake using the legacy implementation.
    ///
    /// This implementation is compatible with `srp` v0.6 and earlier. It hashes
    /// unpadded public values for `u` and uses `M1 = H(A | B | S)` and
    /// `M2 = H(A | M1 | S)`, with the unhashed premaster secret `S`.
    ///
    /// # Params
    /// - `a` is a random value,
    /// - `username`, `password` is supplied by the user
    /// - `salt` and `b_pub` come from the server
    #[deprecated(since = "0.7.0", note = "please use `Client::process_reply`")]
    #[allow(deprecated)]
    pub fn process_reply_legacy(
        &self,
        a: &[u8],
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        b_pub_bytes: &[u8],
    ) -> Result<LegacyClientVerifier<D>, AuthError> {
        let a = BoxedUint::from_be_slice_vartime(a);
        let a_pub_bytes = self.compute_g_x(&a).to_be_bytes_trimmed_vartime();
        let b_pub = BoxedUint::from_be_slice_vartime(b_pub_bytes);

        // Safeguard against malicious B
        self.validate_b_pub(&b_pub)?;

        let u = compute_u::<D>(&a_pub_bytes, b_pub_bytes);
        let k = compute_k::<D>(&self.g);
        let identity_hash = Self::compute_identity_hash(self.identity_username(username), password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);

        let key = self
            .compute_premaster_secret(&b_pub, &k, &x, &a, &u)
            .to_be_bytes_trimmed_vartime()
            .to_vec();

        let m1 = compute_m1_legacy::<D>(&a_pub_bytes, b_pub_bytes, &key);
        let m2 = compute_m2::<D>(&a_pub_bytes, &m1, &key);
        Ok(LegacyClientVerifier { m1, m2, key })
    }

    /// Conditionally include username in the computation of `x`.
    fn identity_username<'a>(&self, username: &'a [u8]) -> &'a [u8] {
        if self.encoding.username_in_x {
            username
        } else {
            &[]
        }
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

/// SRP-6a client state with RFC 2945-style authentication proofs.
///
/// The server is not authenticated until [`Self::verify_server`] succeeds.
#[derive(Debug)]
pub struct ClientVerifier<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
    session_key: Vec<u8>,
}

impl<D: Digest> ClientVerifier<D> {
    /// Return the unhashed premaster secret `S`, encoded without leading zeros.
    ///
    /// This does not authenticate the server or return the session key `K`.
    /// Prefer [`Self::verify_server`], which returns `K = H(S)` on success.
    /// Use `S` directly only when the enclosing protocol specifies its own key
    /// derivation and authentication.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Client proof `M1` to send to the server.
    pub fn proof(&self) -> &[u8] {
        self.m1.as_slice()
    }

    /// Verify the server's proof `M2` and return the session key `K = H(S)`.
    pub fn verify_server(&self, reply: &[u8]) -> Result<&[u8], AuthError> {
        if self.m2.ct_eq(reply).unwrap_u8() == 1 {
            Ok(self.session_key.as_slice())
        } else {
            Err(AuthError::BadRecordMac { peer: "server" })
        }
    }
}

/// Legacy SRP client state after handshake with the server, compatible with `srp` v0.6 and earlier.
#[deprecated(since = "0.7.0", note = "please switch to `ClientVerifier`")]
#[derive(Debug)]
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
