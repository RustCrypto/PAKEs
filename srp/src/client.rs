//! SRP client implementation.
//!
//! # Usage
//! First create SRP client struct by passing to it SRP parameters (shared
//! between client and server) and randomly generated `a`:
//!
//! ```ignore
//! use srp::groups::G_2048;
//! use sha2::Sha256;
//!
//! let mut a = [0u8; 64];
//! rng.fill_bytes(&mut a);
//! let client = SrpClient::<Sha256>::new(&a, &G_2048);
//! ```
//!
//! Next send handshake data (username and `a_pub`) to the server and receive
//! `salt` and `b_pub`:
//!
//! ```ignore
//! let a_pub = client.get_a_pub();
//! let (salt, b_pub) = conn.send_handshake(username, a_pub);
//! ```
//!
//! Compute private key using `salt` with any password hashing function.
//! You can use method from SRP-6a, but it's recommended to use specialized
//! password hashing algorithm instead (e.g. PBKDF2, argon2 or scrypt).
//! Next create verifier instance, note that `get_verifier` consumes client and
//! can return error in case of malicious `b_pub`.
//!
//! ```ignore
//! let private_key = srp_private_key::<Sha256>(username, password, salt);
//! let verifier = client.get_verifier(&private_key, &b_pub)?;
//! ```
//!
//! Finally verify the server: first generate user proof,
//! send it to the server and verify server proof in the reply. Note that
//! `verify_server` method will return error in case of incorrect server reply.
//!
//! ```ignore
//! let user_proof = verifier.get_proof();
//! let server_proof = conn.send_proof(user_proof);
//! let key = verifier.verify_server(server_proof)?;
//! ```
//!
//! `key` contains shared secret key between user and the server. Alternatively
//! you can directly extract shared secret key using `get_key()` method and
//! handle authentication through different (secure!) means (e.g. by using
//! authenticated cipher mode).
//!
//! For user registration on the server first generate salt (e.g. 32 bytes long)
//! and get password verifier which depends on private key. Send username, salt
//! and password verifier over protected channel to protect against
//! Man-in-the-middle (MITM) attack for registration.
//!
//! ```ignore
//! let pwd_verifier = client.get_password_verifier(&private_key);
//! conn.send_registration_data(username, salt, pwd_verifier);
//! ```

use std::marker::PhantomData;

use digest::{Digest, Output};
use num_bigint::BigUint;

use crate::types::{SrpAuthError, SrpGroup};
use crate::utils::{compute_k, compute_m1, compute_m2, compute_u};

/// SRP client state before handshake with the server.
pub struct SrpClient<'a, D: Digest> {
    params: &'a SrpGroup,
    d: PhantomData<D>,
}

/// SRP client state after handshake with the server.
pub struct SrpClientVerifier<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
}

impl<'a, D: Digest> SrpClient<'a, D> {
    /// Create new SRP client instance.
    pub fn new(params: &'a SrpGroup) -> Self {
        Self {
            params,
            d: Default::default(),
        }
    }

    pub fn compute_a_pub(&self, a: &BigUint) -> BigUint {
        self.params.g.modpow(&a, &self.params.n)
    }

    pub fn compute_identity_hash(username: &[u8], password: &[u8]) -> Output<D> {
        let mut d = D::new();
        d.update(username);
        d.update(b":");
        d.update(password);
        d.finalize()
    }

    // x = H(<salt> | H(<username> | ":" | <raw password>))
    pub fn compute_x(identity_hash: &[u8], salt: &[u8]) -> BigUint {
        let mut x = D::new();
        x.update(salt);
        x.update(identity_hash);
        BigUint::from_bytes_be(&x.finalize())
    }

    // (B - (k * g^x)) ^ (a + (u * x)) % N
    pub fn compute_premaster_secret(
        &self,
        b_pub: &BigUint,
        k: &BigUint,
        x: &BigUint,
        a: &BigUint,
        u: &BigUint,
    ) -> BigUint {
        // (k * g^x)
        let base = (k * (self.params.g.modpow(x, &self.params.n))) % &self.params.n;
        // Because we do operation in modulo N we can get: b_pub > base. That's not good. So we add N to b_pub to make sure.
        // B - kg^x
        let base = (&self.params.n + b_pub - &base) % &self.params.n;
        let exp = (u * x) + a;
        // S = (B - kg^x) ^ (a + ux)
        // or
        // S = base ^ exp
        base.modpow(&exp, &self.params.n)
    }

    // v = g^x % N
    pub fn compute_v(&self, x: &BigUint) -> BigUint {
        self.params.g.modpow(&x, &self.params.n)
    }

    /// Get password verifier (v in RFC5054) for user registration on the server.
    pub fn compute_verifier(&self, username: &[u8], password: &[u8], salt: &[u8]) -> Vec<u8> {
        let identity_hash = Self::compute_identity_hash(username, password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);
        self.compute_v(&x).to_bytes_be()
    }

    /// Get public ephemeral value for handshaking with the server.
    /// g^a % N
    pub fn compute_public_ephemeral(&self, a: &[u8]) -> Vec<u8> {
        self.compute_a_pub(&BigUint::from_bytes_be(&a))
            .to_bytes_be()
    }

    /// Process server reply to the handshake.
    /// a is a random value,
    /// username, password is supplied by the user
    /// salt and b_pub come from the server
    pub fn process_reply(
        &self,
        a: &[u8],
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        b_pub: &[u8],
    ) -> Result<SrpClientVerifier<D>, SrpAuthError> {
        let a = BigUint::from_bytes_be(a);
        let a_pub = self.compute_a_pub(&a);
        let b_pub = BigUint::from_bytes_be(b_pub);

        // Safeguard against malicious B
        if &b_pub % &self.params.n == BigUint::default() {
            return Err(SrpAuthError {
                description: "illegal_parameter: malicious b_pub value",
            });
        }

        let u = compute_u::<D>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be());
        let k = compute_k::<D>(self.params);
        let identity_hash = Self::compute_identity_hash(username, password);
        let x = Self::compute_x(identity_hash.as_slice(), salt);

        let key = self.compute_premaster_secret(&b_pub, &k, &x, &a, &u);

        let m1 = compute_m1::<D>(
            &a_pub.to_bytes_be(),
            &b_pub.to_bytes_be(),
            &key.to_bytes_be(),
        );

        let m2 = compute_m2::<D>(&a_pub.to_bytes_be(), &m1, &key.to_bytes_be());

        Ok(SrpClientVerifier {
            m1,
            m2,
            key: key.to_bytes_be(),
        })
    }
}

impl<D: Digest> SrpClientVerifier<D> {
    /// Get shared secret key without authenticating server, e.g. for using with
    /// authenticated encryption modes. DO NOT USE this method without
    /// some kind of secure authentication
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Verification data for sending to the server.
    pub fn proof(&self) -> &Output<D> {
        &self.m1
    }

    /// Verify server reply to verification data.
    pub fn verify_server(&self, reply: &[u8]) -> Result<(), SrpAuthError> {
        if self.m2.as_slice() != reply {
            // TODO timing attack
            Err(SrpAuthError {
                description: "bad_record_mac: Incorrect server proof",
            })
        } else {
            Ok(())
        }
    }
}
