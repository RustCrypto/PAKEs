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
use generic_array::GenericArray;
use num_bigint::{BigInt, Sign};

use crate::types::{SrpAuthError, SrpGroup};

/// SRP client state before handshake with the server.
pub struct SrpClient<'a, D: Digest> {
    params: &'a SrpGroup,

    a: BigInt,
    a_pub: BigInt,

    d: PhantomData<D>,
}

/// SRP client state after handshake with the server.
pub struct SrpClientVerifier<D: Digest> {
    proof: Output<D>,
    server_proof: Output<D>,
    key: Output<D>,
}

/// Compute user private key as described in the RFC 5054. Consider using proper
/// password hashing algorithm instead.
pub fn srp_private_key<D: Digest>(username: &[u8], password: &[u8], salt: &[u8]) -> Output<D> {
    let p = {
        let mut d = D::new();
        d.update(username);
        d.update(b":");
        d.update(password);
        d.finalize()
    };
    let mut d = D::new();
    d.update(salt);
    d.update(p.as_slice());
    d.finalize()
}

impl<'a, D: Digest> SrpClient<'a, D> {
    /// Create new SRP client instance.
    pub fn new(a: &[u8], params: &'a SrpGroup) -> Self {
        let a = BigInt::from_bytes_be(Sign::Plus, a);
        let a_pub = params.modpow(&a);

        Self {
            params,
            a,
            a_pub,
            d: Default::default(),
        }
    }

    /// Get password verfier for user registration on the server
    pub fn get_password_verifier(&self, private_key: &[u8]) -> Vec<u8> {
        let x = BigInt::from_bytes_be(Sign::Plus, private_key);
        let v = self.params.modpow(&x);
        v.to_bytes_be().1
    }

    fn calc_key(&self, b_pub: &BigInt, x: &BigInt, u: &BigInt) -> GenericArray<u8, D::OutputSize> {
        let n = &self.params.n;
        let k = self.params.compute_k::<D>();
        let interm = k * self.params.modpow(x);
        let v = b_pub - &interm;
        // S = |B - kg^x| ^ (a + ux)
        let s = v.modpow(&(&self.a + (u * x)), n);
        D::digest(&s.to_bytes_be().1)
    }

    /// Process server reply to the handshake.
    pub fn process_reply(
        self,
        username: &[u8],
        salt: &[u8],
        private_key: &[u8],
        b_pub: &[u8],
    ) -> Result<SrpClientVerifier<D>, SrpAuthError> {
        let u = {
            let mut d = D::new();
            d.update(&self.a_pub.to_bytes_be().1);
            d.update(b_pub);
            let h = d.finalize();
            BigInt::from_bytes_be(Sign::Plus, h.as_slice())
        };

        let b_pub = BigInt::from_bytes_be(Sign::Plus, b_pub);

        // Safeguard against malicious B
        if &b_pub % &self.params.n == BigInt::default() {
            return Err(SrpAuthError {
                description: "Malicious b_pub value",
            });
        }

        let x = BigInt::from_bytes_be(Sign::Plus, private_key);
        let key = self.calc_key(&b_pub, &x, &u);
        // M = H(H(N) XOR H(g) | H(U) | s | A | B | K)
        let proof = {
            let hn = {
                let n = &self.params.n;
                let mut d = D::new();
                d.update(n.to_bytes_be().1);
                BigInt::from_bytes_be(Sign::Plus, &d.finalize())
            };
            let hg = {
                let g = &self.params.g;
                let mut d = D::new();
                d.update(g.to_bytes_be().1);
                BigInt::from_bytes_be(Sign::Plus, &d.finalize())
            };
            let hu = {
                let mut d = D::new();
                d.update(username);
                d.finalize()
            };
            let mut d = D::new();
            d.update((hn ^ hg).to_bytes_be().1);
            d.update(hu);
            d.update(salt);
            d.update(&self.a_pub.to_bytes_be().1);
            d.update(&b_pub.to_bytes_be().1);
            d.update(&key);
            d.finalize()
        };

        // M2 = H(A, M1, K)
        let server_proof = {
            let mut d = D::new();
            d.update(&self.a_pub.to_bytes_be().1);
            d.update(&proof);
            d.update(&key);
            d.finalize()
        };

        Ok(SrpClientVerifier {
            proof,
            server_proof,
            key,
        })
    }

    /// Get public ephemeral value for handshaking with the server.
    pub fn get_a_pub(&self) -> Vec<u8> {
        self.a_pub.to_bytes_be().1
    }
}

impl<D: Digest> SrpClientVerifier<D> {
    /// Get shared secret key without authenticating server, e.g. for using with
    /// authenticated encryption modes. DO NOT USE this method without
    /// some kind of secure authentication
    pub fn get_key(self) -> Output<D> {
        self.key
    }

    /// Verification data for sending to the server.
    pub fn get_proof(&self) -> Output<D> {
        self.proof.clone()
    }

    /// Verify server reply to verification data. It will return shared secret
    /// key in case of success.
    pub fn verify_server(self, reply: &[u8]) -> Result<Output<D>, SrpAuthError> {
        if self.server_proof.as_slice() != reply {
            Err(SrpAuthError {
                description: "Incorrect server proof",
            })
        } else {
            Ok(self.key)
        }
    }
}
