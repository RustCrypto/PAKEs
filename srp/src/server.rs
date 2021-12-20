//! SRP server implementation
//!
//! # Usage
//! First receive user's username and public value `a_pub`, retrieve from a
//! database `UserRecord` for a given username, generate `b` (e.g. 512 bits
//! long) and initialize SRP server instance:
//!
//! ```ignore
//! use srp::groups::G_2048;
//!
//! let (username, a_pub) = conn.receive_handshake();
//! let user = db.retrieve_user_record(username);
//! let b = [0u8; 64];
//! rng.fill_bytes(&mut b);
//! let server = SrpServer::<Sha256>::new(&user, &a_pub, &b, &G_2048)?;
//! ```
//!
//! Next send to user `b_pub` and `salt` from user record:
//!
//! ```ignore
//! let b_pub = server.get_b_pub();
//! conn.reply_to_handshake(&user.salt, b_pub);
//! ```
//!
//! And finally receive user proof, verify it and send server proof in the
//! reply:
//!
//! ```ignore
//! let user_proof = conn.receive_proof();
//! let server_proof = server.verify(user_proof)?;
//! conn.send_proof(server_proof);
//! ```
//!
//! To get the shared secret use `get_key` method. As alternative to using
//! `verify` method it's also possible to use this key for authentificated
//! encryption.
use std::marker::PhantomData;

use digest::{Digest, Output};
use num_bigint::BigUint;

use crate::types::{SrpAuthError, SrpGroup};
use crate::utils::{compute_k, compute_m1, compute_m2, compute_u};

/// SRP server state
pub struct SrpServer<'a, D: Digest> {
    params: &'a SrpGroup,
    d: PhantomData<D>,
}

/// SRP server state after handshake with the client.
pub struct SrpServerVerifier<D: Digest> {
    m1: Output<D>,
    m2: Output<D>,
    key: Vec<u8>,
}

impl<'a, D: Digest> SrpServer<'a, D> {
    /// Create new server state.
    pub fn new(params: &'a SrpGroup) -> Self {
        Self {
            params,
            d: Default::default(),
        }
    }

    //  k*v + g^b % N
    pub fn compute_b_pub(&self, b: &BigUint, k: &BigUint, v: &BigUint) -> BigUint {
        let inter = (k * v) % &self.params.n;
        (inter + self.params.g.modpow(&b, &self.params.n)) % &self.params.n
    }

    // <premaster secret> = (A * v^u) ^ b % N
    pub fn compute_premaster_secret(
        &self,
        a_pub: &BigUint,
        v: &BigUint,
        u: &BigUint,
        b: &BigUint,
    ) -> BigUint {
        // (A * v^u)
        let base = (a_pub * v.modpow(&u, &self.params.n)) % &self.params.n;
        base.modpow(b, &self.params.n)
    }

    /// Get public ephemeral value for sending to the client.
    pub fn compute_public_ephemeral(&self, b: &[u8], v: &[u8]) -> Vec<u8> {
        self.compute_b_pub(
            &BigUint::from_bytes_be(&b),
            &compute_k::<D>(&self.params),
            &BigUint::from_bytes_be(&v),
        )
        .to_bytes_be()
    }

    /// Process client reply to the handshake.
    /// b is a random value,
    /// v is the provided during initial user registration
    pub fn process_reply(
        &self,
        b: &[u8],
        v: &[u8],
        a_pub: &[u8],
    ) -> Result<SrpServerVerifier<D>, SrpAuthError> {
        let b = BigUint::from_bytes_be(b);
        let v = BigUint::from_bytes_be(v);
        let a_pub = BigUint::from_bytes_be(a_pub);

        let k = compute_k::<D>(self.params);
        let b_pub = self.compute_b_pub(&b, &k, &v);

        // Safeguard against malicious B
        if &a_pub % &self.params.n == BigUint::default() {
            return Err(SrpAuthError {
                description: "illegal_parameter: malicious a_pub value",
            });
        }

        let u = compute_u::<D>(&a_pub.to_bytes_be(), &b_pub.to_bytes_be());

        let key = self.compute_premaster_secret(&a_pub, &v, &u, &b);

        let m1 = compute_m1::<D>(
            &a_pub.to_bytes_be(),
            &b_pub.to_bytes_be(),
            &key.to_bytes_be(),
        );

        let m2 = compute_m2::<D>(&a_pub.to_bytes_be(), &m1, &key.to_bytes_be());

        Ok(SrpServerVerifier {
            m1,
            m2,
            key: key.to_bytes_be(),
        })
    }
}

impl<D: Digest> SrpServerVerifier<D> {
    /// Get shared secret between user and the server. (do not forget to verify
    /// that keys are the same!)
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Verification data for sending to the client.
    pub fn proof(&self) -> &Output<D> {
        &self.m2
    }

    /// Process user proof of having the same shared secret.
    pub fn verify_client(&self, reply: &[u8]) -> Result<(), SrpAuthError> {
        if self.m1.as_slice() != reply {
            // TODO timing attack
            Err(SrpAuthError {
                description: "bad_record_mac: Incorrect client proof",
            })
        } else {
            Ok(())
        }
    }
}
