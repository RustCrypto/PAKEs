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
use generic_array::GenericArray;
use num_bigint::{BigInt, Sign};

use crate::types::{SrpAuthError, SrpGroup};

/// Data provided by users upon registration, usually stored in the database.
pub struct UserRecord<'a> {
    pub username: &'a [u8],
    pub salt: &'a [u8],
    /// Password verifier
    pub verifier: &'a [u8],
}

/// SRP server state
pub struct SrpServer<'a, D: Digest> {
    user: &'a UserRecord<'a>,
    b: BigInt,
    a_pub: BigInt,
    b_pub: BigInt,

    key: Output<D>,

    d: PhantomData<D>,

    params: &'a SrpGroup,
}

impl<'a, D: Digest> SrpServer<'a, D> {
    /// Create new server state.
    pub fn new(
        user: &'a UserRecord,
        a_pub: &[u8],
        b: &[u8],
        params: &'a SrpGroup,
    ) -> Result<Self, SrpAuthError> {
        let a_pub = BigInt::from_bytes_be(Sign::Plus, a_pub);
        // Safeguard against malicious A
        if &a_pub % &params.n == BigInt::default() {
            return Err(SrpAuthError {
                description: "Malicious a_pub value",
            });
        }
        let v = BigInt::from_bytes_be(Sign::Plus, user.verifier);
        let b = BigInt::from_bytes_be(Sign::Plus, b);
        let k = params.compute_k::<D>();
        // kv + g^b
        let interm = k * &v;
        let b_pub = interm + &params.modpow(&b);
        // H(A || B)
        let u = {
            let mut d = D::new();
            d.update(&a_pub.to_bytes_be().1);
            d.update(&b_pub.to_bytes_be().1);
            d.finalize()
        };
        let d = Default::default();
        //(Av^u) ^ b
        let key = {
            let u = BigInt::from_bytes_be(Sign::Plus, &u);
            let t = &a_pub * v.modpow(&u, &params.n);
            let s = t.modpow(&b, &params.n);
            D::digest(&s.to_bytes_be().1)
        };
        Ok(Self {
            user,
            b,
            a_pub,
            b_pub,
            key,
            d,
            params,
        })
    }

    /// Get private `b` value. (see `new_with_b` documentation)
    pub fn get_b(&self) -> Vec<u8> {
        self.b.to_bytes_be().1
    }

    /// Get public `b_pub` value for sending to the user.
    pub fn get_b_pub(&self) -> Vec<u8> {
        self.b_pub.to_bytes_be().1
    }

    /// Get shared secret between user and the server. (do not forget to verify
    /// that keys are the same!)
    pub fn get_key(&self) -> Output<D> {
        self.key.clone()
    }

    /// Process user proof of having the same shared secret and compute
    /// server proof for sending to the user.
    pub fn verify(
        &self,
        user_proof: &[u8],
    ) -> Result<GenericArray<u8, D::OutputSize>, SrpAuthError> {
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
                d.update(self.user.username);
                d.finalize()
            };
            let mut d = D::new();
            d.update((hn ^ hg).to_bytes_be().1);
            d.update(hu);
            d.update(self.user.salt);
            d.update(&self.a_pub.to_bytes_be().1);
            d.update(&self.b_pub.to_bytes_be().1);
            d.update(&self.key);
            d.finalize()
        };

        if user_proof == proof.as_slice() {
            // H(A, M, K)
            let mut d = D::new();
            d.update(&self.a_pub.to_bytes_be().1);
            d.update(user_proof);
            d.update(&self.key);
            Ok(d.finalize())
        } else {
            Err(SrpAuthError {
                description: "Incorrect user proof",
            })
        }
    }
}
