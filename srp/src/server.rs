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
//! And finally recieve user proof, verify it and send server proof in the
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

use digest::Digest;
use generic_array::GenericArray;
use num_bigint::BigUint;

use crate::tools::powm;
use crate::types::{SrpAuthError, SrpGroup};

/// Data provided by users upon registration, usually stored in the database.
pub struct UserRecord<'a> {
    pub username: &'a [u8],
    pub salt: &'a [u8],
    /// Password verifier
    pub verifier: &'a [u8],
}

/// SRP server state
pub struct SrpServer<D: Digest> {
    b: BigUint,
    a_pub: BigUint,
    b_pub: BigUint,

    key: GenericArray<u8, D::OutputSize>,

    d: PhantomData<D>,
}

impl<D: Digest> SrpServer<D> {
    /// Create new server state.
    pub fn new(
        user: &UserRecord<'_>,
        a_pub: &[u8],
        b: &[u8],
        params: &SrpGroup,
    ) -> Result<Self, SrpAuthError> {
        let a_pub = BigUint::from_bytes_be(a_pub);
        // Safeguard against malicious A
        if &a_pub % &params.n == BigUint::default() {
            return Err(SrpAuthError {
                description: "Malicious a_pub value",
            });
        }
        let v = BigUint::from_bytes_be(user.verifier);
        let b = BigUint::from_bytes_be(b) % &params.n;
        let k = params.compute_k::<D>();
        // kv + g^b
        let interm = (k * &v) % &params.n;
        let b_pub = (interm + &params.powm(&b)) % &params.n;
        // H(A || B)
        let u = {
            let mut d = D::new();
            d.input(&a_pub.to_bytes_be());
            d.input(&b_pub.to_bytes_be());
            d.result()
        };
        let d = Default::default();
        //(Av^u) ^ b
        let key = {
            let u = BigUint::from_bytes_be(&u);
            let t = (&a_pub * powm(&v, &u, &params.n)) % &params.n;
            let s = powm(&t, &b, &params.n);
            D::digest(&s.to_bytes_be())
        };
        Ok(Self {
            b,
            a_pub,
            b_pub,
            key,
            d,
        })
    }

    /// Get private `b` value. (see `new_with_b` documentation)
    pub fn get_b(&self) -> Vec<u8> {
        self.b.to_bytes_be()
    }

    /// Get public `b_pub` value for sending to the user.
    pub fn get_b_pub(&self) -> Vec<u8> {
        self.b_pub.to_bytes_be()
    }

    /// Get shared secret between user and the server. (do not forget to verify
    /// that keys are the same!)
    pub fn get_key(&self) -> GenericArray<u8, D::OutputSize> {
        self.key.clone()
    }

    /// Process user proof of having the same shared secret and compute
    /// server proof for sending to the user.
    pub fn verify(
        &self,
        user_proof: &[u8],
    ) -> Result<GenericArray<u8, D::OutputSize>, SrpAuthError> {
        // M = H(A, B, K)
        let mut d = D::new();
        d.input(&self.a_pub.to_bytes_be());
        d.input(&self.b_pub.to_bytes_be());
        d.input(&self.key);

        if user_proof == d.result().as_slice() {
            // H(A, M, K)
            let mut d = D::new();
            d.input(&self.a_pub.to_bytes_be());
            d.input(user_proof);
            d.input(&self.key);
            Ok(d.result())
        } else {
            Err(SrpAuthError {
                description: "Incorrect user proof",
            })
        }
    }
}
