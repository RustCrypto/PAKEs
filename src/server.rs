//! SRP server implementation
//!
//! # Usage
//! First receive user's username and public value `a_pub`, retrieve from a
//! database `UserRecord` for a given username and initialize SRP server state:
//! 
//! ```ignore
//! let mut rng = rand::os::OsRng::new().unwrap();
//! let (username, a_pub) = conn.receive_handshake();
//! let user = db.retrieve_user_record(username);
//! let server = SrpServer::<Sha256>::new(&user, &a_pub, &srp_params, &mut rng)?;
//! ```
//! 
//! Next send to user `b_pub` and `salt` from user record:
//! 
//! ```ignore
//! let b_pub = server.get_b_pub();
//! conn.reply_to_handshake(&user.salt, b_pub);
//! ```
//! 
//! And finally recieve user proof, verify it and send server proof as reply:
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

use rand::Rng;
use num::{BigUint, Zero};
use digest::Digest;
use generic_array::GenericArray;

use tools::powm;
use types::{SrpAuthError, SrpParams};

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

    d: PhantomData<D>
}

impl< D: Digest> SrpServer< D> {
    /// Create new server state with randomly generated `b`.
    pub fn new<R: Rng>(user: &UserRecord, a_pub: &[u8], params: &SrpParams,
            rng: &mut R)
        -> Result<Self, SrpAuthError>
    {
        let l = params.n.bits()/8; 
        let b = rng.gen_iter::<u8>().take(l).collect::<Vec<u8>>();
        Self::new_with_b(user, a_pub, &b, params)
    }

    /// Create new server state with given `b`.
    ///
    /// Usefull if it's not convenient to keep `SrpServer` state between
    /// handshake and verification steps. (e.g. when working over HTTP and
    /// storing `b` in a database)
    pub fn new_with_b(user: &UserRecord, a_pub: &[u8], b: &[u8],
                params: &SrpParams)
        -> Result<Self, SrpAuthError>
    {
        let a_pub = BigUint::from_bytes_le(a_pub);
        // Safeguard against malicious A
        if &a_pub % &params.n == BigUint::zero() {
            return Err(SrpAuthError { description: "Malicious a_pub value" })
        }
        let v = BigUint::from_bytes_le(user.verifier);
        let b = BigUint::from_bytes_le(b)  % &params.n;
        // kv + g^b
        let interm = (&params.k * &v) % &params.n;
        let b_pub = (interm + &params.powm(&b)) % &params.n;
        // H(A || B)
        let u = {
            let mut d = D::new();
            d.input(&a_pub.to_bytes_le());
            d.input(&b_pub.to_bytes_le());
            d.result()
        };
        let d = Default::default();
        //(Av^u) ^ b
        let key = {
            let u =  BigUint::from_bytes_le(&u);
            let t = (&a_pub * powm(&v, &u, &params.n)) % &params.n;
            let s = powm(&t, &b, &params.n);
            D::digest(&s.to_bytes_le())
        };
        Ok(Self { b, a_pub, b_pub, key, d})
    }

    /// Get private `b` value. (see `new_with_b` documentation)
    pub fn get_b(&self) -> Vec<u8> {
        self.b.to_bytes_le()
    }

    /// Get public `b_pub` value for sending to the user.
    pub fn get_b_pub(&self) -> Vec<u8> {
        self.b_pub.to_bytes_le()
    }

    /// Get shared secret between user and the server. (do not forget to verify
    /// that keys are the same!)
    pub fn get_key(&self) -> GenericArray<u8, D::OutputSize> {
        self.key.clone()
    }

    /// Process user proof of having the same shared secret and compute
    /// server proof for sending to the user.
    pub fn verify(&self, user_proof: &[u8])
        -> Result<GenericArray<u8, D::OutputSize>, SrpAuthError>
    {
        // M = H(A, B, K)
        let mut d = D::new();
        d.input(&self.a_pub.to_bytes_le());
        d.input(&self.b_pub.to_bytes_le());
        d.input(&self.key);

        if user_proof == d.result().as_slice() {
            // H(A, M, K)
            let mut d = D::new();
            d.input(&self.a_pub.to_bytes_le());
            d.input(user_proof);
            d.input(&self.key);
            Ok(d.result())
        } else {
            Err(SrpAuthError { description: "Incorrect user proof" })
        }
    }
}
