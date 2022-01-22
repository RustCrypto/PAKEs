#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

//! # Usage
//!
//! Alice and Bob both initialize their SPAKE2 instances with the same (weak)
//! password. They will exchange messages to (hopefully) derive a shared secret
//! key. The protocol is symmetric: for each operation that Alice does, Bob will
//! do the same.
//!
//! However, there are two roles in the SPAKE2 protocol, "A" and "B". The two
//! sides must agree ahead of time which one will play which role (the
//! messages they generate depend upon which side they play). There are two
//! separate constructor functions, `start_a()` and `start_b()`, and a
//! complete interaction will use one of each (one `start_a` on one computer,
//! and one `start_b` on the other computer).
//!
//! Each instance of a SPAKE2 protocol uses a set of shared parameters. These
//! include a group, a generator, and a pair of arbitrary group elements.
//! This library comes a single pre-generated parameter set, but could be
//! extended with others.
//!
//! You start by calling `start_a()` (or `_b)` with the password and identity
//! strings for both sides. This gives you back a state object and the first
//! message, which you must send to your partner. Once you receive the
//! corresponding inbound message, you pass it into the state object
//! (consuming both in the process) by calling `s.finish()`, and you get back
//! the shared key as a bytestring.
//!
//! The password and identity strings must each be wrapped in a "newtype",
//! which is a simple `struct` that protects against swapping the different
//! types of bytestrings.
//!
//! Thus a client-side program start with:
//!
//! ```rust
//! use spake2::{Ed25519Group, Identity, Password, Spake2};
//! # fn send(msg: &[u8]) {}
//! let (s1, outbound_msg) = Spake2::<Ed25519Group>::start_a(
//!    &Password::new(b"password"),
//!    &Identity::new(b"client id string"),
//!    &Identity::new(b"server id string"));
//! send(&outbound_msg);
//!
//! # fn receive() -> Vec<u8> { let (s2, i2) = Spake2::<Ed25519Group>::start_b(&Password::new(b"password"), &Identity::new(b"client id string"), &Identity::new(b"server id string")); i2 }
//! let inbound_msg = receive();
//! let key1 = s1.finish(&inbound_msg).unwrap();
//! ```
//!
//! while the server-side might do:
//!
//! ```rust
//! # fn send(msg: &[u8]) {}
//! use spake2::{Ed25519Group, Identity, Password, Spake2};
//! let (s1, outbound_msg) = Spake2::<Ed25519Group>::start_b(
//!    &Password::new(b"password"),
//!    &Identity::new(b"client id string"),
//!    &Identity::new(b"server id string"));
//! send(&outbound_msg);
//!
//! # fn receive() -> Vec<u8> { let (s2, i2) = Spake2::<Ed25519Group>::start_a(&Password::new(b"password"), &Identity::new(b"client id string"), &Identity::new(b"server id string")); i2 }
//! let inbound_msg = receive();
//! let key2 = s1.finish(&inbound_msg).unwrap();
//! ```
//!
//! If both sides used the same password, and there is no man-in-the-middle,
//! then `key1` and `key2` will be identical. If not, the two sides will get
//! different keys. When one side encrypts with `key1`, and the other side
//! attempts to decrypt with `key2`, they'll get nothing but garbled noise.
//!
//! The shared key can be used as an HMAC key to provide data integrity on
//! subsequent messages, or as an authenticated-encryption key (e.g.
//! nacl.secretbox). It can also be fed into [HKDF][1] to derive other
//! session keys as necessary.
//!
//! The `SPAKE2` instances, and the messages they create, are single-use. Create
//! a new one for each new session. `finish` consumes the instance.
//!
//! # Symmetric Usage
//!
//! A single SPAKE2 instance must be used asymmetrically: the two sides must
//! somehow decide (ahead of time) which role they will each play. The
//! implementation includes the side identifier in the exchanged message to
//! guard against a `start_a` talking to another `start_a`. Typically a
//! "client" will take on the `A` role, and the "server" will be `B`.
//!
//! This is a nuisance for more egalitarian protocols, where there's no clear
//! way to assign these roles ahead of time. In this case, use
//! `start_symmetric()` on both sides. This uses a different set of
//! parameters (so it is not interoperable with `start_A` or `start_b`), but
//! should otherwise behave the same way. The symmetric mode uses only one
//! identity string, not two.
//!
//! Carol does:
//!
//! ```rust
//! # fn send(msg: &[u8]) {}
//! use spake2::{Ed25519Group, Identity, Password, Spake2};
//! let (s1, outbound_msg) = Spake2::<Ed25519Group>::start_symmetric(
//!    &Password::new(b"password"),
//!    &Identity::new(b"shared id string"));
//! send(&outbound_msg);
//!
//! # fn receive() -> Vec<u8> { let (s2, i2) = Spake2::<Ed25519Group>::start_symmetric(&Password::new(b"password"), &Identity::new(b"shared id string")); i2 }
//! let inbound_msg = receive();
//! let key1 = s1.finish(&inbound_msg).unwrap();
//! ```
//!
//! Dave does exactly the same:
//!
//! ```rust
//! # fn send(msg: &[u8]) {}
//! use spake2::{Ed25519Group, Identity, Password, Spake2};
//! let (s1, outbound_msg) = Spake2::<Ed25519Group>::start_symmetric(
//!    &Password::new(b"password"),
//!    &Identity::new(b"shared id string"));
//! send(&outbound_msg);
//!
//! # fn receive() -> Vec<u8> { let (s2, i2) = Spake2::<Ed25519Group>::start_symmetric(&Password::new(b"password"), &Identity::new(b"shared id string")); i2 }
//! let inbound_msg = receive();
//! let key1 = s1.finish(&inbound_msg).unwrap();
//! ```
//!
//! # Identifier Strings
//!
//! The SPAKE2 protocol includes a pair of "identity strings" `idA` and `idB`
//! that are included in the final key-derivation hash. This binds the key to a
//! single pair of parties, or for some specific purpose.
//!
//! For example, when user "alice" logs into "example.com", both sides should set
//! `idA = b"alice"` and `idB = b"example.com"`. This prevents an attacker from
//! substituting messages from unrelated login sessions (other users on the same
//! server, or other servers for the same user).
//!
//! This also makes sure the session is established with the correct service. If
//! Alice has one password for "example.com" but uses it for both login and
//! file-transfer services, `idB` should be different for the two services.
//! Otherwise if Alice is simultaneously connecting to both services, and
//! attacker could rearrange the messages and cause her login client to connect
//! to the file-transfer server, and vice versa.
//!
//! `idA` and `idB` must be bytestrings (slices of `<u8>`).
//!
//! `start_symmetric` uses a single `idSymmetric=` string, instead of `idA`
//! and `idB`. Both sides must provide the same `idSymmetric=`, or leave it
//! empty.
//!
//! # Serialization
//!
//! Sometimes, you can't hold the SPAKE2 instance in memory for the whole
//! negotiation: perhaps all your program state is stored in a database, and
//! nothing lives in RAM for more than a few moments.
//!
//! Unfortunately the Rust implementation does not yet provide serialization
//! of the state object. A future version should correct this.
//!
//! # Security
//!
//! This library is probably not constant-time, and does not protect against
//! timing attacks. Do not allow attackers to measure how long it takes you
//! to create or respond to a message. This matters somewhat less for pairing
//! protocols, because their passwords are single-use randomly-generated
//! keys, so an attacker has much less to work with.
//!
//! This library depends upon a strong source of random numbers. Do not use it on
//! a system where os.urandom() is weak.
//!
//! # Speed
//!
//! To run the built-in speed tests, just run `cargo bench`.
//!
//! SPAKE2 consists of two phases, separated by a single message exchange.
//! The time these phases take is split roughly 50/50. On my 2.8GHz Core-i7
//! (i7-7600U) cpu, the built-in Ed25519Group parameters take about 112
//! microseconds for each phase, and the message exchanged is 33 bytes long.
//!
//! # Testing
//!
//! Run `cargo test` to run the built-in test suite.
//!
//! # History
//!
//! The protocol was described as "PAKE2" in ["cryptobook"] [2] from Dan Boneh
//! and Victor Shoup. This is a form of "SPAKE2", defined by Abdalla and
//! Pointcheval at [RSA 2005] [3]. Additional recommendations for groups and
//! distinguished elements were published in [Ladd's IETF draft] [4].
//!
//! The Ed25519 implementation uses code adapted from Daniel Bernstein (djb),
//! Matthew Dempsky, Daniel Holth, Ron Garret, with further optimizations by
//! Brian Warner[5]. The "arbitrary element" computation, which must be the same
//! for both participants, is from python-pure25519 version 0.5.
//!
//! The Boneh/Shoup chapter that defines PAKE2 also defines an augmented variant
//! named "PAKE2+", which changes one side (typically a server) to record a
//! derivative of the password instead of the actual password. In PAKE2+, a
//! server compromise does not immediately give access to the passwords: instead,
//! the attacker must perform an offline dictionary attack against the stolen
//! data before they can learn the passwords. PAKE2+ support is planned, but not
//! yet implemented.
//!
//! The security of the symmetric case was proved by Kobara/Imai[6] in 2003, and
//! uses different (slightly weaker?) reductions than that of the asymmetric
//! form. See also Mike Hamburg's analysis[7] from 2015.
//!
//! Brian Warner first wrote the Python version in July 2010. He wrote this
//! Rust version in in May 2017.
//!
//! ### footnotes
//!
//! [1]: https://tools.ietf.org/html/rfc5869 "HKDF"
//! [2]: http://crypto.stanford.edu/~dabo/cryptobook/  "cryptobook"
//! [3]: http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf "RSA 2005"
//! [4]: https://tools.ietf.org/html/draft-ladd-spake2-01 "Ladd's IETF draft"
//! [5]: https://github.com/warner/python-pure25519
//! [6]: http://eprint.iacr.org/2003/038.pdf "Pretty-Simple Password-Authenticated Key-Exchange Under Standard Assumptions"
//! [7]: https://moderncrypto.org/mail-archive/curves/2015/000419.html "PAKE questions"

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[cfg_attr(test, macro_use)]
extern crate std;

mod ed25519;
mod error;
mod group;

pub use self::{
    ed25519::Ed25519Group,
    error::{Error, Result},
    group::Group,
};

use alloc::vec::Vec;
use core::{fmt, ops::Deref, str};
use curve25519_dalek::{edwards::EdwardsPoint as c2_Element, scalar::Scalar as c2_Scalar};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "getrandom")]
use rand_core::OsRng;

/// Password
// TODO(tarcieri): avoid allocation?
#[derive(PartialEq, Eq, Clone)]
pub struct Password(Vec<u8>);

impl Password {
    /// Create a new password.
    pub fn new(p: impl AsRef<[u8]>) -> Password {
        Password(p.as_ref().to_vec())
    }
}

impl Deref for Password {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

/// SPAKE2 identity.
// TODO(tarcieri): avoid allocation?
#[derive(PartialEq, Eq, Clone)]
pub struct Identity(Vec<u8>);

impl Deref for Identity {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl Identity {
    /// Create a new identity.
    pub fn new(p: &[u8]) -> Identity {
        Identity(p.to_vec())
    }
}

/// Session type identifying the "side" in a SPAKE2 exchange.
#[derive(Debug, PartialEq, Eq)]
enum Side {
    A,
    B,
    Symmetric,
}

/// SPAKE2 algorithm.
#[derive(Eq, PartialEq)]
pub struct Spake2<G: Group> {
    //where &G::Scalar: Neg {
    side: Side,
    xy_scalar: G::Scalar,
    password_vec: Vec<u8>,
    id_a: Vec<u8>,
    id_b: Vec<u8>,
    id_s: Vec<u8>,
    msg1: Vec<u8>,
    password_scalar: G::Scalar,
}

impl<G: Group> Spake2<G> {
    /// Start with identity `idA`.
    ///
    /// Uses the system RNG.
    #[cfg(feature = "getrandom")]
    #[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
    pub fn start_a(password: &Password, id_a: &Identity, id_b: &Identity) -> (Spake2<G>, Vec<u8>) {
        Self::start_a_with_rng(password, id_a, id_b, OsRng)
    }

    /// Start with identity `idB`.
    ///
    /// Uses the system RNG.
    #[cfg(feature = "getrandom")]
    #[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
    pub fn start_b(password: &Password, id_a: &Identity, id_b: &Identity) -> (Spake2<G>, Vec<u8>) {
        Self::start_b_with_rng(password, id_a, id_b, OsRng)
    }

    /// Start with symmetric identity.
    ///
    /// Uses the system RNG.
    #[cfg(feature = "getrandom")]
    #[cfg_attr(docsrs, doc(cfg(feature = "getrandom")))]
    pub fn start_symmetric(password: &Password, id_s: &Identity) -> (Spake2<G>, Vec<u8>) {
        Self::start_symmetric_with_rng(password, id_s, OsRng)
    }

    /// Start with identity `idA` and the provided cryptographically secure RNG.
    pub fn start_a_with_rng(
        password: &Password,
        id_a: &Identity,
        id_b: &Identity,
        mut csrng: impl CryptoRng + RngCore,
    ) -> (Spake2<G>, Vec<u8>) {
        let xy_scalar: G::Scalar = G::random_scalar(&mut csrng);
        Self::start_a_internal(password, id_a, id_b, xy_scalar)
    }

    /// Start with identity `idB` and the provided cryptographically secure RNG.
    pub fn start_b_with_rng(
        password: &Password,
        id_a: &Identity,
        id_b: &Identity,
        mut csrng: impl CryptoRng + RngCore,
    ) -> (Spake2<G>, Vec<u8>) {
        let xy_scalar: G::Scalar = G::random_scalar(&mut csrng);
        Self::start_b_internal(password, id_a, id_b, xy_scalar)
    }

    /// Start with symmetric identity and the provided cryptographically secure RNG.
    pub fn start_symmetric_with_rng(
        password: &Password,
        id_s: &Identity,
        mut csrng: impl CryptoRng + RngCore,
    ) -> (Spake2<G>, Vec<u8>) {
        let xy_scalar: G::Scalar = G::random_scalar(&mut csrng);
        Self::start_symmetric_internal(password, id_s, xy_scalar)
    }

    /// Finish SPAKE2.
    pub fn finish(self, msg2: &[u8]) -> Result<Vec<u8>> {
        if msg2.len() != 1 + G::element_length() {
            return Err(Error::WrongLength);
        }
        let msg_side = msg2[0];

        match self.side {
            Side::A => match msg_side {
                0x42 => (), // 'B'
                _ => return Err(Error::BadSide),
            },
            Side::B => match msg_side {
                0x41 => (), // 'A'
                _ => return Err(Error::BadSide),
            },
            Side::Symmetric => match msg_side {
                0x53 => (), // 'S'
                _ => return Err(Error::BadSide),
            },
        }

        let msg2_element = match G::bytes_to_element(&msg2[1..]) {
            Some(x) => x,
            None => return Err(Error::CorruptMessage),
        };

        // a: K = (Y+N*(-pw))*x
        // b: K = (X+M*(-pw))*y
        let unblinding = match self.side {
            Side::A => G::const_n(),
            Side::B => G::const_m(),
            Side::Symmetric => G::const_s(),
        };
        let tmp1 = G::scalarmult(&unblinding, &G::scalar_neg(&self.password_scalar));
        let tmp2 = G::add(&msg2_element, &tmp1);
        let key_element = G::scalarmult(&tmp2, &self.xy_scalar);
        let key_bytes = G::element_to_bytes(&key_element);

        // key = H(H(pw) + H(idA) + H(idB) + X + Y + K)
        //transcript = b"".join([sha256(pw).digest(),
        //                       sha256(idA).digest(), sha256(idB).digest(),
        //                       X_msg, Y_msg, K_bytes])
        //key = sha256(transcript).digest()
        // note that both sides must use the same order

        Ok(match self.side {
            Side::A => ed25519::hash_ab(
                &self.password_vec,
                &self.id_a,
                &self.id_b,
                self.msg1.as_slice(),
                &msg2[1..],
                &key_bytes,
            ),
            Side::B => ed25519::hash_ab(
                &self.password_vec,
                &self.id_a,
                &self.id_b,
                &msg2[1..],
                self.msg1.as_slice(),
                &key_bytes,
            ),
            Side::Symmetric => ed25519::hash_symmetric(
                &self.password_vec,
                &self.id_s,
                &self.msg1,
                &msg2[1..],
                &key_bytes,
            ),
        })
    }

    fn start_internal(
        side: Side,
        password: &Password,
        id_a: &Identity,
        id_b: &Identity,
        id_s: &Identity,
        xy_scalar: G::Scalar,
    ) -> (Spake2<G>, Vec<u8>) {
        //let password_scalar: G::Scalar = hash_to_scalar::<G::Scalar>(password);
        let password_scalar: G::Scalar = G::hash_to_scalar(password);

        // a: X = B*x + M*pw
        // b: Y = B*y + N*pw
        // sym: X = B*x * S*pw
        let blinding = match side {
            Side::A => G::const_m(),
            Side::B => G::const_n(),
            Side::Symmetric => G::const_s(),
        };
        let m1: G::Element = G::add(
            &G::basepoint_mult(&xy_scalar),
            &G::scalarmult(&blinding, &password_scalar),
        );
        //let m1: G::Element = &G::basepoint_mult(&x) + &(blinding * &password_scalar);
        let msg1: Vec<u8> = G::element_to_bytes(&m1);
        let mut password_vec = Vec::new();
        password_vec.extend_from_slice(password);
        let mut id_a_copy = Vec::new();
        id_a_copy.extend_from_slice(id_a);
        let mut id_b_copy = Vec::new();
        id_b_copy.extend_from_slice(id_b);
        let mut id_s_copy = Vec::new();
        id_s_copy.extend_from_slice(id_s);

        let mut msg_and_side = vec![match side {
            Side::A => 0x41,         // 'A'
            Side::B => 0x42,         // 'B'
            Side::Symmetric => 0x53, // 'S'
        }];
        msg_and_side.extend_from_slice(&msg1);

        (
            Spake2 {
                side,
                xy_scalar,
                password_vec, // string
                id_a: id_a_copy,
                id_b: id_b_copy,
                id_s: id_s_copy,
                msg1,
                password_scalar, // scalar
            },
            msg_and_side,
        )
    }

    fn start_a_internal(
        password: &Password,
        id_a: &Identity,
        id_b: &Identity,
        xy_scalar: G::Scalar,
    ) -> (Spake2<G>, Vec<u8>) {
        Self::start_internal(
            Side::A,
            password,
            id_a,
            id_b,
            &Identity::new(b""),
            xy_scalar,
        )
    }

    fn start_b_internal(
        password: &Password,
        id_a: &Identity,
        id_b: &Identity,
        xy_scalar: G::Scalar,
    ) -> (Spake2<G>, Vec<u8>) {
        Self::start_internal(
            Side::B,
            password,
            id_a,
            id_b,
            &Identity::new(b""),
            xy_scalar,
        )
    }

    fn start_symmetric_internal(
        password: &Password,
        id_s: &Identity,
        xy_scalar: G::Scalar,
    ) -> (Spake2<G>, Vec<u8>) {
        Self::start_internal(
            Side::Symmetric,
            password,
            &Identity::new(b""),
            &Identity::new(b""),
            id_s,
            xy_scalar,
        )
    }
}

impl<G: Group> fmt::Debug for Spake2<G> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("SPAKE2")
            .field("group", &G::name())
            .field("side", &self.side)
            .field("idA", &MaybeUtf8(&self.id_a))
            .field("idB", &MaybeUtf8(&self.id_b))
            .field("idS", &MaybeUtf8(&self.id_s))
            .finish()
    }
}

struct MaybeUtf8<'a>(&'a [u8]);

impl fmt::Debug for MaybeUtf8<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(s) = str::from_utf8(self.0) {
            write!(fmt, "(s={})", s)
        } else {
            write!(fmt, "(hex=")?;

            for byte in self.0 {
                write!(fmt, "{:x}", byte)?;
            }

            write!(fmt, ")")
        }
    }
}

/// This compares results against the python compatibility tests:
/// spake2.test.test_compat.SPAKE2.test_asymmetric . The python test passes a
/// deterministic RNG (used only for tests, of course) into the per-Group
/// "random_scalar()" function, which results in some particular scalar.
#[cfg(all(test, feature = "std"))]
mod tests {
    use crate::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use num_bigint::BigUint;

    // the python tests show the long-integer form of scalars. the rust code
    // wants an array of bytes (little-endian). Make sure the way we convert
    // things works correctly.
    fn decimal_to_scalar(d: &[u8]) -> c2_Scalar {
        let bytes = BigUint::parse_bytes(d, 10).unwrap().to_bytes_le();
        assert_eq!(bytes.len(), 32);
        let mut b2 = [0u8; 32];
        b2.copy_from_slice(&bytes);
        c2_Scalar::from_bytes_mod_order(b2)
    }

    #[test]
    fn test_convert() {
        let t1_decimal =
            b"2238329342913194256032495932344128051776374960164957527413114840482143558222";
        let t1_scalar = decimal_to_scalar(t1_decimal);
        let t1_bytes = t1_scalar.to_bytes();
        let expected = [
            0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84, 0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2,
            0x7d, 0x52, 0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44, 0xd4, 0x49, 0xf4, 0xa8,
            0x79, 0xd9, 0xf2, 0x04,
        ];
        assert_eq!(t1_bytes, expected);
        //println!("t1_scalar is {:?}", t1_scalar);
    }

    #[test]
    fn test_serialize_basepoint() {
        // make sure elements are serialized same as the python library
        let exp = "5866666666666666666666666666666666666666666666666666666666666666";
        let base_vec = ED25519_BASEPOINT_POINT.compress().as_bytes().to_vec();
        let base_hex = hex::encode(base_vec);
        println!("exp: {:?}", exp);
        println!("got: {:?}", base_hex);
        assert_eq!(exp, base_hex);
    }

    #[test]
    fn test_password_to_scalar() {
        let password = Password::new(b"password");
        let expected_pw_scalar = decimal_to_scalar(
            b"3515301705789368674385125653994241092664323519848410154015274772661223168839",
        );
        let pw_scalar = Ed25519Group::hash_to_scalar(&password);
        println!("exp: {:?}", hex::encode(expected_pw_scalar.as_bytes()));
        println!("got: {:?}", hex::encode(pw_scalar.as_bytes()));
        assert_eq!(&pw_scalar, &expected_pw_scalar);
    }

    #[test]
    fn test_sizes() {
        let (s1, msg1) = Spake2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
        assert_eq!(msg1.len(), 1 + 32);
        let (s2, msg2) = Spake2::<Ed25519Group>::start_b(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
        assert_eq!(msg2.len(), 1 + 32);
        let key1 = s1.finish(&msg2).unwrap();
        let key2 = s2.finish(&msg1).unwrap();
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);

        let (s1, msg1) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(b"password"),
            &Identity::new(b"idS"),
        );
        assert_eq!(msg1.len(), 1 + 32);
        let (s2, msg2) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(b"password"),
            &Identity::new(b"idS"),
        );
        assert_eq!(msg2.len(), 1 + 32);
        let key1 = s1.finish(&msg2).unwrap();
        let key2 = s2.finish(&msg1).unwrap();
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
    }

    #[test]
    fn test_hash_ab() {
        let key = ed25519::hash_ab(
            b"pw",
            b"idA",
            b"idB",
            b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", // len=32
            b"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
            b"KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK",
        );
        let expected_key = "d59d9ba920f7092565cec747b08d5b2e981d553ac32fde0f25e5b4a4cfca3efd";
        assert_eq!(hex::encode(key), expected_key);
    }

    #[test]
    fn test_hash_symmetric() {
        let key = ed25519::hash_symmetric(
            b"pw",
            b"idSymmetric",
            b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            b"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
            b"KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK",
        );
        let expected_key = "b0b31e4401aae37d91a9a8bf6fbb1298cafc005ff9142e3ffc5b9799fb11128b";
        assert_eq!(hex::encode(key), expected_key);
    }

    #[test]
    fn test_asymmetric() {
        let scalar_a = decimal_to_scalar(
            b"2611694063369306139794446498317402240796898290761098242657700742213257926693",
        );
        let scalar_b = decimal_to_scalar(
            b"7002393159576182977806091886122272758628412261510164356026361256515836884383",
        );
        let expected_pw_scalar = decimal_to_scalar(
            b"3515301705789368674385125653994241092664323519848410154015274772661223168839",
        );

        println!("scalar_a is {}", hex::encode(scalar_a.as_bytes()));

        let (s1, msg1) = Spake2::<Ed25519Group>::start_a_internal(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
            scalar_a,
        );
        let expected_msg1 = "416fc960df73c9cf8ed7198b0c9534e2e96a5984bfc5edc023fd24dacf371f2af9";

        println!();
        println!("xys1: {:?}", hex::encode(s1.xy_scalar.as_bytes()));
        println!();
        println!("pws1: {:?}", hex::encode(s1.password_scalar.as_bytes()));
        println!("exp : {:?}", hex::encode(expected_pw_scalar.as_bytes()));
        println!();
        println!("msg1: {:?}", hex::encode(&msg1));
        println!("exp : {:?}", expected_msg1);
        println!();

        assert_eq!(
            hex::encode(expected_pw_scalar.as_bytes()),
            hex::encode(s1.password_scalar.as_bytes())
        );
        assert_eq!(hex::encode(&msg1), expected_msg1);

        let (s2, msg2) = Spake2::<Ed25519Group>::start_b_internal(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
            scalar_b,
        );
        assert_eq!(expected_pw_scalar, s2.password_scalar);
        assert_eq!(
            hex::encode(&msg2),
            "42354e97b88406922b1df4bea1d7870f17aed3dba7c720b313edae315b00959309"
        );

        let key1 = s1.finish(&msg2).unwrap();
        let key2 = s2.finish(&msg1).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(
            hex::encode(key1),
            "712295de7219c675ddd31942184aa26e0a957cf216bc230d165b215047b520c1"
        );
    }

    #[test]
    fn test_debug() {
        let (s1, _msg1) = Spake2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
        println!("s1: {:?}", s1);
        assert_eq!(
            format!("{:?}", s1),
            "SPAKE2 { group: \"Ed25519\", side: A, idA: (s=idA), idB: (s=idB), idS: (s=) }"
        );

        let (s2, _msg1) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(b"password"),
            &Identity::new(b"idS"),
        );
        println!("s2: {:?}", s2);
        assert_eq!(
            format!("{:?}", s2),
            "SPAKE2 { group: \"Ed25519\", side: Symmetric, idA: (s=), idB: (s=), idS: (s=idS) }"
        );
    }
}
