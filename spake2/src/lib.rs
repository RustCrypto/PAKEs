//! An implementation of the [SPAKE2][1] password-authenticated key-exchange
//! algorithm
//!
//! This library implements the SPAKE2 password-authenticated key exchange
//! ("PAKE") algorithm. This allows two parties, who share a weak password, to
//! safely derive a strong shared secret (and therefore build an
//! encrypted+authenticated channel).
//!
//! A passive attacker who eavesdrops on the connection learns no information
//! about the password or the generated secret. An active attacker
//! (man-in-the-middle) gets exactly one guess at the password, and unless they
//! get it right, they learn no information about the password or the generated
//! secret. Each execution of the protocol enables one guess. The use of a weak
//! password is made safer by the rate-limiting of guesses: no off-line
//! dictionary attack is available to the network-level attacker, and the
//! protocol does not depend upon having previously-established confidentiality
//! of the network (unlike e.g. sending a plaintext password over TLS).
//!
//! The protocol requires the exchange of one pair of messages, so only one round
//! trip is necessary to establish the session key. If key-confirmation is
//! necessary, that will require a second round trip.
//!
//! All messages are bytestrings. For the default security level (using the
//! Ed25519 elliptic curve, roughly equivalent to an 128-bit symmetric key), the
//! message is 33 bytes long.
//!
//! This implementation is generic over a `Group`, which defines the cyclic
//! group to use, the functions which convert group elements and scalars to
//! and from bytestrings, and the three distinctive group elements used in
//! the blinding process. Only one such Group is implemented, named
//! `Ed25519Group`, which provides fast operations and high security, and is
//! compatible with my [python
//! implementation](https://github.com/warner/python-spake2).
//!
//! # What Is It Good For?
//!
//! PAKE can be used in a pairing protocol, like the initial version of Firefox
//! Sync (the one with J-PAKE), to introduce one device to another and help them
//! share secrets. In this mode, one device creates a random code, the user
//! copies that code to the second device, then both devices use the code as a
//! one-time password and run the PAKE protocol. Once both devices have a shared
//! strong key, they can exchange other secrets safely.
//!
//! PAKE can also be used (carefully) in a login protocol, where SRP is perhaps
//! the best-known approach. Traditional non-PAKE login consists of sending a
//! plaintext password through a TLS-encrypted channel, to a server which then
//! checks it (by hashing/stretching and comparing against a stored verifier). In
//! a PAKE login, both sides put the password into their PAKE protocol, and then
//! confirm that their generated key is the same. This nominally does not require
//! the initial TLS-protected channel. However note that it requires other,
//! deeper design considerations (the PAKE protocol must be bound to whatever
//! protected channel you end up using, else the attacker can wait for PAKE to
//! complete normally and then steal the channel), and is not simply a drop-in
//! replacement. In addition, the server cannot hash/stretch the password very
//! much (see the note on "Augmented PAKE" below), so unless the client is
//! willing to perform key-stretching before running PAKE, the server's stored
//! verifier will be vulnerable to a low-cost dictionary attack.
//!
//! # Usage
//!
//! Add the `spake2 dependency to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! spake2 = "0.1"
//! ```
//!
//! and this to your crate root:
//!
//! ```rust
//! extern crate spake2;
//! ```
//!
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
//! use spake2::{Ed25519Group, Identity, Password, SPAKE2};
//! # fn send(msg: &[u8]) {}
//! let (s1, outbound_msg) = SPAKE2::<Ed25519Group>::start_a(
//!    &Password::new(b"password"),
//!    &Identity::new(b"client id string"),
//!    &Identity::new(b"server id string"));
//! send(&outbound_msg);
//!
//! # fn receive() -> Vec<u8> { let (s2, i2) = SPAKE2::<Ed25519Group>::start_b(&Password::new(b"password"), &Identity::new(b"client id string"), &Identity::new(b"server id string")); i2 }
//! let inbound_msg = receive();
//! let key1 = s1.finish(&inbound_msg).unwrap();
//! ```
//!
//! while the server-side might do:
//!
//! ```rust
//! # fn send(msg: &[u8]) {}
//! use spake2::{Ed25519Group, Identity, Password, SPAKE2};
//! let (s1, outbound_msg) = SPAKE2::<Ed25519Group>::start_b(
//!    &Password::new(b"password"),
//!    &Identity::new(b"client id string"),
//!    &Identity::new(b"server id string"));
//! send(&outbound_msg);
//!
//! # fn receive() -> Vec<u8> { let (s2, i2) = SPAKE2::<Ed25519Group>::start_a(&Password::new(b"password"), &Identity::new(b"client id string"), &Identity::new(b"server id string")); i2 }
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
//! nacl.secretbox). It can also be fed into [HKDF] [1] to derive other
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
//! use spake2::{Ed25519Group, Identity, Password, SPAKE2};
//! let (s1, outbound_msg) = SPAKE2::<Ed25519Group>::start_symmetric(
//!    &Password::new(b"password"),
//!    &Identity::new(b"shared id string"));
//! send(&outbound_msg);
//!
//! # fn receive() -> Vec<u8> { let (s2, i2) = SPAKE2::<Ed25519Group>::start_symmetric(&Password::new(b"password"), &Identity::new(b"shared id string")); i2 }
//! let inbound_msg = receive();
//! let key1 = s1.finish(&inbound_msg).unwrap();
//! ```
//!
//! Dave does exactly the same:
//!
//! ```rust
//! # fn send(msg: &[u8]) {}
//! use spake2::{Ed25519Group, Identity, Password, SPAKE2};
//! let (s1, outbound_msg) = SPAKE2::<Ed25519Group>::start_symmetric(
//!    &Password::new(b"password"),
//!    &Identity::new(b"shared id string"));
//! send(&outbound_msg);
//!
//! # fn receive() -> Vec<u8> { let (s2, i2) = SPAKE2::<Ed25519Group>::start_symmetric(&Password::new(b"password"), &Identity::new(b"shared id string")); i2 }
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

#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(warnings)]
#![forbid(unsafe_code)]

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint as c2_Element;
use curve25519_dalek::scalar::Scalar as c2_Scalar;
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;
use std::ops::Deref;

/* "newtype pattern": it's a Vec<u8>, but only used for a specific argument
 * type, to distinguish between ones that are meant as passwords, and ones
 * that are meant as identity strings */

#[derive(PartialEq, Eq, Clone)]
pub struct Password(Vec<u8>);
impl Password {
    pub fn new(p: &[u8]) -> Password {
        Password(p.to_vec())
    }
}
impl Deref for Password {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

#[derive(PartialEq, Eq, Clone)]
pub struct Identity(Vec<u8>);
impl Deref for Identity {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}
impl Identity {
    pub fn new(p: &[u8]) -> Identity {
        Identity(p.to_vec())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorType {
    BadSide,
    WrongLength,
    CorruptMessage,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SPAKEErr {
    pub kind: ErrorType,
}

pub trait Group {
    type Scalar;
    type Element;
    //type Element: Add<Output=Self::Element>
    //    + Mul<Self::Scalar, Output=Self::Element>;
    // const element_length: usize; // in unstable, or u8
    //type ElementBytes : Index<usize, Output=u8>+IndexMut<usize>; // later
    type TranscriptHash;
    fn name() -> &'static str;
    fn const_m() -> Self::Element;
    fn const_n() -> Self::Element;
    fn const_s() -> Self::Element;
    fn hash_to_scalar(s: &[u8]) -> Self::Scalar;
    fn random_scalar<T>(cspring: &mut T) -> Self::Scalar
    where
        T: RngCore + CryptoRng;
    fn scalar_neg(s: &Self::Scalar) -> Self::Scalar;
    fn element_to_bytes(e: &Self::Element) -> Vec<u8>;
    fn bytes_to_element(b: &[u8]) -> Option<Self::Element>;
    fn element_length() -> usize;
    fn basepoint_mult(s: &Self::Scalar) -> Self::Element;
    fn scalarmult(e: &Self::Element, s: &Self::Scalar) -> Self::Element;
    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element;
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ed25519Group;

impl Group for Ed25519Group {
    type Scalar = c2_Scalar;
    type Element = c2_Element;
    //type ElementBytes = Vec<u8>;
    //type ElementBytes = [u8; 32];
    //type ScalarBytes
    type TranscriptHash = Sha256;

    fn name() -> &'static str {
        "Ed25519"
    }

    fn const_m() -> c2_Element {
        // python -c "import binascii, spake2; b=binascii.hexlify(spake2.ParamsEd25519.M.to_bytes()); print(', '.join(['0x'+b[i:i+2] for i in range(0,len(b),2)]))"
        // 15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312
        CompressedEdwardsY([
            0x15, 0xcf, 0xd1, 0x8e, 0x38, 0x59, 0x52, 0x98, 0x2b, 0x6a, 0x8f, 0x8c, 0x78, 0x54,
            0x96, 0x3b, 0x58, 0xe3, 0x43, 0x88, 0xc8, 0xe6, 0xda, 0xe8, 0x91, 0xdb, 0x75, 0x64,
            0x81, 0xa0, 0x23, 0x12,
        ])
        .decompress()
        .unwrap()
    }

    fn const_n() -> c2_Element {
        // python -c "import binascii, spake2; b=binascii.hexlify(spake2.ParamsEd25519.N.to_bytes()); print(', '.join(['0x'+b[i:i+2] for i in range(0,len(b),2)]))"
        // f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3
        CompressedEdwardsY([
            0xf0, 0x4f, 0x2e, 0x7e, 0xb7, 0x34, 0xb2, 0xa8, 0xf8, 0xb4, 0x72, 0xea, 0xf9, 0xc3,
            0xc6, 0x32, 0x57, 0x6a, 0xc6, 0x4a, 0xea, 0x65, 0x0b, 0x49, 0x6a, 0x8a, 0x20, 0xff,
            0x00, 0xe5, 0x83, 0xc3,
        ])
        .decompress()
        .unwrap()
    }

    fn const_s() -> c2_Element {
        // python -c "import binascii, spake2; b=binascii.hexlify(spake2.ParamsEd25519.S.to_bytes()); print(', '.join(['0x'+b[i:i+2] for i in range(0,len(b),2)]))"
        // 6f00dae87c1be1a73b5922ef431cd8f57879569c222d22b1cd71e8546ab8e6f1
        CompressedEdwardsY([
            0x6f, 0x00, 0xda, 0xe8, 0x7c, 0x1b, 0xe1, 0xa7, 0x3b, 0x59, 0x22, 0xef, 0x43, 0x1c,
            0xd8, 0xf5, 0x78, 0x79, 0x56, 0x9c, 0x22, 0x2d, 0x22, 0xb1, 0xcd, 0x71, 0xe8, 0x54,
            0x6a, 0xb8, 0xe6, 0xf1,
        ])
        .decompress()
        .unwrap()
    }

    fn hash_to_scalar(s: &[u8]) -> c2_Scalar {
        ed25519_hash_to_scalar(s)
    }
    fn random_scalar<T>(cspring: &mut T) -> c2_Scalar
    where
        T: RngCore + CryptoRng,
    {
        c2_Scalar::random(cspring)
    }
    fn scalar_neg(s: &c2_Scalar) -> c2_Scalar {
        -s
    }
    fn element_to_bytes(s: &c2_Element) -> Vec<u8> {
        s.compress().as_bytes().to_vec()
    }
    fn element_length() -> usize {
        32
    }
    fn bytes_to_element(b: &[u8]) -> Option<c2_Element> {
        if b.len() != 32 {
            return None;
        }
        //let mut bytes: [u8; 32] =
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(b);
        let cey = CompressedEdwardsY(bytes);
        // CompressedEdwardsY::new(b)
        cey.decompress()
    }

    fn basepoint_mult(s: &c2_Scalar) -> c2_Element {
        //c2_Element::basepoint_mult(s)
        ED25519_BASEPOINT_POINT * s
    }
    fn scalarmult(e: &c2_Element, s: &c2_Scalar) -> c2_Element {
        e * s
        //e.scalar_mult(s)
    }
    fn add(a: &c2_Element, b: &c2_Element) -> c2_Element {
        a + b
        //a.add(b)
    }
}

fn ed25519_hash_to_scalar(s: &[u8]) -> c2_Scalar {
    //c2_Scalar::hash_from_bytes::<Sha512>(&s)
    // spake2.py does:
    //  h = HKDF(salt=b"", ikm=s, hash=SHA256, info=b"SPAKE2 pw", len=32+16)
    //  i = int(h, 16)
    //  i % q

    let mut okm = [0u8; 32 + 16];
    Hkdf::<Sha256>::new(Some(b""), s)
        .expand(b"SPAKE2 pw", &mut okm)
        .unwrap();
    //println!("expanded:   {}{}", "................................", okm.iter().to_hex()); // ok

    let mut reducible = [0u8; 64]; // little-endian
    for (i, x) in okm.iter().enumerate().take(32 + 16) {
        reducible[32 + 16 - 1 - i] = *x;
    }
    //println!("reducible:  {}", reducible.iter().to_hex());
    c2_Scalar::from_bytes_mod_order_wide(&reducible)
    //let reduced = c2_Scalar::reduce(&reducible);
    //println!("reduced:    {}", reduced.as_bytes().to_hex());
    //println!("done");
    //reduced
}

fn ed25519_hash_ab(
    password_vec: &[u8],
    id_a: &[u8],
    id_b: &[u8],
    first_msg: &[u8],
    second_msg: &[u8],
    key_bytes: &[u8],
) -> Vec<u8> {
    assert_eq!(first_msg.len(), 32);
    assert_eq!(second_msg.len(), 32);
    // the transcript is fixed-length, made up of 6 32-byte values:
    // byte 0-31   : sha256(pw)
    // byte 32-63  : sha256(idA)
    // byte 64-95  : sha256(idB)
    // byte 96-127 : X_msg
    // byte 128-159: Y_msg
    // byte 160-191: K_bytes
    let mut transcript = [0u8; 6 * 32];

    let mut pw_hash = Sha256::new();
    pw_hash.input(password_vec);
    transcript[0..32].copy_from_slice(&pw_hash.result());

    let mut ida_hash = Sha256::new();
    ida_hash.input(id_a);
    transcript[32..64].copy_from_slice(&ida_hash.result());

    let mut idb_hash = Sha256::new();
    idb_hash.input(id_b);
    transcript[64..96].copy_from_slice(&idb_hash.result());

    transcript[96..128].copy_from_slice(first_msg);
    transcript[128..160].copy_from_slice(second_msg);
    transcript[160..192].copy_from_slice(key_bytes);

    //println!("transcript: {:?}", transcript.iter().to_hex());

    //let mut hash = G::TranscriptHash::default();
    let mut hash = Sha256::new();
    hash.input(transcript.to_vec());
    hash.result().to_vec()
}

fn ed25519_hash_symmetric(
    password_vec: &[u8],
    id_s: &[u8],
    msg_u: &[u8],
    msg_v: &[u8],
    key_bytes: &[u8],
) -> Vec<u8> {
    assert_eq!(msg_u.len(), 32);
    assert_eq!(msg_v.len(), 32);
    // # since we don't know which side is which, we must sort the messages
    // first_msg, second_msg = sorted([msg1, msg2])
    // transcript = b"".join([sha256(pw).digest(),
    //                        sha256(idSymmetric).digest(),
    //                        first_msg, second_msg, K_bytes])

    // the transcript is fixed-length, made up of 5 32-byte values:
    // byte 0-31   : sha256(pw)
    // byte 32-63  : sha256(idSymmetric)
    // byte 64-95  : X_msg
    // byte 96-127 : Y_msg
    // byte 128-159: K_bytes
    let mut transcript = [0u8; 5 * 32];

    let mut pw_hash = Sha256::new();
    pw_hash.input(password_vec);
    transcript[0..32].copy_from_slice(&pw_hash.result());

    let mut ids_hash = Sha256::new();
    ids_hash.input(id_s);
    transcript[32..64].copy_from_slice(&ids_hash.result());

    if msg_u < msg_v {
        transcript[64..96].copy_from_slice(msg_u);
        transcript[96..128].copy_from_slice(msg_v);
    } else {
        transcript[64..96].copy_from_slice(msg_v);
        transcript[96..128].copy_from_slice(msg_u);
    }
    transcript[128..160].copy_from_slice(key_bytes);

    let mut hash = Sha256::new();
    hash.input(transcript.to_vec());
    hash.result().to_vec()
}

/* "session type pattern" */

#[derive(Debug, PartialEq, Eq)]
enum Side {
    A,
    B,
    Symmetric,
}

// we implement a custom Debug below, to avoid revealing secrets in a dump
#[derive(PartialEq, Eq)]
pub struct SPAKE2<G: Group> {
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

impl<G: Group> SPAKE2<G> {
    fn start_internal(
        side: Side,
        password: &Password,
        id_a: &Identity,
        id_b: &Identity,
        id_s: &Identity,
        xy_scalar: G::Scalar,
    ) -> (SPAKE2<G>, Vec<u8>) {
        //let password_scalar: G::Scalar = hash_to_scalar::<G::Scalar>(password);
        let password_scalar: G::Scalar = G::hash_to_scalar(&password);

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
        password_vec.extend_from_slice(&password);
        let mut id_a_copy = Vec::new();
        id_a_copy.extend_from_slice(&id_a);
        let mut id_b_copy = Vec::new();
        id_b_copy.extend_from_slice(&id_b);
        let mut id_s_copy = Vec::new();
        id_s_copy.extend_from_slice(&id_s);

        let mut msg_and_side = Vec::new();
        msg_and_side.push(match side {
            Side::A => 0x41,         // 'A'
            Side::B => 0x42,         // 'B'
            Side::Symmetric => 0x53, // 'S'
        });
        msg_and_side.extend_from_slice(&msg1);

        (
            SPAKE2 {
                side,
                xy_scalar,
                password_vec, // string
                id_a: id_a_copy,
                id_b: id_b_copy,
                id_s: id_s_copy,
                msg1: msg1.clone(),
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
    ) -> (SPAKE2<G>, Vec<u8>) {
        Self::start_internal(
            Side::A,
            &password,
            &id_a,
            &id_b,
            &Identity::new(b""),
            xy_scalar,
        )
    }

    fn start_b_internal(
        password: &Password,
        id_a: &Identity,
        id_b: &Identity,
        xy_scalar: G::Scalar,
    ) -> (SPAKE2<G>, Vec<u8>) {
        Self::start_internal(
            Side::B,
            &password,
            &id_a,
            &id_b,
            &Identity::new(b""),
            xy_scalar,
        )
    }

    fn start_symmetric_internal(
        password: &Password,
        id_s: &Identity,
        xy_scalar: G::Scalar,
    ) -> (SPAKE2<G>, Vec<u8>) {
        Self::start_internal(
            Side::Symmetric,
            &password,
            &Identity::new(b""),
            &Identity::new(b""),
            &id_s,
            xy_scalar,
        )
    }

    pub fn start_a(password: &Password, id_a: &Identity, id_b: &Identity) -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring = OsRng;
        let xy_scalar: G::Scalar = G::random_scalar(&mut cspring);
        Self::start_a_internal(&password, &id_a, &id_b, xy_scalar)
    }

    pub fn start_b(password: &Password, id_a: &Identity, id_b: &Identity) -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring = OsRng;
        let xy_scalar: G::Scalar = G::random_scalar(&mut cspring);
        Self::start_b_internal(&password, &id_a, &id_b, xy_scalar)
    }

    pub fn start_symmetric(password: &Password, id_s: &Identity) -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring = OsRng;
        let xy_scalar: G::Scalar = G::random_scalar(&mut cspring);
        Self::start_symmetric_internal(&password, &id_s, xy_scalar)
    }

    pub fn finish(self, msg2: &[u8]) -> Result<Vec<u8>, SPAKEErr> {
        if msg2.len() != 1 + G::element_length() {
            return Err(SPAKEErr {
                kind: ErrorType::WrongLength,
            });
        }
        let msg_side = msg2[0];

        match self.side {
            Side::A => match msg_side {
                0x42 => (), // 'B'
                _ => {
                    return Err(SPAKEErr {
                        kind: ErrorType::BadSide,
                    })
                }
            },
            Side::B => match msg_side {
                0x41 => (), // 'A'
                _ => {
                    return Err(SPAKEErr {
                        kind: ErrorType::BadSide,
                    })
                }
            },
            Side::Symmetric => match msg_side {
                0x53 => (), // 'S'
                _ => {
                    return Err(SPAKEErr {
                        kind: ErrorType::BadSide,
                    })
                }
            },
        }

        let msg2_element = match G::bytes_to_element(&msg2[1..]) {
            Some(x) => x,
            None => {
                return Err(SPAKEErr {
                    kind: ErrorType::CorruptMessage,
                })
            }
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
            Side::A => ed25519_hash_ab(
                &self.password_vec,
                &self.id_a,
                &self.id_b,
                self.msg1.as_slice(),
                &msg2[1..],
                &key_bytes,
            ),
            Side::B => ed25519_hash_ab(
                &self.password_vec,
                &self.id_a,
                &self.id_b,
                &msg2[1..],
                self.msg1.as_slice(),
                &key_bytes,
            ),
            Side::Symmetric => ed25519_hash_symmetric(
                &self.password_vec,
                &self.id_s,
                &self.msg1,
                &msg2[1..],
                &key_bytes,
            ),
        })
    }
}

fn maybe_utf8(s: &[u8]) -> String {
    match String::from_utf8(s.to_vec()) {
        Ok(m) => format!("(s={})", m),
        Err(_) => format!("(hex={})", hex::encode(s)),
    }
}

impl<G: Group> fmt::Debug for SPAKE2<G> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("SPAKE2")
            .field("group", &G::name())
            .field("side", &self.side)
            .field("idA", &maybe_utf8(&self.id_a))
            .field("idB", &maybe_utf8(&self.id_b))
            .field("idS", &maybe_utf8(&self.id_s))
            .finish()
    }
}

#[cfg(test)]
mod tests;
