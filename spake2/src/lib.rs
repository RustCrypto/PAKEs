#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(warnings)]
#![forbid(unsafe_code)]

extern crate curve25519_dalek;
extern crate hex;
extern crate hkdf;
extern crate num_bigint;
extern crate rand;
extern crate sha2;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint as c2_Element;
use curve25519_dalek::scalar::Scalar as c2_Scalar;

use hkdf::Hkdf;
use rand::{CryptoRng, OsRng, Rng};
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
    fn const_m() -> Self::Element;
    fn const_n() -> Self::Element;
    fn const_s() -> Self::Element;
    fn hash_to_scalar(s: &[u8]) -> Self::Scalar;
    fn random_scalar<T>(cspring: &mut T) -> Self::Scalar
    where
        T: Rng + CryptoRng;
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

    fn const_m() -> c2_Element {
        // python -c "import binascii, spake2; b=binascii.hexlify(spake2.ParamsEd25519.M.to_bytes()); print(', '.join(['0x'+b[i:i+2] for i in range(0,len(b),2)]))"
        // 15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312
        CompressedEdwardsY([
            0x15, 0xcf, 0xd1, 0x8e, 0x38, 0x59, 0x52, 0x98, 0x2b, 0x6a, 0x8f, 0x8c, 0x78, 0x54,
            0x96, 0x3b, 0x58, 0xe3, 0x43, 0x88, 0xc8, 0xe6, 0xda, 0xe8, 0x91, 0xdb, 0x75, 0x64,
            0x81, 0xa0, 0x23, 0x12,
        ]).decompress()
        .unwrap()
    }

    fn const_n() -> c2_Element {
        // python -c "import binascii, spake2; b=binascii.hexlify(spake2.ParamsEd25519.N.to_bytes()); print(', '.join(['0x'+b[i:i+2] for i in range(0,len(b),2)]))"
        // f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3
        CompressedEdwardsY([
            0xf0, 0x4f, 0x2e, 0x7e, 0xb7, 0x34, 0xb2, 0xa8, 0xf8, 0xb4, 0x72, 0xea, 0xf9, 0xc3,
            0xc6, 0x32, 0x57, 0x6a, 0xc6, 0x4a, 0xea, 0x65, 0x0b, 0x49, 0x6a, 0x8a, 0x20, 0xff,
            0x00, 0xe5, 0x83, 0xc3,
        ]).decompress()
        .unwrap()
    }

    fn const_s() -> c2_Element {
        // python -c "import binascii, spake2; b=binascii.hexlify(spake2.ParamsEd25519.S.to_bytes()); print(', '.join(['0x'+b[i:i+2] for i in range(0,len(b),2)]))"
        // 6f00dae87c1be1a73b5922ef431cd8f57879569c222d22b1cd71e8546ab8e6f1
        CompressedEdwardsY([
            0x6f, 0x00, 0xda, 0xe8, 0x7c, 0x1b, 0xe1, 0xa7, 0x3b, 0x59, 0x22, 0xef, 0x43, 0x1c,
            0xd8, 0xf5, 0x78, 0x79, 0x56, 0x9c, 0x22, 0x2d, 0x22, 0xb1, 0xcd, 0x71, 0xe8, 0x54,
            0x6a, 0xb8, 0xe6, 0xf1,
        ]).decompress()
        .unwrap()
    }

    fn hash_to_scalar(s: &[u8]) -> c2_Scalar {
        ed25519_hash_to_scalar(s)
    }
    fn random_scalar<T>(cspring: &mut T) -> c2_Scalar
    where
        T: Rng + CryptoRng,
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
    Hkdf::<Sha256>::extract(Some(b""), s)
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
        let mut cspring: OsRng = OsRng::new().unwrap();
        let xy_scalar: G::Scalar = G::random_scalar(&mut cspring);
        Self::start_a_internal(&password, &id_a, &id_b, xy_scalar)
    }

    pub fn start_b(password: &Password, id_a: &Identity, id_b: &Identity) -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring: OsRng = OsRng::new().unwrap();
        let xy_scalar: G::Scalar = G::random_scalar(&mut cspring);
        Self::start_b_internal(&password, &id_a, &id_b, xy_scalar)
    }

    pub fn start_symmetric(password: &Password, id_s: &Identity) -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring: OsRng = OsRng::new().unwrap();
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SPAKE2(G=?, side={:?}, idA={}, idB={}, idS={})",
            self.side,
            maybe_utf8(&self.id_a),
            maybe_utf8(&self.id_b),
            maybe_utf8(&self.id_s)
        )
    }
}

#[cfg(test)]
mod tests;
