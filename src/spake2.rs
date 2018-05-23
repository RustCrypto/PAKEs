#![allow(dead_code)]

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint as c2_Element;
use curve25519_dalek::scalar::Scalar as c2_Scalar;
use hkdf::Hkdf;
use num_bigint::BigUint;
use rand::{CryptoRng, OsRng, Rng};
use sha2::{Digest, Sha256};

//use hex::ToHex;

#[derive(Debug, PartialEq)]
pub enum ErrorType {
    BadSide,
    WrongLength,
    CorruptMessage,
}

#[derive(Debug, PartialEq)]
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

fn decimal_to_scalar(d: &[u8]) -> c2_Scalar {
    let bytes = BigUint::parse_bytes(d, 10).unwrap().to_bytes_le();
    assert_eq!(bytes.len(), 32);
    let mut b2 = [0u8; 32];
    b2.copy_from_slice(&bytes);
    c2_Scalar::from_bytes_mod_order(b2)
}

fn ed25519_hash_to_scalar(s: &[u8]) -> c2_Scalar {
    //c2_Scalar::hash_from_bytes::<Sha512>(&s)
    // spake2.py does:
    //  h = HKDF(salt=b"", ikm=s, hash=SHA256, info=b"SPAKE2 pw", len=32+16)
    //  i = int(h, 16)
    //  i % q

    let okm = Hkdf::<Sha256>::extract(Some(b""), s).expand(b"SPAKE2 pw", 32 + 16);
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
    hash.input(&transcript);
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
    hash.input(&transcript);
    hash.result().to_vec()
}

/* "session type pattern" */

enum Side {
    A,
    B,
    Symmetric,
}
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
        password: &[u8],
        id_a: &[u8],
        id_b: &[u8],
        id_s: &[u8],
        xy_scalar: G::Scalar,
    ) -> (SPAKE2<G>, Vec<u8>) {
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
        password: &[u8],
        id_a: &[u8],
        id_b: &[u8],
        xy_scalar: G::Scalar,
    ) -> (SPAKE2<G>, Vec<u8>) {
        Self::start_internal(Side::A, password, id_a, id_b, b"", xy_scalar)
    }

    fn start_b_internal(
        password: &[u8],
        id_a: &[u8],
        id_b: &[u8],
        xy_scalar: G::Scalar,
    ) -> (SPAKE2<G>, Vec<u8>) {
        Self::start_internal(Side::B, password, id_a, id_b, b"", xy_scalar)
    }

    fn start_symmetric_internal(
        password: &[u8],
        id_s: &[u8],
        xy_scalar: G::Scalar,
    ) -> (SPAKE2<G>, Vec<u8>) {
        Self::start_internal(Side::Symmetric, password, b"", b"", id_s, xy_scalar)
    }

    pub fn start_a(password: &[u8], id_a: &[u8], id_b: &[u8]) -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring: OsRng = OsRng::new().unwrap();
        let xy_scalar: G::Scalar = G::random_scalar(&mut cspring);
        Self::start_a_internal(password, id_a, id_b, xy_scalar)
    }

    pub fn start_b(password: &[u8], id_a: &[u8], id_b: &[u8]) -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring: OsRng = OsRng::new().unwrap();
        let xy_scalar: G::Scalar = G::random_scalar(&mut cspring);
        Self::start_b_internal(password, id_a, id_b, xy_scalar)
    }

    pub fn start_symmetric(password: &[u8], id_s: &[u8]) -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring: OsRng = OsRng::new().unwrap();
        let xy_scalar: G::Scalar = G::random_scalar(&mut cspring);
        Self::start_symmetric_internal(password, id_s, xy_scalar)
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

#[cfg(test)]
mod test {
    /* This compares results against the python compatibility tests:
    spake2.test.test_compat.SPAKE2.test_asymmetric . The python test passes a
    deterministic RNG (used only for tests, of course) into the per-Group
    "random_scalar()" function, which results in some particular scalar.
     */
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use hex;
    use spake2::{Ed25519Group, SPAKE2};

    // the python tests show the long-integer form of scalars. the rust code
    // wants an array of bytes (little-endian). Make sure the way we convert
    // things works correctly.

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
        let password = b"password";
        let expected_pw_scalar = decimal_to_scalar(
            b"3515301705789368674385125653994241092664323519848410154015274772661223168839",
        );
        let pw_scalar = Ed25519Group::hash_to_scalar(password);
        println!("exp: {:?}", hex::encode(expected_pw_scalar.as_bytes()));
        println!("got: {:?}", hex::encode(pw_scalar.as_bytes()));
        assert_eq!(&pw_scalar, &expected_pw_scalar);
    }

    #[test]
    fn test_sizes() {
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(b"password", b"idA", b"idB");
        assert_eq!(msg1.len(), 1 + 32);
        let (s2, msg2) = SPAKE2::<Ed25519Group>::start_b(b"password", b"idA", b"idB");
        assert_eq!(msg2.len(), 1 + 32);
        let key1 = s1.finish(&msg2).unwrap();
        let key2 = s2.finish(&msg1).unwrap();
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);

        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_symmetric(b"password", b"idS");
        assert_eq!(msg1.len(), 1 + 32);
        let (s2, msg2) = SPAKE2::<Ed25519Group>::start_symmetric(b"password", b"idS");
        assert_eq!(msg2.len(), 1 + 32);
        let key1 = s1.finish(&msg2).unwrap();
        let key2 = s2.finish(&msg1).unwrap();
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
    }

    #[test]
    fn test_hash_ab() {
        let key = ed25519_hash_ab(
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
        let key = ed25519_hash_symmetric(
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

        let (s1, msg1) =
            SPAKE2::<Ed25519Group>::start_a_internal(b"password", b"idA", b"idB", scalar_a);
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

        let (s2, msg2) =
            SPAKE2::<Ed25519Group>::start_b_internal(b"password", b"idA", b"idB", scalar_b);
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

}
