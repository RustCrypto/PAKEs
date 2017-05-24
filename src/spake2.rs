#![allow(dead_code)]

use curve25519_dalek::scalar::Scalar as c2_Scalar;
use curve25519_dalek::curve::ExtendedPoint as c2_Element;
use curve25519_dalek::constants::ED25519_BASEPOINT;
use curve25519_dalek::curve::CompressedEdwardsY;
use rand::{Rng, OsRng};
use sha2::{Sha256, Sha512, Digest};

#[derive(Debug)]
pub struct SPAKEErr;

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
    fn random_scalar<T: Rng>(cspring: &mut T) -> Self::Scalar;
    fn scalar_neg(s: &Self::Scalar) -> Self::Scalar;
    fn element_to_bytes(e: &Self::Element) -> Vec<u8>;
    fn bytes_to_element(b: &[u8]) -> Option<Self::Element>;
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
            0x15, 0xcf, 0xd1, 0x8e, 0x38, 0x59, 0x52, 0x98, 0x2b, 0x6a, 0x8f,
            0x8c, 0x78, 0x54, 0x96, 0x3b, 0x58, 0xe3, 0x43, 0x88, 0xc8, 0xe6,
            0xda, 0xe8, 0x91, 0xdb, 0x75, 0x64, 0x81, 0xa0, 0x23, 0x12,
            ]).decompress().unwrap()
    }

    fn const_n() -> c2_Element {
        // python -c "import binascii, spake2; b=binascii.hexlify(spake2.ParamsEd25519.N.to_bytes()); print(', '.join(['0x'+b[i:i+2] for i in range(0,len(b),2)]))"
        // f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3
        CompressedEdwardsY([
            0xf0, 0x4f, 0x2e, 0x7e, 0xb7, 0x34, 0xb2, 0xa8, 0xf8, 0xb4, 0x72,
            0xea, 0xf9, 0xc3, 0xc6, 0x32, 0x57, 0x6a, 0xc6, 0x4a, 0xea, 0x65,
            0x0b, 0x49, 0x6a, 0x8a, 0x20, 0xff, 0x00, 0xe5, 0x83, 0xc3,
        ]).decompress().unwrap()

    }

    fn const_s() -> c2_Element {
        // python -c "import binascii, spake2; b=binascii.hexlify(spake2.ParamsEd25519.S.to_bytes()); print(', '.join(['0x'+b[i:i+2] for i in range(0,len(b),2)]))"
        // 6f00dae87c1be1a73b5922ef431cd8f57879569c222d22b1cd71e8546ab8e6f1
        CompressedEdwardsY([
            0x6f, 0x00, 0xda, 0xe8, 0x7c, 0x1b, 0xe1, 0xa7, 0x3b, 0x59, 0x22,
            0xef, 0x43, 0x1c, 0xd8, 0xf5, 0x78, 0x79, 0x56, 0x9c, 0x22, 0x2d,
            0x22, 0xb1, 0xcd, 0x71, 0xe8, 0x54, 0x6a, 0xb8, 0xe6, 0xf1,
        ]).decompress().unwrap()

    }

    fn hash_to_scalar(s: &[u8]) -> c2_Scalar {
        c2_Scalar::hash_from_bytes::<Sha512>(&s)
    }
    fn random_scalar<T: Rng>(cspring: &mut T) -> c2_Scalar {
        c2_Scalar::random(cspring)
    }
    fn scalar_neg(s: &c2_Scalar) -> c2_Scalar {
        -s
    }
    fn element_to_bytes(s: &c2_Element) -> Vec<u8> {
        s.compress_edwards().as_bytes().to_vec()
    }
    fn bytes_to_element(b: &[u8]) -> Option<c2_Element> {
        if b.len() != 32 { return None; }
        //let mut bytes: [u8; 32] =
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(b);
        let cey = CompressedEdwardsY(bytes);
        // CompressedEdwardsY::new(b)
        cey.decompress()
    }

    fn basepoint_mult(s: &c2_Scalar) -> c2_Element {
        //c2_Element::basepoint_mult(s)
        &ED25519_BASEPOINT * s
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


/* "session type pattern" */

enum Side {
    A,
    B,
    Symmetric,
}
pub struct SPAKE2<G: Group> { //where &G::Scalar: Neg {
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
    fn start_internal<T: Rng>(side: Side,
                              password: &[u8],
                              id_a: &[u8], id_b: &[u8], id_s: &[u8],
                              rng: &mut T)
                              -> (SPAKE2<G>, Vec<u8>) {
        //let password_scalar: G::Scalar = hash_to_scalar::<G::Scalar>(password);
        let password_scalar: G::Scalar = G::hash_to_scalar(password);
        let xy: G::Scalar = G::random_scalar(rng);

        // a: X = B*x + M*pw
        // b: Y = B*y + N*pw
        // sym: X = B*x * S*pw
        let blinding = match side {
            Side::A => G::const_m(),
            Side::B => G::const_n(),
            Side::Symmetric => G::const_s(),
        };
        let m1: G::Element = G::add(&G::basepoint_mult(&xy),
                                    &G::scalarmult(&blinding, &password_scalar));
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

        (SPAKE2 {
            side: side,
            xy_scalar: xy,
            password_vec: password_vec, // string
            id_a: id_a_copy,
            id_b: id_b_copy,
            id_s: id_s_copy,
            msg1: msg1.clone(),
            password_scalar: password_scalar, // scalar
        }, msg1)
    }

    pub fn start_a(password: &[u8], id_a: &[u8], id_b: &[u8])
               -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring: OsRng = OsRng::new().unwrap();
        Self::start_internal(Side::A,
                             password, id_a, id_b, b"", &mut cspring)
    }

    pub fn start_b(password: &[u8], id_a: &[u8], id_b: &[u8])
               -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring: OsRng = OsRng::new().unwrap();
        Self::start_internal(Side::B,
                             password, id_a, id_b, b"", &mut cspring)
    }


    pub fn start_symmetric(password: &[u8], id_s: &[u8])
               -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring: OsRng = OsRng::new().unwrap();
        Self::start_internal(Side::Symmetric,
                             password, b"", b"", id_s, &mut cspring)
    }

    pub fn finish(self, msg2: &[u8]) -> Result<Vec<u8>, SPAKEErr> {
        // a: K = (Y+N*(-pw))*x
        // b: K = (X+M*(-pw))*y
        let msg2_element = G::bytes_to_element(msg2).unwrap();
        let unblinding = match self.side {
            Side::A => G::const_n(),
            Side::B => G::const_m(),
            Side::Symmetric => G::const_s(),
        };
        let tmp1 = G::scalarmult(&unblinding,
                                 &G::scalar_neg(&self.password_scalar));
        let tmp2 = G::add(&msg2_element, &tmp1);
        let key_element = G::scalarmult(&tmp2, &self.xy_scalar);

        // key = H(H(pw) + H(idA) + H(idB) + X + Y + K)
        //transcript = b"".join([sha256(pw).digest(),
        //                       sha256(idA).digest(), sha256(idB).digest(),
        //                       X_msg, Y_msg, K_bytes])
        //key = sha256(transcript).digest()
        // note that both sides must use the same order

        Ok(match self.side {
            Side::A => self.hash_ab(&self.msg1.as_slice(), msg2, &key_element),
            Side::B => self.hash_ab(msg2, &self.msg1.as_slice(), &key_element),
            Side::Symmetric => self.hash_symmetric(msg2, &key_element),
        })
    }

    fn hash_ab(&self, first_msg: &[u8], second_msg: &[u8],
               key_element: &G::Element) -> Vec<u8> {
        let mut transcript = Vec::<u8>::new();

        let mut pw_hash = Sha256::new();
        pw_hash.input(&self.password_vec);
        transcript.extend_from_slice(pw_hash.result().as_slice());

        let mut ida_hash = Sha256::new();
        ida_hash.input(&self.id_a);
        transcript.extend_from_slice(ida_hash.result().as_slice());

        let mut idb_hash = Sha256::new();
        idb_hash.input(&self.id_b);
        transcript.extend_from_slice(idb_hash.result().as_slice());

        transcript.extend_from_slice(first_msg);
        transcript.extend_from_slice(second_msg);

        let k_bytes = G::element_to_bytes(&key_element);
        transcript.extend_from_slice(k_bytes.as_slice());

        //let mut hash = G::TranscriptHash::default();
        let mut hash = Sha256::default();
        hash.input(transcript.as_slice());
        hash.result().to_vec()
    }

    fn hash_symmetric(&self, msg2: &[u8], key_element: &G::Element) -> Vec<u8> {
        // # since we don't know which side is which, we must sort the messages
        // first_msg, second_msg = sorted([msg1, msg2])
        // transcript = b"".join([sha256(pw).digest(),
        //                        sha256(idSymmetric).digest(),
        //                        first_msg, second_msg, K_bytes])
        let mut transcript = Vec::<u8>::new();

        let mut pw_hash = Sha256::new();
        pw_hash.input(&self.password_vec);
        transcript.extend_from_slice(pw_hash.result().as_slice());

        let mut ids_hash = Sha256::new();
        ids_hash.input(&self.id_s);
        transcript.extend_from_slice(ids_hash.result().as_slice());

        let msg_u = self.msg1.as_slice();
        let msg_v = msg2;
        if msg_u < msg_v {
            transcript.extend_from_slice(&msg_u);
            transcript.extend_from_slice(msg_v);
        } else {
            transcript.extend_from_slice(msg_v);
            transcript.extend_from_slice(&msg_u);
        }

        let k_bytes = G::element_to_bytes(&key_element);
        transcript.extend_from_slice(k_bytes.as_slice());

        let mut hash = Sha256::default();
        hash.input(transcript.as_slice());
        hash.result().to_vec()
    }
}


#[cfg(test)]
mod test {
}
