#![allow(dead_code)]

use curve25519_dalek::scalar::Scalar as c2_Scalar;
use curve25519_dalek::curve::ExtendedPoint as c2_Element;
use curve25519_dalek::constants::ED25519_BASEPOINT;
use curve25519_dalek::curve::CompressedEdwardsY;
use rand::{Rng, OsRng};
use sha2::Sha512;

#[derive(Debug)]
pub struct SPAKEErr;

pub trait Group {
    type Scalar;
    type Element;
    //type Element: Add<Output=Self::Element>
    //    + Mul<Self::Scalar, Output=Self::Element>;
    // const element_length: usize; // in unstable, or u8
    //type ElementBytes : Index<usize, Output=u8>+IndexMut<usize>; // later
    fn const_m() -> Self::Element;
    fn const_n() -> Self::Element;
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

    fn const_m() -> c2_Element {
        // there's a specific value to return here, not this
        ED25519_BASEPOINT
    }

    fn const_n() -> c2_Element {
        // there's a specific value to return here, not this
        ED25519_BASEPOINT
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

pub struct SPAKE2<G: Group> { //where &G::Scalar: Neg {
    x: G::Scalar,
    password: Vec<u8>,
    id_a: Vec<u8>,
    id_b: Vec<u8>,
    msg1: Vec<u8>,
    pw: G::Scalar,
}

impl<G: Group> SPAKE2<G> {
    pub fn new(password: &[u8], id_a: &[u8], id_b: &[u8])
               -> (SPAKE2<G>, Vec<u8>) {
        let mut cspring: OsRng = OsRng::new().unwrap();
        Self::new_internal(password, id_a, id_b, &mut cspring)
    }
    fn new_internal<T: Rng>(password: &[u8], id_a: &[u8], id_b: &[u8],
                            rng: &mut T)
                    -> (SPAKE2<G>, Vec<u8>) {
        //let pw: G::Scalar = hash_to_scalar::<G::Scalar>(password);
        let pw: G::Scalar = G::hash_to_scalar(password);
        let x: G::Scalar = G::random_scalar(rng);

        // m1 = B*x + M*pw
        let m1: G::Element = G::add(&G::basepoint_mult(&x),
                                    &G::scalarmult(&G::const_m(), &pw));
        //let m1: G::Element = &G::basepoint_mult(&x) + &(&G::const_m() * &pw);
        let msg1: Vec<u8> = G::element_to_bytes(&m1);
        let mut pv = Vec::new();
        pv.extend_from_slice(password);
        let mut id_a_copy = Vec::new();
        id_a_copy.extend_from_slice(id_a);
        let mut id_b_copy = Vec::new();
        id_b_copy.extend_from_slice(id_b);
        (SPAKE2 {x: x,
                 password: pv, // string
                 id_a: id_a_copy,
                 id_b: id_b_copy,
                 msg1: msg1.clone(),
                 pw: pw, // scalar
        }, msg1)
    }

    pub fn finish(self, msg2: &[u8]) -> Result<Vec<u8>, SPAKEErr> {
        #![allow(unused_variables)]
        // KA = scalarmult(Y* + scalarmult(N, -int(pw)), x)
        // key = H(H(pw) + H(idA) + H(idB) + X* + Y* + KA)
        let y = G::bytes_to_element(msg2);
        let foo = &G::scalarmult(&G::const_n(), &G::scalar_neg(&self.pw));

        //"nope".to_vec()
        //unimplemented!()
        Ok(Vec::new())
    }
}


#[cfg(test)]
mod test {
}
