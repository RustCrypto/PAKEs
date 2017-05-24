
use curve25519_dalek::scalar::Scalar as c2_Scalar;
use curve25519_dalek::curve::ExtendedPoint as c2_Element;
use curve25519_dalek::constants::ED25519_BASEPOINT;
//use curve25519_dalek::curve::BasepointMult;
//use curve25519_dalek::curve::ScalarMult;
use rand::OsRng;
use sha2::Sha512;
//use std::ops::{Add, Mul};

trait Group {
    type Scalar;
    type Element;
    //type Element: Add<Output=Self::Element>
    //    + Mul<Self::Scalar, Output=Self::Element>;
    // const element_length: usize; // in unstable, or u8
    //type ElementBytes : Index<usize, Output=u8>+IndexMut<usize>; // later
    fn const_M() -> Self::Element;
    fn const_N() -> Self::Element;
    fn hash_to_scalar(s: &[u8]) -> Self::Scalar;
    fn random_scalar() -> Self::Scalar;
    fn basepoint_mult(s: &Self::Scalar) -> Self::Element;
    fn scalarmult(e: &Self::Element, s: &Self::Scalar) -> Self::Element;
    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element;
}

struct Ed25519Group;

impl Group for Ed25519Group {
    type Scalar = c2_Scalar;
    type Element = c2_Element;
    //type ElementBytes = Vec<u8>;
    //type ElementBytes = [u8; 32];
    //type ScalarBytes

    fn const_M() -> c2_Element {
        // there's a specific value to return here, not this
        ED25519_BASEPOINT
    }

    fn const_N() -> c2_Element {
        // there's a specific value to return here, not this
        ED25519_BASEPOINT
    }

    fn hash_to_scalar(s: &[u8]) -> c2_Scalar {
        c2_Scalar::hash_from_bytes::<Sha512>(&s)
    }
    fn random_scalar() -> c2_Scalar {
        let mut cspring: OsRng = OsRng::new().unwrap();
        c2_Scalar::random(&mut cspring)
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

struct SPAKE2<G: Group> {
    x: G::Scalar,
    password: Vec<u8>,
    idA: Vec<u8>,
    idB: Vec<u8>,
    msg1: Vec<u8>,
    pw: G::Scalar,
}

impl<G: Group> SPAKE2<G> {
    pub fn new(password: &[u8], idA: &[u8], idB: &[u8]) -> (SPAKE2<G>, Vec<u8>) {
        //let pw: G::Scalar = hash_to_scalar::<G::Scalar>(password);
        let pw: G::Scalar = G::hash_to_scalar(password);
        let x: G::Scalar = G::random_scalar();

        // M1 = B*x + M*pw
        let M1: G::Element = G::add(&G::basepoint_mult(&x),
                                    &G::scalarmult(&G::const_M(), &pw));
        //let M1: G::Element = &G::basepoint_mult(&x) + &(&G::const_M() * &pw);
        let msg1: Vec<u8> = unimplemented!(); // M1 to bytes
        let mut pv = Vec::new();
        pv.extend_from_slice(password);
        let mut idA_copy = Vec::new();
        idA_copy.extend_from_slice(idA);
        let mut idB_copy = Vec::new();
        idB_copy.extend_from_slice(idB);
        (SPAKE2 {x: x,
                 password: pv,
                 idA: idA_copy,
                 idB: idB_copy,
                 msg1: msg1.clone(),
                 pw: unimplemented!(),
        }, msg1)
    }

    /*pub fn finish(self, msg2: &[u8]) -> Result<Vec<u8>, SPAKEErr> {
    }*/
}


/*
{
    let (mut s, msg1) = SPAKE2::<Ed25519>(&password, &idA, &idB);
    //let msg1 = s.msg1;
    let key = s.finish(msg2);
}
*/
