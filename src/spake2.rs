
pub fn foo() -> u8 {
    1
}


trait Group {
    type Scalar;
    type Element;
    pub fn scalarmult(s: Scalar) -> Element;
    pub fn scalar_from_integer(u8) -> Scalar;
}


struct SPAKE2<G: Group> {
    x: G::Scalar,
    password: Vec<u8>,
    idA: Vec<u8>,
    idB: Vec<u8>,
    pw: G::Scalar,
}

impl<G> for SPAKE2 {
    pub fn new<G>(password: &[u8], idA: &[u8], idB: &[u8]) -> SPAKE2<G> {
        let pw: G::Scalar = hash_to_scalar::<G::Scalar>(password);
        let x: G::Scalar = random_scalar::<G::Scalar>;

        let M1 G::Element = MAGIC();
        let msg1 = ...
        let mut pv = Vec::new();
        pv.extend_from_slice(password);
        (SPAKE2 {x: x, password: pv, ... }, msg1)
    }
    
    pub fn finish(self, msg2: &[u8]) -> Result<Key, SPAKEErr> {
    }
}


{
    let (mut s, msg1) = SPAKE2::<Ed25519>(&password, &idA, &idB);
    //let msg1 = s.msg1;
    let key = s.finish(msg2);
}
