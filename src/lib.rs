
extern crate rand;
extern crate curve25519_dalek;
extern crate sha2;
extern crate core;

mod spake2;
pub use spake2::*;

#[cfg(test)]
mod tests {
    use spake2::{SPAKE2, Ed25519Group};

    #[test]
    fn test_basic() {
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(b"password",
                                                         b"idA", b"idB");
        let (s2, msg2) = SPAKE2::<Ed25519Group>::start_b(b"password",
                                                         b"idA", b"idB");
        let key1 = s1.finish(msg2.as_slice()).unwrap();
        let key2 = s2.finish(msg1.as_slice()).unwrap();
        assert_eq!(key1, key2);
    }


    #[test]
    fn it_works() {
    }

    #[test]
    #[should_panic(expected = "nope")]
    fn it_panics() {
        assert!(false, "nope");
    }
}
