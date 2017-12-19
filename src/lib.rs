extern crate curve25519_dalek;
extern crate hkdf;
extern crate num_bigint;
extern crate rand;
extern crate sha2;

//extern crate hex;

mod spake2;
pub use spake2::*;

#[cfg(test)]
extern crate hex;

#[cfg(test)]
mod tests {
    use spake2::{Ed25519Group, ErrorType, SPAKE2, SPAKEErr};

    #[test]
    fn test_basic() {
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(b"password", b"idA", b"idB");
        let (s2, msg2) = SPAKE2::<Ed25519Group>::start_b(b"password", b"idA", b"idB");
        let key1 = s1.finish(msg2.as_slice()).unwrap();
        let key2 = s2.finish(msg1.as_slice()).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_mismatch() {
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(b"password", b"idA", b"idB");
        let (s2, msg2) = SPAKE2::<Ed25519Group>::start_b(b"password2", b"idA", b"idB");
        let key1 = s1.finish(msg2.as_slice()).unwrap();
        let key2 = s2.finish(msg1.as_slice()).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_reflected_message() {
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(b"password", b"idA", b"idB");
        let r = s1.finish(msg1.as_slice());
        assert_eq!(
            r.unwrap_err(),
            SPAKEErr {
                kind: ErrorType::BadSide,
            }
        );
    }

    #[test]
    fn test_bad_length() {
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(b"password", b"idA", b"idB");
        let mut msg2 = Vec::<u8>::with_capacity(msg1.len() + 1);
        msg2.resize(msg1.len() + 1, 0u8);
        let r = s1.finish(&msg2);
        assert_eq!(
            r.unwrap_err(),
            SPAKEErr {
                kind: ErrorType::WrongLength,
            }
        );
    }

    #[test]
    fn test_basic_symmetric() {
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_symmetric(b"password", b"idS");
        let (s2, msg2) = SPAKE2::<Ed25519Group>::start_symmetric(b"password", b"idS");
        let key1 = s1.finish(msg2.as_slice()).unwrap();
        let key2 = s2.finish(msg1.as_slice()).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn it_works() {}

    #[test]
    #[should_panic(expected = "nope")]
    fn it_panics() {
        assert!(false, "nope");
    }
}
