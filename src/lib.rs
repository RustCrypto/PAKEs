extern crate curve25519_dalek;
extern crate hex;
extern crate hkdf;
extern crate num_bigint;
extern crate rand;
extern crate sha2;

mod spake2;
pub use spake2::*;

#[cfg(test)]
mod tests {
    use spake2::{Ed25519Group, ErrorType, Identity, Password, SPAKE2, SPAKEErr};

    #[test]
    fn test_basic() {
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
        let (s2, msg2) = SPAKE2::<Ed25519Group>::start_b(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
        let key1 = s1.finish(msg2.as_slice()).unwrap();
        let key2 = s2.finish(msg1.as_slice()).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_mismatch() {
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
        let (s2, msg2) = SPAKE2::<Ed25519Group>::start_b(
            &Password::new(b"password2"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
        let key1 = s1.finish(msg2.as_slice()).unwrap();
        let key2 = s2.finish(msg1.as_slice()).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_reflected_message() {
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
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
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(
            &Password::new(b"password"),
            &Identity::new(b"idA"),
            &Identity::new(b"idB"),
        );
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
        let (s1, msg1) = SPAKE2::<Ed25519Group>::start_symmetric(
            &Password::new(b"password"),
            &Identity::new(b"idS"),
        );
        let (s2, msg2) = SPAKE2::<Ed25519Group>::start_symmetric(
            &Password::new(b"password"),
            &Identity::new(b"idS"),
        );
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
