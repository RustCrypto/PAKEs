
extern crate rand;
extern crate curve25519_dalek;

pub mod spake2;
//use spake2::*;

#[cfg(test)]
mod tests {
    use spake2;
    #[test]
    fn test_foo() {
        assert_eq!(spake2::foo(), 1);
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
