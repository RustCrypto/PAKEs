use num::bigint::Sign;
use num::BigInt;

pub fn powm(base: &BigInt, exp: &BigInt, modulus: &BigInt) -> BigInt {
    let zero = BigInt::new(Sign::Plus, vec![0]);
    let one = BigInt::new(Sign::Plus, vec![1]);
    let two = BigInt::new(Sign::Plus, vec![2]);
    let mut exp = exp.clone();
    let mut result = one.clone();
    let mut base = base % modulus;

    while exp > zero {
        if &exp % &two == one {
            result = (result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }
    result
}
