use num_bigint::BigUint;

pub fn powm(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let zero = BigUint::new(vec![0]);
    let one = BigUint::new(vec![1]);
    let two = BigUint::new(vec![2]);
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
