//! This compares results against the python compatibility tests:
//! spake2.test.test_compat.SPAKE2.test_asymmetric . The python test passes a
//! deterministic RNG (used only for tests, of course) into the per-Group
//! "random_scalar()" function, which results in some particular scalar.
use super::*;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use hex;
use num_bigint::BigUint;

// the python tests show the long-integer form of scalars. the rust code
// wants an array of bytes (little-endian). Make sure the way we convert
// things works correctly.
fn decimal_to_scalar(d: &[u8]) -> c2_Scalar {
    let bytes = BigUint::parse_bytes(d, 10).unwrap().to_bytes_le();
    assert_eq!(bytes.len(), 32);
    let mut b2 = [0u8; 32];
    b2.copy_from_slice(&bytes);
    c2_Scalar::from_bytes_mod_order(b2)
}

#[test]
fn test_convert() {
    let t1_decimal =
        b"2238329342913194256032495932344128051776374960164957527413114840482143558222";
    let t1_scalar = decimal_to_scalar(t1_decimal);
    let t1_bytes = t1_scalar.to_bytes();
    let expected = [
        0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84, 0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2, 0x7d,
        0x52, 0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44, 0xd4, 0x49, 0xf4, 0xa8, 0x79, 0xd9,
        0xf2, 0x04,
    ];
    assert_eq!(t1_bytes, expected);
    //println!("t1_scalar is {:?}", t1_scalar);
}

#[test]
fn test_serialize_basepoint() {
    // make sure elements are serialized same as the python library
    let exp = "5866666666666666666666666666666666666666666666666666666666666666";
    let base_vec = ED25519_BASEPOINT_POINT.compress().as_bytes().to_vec();
    let base_hex = hex::encode(base_vec);
    println!("exp: {:?}", exp);
    println!("got: {:?}", base_hex);
    assert_eq!(exp, base_hex);
}

#[test]
fn test_password_to_scalar() {
    let password = Password::new(b"password");
    let expected_pw_scalar = decimal_to_scalar(
        b"3515301705789368674385125653994241092664323519848410154015274772661223168839",
    );
    let pw_scalar = Ed25519Group::hash_to_scalar(&password);
    println!("exp: {:?}", hex::encode(expected_pw_scalar.as_bytes()));
    println!("got: {:?}", hex::encode(pw_scalar.as_bytes()));
    assert_eq!(&pw_scalar, &expected_pw_scalar);
}

#[test]
fn test_sizes() {
    let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a(
        &Password::new(b"password"),
        &Identity::new(b"idA"),
        &Identity::new(b"idB"),
    );
    assert_eq!(msg1.len(), 1 + 32);
    let (s2, msg2) = SPAKE2::<Ed25519Group>::start_b(
        &Password::new(b"password"),
        &Identity::new(b"idA"),
        &Identity::new(b"idB"),
    );
    assert_eq!(msg2.len(), 1 + 32);
    let key1 = s1.finish(&msg2).unwrap();
    let key2 = s2.finish(&msg1).unwrap();
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);

    let (s1, msg1) = SPAKE2::<Ed25519Group>::start_symmetric(
        &Password::new(b"password"),
        &Identity::new(b"idS"),
    );
    assert_eq!(msg1.len(), 1 + 32);
    let (s2, msg2) = SPAKE2::<Ed25519Group>::start_symmetric(
        &Password::new(b"password"),
        &Identity::new(b"idS"),
    );
    assert_eq!(msg2.len(), 1 + 32);
    let key1 = s1.finish(&msg2).unwrap();
    let key2 = s2.finish(&msg1).unwrap();
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
}

#[test]
fn test_hash_ab() {
    let key = ed25519_hash_ab(
        b"pw",
        b"idA",
        b"idB",
        b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", // len=32
        b"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
        b"KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK",
    );
    let expected_key = "d59d9ba920f7092565cec747b08d5b2e981d553ac32fde0f25e5b4a4cfca3efd";
    assert_eq!(hex::encode(key), expected_key);
}

#[test]
fn test_hash_symmetric() {
    let key = ed25519_hash_symmetric(
        b"pw",
        b"idSymmetric",
        b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        b"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
        b"KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK",
    );
    let expected_key = "b0b31e4401aae37d91a9a8bf6fbb1298cafc005ff9142e3ffc5b9799fb11128b";
    assert_eq!(hex::encode(key), expected_key);
}

#[test]
fn test_asymmetric() {
    let scalar_a = decimal_to_scalar(
        b"2611694063369306139794446498317402240796898290761098242657700742213257926693",
    );
    let scalar_b = decimal_to_scalar(
        b"7002393159576182977806091886122272758628412261510164356026361256515836884383",
    );
    let expected_pw_scalar = decimal_to_scalar(
        b"3515301705789368674385125653994241092664323519848410154015274772661223168839",
    );

    println!("scalar_a is {}", hex::encode(scalar_a.as_bytes()));

    let (s1, msg1) = SPAKE2::<Ed25519Group>::start_a_internal(
        &Password::new(b"password"),
        &Identity::new(b"idA"),
        &Identity::new(b"idB"),
        scalar_a,
    );
    let expected_msg1 = "416fc960df73c9cf8ed7198b0c9534e2e96a5984bfc5edc023fd24dacf371f2af9";

    println!();
    println!("xys1: {:?}", hex::encode(s1.xy_scalar.as_bytes()));
    println!();
    println!("pws1: {:?}", hex::encode(s1.password_scalar.as_bytes()));
    println!("exp : {:?}", hex::encode(expected_pw_scalar.as_bytes()));
    println!();
    println!("msg1: {:?}", hex::encode(&msg1));
    println!("exp : {:?}", expected_msg1);
    println!();

    assert_eq!(
        hex::encode(expected_pw_scalar.as_bytes()),
        hex::encode(s1.password_scalar.as_bytes())
    );
    assert_eq!(hex::encode(&msg1), expected_msg1);

    let (s2, msg2) = SPAKE2::<Ed25519Group>::start_b_internal(
        &Password::new(b"password"),
        &Identity::new(b"idA"),
        &Identity::new(b"idB"),
        scalar_b,
    );
    assert_eq!(expected_pw_scalar, s2.password_scalar);
    assert_eq!(
        hex::encode(&msg2),
        "42354e97b88406922b1df4bea1d7870f17aed3dba7c720b313edae315b00959309"
    );

    let key1 = s1.finish(&msg2).unwrap();
    let key2 = s2.finish(&msg1).unwrap();
    assert_eq!(key1, key2);
    assert_eq!(
        hex::encode(key1),
        "712295de7219c675ddd31942184aa26e0a957cf216bc230d165b215047b520c1"
    );
}

#[test]
fn test_debug() {
    let (s1, _msg1) = SPAKE2::<Ed25519Group>::start_a(
        &Password::new(b"password"),
        &Identity::new(b"idA"),
        &Identity::new(b"idB"),
    );
    println!("s1: {:?}", s1);
    assert_eq!(
        format!("{:?}", s1),
        "SPAKE2 { group: \"Ed25519\", side: A, idA: \"(s=idA)\", idB: \"(s=idB)\", idS: \"(s=)\" }"
    );

    let (s2, _msg1) = SPAKE2::<Ed25519Group>::start_symmetric(
        &Password::new(b"password"),
        &Identity::new(b"idS"),
    );
    println!("s2: {:?}", s2);
    assert_eq!(format!("{:?}", s2),
               "SPAKE2 { group: \"Ed25519\", side: Symmetric, idA: \"(s=)\", idB: \"(s=)\", idS: \"(s=idS)\" }");
}
