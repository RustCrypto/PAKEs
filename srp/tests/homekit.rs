//! Interoperability with Apple's HomeKit ADK SRP implementation.
//!
//! https://github.com/apple/HomeKitADK/blob/fb201f98f5fdc7fef6a455054f08b59cca5d1ec8/PAL/Crypto/OpenSSL/HAPOpenSSL.c

use sha2::{Digest, Sha512};
use srp::{
    AuthError, ClientG3072, EncodingOptions, Group, IntegerEncoding, ServerG3072, groups::G3072,
};

#[path = "data/homekit.rs"]
mod vectors;

struct Vector {
    username: &'static [u8],
    password: &'static [u8],
    salt: &'static [u8],
    a: &'static [u8],
    b: &'static [u8],
    v: &'static [u8],
    a_pub: &'static [u8],
    b_pub: &'static [u8],
    s: &'static [u8],
    k: &'static [u8],
    m1: &'static [u8],
    m2: &'static [u8],
}

fn minimal(value: &[u8]) -> &[u8] {
    &value[value.iter().position(|&b| b != 0).unwrap_or(value.len())..]
}

fn check_vector(v: &Vector) {
    let client = ClientG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT);
    let server = ServerG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT);
    assert_eq!(
        client.compute_verifier(v.username, v.password, v.salt),
        minimal(v.v)
    );
    assert_eq!(client.compute_public_ephemeral(v.a), v.a_pub);
    assert_eq!(server.compute_public_ephemeral(v.b, v.v), v.b_pub);

    // Proof encodings must not depend on how the peer represents its integer.
    // HAP emits padded values; accepting minimal values is also supported.
    for a_pub in [v.a_pub, minimal(v.a_pub)] {
        for b_pub in [v.b_pub, minimal(v.b_pub)] {
            let c = client
                .process_reply(v.a, v.username, v.password, v.salt, b_pub)
                .unwrap();
            let s = server
                .process_reply(v.username, v.salt, v.b, v.v, a_pub)
                .unwrap();
            assert_eq!(c.key(), minimal(v.s));
            assert_eq!(s.key(), minimal(v.s));
            assert_eq!(c.proof(), v.m1);
            assert_eq!(s.proof(), v.m2);
            assert_eq!(s.verify_client(v.m1).unwrap(), v.k);
            assert_eq!(c.verify_server(v.m2).unwrap(), v.k);

            let mut bad_m1 = v.m1.to_vec();
            bad_m1[0] ^= 1;
            assert!(matches!(
                s.verify_client(&bad_m1),
                Err(AuthError::BadRecordMac { peer: "client" })
            ));
            let mut bad_m2 = v.m2.to_vec();
            bad_m2[0] ^= 1;
            assert!(matches!(
                c.verify_server(&bad_m2),
                Err(AuthError::BadRecordMac { peer: "server" })
            ));
        }
    }
}

#[test]
fn apple_adk_known_answer() {
    check_vector(&vectors::BASELINE);
}

#[test]
fn leading_zero_salt_and_public_values() {
    let v = &vectors::LEADING_ZEROS;
    assert_eq!(v.salt[0], 0);
    assert_eq!(v.a_pub[0], 0);
    assert_eq!(v.b_pub[0], 0);
    check_vector(v);
}

#[test]
fn salt_is_never_trimmed() {
    let v = &vectors::LEADING_ZEROS;
    let client = ClientG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT);
    let server = ServerG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT);
    let trimmed = &v.salt[1..];
    assert_ne!(
        client.compute_verifier(v.username, v.password, trimmed),
        minimal(v.v)
    );
    let c = client
        .process_reply(v.a, v.username, v.password, trimmed, v.b_pub)
        .unwrap();
    assert!(c.verify_server(v.m2).is_err());
    // The server does not derive x, but must retain the full salt in M1.
    let s = server
        .process_reply(v.username, trimmed, v.b, v.v, v.a_pub)
        .unwrap();
    assert!(s.verify_client(v.m1).is_err());
}

#[test]
fn wrong_password_is_rejected() {
    let v = &vectors::BASELINE;
    let client = ClientG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT);
    let server = ServerG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT);
    let c = client
        .process_reply(v.a, v.username, b"wrong password", v.salt, v.b_pub)
        .unwrap();
    let s = server
        .process_reply(v.username, v.salt, v.b, v.v, v.a_pub)
        .unwrap();
    assert!(s.verify_client(c.proof()).is_err());
    assert!(c.verify_server(s.proof()).is_err());
}

#[test]
fn default_encodings() {
    let v = &vectors::LEADING_ZEROS;
    let client = ClientG3072::<Sha512>::new();
    let server = ServerG3072::<Sha512>::new();
    assert_eq!(client.compute_public_ephemeral(v.a), minimal(v.a_pub));
    assert_eq!(server.compute_public_ephemeral(v.b, v.v), minimal(v.b_pub));

    let c = client
        .process_reply(v.a, v.username, v.password, v.salt, v.b_pub)
        .unwrap();
    assert_ne!(c.proof(), v.m1); // Default proofs hash padded g.
    let s = server
        .process_reply(v.username, v.salt, v.b, v.v, v.a_pub)
        .unwrap();
    assert_eq!(s.verify_client(c.proof()).unwrap(), v.k);
    assert_eq!(c.verify_server(s.proof()).unwrap(), v.k);
}

#[test]
fn encoding_choices_are_independent() {
    let v = &vectors::LEADING_ZEROS;
    let n = G3072::generator().params().modulus().to_be_bytes();
    let mut padded_g = vec![0; n.len()];
    *padded_g.last_mut().unwrap() = 5;
    let h_n = Sha512::digest(&n);
    let h_i = Sha512::digest(v.username);
    let public_encodings = [IntegerEncoding::Minimal, IntegerEncoding::Padded];
    for generator in [IntegerEncoding::Minimal, IntegerEncoding::Padded] {
        let g = if generator == IntegerEncoding::Minimal {
            &[5][..]
        } else {
            &padded_g
        };
        let h_g = Sha512::digest(g);
        let xor: Vec<_> = h_n.iter().zip(h_g).map(|(n, g)| n ^ g).collect();
        for m1_encoding in public_encodings {
            for m2_encoding in public_encodings {
                for wire in [IntegerEncoding::Minimal, IntegerEncoding::Padded] {
                    let encoding = EncodingOptions {
                        username_in_x: true,
                        m1_generator: generator,
                        m1_public_values: m1_encoding,
                        m2_public_value: m2_encoding,
                        public_ephemeral: wire,
                    };
                    let client = ClientG3072::<Sha512>::new_with_options(encoding);
                    let server = ServerG3072::<Sha512>::new_with_options(encoding);
                    let a_wire = client.compute_public_ephemeral(v.a);
                    let b_wire = server.compute_public_ephemeral(v.b, v.v);
                    let padded = wire == IntegerEncoding::Padded;
                    assert_eq!(a_wire, if padded { v.a_pub } else { minimal(v.a_pub) });
                    assert_eq!(b_wire, if padded { v.b_pub } else { minimal(v.b_pub) });
                    let c = client
                        .process_reply(v.a, v.username, v.password, v.salt, &b_wire)
                        .unwrap();
                    let s = server
                        .process_reply(v.username, v.salt, v.b, v.v, &a_wire)
                        .unwrap();
                    // Build reference transcripts directly from the fixed ADK
                    // values, independently of the crate's encoding helpers.
                    let encode = |mode, full: &[u8]| match mode {
                        IntegerEncoding::Minimal => minimal(full).to_vec(),
                        IntegerEncoding::Padded => full.to_vec(),
                    };
                    let a_m1 = encode(m1_encoding, v.a_pub);
                    let b_m1 = encode(m1_encoding, v.b_pub);
                    let m1 =
                        Sha512::digest([&xor[..], &h_i[..], v.salt, &a_m1, &b_m1, v.k].concat());
                    let a_m2 = encode(m2_encoding, v.a_pub);
                    let m2 = Sha512::digest([&a_m2[..], &m1[..], v.k].concat());
                    assert_eq!(c.proof(), m1.as_slice());
                    assert_eq!(s.proof(), m2.as_slice());
                    assert_eq!(c.verify_server(s.proof()).unwrap(), v.k);
                    assert_eq!(s.verify_client(c.proof()).unwrap(), v.k);
                }
            }
        }
    }
}

#[test]
fn username_option_only_changes_x() {
    let v = &vectors::LEADING_ZEROS;
    let client = ClientG3072::<Sha512>::new_with_options(EncodingOptions {
        username_in_x: false,
        ..EncodingOptions::HOMEKIT
    });
    // Omitting I retains the colon, just like an empty username with defaults.
    let verifier = client.compute_verifier(v.username, v.password, v.salt);
    assert_eq!(
        verifier,
        ClientG3072::<Sha512>::new().compute_verifier(b"", v.password, v.salt)
    );
    assert_ne!(verifier, minimal(v.v));

    // The server uses v and does not need the client's username_in_x setting.
    let server = ServerG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT);
    let b_pub = server.compute_public_ephemeral(v.b, &verifier);
    let a_pub = client.compute_public_ephemeral(v.a);
    let c = client
        .process_reply(v.a, v.username, v.password, v.salt, &b_pub)
        .unwrap();
    let s = server
        .process_reply(v.username, v.salt, v.b, &verifier, &a_pub)
        .unwrap();
    assert_eq!(
        c.verify_server(s.proof()).unwrap(),
        s.verify_client(c.proof()).unwrap()
    );

    // Changing I leaves x and S unchanged, but I is still bound into M1.
    let other = client
        .process_reply(v.a, b"other", v.password, v.salt, &b_pub)
        .unwrap();
    assert_eq!(c.key(), other.key());
    assert_ne!(c.proof(), other.proof());
    assert!(s.verify_client(other.proof()).is_err());
}

#[test]
fn invalid_public_values_return_errors() {
    let v = &vectors::BASELINE;
    let modulus = G3072::generator().params().modulus().to_be_bytes();
    let oversized = [&[0][..], v.a_pub].concat();
    for public in [&[][..], &[0], &modulus, &oversized, &[1; 4096]] {
        for client in [
            ClientG3072::<Sha512>::new(),
            ClientG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT),
        ] {
            assert!(matches!(
                client.process_reply(v.a, v.username, v.password, v.salt, public),
                Err(AuthError::IllegalParameter { name: "b_pub" })
            ));
        }
        for server in [
            ServerG3072::<Sha512>::new(),
            ServerG3072::<Sha512>::new_with_options(EncodingOptions {
                m1_generator: IntegerEncoding::Minimal,
                ..EncodingOptions::default()
            }),
            ServerG3072::<Sha512>::new_with_options(EncodingOptions::HOMEKIT),
        ] {
            assert!(matches!(
                server.process_reply(v.username, v.salt, v.b, v.v, public),
                Err(AuthError::IllegalParameter { name: "a_pub" })
            ));
        }
    }
}
