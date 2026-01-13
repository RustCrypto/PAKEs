use bigint::BoxedUint;
use sha1::Sha1;
use srp::{ClientG2048, ServerG2048};

#[test]
#[should_panic]
fn bad_a_pub() {
    let server = ServerG2048::<Sha1>::new();
    server
        .process_reply(b"", b"", b"", b"", &BoxedUint::zero().to_be_bytes())
        .unwrap();
}

#[test]
#[should_panic]
fn bad_b_pub() {
    let client = ClientG2048::<Sha1>::new();
    client
        .process_reply(b"", b"", b"", b"", &BoxedUint::zero().to_be_bytes())
        .unwrap();
}
