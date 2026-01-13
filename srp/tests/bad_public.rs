use crypto_bigint::BoxedUint;
use sha1::Sha1;
use srp::client::Client;
use srp::groups::G1024;
use srp::server::Server;

#[test]
#[should_panic]
fn bad_a_pub() {
    let server = Server::<G1024, Sha1>::new();
    server
        .process_reply(b"", b"", b"", b"", &BoxedUint::zero().to_be_bytes())
        .unwrap();
}

#[test]
#[should_panic]
fn bad_b_pub() {
    let client = Client::<G1024, Sha1>::new();
    client
        .process_reply(b"", b"", b"", b"", &BoxedUint::zero().to_be_bytes())
        .unwrap();
}
