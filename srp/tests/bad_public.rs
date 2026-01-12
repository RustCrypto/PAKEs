use crypto_bigint::BoxedUint;
use sha1::Sha1;
use srp::client::SrpClient;
use srp::groups::G_1024;
use srp::server::SrpServer;

#[test]
#[should_panic]
fn bad_a_pub() {
    let server = SrpServer::<Sha1>::new(&G_1024);
    server
        .process_reply(b"", b"", &BoxedUint::zero().to_be_bytes())
        .unwrap();
}

#[test]
#[should_panic]
fn bad_b_pub() {
    let client = SrpClient::<Sha1>::new(&G_1024);
    client
        .process_reply(b"", b"", b"", b"", &BoxedUint::zero().to_be_bytes())
        .unwrap();
}
