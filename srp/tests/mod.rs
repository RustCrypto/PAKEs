use rand;
use rand::RngCore;
use sha2::Sha256;

use srp::client::{srp_private_key, SrpClient};
use srp::groups::G_2048;
use srp::server::{SrpServer, UserRecord};

fn auth_test(reg_pwd: &[u8], auth_pwd: &[u8]) {
    let mut rng = rand::rngs::OsRng::new().unwrap();
    let username = b"alice";

    // Client instance creation
    let mut a = [0u8; 64];
    rng.fill_bytes(&mut a);
    let client = SrpClient::<Sha256>::new(&a, &G_2048);

    // Registration
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let reg_priv_key = srp_private_key::<Sha256>(username, reg_pwd, &salt);
    let verif = client.get_password_verifier(&reg_priv_key);

    // User sends handshake
    let a_pub = client.get_a_pub();

    // Server retrieve user record from db and processes handshake
    let user = UserRecord {
        username,
        salt: &salt,
        verifier: &verif,
    };
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    let server = SrpServer::<Sha256>::new(&user, &a_pub, &b, &G_2048).unwrap();
    let (salt, b_pub) = (&user.salt, server.get_b_pub());

    // Client processes handshake reply
    let auth_priv_key = srp_private_key::<Sha256>(username, auth_pwd, salt);
    let client2 = client
        .process_reply(user.username, user.salt, &auth_priv_key, &b_pub)
        .unwrap();
    let proof = client2.get_proof();

    // Server processes verification data
    println!("Client verification");
    let proof2 = server.verify(&proof).unwrap();
    let server_key = server.get_key();

    // Client verifies server
    println!("Server verification");
    let user_key = client2.verify_server(&proof2).unwrap();
    assert_eq!(server_key, user_key, "server and client keys are not equal");
}

#[test]
fn good_password() {
    auth_test(b"password", b"password");
}

#[test]
#[should_panic]
fn bad_password() {
    auth_test(b"password", b"paSsword");
}
