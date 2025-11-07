use aucpace::{
    Client, ClientMessage, Database, OsRng, Result, Server, ServerMessage,
    client::{AuCPaceClientPreAug, AuCPaceClientRecvServerKey},
    rand_core::TryRngCore,
    server::{AuCPaceServerAugLayer, AuCPaceServerRecvClientKey},
};
use curve25519_dalek::RistrettoPoint;
use password_hash::{ParamsString, SaltString};
use scrypt::{Params, Scrypt};
use sha2::Sha512;

const USERNAME: &[u8] = b"jlpicard_1701";
const PASSWORD: &[u8] = b"g04tEd_c4pT41N";
const CI: &[u8] = b"test_channel_identifier";
const PRE_SSID: &[u8] = b"bestest_ssid_ever_i_promise";
const K1: usize = 16;

/// Password Verifier database which can store the info for one user
#[derive(Debug, Default)]
struct SingleUserDatabase {
    user: Option<Vec<u8>>,
    data: Option<(RistrettoPoint, SaltString, ParamsString)>,
}

impl Database for SingleUserDatabase {
    type PasswordVerifier = RistrettoPoint;

    fn lookup_verifier(
        &self,
        username: &[u8],
    ) -> Option<(Self::PasswordVerifier, SaltString, ParamsString)> {
        match &self.user {
            Some(stored_username) if stored_username == username => self.data.clone(),
            _ => None,
        }
    }

    fn store_verifier(
        &mut self,
        username: &[u8],
        salt: SaltString,
        _uad: Option<&[u8]>,
        verifier: Self::PasswordVerifier,
        params: ParamsString,
    ) {
        self.user = Some(username.to_vec());
        self.data = Some((verifier, salt, params));
    }
}

/// test the default key agreement - establish SSID, normal explicit mutual auth, non-strong version
#[test]
fn test_key_agreement() -> Result<()> {
    let (mut base_client, mut base_server, database) = init()?;

    // ===== SSID Establishment =====
    let (server, server_message) = base_server.begin();
    let (client, client_message) = base_client.begin();

    // server receives client nonce
    let server = if let ClientMessage::Nonce(client_nonce) = client_message {
        server.agree_ssid(client_nonce)
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // client receives server nonce
    let client = if let ServerMessage::Nonce(server_nonce) = server_message {
        client.agree_ssid(server_nonce)
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // do the middle bits
    let (client, server, client_message, server_message) = test_core(client, server, &database)?;

    // Server receives client pub key
    let server = if let ClientMessage::PublicKey(client_pubkey) = client_message {
        server.receive_client_pubkey(client_pubkey)?
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // Client receives server pub key and generate the client's authenticators
    let (client, client_message) = if let ServerMessage::PublicKey(server_pubkey) = server_message {
        client.receive_server_pubkey(server_pubkey)?
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // ===== Explicit Mutual Authentication =====
    let (server_key, server_message) = if let ClientMessage::Authenticator(ca) = client_message {
        server.receive_client_authenticator(ca)?
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    let client_key = if let ServerMessage::Authenticator(sa) = server_message {
        client.receive_server_authenticator(sa)?
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // assert that both threads arrived at the same key
    assert_eq!(client_key, server_key);

    Ok(())
}

/// test the default key agreement - establish SSID, normal explicit mutual auth, non-strong version
#[test]
fn test_key_agreement_implicit_auth() -> Result<()> {
    let (mut base_client, mut base_server, database) = init()?;

    // ===== SSID Establishment =====
    let (server, server_message) = base_server.begin();
    let (client, client_message) = base_client.begin();

    // server receives client nonce
    let server = if let ClientMessage::Nonce(client_nonce) = client_message {
        server.agree_ssid(client_nonce)
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // client receives server nonce
    let client = if let ServerMessage::Nonce(server_nonce) = server_message {
        client.agree_ssid(server_nonce)
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // do the middle bits
    let (client, server, client_message, server_message) = test_core(client, server, &database)?;

    // Server receives client pub key
    let server_key = if let ClientMessage::PublicKey(client_pubkey) = client_message {
        server.implicit_auth(client_pubkey)?
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // Client receives server pub key and generate the client's authenticators
    let client_key = if let ServerMessage::PublicKey(server_pubkey) = server_message {
        client.implicit_auth(server_pubkey)?
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // assert that both threads arrived at the same key
    assert_eq!(client_key, server_key);

    Ok(())
}

/// test the default key agreement - establish SSID, normal explicit mutual auth, non-strong version
#[test]
fn test_key_agreement_prestablished_ssid() -> Result<()> {
    let (mut base_client, mut base_server, database) = init()?;

    // ===== SSID Establishment =====
    let server = base_server.begin_prestablished_ssid(PRE_SSID)?;
    let client = base_client.begin_prestablished_ssid(PRE_SSID)?;

    // do the middle bits
    let (client, server, client_message, server_message) = test_core(client, server, &database)?;

    // Server receives client pub key
    let server = if let ClientMessage::PublicKey(client_pubkey) = client_message {
        server.receive_client_pubkey(client_pubkey)?
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // Client receives server pub key and generate the client's authenticators
    let (client, client_message) = if let ServerMessage::PublicKey(server_pubkey) = server_message {
        client.receive_server_pubkey(server_pubkey)?
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // ===== Explicit Mutual Authentication =====
    let (server_key, server_message) = if let ClientMessage::Authenticator(ca) = client_message {
        server.receive_client_authenticator(ca)?
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    let client_key = if let ServerMessage::Authenticator(sa) = server_message {
        client.receive_server_authenticator(sa)?
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // assert that both threads arrived at the same key
    assert_eq!(client_key, server_key);

    Ok(())
}

/// test the default key agreement - establish SSID, normal explicit mutual auth, non-strong version
#[test]
fn test_key_agreement_prestablished_ssid_implicit_auth() -> Result<()> {
    let (mut base_client, mut base_server, database) = init()?;

    // ===== SSID Establishment =====
    let server = base_server.begin_prestablished_ssid(PRE_SSID)?;
    let client = base_client.begin_prestablished_ssid(PRE_SSID)?;

    // do the middle bits
    let (client, server, client_message, server_message) = test_core(client, server, &database)?;

    // Server receives client pub key
    let server_key = if let ClientMessage::PublicKey(client_pubkey) = client_message {
        server.implicit_auth(client_pubkey)?
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // Client receives server pub key and generate the client's authenticators
    let client_key = if let ServerMessage::PublicKey(server_pubkey) = server_message {
        client.implicit_auth(server_pubkey)?
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // assert that both threads arrived at the same key
    assert_eq!(client_key, server_key);

    Ok(())
}

/// Perform the initialisation step for all tests
fn init() -> Result<(Client, Server, SingleUserDatabase)> {
    let rng = OsRng.unwrap_err();

    // Create the client, server and database
    let base_server = Server::new(rng);
    let mut base_client = Client::new(rng);
    let mut database: SingleUserDatabase = Default::default();

    // register a user in the database
    let params = Params::recommended();
    let registration = base_client.register_alloc(USERNAME, PASSWORD, params, Scrypt)?;
    if let ClientMessage::Registration {
        username,
        salt,
        params,
        verifier,
    } = registration
    {
        database.store_verifier(username, salt, None, verifier, params);
    }

    Ok((base_client, base_server, database))
}

/// perform all the middle steps common to all tests
fn test_core(
    client: AuCPaceClientPreAug<Sha512, Scrypt, K1>,
    server: AuCPaceServerAugLayer<Sha512, K1>,
    database: &SingleUserDatabase,
) -> Result<(
    AuCPaceClientRecvServerKey<Sha512, K1>,
    AuCPaceServerRecvClientKey<Sha512, K1>,
    ClientMessage<'_, K1>,
    ServerMessage<'_, K1>,
)> {
    let mut rng = OsRng.unwrap_err();

    // ===== Augmentation Layer =====
    // client initiates the augmentation phase
    let (client, client_message) = client.start_augmentation(USERNAME, PASSWORD);

    // server generates augmentation info from client's username
    let (server, server_message) = if let ClientMessage::Username(username) = client_message {
        server.generate_client_info(username, database, rng)
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // client receives the info and moves into the CPace step
    let client = if let ServerMessage::AugmentationInfo {
        x_pub,
        salt,
        pbkdf_params,
        ..
    } = server_message
    {
        let params = {
            // its christmas time!
            let log_n = pbkdf_params.get_str("ln").unwrap().parse().unwrap();
            let r = pbkdf_params.get_str("r").unwrap().parse().unwrap();
            let p = pbkdf_params.get_str("p").unwrap().parse().unwrap();

            Params::new(log_n, r, p).unwrap()
        };
        client.generate_cpace_alloc(x_pub, &salt, params, Scrypt)?
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // ===== CPace substep =====
    let (server, server_message) = server.generate_public_key(CI);
    let (client, client_message) = client.generate_public_key(CI, &mut rng);

    Ok((client, server, client_message, server_message))
}
