#![cfg(all(
    feature = "scrypt",
    feature = "sha2",
    feature = "alloc",
    feature = "partial_augmentation",
    feature = "getrandom"
))]

use aucpace::{
    AuCPaceClient, ClientMessage, Database, Error, PartialAugDatabase, Result, Salt, Server,
    ServerMessage, SysRng,
    client::{AuCPaceClientPreAug, AuCPaceClientRecvServerKey},
    server::{AuCPaceServerAugLayer, AuCPaceServerRecvClientKey},
};
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::UnwrapErr;
use scrypt::{Params, Scrypt};
use sha2::Sha512;

const USERNAME: &[u8] = b"jlpicard_1701";
const PASSWORD: &[u8] = b"g04tEd_c4pT41N";
const CI: &[u8] = b"test_channel_identifier";
const PRE_SSID: &[u8] = b"bestest_ssid_ever_i_promise";
const K1: usize = 16;

type Client<const N: usize = 32> = AuCPaceClient<Sha512, Scrypt, UnwrapErr<SysRng>, K1, N>;

/// Password Verifier database which can store the info for one user
#[derive(Debug, Default)]
struct SingleUserDatabase {
    user: Option<Vec<u8>>,
    data: Option<(RistrettoPoint, Salt, Params)>,
    long_term_keypair: Option<(Scalar, RistrettoPoint)>,
}

impl Database for SingleUserDatabase {
    type PasswordVerifier = RistrettoPoint;
    type Params = Params;

    fn default_params(&self) -> Self::Params {
        Params::new(4, 8, 1).unwrap()
    }

    fn lookup_verifier(&self, username: &[u8]) -> Option<(Self::PasswordVerifier, Salt, Params)> {
        match &self.user {
            Some(stored_username) if stored_username == username => self.data.clone(),
            _ => None,
        }
    }

    fn store_verifier(
        &mut self,
        username: &[u8],
        salt: Salt,
        _uad: Option<&[u8]>,
        verifier: Self::PasswordVerifier,
        params: Params,
    ) {
        self.user = Some(username.to_vec());
        self.data = Some((verifier, salt, params));
    }
}

impl PartialAugDatabase for SingleUserDatabase {
    type PrivateKey = Scalar;
    type PublicKey = RistrettoPoint;

    fn lookup_long_term_keypair(
        &self,
        username: &[u8],
    ) -> Option<(Self::PrivateKey, Self::PublicKey)> {
        match &self.user {
            Some(stored_user) if stored_user == username => self.long_term_keypair,
            _ => None,
        }
    }

    fn store_long_term_keypair(
        &mut self,
        username: &[u8],
        priv_key: Self::PrivateKey,
        pub_key: Self::PublicKey,
    ) -> Result<()> {
        match &self.user {
            Some(stored_user) if stored_user == username => {
                self.long_term_keypair = Some((priv_key, pub_key));
                Ok(())
            }
            _ => Err(Error::UserNotRegistered),
        }
    }
}

/// test the default key agreement - establish SSID, normal explicit mutual auth, non-strong version
#[test]
fn test_key_agreement() -> Result<()> {
    key_agreement::<32>()
}

#[test]
fn test_key_agreement_64_bytes() -> Result<()> {
    key_agreement::<64>()
}

fn key_agreement<const N: usize>() -> Result<()> {
    let (mut base_client, mut base_server, database) = init::<N>()?;

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
    let (mut base_client, mut base_server, database) = init::<32>()?;

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
    let (mut base_client, mut base_server, database) = init::<32>()?;

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
    let (mut base_client, mut base_server, database) = init::<32>()?;

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
fn init<const N: usize>() -> Result<(Client<N>, Server, SingleUserDatabase)> {
    let rng = UnwrapErr(SysRng);

    // Create the client, server and database
    let mut base_server = Server::new(rng);
    let mut base_client = Client::<N>::new(rng);
    let mut database: SingleUserDatabase = Default::default();

    // register a user in the database
    // Weak, non-default parameters keep tests fast. Do not use in production.
    let params = Params::new(4, 8, 1).unwrap();
    let registration =
        base_client.register_alloc(USERNAME, PASSWORD, params, Scrypt::new_with_params(params))?;
    if let ClientMessage::Registration {
        username,
        salt,
        params,
        verifier,
    } = registration
    {
        database.store_verifier(username, salt, None, verifier, params);
        let (private, public) = base_server.generate_long_term_keypair();
        database.store_long_term_keypair(username, private, public)?;
    }

    Ok((base_client, base_server, database))
}

/// perform all the middle steps common to all tests
fn test_core<const N: usize>(
    client: AuCPaceClientPreAug<Sha512, Scrypt, K1, N>,
    server: AuCPaceServerAugLayer<Sha512, K1>,
    database: &SingleUserDatabase,
) -> Result<(
    AuCPaceClientRecvServerKey<Sha512, K1>,
    AuCPaceServerRecvClientKey<Sha512, K1>,
    ClientMessage<'_, K1>,
    ServerMessage<'_, K1>,
)> {
    let mut rng = UnwrapErr(SysRng);

    // ===== Augmentation Layer =====
    // client initiates the augmentation phase
    let (client, client_message) = client.start_augmentation(USERNAME, PASSWORD);

    // server generates augmentation info from client's username
    let (server, server_message) = if let ClientMessage::Username(username) = client_message {
        server.generate_client_info_partial_aug(username, database, rng)
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
        client.generate_cpace_alloc(x_pub, &salt, Scrypt::new_with_params(pbkdf_params))?
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // ===== CPace substep =====
    let (server, server_message) = server.generate_public_key(CI);
    let (client, client_message) = client.generate_public_key(CI, &mut rng);

    Ok((client, server, client_message, server_message))
}

#[test]
fn test_unknown_user_parameters() -> Result<()> {
    let (_, mut base_server, database) = init::<32>()?;
    let server = base_server.begin_prestablished_ssid(PRE_SSID)?;
    let (_, message) =
        server.generate_client_info_partial_aug(b"unknown user", &database, UnwrapErr(SysRng));
    if let ServerMessage::AugmentationInfo {
        salt, pbkdf_params, ..
    } = message
    {
        assert_eq!(pbkdf_params, Params::new(4, 8, 1).unwrap());
        assert_eq!(salt.len(), 16);
    } else {
        panic!("Expected augmentation info");
    }
    Ok(())
}
