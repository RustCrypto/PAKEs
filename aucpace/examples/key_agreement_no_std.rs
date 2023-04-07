#![no_std]

// use println and Instant only from std
extern crate std;
use std::{println, time::Instant};

use aucpace::{Client, ClientMessage, Database, Result, Server, ServerMessage};
use curve25519_dalek::ristretto::RistrettoPoint;
use password_hash::{ParamsString, SaltString};
use rand_core::OsRng;
use scrypt::{Params, Scrypt};

/// function like macro to wrap sending data over a tcp stream, returns the number of bytes sent
macro_rules! send {
    ($buf:ident, $msg:ident) => {{
        $buf.fill(0u8);
        let serialised = postcard::to_slice(&$msg, &mut $buf).unwrap();
        serialised.len()
    }};
}

/// function like macro to wrap receiving data over a tcp stream, returns the message received
macro_rules! recv {
    ($buf:ident) => {{
        postcard::from_bytes(&$buf).unwrap()
    }};
}

fn main() -> Result<()> {
    // example username and password, never user these...
    const USERNAME: &'static [u8] = b"adira.tal";
    const PASSWORD: &'static [u8] = b"4d1rA_aND-Gr4Y_aRe_tH3-b3sT <3";

    // register the user in the database
    let mut base_server = Server::new(OsRng);
    let mut base_client = Client::new(OsRng);
    let mut database: SingleUserDatabase<100> = Default::default();

    let start = Instant::now();
    let params = Params::recommended();
    let registration = base_client.register::<&[u8], 100>(USERNAME, PASSWORD, params, Scrypt)?;
    if let ClientMessage::Registration {
        username,
        salt,
        params,
        verifier,
    } = registration
    {
        database.store_verifier(username, salt, None, verifier, params);
    }
    println!(
        "Registered `{}:{}` in {}ms",
        core::str::from_utf8(USERNAME).unwrap(),
        core::str::from_utf8(PASSWORD).unwrap(),
        Instant::now().duration_since(start).as_millis()
    );

    // count the number of bytes sent by each side
    let mut client_bytes_sent = 0;
    let mut server_bytes_sent = 0;

    // time how long the protocol takes
    let start = Instant::now();

    // buffers for receiving packets
    let mut client_buf = [0u8; 1024];
    let mut server_buf = [0u8; 1024];

    // ===== SSID Establishment =====
    // client sends SSID establishment packet
    let (client, message) = base_client.begin();
    let bytes_sent = send!(client_buf, message);
    client_bytes_sent += bytes_sent;
    println!(
        "[client] Sending message: ClientNonce, sent {} bytes",
        bytes_sent
    );

    // server receives SSID establishment packet and begins SSID establishment itself,
    // responding with a ServerNonce packet
    let mut client_message: ClientMessage<16> = recv!(client_buf);
    let server = if let ClientMessage::Nonce(client_nonce) = client_message {
        let (server, message) = base_server.begin();
        let bytes_sent = send!(server_buf, message);
        server_bytes_sent += bytes_sent;
        println!(
            "[server] Sending message: ServerNonce, sent {} bytes",
            bytes_sent
        );
        server.agree_ssid(client_nonce)
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // the client receives the nonce, calculates the SSID then moves on to the
    let mut server_message = recv!(server_buf);
    let client = if let ServerMessage::Nonce(nonce) = server_message {
        client.agree_ssid(nonce)
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // ===== Augmentation Layer =====
    // client begins the augmentation layer by sending the username to the server
    let (client, message) = client.start_augmentation(USERNAME, PASSWORD);
    let bytes_sent = send!(client_buf, message);
    client_bytes_sent += bytes_sent;
    println!(
        "[client] Sending message: Username, sent {} bytes",
        bytes_sent
    );

    // server receives the username then looks up
    client_message = recv!(client_buf);
    let (server, message) = if let ClientMessage::Username(username) = client_message {
        server.generate_client_info(username, &database, OsRng)
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };
    let bytes_sent = send!(server_buf, message);
    server_bytes_sent += bytes_sent;
    println!(
        "[server] Sending message: AugmentationInfo, sent {} bytes",
        bytes_sent
    );

    // client then receives the augmentation info back from the server
    server_message = recv!(server_buf);
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
        client.generate_cpace::<&SaltString, 100>(x_pub, &salt, params, Scrypt)?
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // ===== CPace substep =====
    // first generate the server's public key and send it
    const CI: &'static str = "channel_identifier";
    let (server, message) = server.generate_public_key(CI);
    let bytes_sent = send!(server_buf, message);
    server_bytes_sent += bytes_sent;
    println!(
        "[server] Sending message: PublicKey, sent {} bytes",
        bytes_sent
    );

    // now generate the client's public key and send it
    let (client, message) = client.generate_public_key(CI, &mut OsRng);
    let bytes_sent = send!(client_buf, message);
    client_bytes_sent += bytes_sent;
    println!(
        "[client] Sending message: PublicKey, sent {} bytes",
        bytes_sent
    );

    // now receive the client's public key
    client_message = recv!(client_buf);
    let server = if let ClientMessage::PublicKey(client_pubkey) = client_message {
        server.receive_client_pubkey(client_pubkey)?
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // now receive the server's public key
    server_message = recv!(server_buf);
    let (client, message) = if let ServerMessage::PublicKey(server_pubkey) = server_message {
        client.receive_server_pubkey(server_pubkey)?
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // ===== Explicit Mutual Authentication =====
    // send the client's authenticator
    let bytes_sent = send!(client_buf, message);
    client_bytes_sent += bytes_sent;
    println!(
        "[client] Sending message: Authenticator, sent {} bytes",
        bytes_sent
    );

    // receive the client's authenticator
    client_message = recv!(client_buf);
    let server_key = if let ClientMessage::Authenticator(client_authenticator) = client_message {
        let (key, message) = server.receive_client_authenticator(client_authenticator)?;
        let bytes_sent = send!(server_buf, message);
        server_bytes_sent += bytes_sent;
        println!(
            "[server] Sending message: Authenticator, sent {} bytes",
            bytes_sent
        );

        // return the dervied key
        key
    } else {
        panic!("Received invalid client message {:?}", client_message);
    };

    // receive the server's authenticator
    server_message = recv!(server_buf);
    let client_key = if let ServerMessage::Authenticator(server_authenticator) = server_message {
        client
            .receive_server_authenticator(server_authenticator)
            .unwrap()
    } else {
        panic!("Received invalid server message {:?}", server_message);
    };

    // record end time
    let end = Instant::now();

    // ===== Protocol end =====
    // assert that both threads arrived at the same key
    assert_eq!(client_key, server_key);
    println!(
        "Negotiation finished, both parties arrived at a key of: {:X}",
        client_key
    );

    println!("Client sent {} bytes total", client_bytes_sent);
    println!("Server sent {} bytes total", server_bytes_sent);
    println!(
        "The computation took {}ms",
        end.duration_since(start).as_millis()
    );

    Ok(())
}

/// Password Verifier database which can store the info for one user
#[derive(Debug, Default)]
struct SingleUserDatabase<const USERSIZE: usize> {
    user: Option<([u8; USERSIZE], usize)>,
    data: Option<(RistrettoPoint, SaltString, ParamsString)>,
}

impl<const USERSIZE: usize> Database for SingleUserDatabase<USERSIZE> {
    type PasswordVerifier = RistrettoPoint;

    fn lookup_verifier(
        &self,
        username: &[u8],
    ) -> Option<(Self::PasswordVerifier, SaltString, ParamsString)> {
        match self.user {
            Some((ref stored_username, len)) if &stored_username[..len] == username => {
                self.data.clone()
            }
            _ => None,
        }
    }

    fn store_verifier(
        &mut self,
        username: &[u8],
        salt: SaltString,
        // we don't care about this for an example
        _uad: Option<&[u8]>,
        verifier: Self::PasswordVerifier,
        params: ParamsString,
    ) {
        // silently fail because this is just an example and I'm lazy
        if username.len() <= USERSIZE {
            let mut buf = [0u8; USERSIZE];
            buf[..username.len()].copy_from_slice(username);
            self.user = Some((buf, username.len()));
            self.data = Some((verifier, salt, params));
        }
    }
}
