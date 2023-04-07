use aucpace::{Client, ClientMessage, Result, Server, ServerMessage, StrongDatabase};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use password_hash::ParamsString;
use rand_core::OsRng;
use scrypt::{Params, Scrypt};
use sha2::digest::Output;
use sha2::Sha512;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

/// function like macro to wrap sending data over a tcp stream, returns the number of bytes sent
macro_rules! send {
    ($stream:ident, $msg:ident) => {{
        let serialised = bincode::serialize(&$msg).unwrap();
        $stream.write_all(&serialised).unwrap();
        serialised.len()
    }};
}

/// function like macro to wrap receiving data over a tcp stream, returns the message received
macro_rules! recv {
    ($stream:ident, $buf:ident) => {{
        let bytes_received = $stream.read(&mut $buf).unwrap();
        let received = &$buf[..bytes_received];
        bincode::deserialize(received).unwrap()
    }};
}

fn main() -> Result<()> {
    // example username and password, never user these...
    const USERNAME: &'static [u8] = b"jlpicard_1701";
    const PASSWORD: &'static [u8] = b"g04tEd_c4pT41N";

    // the server socket address to bind to
    let server_socket: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 25519);

    // register the user in the database
    let mut base_client = Client::new(OsRng);
    let mut database: SingleUserDatabase = Default::default();

    let params = Params::recommended();
    let registration = base_client.register_alloc_strong(USERNAME, PASSWORD, params, Scrypt)?;
    if let ClientMessage::StrongRegistration {
        username,
        secret_exponent,
        params,
        verifier,
    } = registration
    {
        database.store_verifier_strong(username, None, verifier, secret_exponent, params);
    }

    static CLIENT_BYTES_SENT: AtomicUsize = AtomicUsize::new(0);
    static SERVER_BYTES_SENT: AtomicUsize = AtomicUsize::new(0);

    // spawn a thread for the server
    let server_thread = thread::spawn(move || -> Result<Output<Sha512>> {
        let start = Instant::now();
        println!("[server] Starting negotiation");

        let listener = TcpListener::bind(server_socket).unwrap();
        let (mut stream, client_addr) = listener.accept().unwrap();

        // buffer for receiving packets
        let mut buf = [0u8; 1024];
        let mut base_server = Server::new(OsRng);

        // ===== SSID Establishment =====
        let (server, message) = base_server.begin();
        let bytes_sent = send!(stream, message);
        SERVER_BYTES_SENT.fetch_add(bytes_sent, Ordering::SeqCst);
        println!("[server] Sending message: Nonce, sent {} bytes", bytes_sent);

        let mut client_message: ClientMessage<16> = recv!(stream, buf);
        let server = if let ClientMessage::Nonce(client_nonce) = client_message {
            server.agree_ssid(client_nonce)
        } else {
            panic!("Received invalid client message {:?}", client_message);
        };

        // ===== Augmentation Layer =====
        client_message = recv!(stream, buf);
        let (server, message) =
            if let ClientMessage::StrongUsername { username, blinded } = client_message {
                server
                    .generate_client_info_strong(username, blinded, &database, OsRng)
                    .unwrap()
            } else {
                panic!("Received invalid client message {:?}", client_message);
            };
        let bytes_sent = send!(stream, message);
        SERVER_BYTES_SENT.fetch_add(bytes_sent, Ordering::SeqCst);
        println!(
            "[server] Sending message: StrongAugmentationInfo, sent {} bytes",
            bytes_sent
        );

        // ===== CPace substep =====
        let ci = TcpChannelIdentifier::new(client_addr, server_socket).unwrap();
        let (server, message) = server.generate_public_key(ci);
        let bytes_sent = send!(stream, message);
        SERVER_BYTES_SENT.fetch_add(bytes_sent, Ordering::SeqCst);
        println!(
            "[server] Sending message: PublicKey, sent {} bytes",
            bytes_sent
        );

        client_message = recv!(stream, buf);
        let server = if let ClientMessage::PublicKey(client_pubkey) = client_message {
            server.receive_client_pubkey(client_pubkey)?
        } else {
            panic!("Received invalid client message {:?}", client_message);
        };

        // ===== Explicit Mutual Authentication =====
        client_message = recv!(stream, buf);
        if let ClientMessage::Authenticator(client_authenticator) = client_message {
            let (key, message) = server.receive_client_authenticator(client_authenticator)?;
            let bytes_sent = send!(stream, message);
            SERVER_BYTES_SENT.fetch_add(bytes_sent, Ordering::SeqCst);
            println!(
                "[server] Sending message: Authenticator, sent {} bytes",
                bytes_sent
            );

            println!(
                "[server] Derived final key in {}ms",
                Instant::now().duration_since(start).as_millis()
            );
            // return the dervied key
            Ok(key)
        } else {
            panic!("Received invalid client message {:?}", client_message);
        }
    });

    // spawn a thread for the client
    let client_thread = thread::spawn(move || -> Result<Output<Sha512>> {
        println!("[client] Starting negotiation");
        let start = Instant::now();

        let mut stream = TcpStream::connect(server_socket).unwrap();
        let mut buf = [0u8; 1024];

        // ===== SSID ESTABLISHMENT =====
        let (client, message) = base_client.begin();
        let bytes_sent = send!(stream, message);
        CLIENT_BYTES_SENT.fetch_add(bytes_sent, Ordering::SeqCst);
        println!("[client] Sending message: Nonce, sent {} bytes", bytes_sent);

        // receive the server nonce to agree on SSID
        let mut server_message: ServerMessage<16> = recv!(stream, buf);
        let client = if let ServerMessage::Nonce(server_nonce) = server_message {
            client.agree_ssid(server_nonce)
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };

        // ===== Augmentation Layer =====
        let (client, message) = client.start_augmentation_strong(USERNAME, PASSWORD, &mut OsRng);
        let bytes_sent = send!(stream, message);
        CLIENT_BYTES_SENT.fetch_add(bytes_sent, Ordering::SeqCst);
        println!(
            "[client] Sending message: StrongUsername, sent {} bytes",
            bytes_sent
        );

        server_message = recv!(stream, buf);
        let client = if let ServerMessage::StrongAugmentationInfo {
            x_pub,
            blinded_salt,
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
            client.generate_cpace_alloc(x_pub, blinded_salt, params, Scrypt)?
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };

        // ===== CPace substep =====
        let ci = TcpChannelIdentifier::new(stream.local_addr().unwrap(), server_socket).unwrap();
        let (client, message) = client.generate_public_key(ci, &mut OsRng);
        let bytes_sent = send!(stream, message);
        CLIENT_BYTES_SENT.fetch_add(bytes_sent, Ordering::SeqCst);
        println!(
            "[client] Sending message: PublicKey, sent {} bytes",
            bytes_sent
        );

        server_message = recv!(stream, buf);
        let (client, message) = if let ServerMessage::PublicKey(server_pubkey) = server_message {
            client.receive_server_pubkey(server_pubkey)?
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };

        // ===== Explicit Mutual Auth =====
        let bytes_sent = send!(stream, message);
        CLIENT_BYTES_SENT.fetch_add(bytes_sent, Ordering::SeqCst);
        println!(
            "[client] Sending message: Authenticator, sent {} bytes",
            bytes_sent
        );

        server_message = recv!(stream, buf);
        let key = if let ServerMessage::Authenticator(server_authenticator) = server_message {
            client.receive_server_authenticator(server_authenticator)
        } else {
            panic!("Received invalid server message {:?}", server_message);
        };

        println!(
            "[client] Derived final key in {}ms",
            Instant::now().duration_since(start).as_millis()
        );

        key
    });

    // assert that both threads arrived at the same key
    let client_key: Output<Sha512> = client_thread.join().unwrap().unwrap();
    let server_key: Output<Sha512> = server_thread.join().unwrap().unwrap();
    assert_eq!(client_key, server_key);
    println!(
        "Negotiation finished, both parties arrived at a key of: {:X}",
        client_key
    );
    println!(
        "Client sent {} bytes total",
        CLIENT_BYTES_SENT.load(Ordering::SeqCst)
    );
    println!(
        "Server sent {} bytes total",
        SERVER_BYTES_SENT.load(Ordering::SeqCst)
    );

    Ok(())
}

/// Password Verifier database which can store the info for one user
#[derive(Debug, Default)]
struct SingleUserDatabase {
    user: Option<Vec<u8>>,
    data: Option<(RistrettoPoint, Scalar, ParamsString)>,
}

impl StrongDatabase for SingleUserDatabase {
    type PasswordVerifier = RistrettoPoint;
    type Exponent = Scalar;

    fn lookup_verifier_strong(
        &self,
        username: &[u8],
    ) -> Option<(Self::PasswordVerifier, Self::Exponent, ParamsString)> {
        match &self.user {
            Some(stored_username) if stored_username == username => self.data.clone(),
            _ => None,
        }
    }

    fn store_verifier_strong(
        &mut self,
        username: &[u8],
        _uad: Option<&[u8]>,
        verifier: Self::PasswordVerifier,
        secret_exponent: Self::Exponent,
        params: ParamsString,
    ) {
        self.user = Some(username.to_vec());
        self.data = Some((verifier, secret_exponent, params));
    }
}

/// Channel Identifier type for TCP connections
struct TcpChannelIdentifier {
    // src.ip:src.port:dst.ip:dst.port
    id: Vec<u8>,
}

impl TcpChannelIdentifier {
    fn new(src: SocketAddr, dst: SocketAddr) -> std::io::Result<Self> {
        let mut id = vec![];

        // write src.ip:src.port:dst.ip:dst.port
        match src.ip() {
            IpAddr::V4(addr) => id.write(&addr.octets()),
            IpAddr::V6(addr) => id.write(&addr.octets()),
        }?;
        id.push(b':');
        id.write(&src.port().to_be_bytes())?;
        id.push(b':');
        match dst.ip() {
            IpAddr::V4(addr) => id.write(&addr.octets()),
            IpAddr::V6(addr) => id.write(&addr.octets()),
        }?;
        id.push(b':');
        id.write(&dst.port().to_be_bytes())?;

        Ok(Self { id })
    }
}

impl AsRef<[u8]> for TcpChannelIdentifier {
    fn as_ref(&self) -> &[u8] {
        &self.id
    }
}
