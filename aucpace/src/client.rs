use crate::{
    Salt,
    constants::MIN_SSID_LEN,
    errors::{Error, Result},
    utils::{
        H0, compute_authenticator_messages, compute_first_session_key, compute_session_key,
        compute_ssid, generate_keypair, generate_nonce, scalar_from_hash,
    },
};
use core::marker::PhantomData;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    digest::consts::U64,
    digest::{Digest, Output},
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::IsIdentity,
};
use kdf::Pbkdf;
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;

#[cfg(feature = "strong_aucpace")]
use crate::utils::H1;
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Implementation of the client side of the `AuCPace` protocol
///
/// `H` is a configured password-based KDF. `KDF_OUTPUT` is its output length in bytes,
/// either 32 (the default) or 64. Registration and login must use the same length;
/// it is independent of any output length configured in `H`.
///
/// Registration takes separate application-defined parameter metadata for the server
/// to store and send back at login. It is not interpreted by this crate; use `()` if
/// the KDF configuration is agreed out of band.
pub struct AuCPaceClient<D, H, CSPRNG, const K1: usize, const KDF_OUTPUT: usize = 32>
where
    D: Digest<OutputSize = U64> + Default,
    H: Pbkdf,
    CSPRNG: CryptoRng,
{
    rng: CSPRNG,
    d: PhantomData<D>,
    h: PhantomData<H>,
}

impl<D, H, CSPRNG, const K1: usize, const KDF_OUTPUT: usize>
    AuCPaceClient<D, H, CSPRNG, K1, KDF_OUTPUT>
where
    D: Digest<OutputSize = U64> + Default,
    H: Pbkdf,
    CSPRNG: CryptoRng,
{
    /// Create new client
    pub const fn new(rng: CSPRNG) -> Self {
        Self {
            rng,
            d: PhantomData,
            h: PhantomData,
        }
    }

    /// Create a new client in the SSID agreement phase
    ///
    /// # Return:
    /// ([`next_step`](AuCPaceClientSsidEstablish), [`message`](ClientMessage::Nonce))
    /// - [`next_step`](AuCPaceClientSsidEstablish): the client in the SSID establishment stage
    /// - [`message`](ClientMessage::Nonce): the message to send to the server
    ///
    pub fn begin(
        &mut self,
    ) -> (
        AuCPaceClientSsidEstablish<D, H, K1, KDF_OUTPUT>,
        ClientMessage<'_, K1>,
    ) {
        let next_step = AuCPaceClientSsidEstablish::new(&mut self.rng);
        let message = ClientMessage::Nonce(next_step.nonce);

        (next_step, message)
    }

    /// Create a new client in the pre-augmentation layer phase, provided an SSID
    ///
    /// # Argument:
    /// - `ssid`: Some data to be hashed and act as the sub-session ID
    ///
    /// # Return:
    /// - Ok([`next_step`](AuCPaceClientSsidEstablish)): the server in the SSID establishment stage
    /// - Err([`Error::InsecureSsid`](Error::InsecureSsid)): the SSID provided was not long enough to be secure
    ///
    pub fn begin_prestablished_ssid<S>(
        &mut self,
        ssid: S,
    ) -> Result<AuCPaceClientPreAug<D, H, K1, KDF_OUTPUT>>
    where
        S: AsRef<[u8]>,
    {
        // if the SSID isn't long enough return an error
        if ssid.as_ref().len() < MIN_SSID_LEN {
            return Err(Error::InsecureSsid);
        }

        // hash the SSID and begin the next step
        let mut hasher: D = H0();
        hasher.update(ssid);
        let ssid_hash = hasher.finalize();
        let next_step = AuCPaceClientPreAug::new(ssid_hash);
        Ok(next_step)
    }

    /// Register a username/password
    ///
    /// # Arguments:
    /// - `username` - the username to register with
    /// - `password` - the password for the user
    /// - `params` - application-defined parameters describing the configured PBKDF, sent to the server
    /// - `hasher` - the PBKDF configured with `params`, used to hash the username and password.
    ///
    /// # Const Parameters
    /// - `BUFSIZ` - the size of the buffer to use while hashing
    ///   it should be enough to store the maximum length of a username + password + 1 for your use case
    ///   e.g. if you have a username limit of 20 and password limit of 60, 81 would be the right value.
    ///
    /// # Return:
    /// - Ok([`messsage`](ClientMessage::Registration)): the message to send to the server
    /// - Err([`Error::PasswordHashing`] | [`Error::HashSizeInvalid`]):
    ///   key derivation failed or `KDF_OUTPUT` was not 32 or 64
    ///
    pub fn register<'a, P, Params, const BUFSIZ: usize>(
        &mut self,
        username: &'a [u8],
        password: P,
        params: Params,
        hasher: H,
    ) -> Result<ClientMessage<'a, K1, Params>>
    where
        P: AsRef<[u8]>,
    {
        let salt: Salt = generate_nonce(&mut self.rng);

        // compute the verifier W
        let pw_hash =
            hash_password::<&[u8], P, H, BUFSIZ, KDF_OUTPUT>(username, password, &salt, &hasher)?;

        let cofactor = Scalar::ONE;
        let w = scalar_from_hash(&pw_hash)?;
        let verifier = RISTRETTO_BASEPOINT_POINT * (w * cofactor);

        Ok(ClientMessage::Registration {
            username,
            salt,
            params,
            verifier,
        })
    }

    /// Register a username/password in the strong variant of the protocol
    ///
    /// # Arguments:
    /// - `username` - the username to register with
    /// - `password` - the password for the user
    /// - `params` - application-defined parameters describing the configured PBKDF, sent to the server
    /// - `hasher` - the PBKDF configured with `params`, used to hash the username and password.
    ///
    /// # Const Parameters
    /// - `BUFSIZ` - the size of the buffer to use while hashing
    ///   it should be enough to store the maximum length of a username + password + 1 for your use case
    ///   e.g. if you have a username limit of 20 and password limit of 60, 81 would be the right value.
    ///
    /// # Return:
    /// - Ok([`messsage`](ClientMessage::Registration)): the message to send to the server
    /// - Err([`Error::PasswordHashing`] | [`Error::HashSizeInvalid`]):
    ///   key derivation failed or `KDF_OUTPUT` was not 32 or 64
    ///
    #[cfg(feature = "strong_aucpace")]
    pub fn register_strong<'a, P, Params, const BUFSIZ: usize>(
        &mut self,
        username: &'a [u8],
        password: P,
        params: Params,
        hasher: H,
    ) -> Result<ClientMessage<'a, K1, Params>>
    where
        P: AsRef<[u8]>,
    {
        // generate a secret exponent and salt
        let (q, salt) = Self::generate_salt_strong(username, password.as_ref(), &mut self.rng);

        // compute the verifier W
        let pw_hash =
            hash_password::<&[u8], P, H, BUFSIZ, KDF_OUTPUT>(username, password, &salt, &hasher)?;
        let cofactor = Scalar::ONE;
        let w = scalar_from_hash(&pw_hash)?;
        let verifier = RISTRETTO_BASEPOINT_POINT * (w * cofactor);

        Ok(ClientMessage::StrongRegistration {
            username,
            secret_exponent: q,
            params,
            verifier,
        })
    }

    /// Register a username/password
    ///
    /// Allocates space for user:pass string on the heap, instead of a constant size buffer.
    ///
    /// # Arguments:
    /// - `username` - the username to register with
    /// - `password` - the password for the user
    /// - `params` - application-defined parameters describing the configured PBKDF, sent to the server
    /// - `hasher` - the PBKDF configured with `params`, used to hash the username and password.
    ///
    /// # Return:
    /// - Ok([`messsage`](ClientMessage::Registration)): the message to send to the server
    /// - Err([`Error::PasswordHashing`] | [`Error::HashSizeInvalid`]):
    ///   key derivation failed or `KDF_OUTPUT` was not 32 or 64
    ///
    #[cfg(feature = "alloc")]
    pub fn register_alloc<'a, P, Params>(
        &mut self,
        username: &'a [u8],
        password: P,
        params: Params,
        hasher: H,
    ) -> Result<ClientMessage<'a, K1, Params>>
    where
        P: AsRef<[u8]>,
    {
        let salt: Salt = generate_nonce(&mut self.rng);

        // compute the verifier W
        let pw_hash =
            hash_password_alloc::<_, _, _, KDF_OUTPUT>(username, password, &salt, &hasher)?;
        let cofactor = Scalar::ONE;
        let w = scalar_from_hash(&pw_hash)?;
        let verifier = RISTRETTO_BASEPOINT_POINT * (w * cofactor);

        Ok(ClientMessage::Registration {
            username,
            salt,
            params,
            verifier,
        })
    }

    /// Register a username/password in the strong variant of the protocol
    ///
    /// Allocates space for user:pass string on the heap, instead of a constant size buffer.
    ///
    /// # Arguments:
    /// - `username` - the username to register with
    /// - `password` - the password for the user
    /// - `params` - application-defined parameters describing the configured PBKDF, sent to the server
    /// - `hasher` - the PBKDF configured with `params`, used to hash the username and password.
    ///
    /// # Return:
    /// - Ok([`messsage`](ClientMessage::Registration)): the message to send to the server
    /// - Err([`Error::PasswordHashing`] | [`Error::HashSizeInvalid`]):
    ///   key derivation failed or `KDF_OUTPUT` was not 32 or 64
    ///
    #[cfg(all(feature = "strong_aucpace", feature = "alloc"))]
    pub fn register_alloc_strong<'a, P, Params>(
        &mut self,
        username: &'a [u8],
        password: P,
        params: Params,
        hasher: H,
    ) -> Result<ClientMessage<'a, K1, Params>>
    where
        P: AsRef<[u8]>,
    {
        // generate a secret exponent and salt
        let (q, salt) = Self::generate_salt_strong(username, password.as_ref(), &mut self.rng);

        // compute the verifier W
        let pw_hash =
            hash_password_alloc::<_, _, _, KDF_OUTPUT>(username, password, &salt, &hasher)?;
        let cofactor = Scalar::ONE;
        let w = scalar_from_hash(&pw_hash)?;
        let verifier = RISTRETTO_BASEPOINT_POINT * (w * cofactor);

        Ok(ClientMessage::StrongRegistration {
            username,
            secret_exponent: q,
            params,
            verifier,
        })
    }

    /// generate a secret exponent and a salt value for the strong variant of the protocol
    #[cfg(feature = "strong_aucpace")]
    fn generate_salt_strong(user: &[u8], pass: &[u8], rng: &mut CSPRNG) -> (Scalar, [u8; 32]) {
        // choose a random q
        let q = Scalar::random(rng);

        // compute z
        let mut hasher: D = H1();
        hasher.update(user);
        hasher.update(pass);
        let z = RistrettoPoint::from_hash(hasher);

        // compute the salt value
        let cofactor = Scalar::ONE;
        let salt_point = z * (q * cofactor);
        let salt = salt_point.compress().to_bytes();

        (q, salt)
    }
}

/// Client in the SSID agreement phase
pub struct AuCPaceClientSsidEstablish<D, H, const K1: usize, const KDF_OUTPUT: usize = 32>
where
    D: Digest<OutputSize = U64> + Default,
    H: Pbkdf,
{
    nonce: [u8; K1],
    d: PhantomData<D>,
    h: PhantomData<H>,
}

impl<D, H, const K1: usize, const KDF_OUTPUT: usize>
    AuCPaceClientSsidEstablish<D, H, K1, KDF_OUTPUT>
where
    D: Digest<OutputSize = U64> + Default,
    H: Pbkdf,
{
    fn new<CSPRNG>(rng: &mut CSPRNG) -> Self
    where
        CSPRNG: CryptoRng,
    {
        Self {
            nonce: generate_nonce(rng),
            d: PhantomData,
            h: PhantomData,
        }
    }

    /// Consume the server's nonce - `s` and progress to the augmentation layer
    ///
    /// # arguments:
    /// - `server_nonce` - the nonce received from the server
    ///
    /// # return:
    /// [`next_step`](AuCPaceClientPreAug): the client in the pre-augmentation stage
    ///
    #[must_use]
    pub fn agree_ssid(self, server_nonce: [u8; K1]) -> AuCPaceClientPreAug<D, H, K1, KDF_OUTPUT> {
        let ssid = compute_ssid::<D, K1>(server_nonce, self.nonce);
        AuCPaceClientPreAug::new(ssid)
    }
}

/// Client in the pre-augmentation phase
pub struct AuCPaceClientPreAug<D, H, const K1: usize, const KDF_OUTPUT: usize = 32>
where
    D: Digest<OutputSize = U64> + Default,
    H: Pbkdf,
{
    ssid: Output<D>,
    h: PhantomData<H>,
}

impl<D, H, const K1: usize, const KDF_OUTPUT: usize> AuCPaceClientPreAug<D, H, K1, KDF_OUTPUT>
where
    D: Digest<OutputSize = U64> + Default,
    H: Pbkdf,
{
    const fn new(ssid: Output<D>) -> Self {
        Self {
            ssid,
            h: PhantomData,
        }
    }

    /// Consume the client's username and begin the augmentation layer
    ///
    /// # Arguments:
    /// - `username` - a reference to the client's username
    ///
    /// # Return:
    /// ([`next_step`](AuCPaceClientAugLayer), [`message`](ClientMessage::Username))
    /// - [`next_step`](AuCPaceClientAugLayer): the client in the augmentation layer
    /// - [`message`](ClientMessage::Username): the message to send to the server
    ///
    #[must_use]
    pub const fn start_augmentation<'a>(
        self,
        username: &'a [u8],
        password: &'a [u8],
    ) -> (
        AuCPaceClientAugLayer<'a, D, H, K1, KDF_OUTPUT>,
        ClientMessage<'a, K1>,
    ) {
        let next_step = AuCPaceClientAugLayer::new(self.ssid, username, password);
        let message = ClientMessage::Username(username);

        (next_step, message)
    }

    /// Consume the client's username and begin the augmentation layer.
    /// This variant performs the strong version of the protocol.
    ///
    /// # Arguments:
    /// - `username` - a reference to the client's username
    ///
    /// # Return:
    /// ([`next_step`](StrongAuCPaceClientAugLayer), [`message`](ClientMessage::Username))
    /// - [`next_step`](StrongAuCPaceClientAugLayer): the client in the augmentation layer
    /// - [`message`](ClientMessage::Username): the message to send to the server
    ///
    #[cfg(feature = "strong_aucpace")]
    pub fn start_augmentation_strong<'a, CSPRNG>(
        self,
        username: &'a [u8],
        password: &'a [u8],
        rng: &mut CSPRNG,
    ) -> (
        StrongAuCPaceClientAugLayer<'a, D, H, K1, KDF_OUTPUT>,
        ClientMessage<'a, K1>,
    )
    where
        CSPRNG: CryptoRng,
    {
        // compute the blinding value and blind the hash of the username and password
        // ensuring that it is non-zero as required by `invert`
        let blinding_value = loop {
            let val = Scalar::random(rng);
            if val != Scalar::ZERO {
                break val;
            }
        };
        let mut hasher: D = H1();
        hasher.update(username);
        hasher.update(password);
        let z = RistrettoPoint::from_hash(hasher);
        let cofactor = Scalar::ONE;
        let blinded = z * (blinding_value * cofactor);

        let next_step =
            StrongAuCPaceClientAugLayer::new(self.ssid, username, password, blinding_value);
        let message = ClientMessage::StrongUsername { username, blinded };

        (next_step, message)
    }
}

/// Client in the augmentation layer
pub struct AuCPaceClientAugLayer<'a, D, H, const K1: usize, const KDF_OUTPUT: usize = 32>
where
    D: Digest<OutputSize = U64> + Default,
    H: Pbkdf,
{
    ssid: Output<D>,
    username: &'a [u8],
    password: &'a [u8],
    h: PhantomData<H>,
}

impl<'a, D, H, const K1: usize, const KDF_OUTPUT: usize>
    AuCPaceClientAugLayer<'a, D, H, K1, KDF_OUTPUT>
where
    D: Digest<OutputSize = U64> + Default,
    H: Pbkdf,
{
    const fn new(ssid: Output<D>, username: &'a [u8], password: &'a [u8]) -> Self {
        Self {
            ssid,
            username,
            password,
            h: PhantomData,
        }
    }

    /// Process the augmentation layer information from the server, hashes the user's password
    /// together with their username, then computes `w` and `PRS`.
    ///
    /// # Arguments:
    /// - `x_pub` - `x` from the protocol definition, used in generating the password related string (prs)
    /// - `salt` - the salt value sent by the server
    /// - `hasher` - the PBKDF configured with the parameters received from the server
    ///
    /// # Const Parameters
    /// - `BUFSIZ` - the size of the buffer to use while hashing
    ///   it should be enough to store the maximum length of a username + password + 1 for your use case
    ///   e.g. if you have a username limit of 20 and password limit of 60, 81 would be the right value.
    ///
    /// # Return:
    /// - Ok([`next_step`](AuCPaceClientCPaceSubstep)): the client in the cpace substep
    /// - Err([`Error::PasswordHashing`] | [`Error::HashSizeInvalid`]):
    ///   key derivation failed or `KDF_OUTPUT` was not 32 or 64
    ///
    pub fn generate_cpace<S, const BUFSIZ: usize>(
        self,
        x_pub: RistrettoPoint,
        salt: S,
        hasher: H,
    ) -> Result<AuCPaceClientCPaceSubstep<D, K1>>
    where
        S: AsRef<[u8]>,
    {
        // check for the identity point
        if x_pub.is_identity() {
            return Err(Error::IllegalPointError);
        }

        let cofactor = Scalar::ONE;
        let pw_hash = hash_password::<&[u8], &[u8], H, BUFSIZ, KDF_OUTPUT>(
            self.username,
            self.password,
            salt.as_ref(),
            &hasher,
        )?;
        let w = scalar_from_hash(&pw_hash)?;

        let prs = (x_pub * (w * cofactor)).compress().to_bytes();

        Ok(AuCPaceClientCPaceSubstep::new(self.ssid, prs))
    }

    /// Process the augmentation layer information from the server, hashes the user's password
    /// together with their username, then computes `w` and `PRS`.
    ///
    /// This version requires the alloc feature and allocates space for
    /// the username:password string on the heap.
    ///
    /// # Arguments:
    /// - `x_pub` - `x` from the protocol definition, used in generating the password related string (prs)
    /// - `salt` - the salt value sent by the server
    /// - `hasher` - the PBKDF configured with the parameters received from the server
    ///
    /// # Return:
    /// - Ok([`next_step`](AuCPaceClientCPaceSubstep)): the client in the cpace substep
    /// - Err([`Error::PasswordHashing`] | [`Error::HashSizeInvalid`]):
    ///   key derivation failed or `KDF_OUTPUT` was not 32 or 64
    ///
    #[cfg(feature = "alloc")]
    pub fn generate_cpace_alloc<S>(
        self,
        x_pub: RistrettoPoint,
        salt: S,
        hasher: H,
    ) -> Result<AuCPaceClientCPaceSubstep<D, K1>>
    where
        S: AsRef<[u8]>,
    {
        // check for the identity point
        if x_pub.is_identity() {
            return Err(Error::IllegalPointError);
        }

        let cofactor = Scalar::ONE;
        let pw_hash = hash_password_alloc::<_, _, _, KDF_OUTPUT>(
            self.username,
            self.password,
            salt.as_ref(),
            &hasher,
        )?;
        let w = scalar_from_hash(&pw_hash)?;

        let prs = (x_pub * (w * cofactor)).compress().to_bytes();

        Ok(AuCPaceClientCPaceSubstep::new(self.ssid, prs))
    }
}

/// Client in the augmentation layer - strong version
#[cfg(feature = "strong_aucpace")]
pub struct StrongAuCPaceClientAugLayer<'a, D, H, const K1: usize, const KDF_OUTPUT: usize = 32>
where
    D: Digest<OutputSize = U64> + Default,
    H: Pbkdf,
{
    ssid: Output<D>,
    username: &'a [u8],
    password: &'a [u8],
    blinding_value: Scalar,
    h: PhantomData<H>,
}

#[cfg(feature = "strong_aucpace")]
impl<'a, D, H, const K1: usize, const KDF_OUTPUT: usize>
    StrongAuCPaceClientAugLayer<'a, D, H, K1, KDF_OUTPUT>
where
    D: Digest<OutputSize = U64> + Default,
    H: Pbkdf,
{
    const fn new(
        ssid: Output<D>,
        username: &'a [u8],
        password: &'a [u8],
        blinding_value: Scalar,
    ) -> Self {
        Self {
            ssid,
            username,
            password,
            blinding_value,
            h: PhantomData,
        }
    }

    /// Process the strong augmentation layer information from the server, unblinds the salt value,
    /// hashes the user's password together with their username, then computes `w` and `PRS`.
    ///
    /// # Arguments:
    /// - `x_pub` - `x` from the protocol definition, used in generating the password related string (prs)
    /// - `blinded_salt` - our blinded point `U`, multiplied by the server's secret exponent `q`
    /// - `hasher` - the PBKDF configured with the parameters received from the server
    ///
    /// # Const Parameters
    /// - `BUFSIZ` - the size of the buffer to use while hashing
    ///   it should be enough to store the maximum length of a username + password + 1 for your use case
    ///   e.g. if you have a username limit of 20 and password limit of 60, 81 would be the right value.
    ///
    /// # Return:
    /// - Ok([`next_step`](AuCPaceClientCPaceSubstep)): the client in the cpace substep
    /// - Err([`Error::PasswordHashing`] | [`Error::HashSizeInvalid`]):
    ///   key derivation failed or `KDF_OUTPUT` was not 32 or 64
    ///
    pub fn generate_cpace<const BUFSIZ: usize>(
        self,
        x_pub: RistrettoPoint,
        blinded_salt: RistrettoPoint,
        hasher: H,
    ) -> Result<AuCPaceClientCPaceSubstep<D, K1>> {
        // check for the identity point
        if x_pub.is_identity() {
            return Err(Error::IllegalPointError);
        }

        // first recover the salt
        let cofactor = Scalar::ONE;

        // this is a tad funky, in the paper they write (1/(r * cj^2))*cj
        // I have interpreted this as the multiplicative inverse of (r * cj^2)
        // then multiplied by cj again.
        let exponent = (self.blinding_value * cofactor * cofactor).invert() * cofactor;
        let salt_point = blinded_salt * exponent;
        if salt_point.is_identity() {
            return Err(Error::IllegalPointError);
        }
        let salt = salt_point.compress().to_bytes();

        // compute the PRS
        let pw_hash = hash_password::<&[u8], &[u8], H, BUFSIZ, KDF_OUTPUT>(
            self.username,
            self.password,
            &salt,
            &hasher,
        )?;
        let w = scalar_from_hash(&pw_hash)?;
        let prs = (x_pub * (w * cofactor)).compress().to_bytes();

        Ok(AuCPaceClientCPaceSubstep::new(self.ssid, prs))
    }

    /// Process the strong augmentation layer information from the server, unblinds the salt value,
    /// hashes the user's password together with their username, then computes `w` and `PRS`.
    ///
    /// This version requires the alloc feature and allocates space for
    /// the username:password string on the heap.
    ///
    /// # Arguments:
    /// - `x_pub` - `x` from the protocol definition, used in generating the password related string (prs)
    /// - `blinded_salt` - our blinded point `U`, multiplied by the server's secret exponent `q`
    /// - `hasher` - the PBKDF configured with the parameters received from the server
    ///
    /// # Return:
    /// - Ok([`next_step`](AuCPaceClientCPaceSubstep)): the client in the cpace substep
    /// - Err([`Error::PasswordHashing`] | [`Error::HashSizeInvalid`]):
    ///   key derivation failed or `KDF_OUTPUT` was not 32 or 64
    ///
    #[cfg(feature = "alloc")]
    pub fn generate_cpace_alloc(
        self,
        x_pub: RistrettoPoint,
        blinded_salt: RistrettoPoint,
        hasher: H,
    ) -> Result<AuCPaceClientCPaceSubstep<D, K1>> {
        // check for the identity point
        if x_pub.is_identity() {
            return Err(Error::IllegalPointError);
        }

        // first recover the salt
        let cofactor = Scalar::ONE;

        // this is a tad funky, in the paper they write (1/(r * cj^2))*cj
        // I have interpreted this as the multiplicative inverse of (r * cj^2)
        // then multiplied by cj again.
        let exponent = (self.blinding_value * cofactor * cofactor).invert() * cofactor;

        // check if the salt point is the neutral element
        let salt_point = blinded_salt * exponent;
        if salt_point.is_identity() {
            return Err(Error::IllegalPointError);
        }
        let salt = salt_point.compress().to_bytes();

        // compute the PRS
        let pw_hash = hash_password_alloc::<_, _, _, KDF_OUTPUT>(
            self.username,
            self.password,
            &salt,
            &hasher,
        )?;
        let w = scalar_from_hash(&pw_hash)?;
        let prs = (x_pub * (w * cofactor)).compress().to_bytes();

        Ok(AuCPaceClientCPaceSubstep::new(self.ssid, prs))
    }
}

/// Client in the `CPace` substep
pub struct AuCPaceClientCPaceSubstep<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    prs: [u8; 32],
}

impl<D, const K1: usize> AuCPaceClientCPaceSubstep<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    const fn new(ssid: Output<D>, prs: [u8; 32]) -> Self {
        Self { ssid, prs }
    }

    /// Generate a public key
    /// moving the protocol onto the second half of the `CPace` substep - Receive Server Pubkey
    ///
    /// # Arguments:
    /// - `channel_identifier` - `CI` from the protocol definition, in the context of TCP/IP this
    ///   is usually some combination of the server and client's IP address and TCP port numbers.
    ///   It's purpose is to prevent relay attacks.
    /// - `rng` - the CSPRNG used when generating the public/private keypair
    ///
    /// # Return:
    /// ([`next_step`](AuCPaceClientRecvServerKey), [`message`](ClientMessage::PublicKey))
    /// - [`next_step`](AuCPaceClientRecvServerKey): the client waiting for the server's public key
    /// - [`message`](ClientMessage::PublicKey): the message to send to the server
    ///
    pub fn generate_public_key<CI, CSPRNG>(
        self,
        channel_identifier: CI,
        rng: &mut CSPRNG,
    ) -> (
        AuCPaceClientRecvServerKey<D, K1>,
        ClientMessage<'static, K1>,
    )
    where
        CI: AsRef<[u8]>,
        CSPRNG: CryptoRng,
    {
        let (priv_key, pub_key) =
            generate_keypair::<D, CSPRNG, CI>(rng, self.ssid, self.prs, channel_identifier);

        let next_step = AuCPaceClientRecvServerKey::new(self.ssid, priv_key);
        let message = ClientMessage::PublicKey(pub_key);

        (next_step, message)
    }
}

/// Client waiting to receive the server's public key
pub struct AuCPaceClientRecvServerKey<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    priv_key: Scalar,
}

impl<D, const K1: usize> AuCPaceClientRecvServerKey<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    const fn new(ssid: Output<D>, priv_key: Scalar) -> Self {
        Self { ssid, priv_key }
    }

    /// Receive the server's public key
    /// This completes the `CPace` substep and moves the client on to explicit mutual authentication.
    ///
    /// # Arguments:
    /// - `server_pubkey` - the server's public key
    ///
    /// # Return:
    /// ([`next_step`](AuCPaceClientExpMutAuth), [`message`](ClientMessage::Authenticator))
    /// - [`next_step`](AuCPaceClientExpMutAuth): the client in the Explicit Mutual Authentication phase
    /// - [`message`](ClientMessage::Authenticator): the message to send to the server
    ///
    pub fn receive_server_pubkey(
        self,
        server_pubkey: RistrettoPoint,
    ) -> Result<(AuCPaceClientExpMutAuth<D, K1>, ClientMessage<'static, K1>)> {
        if server_pubkey.is_identity() {
            return Err(Error::IllegalPointError);
        }

        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, server_pubkey);
        let (ta, tb) = compute_authenticator_messages::<D>(self.ssid, sk1);
        let next_step = AuCPaceClientExpMutAuth::new(self.ssid, sk1, ta);
        let message = ClientMessage::Authenticator(
            tb.as_slice()
                .try_into()
                .expect("array length invariant broken"),
        );
        Ok((next_step, message))
    }

    /// Allow the user to exit the protocol early in the case of implicit authentication
    /// Note: this should only be used in special circumstances and the
    ///       explicit mutual authentication stage should be used in all other cases
    ///
    /// # Arguments:
    /// - `server_pubkey` - the server's public key
    ///
    /// # Return:
    /// `sk`: the session key reached by the `AuCPace` protocol
    ///
    pub fn implicit_auth(self, server_pubkey: RistrettoPoint) -> Result<Output<D>> {
        if server_pubkey.is_identity() {
            return Err(Error::IllegalPointError);
        }

        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, server_pubkey);
        Ok(compute_session_key::<D>(self.ssid, sk1))
    }
}

/// Client in the Explicit Mutual Authenticaton phase
pub struct AuCPaceClientExpMutAuth<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    sk1: Output<D>,
    server_authenticator: Output<D>,
}

impl<D, const K1: usize> AuCPaceClientExpMutAuth<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    const fn new(ssid: Output<D>, sk1: Output<D>, server_authenticator: Output<D>) -> Self {
        Self {
            ssid,
            sk1,
            server_authenticator,
        }
    }

    /// Receive the server's authenticator.
    /// This completes the protocol and returns the derived key.
    ///
    /// # Arguments:
    /// - `server_authenticator` - the server's authenticator
    ///
    /// # Return:
    /// either:
    /// - Ok(`sk`): the session key reached by the `AuCPace` protocol
    /// - Err([`Error::MutualAuthFail`](Error::MutualAuthFail)): an error if the authenticator we computed doesn't match
    ///   the server's authenticator, compared in constant time.
    ///
    pub fn receive_server_authenticator(self, server_authenticator: [u8; 64]) -> Result<Output<D>> {
        if self
            .server_authenticator
            .ct_eq(&server_authenticator)
            .into()
        {
            Ok(compute_session_key::<D>(self.ssid, self.sk1))
        } else {
            Err(Error::MutualAuthFail)
        }
    }
}

/// Hash a username and password with the given password hasher
fn hash_password<U, P, H, const BUFSIZ: usize, const N: usize>(
    username: U,
    password: P,
    salt: &[u8],
    hasher: &H,
) -> Result<[u8; N]>
where
    H: Pbkdf,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    let user = username.as_ref();
    let pass = password.as_ref();
    let u = user.len();
    let p = pass.len();

    if u + p + 1 > BUFSIZ {
        return Err(Error::UsernameOrPasswordTooLong);
    }

    let mut buf = [0u8; BUFSIZ];
    buf[0..u].copy_from_slice(user);
    buf[u] = b':';
    buf[(u + 1)..=(u + p)].copy_from_slice(pass);

    derive_password_key(&buf[0..=(u + p)], salt, hasher)
}

/// Hash a username and password with the given password hasher
#[cfg(feature = "alloc")]
fn hash_password_alloc<U, P, H, const N: usize>(
    username: U,
    password: P,
    salt: &[u8],
    hasher: &H,
) -> Result<[u8; N]>
where
    H: Pbkdf,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
{
    let user = username.as_ref();
    let pass = password.as_ref();

    // hash "{username}:{password}"
    let mut v = alloc::vec::Vec::with_capacity(user.len() + pass.len() + 1);
    v.extend_from_slice(user);
    v.push(b':');
    v.extend_from_slice(pass);

    derive_password_key(v.as_slice(), salt, hasher)
}

/// Derive raw key material of a supported length from the decoded salt.
fn derive_password_key<H: Pbkdf, const N: usize>(
    password: &[u8],
    salt: &[u8],
    hasher: &H,
) -> Result<[u8; N]> {
    if N != 32 && N != 64 {
        return Err(Error::HashSizeInvalid);
    }

    let mut output = [0u8; N];
    hasher
        .derive_key(password, salt, &mut output)
        .map_err(Error::PasswordHashing)?;
    Ok(output)
}

/// An enum representing the different messages the client can send to the server.
///
/// `Params` is application-defined PBKDF metadata. Use `()` when the KDF configuration
/// is agreed out of band. Only registration messages contain this metadata.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ClientMessage<'a, const K1: usize, Params = ()> {
    /// SSID establishment message - the client's nonce: `t`
    Nonce(#[cfg_attr(feature = "serde", serde(with = "serde_byte_array"))] [u8; K1]),

    /// Username - the client's username
    Username(&'a [u8]),

    /// StrongUsername - the strong `AuCPace` username message
    /// also contains the blinded point `U`
    #[cfg(feature = "strong_aucpace")]
    StrongUsername {
        /// The client's username
        username: &'a [u8],
        /// The blinded point `U`
        blinded: RistrettoPoint,
    },

    /// PublicKey - the client's public key: `Ya`
    PublicKey(RistrettoPoint),

    /// Explicit Mutual Authentication - the client's authenticator: `Tb`
    Authenticator(#[cfg_attr(feature = "serde", serde(with = "serde_byte_array"))] [u8; 64]),

    /// Registration - the username, verifier, salt and parameters needed for registering a user
    /// NOTE: if the UAD field is desired this should be handled separately and sent at the same time
    Registration {
        /// The username of whoever is registering
        username: &'a [u8],

        /// The salt used when computing the verifier
        salt: Salt,

        /// The password hasher's parameters used when computing the verifier
        params: Params,

        /// The verifier computer from the user's password
        verifier: RistrettoPoint,
    },

    /// Registration Strong version - the username, verifier, secret exponent and parameters needed for registering a user
    /// NOTE: if the UAD field is desired this should be handled separately and sent at the same time
    #[cfg(feature = "strong_aucpace")]
    StrongRegistration {
        /// The username of whoever is registering
        username: &'a [u8],

        /// The salt used when computing the verifier
        secret_exponent: Scalar,

        /// The password hasher's parameters used when computing the verifier
        params: Params,

        /// The verifier computer from the user's password
        verifier: RistrettoPoint,
    },
}

#[cfg(test)]
mod tests {
    #[allow(unused)]
    use super::*;

    #[cfg(all(feature = "getrandom", feature = "sha2", feature = "scrypt"))]
    use crate::{SysRng, rand_core::UnwrapErr};

    #[test]
    fn test_pbkdf_test_vector() {
        use scrypt::{Params, Scrypt};

        fn check<const N: usize>() {
            // Weak parameters for tests only, with non-default output lengths.
            let params = Params::new(4, 8, 1).unwrap();
            let scrypt = Scrypt::new_with_params(params);
            let salt = b"\0binary\xffsalt\0";
            // Independently generated with Python's hashlib.scrypt.
            let expected = [
                0xab, 0x1a, 0x35, 0xb7, 0x4a, 0x2a, 0x59, 0x4c, 0x33, 0x46, 0x17, 0xcf, 0x2c, 0xb0,
                0x7b, 0xa9, 0x8c, 0x05, 0xb3, 0xf4, 0x11, 0xd3, 0x5d, 0xc0, 0x22, 0x74, 0xac, 0xb6,
                0xa6, 0x03, 0x20, 0x9f, 0xd2, 0xa4, 0x5d, 0xd8, 0x81, 0x82, 0x3f, 0xc4, 0x81, 0xdb,
                0xca, 0x1d, 0xe3, 0xfe, 0x2b, 0x4a, 0x3f, 0x19, 0x34, 0xef, 0xde, 0xa4, 0x55, 0xb8,
                0xd4, 0x36, 0x5e, 0xcb, 0x15, 0x74, 0xd5, 0xc2,
            ];
            let derived =
                hash_password::<_, _, _, 13, N>(b"user", b"password", salt, &scrypt).unwrap();
            assert_eq!(derived.as_slice(), &expected[..N]);

            #[cfg(feature = "alloc")]
            assert_eq!(
                hash_password_alloc::<_, _, _, N>(b"user", b"password", salt, &scrypt).unwrap(),
                derived,
            );
        }

        check::<32>();
        check::<64>();
    }

    struct FailingPbkdf;

    impl kdf::Kdf for FailingPbkdf {
        fn derive_key(&self, _: &[u8], _: &[u8], _: &mut [u8]) -> kdf::Result<()> {
            Err(kdf::Error)
        }
    }

    impl Pbkdf for FailingPbkdf {}

    #[test]
    fn test_pbkdf_errors() {
        let salt = b"test salt";
        assert_eq!(
            hash_password::<_, _, _, 13, 32>(b"user", b"password", salt, &FailingPbkdf),
            Err(Error::PasswordHashing(kdf::Error)),
        );
        assert_eq!(
            hash_password::<_, _, _, 12, 32>(b"user", b"password", salt, &FailingPbkdf),
            Err(Error::UsernameOrPasswordTooLong),
        );
        assert_eq!(
            hash_password::<_, _, _, 13, 48>(b"user", b"password", salt, &FailingPbkdf),
            Err(Error::HashSizeInvalid),
        );

        #[cfg(feature = "alloc")]
        assert_eq!(
            hash_password_alloc::<_, _, _, 32>(b"user", b"password", salt, &FailingPbkdf),
            Err(Error::PasswordHashing(kdf::Error)),
        );
    }

    #[test]
    #[cfg(all(feature = "getrandom", feature = "sha2", feature = "scrypt"))]
    fn test_client_doesnt_accept_insecure_ssid() {
        use crate::Client;

        let mut client = Client::new(UnwrapErr(SysRng));
        let res = client.begin_prestablished_ssid("bad ssid");
        assert!(matches!(res, Err(Error::InsecureSsid)));
    }

    #[test]
    #[cfg(all(feature = "sha2", feature = "scrypt"))]
    fn test_client_doesnt_accept_invalid_x_pub() {
        use crate::utils::H0;
        use curve25519_dalek::traits::Identity;
        let ssid = H0::<sha2::Sha512>().finalize();
        let aug_client: AuCPaceClientAugLayer<'_, sha2::Sha512, scrypt::Scrypt, 16> =
            AuCPaceClientAugLayer::new(
                ssid,
                b"bob",
                b"bob's very secure password that nobody knows about, honest",
            );
        let res = aug_client.generate_cpace::<_, 100>(
            RistrettoPoint::identity(),
            b"saltyboi",
            scrypt::Scrypt::default(),
        );

        if let Err(e) = res {
            assert_eq!(e, Error::IllegalPointError);
        } else {
            panic!("Client accepted illegal point.");
        }
    }

    #[test]
    #[cfg(all(feature = "sha2", feature = "scrypt", feature = "alloc"))]
    fn test_alloc_client_doesnt_accept_invalid_x_pub() {
        use crate::utils::H0;
        use curve25519_dalek::traits::Identity;
        let ssid = H0::<sha2::Sha512>().finalize();
        let aug_client: AuCPaceClientAugLayer<'_, sha2::Sha512, scrypt::Scrypt, 16> =
            AuCPaceClientAugLayer::new(
                ssid,
                b"bob",
                b"bob's very secure password that nobody knows about, honest",
            );
        let res = aug_client.generate_cpace_alloc(
            RistrettoPoint::identity(),
            b"saltyboi",
            scrypt::Scrypt::default(),
        );

        if let Err(e) = res {
            assert_eq!(e, Error::IllegalPointError);
        } else {
            panic!("Client accepted illegal point.");
        }
    }

    #[test]
    #[cfg(all(feature = "sha2", feature = "scrypt", feature = "strong_aucpace"))]
    fn test_strong_client_doesnt_accept_invalid_x_pub() {
        use crate::utils::H0;
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::traits::Identity;

        let ssid = H0::<sha2::Sha512>().finalize();
        let aug_client: StrongAuCPaceClientAugLayer<'_, sha2::Sha512, scrypt::Scrypt, 16> =
            StrongAuCPaceClientAugLayer::new(
                ssid,
                b"bob",
                b"bob's very secure password that nobody knows about, honest",
                Scalar::from(69u32),
            );
        let res = aug_client.generate_cpace::<100>(
            RistrettoPoint::identity(),
            RISTRETTO_BASEPOINT_POINT,
            scrypt::Scrypt::default(),
        );

        if let Err(e) = res {
            assert_eq!(e, Error::IllegalPointError);
        } else {
            panic!("Client accepted illegal point.");
        }
    }

    #[test]
    #[cfg(all(
        feature = "sha2",
        feature = "scrypt",
        feature = "alloc",
        feature = "strong_aucpace"
    ))]
    fn test_strong_alloc_client_doesnt_accept_invalid_x_pub() {
        use crate::utils::H0;
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::traits::Identity;

        let ssid = H0::<sha2::Sha512>().finalize();
        let aug_client: StrongAuCPaceClientAugLayer<'_, sha2::Sha512, scrypt::Scrypt, 16> =
            StrongAuCPaceClientAugLayer::new(
                ssid,
                b"bob",
                b"bob's very secure password that nobody knows about, honest",
                Scalar::from(69u32),
            );
        let res = aug_client.generate_cpace_alloc(
            RistrettoPoint::identity(),
            RISTRETTO_BASEPOINT_POINT,
            scrypt::Scrypt::default(),
        );

        if let Err(e) = res {
            assert_eq!(e, Error::IllegalPointError);
        } else {
            panic!("Client accepted illegal point.");
        }
    }

    #[test]
    #[cfg(all(feature = "sha2", feature = "scrypt"))]
    fn test_client_doesnt_accept_invalid_pubkey() {
        use crate::utils::H0;
        use curve25519_dalek::traits::Identity;
        let ssid = H0::<sha2::Sha512>().finalize();
        let aug_client: AuCPaceClientRecvServerKey<sha2::Sha512, 16> =
            AuCPaceClientRecvServerKey::new(ssid, Scalar::from(420u32));
        let res = aug_client.receive_server_pubkey(RistrettoPoint::identity());

        if let Err(e) = res {
            assert_eq!(e, Error::IllegalPointError);
        } else {
            panic!("Client accepted illegal point.");
        }
    }

    #[test]
    #[cfg(all(feature = "sha2", feature = "scrypt"))]
    fn test_client_doesnt_accept_invalid_pubkey_implicit_auth() {
        use crate::utils::H0;
        use curve25519_dalek::traits::Identity;
        let ssid = H0::<sha2::Sha512>().finalize();
        let aug_client: AuCPaceClientRecvServerKey<sha2::Sha512, 16> =
            AuCPaceClientRecvServerKey::new(ssid, Scalar::from(420u32));
        let res = aug_client.implicit_auth(RistrettoPoint::identity());

        if let Err(e) = res {
            assert_eq!(e, Error::IllegalPointError);
        } else {
            panic!("Client accepted illegal point.");
        }
    }

    #[test]
    #[cfg(all(feature = "sha2", feature = "scrypt", feature = "strong_aucpace"))]
    fn test_strong_client_doesnt_accept_invalid_salt() {
        use crate::utils::H0;
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::traits::Identity;

        let ssid = H0::<sha2::Sha512>().finalize();
        let aug_client: StrongAuCPaceClientAugLayer<'_, sha2::Sha512, scrypt::Scrypt, 16> =
            StrongAuCPaceClientAugLayer::new(
                ssid,
                b"bob",
                b"bob's very secure password that nobody knows about, honest",
                Scalar::from(69u32),
            );
        let res = aug_client.generate_cpace::<100>(
            RISTRETTO_BASEPOINT_POINT,
            RistrettoPoint::identity(),
            scrypt::Scrypt::default(),
        );

        if let Err(e) = res {
            assert_eq!(e, Error::IllegalPointError);
        } else {
            panic!("Client accepted illegal point.");
        }
    }
    #[test]
    #[cfg(all(
        feature = "sha2",
        feature = "scrypt",
        feature = "alloc",
        feature = "strong_aucpace"
    ))]
    fn test_strong_alloc_client_doesnt_accept_invalid_salt() {
        use crate::utils::H0;
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::traits::Identity;

        let ssid = H0::<sha2::Sha512>().finalize();
        let aug_client: StrongAuCPaceClientAugLayer<'_, sha2::Sha512, scrypt::Scrypt, 16> =
            StrongAuCPaceClientAugLayer::new(
                ssid,
                b"bob",
                b"bob's very secure password that nobody knows about, honest",
                Scalar::from(69u32),
            );
        let res = aug_client.generate_cpace_alloc(
            RISTRETTO_BASEPOINT_POINT,
            RistrettoPoint::identity(),
            scrypt::Scrypt::default(),
        );

        if let Err(e) = res {
            assert_eq!(e, Error::IllegalPointError);
        } else {
            panic!("Client accepted illegal point.");
        }
    }
}
