use crate::{
    errors::{Error, Result},
    utils::{
        compute_authenticator_messages, compute_first_session_key, compute_session_key,
        compute_ssid, generate_keypair, generate_nonce, scalar_from_hash, H0,
    },
};

use crate::constants::MIN_SSID_LEN;
use core::marker::PhantomData;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{
    digest::consts::U64,
    digest::{Digest, Output},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use password_hash::{ParamsString, PasswordHash, PasswordHasher, Salt, SaltString};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

#[cfg(feature = "strong_aucpace")]
use crate::utils::H1;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "serde")]
use crate::utils::{serde_paramsstring, serde_saltstring};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Implementation of the client side of the AuCPace protocol
pub struct AuCPaceClient<D, H, CSPRNG, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
    H: PasswordHasher,
    CSPRNG: CryptoRngCore,
{
    rng: CSPRNG,
    d: PhantomData<D>,
    h: PhantomData<H>,
}

impl<D, H, CSPRNG, const K1: usize> AuCPaceClient<D, H, CSPRNG, K1>
where
    D: Digest<OutputSize = U64> + Default,
    H: PasswordHasher,
    CSPRNG: CryptoRngCore,
{
    /// Create new server
    pub fn new(rng: CSPRNG) -> Self {
        Self {
            rng,
            d: Default::default(),
            h: Default::default(),
        }
    }

    /// Create a new client in the SSID agreement phase
    ///
    /// # Return:
    /// ([`next_step`](AuCPaceClientSsidEstablish), [`message`](ClientMessage::Nonce))
    /// - [`next_step`](AuCPaceClientSsidEstablish): the client in the SSID establishment stage
    /// - [`message`](ClientMessage::Nonce): the message to send to the server
    ///
    pub fn begin(&mut self) -> (AuCPaceClientSsidEstablish<D, H, K1>, ClientMessage<'_, K1>) {
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
    pub fn begin_prestablished_ssid<S>(&mut self, ssid: S) -> Result<AuCPaceClientPreAug<D, H, K1>>
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
    /// - `params` - the parameters of the PBKDF used
    /// - `hasher` - the hasher to use for hashing the username and password.
    ///
    /// # Const Parameters
    /// - `BUFSIZ` - the size of the buffer to use while hashing
    ///   it should be enough to store the maximum length of a username + password + 1 for your use case
    ///   e.g. if you have a username limit of 20 and password limit of 60, 81 would be the right value.
    ///
    /// # Return:
    /// - Ok([`messsage`](ClientMessage::Registration)): the message to send to the server
    /// - Err([`Error::PasswordHashing`](Error::PasswordHashing) | [`Error::HashEmpty`](Error::HashEmpty) | [`Error::HashSizeInvalid`](Error::HashSizeInvalid)):
    ///   one of the three error variants that can result from the password hashing process
    ///
    pub fn register<'a, P, const BUFSIZ: usize>(
        &mut self,
        username: &'a [u8],
        password: P,
        params: H::Params,
        hasher: H,
    ) -> Result<ClientMessage<'a, K1>>
    where
        P: AsRef<[u8]>,
    {
        let salt_string = SaltString::generate(&mut self.rng);

        // compute the verifier W
        let pw_hash = hash_password::<&[u8], P, &SaltString, H, BUFSIZ>(
            username,
            password,
            &salt_string,
            params.clone(),
            hasher,
        )?;

        let cofactor = Scalar::ONE;
        let w = scalar_from_hash(pw_hash)?;
        let verifier = RISTRETTO_BASEPOINT_POINT * (w * cofactor);

        // attempt to convert the parameters to a ParamsString
        let params_string = params.try_into().map_err(Error::PasswordHashing)?;

        Ok(ClientMessage::Registration {
            username,
            salt: salt_string,
            params: params_string,
            verifier,
        })
    }

    /// Register a username/password in the strong variant of the protocol
    ///
    /// # Arguments:
    /// - `username` - the username to register with
    /// - `password` - the password for the user
    /// - `params` - the parameters of the PBKDF used
    /// - `hasher` - the hasher to use for hashing the username and password.
    ///
    /// # Const Parameters
    /// - `BUFSIZ` - the size of the buffer to use while hashing
    ///   it should be enough to store the maximum length of a username + password + 1 for your use case
    ///   e.g. if you have a username limit of 20 and password limit of 60, 81 would be the right value.
    ///
    /// # Return:
    /// - Ok([`messsage`](ClientMessage::Registration)): the message to send to the server
    /// - Err([`Error::PasswordHashing`](Error::PasswordHashing) | [`Error::HashEmpty`](Error::HashEmpty) | [`Error::HashSizeInvalid`](Error::HashSizeInvalid)):
    ///   one of the three error variants that can result from the password hashing process
    ///
    #[cfg(feature = "strong_aucpace")]
    pub fn register_strong<'a, P, const BUFSIZ: usize>(
        &mut self,
        username: &'a [u8],
        password: P,
        params: H::Params,
        hasher: H,
    ) -> Result<ClientMessage<'a, K1>>
    where
        P: AsRef<[u8]>,
    {
        // generate a secret exponent and salt
        let (q, salt_string) =
            Self::generate_salt_strong(username, password.as_ref(), &mut self.rng)?;

        // compute the verifier W
        let pw_hash = hash_password::<&[u8], P, &SaltString, H, BUFSIZ>(
            username,
            password,
            &salt_string,
            params.clone(),
            hasher,
        )?;
        let cofactor = Scalar::ONE;
        let w = scalar_from_hash(pw_hash)?;
        let verifier = RISTRETTO_BASEPOINT_POINT * (w * cofactor);

        // attempt to convert the parameters to a ParamsString
        let params_string = params.try_into().map_err(Error::PasswordHashing)?;

        Ok(ClientMessage::StrongRegistration {
            username,
            secret_exponent: q,
            params: params_string,
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
    /// - `params` - the parameters of the PBKDF used
    /// - `hasher` - the hasher to use for hashing the username and password.
    ///
    /// # Return:
    /// - Ok([`messsage`](ClientMessage::Registration)): the message to send to the server
    /// - Err([`Error::PasswordHashing`](Error::PasswordHashing) | [`Error::HashEmpty`](Error::HashEmpty) | [`Error::HashSizeInvalid`](Error::HashSizeInvalid)):
    ///   one of the three error variants that can result from the password hashing process
    ///
    #[cfg(feature = "alloc")]
    pub fn register_alloc<'a, P>(
        &mut self,
        username: &'a [u8],
        password: P,
        params: H::Params,
        hasher: H,
    ) -> Result<ClientMessage<'a, K1>>
    where
        P: AsRef<[u8]>,
    {
        // adapted from SaltString::generate, which we cannot use due to curve25519 versions of rand_core
        let salt_string = SaltString::generate(&mut self.rng);

        // compute the verifier W
        let pw_hash =
            hash_password_alloc(username, password, &salt_string, params.clone(), hasher)?;
        let cofactor = Scalar::ONE;
        let w = scalar_from_hash(pw_hash)?;
        let verifier = RISTRETTO_BASEPOINT_POINT * (w * cofactor);

        // attempt to convert the parameters to a ParamsString
        let params_string = params.try_into().map_err(Error::PasswordHashing)?;

        Ok(ClientMessage::Registration {
            username,
            salt: salt_string,
            params: params_string,
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
    /// - `params` - the parameters of the PBKDF used
    /// - `hasher` - the hasher to use for hashing the username and password.
    ///
    /// # Const Parameters
    /// - `BUFSIZ` - the size of the buffer to use while hashing
    ///   it should be enough to store the maximum length of a username + password + 1 for your use case
    ///   e.g. if you have a username limit of 20 and password limit of 60, 81 would be the right value.
    ///
    /// # Return:
    /// - Ok([`messsage`](ClientMessage::Registration)): the message to send to the server
    /// - Err([`Error::PasswordHashing`](Error::PasswordHashing) | [`Error::HashEmpty`](Error::HashEmpty) | [`Error::HashSizeInvalid`](Error::HashSizeInvalid)):
    ///   one of the three error variants that can result from the password hashing process
    ///
    #[cfg(all(feature = "strong_aucpace", feature = "alloc"))]
    pub fn register_alloc_strong<'a, P>(
        &mut self,
        username: &'a [u8],
        password: P,
        params: H::Params,
        hasher: H,
    ) -> Result<ClientMessage<'a, K1>>
    where
        P: AsRef<[u8]>,
    {
        // generate a secret exponent and salt
        let (q, salt_string) =
            Self::generate_salt_strong(username, password.as_ref(), &mut self.rng)?;

        // compute the verifier W
        let pw_hash = hash_password_alloc(
            username,
            password,
            salt_string.as_salt(),
            params.clone(),
            hasher,
        )?;
        let cofactor = Scalar::ONE;
        let w = scalar_from_hash(pw_hash)?;
        let verifier = RISTRETTO_BASEPOINT_POINT * (w * cofactor);

        // attempt to convert the parameters to a ParamsString
        let params_string = params.try_into().map_err(Error::PasswordHashing)?;

        Ok(ClientMessage::StrongRegistration {
            username,
            secret_exponent: q,
            params: params_string,
            verifier,
        })
    }

    /// generate a secret exponent and a salt value for the strong variant of the protocol
    #[cfg(feature = "strong_aucpace")]
    fn generate_salt_strong(
        user: &[u8],
        pass: &[u8],
        rng: &mut CSPRNG,
    ) -> Result<(Scalar, SaltString)> {
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
        let salt_string = SaltString::b64_encode(&salt).map_err(Error::PasswordHashing)?;

        Ok((q, salt_string))
    }
}

/// Client in the SSID agreement phase
pub struct AuCPaceClientSsidEstablish<D, H, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
    H: PasswordHasher,
{
    nonce: [u8; K1],
    d: PhantomData<D>,
    h: PhantomData<H>,
}

impl<D, H, const K1: usize> AuCPaceClientSsidEstablish<D, H, K1>
where
    D: Digest<OutputSize = U64> + Default,
    H: PasswordHasher,
{
    fn new<CSPRNG>(rng: &mut CSPRNG) -> Self
    where
        CSPRNG: CryptoRngCore,
    {
        Self {
            nonce: generate_nonce(rng),
            d: Default::default(),
            h: Default::default(),
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
    pub fn agree_ssid(self, server_nonce: [u8; K1]) -> AuCPaceClientPreAug<D, H, K1> {
        let ssid = compute_ssid::<D, K1>(server_nonce, self.nonce);
        AuCPaceClientPreAug::new(ssid)
    }
}

/// Client in the pre-augmentation phase
pub struct AuCPaceClientPreAug<D, H, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
    H: PasswordHasher,
{
    ssid: Output<D>,
    h: PhantomData<H>,
}

impl<D, H, const K1: usize> AuCPaceClientPreAug<D, H, K1>
where
    D: Digest<OutputSize = U64> + Default,
    H: PasswordHasher,
{
    fn new(ssid: Output<D>) -> Self {
        Self {
            ssid,
            h: Default::default(),
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
    pub fn start_augmentation<'a>(
        self,
        username: &'a [u8],
        password: &'a [u8],
    ) -> (AuCPaceClientAugLayer<'a, D, H, K1>, ClientMessage<'a, K1>) {
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
        StrongAuCPaceClientAugLayer<'a, D, H, K1>,
        ClientMessage<'a, K1>,
    )
    where
        CSPRNG: CryptoRngCore,
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
pub struct AuCPaceClientAugLayer<'a, D, H, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
    H: PasswordHasher,
{
    ssid: Output<D>,
    username: &'a [u8],
    password: &'a [u8],
    h: PhantomData<H>,
}

impl<'a, D, H, const K1: usize> AuCPaceClientAugLayer<'a, D, H, K1>
where
    D: Digest<OutputSize = U64> + Default,
    H: PasswordHasher,
{
    fn new(ssid: Output<D>, username: &'a [u8], password: &'a [u8]) -> Self {
        Self {
            ssid,
            username,
            password,
            h: Default::default(),
        }
    }

    /// Process the augmentation layer information from the server, hashes the user's password
    /// together with their username, then computes `w` and `PRS`.
    ///
    /// # Arguments:
    /// - `x_pub` - `x` from the protocol definition, used in generating the password related string (prs)
    /// - `salt` - the salt value sent by the server
    /// - `params` - the parameters used by the hasher
    /// - `hasher` - the hasher to use when computing `w`
    ///
    /// # Const Parameters
    /// - `BUFSIZ` - the size of the buffer to use while hashing
    ///   it should be enough to store the maximum length of a username + password + 1 for your use case
    ///   e.g. if you have a username limit of 20 and password limit of 60, 81 would be the right value.
    ///
    /// This version requires the alloc feature and allocates space for
    /// the username and password on the heap using Vec.
    ///
    /// # Return:
    /// - Ok([`next_step`](AuCPaceClientCPaceSubstep)): the client in the cpace substep
    /// - Err([`Error::PasswordHashing`](Error::PasswordHashing) | [`Error::HashEmpty`](Error::HashEmpty) | [`Error::HashSizeInvalid`](Error::HashSizeInvalid)):
    ///   one of the three error variants that can result from the password hashing process
    ///
    pub fn generate_cpace<'salt, S, const BUFSIZ: usize>(
        self,
        x_pub: RistrettoPoint,
        salt: S,
        params: H::Params,
        hasher: H,
    ) -> Result<AuCPaceClientCPaceSubstep<D, K1>>
    where
        S: Into<Salt<'a>>,
    {
        let cofactor = Scalar::ONE;
        let pw_hash = hash_password::<&[u8], &[u8], S, H, BUFSIZ>(
            self.username,
            self.password,
            salt,
            params,
            hasher,
        )?;
        let w = scalar_from_hash(pw_hash)?;

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
    /// - `params` - the parameters used by the hasher
    /// - `hasher` - the hasher to use when computing `w`
    ///
    /// # Return:
    /// - Ok([`next_step`](AuCPaceClientCPaceSubstep)): the client in the cpace substep
    /// - Err([`Error::PasswordHashing`](Error::PasswordHashing) | [`Error::HashEmpty`](Error::HashEmpty) | [`Error::HashSizeInvalid`](Error::HashSizeInvalid)):
    ///   one of the three error variants that can result from the password hashing process
    ///
    #[cfg(feature = "alloc")]
    pub fn generate_cpace_alloc<'salt, S>(
        self,
        x_pub: RistrettoPoint,
        salt: S,
        params: H::Params,
        hasher: H,
    ) -> Result<AuCPaceClientCPaceSubstep<D, K1>>
    where
        S: Into<Salt<'a>>,
    {
        let cofactor = Scalar::ONE;
        let pw_hash = hash_password_alloc(self.username, self.password, salt, params, hasher)?;
        let w = scalar_from_hash(pw_hash)?;

        let prs = (x_pub * (w * cofactor)).compress().to_bytes();

        Ok(AuCPaceClientCPaceSubstep::new(self.ssid, prs))
    }
}

/// Client in the augmentation layer - strong version
#[cfg(feature = "strong_aucpace")]
pub struct StrongAuCPaceClientAugLayer<'a, D, H, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
    H: PasswordHasher,
{
    ssid: Output<D>,
    username: &'a [u8],
    password: &'a [u8],
    blinding_value: Scalar,
    h: PhantomData<H>,
}

#[cfg(feature = "strong_aucpace")]
impl<'a, D, H, const K1: usize> StrongAuCPaceClientAugLayer<'a, D, H, K1>
where
    D: Digest<OutputSize = U64> + Default,
    H: PasswordHasher,
{
    fn new(
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
            h: Default::default(),
        }
    }

    /// Process the strong augmentation layer information from the server, unblinds the salt value,
    /// hashes the user's password together with their username, then computes `w` and `PRS`.
    ///
    /// # Arguments:
    /// - `x_pub` - `x` from the protocol definition, used in generating the password related string (prs)
    /// - `salt_point` - our blinded point `U`, multiplied by the server's secret exponent `q`
    /// - `params` - the parameters used by the hasher
    /// - `hasher` - the hasher to use when computing `w`
    ///
    /// # Const Parameters
    /// - `BUFSIZ` - the size of the buffer to use while hashing
    ///   it should be enough to store the maximum length of a username + password + 1 for your use case
    ///   e.g. if you have a username limit of 20 and password limit of 60, 81 would be the right value.
    ///
    /// This version requires the alloc feature and allocates space for
    /// the username and password on the heap using Vec.
    ///
    /// # Return:
    /// - Ok([`next_step`](AuCPaceClientCPaceSubstep)): the client in the cpace substep
    /// - Err([`Error::PasswordHashing`](Error::PasswordHashing) | [`Error::HashEmpty`](Error::HashEmpty) | [`Error::HashSizeInvalid`](Error::HashSizeInvalid)):
    ///   one of the three error variants that can result from the password hashing process
    ///
    pub fn generate_cpace<const BUFSIZ: usize>(
        self,
        x_pub: RistrettoPoint,
        blinded_salt: RistrettoPoint,
        params: H::Params,
        hasher: H,
    ) -> Result<AuCPaceClientCPaceSubstep<D, K1>> {
        // first recover the salt
        let cofactor = Scalar::ONE;

        // this is a tad funky, in the paper they write (1/(r * cj^2))*cj
        // I have interpreted this as the multiplicative inverse of (r * cj^2)
        // then multiplied by cj again.
        let exponent = (self.blinding_value * cofactor * cofactor).invert() * cofactor;
        let salt = (blinded_salt * exponent).compress().to_bytes();
        let salt_string = SaltString::b64_encode(&salt).map_err(Error::PasswordHashing)?;

        // compute the PRS
        let pw_hash = hash_password::<&[u8], &[u8], &SaltString, H, BUFSIZ>(
            self.username,
            self.password,
            &salt_string,
            params,
            hasher,
        )?;
        let w = scalar_from_hash(pw_hash)?;
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
    /// - `password` - the user's password
    /// - `salt` - the salt value sent by the server
    /// - `params` - the parameters used by the hasher
    /// - `hasher` - the hasher to use when computing `w`
    ///
    /// # Return:
    /// - Ok([`next_step`](AuCPaceClientCPaceSubstep)): the client in the cpace substep
    /// - Err([`Error::PasswordHashing`](Error::PasswordHashing) | [`Error::HashEmpty`](Error::HashEmpty) | [`Error::HashSizeInvalid`](Error::HashSizeInvalid)):
    ///   one of the three error variants that can result from the password hashing process
    ///
    #[cfg(feature = "alloc")]
    pub fn generate_cpace_alloc(
        self,
        x_pub: RistrettoPoint,
        blinded_salt: RistrettoPoint,
        params: H::Params,
        hasher: H,
    ) -> Result<AuCPaceClientCPaceSubstep<D, K1>> {
        // first recover the salt
        let cofactor = Scalar::ONE;

        // this is a tad funky, in the paper they write (1/(r * cj^2))*cj
        // I have interpreted this as the multiplicative inverse of (r * cj^2)
        // then multiplied by cj again.
        let exponent = (self.blinding_value * cofactor * cofactor).invert() * cofactor;
        let salt = (blinded_salt * exponent).compress().to_bytes();
        let salt_string = SaltString::b64_encode(&salt).map_err(Error::PasswordHashing)?;

        // compute the PRS
        let pw_hash = hash_password_alloc(
            self.username,
            self.password,
            salt_string.as_salt(),
            params,
            hasher,
        )?;
        let w = scalar_from_hash(pw_hash)?;
        let prs = (x_pub * (w * cofactor)).compress().to_bytes();

        Ok(AuCPaceClientCPaceSubstep::new(self.ssid, prs))
    }
}

/// Client in the CPace substep
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
    fn new(ssid: Output<D>, prs: [u8; 32]) -> Self {
        Self { ssid, prs }
    }

    /// Generate a public key
    /// moving the protocol onto the second half of the CPace substep - Receive Server Pubkey
    ///
    /// # Arguments:
    /// - `channel_identifier` - `CI` from the protocol definition, in the context of TCP/IP this
    ///     is usually some combination of the server and client's IP address and TCP port numbers.
    ///     It's purpose is to prevent relay attacks.
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
        CSPRNG: CryptoRngCore,
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
    fn new(ssid: Output<D>, priv_key: Scalar) -> Self {
        Self { ssid, priv_key }
    }

    /// Receive the server's public key
    /// This completes the CPace substep and moves the client on to explicit mutual authentication.
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
    ) -> (AuCPaceClientExpMutAuth<D, K1>, ClientMessage<'static, K1>) {
        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, server_pubkey);
        let (ta, tb) = compute_authenticator_messages::<D>(self.ssid, sk1);
        let next_step = AuCPaceClientExpMutAuth::new(self.ssid, sk1, ta);
        let message = ClientMessage::Authenticator(
            tb.as_slice()
                .try_into()
                .expect("array length invariant broken"),
        );
        (next_step, message)
    }

    /// Allow the user to exit the protocol early in the case of implicit authentication
    /// Note: this should only be used in special circumstances and the
    ///       explicit mutual authentication stage should be used in all other cases
    ///
    /// # Arguments:
    /// - `server_pubkey` - the server's public key
    ///
    /// # Return:
    /// `sk`: the session key reached by the AuCPace protocol
    ///
    pub fn implicit_auth(self, server_pubkey: RistrettoPoint) -> Output<D> {
        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, server_pubkey);
        compute_session_key::<D>(self.ssid, sk1)
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
    fn new(ssid: Output<D>, sk1: Output<D>, server_authenticator: Output<D>) -> Self {
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
    /// - Ok(`sk`): the session key reached by the AuCPace protocol
    /// - Err([`Error::MutualAuthFail`](Error::MutualAuthFail)): an error if the authenticator we computed doesn't match
    ///     the server's authenticator, compared in constant time.
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
fn hash_password<'a, U, P, S, H, const BUFSIZ: usize>(
    username: U,
    password: P,
    salt: S,
    params: H::Params,
    hasher: H,
) -> Result<PasswordHash<'a>>
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
    S: Into<Salt<'a>>,
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
    buf[u + 1..u + p + 1].copy_from_slice(pass);

    let hash = hasher
        .hash_password_customized(&buf[0..u + p + 1], None, None, params, salt)
        .map_err(Error::PasswordHashing);

    hash
}

/// Hash a username and password with the given password hasher
#[cfg(feature = "alloc")]
fn hash_password_alloc<'a, U, P, S, H>(
    username: U,
    password: P,
    salt: S,
    params: H::Params,
    hasher: H,
) -> Result<PasswordHash<'a>>
where
    H: PasswordHasher,
    U: AsRef<[u8]>,
    P: AsRef<[u8]>,
    S: Into<Salt<'a>>,
{
    let user = username.as_ref();
    let pass = password.as_ref();

    // hash "{username}:{password}"
    let mut v = alloc::vec::Vec::with_capacity(user.len() + pass.len() + 1);
    v.extend_from_slice(user);
    v.push(b':');
    v.extend_from_slice(pass);

    hasher
        .hash_password_customized(v.as_slice(), None, None, params, salt)
        .map_err(Error::PasswordHashing)
}

/// An enum representing the different messages the client can send to the server
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ClientMessage<'a, const K1: usize> {
    /// SSID establishment message - the client's nonce: `t`
    Nonce(#[cfg_attr(feature = "serde", serde(with = "serde_arrays"))] [u8; K1]),

    /// Username - the client's username
    Username(&'a [u8]),

    /// StrongUsername - the strong AuCPace username message
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
    Authenticator(#[cfg_attr(feature = "serde", serde(with = "serde_arrays"))] [u8; 64]),

    /// Registration - the username, verifier, salt and parameters needed for registering a user
    /// NOTE: if the UAD field is desired this should be handled separately and sent at the same time
    Registration {
        /// The username of whoever is registering
        username: &'a [u8],

        /// The salt used when computing the verifier
        #[cfg_attr(feature = "serde", serde(with = "serde_saltstring"))]
        salt: SaltString,

        /// The password hasher's parameters used when computing the verifier
        #[cfg_attr(feature = "serde", serde(with = "serde_paramsstring"))]
        params: ParamsString,

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
        #[cfg_attr(feature = "serde", serde(with = "serde_paramsstring"))]
        params: ParamsString,

        /// The verifier computer from the user's password
        verifier: RistrettoPoint,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;
    use rand_core::OsRng;

    #[test]
    #[cfg(all(feature = "alloc", feature = "getrandom", feature = "scrypt"))]
    fn test_hash_password_no_std_and_alloc_agree() {
        use rand_core::RngCore;
        use scrypt::{Params, Scrypt};

        let username = "worf@starship.enterprise";
        let password = "data_x_worf_4ever_<3";
        let mut bytes = [0u8; Salt::RECOMMENDED_LENGTH];
        OsRng.fill_bytes(&mut bytes);
        let salt = SaltString::b64_encode(&bytes).expect("Salt length invariant broken.");
        // These are weak parameters, do not use them
        // they are used here to make the test run faster
        let params = Params::new(1, 8, 1).unwrap();

        let no_std_res = hash_password::<&str, &str, &SaltString, Scrypt, 100>(
            username, password, &salt, params, Scrypt,
        )
        .unwrap();
        let alloc_res = hash_password_alloc(username, password, &salt, params, Scrypt).unwrap();

        assert_eq!(alloc_res, no_std_res);
    }

    #[test]
    #[cfg(all(feature = "getrandom"))]
    fn test_client_doesnt_accept_insecure_ssid() {
        let mut client = Client::new(OsRng);
        let res = client.begin_prestablished_ssid("bad ssid");
        assert!(matches!(res, Err(Error::InsecureSsid)));
    }
}
