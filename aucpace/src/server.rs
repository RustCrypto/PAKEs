use crate::constants::MIN_SSID_LEN;
use crate::utils::{
    compute_authenticator_messages, compute_first_session_key, compute_session_key, compute_ssid,
    generate_keypair, generate_nonce, generate_server_keypair, H0,
};
use crate::Database;
use crate::{Error, Result};
use core::marker::PhantomData;
use curve25519_dalek::{
    digest::consts::U64,
    digest::{Digest, Output},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use password_hash::{ParamsString, SaltString};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

#[cfg(feature = "partial_augmentation")]
use crate::database::PartialAugDatabase;

#[cfg(feature = "strong_aucpace")]
use crate::database::StrongDatabase;

#[cfg(feature = "serde")]
use crate::utils::{serde_paramsstring, serde_saltstring};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A non-copy wrapper around u64
#[derive(Clone)]
struct ServerSecret(u64);

impl ServerSecret {
    fn new<CSPRNG: CryptoRngCore>(rng: &mut CSPRNG) -> Self {
        Self(rng.next_u64())
    }
}

/// Implementation of the server side of the AuCPace protocol
pub struct AuCPaceServer<D, CSPRNG, const K1: usize>
where
    D: Digest + Default,
    CSPRNG: CryptoRngCore,
{
    /// The CSPRNG used to generate random values where needed
    rng: CSPRNG,

    /// the secret used to obscure when a password lookup failed
    secret: ServerSecret,

    d: PhantomData<D>,
}

impl<D, CSPRNG, const K1: usize> AuCPaceServer<D, CSPRNG, K1>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: CryptoRngCore,
{
    /// Create a new server
    pub fn new(mut rng: CSPRNG) -> Self {
        let secret = ServerSecret::new(&mut rng);
        Self {
            rng,
            secret,
            d: Default::default(),
        }
    }

    /// Create a new server in the SSID agreement phase
    ///
    /// # Return:
    /// ([`next_step`](AuCPaceServerSsidEstablish), [`message`](ServerMessage::Nonce))
    /// - [`next_step`](AuCPaceServerSsidEstablish): the server in the SSID establishment stage
    /// - [`message`](ServerMessage::Nonce): the message to send to the server
    ///
    pub fn begin(
        &mut self,
    ) -> (
        AuCPaceServerSsidEstablish<D, K1>,
        ServerMessage<'static, K1>,
    ) {
        let next_step = AuCPaceServerSsidEstablish::new(self.secret.clone(), &mut self.rng);
        let message = ServerMessage::Nonce(next_step.nonce);
        (next_step, message)
    }

    /// Create a new server in the Augmentation layer phase, provided an SSID
    ///
    /// # Argument:
    /// `ssid`: Some data to be hashed and act as the sub-session ID
    ///
    /// # Return:
    /// - Ok([`next_step`](AuCPaceServerAugLayer)): the server in the SSID establishment stage
    /// - Err([`Error::InsecureSsid`](Error::InsecureSsid)): the SSID provided was not long enough to be secure
    ///
    pub fn begin_prestablished_ssid<S>(&mut self, ssid: S) -> Result<AuCPaceServerAugLayer<D, K1>>
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
        let next_step = AuCPaceServerAugLayer::new(self.secret.clone(), ssid_hash);
        Ok(next_step)
    }

    /// Generate a new long-term keypair
    ///
    /// This is inteded to be used when registering a user when using partial augmentation.
    /// As well as on all password changes.
    ///
    /// # Return:
    /// (`private_key`, `public_key`):
    /// - `private_key`: the private key
    /// - `public_key`: the public key
    ///
    #[cfg(feature = "partial_augmentation")]
    pub fn generate_long_term_keypair(&mut self) -> (Scalar, RistrettoPoint) {
        generate_server_keypair(&mut self.rng)
    }
}

/// Server in the SSID agreement phase
pub struct AuCPaceServerSsidEstablish<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    secret: ServerSecret,
    nonce: [u8; K1],
    _d: PhantomData<D>,
}

impl<D, const K1: usize> AuCPaceServerSsidEstablish<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new<CSPRNG>(secret: ServerSecret, rng: &mut CSPRNG) -> Self
    where
        CSPRNG: CryptoRngCore,
    {
        Self {
            secret,
            nonce: generate_nonce(rng),
            _d: Default::default(),
        }
    }

    /// Consume the client's nonce - `t` and progress to the augmentation layer
    ///
    /// # arguments:
    /// - `client_nonce` - the nonce received from the server
    ///
    /// # return:
    /// [`next_step`](AuCPaceServerAugLayer): the server in the augmentation layer
    ///
    pub fn agree_ssid(self, client_nonce: [u8; K1]) -> AuCPaceServerAugLayer<D, K1> {
        let ssid = compute_ssid::<D, K1>(self.nonce, client_nonce);
        AuCPaceServerAugLayer::new(self.secret, ssid)
    }
}

/// Server in the Augmentation layer phase
pub struct AuCPaceServerAugLayer<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    secret: ServerSecret,
    ssid: Output<D>,
}

impl<D, const K1: usize> AuCPaceServerAugLayer<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(secret: ServerSecret, ssid: Output<D>) -> Self {
        Self { secret, ssid }
    }

    /// Accept the user's username and generate the ClientInfo for the response.
    /// Moves the protocol into the CPace substep phase
    ///
    /// # Arguments:
    /// - `username`: the client's username
    /// - `database`: the password verifier database to retrieve the client's information from
    ///
    /// # Return:
    /// ([`next_step`](AuCPaceServerCPaceSubstep), [`message`](ServerMessage::AugmentationInfo))
    /// - [`next_step`](AuCPaceServerCPaceSubstep): the server in the CPace substep stage
    /// - [`message`](ServerMessage::AugmentationInfo): the message to send to the client
    ///
    pub fn generate_client_info<U, DB, CSPRNG>(
        self,
        username: U,
        database: &DB,
        mut rng: CSPRNG,
    ) -> (
        AuCPaceServerCPaceSubstep<D, CSPRNG, K1>,
        ServerMessage<'static, K1>,
    )
    where
        U: AsRef<[u8]>,
        DB: Database<PasswordVerifier = RistrettoPoint>,
        CSPRNG: CryptoRngCore,
    {
        let (x, x_pub) = generate_server_keypair(&mut rng);

        // generate the prs and client message
        let (prs, message) = self.generate_prs(username.as_ref(), database, &mut rng, x, x_pub);
        let next_step = AuCPaceServerCPaceSubstep::new(self.ssid, prs, rng);

        (next_step, message)
    }

    /// Accept the user's username and generate the ClientInfo for the response.
    /// Moves the protocol into the CPace substep phase
    ///
    /// This method performs the "partial augmentation" variant of the protocol.
    /// This means that instead of generating x and x_pub as ephemeral keys, a long term keypair is
    /// retrieved from the database instead. This comes with decreased security in the case of
    /// server compromise but significantly decreases the amount of computation the server has to
    /// do. The reference paper goes into more detail on the tradeoffs and why you might choose to
    /// use this method.
    ///
    /// # Arguments:
    /// - `username`: the client's username
    /// - `database`: the password verifier database to retrieve the client's information from
    ///    This is a PartialAugDatabase so we can lookup the server's long term keypair.
    ///
    /// # Return:
    /// ([`next_step`](AuCPaceServerCPaceSubstep), [`message`](ServerMessage::AugmentationInfo))
    /// - [`next_step`](AuCPaceServerCPaceSubstep): the server in the CPace substep stage
    /// - [`message`](ServerMessage::AugmentationInfo): the message to send to the client
    ///
    #[cfg(feature = "partial_augmentation")]
    pub fn generate_client_info_partial_aug<U, DB, CSPRNG>(
        self,
        username: U,
        database: &DB,
        mut rng: CSPRNG,
    ) -> (
        AuCPaceServerCPaceSubstep<D, CSPRNG, K1>,
        ServerMessage<'static, K1>,
    )
    where
        U: AsRef<[u8]>,
        DB: Database<PasswordVerifier = RistrettoPoint>
            + PartialAugDatabase<PrivateKey = Scalar, PublicKey = RistrettoPoint>,
        CSPRNG: CryptoRngCore,
    {
        let user = username.as_ref();
        let (prs, message) = if let Some((x, x_pub)) = database.lookup_long_term_keypair(user) {
            // generate the prs and client message
            self.generate_prs(user, database, &mut rng, x, x_pub)
        } else {
            // if the user does not have a keypair stored then we generate a random point on the
            // curve to be the public key, and handle the failed lookup as normal
            let x_pub = RistrettoPoint::random(&mut rng);
            self.lookup_failed(user, x_pub, &mut rng)
        };
        let next_step = AuCPaceServerCPaceSubstep::new(self.ssid, prs, rng);

        (next_step, message)
    }

    /// Accept the user's username, and blinded point U and generate the ClientInfo for the response.
    /// Moves the protocol into the CPace substep phase
    ///
    /// This method performs the Strong variant of the protocol.
    /// This means that the information is blinded in transit so that it is impossible to do any
    /// precomputation to attack the user's password before the actual verifier database is compromised.
    ///
    /// # Arguments:
    /// - `username`: the client's username
    /// - `blinded`: the client's blinded point `U`
    /// - `database`: the password verifier database to retrieve the client's information from
    ///    This is a PartialAugDatabase so we can lookup the server's long term keypair.
    ///
    /// # Return:
    /// ([`next_step`](AuCPaceServerCPaceSubstep), [`message`](ServerMessage::AugmentationInfo))
    /// - [`next_step`](AuCPaceServerCPaceSubstep): the server in the CPace substep stage
    /// - [`message`](ServerMessage::AugmentationInfo): the message to send to the client
    ///
    #[cfg(feature = "strong_aucpace")]
    pub fn generate_client_info_strong<U, DB, CSPRNG>(
        self,
        username: U,
        blinded: RistrettoPoint,
        database: &DB,
        mut rng: CSPRNG,
    ) -> (
        AuCPaceServerCPaceSubstep<D, CSPRNG, K1>,
        ServerMessage<'static, K1>,
    )
    where
        U: AsRef<[u8]>,
        DB: StrongDatabase<PasswordVerifier = RistrettoPoint, Exponent = Scalar>,
        CSPRNG: CryptoRngCore,
    {
        let (x, x_pub) = generate_server_keypair(&mut rng);

        // generate the prs and client message
        let (prs, message) =
            self.generate_prs_strong(username.as_ref(), blinded, database, &mut rng, x, x_pub);
        let next_step = AuCPaceServerCPaceSubstep::new(self.ssid, prs, rng);

        (next_step, message)
    }

    /// Accept the user's username, and blinded point U and generate the ClientInfo for the response.
    /// Moves the protocol into the CPace substep phase
    ///
    /// This method performs the Strong + Partially augmented variant of the protocol.
    /// This means that the information is blinded in transit so that it is impossible to do any
    /// precomputation to attack the user's password before the actual verifier database is compromised.
    /// And that the server looks up the user's long term keypair in the database instead of generating it.
    ///
    /// # Arguments:
    /// - `username`: the client's username
    /// - `blinded`: the client's blinded point `U`
    /// - `database`: the password verifier database to retrieve the client's information from
    ///    This is a PartialAugDatabase so we can lookup the server's long term keypair.
    ///
    /// # Return:
    /// ([`next_step`](AuCPaceServerCPaceSubstep), [`message`](ServerMessage::AugmentationInfo))
    /// - [`next_step`](AuCPaceServerCPaceSubstep): the server in the CPace substep stage
    /// - [`message`](ServerMessage::AugmentationInfo): the message to send to the client
    ///
    #[cfg(all(feature = "strong_aucpace", feature = "partial_augmentation"))]
    pub fn generate_client_info_partial_strong<U, DB, CSPRNG>(
        self,
        username: U,
        blinded: RistrettoPoint,
        database: &DB,
        mut rng: CSPRNG,
    ) -> (
        AuCPaceServerCPaceSubstep<D, CSPRNG, K1>,
        ServerMessage<'static, K1>,
    )
    where
        U: AsRef<[u8]>,
        DB: StrongDatabase<PasswordVerifier = RistrettoPoint, Exponent = Scalar>
            + PartialAugDatabase<PrivateKey = Scalar, PublicKey = RistrettoPoint>,
        CSPRNG: CryptoRngCore,
    {
        let user = username.as_ref();
        let (prs, message) = if let Some((x, x_pub)) = database.lookup_long_term_keypair(user) {
            // generate the prs and client message
            self.generate_prs_strong(user, blinded, database, &mut rng, x, x_pub)
        } else {
            // if the user does not have a keypair stored then we generate a random point on the
            // curve to be the public key, and handle the failed lookup as normal
            let x_pub = RistrettoPoint::random(&mut rng);
            self.lookup_failed_strong(user, blinded, x_pub, &mut rng)
        };
        let next_step = AuCPaceServerCPaceSubstep::new(self.ssid, prs, rng);

        (next_step, message)
    }

    /// Generate the Password Related String (PRS) and the message to be sent to the user.
    fn generate_prs<DB, CSPRNG>(
        &self,
        username: &[u8],
        database: &DB,
        rng: &mut CSPRNG,
        x: Scalar,
        x_pub: RistrettoPoint,
    ) -> ([u8; 32], ServerMessage<'static, K1>)
    where
        DB: Database<PasswordVerifier = RistrettoPoint>,
        CSPRNG: CryptoRngCore,
    {
        if let Some((w, salt, sigma)) = database.lookup_verifier(username.as_ref()) {
            let cofactor = Scalar::ONE;
            let prs = (w * x * cofactor).compress().to_bytes();
            let message = ServerMessage::AugmentationInfo {
                // this will have to be provided by the trait in future
                group: "ristretto255",
                x_pub,
                salt,
                pbkdf_params: sigma,
            };
            (prs, message)
        } else {
            // handle the failure case
            self.lookup_failed(username, x_pub, rng)
        }
    }

    /// Generate the Password Related String (PRS) and the message to be sent to the user.
    /// This variant uses a strong database
    #[cfg(feature = "strong_aucpace")]
    fn generate_prs_strong<DB, CSPRNG>(
        &self,
        username: &[u8],
        blinded: RistrettoPoint,
        database: &DB,
        rng: &mut CSPRNG,
        x: Scalar,
        x_pub: RistrettoPoint,
    ) -> ([u8; 32], ServerMessage<'static, K1>)
    where
        DB: StrongDatabase<PasswordVerifier = RistrettoPoint, Exponent = Scalar>,
        CSPRNG: CryptoRngCore,
    {
        if let Some((w, q, sigma)) = database.lookup_verifier_strong(username.as_ref()) {
            let cofactor = Scalar::ONE;
            let prs = (w * (x * cofactor)).compress().to_bytes();
            let uq = blinded * (q * cofactor);
            let message = ServerMessage::StrongAugmentationInfo {
                // this will have to be provided by the trait in future
                group: "ristretto255",
                x_pub,
                blinded_salt: uq,
                pbkdf_params: sigma,
            };
            (prs, message)
        } else {
            // handle the failure case
            self.lookup_failed_strong(username, blinded, x_pub, rng)
        }
    }

    /// Generate the message for if the lookup failed
    fn lookup_failed<CSPRNG>(
        &self,
        username: &[u8],
        x_pub: RistrettoPoint,
        rng: &mut CSPRNG,
    ) -> ([u8; 32], ServerMessage<'static, K1>)
    where
        CSPRNG: CryptoRngCore,
    {
        let prs = {
            let mut tmp = [0u8; 32];
            rng.fill_bytes(&mut tmp);
            tmp
        };

        // generate the salt from the hash of the server secret and the user's name
        let mut hasher: D = Default::default();
        hasher.update(self.secret.0.to_le_bytes());
        hasher.update(username);
        let hash = hasher.finalize();
        let hash_bytes: &[u8] = hash.as_ref();

        // It is okay to expect here because SaltString has a buffer of 64 bytes by requirement
        // from the PHC spec. 48 bytes of data when encoded as base64 transform to 64 bytes.
        // This gives us the most entropy possible from the hash in the SaltString.
        let salt = SaltString::b64_encode(&hash_bytes[..48])
            .expect("SaltString maximum length invariant broken");

        let message = ServerMessage::AugmentationInfo {
            group: "ristretto255",
            x_pub,
            salt,
            pbkdf_params: Default::default(),
        };

        (prs, message)
    }

    /// Generate the message for if the lookup failed
    #[cfg(feature = "strong_aucpace")]
    fn lookup_failed_strong<CSPRNG>(
        &self,
        username: &[u8],
        blinded: RistrettoPoint,
        x_pub: RistrettoPoint,
        rng: &mut CSPRNG,
    ) -> ([u8; 32], ServerMessage<'static, K1>)
    where
        CSPRNG: CryptoRngCore,
    {
        let prs = {
            let mut tmp = [0u8; 32];
            rng.fill_bytes(&mut tmp);
            tmp
        };

        // generate q from the hash of the username and the server secret
        let mut hasher: D = Default::default();
        hasher.update(self.secret.0.to_le_bytes());
        hasher.update(username);
        let cofactor = Scalar::ONE;
        let q = Scalar::from_hash(hasher);
        let fake_blinded_salt = blinded * (q * cofactor);

        let message = ServerMessage::StrongAugmentationInfo {
            group: "ristretto255",
            x_pub,
            blinded_salt: fake_blinded_salt,
            pbkdf_params: Default::default(),
        };

        (prs, message)
    }
}

/// Server in the CPace substep phase
pub struct AuCPaceServerCPaceSubstep<D, CSPRNG, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: CryptoRngCore,
{
    ssid: Output<D>,
    prs: [u8; 32],
    rng: CSPRNG,
}

impl<D, CSPRNG, const K1: usize> AuCPaceServerCPaceSubstep<D, CSPRNG, K1>
where
    D: Digest<OutputSize = U64> + Default,
    CSPRNG: CryptoRngCore,
{
    fn new(ssid: Output<D>, prs: [u8; 32], rng: CSPRNG) -> Self {
        Self { ssid, prs, rng }
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
    /// ([`next_step`](AuCPaceServerRecvClientKey), [`messsage`](ServerMessage::PublicKey))
    /// - [`next_step`](AuCPaceServerRecvClientKey): the server waiting for the client's public key
    /// - [`messsage`](ServerMessage::PublicKey): the message to send to the client
    ///
    pub fn generate_public_key<CI: AsRef<[u8]>>(
        mut self,
        channel_identifier: CI,
    ) -> (
        AuCPaceServerRecvClientKey<D, K1>,
        ServerMessage<'static, K1>,
    ) {
        let (priv_key, pub_key) = generate_keypair::<D, CSPRNG, CI>(
            &mut self.rng,
            self.ssid,
            self.prs,
            channel_identifier,
        );

        let next_step = AuCPaceServerRecvClientKey::new(self.ssid, priv_key);
        let message = ServerMessage::PublicKey(pub_key);

        (next_step, message)
    }
}

/// Server in the CPace substep phase
pub struct AuCPaceServerRecvClientKey<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    priv_key: Scalar,
}

impl<D, const K1: usize> AuCPaceServerRecvClientKey<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>, priv_key: Scalar) -> Self {
        Self { ssid, priv_key }
    }

    /// Receive the client's public key
    /// This completes the CPace substep and moves the client on to explicit mutual authentication.
    ///
    /// # Arguments:
    /// - `client_pubkey` - the client's public key
    ///
    /// # Return:
    /// [`next_step`](AuCPaceServerExpMutAuth): the server in the Explicit Mutual Authentication phase
    ///
    pub fn receive_client_pubkey(
        self,
        client_pubkey: RistrettoPoint,
    ) -> AuCPaceServerExpMutAuth<D, K1> {
        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, client_pubkey);
        AuCPaceServerExpMutAuth::new(self.ssid, sk1)
    }

    /// Allow exiting the protocol early in the case of implicit authentication
    /// Note: this should only be used in special circumstances and the
    ///       explicit mutual authentication stage should be used in all other cases
    ///
    /// # Arguments:
    /// - `client_pubkey` - the client's public key
    ///
    /// # Return:
    /// `sk`: the session key reached by the AuCPace protocol
    ///
    pub fn implicit_auth(self, client_pubkey: RistrettoPoint) -> Output<D> {
        let sk1 = compute_first_session_key::<D>(self.ssid, self.priv_key, client_pubkey);
        compute_session_key::<D>(self.ssid, sk1)
    }
}

/// Server in the Explicity Mutual Authenticaton phase
pub struct AuCPaceServerExpMutAuth<D, const K1: usize>
where
    D: Digest<OutputSize = U64> + Default,
{
    ssid: Output<D>,
    sk1: Output<D>,
}

impl<D, const K1: usize> AuCPaceServerExpMutAuth<D, K1>
where
    D: Digest<OutputSize = U64> + Default,
{
    fn new(ssid: Output<D>, sk1: Output<D>) -> Self {
        Self { ssid, sk1 }
    }

    /// Receive the server's authenticator.
    /// This completes the protocol and returns the derived key.
    ///
    /// # Arguments:
    /// - `server_authenticator` - the server's authenticator
    ///
    /// # Return:
    /// either:
    /// - Ok((`sk`, `message`)):
    ///     - `sk` - the session key reached by the AuCPace protocol
    ///     - [`message`](ServerMessage::Authenticator) - the message to send to the client
    /// - Err([`Error::MutualAuthFail`](Error::MutualAuthFail)): an error if the authenticator we computed doesn't match
    ///     the client's authenticator, compared in constant time.
    ///
    pub fn receive_client_authenticator(
        self,
        client_authenticator: [u8; 64],
    ) -> Result<(Output<D>, ServerMessage<'static, K1>)> {
        let (ta, tb) = compute_authenticator_messages::<D>(self.ssid, self.sk1);
        if tb.ct_eq(&client_authenticator).into() {
            let sk = compute_session_key::<D>(self.ssid, self.sk1);
            let message = ServerMessage::Authenticator(
                ta.as_slice()
                    .try_into()
                    .expect("array length invariant broken"),
            );
            Ok((sk, message))
        } else {
            Err(Error::MutualAuthFail)
        }
    }
}

/// An enum representing the different messages the server can send to the client
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ServerMessage<'a, const K1: usize> {
    /// SSID establishment message - the server's nonce: `s`
    Nonce(#[cfg_attr(feature = "serde", serde(with = "serde_arrays"))] [u8; K1]),

    /// Information required for the AuCPace Augmentation layer sub-step
    AugmentationInfo {
        /// J from the protocol definition
        group: &'a str,

        /// X from the protocol definition
        x_pub: RistrettoPoint,

        /// the salt used with the PBKDF
        #[cfg_attr(feature = "serde", serde(with = "serde_saltstring"))]
        salt: SaltString,

        /// the parameters for the PBKDF used - sigma from the protocol definition
        #[cfg_attr(feature = "serde", serde(with = "serde_paramsstring"))]
        pbkdf_params: ParamsString,
    },

    /// Information required for the AuCPace Augmentation layer sub-step
    #[cfg(feature = "strong_aucpace")]
    StrongAugmentationInfo {
        /// J from the protocol definition
        group: &'a str,

        /// X from the protocol definition
        x_pub: RistrettoPoint,

        /// the blinded salt used with the PBKDF
        blinded_salt: RistrettoPoint,

        /// the parameters for the PBKDF used - sigma from the protocol definition
        #[cfg_attr(feature = "serde", serde(with = "serde_paramsstring"))]
        pbkdf_params: ParamsString,
    },

    /// CPace substep message - the server's public key: `Ya`
    PublicKey(RistrettoPoint),

    /// Explicit Mutual Authentication - the server's authenticator: `Ta`
    Authenticator(#[cfg_attr(feature = "serde", serde(with = "serde_arrays"))] [u8; 64]),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Server;
    use rand_core::OsRng;

    #[test]
    fn test_server_doesnt_accept_insecure_ssid() {
        let mut server = Server::new(OsRng);
        let res = server.begin_prestablished_ssid("bad ssid");
        assert!(matches!(res, Err(Error::InsecureSsid)));
    }
}
