#[cfg(feature = "partial_augmentation")]
use crate::Result;
use password_hash::{ParamsString, SaltString};

/// trait for AuCPace to use to abstract over the storage and retrieval of verifiers
pub trait Database {
    /// The type of password verifier stored in the database
    type PasswordVerifier;

    /// perform `LookupW`, returning the password verifier `W`, if it exists.
    ///
    /// # Arguments:
    /// `username`: the user the lookup the verifier for
    ///
    /// # Return:
    /// `(password verifier, salt, sigma)`
    /// where `password verifier` is the verifier stored for the given user
    /// `salt` is the salt used when hashing the password
    /// `sigma` is the parameters used by the the PBKDF when hashing the user's password
    fn lookup_verifier(
        &self,
        username: &[u8],
    ) -> Option<(Self::PasswordVerifier, SaltString, ParamsString)>;

    /// store a username, salt, verifier and hash parameters to the database.
    /// This function should allow for overwriting users credentials if they exist.
    /// This is required for password changes and should only be performed once the user has
    /// negotiated a full session key.
    ///
    /// # Arguments:
    /// - `username`: The name of the user who is storing a verifier
    /// - `salt`: The salt used when creating the verifier
    /// - `uad`: Optional - User Attached Data - "represents application data associated with
    ///          this specific user account, e.g. specifying the granted authorization level
    ///          on the server."
    /// - `verifier`: The password verifier for the given user
    /// - `params`: The parameters used when hashing the password into the verifier -
    ///             It is called sigma in the protocol defionition
    fn store_verifier(
        &mut self,
        username: &[u8],
        salt: SaltString,
        uad: Option<&[u8]>,
        verifier: Self::PasswordVerifier,
        params: ParamsString,
    );
}

/// trait for AuCPace to use to abstract over the storage and retrieval of long-term keypairs
#[cfg(feature = "partial_augmentation")]
pub trait PartialAugDatabase {
    /// The private key type
    type PrivateKey;

    /// The public key type
    type PublicKey;

    /// retrieve a long-term key pair from the database
    ///
    /// # Arguments:
    /// `username`: the user the lookup the keypair for
    ///
    /// # Return:
    /// - Some((`public_key`, `private_key`)): if the user has a long term keypair associated with them
    ///   - `private_key`: corresponds to x from the protocol definition
    ///   - `public_key`: corresponds to x_pub from the protocol definition
    /// - None: if the user has no associated keypair
    ///
    fn lookup_long_term_keypair(
        &self,
        username: &[u8],
    ) -> Option<(Self::PrivateKey, Self::PublicKey)>;

    /// store a long-term key pair for `username`
    ///
    /// This can be generated with [`AuCPaceServer::generate_long_term_keypair`](crate::AuCPaceServer::generate_long_term_keypair)
    ///
    /// # Arguments:
    /// - `username`: the user the store the keypair for
    /// - `priv_key`: the private key to store
    /// - `pub_key`: the public key to store
    ///
    /// # Return:
    /// - Ok(()): success - the keypair was stored correctly
    /// - Err([`Error::UserNotRegistered`](crate::Error::UserNotRegistered)): failure -
    ///    `username` is not registered and thus we cannot store a keypair for them
    ///
    fn store_long_term_keypair(
        &mut self,
        username: &[u8],
        priv_key: Self::PrivateKey,
        pub_key: Self::PublicKey,
    ) -> Result<()>;
}

/// trait for AuCPace to use to abstract over the storage and retrieval of verifiers and secret exponents
#[cfg(feature = "strong_aucpace")]
pub trait StrongDatabase {
    /// The type of password verifier stored in the database
    type PasswordVerifier;

    /// The type of the secret exponent `q` stored in the database
    type Exponent;

    /// perform `LookupW`, returning the password verifier `W`, and secret exponent `q` if they exist
    ///
    /// # Arguments:
    /// `username`: the user to lookup the verifier for
    ///
    /// # Return:
    /// `(password verifier, secret exponent, params)`:
    /// - `password verifier`: the verifier stored for the given user
    /// - `secret exponent`: the value of `q` stored for the given user
    /// - `params`: the parameters used by the the PBKDF when hashing the user's password
    fn lookup_verifier_strong(
        &self,
        username: &[u8],
    ) -> Option<(Self::PasswordVerifier, Self::Exponent, ParamsString)>;

    /// store a username, secret exponent, verifier and hash parameters to the database.
    /// This function should allow for overwriting users credentials if they exist.
    /// This is required for password changes and should only be done once the user has negotiated
    /// a full session key.
    ///
    /// # Arguments:
    /// - `username`: The name of the user who is storing a verifier
    /// - `uad`: Optional - User Attached Data - "represents application data associated with
    ///          this specific user account, e.g. specifying the granted authorization level
    ///          on the server."
    /// - `verifier`: The password verifier for the given user
    /// - `secret exponent`: the value of `q` stored for the given user
    /// - `params`: The parameters used when hashing the password into the verifier -
    ///             It is called sigma in the protocol definition
    fn store_verifier_strong(
        &mut self,
        username: &[u8],
        uad: Option<&[u8]>,
        verifier: Self::PasswordVerifier,
        secret_exponent: Self::Exponent,
        params: ParamsString,
    );
}
