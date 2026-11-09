use core::fmt;

/// Errors that can occur during the protocol
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Some points such as the Neutral or Identity point are illegal
    IllegalPointError,
    /// Password-based key derivation failed
    PasswordHashing(kdf::Error),
    /// The configured PBKDF output length is not 32 or 64 bytes
    HashSizeInvalid,
    /// Failure during Explicit Mutual Authentication
    MutualAuthFail,
    /// The username:password string would overflow the buffer size allocated for hashing the password
    /// Note: this error can only occur when using the fixed-size buffer APIs
    UsernameOrPasswordTooLong,
    /// The SSID provided is too short to be secure, SSIDs must be at least 16 bytes long
    /// Note: this error can only occur if the SSID establishment phase is bypassed
    InsecureSsid,
    /// This error happens when a long term keypair for a user is stored in a [`PartialAugDatabase`](crate::PartialAugDatabase)
    /// but the user doesn't exist, this operation has no meaning and as such is an error.
    #[cfg(feature = "partial_augmentation")]
    UserNotRegistered,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalPointError => write!(f, "illegal point encountered"),
            Self::PasswordHashing(error) => write!(f, "error while hashing password: {error}"),
            Self::HashSizeInvalid => write!(f, "password hash invalid, should be 32 or 64 bytes"),
            Self::MutualAuthFail => write!(
                f,
                "explicit mutual authentication failed, authenticators didn't match"
            ),
            Self::UsernameOrPasswordTooLong => write!(f, "username or password too long"),
            Self::InsecureSsid => write!(
                f,
                "provided SSID is insecure - SSIDs must be at least 16 bytes long"
            ),
            #[cfg(feature = "partial_augmentation")]
            Self::UserNotRegistered => write!(
                f,
                "user must be registered before a long-term keypair can be stored"
            ),
        }
    }
}

/// Result type
pub type Result<T> = core::result::Result<T, Error>;
