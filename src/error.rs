use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("invalid hex string: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid HMAC key")]
    InvalidHmacKey,

    #[cfg(feature = "argon2")]
    #[error("argon2 error: {0}")]
    Argon2(String),

    #[cfg(feature = "scrypt")]
    #[error("scrypt error: {0}")]
    Scrypt(String),

    #[error("invalid parameters: {0}")]
    InvalidParameters(String),
}

impl From<hmac::digest::InvalidLength> for Error {
    fn from(_: hmac::digest::InvalidLength) -> Self {
        Error::InvalidHmacKey
    }
}

#[cfg(feature = "argon2")]
impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Argon2(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
