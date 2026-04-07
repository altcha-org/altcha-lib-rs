#[cfg(feature = "argon2")]
mod argon2id;
mod pbkdf2;
#[cfg(feature = "scrypt")]
mod scrypt;
mod sha;

use crate::error::Result;
use crate::types::ChallengeParameters;

/// Derives a key from the given parameters, salt, and password.
///
/// Dispatches to the correct KDF based on `parameters.algorithm`.
///
/// Supported algorithms:
/// - `"PBKDF2/SHA-256"`, `"PBKDF2/SHA-384"`, `"PBKDF2/SHA-512"` — PBKDF2
/// - `"SHA-256"`, `"SHA-384"`, `"SHA-512"` — iterative SHA hashing
/// - `"SCRYPT"` — scrypt
/// - `"ARGON2ID"` — Argon2id
pub fn derive_key(
    parameters: &ChallengeParameters,
    salt: &[u8],
    password: &[u8],
) -> Result<Vec<u8>> {
    match parameters.algorithm.to_uppercase().as_str() {
        "PBKDF2/SHA-256" | "PBKDF2/SHA-384" | "PBKDF2/SHA-512" => {
            pbkdf2::derive_key(parameters, salt, password)
        }
        "SHA-256" | "SHA-384" | "SHA-512" => sha::derive_key(parameters, salt, password),
        #[cfg(feature = "scrypt")]
        "SCRYPT" => scrypt::derive_key(parameters, salt, password),
        #[cfg(feature = "argon2")]
        "ARGON2ID" => argon2id::derive_key(parameters, salt, password),
        other => Err(crate::error::Error::UnsupportedAlgorithm(other.to_string())),
    }
}
