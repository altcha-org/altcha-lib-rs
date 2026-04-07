use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha384, Sha512};

use crate::error::Result;
use crate::types::ChallengeParameters;

pub fn derive_key(
    parameters: &ChallengeParameters,
    salt: &[u8],
    password: &[u8],
) -> Result<Vec<u8>> {
    let key_len = parameters.key_length;
    let rounds = parameters.cost;
    let mut out = vec![0u8; key_len];

    match parameters.algorithm.to_uppercase().as_str() {
        "PBKDF2/SHA-384" => pbkdf2_hmac::<Sha384>(password, salt, rounds, &mut out),
        "PBKDF2/SHA-512" => pbkdf2_hmac::<Sha512>(password, salt, rounds, &mut out),
        _ => pbkdf2_hmac::<Sha256>(password, salt, rounds, &mut out),
    }

    Ok(out)
}
