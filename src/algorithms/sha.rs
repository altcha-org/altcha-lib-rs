use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::Result;
use crate::types::ChallengeParameters;

/// Iterative SHA hashing: start with `salt || password`, then hash the result `cost` times.
pub fn derive_key(
    parameters: &ChallengeParameters,
    salt: &[u8],
    password: &[u8],
) -> Result<Vec<u8>> {
    let key_len = parameters.key_length;
    let iterations = parameters.cost.max(1) as usize;

    let initial: Vec<u8> = salt.iter().chain(password.iter()).copied().collect();

    let derived = match parameters.algorithm.to_uppercase().as_str() {
        "SHA-384" => hash_iterations::<Sha384>(&initial, iterations),
        "SHA-512" => hash_iterations::<Sha512>(&initial, iterations),
        _ => hash_iterations::<Sha256>(&initial, iterations),
    };

    Ok(derived[..key_len.min(derived.len())].to_vec())
}

fn hash_iterations<D: Digest>(initial: &[u8], iterations: usize) -> Vec<u8> {
    let mut data: Vec<u8> = initial.to_vec();
    for _ in 0..iterations {
        let mut hasher = D::new();
        hasher.update(&data);
        data = hasher.finalize().to_vec();
    }
    data
}
