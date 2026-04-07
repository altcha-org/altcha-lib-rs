use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{Error, Result};
use crate::types::ChallengeParameters;

/// Derives a key using Argon2id.
///
/// Parameters mapping from `ChallengeParameters`:
/// - `memory_cost`  → m (memory in KiB, required)
/// - `cost`         → t (time cost / passes)
/// - `parallelism`  → p (default 1)
pub fn derive_key(
    parameters: &ChallengeParameters,
    salt: &[u8],
    password: &[u8],
) -> Result<Vec<u8>> {
    let m_cost = parameters.memory_cost.ok_or_else(|| {
        Error::InvalidParameters("Argon2id requires memory_cost".to_string())
    })?;
    let t_cost = parameters.cost;
    let p_cost = parameters.parallelism.unwrap_or(1);
    let key_len = parameters.key_length;

    let params = Params::new(m_cost, t_cost, p_cost, Some(key_len))
        .map_err(|e| Error::Argon2(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = vec![0u8; key_len];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| Error::Argon2(e.to_string()))?;

    Ok(out)
}
