use crate::error::{Error, Result};
use crate::types::ChallengeParameters;

/// Derives a key using scrypt.
///
/// Parameters mapping from `ChallengeParameters`:
/// - `cost`        → N (CPU cost, must be a power of 2)
/// - `memory_cost` → r (block size, default 8)
/// - `parallelism` → p (default 1)
pub fn derive_key(
    parameters: &ChallengeParameters,
    salt: &[u8],
    password: &[u8],
) -> Result<Vec<u8>> {
    let n = parameters.cost;
    let r = parameters.memory_cost.unwrap_or(8);
    let p = parameters.parallelism.unwrap_or(1);
    let key_len = parameters.key_length;

    let log_n = n
        .checked_ilog2()
        .filter(|_| n.is_power_of_two())
        .ok_or_else(|| {
            Error::InvalidParameters(format!(
                "scrypt cost (N) must be a power of 2, got {}",
                n
            ))
        })? as u8;

    let params = scrypt::Params::new(log_n, r, p, key_len)
        .map_err(|e| Error::Scrypt(e.to_string()))?;

    let mut out = vec![0u8; key_len];
    scrypt::scrypt(password, salt, &params, &mut out)
        .map_err(|e| Error::Scrypt(e.to_string()))?;

    Ok(out)
}
