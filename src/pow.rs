use std::time::Instant;

use crate::algorithms::derive_key;
use crate::error::Result;
use crate::helpers::{
    buffer_starts_with, build_password, bytes_to_hex, canonical_json, constant_time_equal_hex,
    elapsed_ms, hex_to_bytes, hmac_sign, random_bytes_16,
};
use crate::types::{
    Challenge, ChallengeParameters, CreateChallengeOptions, HmacAlgorithm, Solution,
    SolveChallengeOptions, VerifySolutionOptions, VerifySolutionResult,
};

/// Creates a new ALTCHA PoW v2 challenge.
///
/// Generates a random nonce and salt. If `options.counter` is set the challenge
/// operates in *deterministic mode*: the key prefix is derived from that counter
/// so the server knows exactly which key prefix to expect.
///
/// The challenge is optionally signed with HMAC when `options.hmac_signature_secret`
/// is provided.
pub fn create_challenge(options: CreateChallengeOptions) -> Result<Challenge> {
    let key_prefix_length = options.key_prefix_length.unwrap_or(options.key_length / 2);

    let nonce_hex = bytes_to_hex(&random_bytes_16());
    let salt_hex = bytes_to_hex(&random_bytes_16());

    let mut parameters = ChallengeParameters {
        algorithm: options.algorithm,
        cost: options.cost,
        data: options.data,
        expires_at: options.expires_at,
        key_length: options.key_length,
        key_prefix: options.key_prefix,
        key_signature: None,
        memory_cost: options.memory_cost,
        nonce: nonce_hex,
        parallelism: options.parallelism,
        salt: salt_hex,
    };

    // Deterministic mode: derive the key and extract the prefix the client must match.
    let derived_key_bytes: Option<Vec<u8>> = if let Some(counter) = options.counter {
        let nonce_bytes = hex_to_bytes(&parameters.nonce)?;
        let salt_bytes = hex_to_bytes(&parameters.salt)?;
        let password = build_password(&nonce_bytes, counter);
        let key = derive_key(&parameters, &salt_bytes, &password)?;
        parameters.key_prefix = bytes_to_hex(&key[..key_prefix_length]);
        Some(key)
    } else {
        None
    };

    if options.hmac_signature_secret.is_none() {
        return Ok(Challenge {
            parameters,
            signature: None,
        });
    }

    sign_challenge(
        &options.hmac_algorithm,
        &mut parameters,
        derived_key_bytes.as_deref(),
        options.hmac_signature_secret.as_deref().unwrap(),
        options.hmac_key_signature_secret.as_deref(),
    )
}

/// Signs challenge parameters and returns a `Challenge` with a signature.
///
/// When `hmac_key_signature_secret` is provided and a `derived_key` is given,
/// the derived key is also signed separately so that verification can skip
/// re-deriving the key (fast-path verification).
pub fn sign_challenge(
    algorithm: &HmacAlgorithm,
    parameters: &mut ChallengeParameters,
    derived_key: Option<&[u8]>,
    hmac_signature_secret: &str,
    hmac_key_signature_secret: Option<&str>,
) -> Result<Challenge> {
    if let (Some(key), Some(key_secret)) = (derived_key, hmac_key_signature_secret) {
        let key_sig = hmac_sign(algorithm, key, key_secret)?;
        parameters.key_signature = Some(bytes_to_hex(&key_sig));
    }

    let json = canonical_json(parameters)?;
    let sig = hmac_sign(algorithm, json.as_bytes(), hmac_signature_secret)?;

    Ok(Challenge {
        parameters: parameters.clone(),
        signature: Some(bytes_to_hex(&sig)),
    })
}

/// Solves a challenge by iterating counter values until the derived key matches
/// the required prefix.
///
/// Returns `None` if the timeout is reached before a solution is found.
pub fn solve_challenge(options: SolveChallengeOptions<'_>) -> Result<Option<Solution>> {
    let params = &options.challenge.parameters;

    let nonce_bytes = hex_to_bytes(&params.nonce)?;
    let salt_bytes = hex_to_bytes(&params.salt)?;

    // Pre-decode the key prefix bytes if the hex string has even length.
    let key_prefix_bytes: Option<Vec<u8>> = if params.key_prefix.len() % 2 == 0 {
        Some(hex_to_bytes(&params.key_prefix)?)
    } else {
        None
    };

    let start = Instant::now();
    let timeout = std::time::Duration::from_millis(options.timeout_ms);
    let mut counter = options.counter_start;

    loop {
        // Check timeout every 10 iterations.
        if counter % 10 == 0 && start.elapsed() > timeout {
            return Ok(None);
        }

        let password = build_password(&nonce_bytes, counter);
        let derived = derive_key(params, &salt_bytes, &password)?;

        let matched = match &key_prefix_bytes {
            Some(prefix) => buffer_starts_with(&derived, prefix),
            None => bytes_to_hex(&derived).starts_with(&params.key_prefix),
        };

        if matched {
            return Ok(Some(Solution {
                counter,
                derived_key: bytes_to_hex(&derived),
                time: Some(elapsed_ms(start)),
            }));
        }

        counter = counter.wrapping_add(options.counter_step);
    }
}

/// Verifies a submitted solution against a challenge.
///
/// Checks (in order):
/// 1. Expiration — if the challenge has an `expires_at` timestamp.
/// 2. Signature presence — the challenge must have a `signature` field.
/// 3. Signature validity — HMAC of the canonical JSON of parameters.
/// 4. Solution validity — either via key signature (fast path) or by re-deriving the key.
pub fn verify_solution(options: VerifySolutionOptions<'_>) -> Result<VerifySolutionResult> {
    let start = Instant::now();
    let challenge = options.challenge;
    let solution = options.solution;
    let params = &challenge.parameters;

    // 1. Expiration check.
    if let Some(expires_at) = params.expires_at {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now_secs > expires_at {
            return Ok(VerifySolutionResult {
                expired: true,
                invalid_signature: None,
                invalid_solution: None,
                time: elapsed_ms(start),
                verified: false,
            });
        }
    }

    // 2. Signature presence check.
    let Some(challenge_sig) = &challenge.signature else {
        return Ok(VerifySolutionResult {
            expired: false,
            invalid_signature: Some(true),
            invalid_solution: None,
            time: elapsed_ms(start),
            verified: false,
        });
    };

    // 3. Signature validity — verify HMAC over canonical JSON of parameters.
    let json = canonical_json(params)?;
    let expected_sig = hmac_sign(
        &options.hmac_algorithm,
        json.as_bytes(),
        &options.hmac_signature_secret,
    )?;
    if !constant_time_equal_hex(challenge_sig, &bytes_to_hex(&expected_sig)) {
        return Ok(VerifySolutionResult {
            expired: false,
            invalid_signature: Some(true),
            invalid_solution: None,
            time: elapsed_ms(start),
            verified: false,
        });
    }

    // 4a. Fast path: verify the submitted derived key against the key signature.
    if let (Some(key_sig), Some(key_secret)) =
        (&params.key_signature, &options.hmac_key_signature_secret)
    {
        let derived_key_bytes = hex_to_bytes(&solution.derived_key)?;
        let expected_key_sig =
            hmac_sign(&options.hmac_algorithm, &derived_key_bytes, key_secret)?;
        let valid = constant_time_equal_hex(key_sig, &bytes_to_hex(&expected_key_sig));
        return Ok(VerifySolutionResult {
            expired: false,
            invalid_signature: Some(false),
            invalid_solution: Some(!valid),
            time: elapsed_ms(start),
            verified: valid,
        });
    }

    // 4b. Full path: re-derive the key from the submitted counter and compare,
    // and require it to satisfy the signed key prefix.
    let nonce_bytes = hex_to_bytes(&params.nonce)?;
    let salt_bytes = hex_to_bytes(&params.salt)?;
    let password = build_password(&nonce_bytes, solution.counter);
    let derived = derive_key(params, &salt_bytes, &password)?;
    let derived_hex = bytes_to_hex(&derived);
    let key_matches = constant_time_equal_hex(&derived_hex, &solution.derived_key);
    let prefix_matches = derived_hex.starts_with(&params.key_prefix);
    let valid = key_matches && prefix_matches;

    Ok(VerifySolutionResult {
        expired: false,
        invalid_signature: Some(false),
        invalid_solution: Some(!valid),
        time: elapsed_ms(start),
        verified: valid,
    })
}
