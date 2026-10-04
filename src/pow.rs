use std::time::{Duration, Instant};

use crate::algorithms::derive_key;
use crate::error::{Error, Result};
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
/// so the server knows exactly which key prefix to expect. The prefix is capped at half
/// the derived key length.
///
/// The challenge is optionally signed with HMAC when `options.hmac_signature_secret`
/// is provided.
///
/// `options.key_prefix` is normalized to lowercase. Returns [`Error::InvalidParameters`]
/// if it contains non-hex characters (outside deterministic mode, where it is replaced by
/// the derived prefix).
pub fn create_challenge(options: CreateChallengeOptions) -> Result<Challenge> {
    let key_prefix_length = options.key_prefix_length.unwrap_or(options.key_length / 2);

    // A malformed prefix is a server misconfiguration: fail here instead of making
    // clients' solve (and later verify) error out.
    if options.counter.is_none() && !options.key_prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidParameters(format!(
            "key_prefix must be a hex string, got {:?}",
            options.key_prefix
        )));
    }

    let nonce_hex = bytes_to_hex(&random_bytes_16());
    let salt_hex = bytes_to_hex(&random_bytes_16());

    let mut parameters = ChallengeParameters {
        algorithm: options.algorithm,
        cost: options.cost,
        data: options.data,
        expires_at: options.expires_at,
        key_length: options.key_length,
        key_prefix: options.key_prefix.to_ascii_lowercase(),
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
        // Cap at half the key so the prefix never covers the whole key (and never
        // indexes past it). Uses the actual key length: SHA output may be shorter than
        // `key_length`.
        let prefix_len = key_prefix_length.min(key.len() / 2);
        parameters.key_prefix = bytes_to_hex(&key[..prefix_len]);
        Some(key)
    } else {
        None
    };

    // An empty secret counts as absent, as in JS (`!hmacSignatureSecret`).
    let Some(hmac_signature_secret) = non_empty(options.hmac_signature_secret.as_deref()) else {
        return Ok(Challenge {
            parameters,
            signature: None,
        });
    };

    sign_challenge(
        &options.hmac_algorithm,
        &mut parameters,
        derived_key_bytes.as_deref(),
        hmac_signature_secret,
        options.hmac_key_signature_secret.as_deref(),
    )
}

/// Signs challenge parameters and returns a `Challenge` with a signature.
///
/// When a non-empty `hmac_key_signature_secret` is provided and a `derived_key` is given,
/// the derived key is also signed separately so that verification can skip
/// re-deriving the key (fast-path verification).
pub fn sign_challenge(
    algorithm: &HmacAlgorithm,
    parameters: &mut ChallengeParameters,
    derived_key: Option<&[u8]>,
    hmac_signature_secret: &str,
    hmac_key_signature_secret: Option<&str>,
) -> Result<Challenge> {
    if let (Some(key), Some(key_secret)) = (derived_key, non_empty(hmac_key_signature_secret)) {
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
/// Returns `None` if the timeout is reached before a solution is found. A `timeout_ms`
/// of `0` disables the timeout.
pub fn solve_challenge(options: SolveChallengeOptions<'_>) -> Result<Option<Solution>> {
    let params = &options.challenge.parameters;

    let nonce_bytes = hex_to_bytes(&params.nonce)?;
    let salt_bytes = hex_to_bytes(&params.salt)?;

    let key_prefix = KeyPrefix::parse(&params.key_prefix)?;

    let start = Instant::now();
    // `0` disables the timeout, as in the JS reference.
    let timeout = (options.timeout_ms != 0).then(|| Duration::from_millis(options.timeout_ms));
    let mut counter = options.counter_start;
    let mut iterations: u64 = 0;

    loop {
        // Check timeout every 10 iterations. Counted independently of the counter so
        // every (counter_start, counter_step) sequence can time out.
        if iterations % 10 == 0 && timeout.is_some_and(|timeout| start.elapsed() > timeout) {
            return Ok(None);
        }

        let password = build_password(&nonce_bytes, counter);
        let derived = derive_key(params, &salt_bytes, &password)?;

        let matched = key_prefix.matches(&derived);

        if matched {
            return Ok(Some(Solution {
                counter,
                derived_key: bytes_to_hex(&derived),
                time: Some(elapsed_ms(start)),
            }));
        }

        counter = counter.wrapping_add(options.counter_step);
        iterations += 1;
    }
}

/// Key prefix matcher. The prefix is case-insensitive: an even-length prefix is
/// hex-decoded and compared as bytes, an odd-length prefix is compared as a string
/// against the hex of the derived key, ignoring ASCII case.
enum KeyPrefix<'a> {
    Bytes(Vec<u8>),
    Hex(&'a str),
}

impl<'a> KeyPrefix<'a> {
    fn parse(prefix: &'a str) -> Result<Self> {
        if prefix.len() % 2 == 0 {
            Ok(Self::Bytes(hex_to_bytes(prefix)?))
        } else {
            Ok(Self::Hex(prefix))
        }
    }

    fn matches(&self, derived: &[u8]) -> bool {
        match self {
            Self::Bytes(prefix) => buffer_starts_with(derived, prefix),
            Self::Hex(prefix) => {
                let hex = bytes_to_hex(derived);
                hex.len() >= prefix.len()
                    && hex.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
            }
        }
    }
}

/// Verifies a submitted solution against a challenge.
///
/// Checks (in order):
/// 1. Expiration — if the challenge has a non-zero `expires_at` timestamp.
/// 2. Signature presence — the challenge must have a `signature` field.
/// 3. Signature validity — HMAC of the canonical JSON of parameters.
/// 4. Solution validity — either via key signature (fast path) or by re-deriving the key.
pub fn verify_solution(options: VerifySolutionOptions<'_>) -> Result<VerifySolutionResult> {
    let start = Instant::now();
    let challenge = options.challenge;
    let solution = options.solution;
    let params = &challenge.parameters;

    // 1. Expiration check. Mirrors JS `expiresAt && expiresAt < Date.now() / 1000`:
    // `0` means no expiry, negative timestamps are always in the past, and the
    // challenge is expired as soon as `now` passes `expires_at` (sub-second precision).
    if let Some(expires_at) = params.expires_at.filter(|&t| t != 0) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let expired = u64::try_from(expires_at)
            .map_or(true, |secs| now > std::time::Duration::from_secs(secs));
        if expired {
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
    // Empty values count as absent, as in JS (`keySignature && hmacKeySignatureSecret`).
    if let (Some(key_sig), Some(key_secret)) = (
        non_empty(params.key_signature.as_deref()),
        non_empty(options.hmac_key_signature_secret.as_deref()),
    ) {
        // The derived key is client-controlled: malformed hex is an invalid solution,
        // not an error.
        let valid = match hex_to_bytes(&solution.derived_key) {
            Ok(derived_key_bytes) => {
                let expected_key_sig =
                    hmac_sign(&options.hmac_algorithm, &derived_key_bytes, key_secret)?;
                constant_time_equal_hex(key_sig, &bytes_to_hex(&expected_key_sig))
            }
            Err(_) => false,
        };
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
    let prefix_matches = KeyPrefix::parse(&params.key_prefix)?.matches(&derived);
    let valid = key_matches && prefix_matches;

    Ok(VerifySolutionResult {
        expired: false,
        invalid_signature: Some(false),
        invalid_solution: Some(!valid),
        time: elapsed_ms(start),
        verified: valid,
    })
}

/// Treats an empty string like `None`, matching JS truthiness checks on optional strings.
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|s| !s.is_empty())
}
