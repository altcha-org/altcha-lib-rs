use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

/// HMAC digest algorithm used for signing challenges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HmacAlgorithm {
    #[serde(rename = "SHA-256")]
    #[default]
    Sha256,
    #[serde(rename = "SHA-384")]
    Sha384,
    #[serde(rename = "SHA-512")]
    Sha512,
}

/// Challenge parameters embedded in a challenge.
///
/// Keys are serialized in alphabetical order for deterministic HMAC signing.
/// Optional `None` fields are omitted from the JSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeParameters {
    pub algorithm: String,
    pub cost: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(rename = "keyLength")]
    pub key_length: usize,
    #[serde(rename = "keyPrefix")]
    pub key_prefix: String,
    #[serde(rename = "keySignature", skip_serializing_if = "Option::is_none")]
    pub key_signature: Option<String>,
    #[serde(rename = "memoryCost", skip_serializing_if = "Option::is_none")]
    pub memory_cost: Option<u32>,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    pub salt: String,
}

/// A challenge issued to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub parameters: ChallengeParameters,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A solution returned by the client after solving a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solution {
    pub counter: u32,
    #[serde(rename = "derivedKey")]
    pub derived_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<f64>,
}

/// Combined payload sent from the client to the server for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub challenge: Challenge,
    pub solution: Solution,
}

/// Result of verifying a challenge solution.
#[derive(Debug, Clone)]
pub struct VerifySolutionResult {
    /// Whether the challenge has expired.
    pub expired: bool,
    /// Whether the challenge signature is invalid or missing.
    /// `None` when expiration check failed before reaching this step.
    pub invalid_signature: Option<bool>,
    /// Whether the solution (derived key) is invalid.
    /// `None` when signature check failed before reaching this step.
    pub invalid_solution: Option<bool>,
    /// Time taken to perform verification in milliseconds.
    pub time: f64,
    /// Whether the solution is valid overall.
    pub verified: bool,
}

/// Payload sent from ALTCHA Sentinel to be verified server-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSignaturePayload {
    /// Hash + HMAC algorithm (e.g. `"SHA-256"`).
    pub algorithm: String,
    #[serde(rename = "apiKey", skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Hex-encoded HMAC signature of `HASH(verificationData)`.
    pub signature: String,
    /// URL-encoded query string of verification data from ALTCHA Sentinel.
    #[serde(rename = "verificationData")]
    pub verification_data: String,
    /// Whether ALTCHA Sentinel considers the submission verified.
    pub verified: bool,
}

/// Parsed key-value data from the `verificationData` field of a [`ServerSignaturePayload`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct ServerSignatureVerificationData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Unix timestamp after which the payload is considered expired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    /// Any additional fields not explicitly modelled above.
    #[serde(flatten)]
    pub extra: BTreeMap<String, String>,
}

/// Result of verifying a [`ServerSignaturePayload`].
#[derive(Debug, Clone)]
pub struct VerifyServerSignatureResult {
    pub expired: bool,
    pub invalid_signature: bool,
    pub invalid_solution: bool,
    pub time: f64,
    pub verified: bool,
    /// Parsed verification data, or `None` if parsing failed.
    pub verification_data: Option<ServerSignatureVerificationData>,
}

/// Options for creating a new challenge.
pub struct CreateChallengeOptions {
    /// Key derivation algorithm (e.g. `"PBKDF2/SHA-256"`, `"SCRYPT"`, `"ARGON2ID"`).
    pub algorithm: String,
    /// Optional pre-determined counter for deterministic mode.
    /// When set, the key prefix is derived from this counter value.
    pub counter: Option<u32>,
    /// Algorithm-specific cost parameter (iterations, time cost, etc.).
    pub cost: u32,
    /// Arbitrary metadata to embed in the challenge.
    pub data: Option<BTreeMap<String, serde_json::Value>>,
    /// Unix timestamp (seconds) after which the challenge expires.
    pub expires_at: Option<u64>,
    /// HMAC algorithm for signing (default: `HmacAlgorithm::Sha256`).
    pub hmac_algorithm: HmacAlgorithm,
    /// HMAC secret for signing derived keys (deterministic mode only).
    pub hmac_key_signature_secret: Option<String>,
    /// HMAC secret for signing the challenge payload. If `None`, the challenge is unsigned.
    pub hmac_signature_secret: Option<String>,
    /// Length of the derived key in bytes (default: 32).
    pub key_length: usize,
    /// Required hex prefix the derived key must start with (default: `"00"`).
    pub key_prefix: String,
    /// Number of bytes used as the key prefix in deterministic mode (default: `key_length / 2`).
    pub key_prefix_length: Option<usize>,
    /// Memory cost in KiB for memory-hard algorithms (Argon2id, Scrypt).
    pub memory_cost: Option<u32>,
    /// Parallelism factor for Argon2id and Scrypt.
    pub parallelism: Option<u32>,
}

impl Default for CreateChallengeOptions {
    fn default() -> Self {
        Self {
            algorithm: "PBKDF2/SHA-256".to_string(),
            counter: None,
            cost: 100_000,
            data: None,
            expires_at: None,
            hmac_algorithm: HmacAlgorithm::Sha256,
            hmac_key_signature_secret: None,
            hmac_signature_secret: None,
            key_length: 32,
            key_prefix: "00".to_string(),
            key_prefix_length: None,
            memory_cost: None,
            parallelism: None,
        }
    }
}

/// Options for solving a challenge.
pub struct SolveChallengeOptions<'a> {
    /// The challenge to solve.
    pub challenge: &'a Challenge,
    /// Starting counter value (default: 0).
    pub counter_start: u32,
    /// Counter increment per iteration (default: 1).
    pub counter_step: u32,
    /// Maximum time to attempt solving in milliseconds (default: 90,000).
    pub timeout_ms: u64,
}

impl<'a> SolveChallengeOptions<'a> {
    pub fn new(challenge: &'a Challenge) -> Self {
        Self {
            challenge,
            counter_start: 0,
            counter_step: 1,
            timeout_ms: 90_000,
        }
    }
}

/// Options for verifying a submitted solution.
pub struct VerifySolutionOptions<'a> {
    /// The challenge that was issued.
    pub challenge: &'a Challenge,
    /// The solution submitted by the client.
    pub solution: &'a Solution,
    /// HMAC algorithm used to sign the challenge (default: `HmacAlgorithm::Sha256`).
    pub hmac_algorithm: HmacAlgorithm,
    /// HMAC secret for verifying derived-key signatures (deterministic mode).
    pub hmac_key_signature_secret: Option<String>,
    /// HMAC secret used when the challenge was created.
    pub hmac_signature_secret: String,
}

impl<'a> VerifySolutionOptions<'a> {
    pub fn new(
        challenge: &'a Challenge,
        solution: &'a Solution,
        hmac_signature_secret: impl Into<String>,
    ) -> Self {
        Self {
            challenge,
            solution,
            hmac_algorithm: HmacAlgorithm::Sha256,
            hmac_key_signature_secret: None,
            hmac_signature_secret: hmac_signature_secret.into(),
        }
    }
}
