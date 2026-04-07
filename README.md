# altcha

A Rust implementation of the [ALTCHA](https://altcha.org) Proof-of-Work v2 protocol.

ALTCHA is a privacy-friendly, self-hosted CAPTCHA alternative that uses proof-of-work challenges to block bots.

## Installation

```toml
[dependencies]
altcha = "0"
```

To enable optional KDF algorithms:

```toml
[dependencies]
altcha = { version = "0", features = ["argon2", "scrypt"] }
```

### Examples

- [`examples/http_server.rs`](/examples/http_server.rs)

### Features

| Feature | Enables | Default |
|---|---|---|
| `argon2` | Argon2id algorithm | no |
| `scrypt` | scrypt algorithm | no |

PBKDF2 and iterative SHA algorithms are always available.

## Quick start

```rust
use altcha::{
    create_challenge, solve_challenge, verify_solution,
    CreateChallengeOptions, SolveChallengeOptions, VerifySolutionOptions,
};

// ── Server: create a challenge ───────────────────────────────────────────────
let challenge = create_challenge(CreateChallengeOptions {
    algorithm: "PBKDF2/SHA-256".to_string(),
    // PBKDF2 iterations
    cost: 5_000,
    // Random counter enables deterministic mode
    counter: Some(rand::thread_rng().gen_range(5_000..=10_000)),
    // Expire challenges after 10 minutes so they cannot be reused indefinitely.
    expires_at: Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600,
    ),
    hmac_signature_secret: Some("my-hmac-secret".to_string()),
    // Required for deterministic mode: signs the derived key so verification
    // can skip re-deriving it (fast path).
    hmac_key_signature_secret: Some("my-key-secret".to_string()),
    ..Default::default()
})?;

// Serialize and send `challenge` to the client (e.g. as JSON).

// ── Client: solve the challenge ──────────────────────────────────────────────
let solution = solve_challenge(SolveChallengeOptions::new(&challenge))?
    .expect("no solution found within timeout");

// Send `solution` back to the server alongside `challenge`.

// ── Server: verify the solution ──────────────────────────────────────────────
let result = verify_solution(VerifySolutionOptions {
    hmac_key_signature_secret: Some("my-key-secret".to_string()),
    ..VerifySolutionOptions::new(&challenge, &solution, "my-hmac-secret")
})?;

assert!(result.verified);
```

## API

### `create_challenge`

```rust
pub fn create_challenge(options: CreateChallengeOptions) -> Result<Challenge>
```

Generates a new challenge with a random 16-byte nonce and salt. If `hmac_signature_secret` is set the challenge is signed with HMAC so that the server can detect tampering on verification.

**`CreateChallengeOptions` fields** (all optional except `algorithm` and `cost`):

| Field | Type | Default | Description |
|---|---|---|---|
| `algorithm` | `String` | — | KDF algorithm string (see [Algorithms](#algorithms)) |
| `cost` | `u32` | — | Algorithm cost (iterations, time cost, N for scrypt) |
| `counter` | `Option<u32>` | `None` | Enables deterministic mode; key prefix is derived from this counter |
| `data` | `Option<BTreeMap<String, Value>>` | `None` | Arbitrary metadata embedded in the signed challenge |
| `expires_at` | `Option<u64>` | `None` | Unix timestamp (seconds) after which the challenge is invalid |
| `hmac_algorithm` | `HmacAlgorithm` | `Sha256` | HMAC digest algorithm |
| `hmac_signature_secret` | `Option<String>` | `None` | Secret for signing the challenge; if absent the challenge is unsigned |
| `hmac_key_signature_secret` | `Option<String>` | `None` | Secret for signing the derived key (deterministic mode only) |
| `key_length` | `usize` | `32` | Output key length in bytes |
| `key_prefix` | `String` | `"00"` | Required hex prefix the derived key must start with |
| `key_prefix_length` | `Option<usize>` | `key_length / 2` | Bytes used as prefix in deterministic mode |
| `memory_cost` | `Option<u32>` | `None` | Memory cost in KiB (Argon2id, scrypt `r`) |
| `parallelism` | `Option<u32>` | `None` | Parallelism factor (Argon2id, scrypt `p`; default 1) |

---

### `solve_challenge`

```rust
pub fn solve_challenge(options: SolveChallengeOptions<'_>) -> Result<Option<Solution>>
```

Iterates counter values from `counter_start`, incrementing by `counter_step`, until the derived key starts with the required prefix. Returns `None` when `timeout_ms` elapses.

**`SolveChallengeOptions` fields:**

| Field | Default | Description |
|---|---|---|
| `challenge` | — | Reference to the challenge to solve |
| `counter_start` | `0` | First counter value to try |
| `counter_step` | `1` | Increment per attempt |
| `timeout_ms` | `90_000` | Maximum solve time in milliseconds |

Use `SolveChallengeOptions::new(&challenge)` to get sensible defaults.

---

### `verify_solution`

```rust
pub fn verify_solution(options: VerifySolutionOptions<'_>) -> Result<VerifySolutionResult>
```

Verifies a submitted solution in three steps:

1. **Expiration** — rejects challenges whose `expires_at` has passed.
2. **Signature** — recomputes `HMAC(canonical_json(parameters), secret)` and compares in constant time.
3. **Solution** — either verifies the submitted key against a stored key signature (fast path, deterministic mode) or re-derives the key from the submitted counter (full path).

**`VerifySolutionOptions` fields:**

| Field | Default | Description |
|---|---|---|
| `challenge` | — | The original challenge |
| `solution` | — | The solution submitted by the client |
| `hmac_signature_secret` | — | Secret used when the challenge was created |
| `hmac_algorithm` | `Sha256` | HMAC digest algorithm |
| `hmac_key_signature_secret` | `None` | Secret for fast-path key signature verification |

Use `VerifySolutionOptions::new(&challenge, &solution, "secret")` for defaults.

**`VerifySolutionResult`:**

```rust
pub struct VerifySolutionResult {
    pub verified: bool,
    pub expired: bool,
    pub invalid_signature: Option<bool>,  // None if expired before reaching this check
    pub invalid_solution: Option<bool>,   // None if signature check failed
    pub time: f64,                        // milliseconds to verify
}
```

---

### `sign_challenge`

```rust
pub fn sign_challenge(
    algorithm: &HmacAlgorithm,
    parameters: &mut ChallengeParameters,
    derived_key: Option<&[u8]>,
    hmac_signature_secret: &str,
    hmac_key_signature_secret: Option<&str>,
) -> Result<Challenge>
```

Signs an existing set of challenge parameters. Useful when building challenges manually.

---

### `verify_server_signature`

```rust
pub fn verify_server_signature(
    payload: &ServerSignaturePayload,
    hmac_secret: &str,
) -> Result<VerifyServerSignatureResult>
```

Verifies a payload issued by [ALTCHA Sentinel](https://altcha.org/docs/v2/server-integration). The payload is typically obtained from a form field (base64-encoded JSON) when using the ALTCHA Sentinel service for server-side bot scoring.

**Verification steps:**

1. Compute `HMAC(SHA(verificationData), hmac_secret)` and compare with `payload.signature` in constant time.
2. Parse `verificationData` (URL-encoded query string) into typed fields.
3. Check that the `expire` timestamp has not passed.
4. Check that both `payload.verified` and the parsed `verified` field are `true`.

**`ServerSignaturePayload` fields:**

| Field | Type | Description |
|---|---|---|
| `algorithm` | `String` | Hash and HMAC algorithm (e.g. `"SHA-256"`) |
| `api_key` | `Option<String>` | ALTCHA Sentinel API key (informational) |
| `id` | `Option<String>` | Submission ID |
| `signature` | `String` | Hex-encoded `HMAC(SHA(verificationData), secret)` |
| `verification_data` | `String` | URL-encoded query string from ALTCHA Sentinel |
| `verified` | `bool` | Whether Sentinel considers the submission verified |

**`VerifyServerSignatureResult`:**

```rust
pub struct VerifyServerSignatureResult {
    pub verified: bool,
    pub expired: bool,
    pub invalid_signature: bool,
    pub invalid_solution: bool,
    pub time: f64,
    pub verification_data: Option<ServerSignatureVerificationData>,
}
```

**`ServerSignatureVerificationData`** — parsed fields from `verificationData`:

| Field | Type | Description |
|---|---|---|
| `classification` | `Option<String>` | `"BAD"`, `"GOOD"`, or `"NEUTRAL"` |
| `email` | `Option<String>` | Submitter email (if provided) |
| `expire` | `Option<u64>` | Unix timestamp after which the payload expires |
| `fields` | `Option<Vec<String>>` | Form field names included in the fields hash |
| `fields_hash` | `Option<String>` | Hex hash of the selected form fields |
| `id` | `Option<String>` | Submission ID |
| `ip_address` | `Option<String>` | Submitter IP address |
| `reasons` | `Option<Vec<String>>` | Scoring reasons |
| `score` | `Option<f64>` | Bot probability score |
| `time` | `Option<f64>` | Submission timestamp |
| `verified` | `Option<bool>` | Whether Sentinel verified the submission |
| `extra` | `BTreeMap<String, String>` | Any additional fields not listed above |

**Example:**

```rust
use altcha::{verify_server_signature, ServerSignaturePayload};

// The ALTCHA widget puts a base64-encoded JSON ServerSignaturePayload
// into a hidden form field when connected to ALTCHA Sentinel.
let payload: ServerSignaturePayload = serde_json::from_slice(
    &base64::engine::general_purpose::STANDARD.decode(&form_field)?
)?;

let result = verify_server_signature(&payload, "my-hmac-secret")?;

if result.verified {
    // Safe to process the form submission.
    if let Some(data) = &result.verification_data {
        println!("score: {:?}, classification: {:?}", data.score, data.classification);
    }
}
```

---

### `verify_fields_hash`

```rust
pub fn verify_fields_hash(
    form_data: &HashMap<String, String>,
    fields: &[String],
    fields_hash: &str,
    algorithm: Option<&HmacAlgorithm>,
) -> bool
```

Verifies that a hash of selected form field values matches an expected digest. Used to confirm that specific fields have not been tampered with after the ALTCHA Sentinel payload was signed.

Joins the values of `fields` (in the given order) with `"\n"`, hashes with the specified algorithm (defaults to SHA-256), and compares with `fields_hash` in constant time.

---

### `parse_verification_data`

```rust
pub fn parse_verification_data(data: &str) -> Option<ServerSignatureVerificationData>
```

Parses the URL-encoded `verificationData` string from a [`ServerSignaturePayload`] into a typed [`ServerSignatureVerificationData`] struct. Called automatically by `verify_server_signature`; exposed for cases where you need to inspect the data independently.

## Algorithms

| Algorithm string | KDF | Feature | Notes |
|---|---|---|---|
| `"PBKDF2/SHA-256"` | PBKDF2-HMAC-SHA-256 | — | Default; `cost` = iteration count |
| `"PBKDF2/SHA-384"` | PBKDF2-HMAC-SHA-384 | — | `cost` = iteration count |
| `"PBKDF2/SHA-512"` | PBKDF2-HMAC-SHA-512 | — | `cost` = iteration count |
| `"SHA-256"` | Iterative SHA-256 | — | `cost` = iteration count |
| `"SHA-384"` | Iterative SHA-384 | — | `cost` = iteration count |
| `"SHA-512"` | Iterative SHA-512 | — | `cost` = iteration count |
| `"SCRYPT"` | scrypt | `scrypt` | `cost` = N (must be power of 2), `memory_cost` = r (default 8), `parallelism` = p (default 1) |
| `"ARGON2ID"` | Argon2id | `argon2` | `cost` = time cost, `memory_cost` = KiB (required), `parallelism` = p (default 1) |

## Serialization

`Challenge`, `Solution`, and `ServerSignaturePayload` implement `serde::Serialize` / `serde::Deserialize` and produce JSON compatible with the reference JavaScript library. Field names follow the camelCase convention used in the ALTCHA spec (`keyLength`, `keyPrefix`, `expiresAt`, `derivedKey`, `verificationData`, etc.).

```rust
let json = serde_json::to_string(&challenge)?;
let challenge: Challenge = serde_json::from_str(&json)?;
```

## License

MIT
