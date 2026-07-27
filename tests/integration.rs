use altcha::{
    create_challenge, sign_challenge, solve_challenge, verify_solution, CreateChallengeOptions,
    HmacAlgorithm, Solution, SolveChallengeOptions, VerifySolutionOptions,
};

fn secret() -> String {
    "test-secret".to_string()
}

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

/// Verifies that a freshly created + solved challenge passes verification.
fn roundtrip(algorithm: &str, cost: u32) {
    let options = CreateChallengeOptions {
        algorithm: algorithm.to_string(),
        cost,
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    };
    let challenge = create_challenge(options).expect("create_challenge failed");
    assert!(challenge.signature.is_some(), "challenge must be signed");

    let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
        .expect("solve_challenge failed")
        .expect("no solution found within timeout");

    let result = verify_solution(VerifySolutionOptions::new(&challenge, &solution, secret()))
        .expect("verify_solution failed");

    assert!(result.verified, "solution must verify for {algorithm}");
    assert!(!result.expired);
    assert_eq!(result.invalid_signature, Some(false));
    assert_eq!(result.invalid_solution, Some(false));
}

#[test]
fn roundtrip_pbkdf2_sha256() {
    roundtrip("PBKDF2/SHA-256", 100);
}

#[test]
fn roundtrip_pbkdf2_sha384() {
    roundtrip("PBKDF2/SHA-384", 100);
}

#[test]
fn roundtrip_pbkdf2_sha512() {
    roundtrip("PBKDF2/SHA-512", 100);
}

#[test]
fn roundtrip_sha256() {
    roundtrip("SHA-256", 10);
}

#[test]
fn roundtrip_sha384() {
    roundtrip("SHA-384", 10);
}

#[test]
fn roundtrip_sha512() {
    roundtrip("SHA-512", 10);
}

#[cfg(feature = "scrypt")]
#[test]
fn roundtrip_scrypt() {
    roundtrip("SCRYPT", 1024); // N=1024, r=8 (default), p=1 (default)
}

#[cfg(feature = "argon2")]
#[test]
fn roundtrip_argon2id() {
    let options = CreateChallengeOptions {
        algorithm: "ARGON2ID".to_string(),
        cost: 1,        // t_cost (passes)
        memory_cost: Some(8), // m_cost in KiB
        parallelism: Some(1),
        key_prefix: "00".to_string(),
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    };
    let challenge = create_challenge(options).expect("create_challenge failed");
    let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
        .expect("solve_challenge failed")
        .expect("no solution found");
    let result = verify_solution(VerifySolutionOptions::new(&challenge, &solution, secret()))
        .expect("verify_solution failed");
    assert!(result.verified, "argon2id solution must verify");
}

// ---------------------------------------------------------------------------
// Deterministic mode
// ---------------------------------------------------------------------------

#[test]
fn deterministic_mode_roundtrip() {
    let options = CreateChallengeOptions {
        algorithm: "PBKDF2/SHA-256".to_string(),
        cost: 100,
        counter: Some(0),
        hmac_signature_secret: Some(secret()),
        hmac_key_signature_secret: Some("key-secret".to_string()),
        ..Default::default()
    };
    let challenge = create_challenge(options).expect("create_challenge failed");
    assert!(
        challenge.parameters.key_signature.is_some(),
        "keySignature must be present in deterministic mode"
    );

    let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
        .expect("solve_challenge failed")
        .expect("no solution found");

    // Fast-path verification via key signature.
    let result = verify_solution(VerifySolutionOptions {
        hmac_key_signature_secret: Some("key-secret".to_string()),
        ..VerifySolutionOptions::new(&challenge, &solution, secret())
    })
    .expect("verify_solution failed");

    assert!(result.verified, "deterministic mode must verify");
    assert_eq!(result.invalid_solution, Some(false));
}

// ---------------------------------------------------------------------------
// Negative cases
// ---------------------------------------------------------------------------

#[test]
fn wrong_secret_fails_verification() {
    let options = CreateChallengeOptions {
        algorithm: "PBKDF2/SHA-256".to_string(),
        cost: 100,
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    };
    let challenge = create_challenge(options).expect("create_challenge failed");
    let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
        .expect("solve_challenge failed")
        .expect("no solution found");

    let result =
        verify_solution(VerifySolutionOptions::new(&challenge, &solution, "wrong-secret"))
            .expect("verify_solution failed");

    assert!(!result.verified);
    assert_eq!(result.invalid_signature, Some(true));
}

/// Regression test: the fallback verification path (no key signature) must reject a
/// solution whose derived key is genuinely correct for its counter but does not satisfy
/// the challenge's `keyPrefix`. Previously only `derivedKey == KDF(counter)` was checked,
/// letting a client submit any counter after a single KDF execution and skip the prefix
/// search entirely.
#[test]
fn fallback_verification_enforces_key_prefix() {
    let mut challenge = create_challenge(CreateChallengeOptions {
        algorithm: "SHA-256".to_string(),
        cost: 10,
        ..Default::default()
    })
    .expect("create_challenge failed");

    // Learn the honest KDF output for counter 0 with exactly one hash computation: solve a
    // probe copy of the challenge whose keyPrefix is "" (matches immediately, no search).
    let mut probe = challenge.clone();
    probe.parameters.key_prefix = String::new();
    let honest = solve_challenge(SolveChallengeOptions::new(&probe))
        .expect("solve_challenge failed")
        .expect("no solution found");

    // Pick a keyPrefix the honest key is guaranteed not to satisfy: a byte can't be both
    // 0x00 and 0xff.
    let mismatched_prefix = if honest.derived_key.starts_with("00") {
        "ff"
    } else {
        "00"
    };
    challenge.parameters.key_prefix = mismatched_prefix.to_string();
    let signed = sign_challenge(
        &HmacAlgorithm::Sha256,
        &mut challenge.parameters,
        None,
        &secret(),
        None,
    )
    .expect("sign_challenge failed");

    // Submit the honestly-derived key/counter pair (one KDF execution, no prefix search)
    // against the challenge whose signed keyPrefix it does not satisfy.
    let solution = Solution {
        counter: honest.counter,
        derived_key: honest.derived_key,
        time: None,
    };

    let result = verify_solution(VerifySolutionOptions::new(&signed, &solution, secret()))
        .expect("verify_solution failed");

    assert!(
        !result.verified,
        "solution violating key_prefix must not verify"
    );
    assert_eq!(result.invalid_solution, Some(true));
}

#[test]
fn tampered_counter_fails_verification() {
    let options = CreateChallengeOptions {
        algorithm: "PBKDF2/SHA-256".to_string(),
        cost: 100,
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    };
    let challenge = create_challenge(options).expect("create_challenge failed");
    let mut solution = solve_challenge(SolveChallengeOptions::new(&challenge))
        .expect("solve_challenge failed")
        .expect("no solution found");

    // Tamper with the counter.
    solution.counter = solution.counter.wrapping_add(1);

    let result = verify_solution(VerifySolutionOptions::new(&challenge, &solution, secret()))
        .expect("verify_solution failed");

    assert!(!result.verified);
    assert_eq!(result.invalid_solution, Some(true));
}

#[test]
fn unsigned_challenge_fails_verification() {
    let options = CreateChallengeOptions {
        algorithm: "PBKDF2/SHA-256".to_string(),
        cost: 100,
        hmac_signature_secret: None, // no signing
        ..Default::default()
    };
    let challenge = create_challenge(options).expect("create_challenge failed");
    let solution = Solution {
        counter: 0,
        derived_key: "00".to_string(),
        time: None,
    };

    let result = verify_solution(VerifySolutionOptions::new(&challenge, &solution, secret()))
        .expect("verify_solution failed");

    assert!(!result.verified);
    assert_eq!(result.invalid_signature, Some(true));
}

#[test]
fn expired_challenge_fails_verification() {
    let past = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 1; // 1 second in the past

    let options = CreateChallengeOptions {
        algorithm: "PBKDF2/SHA-256".to_string(),
        cost: 100,
        expires_at: Some(past),
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    };
    let challenge = create_challenge(options).expect("create_challenge failed");
    let solution = Solution {
        counter: 0,
        derived_key: "00".to_string(),
        time: None,
    };

    let result = verify_solution(VerifySolutionOptions::new(&challenge, &solution, secret()))
        .expect("verify_solution failed");

    assert!(!result.verified);
    assert!(result.expired);
}

// ---------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------

/// Verifies that canonical JSON produces sorted keys, matching the JS reference.
#[test]
fn canonical_json_sorted_keys() {
    // Reconstruct what the JS `canonicalJSON(parameters)` would produce for a fixed set
    // of parameters. Keys must appear in alphabetical order with no undefined fields.
    use altcha::ChallengeParameters;
    use serde_json;

    let params = ChallengeParameters {
        algorithm: "PBKDF2/SHA-256".to_string(),
        cost: 1000,
        data: None,
        expires_at: None,
        key_length: 32,
        key_prefix: "00".to_string(),
        key_signature: None,
        memory_cost: None,
        nonce: "aabbccdd".to_string(),
        parallelism: None,
        salt: "eeff0011".to_string(),
    };

    let json = serde_json::to_string(&params).unwrap();
    // Keys must be: algorithm, cost, keyLength, keyPrefix, nonce, salt (alphabetical)
    let expected_keys = ["algorithm", "cost", "keyLength", "keyPrefix", "nonce", "salt"];
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = value.as_object().unwrap();
    let actual_keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    assert_eq!(actual_keys, expected_keys, "JSON keys must be sorted alphabetically");
}
