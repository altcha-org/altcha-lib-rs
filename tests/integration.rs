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

/// Regression test: an even-length keyPrefix is compared as bytes (case-insensitive hex)
/// by the JS reference in both solve and verify. Verify previously did a string compare
/// against the lowercase derived key, rejecting solutions to uppercase prefixes that its
/// own solver accepted.
#[test]
fn fallback_verification_accepts_uppercase_even_prefix() {
    let challenge = create_challenge(CreateChallengeOptions {
        algorithm: "SHA-256".to_string(),
        cost: 10,
        key_prefix: "0A".to_string(),
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    })
    .expect("create_challenge failed");
    let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
        .expect("solve_challenge failed")
        .expect("no solution found");
    assert!(solution.derived_key.starts_with("0a"));

    let result = verify_solution(VerifySolutionOptions::new(&challenge, &solution, secret()))
        .expect("verify_solution failed");

    assert!(result.verified, "solver output must verify: {result:?}");
    assert_eq!(result.invalid_solution, Some(false));
}

/// Regression test: on the key-signature path the client-controlled `derivedKey` is
/// hex-decoded. Non-hex or odd-length input must yield a clean `invalid_solution`, not
/// an `Err` from `verify_solution`.
#[test]
fn key_signature_path_rejects_malformed_derived_key() {
    let challenge = create_challenge(CreateChallengeOptions {
        algorithm: "SHA-256".to_string(),
        cost: 10,
        counter: Some(0),
        hmac_signature_secret: Some(secret()),
        hmac_key_signature_secret: Some("key-secret".to_string()),
        ..Default::default()
    })
    .expect("create_challenge failed");

    for derived_key in ["zz".repeat(32), "abc".to_string()] {
        let solution = Solution {
            counter: 0,
            derived_key,
            time: None,
        };
        let result = verify_solution(VerifySolutionOptions {
            hmac_key_signature_secret: Some("key-secret".to_string()),
            ..VerifySolutionOptions::new(&challenge, &solution, secret())
        })
        .expect("malformed derivedKey must not return Err");

        assert!(!result.verified, "{:?}", solution.derived_key);
        assert_eq!(result.invalid_signature, Some(false));
        assert_eq!(result.invalid_solution, Some(true));
    }
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

/// A challenge expires as soon as the current time passes `expires_at`, with sub-second
/// precision (JS: `expiresAt < Date.now() / 1000`). `expires_at` = the current whole
/// second must already be expired; truncating `now` to seconds used to grant up to 1s
/// of grace.
#[test]
fn expired_challenge_fails_verification() {
    let current_second = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let options = CreateChallengeOptions {
        algorithm: "PBKDF2/SHA-256".to_string(),
        cost: 100,
        expires_at: Some(current_second),
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    };
    let challenge = create_challenge(options).expect("create_challenge failed");
    let solution = Solution {
        counter: 0,
        derived_key: "00".to_string(),
        time: None,
    };

    // Guarantee `now` is strictly past `current_second` at verification time.
    std::thread::sleep(std::time::Duration::from_millis(1));
    let result = verify_solution(VerifySolutionOptions::new(&challenge, &solution, secret()))
        .expect("verify_solution failed");

    assert!(!result.verified);
    assert!(result.expired);
}

/// `expires_at = 0` means "no expiry" (JS: `expiresAt && …`, 0 is falsy).
#[test]
fn zero_expires_at_never_expires() {
    let challenge = create_challenge(CreateChallengeOptions {
        algorithm: "SHA-256".to_string(),
        cost: 10,
        expires_at: Some(0),
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    })
    .expect("create_challenge failed");
    let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
        .expect("solve_challenge failed")
        .expect("no solution found");

    let result = verify_solution(VerifySolutionOptions::new(&challenge, &solution, secret()))
        .expect("verify_solution failed");

    assert!(!result.expired);
    assert!(result.verified, "{result:?}");
}

/// Negative `expires_at` lies before the Unix epoch and is always expired.
#[test]
fn negative_expires_at_is_expired() {
    let challenge = create_challenge(CreateChallengeOptions {
        algorithm: "SHA-256".to_string(),
        cost: 10,
        expires_at: Some(-1),
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    })
    .expect("create_challenge failed");
    let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
        .expect("solve_challenge failed")
        .expect("no solution found");

    let result = verify_solution(VerifySolutionOptions::new(&challenge, &solution, secret()))
        .expect("verify_solution failed");

    assert!(result.expired);
    assert!(!result.verified);
}

/// Regression test: the solver timeout is checked every 10 iterations, independent of the
/// counter values. Previously it was checked only when `counter % 10 == 0`, so a sequence
/// that never hits a multiple of 10 (here: odd counters, as in worker partitioning) never
/// timed out.
#[test]
fn solver_times_out_for_any_counter_sequence() {
    let challenge = create_challenge(CreateChallengeOptions {
        algorithm: "SHA-256".to_string(),
        cost: 10,
        // Odd-length prefix is compared against the lowercase hex key: never matches.
        key_prefix: "z".to_string(),
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    })
    .expect("create_challenge failed");

    // Solve on a separate thread so a regression fails the test instead of hanging it.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = solve_challenge(SolveChallengeOptions {
            counter_start: 1,
            counter_step: 2,
            timeout_ms: 100,
            ..SolveChallengeOptions::new(&challenge)
        });
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("solver did not time out");
    assert!(result.expect("solve_challenge failed").is_none());
}

/// `timeout_ms: 0` disables the timeout (JS: `timeout && …`) rather than expiring at once.
#[test]
fn zero_timeout_means_no_timeout() {
    let challenge = create_challenge(CreateChallengeOptions {
        algorithm: "SHA-256".to_string(),
        cost: 10,
        counter: Some(50),
        hmac_signature_secret: Some(secret()),
        ..Default::default()
    })
    .expect("create_challenge failed");

    let solution = solve_challenge(SolveChallengeOptions {
        timeout_ms: 0,
        ..SolveChallengeOptions::new(&challenge)
    })
    .expect("solve_challenge failed");

    assert!(solution.is_some(), "timeout_ms 0 must not time out");
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
