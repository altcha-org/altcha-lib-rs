use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::helpers::{
    bytes_to_hex, constant_time_equal_hex, elapsed_ms, hmac_sign, sha_hash,
};
use crate::types::{
    HmacAlgorithm, ServerSignaturePayload, ServerSignatureVerificationData,
    VerifyServerSignatureResult,
};

/// Parses a URL-encoded `verificationData` string into a
/// [`ServerSignatureVerificationData`] struct.
///
/// Type coercions applied per key:
/// - `"true"` / `"false"` → `bool`
/// - All-digit strings → `u64` (integers)
/// - `digit.digit` strings → `f64` (floats)
/// - `fields` and `reasons` keys → comma-split `Vec<String>`
/// - Everything else → trimmed `String` stored in `extra`
pub fn parse_verification_data(data: &str) -> Option<ServerSignatureVerificationData> {
    let pairs = parse_urlencoded(data);
    let mut out = ServerSignatureVerificationData::default();

    for (key, value) in pairs {
        match key.as_str() {
            "classification" => out.classification = Some(value),
            "email" => out.email = Some(value),
            "expire" => out.expire = value.parse().ok(),
            "fields" => {
                out.fields = Some(
                    value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                )
            }
            "fieldsHash" => out.fields_hash = Some(value),
            "id" => out.id = Some(value),
            "ipAddress" => out.ip_address = Some(value),
            "reasons" => {
                out.reasons = Some(
                    value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                )
            }
            "score" => out.score = value.parse().ok(),
            "time" => out.time = value.parse().ok(),
            "verified" => out.verified = Some(value == "true"),
            _ => {
                out.extra.insert(key, value);
            }
        }
    }

    Some(out)
}

/// Verifies a [`ServerSignaturePayload`] issued by ALTCHA Sentinel.
///
/// The verification process:
/// 1. Compute `HMAC(SHA(verificationData), hmacSecret)` and compare with `payload.signature`.
/// 2. Parse the `verificationData` URL-encoded string.
/// 3. Check that the parsed data has not expired (`expire` field).
/// 4. Check that both `payload.verified` and `verificationData.verified` are `true`.
pub fn verify_server_signature(
    payload: &ServerSignaturePayload,
    hmac_secret: &str,
) -> Result<VerifyServerSignatureResult> {
    let start = std::time::Instant::now();

    let algorithm = parse_hmac_algorithm(&payload.algorithm)?;

    // Compute expected signature: HMAC(HASH(verificationData), hmacSecret)
    let hash = sha_hash(&algorithm, payload.verification_data.as_bytes());
    let expected_sig = hmac_sign(&algorithm, &hash, hmac_secret)?;
    let invalid_signature = !constant_time_equal_hex(&payload.signature, &bytes_to_hex(&expected_sig));

    let verification_data = parse_verification_data(&payload.verification_data);

    let expired = verification_data
        .as_ref()
        .and_then(|d| d.expire)
        .map(|exp| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now > exp
        })
        .unwrap_or(false);

    let invalid_solution = verification_data
        .as_ref()
        .map(|d| d.verified != Some(true))
        .unwrap_or(true)
        || !payload.verified;

    let verified = !expired && !invalid_signature && !invalid_solution;

    Ok(VerifyServerSignatureResult {
        expired,
        invalid_signature,
        invalid_solution,
        time: elapsed_ms(start),
        verification_data,
        verified,
    })
}

/// Verifies a hash of selected form fields against an expected hex digest.
///
/// Joins the values of `fields` (in order) with `"\n"`, hashes the result
/// with the given algorithm (default SHA-256), and compares the hex output
/// with `fields_hash`.
pub fn verify_fields_hash(
    form_data: &HashMap<String, String>,
    fields: &[String],
    fields_hash: &str,
    algorithm: Option<&HmacAlgorithm>,
) -> bool {
    let algo = algorithm.unwrap_or(&HmacAlgorithm::Sha256);
    let joined = fields
        .iter()
        .map(|f| form_data.get(f).map(|s| s.as_str()).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let hash = sha_hash(algo, joined.as_bytes());
    constant_time_equal_hex(&bytes_to_hex(&hash), fields_hash)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_hmac_algorithm(s: &str) -> Result<HmacAlgorithm> {
    match s.to_uppercase().as_str() {
        "SHA-256" => Ok(HmacAlgorithm::Sha256),
        "SHA-384" => Ok(HmacAlgorithm::Sha384),
        "SHA-512" => Ok(HmacAlgorithm::Sha512),
        other => Err(Error::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Decodes an `application/x-www-form-urlencoded` string into key-value pairs.
fn parse_urlencoded(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = percent_decode(parts.next()?);
            let value = percent_decode(parts.next().unwrap_or(""));
            if key.is_empty() {
                return None;
            }
            Some((key, value.trim().to_string()))
        })
        .collect()
}

/// Percent-decodes a URL-encoded string (`+` → space, `%XX` → byte).
fn percent_decode(s: &str) -> String {
    let s = s.replace('+', " ");
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex_str, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_urlencoded_basic() {
        let pairs = parse_urlencoded("foo=bar&baz=qux");
        assert_eq!(pairs, vec![("foo".into(), "bar".into()), ("baz".into(), "qux".into())]);
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("foo+bar"), "foo bar");
        assert_eq!(percent_decode("a%3Db"), "a=b");
    }

    #[test]
    fn test_parse_verification_data() {
        let data = "verified=true&expire=9999999999&score=0.9&classification=GOOD&reasons=vp%2Cvd";
        let vd = parse_verification_data(data).unwrap();
        assert_eq!(vd.verified, Some(true));
        assert_eq!(vd.expire, Some(9999999999));
        assert_eq!(vd.score, Some(0.9));
        assert_eq!(vd.classification.as_deref(), Some("GOOD"));
        assert_eq!(vd.reasons, Some(vec!["vp".into(), "vd".into()]));
    }

    #[test]
    fn test_verify_fields_hash() {
        use sha2::{Digest, Sha256};

        let mut form = HashMap::new();
        form.insert("name".into(), "Ada".into());
        form.insert("email".into(), "ada@example.com".into());

        let fields = vec!["name".into(), "email".into()];
        let joined = "Ada\nada@example.com";
        let expected_hash = hex::encode(Sha256::digest(joined.as_bytes()));

        assert!(verify_fields_hash(&form, &fields, &expected_hash, None));
        assert!(!verify_fields_hash(&form, &fields, "deadbeef", None));
    }
}
