use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use crate::error::Result;
use crate::types::HmacAlgorithm;

/// Converts raw bytes to a lowercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decodes a hex string into bytes.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s)?)
}

/// Checks whether `buf` starts with the bytes in `prefix`.
pub fn buffer_starts_with(buf: &[u8], prefix: &[u8]) -> bool {
    buf.len() >= prefix.len() && buf[..prefix.len()] == *prefix
}

/// Constant-time equality check for byte slices.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time equality check for hex-encoded strings (compared as raw bytes).
pub fn constant_time_equal_hex(a: &str, b: &str) -> bool {
    constant_time_equal(a.as_bytes(), b.as_bytes())
}

/// Computes HMAC using the specified digest algorithm.
///
/// `data` may be either a byte slice or a string (passed as bytes).
pub fn hmac_sign(algorithm: &HmacAlgorithm, data: &[u8], key: &str) -> Result<Vec<u8>> {
    let key_bytes = key.as_bytes();
    match algorithm {
        HmacAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key_bytes)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        HmacAlgorithm::Sha384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(key_bytes)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        HmacAlgorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key_bytes)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Produces a canonical JSON string with object keys sorted alphabetically at all levels.
///
/// Matches the behaviour of the reference JavaScript `canonicalJSON` / `sortKeys` functions.
pub fn canonical_json<T: serde::Serialize>(value: &T) -> Result<String> {
    let json_value = serde_json::to_value(value)?;
    let sorted = sort_json_keys(json_value);
    Ok(serde_json::to_string(&sorted)?)
}

/// Recursively sorts all object keys in a `serde_json::Value`.
fn sort_json_keys(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_json_keys(v)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_json_keys).collect())
        }
        other => other,
    }
}

/// Computes a SHA digest of `data` using the given algorithm.
pub fn sha_hash(algorithm: &HmacAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HmacAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HmacAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        HmacAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
    }
}

/// Builds the password buffer used as KDF input for a given counter value.
///
/// Format: `nonce_bytes || counter.to_be_bytes()` (nonce length + 4 bytes).
pub fn build_password(nonce_bytes: &[u8], counter: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(nonce_bytes.len() + 4);
    buf.extend_from_slice(nonce_bytes);
    buf.extend_from_slice(&counter.to_be_bytes());
    buf
}

/// Generates 16 random bytes using the OS random source.
pub fn random_bytes_16() -> [u8; 16] {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Returns elapsed milliseconds since `start` with 0.1 ms precision.
pub fn elapsed_ms(start: std::time::Instant) -> f64 {
    let nanos = start.elapsed().as_nanos() as f64;
    (nanos / 100_000.0).floor() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_json_sorts_keys() {
        use serde_json::json;
        let v = json!({ "z": 1, "a": 2, "m": 3 });
        let s = serde_json::to_string(&sort_json_keys(v)).unwrap();
        assert_eq!(s, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_build_password() {
        let nonce = [0u8; 4];
        let pwd = build_password(&nonce, 1);
        assert_eq!(pwd, vec![0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_constant_time_equal() {
        assert!(constant_time_equal(b"hello", b"hello"));
        assert!(!constant_time_equal(b"hello", b"world"));
        assert!(!constant_time_equal(b"hello", b"hell"));
    }

    #[test]
    fn test_buffer_starts_with() {
        assert!(buffer_starts_with(&[0x00, 0x01, 0x02], &[0x00, 0x01]));
        assert!(!buffer_starts_with(&[0x01, 0x01], &[0x00]));
    }
}
