//! # altcha
//!
//! ALTCHA Proof-of-Work v2 implementation in Rust.
//!
//! This crate provides server-side challenge creation and verification as well as
//! client-side challenge solving for the [ALTCHA](https://altcha.org) PoW v2 protocol.
//!
//! ## Quick start
//!
//! ```rust
//! use altcha::{
//!     CreateChallengeOptions, SolveChallengeOptions, VerifySolutionOptions,
//!     create_challenge, solve_challenge, verify_solution,
//! };
//!
//! // Server: create a challenge
//! let options = CreateChallengeOptions {
//!     algorithm: "PBKDF2/SHA-256".to_string(),
//!     cost: 5000,
//!     hmac_signature_secret: Some("my-secret".to_string()),
//!     ..Default::default()
//! };
//! let challenge = create_challenge(options).unwrap();
//!
//! // Client: solve the challenge
//! let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
//!     .unwrap()
//!     .expect("solution not found within timeout");
//!
//! // Server: verify the solution
//! let result = verify_solution(VerifySolutionOptions::new(
//!     &challenge,
//!     &solution,
//!     "my-secret",
//! ))
//! .unwrap();
//!
//! assert!(result.verified);
//! ```

mod algorithms;
pub mod error;
mod helpers;
mod pow;
mod server_signature;
pub mod types;

pub use error::{Error, Result};
pub use pow::{create_challenge, sign_challenge, solve_challenge, verify_solution};
pub use server_signature::{
    parse_verification_data, verify_fields_hash, verify_server_signature,
};
pub use types::{
    Challenge, ChallengeParameters, CreateChallengeOptions, HmacAlgorithm, Payload, Solution,
    ServerSignaturePayload, ServerSignatureVerificationData, SolveChallengeOptions,
    VerifySolutionOptions, VerifySolutionResult, VerifyServerSignatureResult,
};
