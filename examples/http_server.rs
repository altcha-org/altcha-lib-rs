//! # HTTP server example
//!
//! Demonstrates a minimal ALTCHA-protected HTTP API with two endpoints:
//!
//! - `GET  /challenge` — issue a new signed PoW challenge (JSON)
//! - `POST /submit`    — verify an ALTCHA payload submitted with a form
//!
//! ## Run
//!
//! ```sh
//! cargo run --example http_server
//! ```

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Form, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use altcha::{
    create_challenge, verify_server_signature, verify_solution, CreateChallengeOptions, Payload,
    ServerSignaturePayload, ServerSignatureVerificationData, VerifySolutionOptions,
};
use rand::Rng;

// ---------------------------------------------------------------------------
// Server config
// ---------------------------------------------------------------------------

/// Shared application state passed to every handler.
#[derive(Clone)]
struct AppState {
    /// HMAC secret used to sign and verify challenges.
    /// In production load this from an environment variable or secrets manager.
    hmac_secret: Arc<String>,
    hmac_key_secret: Arc<String>,
}

// ---------------------------------------------------------------------------
// GET /challenge
// ---------------------------------------------------------------------------

async fn get_challenge(State(state): State<AppState>) -> Response {
    let options = CreateChallengeOptions {
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
        hmac_signature_secret: Some((*state.hmac_secret).clone()),
        hmac_key_signature_secret: Some((*state.hmac_key_secret).clone()),
        ..Default::default()
    };

    match create_challenge(options) {
        Ok(challenge) => Json(challenge).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to create challenge: {err}"),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /submit
// ---------------------------------------------------------------------------

/// Form fields sent by the client.
///
/// The ALTCHA widget automatically populates the `altcha` hidden input with
/// a Base64-encoded JSON payload before the form is submitted.
#[derive(Deserialize)]
struct SubmitForm {
    altcha: String,
}

#[derive(Serialize)]
struct AltchaResult {
    verified: bool,
    expired: bool,
    invalid_signature: Option<bool>,
    invalid_solution: Option<bool>,
    time: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_data: Option<ServerSignatureVerificationData>,
}

#[derive(Serialize)]
struct SubmitResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    altcha: Option<AltchaResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SubmitResponse {
    fn ok(altcha: AltchaResult) -> Self {
        Self { ok: true, altcha: Some(altcha), error: None }
    }
    fn err(msg: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::BAD_REQUEST,
            Json(Self { ok: false, altcha: None, error: Some(msg.into()) }),
        )
    }
}

/// Distinguishes between a PoW client payload and an ALTCHA Sentinel server
/// signature payload by inspecting which top-level keys are present — matching
/// the detection logic used in the reference JavaScript implementation.
#[derive(Deserialize)]
#[serde(untagged)]
enum AltchaPayload {
    /// ALTCHA Sentinel payload: contains `verificationData`.
    ServerSignature(ServerSignaturePayload),
    /// PoW client payload: contains `challenge` and `solution`.
    Client(Payload),
}

async fn post_submit(
    State(state): State<AppState>,
    Form(form): Form<SubmitForm>,
) -> Response {
    let secret = (*state.hmac_secret).as_str();

    // 1. Base64-decode the widget payload.
    let bytes = match BASE64.decode(&form.altcha) {
        Ok(b) => b,
        Err(_) => return SubmitResponse::err("altcha: base64 decode failed").into_response(),
    };

    // 2. Detect payload type and verify accordingly.
    let altcha_result = match serde_json::from_slice::<AltchaPayload>(&bytes) {
        Ok(AltchaPayload::Client(payload)) => {
            // PoW client payload — verify the solved challenge.
            // Pass hmac_key_signature_secret to take the fast path: the key
            // signature embedded in the challenge is checked instead of
            // re-deriving the key from scratch.
            match verify_solution(VerifySolutionOptions {
                hmac_key_signature_secret: Some((*state.hmac_key_secret).clone()),
                ..VerifySolutionOptions::new(&payload.challenge, &payload.solution, secret)
            }) {
                Ok(r) => AltchaResult {
                    verified: r.verified,
                    expired: r.expired,
                    invalid_signature: r.invalid_signature,
                    invalid_solution: r.invalid_solution,
                    time: r.time,
                    verification_data: None,
                },
                Err(err) => {
                    return SubmitResponse::err(format!("altcha: {err}")).into_response()
                }
            }
        }
        Ok(AltchaPayload::ServerSignature(payload)) => {
            // ALTCHA Sentinel server signature — verify the signed verification data.
            match verify_server_signature(&payload, secret) {
                Ok(r) => AltchaResult {
                    verified: r.verified,
                    expired: r.expired,
                    invalid_signature: Some(r.invalid_signature),
                    invalid_solution: Some(r.invalid_solution),
                    time: r.time,
                    verification_data: r.verification_data,
                },
                Err(err) => {
                    return SubmitResponse::err(format!("altcha: {err}")).into_response()
                }
            }
        }
        Err(_) => {
            return SubmitResponse::err("altcha: unrecognised payload format").into_response()
        }
    };

    if !altcha_result.verified {
        let reason = if altcha_result.expired {
            "challenge has expired"
        } else if altcha_result.invalid_signature == Some(true) {
            "invalid signature"
        } else {
            "invalid solution"
        };
        return SubmitResponse::err(format!("altcha: {reason}")).into_response();
    }

    // 3. ALTCHA passed — process the actual form submission.

    Json(SubmitResponse::ok(altcha_result)).into_response()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let state = AppState {
        // In production: std::env::var("HMAC_SECRET").expect("HMAC_SECRET must be set")
        hmac_secret: Arc::new("change-me-in-production".to_string()),
        hmac_key_secret: Arc::new("change-me-in-production".to_string()),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/challenge", get(get_challenge))
        .route("/submit", post(post_submit))
        .layer(cors)
        .with_state(state);

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("listening on http://{addr}");
    axum::serve(listener, app).await.unwrap();
}
