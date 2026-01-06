use http_body_util::{BodyExt, Full};
use hyper::Error as HyperError;
use hyper::{Response, StatusCode, body::Bytes};
use log::{info, warn};
use serde_json::{Value, json};
use std::{fs, io};

use serde::{Deserialize, Serialize};
use tokio::signal::{
    self,
    unix::{SignalKind, signal as unix_signal},
};
/// A Succinct Prover Network request ID.
/// See: <https://docs.succinct.xyz/docs/sp1/generating-proofs/prover-network/usage>
pub type SuccNetJobId = [u8; 32];

/// A SHA2 256 bit hash of a zkVM program's ELF.
pub type SuccNetProgramId = [u8; 32];

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct SP1ProofSetup {
    pub pk: sp1_sdk::SP1ProvingKey,
    pub vk: sp1_sdk::SP1VerifyingKey,
}

impl From<(sp1_sdk::SP1ProvingKey, sp1_sdk::SP1VerifyingKey)> for SP1ProofSetup {
    fn from(tuple: (sp1_sdk::SP1ProvingKey, sp1_sdk::SP1VerifyingKey)) -> Self {
        Self {
            pk: tuple.0,
            vk: tuple.1,
        }
    }
}

/// Account for shutdown signals, `ctrl+c` and other common Unix signals.
#[cfg(target_os = "linux")]
pub async fn wait_shutdown_signals() {
    // Wait for the Ctrl+C signal.
    let ctrl_c = signal::ctrl_c();

    // Create listeners for SIGTERM, SIGINT, and SIGHUP.
    let mut sigterm =
        unix_signal(SignalKind::terminate()).expect("Failed to set up SIGTERM listener");
    let mut sigint =
        unix_signal(SignalKind::interrupt()).expect("Failed to set up SIGINT listener");
    let mut sighup = unix_signal(SignalKind::hangup()).expect("Failed to set up SIGHUP listener");

    info!("Listening for shutdown signals (ctrl+c, SIGTERM, SIGINT, SIGHUP)");

    // Wait for any of the signals to occur.
    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C.");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM.");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT.");
        }
        _ = sighup.recv() => {
            info!("Received SIGHUP.");
        }
    }
}

use rand::{TryRngCore, rngs::OsRng};

pub fn random_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce).expect("Rng->buffer");
    nonce
}

/// Account for shutdown signals, `ctrl+c`
///
/// TODO: handle OS specific signals
#[cfg(not(target_os = "linux"))]
pub async fn wait_shutdown_signals() {
    // Wait for the Ctrl+C signal.
    let ctrl_c = signal::ctrl_c();

    info!("Listening for shutdown signals (ctrl+c)");

    // Wait for any of the signals to occur.
    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C.");
        }
    }
}

// Stolen from https://github.com/rustls/hyper-rustls/blob/main/examples/server.rs
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
/// Load public certificate from file.
pub fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    // Open certificate file.
    let cert_file = fs::File::open(filename).map_err(|e| {
        let err = format!("failed to open {filename}: {e}");
        io::Error::other(err)
    })?;
    let mut reader = io::BufReader::new(cert_file);

    // Load and return certificate.
    rustls_pemfile::certs(&mut reader).collect()
}

/// Load private key from file.
pub fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    // Open keyfile.
    let keyfile = fs::File::open(filename).map_err(|e| {
        let err = format!("failed to open {filename}: {e}");
        io::Error::other(err)
    })?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
}

/* ---------------- Utility JSON responses ---------------- */

pub type StreamBody = http_body_util::combinators::BoxBody<Bytes, HyperError>;

pub fn json_response(body: Value, status: StatusCode) -> Response<StreamBody> {
    let s = serde_json::to_string(&body).expect("serialize");
    new_response_from(&s, status)
}

pub fn pending_response() -> Response<StreamBody> {
    let raw_json = r#"{ "id": 1, "jsonrpc": "2.0", "status": "[pbs-proxy] Verifiable encryption processing... Call back for result" }"#;
    new_response_from(raw_json, StatusCode::ACCEPTED)
}

pub fn internal_error_response(error: &str) -> Response<StreamBody> {
    let json_obj = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "error": { "message": format!("[pbs-proxy] internal error: {}", error) }
    });
    json_response(json_obj, StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn bad_auth_response() -> Response<StreamBody> {
    warn!("Missing or malformed Authorization header.");
    let raw_json = r#"{ "id": 1, "jsonrpc": "2.0", "error": { "message": "Missing or malformed Authorization header. Expected format: Bearer <token)" } }"#;
    new_response_from(raw_json, StatusCode::UNAUTHORIZED)
}

pub fn new_response_from(raw_json: &str, status: StatusCode) -> Response<StreamBody> {
    let body: StreamBody = Full::new(Bytes::from(raw_json.to_owned()))
        .map_err(|_: std::convert::Infallible| -> HyperError { unreachable!() })
        .boxed();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

pub fn bad_request_response(msg: &str) -> Response<StreamBody> {
    let body = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "error": { "message": msg },
    });
    json_response(body, StatusCode::BAD_REQUEST)
}
