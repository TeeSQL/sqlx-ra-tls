//! Shared types for RA-TLS attestation verification.
//!
//! Mirrors the data model used by the Python `ra-tls-verify` and the TypeScript
//! `prisma-ra-tls` SDKs so results are comparable across languages.

use async_trait::async_trait;

/// Options passed to a verifier on every verification call.
///
/// - `allowed_mr_td`: if non-empty, the server's MRTD must match one of the
///   entries (case-insensitive, with or without a `0x` prefix). An empty list
///   accepts any MRTD — not recommended for production.
/// - `allow_debug_mode`: if `false`, a debug-mode TD is rejected. Debug TDs
///   have no confidentiality guarantees and must never be allowed in
///   production.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub allowed_mr_td: Vec<String>,
    pub allow_debug_mode: bool,
}

/// Successful verification output. All fields are lowercase hex strings
/// (no `0x` prefix) so they can be compared with simple equality.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub mr_td: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
    pub tcb_status: String,
    pub is_debug_mode: bool,
}

/// Errors surfaced by a verifier. Any other error — transport, parsing, API —
/// should be wrapped in `Other`.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("TDX TD is in debug mode; set allow_debug_mode=true to override")]
    DebugMode,
    #[error("unacceptable TCB status: {0}")]
    BadTcbStatus(String),
    #[error("MRTD {mrtd} not in allowlist")]
    MrtdNotAllowed { mrtd: String },
    #[error("attestation service error: {0}")]
    Service(String),
    #[error("{0}")]
    Other(String),
}

/// Interface implemented by attestation verifiers.
///
/// The verifier is async and thread-safe so it can be shared across an
/// `Arc` inside the connection pool. Implementations should validate the
/// quote using whatever backend they target (Intel Trust Authority, a local
/// DCAP service, etc.) and return either a populated `VerificationResult`
/// or a descriptive error.
#[async_trait]
pub trait RaTlsVerifier: Send + Sync + 'static {
    async fn verify(
        &self,
        quote: &[u8],
        options: &VerifyOptions,
    ) -> Result<VerificationResult, VerifyError>;
}
