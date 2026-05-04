//! Shared types for RA-TLS attestation verification.
//!
//! Mirrors the data model used by the Python `ra-tls-verify` and the TypeScript
//! `prisma-ra-tls` SDKs so results are comparable across languages.

use async_trait::async_trait;
use sha2::{Digest, Sha512};
use x509_parser::prelude::*;

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
    /// The TDX quote's `report_data` field does not commit to the TLS leaf
    /// certificate's SubjectPublicKeyInfo. Without this binding a captured
    /// quote can be replayed by any party that wraps it in a fresh self-signed
    /// cert; see `dstack-attest::Attestation::verify_with_ra_pubkey` for the
    /// canonical shape this check reproduces.
    #[error(
        "quote report_data does not bind the TLS certificate's public key (replay-attack guard)"
    )]
    PubkeyMismatch,
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
///
/// # Replay-attack guard
///
/// Every TLS callsite MUST use [`RaTlsVerifier::verify_with_pubkey`], not
/// the bare [`RaTlsVerifier::verify`]. A successful `verify` only proves
/// that *some* TEE produced *some* valid quote, sometime — a captured
/// quote can be wrapped inside a fresh self-signed cert by anyone holding
/// it. The pubkey-bound variant additionally asserts that the quote's
/// `report_data` field commits to the TLS leaf cert's
/// SubjectPublicKeyInfo, anchoring the quote to *this* TLS session.
///
/// `verify` is retained for non-TLS callers (CLI quote inspection,
/// out-of-band attestation tooling) and so `verify_with_pubkey` can be
/// implemented as a default that wraps it. New TLS adapters should never
/// call `verify` directly.
#[async_trait]
pub trait RaTlsVerifier: Send + Sync + 'static {
    async fn verify(
        &self,
        quote: &[u8],
        options: &VerifyOptions,
    ) -> Result<VerificationResult, VerifyError>;

    /// Verify a quote and additionally bind it to the TLS leaf cert's
    /// public key.
    ///
    /// `cert_der` is the DER-encoded leaf certificate captured during the
    /// TLS handshake (e.g. via the rustls `LeafCaptureVerifier` shim used
    /// by the connector and forwarder). The default implementation:
    ///
    /// 1. Calls [`verify`] for the existing TCB / debug / MRTD checks.
    /// 2. Parses the cert and extracts its
    ///    SubjectPublicKeyInfo (SPKI) DER bytes.
    /// 3. Computes
    ///    `expected = SHA-512("ratls-cert:" || spki_der)` — matching
    ///    `dstack_attest::QuoteContentType::RaTlsCert::to_report_data`
    ///    (`open-source/dstack/dstack-attest/src/attestation.rs:622-632`,
    ///    cross-checked against the Go SDK at
    ///    `open-source/dstack/sdk/go/ratls/ratls.go:108-121`).
    /// 4. Parses the quote and extracts its 64-byte `report_data` field.
    /// 5. Returns [`VerifyError::PubkeyMismatch`] if `expected !=
    ///    report_data`.
    ///
    /// Implementations that need a single-pass DCAP roundtrip (skipping
    /// the duplicate `verify_inner` call the default does) may override
    /// this; [`super::DcapVerifier`] does so for clarity at the binding
    /// site, but the default is correct and replay-safe for any verifier
    /// that implements `verify`.
    async fn verify_with_pubkey(
        &self,
        quote: &[u8],
        options: &VerifyOptions,
        cert_der: &[u8],
    ) -> Result<VerificationResult, VerifyError> {
        let result = self.verify(quote, options).await?;
        let report_data = extract_report_data_from_quote(quote)?;
        let spki_der = extract_spki_der(cert_der)?;
        let expected = expected_report_data_for_pubkey(&spki_der);
        if expected != report_data {
            return Err(VerifyError::PubkeyMismatch);
        }
        Ok(result)
    }
}

/// Compute the expected 64-byte `report_data` value that a TDX quote
/// should carry to bind itself to a TLS cert with the given
/// SubjectPublicKeyInfo DER bytes.
///
/// Matches the dstack reference at
/// `open-source/dstack/dstack-attest/src/attestation.rs:218-287`
/// (`QuoteContentType::RaTlsCert.to_report_data` →
/// `SHA-512("ratls-cert:" || spki_der)`). SHA-512's 64-byte output fills
/// the entire `report_data` slot with no padding.
pub fn expected_report_data_for_pubkey(spki_der: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(b"ratls-cert:");
    hasher.update(spki_der);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Extract the 64-byte `report_data` field from a raw TDX quote.
///
/// Accepts both TDX V4 (TD report 1.0) and V5 (TD report 1.0 / 1.5)
/// shapes — they all carry the same `report_data` slot at the end of the
/// TD report struct. SGX quotes are rejected because the rest of the
/// stack only handles TDX peers.
pub(crate) fn extract_report_data_from_quote(quote: &[u8]) -> Result<[u8; 64], VerifyError> {
    use dcap_qvl::quote::{Quote, Report};

    let parsed = Quote::parse(quote)
        .map_err(|e| VerifyError::Service(format!("parse quote for pubkey binding: {e:?}")))?;
    match parsed.report {
        Report::TD10(r) => Ok(r.report_data),
        Report::TD15(r) => Ok(r.base.report_data),
        Report::SgxEnclave(_) => Err(VerifyError::Service(
            "expected a TDX quote, got an SGX enclave report".into(),
        )),
    }
}

/// Extract the DER-encoded SubjectPublicKeyInfo (SPKI) from a leaf
/// certificate's DER bytes.
///
/// Returns the *whole* SPKI DER (the same `RawSubjectPublicKeyInfo` field
/// the Go SDK hashes at `open-source/dstack/sdk/go/ratls/ratls.go:113`,
/// and the same `cert.public_key().raw` the Rust dstack-attest reference
/// hashes at `attestation.rs:627`). Hashing the SPKI rather than just the
/// raw key bytes commits the algorithm identifier as well, so swapping
/// curves on a captured key cannot bypass the check.
pub(crate) fn extract_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| VerifyError::Service(format!("parse leaf cert for pubkey binding: {e}")))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}
