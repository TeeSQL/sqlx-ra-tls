//! Regression tests for the P0-1 RA-TLS quote ↔ certificate pubkey binding.
//!
//! Before this fix, `RaTlsVerifier::verify` only proved that *some* TEE
//! produced *some* valid TDX quote at *some* point in the past. The
//! verifier never checked that the quote's `report_data` field committed
//! to the TLS leaf cert's SubjectPublicKeyInfo, so any captured quote
//! could be wrapped inside an attacker-issued cert and replayed.
//!
//! [`RaTlsVerifier::verify_with_pubkey`] closes the gap by asserting
//! `report_data == SHA-512("ratls-cert:" || cert_spki_der)` — the same
//! shape `dstack_attest::Attestation::verify_with_ra_pubkey` enforces in
//! `open-source/dstack/dstack-attest/src/attestation.rs:622-632`.
//!
//! The two regression tests below pin both directions of the binding:
//!
//! 1. **Matching pubkey → succeeds**: a quote whose `report_data` was
//!    constructed for cert A should verify under cert A.
//! 2. **Mismatched pubkey → fails with [`VerifyError::PubkeyMismatch`]**:
//!    the same quote handed to a verifier with cert B (the
//!    replay-attempt simulation) must reject.
//!
//! Tests use a real TDX-V4 quote fixture (the same one
//! `dcap_roundtrip.rs` and `tests/fixtures/tdx_quote` use) parsed,
//! mutated to substitute a controllable `report_data`, then re-encoded
//! via `parity-scale-codec`. The DCAP signature path is intentionally
//! bypassed — these tests exercise the binding logic, not Intel's TCB
//! chain — by routing through the trait's default implementation against
//! a `MockVerifier` that always returns `Ok`. The default impl is the
//! hot path for any future verifier; pinning it here protects new
//! adapters from regressing the gap.

#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use dcap_qvl::quote::{Quote, Report, TDReport10};
use parity_scale_codec::Encode;
use rcgen::{CertificateParams, KeyPair};
use sqlx_ra_tls::types::{
    expected_report_data_for_pubkey, RaTlsVerifier, VerificationResult, VerifyError, VerifyOptions,
};

const REAL_TDX_QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote");

/// Always-Ok verifier used to isolate the binding-check from DCAP
/// signature verification. Inherits the default `verify_with_pubkey`
/// implementation from the trait — that is precisely the code under
/// test.
struct MockVerifier;

#[async_trait]
impl RaTlsVerifier for MockVerifier {
    async fn verify(
        &self,
        _quote: &[u8],
        _options: &VerifyOptions,
    ) -> Result<VerificationResult, VerifyError> {
        Ok(VerificationResult {
            mr_td: "0".repeat(96),
            rtmr0: "0".repeat(96),
            rtmr1: "0".repeat(96),
            rtmr2: "0".repeat(96),
            rtmr3: "0".repeat(96),
            tcb_status: "UpToDate".to_string(),
            is_debug_mode: false,
        })
    }
}

/// Build a self-signed cert (DER) and return both the cert bytes and
/// the SubjectPublicKeyInfo DER bytes that should be hashed for the
/// binding.
fn fresh_cert_with_spki() -> (Vec<u8>, Vec<u8>) {
    let key_pair = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec!["test.invalid".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = cert.der().to_vec();

    // Re-parse to extract the SPKI; matches what the verifier does in
    // `extract_spki_der`.
    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(&cert_der).unwrap();
    let spki = parsed.tbs_certificate.subject_pki.raw.to_vec();
    (cert_der, spki)
}

/// Re-encode the real TDX V4 fixture quote with `report_data` replaced
/// by the supplied 64-byte slot. Preserves all other fields (mr_td,
/// rtmrs, signatures, etc.) so the result still parses cleanly through
/// `dcap_qvl::quote::Quote::parse`.
fn quote_with_report_data(new_report_data: [u8; 64]) -> Vec<u8> {
    let mut quote = Quote::parse(REAL_TDX_QUOTE).unwrap();
    match &mut quote.report {
        Report::TD10(r) => {
            *r = TDReport10 {
                report_data: new_report_data,
                ..*r
            };
        }
        Report::TD15(r) => {
            r.base.report_data = new_report_data;
        }
        Report::SgxEnclave(_) => panic!("fixture is not TDX"),
    }
    quote.encode()
}

#[tokio::test]
async fn verify_with_pubkey_accepts_matching_cert() {
    let (cert_der, spki_der) = fresh_cert_with_spki();
    let report_data = expected_report_data_for_pubkey(&spki_der);
    let quote = quote_with_report_data(report_data);

    let verifier = MockVerifier;
    let result = verifier
        .verify_with_pubkey(&quote, &VerifyOptions::default(), &cert_der)
        .await
        .expect("matching pubkey + report_data should succeed");

    // The MockVerifier returns canned values, so just assert we got
    // something through — the value itself isn't load-bearing for the
    // binding test.
    assert_eq!(result.tcb_status, "UpToDate");
}

#[tokio::test]
async fn verify_with_pubkey_rejects_replay_with_different_cert() {
    // Step 1: build cert A and a quote whose report_data was generated
    // for cert A's pubkey. Imagine an attacker captured this
    // (cert_a, quote) pair from a real handshake.
    let (_cert_a_der, spki_a_der) = fresh_cert_with_spki();
    let report_data_for_a = expected_report_data_for_pubkey(&spki_a_der);
    let captured_quote = quote_with_report_data(report_data_for_a);

    // Step 2: the attacker now wraps that quote inside their own freshly
    // issued cert B (different keypair → different SPKI → different
    // expected report_data) and presents (cert_b, captured_quote) to
    // the verifier. The binding check MUST refuse.
    let (cert_b_der, _spki_b_der) = fresh_cert_with_spki();

    let verifier = MockVerifier;
    let err = verifier
        .verify_with_pubkey(&captured_quote, &VerifyOptions::default(), &cert_b_der)
        .await
        .expect_err("replay attempt with different cert must be rejected");

    assert!(
        matches!(err, VerifyError::PubkeyMismatch),
        "expected VerifyError::PubkeyMismatch, got: {err:?}"
    );

    let msg = format!("{err}");
    assert!(
        msg.contains("does not bind"),
        "error message should explain the binding failure, got: {msg}"
    );
}

#[tokio::test]
async fn verify_with_pubkey_rejects_zero_report_data_against_real_cert() {
    // The fixture quote ships with whatever report_data its source CVM
    // emitted. Hand that quote to the verifier alongside a freshly
    // generated cert and the binding MUST fail — the cert was never
    // bound to that report_data.
    let (cert_der, _spki_der) = fresh_cert_with_spki();

    let verifier = MockVerifier;
    let err = verifier
        .verify_with_pubkey(REAL_TDX_QUOTE, &VerifyOptions::default(), &cert_der)
        .await
        .expect_err("real quote with arbitrary cert must be rejected");

    assert!(
        matches!(err, VerifyError::PubkeyMismatch),
        "expected VerifyError::PubkeyMismatch, got: {err:?}"
    );
}

#[test]
fn expected_report_data_matches_dstack_format() {
    // Pin the on-wire format so any drift from
    // `dstack_attest::QuoteContentType::RaTlsCert.to_report_data` is
    // caught at compile time of this crate. The Go SDK at
    // `open-source/dstack/sdk/go/ratls/ratls.go:108-114` performs the
    // identical computation:
    //
    //   h := sha512.New()
    //   h.Write([]byte("ratls-cert:"))
    //   h.Write(cert.RawSubjectPublicKeyInfo)
    //   expected := h.Sum(nil)
    //
    // Compute against a known input and assert the first / last bytes
    // agree with an independently-computed SHA-512.
    use sha2::{Digest, Sha512};

    let spki = b"some-fake-spki-der-bytes-just-for-the-hash";
    let actual = expected_report_data_for_pubkey(spki);

    let mut h = Sha512::new();
    h.update(b"ratls-cert:");
    h.update(spki);
    let expected: [u8; 64] = h.finalize().into();

    assert_eq!(actual, expected, "binding hash must match dstack format");
    // SHA-512 fills the entire 64-byte report_data slot — no padding.
    assert_eq!(actual.len(), 64);
}
