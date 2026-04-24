//! End-to-end DCAP roundtrip tests for [`sqlx_ra_tls::DcapVerifier`].
//!
//! Drives a real, known-good TDX quote (lifted from the
//! [`dcap-qvl`](https://crates.io/crates/dcap-qvl) crate's own
//! `sample/` directory) through the full local-DCAP pipeline:
//!
//! 1. Parse the quote.
//! 2. Verify it against the bundled `QuoteCollateralV3`, evaluated
//!    inside the collateral's validity window.
//! 3. Apply the same policy checks `DcapVerifier::verify` runs
//!    online, but driven via `verify_with_collateral` so the test
//!    has no PCCS network dependency.
//!
//! The fixture covers a non-debug TD with `tcb_status = "UpToDate"` so
//! it exercises the happy path. Edge-case policy behavior (debug
//! mode, bad TCB status, MRTD allowlist) is covered by the unit
//! tests in `src/verifiers/dcap.rs`.

#![allow(clippy::unwrap_used)]

use chrono::DateTime;
use dcap_qvl::QuoteCollateralV3;
use der::Decode as _;
use serde_json::Value;
use sqlx_ra_tls::{DcapVerifier, VerifyOptions};
use x509_cert::crl::CertificateList;

const TDX_QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote");
const TDX_COLLATERAL_JSON: &[u8] = include_bytes!("fixtures/tdx_quote_collateral.json");

/// Compute a `now` timestamp that lies inside every collateral
/// item's validity window — TCB info, QE identity, *and* both CRLs.
/// Mirrors the helper in `dcap-qvl`'s own `tests/verify_quote.rs`.
fn now_inside_collateral_window(collateral: &QuoteCollateralV3) -> u64 {
    fn parse_window(json_str: &str) -> (u64, u64) {
        let v: Value = serde_json::from_str(json_str).unwrap();
        let issue = v["issueDate"].as_str().unwrap();
        let next = v["nextUpdate"].as_str().unwrap();
        let issue_ts = DateTime::parse_from_rfc3339(issue).unwrap().timestamp() as u64;
        let next_ts = DateTime::parse_from_rfc3339(next).unwrap().timestamp() as u64;
        (issue_ts, next_ts)
    }

    fn parse_crl_bounds(crl_der: &[u8]) -> (u64, Option<u64>) {
        let crl = CertificateList::from_der(crl_der).unwrap();
        let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        let next_update = crl
            .tbs_cert_list
            .next_update
            .map(|t| t.to_unix_duration().as_secs());
        (this_update, next_update)
    }

    let (tcb_issue, tcb_next) = parse_window(&collateral.tcb_info);
    let (qe_issue, qe_next) = parse_window(&collateral.qe_identity);
    let mut not_before = tcb_issue.max(qe_issue);
    let mut not_after = tcb_next.min(qe_next);

    for crl_der in [&collateral.root_ca_crl[..], &collateral.pck_crl[..]] {
        let (this_update, next_update) = parse_crl_bounds(crl_der);
        not_before = not_before.max(this_update);
        if let Some(next) = next_update {
            not_after = not_after.min(next);
        }
    }

    assert!(
        not_before <= not_after,
        "fixture collateral validity window invalid"
    );
    if not_after > not_before {
        not_after - 1
    } else {
        not_after
    }
}

#[tokio::test]
async fn dcap_verifier_accepts_known_good_tdx_quote() {
    let collateral: QuoteCollateralV3 = serde_json::from_slice(TDX_COLLATERAL_JSON).unwrap();
    let now = now_inside_collateral_window(&collateral);

    let verifier = DcapVerifier::new();
    let result = verifier
        .verify_with_collateral(TDX_QUOTE, &collateral, now, &VerifyOptions::default())
        .expect("known-good TDX quote should verify");

    // MRTD / RTMR values for the bundled `dcap-qvl` TDX sample. If
    // this fixture is ever swapped, regenerate via:
    //   `cargo run --example print_tdx_claims --release` (or similar
    //   one-shot using `Quote::decode` + `Report::as_td10`).
    assert_eq!(
        result.mr_td,
        "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7"
    );
    assert_eq!(
        result.rtmr0,
        "44c0197b39157fdd7a4dcc44767f9d6b0bb3977c7a8e347b8492f827fe9d9e5c48aca29b220b80b6a540cf994b9bc9c0"
    );
    assert_eq!(
        result.rtmr1,
        "0084452c01668329d4bc06acdf58a7205c26743304509973949e5619bf81a6a7aea8c323c173019b3093d54e579e9378"
    );
    assert_eq!(
        result.rtmr2,
        "d833feef2cd945148aa38ead2c53e9b7f138190aaaebfc551dccd829fc207aa3ba80b70870d7330733642e01d48c3132"
    );
    assert_eq!(result.rtmr3, "0".repeat(96));
    assert_eq!(result.tcb_status, "UpToDate");
    assert!(!result.is_debug_mode);
}

#[tokio::test]
async fn dcap_verifier_rejects_when_mrtd_not_allowed() {
    let collateral: QuoteCollateralV3 = serde_json::from_slice(TDX_COLLATERAL_JSON).unwrap();
    let now = now_inside_collateral_window(&collateral);

    let verifier = DcapVerifier::new();
    let opts = VerifyOptions {
        allowed_mr_td: vec!["deadbeef".into()],
        ..Default::default()
    };
    let err = verifier
        .verify_with_collateral(TDX_QUOTE, &collateral, now, &opts)
        .expect_err("MRTD allowlist mismatch must reject");

    let msg = format!("{err}");
    assert!(
        msg.to_ascii_lowercase().contains("not in allowlist"),
        "{msg}"
    );
}

#[tokio::test]
async fn dcap_verifier_accepts_when_mrtd_in_allowlist_with_prefix() {
    let collateral: QuoteCollateralV3 = serde_json::from_slice(TDX_COLLATERAL_JSON).unwrap();
    let now = now_inside_collateral_window(&collateral);

    let verifier = DcapVerifier::new();
    let opts = VerifyOptions {
        // Same MRTD as the fixture, but in upper-case with `0X`
        // prefix to exercise the case-insensitive normalization.
        allowed_mr_td: vec![
            "0X91EB2B44D141D4ECE09F0C75C2C53D247A3C68EDD7FAFE8A3520C942A604A407DE03AE6DC5F87F27428B2538873118B7".into(),
        ],
        ..Default::default()
    };
    let result = verifier
        .verify_with_collateral(TDX_QUOTE, &collateral, now, &opts)
        .expect("uppercase + prefixed MRTD allowlist must match");
    assert_eq!(result.tcb_status, "UpToDate");
}

/// Live test: end-to-end through the full `DcapVerifier::verify` path
/// (which fetches collateral from PCCS over the network). Disabled by
/// default because it depends on outbound HTTPS to Intel PCS or the
/// configured PCCS mirror. Run with:
///
/// ```bash
/// cargo test --test dcap_roundtrip -- --ignored
/// ```
#[tokio::test]
#[ignore = "requires outbound HTTPS to Intel PCS / PCCS"]
async fn dcap_verifier_live_pccs_roundtrip() {
    use sqlx_ra_tls::RaTlsVerifier;

    let pccs_url =
        std::env::var("PCCS_URL").unwrap_or_else(|_| sqlx_ra_tls::DEFAULT_PCCS_URL.to_string());
    let verifier = DcapVerifier::with_pccs_url(pccs_url);

    let result = verifier
        .verify(TDX_QUOTE, &VerifyOptions::default())
        .await
        .expect("live PCCS verify");

    assert_eq!(
        result.mr_td,
        "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7"
    );
    assert_eq!(result.tcb_status, "UpToDate");
}
