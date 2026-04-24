//! Local DCAP attestation verifier.
//!
//! Verifies a TDX quote end-to-end against Intel's trusted root CA using
//! the pure-Rust [`dcap-qvl`](https://crates.io/crates/dcap-qvl) crate —
//! the same library `dstack-verifier` uses.
//!
//! Unlike [`super::IntelApiVerifier`], `DcapVerifier` does not require an
//! Intel Trust Authority API key or any account on Intel's services. It
//! does need to reach a PCCS (Provisioning Certification Caching Service)
//! endpoint to fetch platform collateral; the default is Intel's public
//! PCS at `https://api.trustedservices.intel.com`.
//!
//! Claim mapping mirrors `IntelApiVerifier::apply_policy` so callers can
//! switch between the two without touching `VerifyOptions.allowed_mr_td`,
//! debug-mode handling, or the acceptable-TCB allowlist.

use std::time::SystemTime;

use async_trait::async_trait;
use dcap_qvl::collateral::CollateralClient;
use dcap_qvl::quote::Report;
use dcap_qvl::verify::{self, VerifiedReport};
use dcap_qvl::QuoteCollateralV3;

use crate::types::{RaTlsVerifier, VerificationResult, VerifyError, VerifyOptions};

/// Default PCCS endpoint — Intel's public Provisioning Certification
/// Service. Override with [`DcapVerifier::with_pccs_url`] if you operate
/// a private PCCS or want to use the Phala mirror
/// (`https://pccs.phala.network`).
pub const DEFAULT_PCCS_URL: &str = "https://api.trustedservices.intel.com";

/// TCB statuses we accept. Identical to
/// [`super::IntelApiVerifier`]'s policy so the two verifiers are
/// drop-in interchangeable.
const ACCEPTABLE_TCB_STATUSES: &[&str] = &["UpToDate", "SWHardeningNeeded"];

/// Verifier that performs offline DCAP quote verification.
///
/// Construct with [`DcapVerifier::new`] for the default Intel PCS, or
/// [`DcapVerifier::with_pccs_url`] to point at a custom PCCS.
///
/// The verifier is `Send + Sync + 'static` so it can be wrapped in an
/// `Arc` and shared across a connection pool.
#[derive(Debug, Clone)]
pub struct DcapVerifier {
    pccs_url: String,
}

impl Default for DcapVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DcapVerifier {
    /// Build a verifier targeting the default Intel PCS endpoint.
    pub fn new() -> Self {
        Self {
            pccs_url: DEFAULT_PCCS_URL.to_string(),
        }
    }

    /// Build a verifier targeting a custom PCCS URL.
    ///
    /// Examples:
    ///
    /// ```rust
    /// use sqlx_ra_tls::DcapVerifier;
    ///
    /// // Phala's public PCCS mirror.
    /// let v = DcapVerifier::with_pccs_url("https://pccs.phala.network");
    /// // A self-hosted PCCS.
    /// let v = DcapVerifier::with_pccs_url("https://pccs.local:8081");
    /// # let _ = v;
    /// ```
    pub fn with_pccs_url(pccs_url: impl Into<String>) -> Self {
        Self {
            pccs_url: pccs_url.into(),
        }
    }

    /// PCCS URL this verifier was constructed with.
    pub fn pccs_url(&self) -> &str {
        &self.pccs_url
    }

    async fn verify_inner(&self, quote: &[u8]) -> Result<VerifiedReport, VerifyError> {
        let collateral = CollateralClient::with_default_http(self.pccs_url.clone())
            .map_err(|e| VerifyError::Service(format!("build PCCS client: {e}")))?
            .fetch(quote)
            .await
            .map_err(|e| VerifyError::Service(format!("fetch PCCS collateral: {e:#}")))?;

        let now_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| VerifyError::Service(format!("system clock before UNIX epoch: {e}")))?
            .as_secs();

        verify::verify(quote, &collateral, now_secs)
            .map_err(|e| VerifyError::Service(format!("DCAP quote verification failed: {e:#}")))
    }

    /// Verify a quote against a caller-supplied [`QuoteCollateralV3`]
    /// at a caller-supplied timestamp.
    ///
    /// Skips the PCCS round trip entirely — useful for callers that
    /// keep a per-FMSPC collateral cache, or for offline / air-gapped
    /// verification of a quote whose collateral was fetched out of
    /// band.
    ///
    /// `now_secs` is the wall-clock time at which to evaluate the
    /// collateral's validity window (must lie between each item's
    /// `issueDate` and `nextUpdate`). For the default
    /// "verify against the current clock" behavior, see
    /// [`Self::verify`].
    pub fn verify_with_collateral(
        &self,
        quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
        options: &VerifyOptions,
    ) -> Result<VerificationResult, VerifyError> {
        let verified = verify::verify(quote, collateral, now_secs)
            .map_err(|e| VerifyError::Service(format!("DCAP quote verification failed: {e:#}")))?;
        apply_policy(&verified, options)
    }
}

#[async_trait]
impl RaTlsVerifier for DcapVerifier {
    async fn verify(
        &self,
        quote: &[u8],
        options: &VerifyOptions,
    ) -> Result<VerificationResult, VerifyError> {
        let verified = self.verify_inner(quote).await?;
        apply_policy(&verified, options)
    }
}

/// Map a [`VerifiedReport`] into a [`VerificationResult`], applying the
/// same policy as [`super::IntelApiVerifier::apply_policy`]:
/// reject debug TDs unless explicitly allowed, reject TCB statuses
/// outside the [`ACCEPTABLE_TCB_STATUSES`] list, enforce
/// `VerifyOptions.allowed_mr_td` when non-empty.
fn apply_policy(
    report: &VerifiedReport,
    options: &VerifyOptions,
) -> Result<VerificationResult, VerifyError> {
    let td_report = match &report.report {
        Report::TD10(r) => r,
        Report::TD15(r) => &r.base,
        Report::SgxEnclave(_) => {
            return Err(VerifyError::Service(
                "expected a TDX quote, got an SGX enclave report".into(),
            ))
        }
    };

    // TD attributes layout: byte 0, bit 0 is the DEBUG flag.
    // dstack's `validate_tcb` (dstack-attest/src/attestation.rs) and
    // Intel's TDX Module Spec both define this bit.
    let is_debug = td_report.td_attributes[0] & 0x01 != 0;

    if is_debug && !options.allow_debug_mode {
        return Err(VerifyError::DebugMode);
    }

    let tcb_status = report.status.clone();

    if !ACCEPTABLE_TCB_STATUSES.contains(&tcb_status.as_str()) {
        return Err(VerifyError::BadTcbStatus(tcb_status));
    }

    let mr_td = hex::encode(td_report.mr_td);

    if !options.allowed_mr_td.is_empty() {
        let allowlist: Vec<String> = options
            .allowed_mr_td
            .iter()
            .map(|s| hex_lower_no_prefix(s))
            .collect();
        if !allowlist.contains(&mr_td) {
            return Err(VerifyError::MrtdNotAllowed { mrtd: mr_td });
        }
    }

    Ok(VerificationResult {
        mr_td,
        rtmr0: hex::encode(td_report.rt_mr0),
        rtmr1: hex::encode(td_report.rt_mr1),
        rtmr2: hex::encode(td_report.rt_mr2),
        rtmr3: hex::encode(td_report.rt_mr3),
        tcb_status,
        is_debug_mode: is_debug,
    })
}

/// Normalize an MRTD (or any hex string) for case-insensitive comparison
/// with `hex::encode` output: strip `0x`/`0X` and lowercase. Identical to
/// `IntelApiVerifier`'s helper of the same name.
fn hex_lower_no_prefix(s: &str) -> String {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    s.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_qvl::quote::TDReport10;
    use dcap_qvl::tcb_info::TcbStatusWithAdvisory;

    fn td10_with_attrs(td_attributes: [u8; 8], mr_td: [u8; 48]) -> TDReport10 {
        TDReport10 {
            tee_tcb_svn: [0u8; 16],
            mr_seam: [0u8; 48],
            mr_signer_seam: [0u8; 48],
            seam_attributes: [0u8; 8],
            td_attributes,
            xfam: [0u8; 8],
            mr_td,
            mr_config_id: [0u8; 48],
            mr_owner: [0u8; 48],
            mr_owner_config: [0u8; 48],
            rt_mr0: [0xaa; 48],
            rt_mr1: [0xbb; 48],
            rt_mr2: [0xcc; 48],
            rt_mr3: [0xdd; 48],
            report_data: [0u8; 64],
        }
    }

    fn report_with(status: &str, td_report: TDReport10) -> VerifiedReport {
        // `dcap_qvl::tcb_info::TcbStatus` only exposes a small enumerated
        // set, but `VerifiedReport.status` is the human-readable string,
        // so we synthesise it directly.
        VerifiedReport {
            status: status.to_string(),
            advisory_ids: Vec::new(),
            report: Report::TD10(td_report),
            ppid: vec![0u8; 16],
            qe_status: TcbStatusWithAdvisory::new(
                dcap_qvl::tcb_info::TcbStatus::UpToDate,
                Vec::new(),
            ),
            platform_status: TcbStatusWithAdvisory::new(
                dcap_qvl::tcb_info::TcbStatus::UpToDate,
                Vec::new(),
            ),
        }
    }

    #[test]
    fn policy_rejects_debug_by_default() {
        let report = report_with(
            "UpToDate",
            td10_with_attrs([0x01, 0, 0, 0, 0, 0, 0, 0], [0; 48]),
        );
        let err = apply_policy(&report, &VerifyOptions::default()).unwrap_err();
        assert!(matches!(err, VerifyError::DebugMode));
    }

    #[test]
    fn policy_accepts_debug_when_allowed() {
        let mut mr = [0u8; 48];
        mr[..3].copy_from_slice(&[0xab, 0xcd, 0xef]);
        let report = report_with("UpToDate", td10_with_attrs([0x01, 0, 0, 0, 0, 0, 0, 0], mr));
        let opts = VerifyOptions {
            allow_debug_mode: true,
            ..Default::default()
        };
        let result = apply_policy(&report, &opts).unwrap();
        assert!(result.is_debug_mode);
        assert!(result.mr_td.starts_with("abcdef"));
    }

    #[test]
    fn policy_rejects_bad_tcb() {
        let report = report_with("OutOfDate", td10_with_attrs([0; 8], [0; 48]));
        let err = apply_policy(&report, &VerifyOptions::default()).unwrap_err();
        assert!(matches!(err, VerifyError::BadTcbStatus(s) if s == "OutOfDate"));
    }

    #[test]
    fn policy_normalizes_mrtd_and_allowlist() {
        let mut mr = [0u8; 48];
        mr[..3].copy_from_slice(&[0xab, 0xcd, 0xef]);
        let report = report_with("UpToDate", td10_with_attrs([0; 8], mr));

        let mr_hex_no_prefix = hex::encode(mr);
        let mr_hex_with_prefix = format!("0X{}", mr_hex_no_prefix.to_ascii_uppercase());

        let opts = VerifyOptions {
            allowed_mr_td: vec![mr_hex_with_prefix, "0000".into()],
            ..Default::default()
        };
        let result = apply_policy(&report, &opts).unwrap();
        assert!(result.mr_td.starts_with("abcdef"));
        // RTMR0 was set to 0xaa repeating 48 times by the helper.
        assert_eq!(result.rtmr0, hex::encode([0xaa; 48]));
    }

    #[test]
    fn policy_rejects_mrtd_not_in_allowlist() {
        let mut mr = [0u8; 48];
        mr[..3].copy_from_slice(&[0xfe, 0xed, 0xfa]);
        let report = report_with("UpToDate", td10_with_attrs([0; 8], mr));
        let opts = VerifyOptions {
            allowed_mr_td: vec!["abcdef".into()],
            ..Default::default()
        };
        let err = apply_policy(&report, &opts).unwrap_err();
        assert!(matches!(err, VerifyError::MrtdNotAllowed { mrtd } if mrtd.starts_with("feedfa")));
    }

    #[test]
    fn policy_accepts_sw_hardening_needed() {
        let report = report_with("SWHardeningNeeded", td10_with_attrs([0; 8], [0; 48]));
        let result = apply_policy(&report, &VerifyOptions::default()).unwrap();
        assert_eq!(result.tcb_status, "SWHardeningNeeded");
        assert!(!result.is_debug_mode);
    }

    #[test]
    fn default_pccs_url_points_at_intel_public() {
        let v = DcapVerifier::new();
        assert_eq!(v.pccs_url(), "https://api.trustedservices.intel.com");
    }

    #[test]
    fn with_pccs_url_overrides_default() {
        let v = DcapVerifier::with_pccs_url("https://pccs.phala.network");
        assert_eq!(v.pccs_url(), "https://pccs.phala.network");
    }
}
