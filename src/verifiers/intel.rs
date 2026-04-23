//! Intel Trust Authority attestation verifier.
//!
//! Posts the TDX quote to Intel's REST API, validates the returned JWT
//! against Intel's JWKS, and maps claims onto a [`VerificationResult`].
//!
//! Mirrors the Python `IntelApiVerifier` in `ra-tls-verify` and the
//! TypeScript version in `prisma-ra-tls/src/verifiers/intel.ts`.

use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::types::{RaTlsVerifier, VerificationResult, VerifyError, VerifyOptions};

/// Intel Trust Authority public endpoint — US region.
pub const ITA_BASE_US: &str = "https://api.trustauthority.intel.com";
/// Intel Trust Authority public endpoint — EU region.
pub const ITA_BASE_EU: &str = "https://api.eu.trustauthority.intel.com";

/// TCB statuses Intel may report that we consider acceptable.
///
/// `OutOfDate` / `Revoked` / `ConfigurationNeeded` / similar are rejected.
/// Callers that need a different policy should implement their own verifier.
const ACCEPTABLE_TCB_STATUSES: &[&str] = &["UpToDate", "SWHardeningNeeded"];

/// HTTP request timeout for the `/appraisal/v2/attest` call.
const ATTEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// HTTP request timeout for the JWKS fetch during token validation.
const JWKS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Attestation region selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    Us,
    Eu,
}

impl Region {
    fn base_url(self) -> &'static str {
        match self {
            Region::Us => ITA_BASE_US,
            Region::Eu => ITA_BASE_EU,
        }
    }
}

/// Verifier backed by Intel Trust Authority.
///
/// Construct with [`IntelApiVerifier::new`] (US region) or
/// [`IntelApiVerifier::with_region`] / [`IntelApiVerifier::with_base_url`] to
/// target a different endpoint (EU, staging, proxy, etc.).
#[derive(Debug, Clone)]
pub struct IntelApiVerifier {
    api_key: String,
    base_url: String,
    http: reqwest::Client,
}

impl IntelApiVerifier {
    /// Build a verifier that targets the US Trust Authority endpoint.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_region(api_key, Region::Us)
    }

    /// Build a verifier for the given region.
    pub fn with_region(api_key: impl Into<String>, region: Region) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: region.base_url().to_string(),
            http: default_http_client(),
        }
    }

    /// Build a verifier with a fully-custom base URL (useful for proxies or
    /// Intel's staging endpoint).
    pub fn with_base_url(api_key: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: base_url.into(),
            http: default_http_client(),
        }
    }

    async fn fetch_token(&self, quote: &[u8]) -> Result<String, VerifyError> {
        #[derive(Serialize)]
        struct AttestRequest<'a> {
            quote: &'a str,
            token_signing_alg: &'a str,
        }
        #[derive(Deserialize)]
        struct AttestResponse {
            token: Option<String>,
        }

        let encoded = base64::engine::general_purpose::STANDARD.encode(quote);
        let req = AttestRequest {
            quote: &encoded,
            token_signing_alg: "PS384",
        };

        let url = format!(
            "{}/appraisal/v2/attest",
            self.base_url.trim_end_matches('/')
        );

        let resp = self
            .http
            .post(url)
            .header("x-api-key", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&req)
            .timeout(ATTEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| VerifyError::Service(format!("attest request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".into());
            return Err(VerifyError::Service(format!(
                "Intel Trust Authority returned {status}: {body}"
            )));
        }

        let body: AttestResponse = resp
            .json()
            .await
            .map_err(|e| VerifyError::Service(format!("decode attest response: {e}")))?;

        body.token
            .ok_or_else(|| VerifyError::Service("attestation response missing token".into()))
    }

    async fn fetch_jwk(&self, jku: &str, kid: &str) -> Result<Jwk, VerifyError> {
        let resp = self
            .http
            .get(jku)
            .header("Accept", "application/json")
            .timeout(JWKS_TIMEOUT)
            .send()
            .await
            .map_err(|e| VerifyError::Service(format!("JWKS fetch failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(VerifyError::Service(format!(
                "JWKS endpoint returned {}",
                resp.status()
            )));
        }

        let set: JwkSet = resp
            .json()
            .await
            .map_err(|e| VerifyError::Service(format!("decode JWKS: {e}")))?;

        set.keys
            .into_iter()
            .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
            .ok_or_else(|| VerifyError::Service(format!("JWKS at {jku} has no key with kid={kid}")))
    }

    async fn validate_token(
        &self,
        token: &str,
        options: &VerifyOptions,
    ) -> Result<VerificationResult, VerifyError> {
        let header = decode_header(token)
            .map_err(|e| VerifyError::Service(format!("decode JWT header: {e}")))?;

        let jku = header
            .jku
            .as_deref()
            .ok_or_else(|| VerifyError::Service("attestation token missing jku header".into()))?;
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| VerifyError::Service("attestation token missing kid header".into()))?;

        let jwk = self.fetch_jwk(jku, kid).await?;
        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|e| VerifyError::Service(format!("build JWT decoding key: {e}")))?;

        // Resolve the signing algorithm from the JWK itself when available
        // so we don't silently accept a weaker algorithm than Intel intended.
        let algorithm = match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => match header.alg {
                Algorithm::PS384 | Algorithm::RS256 => header.alg,
                other => {
                    return Err(VerifyError::Service(format!(
                        "unexpected token algorithm: {other:?}"
                    )))
                }
            },
            other => {
                return Err(VerifyError::Service(format!(
                    "unsupported JWK algorithm: {other:?}"
                )))
            }
        };

        let mut validation = Validation::new(algorithm);
        validation.algorithms = vec![Algorithm::PS384, Algorithm::RS256];
        validation.validate_aud = false;

        let token_data = decode::<serde_json::Value>(token, &decoding_key, &validation)
            .map_err(|e| VerifyError::Service(format!("JWT validation failed: {e}")))?;

        apply_policy(token_data.claims, options)
    }
}

fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("sqlx-ra-tls/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("build reqwest client")
}

fn hex_lower_no_prefix(s: &str) -> String {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    s.to_ascii_lowercase()
}

fn apply_policy(
    claims: serde_json::Value,
    options: &VerifyOptions,
) -> Result<VerificationResult, VerifyError> {
    let is_debug = claims
        .get("tdx_is_debuggable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        || claims
            .get("tdx_td_attributes_debug")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

    if is_debug && !options.allow_debug_mode {
        return Err(VerifyError::DebugMode);
    }

    let tcb_status = claims
        .get("attester_tcb_status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Unknown")
        .to_string();

    if !ACCEPTABLE_TCB_STATUSES.contains(&tcb_status.as_str()) {
        return Err(VerifyError::BadTcbStatus(tcb_status));
    }

    let mr_td = hex_lower_no_prefix(
        claims
            .get("tdx_mrtd")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
    );

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

    let rtmr = |field: &str| -> String {
        hex_lower_no_prefix(
            claims
                .get(field)
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        )
    };

    Ok(VerificationResult {
        mr_td,
        rtmr0: rtmr("tdx_rtmr0"),
        rtmr1: rtmr("tdx_rtmr1"),
        rtmr2: rtmr("tdx_rtmr2"),
        rtmr3: rtmr("tdx_rtmr3"),
        tcb_status,
        is_debug_mode: is_debug,
    })
}

#[async_trait]
impl RaTlsVerifier for IntelApiVerifier {
    async fn verify(
        &self,
        quote: &[u8],
        options: &VerifyOptions,
    ) -> Result<VerificationResult, VerifyError> {
        let token = self.fetch_token(quote).await?;
        self.validate_token(&token, options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn policy_rejects_debug_by_default() {
        let claims = json!({ "tdx_is_debuggable": true, "attester_tcb_status": "UpToDate", "tdx_mrtd": "00" });
        let err = apply_policy(claims, &VerifyOptions::default()).unwrap_err();
        assert!(matches!(err, VerifyError::DebugMode));
    }

    #[test]
    fn policy_accepts_debug_when_allowed() {
        let claims = json!({
            "tdx_is_debuggable": true,
            "attester_tcb_status": "UpToDate",
            "tdx_mrtd": "abcdef",
            "tdx_rtmr0": "00",
            "tdx_rtmr1": "00",
            "tdx_rtmr2": "00",
            "tdx_rtmr3": "00",
        });
        let opts = VerifyOptions {
            allow_debug_mode: true,
            ..Default::default()
        };
        let result = apply_policy(claims, &opts).unwrap();
        assert!(result.is_debug_mode);
        assert_eq!(result.mr_td, "abcdef");
    }

    #[test]
    fn policy_rejects_bad_tcb() {
        let claims = json!({ "attester_tcb_status": "OutOfDate", "tdx_mrtd": "" });
        let err = apply_policy(claims, &VerifyOptions::default()).unwrap_err();
        assert!(matches!(err, VerifyError::BadTcbStatus(s) if s == "OutOfDate"));
    }

    #[test]
    fn policy_normalizes_mrtd_and_allowlist() {
        let claims = json!({
            "attester_tcb_status": "UpToDate",
            "tdx_mrtd": "0xABCDEF",
            "tdx_rtmr0": "0xDEADBEEF",
            "tdx_rtmr1": "00",
            "tdx_rtmr2": "00",
            "tdx_rtmr3": "00",
        });
        let opts = VerifyOptions {
            allowed_mr_td: vec!["abcdef".into(), "0000".into()],
            ..Default::default()
        };
        let result = apply_policy(claims, &opts).unwrap();
        assert_eq!(result.mr_td, "abcdef");
        assert_eq!(result.rtmr0, "deadbeef");
    }

    #[test]
    fn policy_rejects_mrtd_not_in_allowlist() {
        let claims = json!({
            "attester_tcb_status": "UpToDate",
            "tdx_mrtd": "feedface",
        });
        let opts = VerifyOptions {
            allowed_mr_td: vec!["abcdef".into()],
            ..Default::default()
        };
        let err = apply_policy(claims, &opts).unwrap_err();
        assert!(matches!(err, VerifyError::MrtdNotAllowed { mrtd } if mrtd == "feedface"));
    }

    #[test]
    fn policy_accepts_sw_hardening_needed() {
        let claims = json!({
            "attester_tcb_status": "SWHardeningNeeded",
            "tdx_mrtd": "",
            "tdx_rtmr0": "",
            "tdx_rtmr1": "",
            "tdx_rtmr2": "",
            "tdx_rtmr3": "",
        });
        let result = apply_policy(claims, &VerifyOptions::default()).unwrap();
        assert_eq!(result.tcb_status, "SWHardeningNeeded");
    }
}
