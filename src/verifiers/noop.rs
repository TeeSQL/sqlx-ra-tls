//! Verifier that never fails. For tests and local development only.
//!
//! `NoopVerifier` emits a `log::warn!` on construction so production
//! deployments that wire it by mistake leave a breadcrumb in their logs.

use async_trait::async_trait;

use crate::types::{RaTlsVerifier, VerificationResult, VerifyError, VerifyOptions};

/// Dev-only verifier. Accepts every quote. Do not use in production.
#[derive(Debug, Clone, Default)]
pub struct NoopVerifier {
    _private: (),
}

impl NoopVerifier {
    /// Build a new `NoopVerifier`, logging a warning so operators that wire
    /// it by mistake notice at startup.
    pub fn new() -> Self {
        log::warn!(
            "sqlx-ra-tls: NoopVerifier constructed — attestation checks are disabled. \
             This verifier is for development and tests only. Never use in production."
        );
        Self { _private: () }
    }
}

#[async_trait]
impl RaTlsVerifier for NoopVerifier {
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

    /// Dev-only override: accept any quote ↔ cert pairing without
    /// running the binding check. The default trait impl would parse the
    /// quote and the cert and compare hashes; in dev/simulator paths the
    /// quote is often an empty placeholder and the cert is a self-signed
    /// rcgen cert with no `report_data` baked in, so the binding check
    /// would always fail. The constructor's loud `log::warn!` is the
    /// breadcrumb operators get if they wire this in production by
    /// accident.
    async fn verify_with_pubkey(
        &self,
        quote: &[u8],
        options: &VerifyOptions,
        _cert_der: &[u8],
    ) -> Result<VerificationResult, VerifyError> {
        self.verify(quote, options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_always_succeeds() {
        let v = NoopVerifier::new();
        let result = v
            .verify(&[1, 2, 3], &VerifyOptions::default())
            .await
            .unwrap();
        assert_eq!(result.mr_td.len(), 96);
        assert_eq!(result.tcb_status, "UpToDate");
        assert!(!result.is_debug_mode);
    }
}
