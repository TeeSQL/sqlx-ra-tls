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
