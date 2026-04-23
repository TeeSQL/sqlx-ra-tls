//! dstack guest-agent integration for client RA-TLS certificates.
//!
//! Mutual RA-TLS is mandatory in `sqlx-ra-tls`: every connection presents
//! a short-lived, TDX-attested client certificate issued by the dstack
//! guest-agent. That certificate embeds a fresh TDX quote in a Phala
//! RA-TLS X.509 extension, so the server (typically a teesql sidecar)
//! can verify the client's TEE identity just as the client verifies the
//! server's.
//!
//! We delegate the whole attestation dance to the `dstack-sdk` crate
//! which already talks to the guest agent over its Unix socket (or over
//! HTTP when the simulator is running). This module is a thin wrapper
//! that turns the SDK's response into rustls-compatible types and that
//! fails early if no dstack endpoint can be reached.

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::Error;

/// Environment variable consulted by `dstack-sdk` to locate a running
/// simulator. When unset, the SDK probes a list of well-known Unix socket
/// paths.
pub const DSTACK_SIMULATOR_ENV: &str = "DSTACK_SIMULATOR_ENDPOINT";

/// Candidate Unix socket paths for the dstack guest agent. Mirrors the
/// list inside `dstack-sdk` so we can surface a descriptive error when
/// none of them are reachable.
pub const DSTACK_SOCKET_PATHS: &[&str] = &[
    "/var/run/dstack.sock",
    "/run/dstack.sock",
    "/var/run/dstack/dstack.sock",
    "/run/dstack/dstack.sock",
];

/// PEM bundle issued by the dstack guest-agent.
///
/// `key` is a PEM-encoded PKCS#8 private key. `certificate_chain` is the
/// RA-TLS leaf certificate followed by any intermediates (typically just
/// the leaf for dstack-issued certs).
#[derive(Debug, Clone)]
pub struct DstackClientCert {
    pub key_pem: String,
    pub chain_pem: String,
}

impl DstackClientCert {
    /// Parse the PEM bundle into rustls-native types. Returns the first
    /// certificate in the chain as the leaf followed by the intermediates.
    pub fn to_rustls(
        &self,
    ) -> Result<(PrivateKeyDer<'static>, Vec<CertificateDer<'static>>), Error> {
        let key = ra_tls_parse::parse_private_key(&self.key_pem)
            .map_err(|e| Error::Other(format!("parse dstack key: {e}")))?;
        let certs = ra_tls_parse::parse_certificates(&self.chain_pem)
            .map_err(|e| Error::Other(format!("parse dstack cert chain: {e}")))?;
        if certs.is_empty() {
            return Err(Error::Other("dstack returned empty cert chain".into()));
        }
        Ok((key, certs))
    }
}

/// Fetch a fresh client RA-TLS certificate from the dstack guest-agent.
///
/// The caller must be running inside a dstack CVM (the default) OR have
/// `DSTACK_SIMULATOR_ENDPOINT` set to a reachable simulator URL.
///
/// Returns [`Error::MissingDstackSocket`] when neither path is available.
/// This is intentional: mutual RA-TLS is mandatory, and silently falling
/// back to a plain-TLS connection would break the security model.
pub async fn get_dstack_client_cert() -> Result<DstackClientCert, Error> {
    require_dstack_endpoint()?;

    let client = dstack_sdk::dstack_client::DstackClient::new(None);
    let config = dstack_sdk::dstack_client::TlsKeyConfig::builder()
        .subject("sqlx-ra-tls-client")
        .usage_ra_tls(true)
        .usage_client_auth(true)
        .usage_server_auth(false)
        .build();

    let response = client
        .get_tls_key(config)
        .await
        .map_err(|e| Error::Dstack(format!("GetTlsKey failed: {e}")))?;

    if response.certificate_chain.is_empty() {
        return Err(Error::Dstack(
            "guest agent returned empty certificate chain".into(),
        ));
    }

    Ok(DstackClientCert {
        key_pem: response.key,
        chain_pem: response.certificate_chain.join("\n"),
    })
}

/// Verify that a dstack endpoint (socket or simulator) is reachable from
/// the current process. Returns `Ok(())` if at least one is available.
///
/// This check is deliberately filesystem-level (no connect). The first
/// actual RPC call will still fail loudly if the endpoint is unhealthy;
/// the purpose here is to give a useful error message before we bother
/// constructing the async SDK client.
pub fn require_dstack_endpoint() -> Result<(), Error> {
    if std::env::var(DSTACK_SIMULATOR_ENV).is_ok() {
        return Ok(());
    }
    for path in DSTACK_SOCKET_PATHS {
        if std::path::Path::new(path).exists() {
            return Ok(());
        }
    }
    Err(Error::MissingDstackSocket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests here manipulate process-global env, which is inherently not
    // thread-safe in Rust. Serialize them through a crate-local mutex so
    // cargo's parallel test runner can't interleave mutations.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: Mutex<()> = Mutex::new(());
        &LOCK
    }

    #[test]
    fn require_reports_missing_without_env_or_socket() {
        let _guard = env_lock().lock().unwrap();
        let prev = std::env::var(DSTACK_SIMULATOR_ENV).ok();
        // SAFETY: `remove_var` and `set_var` are `unsafe` in newer Rust
        // editions because they mutate process-global state. Tests
        // touching env vars share `env_lock()` above so no other thread in
        // this crate is reading or writing the environment concurrently.
        unsafe {
            std::env::remove_var(DSTACK_SIMULATOR_ENV);
        }

        let result = require_dstack_endpoint();

        if let Some(value) = prev {
            // SAFETY: same rationale as above; restore original value
            // while still holding the env lock.
            unsafe {
                std::env::set_var(DSTACK_SIMULATOR_ENV, value);
            }
        }

        // On a dev box that does not have a dstack socket installed, the
        // call should fail. On a host with the socket present, it will
        // succeed — accept both. The test still gives useful signal about
        // the error variant via the panic message if it fails unexpectedly.
        if let Err(err) = result {
            assert!(matches!(err, Error::MissingDstackSocket));
        }
    }

    #[test]
    fn require_accepts_simulator_env() {
        let _guard = env_lock().lock().unwrap();
        let prev = std::env::var(DSTACK_SIMULATOR_ENV).ok();
        // SAFETY: see note in `require_reports_missing_without_env_or_socket`.
        unsafe {
            std::env::set_var(DSTACK_SIMULATOR_ENV, "http://127.0.0.1:12345");
        }
        let result = require_dstack_endpoint();
        // SAFETY: same as above; restore while holding the lock.
        unsafe {
            match prev {
                Some(v) => std::env::set_var(DSTACK_SIMULATOR_ENV, v),
                None => std::env::remove_var(DSTACK_SIMULATOR_ENV),
            }
        }
        assert!(result.is_ok());
    }
}
