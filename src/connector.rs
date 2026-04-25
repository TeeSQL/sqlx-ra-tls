//! sqlx RA-TLS connector for dstack TEE Postgres sidecars.
//!
//! sqlx 0.8 runs its own TLS handshake as part of every `PgConnection::connect`
//! using a flat [`PgConnectOptions`]. There's no hook to install a custom
//! `rustls::ClientConfig` or swap in a pre-wrapped stream, so sqlx's TLS
//! always starts with the postgres `SSLRequest` 8-byte preamble. Against a
//! dstack-gateway-routed sidecar, that preamble breaks the gateway's SNI
//! extraction (first byte `0x00` ≠ TLS handshake record type `0x16`) and the
//! connection is closed before any cert exchange happens.
//!
//! To keep mutual RA-TLS working end-to-end through the gateway, we run TLS
//! *outside* of sqlx: an in-process [`RaTlsForwarder`](crate::RaTlsForwarder)
//! listens on `127.0.0.1:<ephemeral>`, terminates mutual RA-TLS against the
//! cluster on each accept, and hands sqlx a plain-TCP local endpoint with
//! `sslmode=disable`. See `forwarder.rs` for the full rationale.
//!
//! [`pg_connect_opts_ra_tls`] is still the one-line entry point — it starts
//! the forwarder and returns `PgConnectOptions` already pointed at it, so
//! callers don't have to know the details.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::cert::extract_tdx_quote;
use crate::dstack::{self, DstackClientCert};
use crate::error::Error;
use crate::forwarder::RaTlsForwarder;
use crate::types::{RaTlsVerifier, VerifyOptions};

/// Options controlling how RA-TLS verification is applied on each connect.
#[derive(Debug, Clone, Default)]
pub struct RaTlsOptions {
    /// MRTD values accepted from the server. Hex strings, case-insensitive,
    /// with or without `0x` prefix. Empty means "accept any".
    pub allowed_mrtds: Vec<String>,
    /// Accept TDs reporting `tdx_is_debuggable=true`. Default `false`.
    pub allow_debug_mode: bool,
    /// Skip server-side quote verification entirely when the server cert
    /// has no RA-TLS extension. Required when talking to a dstack
    /// simulator or a plain Postgres instance. Does not affect the
    /// mandatory client-side dstack identity.
    pub allow_simulator: bool,
    /// Override the dstack client cert. Primarily for tests. When `None`,
    /// the crate fetches a fresh cert from the dstack guest-agent.
    pub client_cert_override: Option<DstackClientCert>,
}

/// Metadata returned by [`verify_server`] so callers can feed it into
/// caches or per-acquire re-verification hooks.
#[derive(Debug, Clone)]
pub struct VerifiedServer {
    /// DER-encoded server leaf certificate.
    pub leaf_cert_der: Vec<u8>,
    /// SHA-256 fingerprint (lowercase hex) of the leaf certificate. Useful
    /// for caches keyed on server identity.
    pub leaf_fingerprint: String,
    /// Raw TDX quote bytes. `None` when `allow_simulator=true` and the
    /// server presented no quote.
    pub quote: Option<Vec<u8>>,
}

/// Valid sidecar usernames as described in
/// `docs/plans/secure-token-authentication.md`.
const TEESQL_USERNAMES: &[&str] = &["teesql_read", "teesql_readwrite"];

/// Length of the 32-byte cluster-secret expressed as lowercase hex.
const CLUSTER_SECRET_HEX_LEN: usize = 64;

/// Maximum duration we wait for a single TLS handshake (either the one-shot
/// probe or a forwarder accept's upstream connect). TLS over the dstack
/// gateway typically completes in well under a second; 15s is generous.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Build a [`PgConnectOptions`] for a teesql-sidecar target, starting an
/// in-process [`RaTlsForwarder`](crate::RaTlsForwarder) that terminates
/// mutual RA-TLS and bridges bytes to the cluster. The returned options
/// point at the forwarder's local address with `sslmode=disable`, and are
/// ready to pass to `PgPoolOptions::new().connect_with(opts)`.
///
/// The flow:
/// 1. Parse the DSN; enforce `teesql_read` / `teesql_readwrite` and a 64-char
///    hex cluster secret.
/// 2. Fetch a short-lived dstack client cert (or reuse the override).
/// 3. Spawn an [`RaTlsForwarder`](crate::RaTlsForwarder) bound to
///    `127.0.0.1:<ephemeral>` that opens mutual RA-TLS to the cluster on
///    every accept and bridges bytes.
/// 4. Return `PgConnectOptions` with host/port replaced by the forwarder's
///    local address and `ssl_mode=disable`, preserving user/password/db
///    from the original DSN.
///
/// The forwarder is leaked for the process lifetime — typical teesql
/// clients hold a single `PgPool` for as long as the service runs, which
/// outlives any explicit handle anyway. Programs that need a tighter
/// lifecycle should call [`RaTlsForwarder::start`](crate::RaTlsForwarder::start)
/// directly and compose the options by hand.
pub async fn pg_connect_opts_ra_tls(
    dsn: &str,
    verifier: Arc<dyn RaTlsVerifier>,
    opts: RaTlsOptions,
) -> Result<PgConnectOptions, Error> {
    let base_opts: PgConnectOptions = dsn
        .parse()
        .map_err(|e: sqlx::Error| Error::BadDsn(e.to_string()))?;

    // DSN discipline: the sidecar accepts only teesql_* users and a 32-byte
    // cluster secret as the "password". Reject anything else up front so
    // callers do not spend an RTT discovering a configuration error.
    validate_dsn(&base_opts, dsn)?;

    // Fetch the client cert. Mandatory — the cluster's sidecar requires a
    // TDX-attested client cert during the TLS handshake; see
    // `crate::Error::MissingDstackSocket` for the simulator guidance.
    let client_cert = match opts.client_cert_override.clone() {
        Some(cert) => cert,
        None => dstack::get_dstack_client_cert().await?,
    };

    // Spawn the forwarder and return options pointing at it. The forwarder
    // owns a background accept loop that terminates mutual RA-TLS against
    // the target cluster on every connection.
    let target_host = base_opts.get_host().to_string();
    let target_port = base_opts.get_port();
    let forwarder = RaTlsForwarder::start(
        target_host,
        target_port,
        client_cert,
        verifier,
        opts,
    )
    .await?;
    let local_addr = forwarder.local_addr;
    // Leak — see function docs. Tighter-lifetime callers should use
    // `RaTlsForwarder::start` directly.
    let _: &'static RaTlsForwarder = Box::leak(Box::new(forwarder));

    let verified_opts = base_opts
        .host(&local_addr.ip().to_string())
        .port(local_addr.port())
        .ssl_mode(PgSslMode::Disable);

    Ok(verified_opts)
}

/// Lower-level one-shot RA-TLS probe. Opens a raw TLS connection to
/// `(host, port)` presenting `client_cert`, verifies the server's TDX
/// quote, and returns the captured leaf cert + fingerprint.
///
/// Use this for standalone health checks or CVM-replacement detection.
/// It deliberately does *not* send the postgres `SSLRequest` preamble —
/// the connection target is expected to speak TLS directly (through a
/// dstack gateway in passthrough mode, or directly to a sidecar's :5433
/// RA-TLS listener). For sqlx pool connections, use [`pg_connect_opts_ra_tls`]
/// which wires up an [`RaTlsForwarder`](crate::RaTlsForwarder).
pub async fn verify_server(
    host: &str,
    port: u16,
    client_cert: &DstackClientCert,
    verifier: &dyn RaTlsVerifier,
    opts: &RaTlsOptions,
) -> Result<VerifiedServer, Error> {
    let capture = Arc::new(LeafCaptureVerifier::new(Arc::new(default_crypto_provider())));
    let client_config = build_ra_tls_client_config(client_cert, Arc::clone(&capture))?;
    let connector = TlsConnector::from(Arc::new(client_config));

    // We deliberately ignore DNS SANs: RA-TLS certs are self-signed and
    // trust derives from the quote, not the hostname. We still need a
    // non-empty ServerName to drive SNI; pick one that reflects intent.
    let server_name = ServerName::try_from(host.to_string())
        .unwrap_or(ServerName::try_from("teesql.invalid".to_string()).expect("literal parses"));

    let tcp = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(format!("{host}:{port}")))
        .await
        .map_err(|_| Error::Other("TCP connect timed out".into()))??;

    tcp.set_nodelay(true)?;

    let tls = tokio::time::timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| Error::Other("TLS handshake timed out".into()))?
        .map_err(|e| Error::Other(format!("TLS handshake failed: {e}")))?;

    // Try to shut down the probe connection. If the server has already
    // closed (as sidecars commonly do mid-handshake when a SQL frame is
    // expected next) we just drop it; we already captured what we need.
    let (_io, _session) = tls.into_inner();
    drop(_io);

    let leaf_cert_der = capture
        .leaf()
        .ok_or_else(|| Error::Other("server presented no leaf certificate".into()))?;

    let leaf_fingerprint = sha256_hex(&leaf_cert_der);

    let quote_bytes = extract_tdx_quote(&leaf_cert_der);
    let quote = match (quote_bytes, opts.allow_simulator) {
        (Some(q), _) => Some(q),
        (None, true) => {
            log::warn!(
                "sqlx-ra-tls: server cert has no TDX attestation extension, continuing \
                 because allow_simulator=true"
            );
            None
        }
        (None, false) => return Err(Error::QuoteExtractionFailed),
    };

    if let Some(quote_bytes) = quote.as_ref() {
        let vopts = VerifyOptions {
            allowed_mr_td: opts.allowed_mrtds.clone(),
            allow_debug_mode: opts.allow_debug_mode,
        };
        let result = verifier
            .verify(quote_bytes, &vopts)
            .await
            .map_err(Error::VerificationFailed)?;
        let short_mr = result.mr_td.chars().take(16).collect::<String>();
        log::info!(
            "sqlx-ra-tls: RA-TLS verification passed: mrtd={short_mr}... tcb={}",
            result.tcb_status
        );
    }

    Ok(VerifiedServer {
        leaf_cert_der,
        leaf_fingerprint,
        quote,
    })
}

/// Build a rustls `ClientConfig` that:
/// - presents `client_cert` during the handshake;
/// - captures the server's leaf cert via `capture` for post-handshake quote
///   extraction;
/// - accepts any server chain (real verification is DCAP on the captured
///   quote, not PKI).
///
/// `pub(crate)` so [`RaTlsForwarder`](crate::RaTlsForwarder) can build the
/// same config without duplicating the safety dance.
pub(crate) fn build_ra_tls_client_config(
    client_cert: &DstackClientCert,
    capture: Arc<LeafCaptureVerifier>,
) -> Result<rustls::ClientConfig, Error> {
    let (client_key, client_chain) = client_cert.to_rustls()?;
    let provider = Arc::new(default_crypto_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(Error::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(capture)
        .with_client_auth_cert(client_chain, client_key)
        .map_err(Error::Tls)
}

pub(crate) fn default_crypto_provider() -> CryptoProvider {
    // We depend on the `ring` feature of rustls; if a caller has also
    // installed a process-wide default provider, prefer that to avoid
    // surprises. Otherwise fall back to ring directly.
    if let Some(installed) = CryptoProvider::get_default() {
        (**installed).clone()
    } else {
        rustls::crypto::ring::default_provider()
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use rustls::crypto::hash::HashAlgorithm;

    // Reuse whatever SHA-256 implementation the rustls crypto provider
    // already pulled in. This keeps our dependency surface minimal (no
    // direct sha2 dep) and guarantees the same primitive is used for
    // handshake and fingerprint hashing.
    let provider = default_crypto_provider();
    let hasher = provider
        .cipher_suites
        .iter()
        .filter_map(|cs| cs.tls13().map(|s| s.common.hash_provider))
        .find(|h| h.algorithm() == HashAlgorithm::SHA256)
        .expect("rustls provider exposes at least one SHA-256 hasher");

    let digest = hasher.hash(data);
    hex::encode(digest.as_ref())
}

fn validate_dsn(opts: &PgConnectOptions, raw_dsn: &str) -> Result<(), Error> {
    let username = opts.get_username();
    if !TEESQL_USERNAMES.contains(&username) {
        return Err(Error::BadCredentials(format!(
            "username must be one of {TEESQL_USERNAMES:?} for the teesql sidecar, got '{username}'"
        )));
    }

    // sqlx does not expose the password directly. Parse it ourselves from
    // the DSN. Support only URL-style DSNs — the sidecar contract is
    // URL-only anyway.
    let password = extract_password_from_dsn(raw_dsn)?;

    if password.len() != CLUSTER_SECRET_HEX_LEN {
        return Err(Error::BadCredentials(format!(
            "cluster secret password must be {CLUSTER_SECRET_HEX_LEN} hex chars \
             (32 bytes), got {}",
            password.len()
        )));
    }
    if !password.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::BadCredentials(
            "cluster secret password must be lowercase hex".into(),
        ));
    }

    Ok(())
}

fn extract_password_from_dsn(dsn: &str) -> Result<String, Error> {
    let url =
        url::Url::parse(dsn).map_err(|e| Error::BadDsn(format!("could not parse DSN URL: {e}")))?;
    let password = url
        .password()
        .ok_or_else(|| Error::BadCredentials("DSN must include a password field".into()))?;
    // url::Url returns the password percent-decoded when read through
    // `.password()`. Use it verbatim — we only validate hex content.
    Ok(password.to_string())
}

/// rustls ServerCertVerifier that captures the server's leaf certificate
/// into a shared slot and always claims success. We run real verification
/// (quote extraction + attestation) after the handshake completes.
///
/// `pub(crate)` so [`RaTlsForwarder`](crate::RaTlsForwarder) can share
/// the same capture/verifier dance on every forwarded accept.
#[derive(Debug)]
pub(crate) struct LeafCaptureVerifier {
    leaf: std::sync::Mutex<Option<Vec<u8>>>,
    provider: Arc<CryptoProvider>,
}

impl LeafCaptureVerifier {
    pub(crate) fn new(provider: Arc<CryptoProvider>) -> Self {
        Self {
            leaf: std::sync::Mutex::new(None),
            provider,
        }
    }

    pub(crate) fn leaf(&self) -> Option<Vec<u8>> {
        self.leaf.lock().expect("leaf mutex poisoned").clone()
    }
}

impl ServerCertVerifier for LeafCaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.leaf.lock().expect("leaf mutex poisoned") = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsn_requires_teesql_user() {
        let dsn = "postgres://postgres:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899@host:5433/db";
        let opts: PgConnectOptions = dsn.parse().unwrap();
        let err = validate_dsn(&opts, dsn).unwrap_err();
        assert!(matches!(err, Error::BadCredentials(msg) if msg.contains("username")));
    }

    #[test]
    fn dsn_requires_64_hex_password() {
        let dsn = "postgres://teesql_readwrite:short@host:5433/db";
        let opts: PgConnectOptions = dsn.parse().unwrap();
        let err = validate_dsn(&opts, dsn).unwrap_err();
        assert!(matches!(err, Error::BadCredentials(msg) if msg.contains("hex chars")));
    }

    #[test]
    fn dsn_requires_hex_characters() {
        let pwd = "z".repeat(64);
        let dsn = format!("postgres://teesql_readwrite:{pwd}@host:5433/db");
        let opts: PgConnectOptions = dsn.parse().unwrap();
        let err = validate_dsn(&opts, &dsn).unwrap_err();
        assert!(matches!(err, Error::BadCredentials(msg) if msg.contains("hex")));
    }

    #[test]
    fn dsn_requires_password_field() {
        let dsn = "postgres://teesql_readwrite@host:5433/db";
        let opts: PgConnectOptions = dsn.parse().unwrap();
        let err = validate_dsn(&opts, dsn).unwrap_err();
        assert!(matches!(err, Error::BadCredentials(_)));
    }

    #[test]
    fn dsn_accepts_valid_secret() {
        let pwd = "0123456789abcdef".repeat(4);
        assert_eq!(pwd.len(), 64);
        let dsn = format!("postgres://teesql_read:{pwd}@host:5433/db");
        let opts: PgConnectOptions = dsn.parse().unwrap();
        validate_dsn(&opts, &dsn).unwrap();
    }

    #[test]
    fn dsn_accepts_readwrite_role() {
        let pwd = "0123456789abcdef".repeat(4);
        let dsn = format!("postgres://teesql_readwrite:{pwd}@host:5433/db");
        let opts: PgConnectOptions = dsn.parse().unwrap();
        validate_dsn(&opts, &dsn).unwrap();
    }

    #[test]
    fn dsn_rejects_malformed_url() {
        let err = extract_password_from_dsn("not://a valid url").unwrap_err();
        assert!(matches!(err, Error::BadDsn(_) | Error::BadCredentials(_)));
    }

    #[test]
    fn sha256_hex_roundtrip() {
        let data = b"hello";
        let out = sha256_hex(data);
        // SHA-256 of "hello": 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            out,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
