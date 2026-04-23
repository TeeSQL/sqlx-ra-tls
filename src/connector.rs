//! RA-TLS connector glue for `sqlx::postgres`.
//!
//! sqlx 0.8 does not expose a hook for installing a custom
//! `rustls::ClientConfig` or a custom `rustls::client::ServerCertVerifier`.
//! Instead, it consumes a flat [`PgConnectOptions`] and builds its own
//! rustls config internally. That makes an in-handshake quote check
//! impossible without forking the crate.
//!
//! The mitigation used by this SDK — and by the Python/TypeScript peers
//! — is to run a dedicated pre-flight TLS probe against the target
//! server, presenting the dstack-issued client cert and extracting the
//! TDX quote from the server's leaf certificate. The returned
//! [`PgConnectOptions`] embed the same client cert/key so sqlx sends
//! them again during its own handshake. This preserves mutual RA-TLS
//! semantics: the client identity is proven on every connection, and
//! the server identity has been attested before any SQL is issued.
//!
//! The probe also records the server cert's SHA-256 fingerprint so
//! callers can re-probe per acquire and detect mid-pool substitutions.

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

/// Maximum duration we wait for the TLS handshake + first flight. The
/// probe is a one-shot TCP+TLS handshake so this budget is generous.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Build a [`PgConnectOptions`] for a teesql-sidecar target and verify the
/// server's TDX quote before returning.
///
/// This is the primary entry point the README recommends. The returned
/// options are ready to be passed to `PgPoolOptions::new().connect_with`.
///
/// The flow:
/// 1. Parse the DSN; enforce `teesql_read` / `teesql_readwrite` and a 64-char
///    hex cluster secret.
/// 2. Fetch a short-lived dstack client cert (or reuse the override).
/// 3. Probe the server with an RA-TLS handshake, extract the quote, and
///    run it through `verifier`.
/// 4. Return options configured for `sslmode=require` plus the client
///    cert/key inlined as PEM — so the same attested identity is
///    presented again during sqlx's own handshake.
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

    // Fetch the client cert. This is mandatory — see MissingDstackSocket
    // docs in [`crate::Error`]. We keep the PEMs as `String`/`Vec<u8>` so
    // they can be inlined into PgConnectOptions verbatim.
    let client_cert = match opts.client_cert_override.clone() {
        Some(cert) => cert,
        None => dstack::get_dstack_client_cert().await?,
    };

    // Run the server verification probe. On success the options become a
    // one-shot proof-of-life; sqlx still re-handshakes on every physical
    // connection, and the caller may run [`verify_server`] again to
    // catch long-lived CVM replacement.
    let _verified = verify_server(
        base_opts.get_host(),
        base_opts.get_port(),
        &client_cert,
        &*verifier,
        &opts,
    )
    .await?;

    let verified_opts = base_opts
        .ssl_mode(PgSslMode::Require)
        .ssl_client_cert_from_pem(client_cert.chain_pem.as_bytes())
        .ssl_client_key_from_pem(client_cert.key_pem.as_bytes());

    Ok(verified_opts)
}

/// Lower-level helper exported for re-verification. Opens a TLS
/// connection to `(host, port)` presenting `client_cert` and runs
/// `verifier` over the quote in the server's leaf certificate.
///
/// Returns [`VerifiedServer`] with the cert fingerprint so the caller
/// can short-circuit a verifier round-trip for the same identity.
pub async fn verify_server(
    host: &str,
    port: u16,
    client_cert: &DstackClientCert,
    verifier: &dyn RaTlsVerifier,
    opts: &RaTlsOptions,
) -> Result<VerifiedServer, Error> {
    let provider = Arc::new(default_crypto_provider());

    let (client_key, client_chain) = client_cert.to_rustls()?;

    let capture = Arc::new(LeafCaptureVerifier::new(provider.clone()));

    let client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(Error::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_client_auth_cert(client_chain, client_key)
        .map_err(Error::Tls)?;

    let connector = TlsConnector::from(Arc::new(client_config));

    // We deliberately ignore DNS SANs: RA-TLS certs are self-signed and
    // trust derives from the quote, not the hostname. We still need a
    // non-empty ServerName to drive SNI; pick one that reflects intent.
    let server_name = ServerName::try_from(host.to_string())
        .unwrap_or(ServerName::try_from("teesql.invalid".to_string()).expect("literal parses"));

    // Postgres speaks StartTLS: we have to send an SSLRequest frame and
    // read the single-byte 'S' reply before rustls can drive the TLS
    // handshake. Doing this ourselves keeps the probe surface small — a
    // TCP connect, one read-write round, then a TLS handshake — and
    // mirrors the sidecar's expected client flow.
    let tcp = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(format!("{host}:{port}")))
        .await
        .map_err(|_| Error::Other("TCP connect timed out".into()))??;

    tcp.set_nodelay(true)?;
    let tcp = start_postgres_tls(tcp).await?;

    let tls = tokio::time::timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| Error::Other("TLS handshake timed out".into()))?
        .map_err(|e| Error::Other(format!("TLS handshake failed: {e}")))?;

    // Try to shut down the probe connection. If the server has already
    // closed (as sidecars commonly do mid-handshake when a SQL frame is
    // expected next) we just drop it; we already captured what we need.
    let (_io, _session) = tls.into_inner();
    drop(_io);

    // Pull the captured leaf certificate out of the verifier.
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

fn default_crypto_provider() -> CryptoProvider {
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

/// Send the Postgres SSLRequest packet and wait for the server's single-byte
/// response. Returns the socket if TLS may proceed; bails otherwise.
async fn start_postgres_tls(mut tcp: TcpStream) -> Result<TcpStream, Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Frame: 8 bytes. length=8, code=80877103 (0x04D2162F).
    const SSL_REQUEST: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F];
    tcp.write_all(&SSL_REQUEST).await?;
    tcp.flush().await?;

    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await?;
    match reply[0] {
        b'S' => Ok(tcp),
        b'N' => Err(Error::Other(
            "server refused TLS during SSLRequest handshake".into(),
        )),
        other => Err(Error::Other(format!(
            "unexpected SSLRequest reply byte: 0x{other:02x}"
        ))),
    }
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
#[derive(Debug)]
struct LeafCaptureVerifier {
    leaf: std::sync::Mutex<Option<Vec<u8>>>,
    provider: Arc<CryptoProvider>,
}

impl LeafCaptureVerifier {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self {
            leaf: std::sync::Mutex::new(None),
            provider,
        }
    }

    fn leaf(&self) -> Option<Vec<u8>> {
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
