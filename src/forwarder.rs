//! Local TCP forwarder that terminates RA-TLS on behalf of the postgres driver.
//!
//! # Why this exists
//!
//! The dstack gateway routes incoming traffic in TLS-passthrough mode by
//! parsing the TLS ClientHello's SNI to pick a target CVM, before
//! forwarding the raw bytes on. Standard postgres clients (libpq, sqlx,
//! psycopg, prisma) start every `sslmode=require` connection with the
//! postgres-specific `SSLRequest` frame — 8 plaintext bytes `[00 00 00
//! 08 04 D2 16 2F]` — and wait for a single-byte reply before sending
//! the TLS ClientHello. The gateway sees the SSLRequest as the first
//! bytes, fails SNI extraction (first byte `0x00` is not a TLS
//! handshake record type), and closes the connection.
//!
//! We can't trust the customer (their TEE has to be proven via the
//! handshake itself), so we can't bypass the gateway by handing out raw
//! sidecar endpoints. That rules out "sqlx does its own TLS handshake"
//! through the gateway.
//!
//! The fix is to move TLS out of sqlx entirely. This module runs a
//! localhost `TcpListener` inside the client process; on every accept
//! it opens a *raw* TLS connection (no `SSLRequest` preamble) to the
//! cluster, presents the RA-TLS client cert, verifies the server's TDX
//! quote via DCAP, and then bridges bytes bidirectionally between the
//! accepted local stream and the TLS-wrapped upstream stream.
//!
//! From sqlx's perspective it's connecting to a plain-TCP local
//! postgres server with `sslmode=disable`. From the sidecar's
//! perspective it's getting a raw-TLS mutual-RA-TLS handshake with a
//! valid client cert. The gateway sees a well-formed TLS ClientHello
//! in the first bytes and routes happily.
//!
//! # Trust model
//!
//! The local hop (sqlx ↔ forwarder ↔ TLS tunnel) lives inside the
//! client process — both ends are the same TEE CVM. The plaintext
//! segment never crosses a process boundary or an untrusted network.
//! The actual mutual-RA-TLS handshake happens on the upstream leg,
//! exactly as the trust model documents.
//!
//! # Lifecycle
//!
//! [`RaTlsForwarder`] owns a background tokio task with an accept
//! loop. Dropping the forwarder cancels the loop. For the common "one
//! pool per process" case, [`pg_connect_opts_ra_tls`] leaks the
//! forwarder for the lifetime of the process — the pool outlives any
//! explicit handle anyway, and the forwarder's footprint is a listener
//! socket plus a few ephemeral TLS connections.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;

use crate::cert::extract_tdx_quote;
use crate::connector::{
    build_ra_tls_client_config, LeafCaptureVerifier, RaTlsOptions, PROBE_TIMEOUT,
};
use crate::dstack::DstackClientCert;
use crate::error::Error;
use crate::types::{RaTlsVerifier, VerifyOptions};

/// A background localhost forwarder that terminates RA-TLS for a
/// sqlx-style postgres client.
///
/// Created by [`crate::pg_connect_opts_ra_tls`]. Most callers will never
/// hold a `RaTlsForwarder` directly — the connect-opts entry point
/// starts one, leaks it for the lifetime of the process, and hands back
/// a `PgConnectOptions` that points at the forwarder's local address.
/// If you need explicit lifecycle control (e.g. short-lived CLI
/// programs that want to drop the forwarder cleanly on exit), call
/// [`RaTlsForwarder::start`] yourself and compose the options manually.
///
/// Dropping the forwarder cancels the background accept loop; existing
/// in-flight connections finish naturally.
#[derive(Debug)]
pub struct RaTlsForwarder {
    /// The `127.0.0.1:<port>` address the forwarder is listening on.
    /// Pass this as the host/port in the `PgConnectOptions` given to
    /// sqlx, with `sslmode=disable`.
    pub local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl RaTlsForwarder {
    /// Bind a localhost listener and spawn the background accept loop.
    ///
    /// Per-accept, the forwarder opens a fresh TCP + TLS connection to
    /// `(target_host, target_port)`, presenting `client_cert` and
    /// verifying the server's TDX quote via `verifier` before any
    /// bytes flow. One upstream TLS connection per downstream accept —
    /// sqlx's pool connections each get their own attested channel.
    pub async fn start(
        target_host: impl Into<String>,
        target_port: u16,
        client_cert: DstackClientCert,
        verifier: Arc<dyn RaTlsVerifier>,
        opts: RaTlsOptions,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| Error::Other(format!("forwarder listener bind: {e}")))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::Other(format!("forwarder local_addr: {e}")))?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let target_host: Arc<str> = Arc::from(target_host.into());
        let client_cert = Arc::new(client_cert);
        let opts = Arc::new(opts);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        log::debug!("sqlx-ra-tls: forwarder shutting down");
                        break;
                    }
                    accept = listener.accept() => {
                        let (local, _peer) = match accept {
                            Ok(x) => x,
                            Err(e) => {
                                log::warn!("sqlx-ra-tls: forwarder accept error: {e}");
                                continue;
                            }
                        };
                        let target_host = Arc::clone(&target_host);
                        let client_cert = Arc::clone(&client_cert);
                        let verifier = Arc::clone(&verifier);
                        let opts = Arc::clone(&opts);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(
                                local,
                                &target_host,
                                target_port,
                                &client_cert,
                                &*verifier,
                                &opts,
                            )
                            .await
                            {
                                log::warn!("sqlx-ra-tls: forwarder connection failed: {e}");
                            }
                        });
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            shutdown_tx: Some(shutdown_tx),
        })
    }
}

impl Drop for RaTlsForwarder {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn handle_connection(
    mut local: TcpStream,
    target_host: &str,
    target_port: u16,
    client_cert: &DstackClientCert,
    verifier: &dyn RaTlsVerifier,
    opts: &RaTlsOptions,
) -> Result<(), Error> {
    // Per-connection rustls config so rotated dstack certs take effect
    // on new connections. The dstack guest-agent returns short-lived
    // RA-TLS certs; a sqlx pool that holds a Pool for hours would
    // otherwise pin the boot-time cert forever.
    let capture = Arc::new(LeafCaptureVerifier::new(Arc::new(
        crate::connector::default_crypto_provider(),
    )));
    let config = build_ra_tls_client_config(client_cert, Arc::clone(&capture))?;
    let connector = TlsConnector::from(Arc::new(config));

    // RA-TLS certs are self-signed with trust derived from the embedded
    // quote, not DNS SANs. Pass a placeholder ServerName to drive SNI
    // without tripping rustls's hostname check (the custom verifier
    // accepts regardless of hostname).
    let server_name = ServerName::try_from(target_host.to_string()).unwrap_or_else(|_| {
        ServerName::try_from("teesql.invalid".to_string()).expect("literal parses")
    });

    let upstream = tokio::time::timeout(
        PROBE_TIMEOUT,
        TcpStream::connect((target_host, target_port)),
    )
    .await
    .map_err(|_| Error::Other("upstream TCP connect timed out".into()))?
    .map_err(|e| Error::Other(format!("upstream TCP connect: {e}")))?;
    upstream.set_nodelay(true).ok();

    let mut tls = tokio::time::timeout(PROBE_TIMEOUT, connector.connect(server_name, upstream))
        .await
        .map_err(|_| Error::Other("upstream TLS handshake timed out".into()))?
        .map_err(|e| Error::Other(format!("upstream TLS handshake: {e}")))?;

    let leaf_der = capture
        .leaf()
        .ok_or_else(|| Error::Other("upstream presented no leaf certificate".into()))?;

    let quote_bytes = extract_tdx_quote(&leaf_der);
    match (quote_bytes, opts.allow_simulator) {
        (Some(q), _) => {
            let vopts = VerifyOptions {
                allowed_mr_td: opts.allowed_mrtds.clone(),
                allow_debug_mode: opts.allow_debug_mode,
            };
            let result = verifier
                .verify(&q, &vopts)
                .await
                .map_err(Error::VerificationFailed)?;
            let short_mr = result.mr_td.chars().take(16).collect::<String>();
            log::debug!(
                "sqlx-ra-tls: upstream RA-TLS verified: mrtd={short_mr}... tcb={}",
                result.tcb_status
            );
        }
        (None, true) => {
            log::warn!(
                "sqlx-ra-tls: upstream cert has no TDX attestation extension, continuing \
                 because allow_simulator=true"
            );
        }
        (None, false) => return Err(Error::QuoteExtractionFailed),
    }

    copy_bidirectional(&mut local, &mut tls)
        .await
        .map_err(|e| Error::Other(format!("bridge failed: {e}")))?;

    Ok(())
}
