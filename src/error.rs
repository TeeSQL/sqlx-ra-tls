//! Unified error type for the crate.

use crate::types::VerifyError;

/// Errors returned by `sqlx-ra-tls`. Constructed by the connector and any
/// user-facing helpers. Internal code should convert into this enum at the
/// boundary.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The dstack guest-agent socket could not be located and no simulator
    /// endpoint was configured. Mutual RA-TLS requires a dstack identity, so
    /// this is fatal even for plain-TLS fallback scenarios.
    #[error(
        "dstack guest-agent unavailable: no socket at known paths and DSTACK_SIMULATOR_ENDPOINT \
         is not set. sqlx-ra-tls must run inside a dstack CVM or with the simulator running."
    )]
    MissingDstackSocket,

    /// The server certificate did not contain a recognizable TDX quote.
    #[error(
        "could not extract TDX quote from server certificate; pass allow_simulator=true for \
         non-TEE servers"
    )]
    QuoteExtractionFailed,

    /// A verifier rejected the quote.
    #[error("attestation verification failed: {0}")]
    VerificationFailed(#[from] VerifyError),

    /// The connection string could not be parsed or did not meet schema
    /// requirements.
    #[error("bad DSN: {0}")]
    BadDsn(String),

    /// The credentials encoded in the DSN do not satisfy the teesql sidecar
    /// contract (valid usernames: `teesql_read` / `teesql_readwrite`;
    /// password: 64-char hex cluster secret).
    #[error("bad credentials: {0}")]
    BadCredentials(String),

    /// A lower-level TLS error.
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    /// A sqlx-originated error.
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// An I/O error (socket read/write, guest-agent connect, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An error from the dstack SDK.
    #[error("dstack SDK error: {0}")]
    Dstack(String),

    /// An HTTP error (Intel Trust Authority, simulator endpoint, etc.).
    #[error("HTTP error: {0}")]
    Http(String),

    /// A token validation error.
    #[error("token validation failed: {0}")]
    Token(String),

    /// Any other error with a descriptive message.
    #[error("{0}")]
    Other(String),
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Http(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        Error::Token(err.to_string())
    }
}
