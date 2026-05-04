//! sqlx RA-TLS connector for dstack TEE Postgres sidecars.
//!
//! See `README.md` at the crate root for the one-line drop-in example.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod cert;
pub mod connector;
pub mod dstack;
mod error;
pub mod forwarder;
pub mod types;
pub mod verifiers;

pub use cert::{extract_tdx_quote, OID_ATTESTATION, OID_TDX_QUOTE};
pub use connector::{pg_connect_opts_ra_tls, verify_server, RaTlsOptions, VerifiedServer};
pub use dstack::{get_dstack_client_cert, DstackClientCert, DSTACK_SIMULATOR_ENV};
pub use error::Error;
pub use forwarder::RaTlsForwarder;
pub use types::{
    expected_report_data_for_pubkey, RaTlsVerifier, VerificationResult, VerifyError, VerifyOptions,
};
pub use verifiers::{DcapVerifier, IntelApiVerifier, NoopVerifier, DEFAULT_PCCS_URL};
