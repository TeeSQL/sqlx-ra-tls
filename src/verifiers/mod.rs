//! Built-in [`RaTlsVerifier`](crate::types::RaTlsVerifier) implementations.
//!
//! - [`DcapVerifier`] — production verifier that validates a TDX quote
//!   locally via `dcap-qvl`. No Intel account required. Default for
//!   v0.2+.
//! - [`IntelApiVerifier`] — opt-in verifier backed by Intel Trust
//!   Authority. Requires an Intel account; useful when MRTD pinning
//!   needs Intel-signed JWT claims.
//! - [`NoopVerifier`] — dev-only verifier that parses the quote for
//!   logging but never fails. Emits a warning on construction.

mod dcap;
mod intel;
mod noop;

pub use dcap::{DcapVerifier, DEFAULT_PCCS_URL};
pub use intel::IntelApiVerifier;
pub use noop::NoopVerifier;
