//! Built-in [`RaTlsVerifier`](crate::types::RaTlsVerifier) implementations.
//!
//! - [`IntelApiVerifier`] — production verifier backed by Intel Trust Authority.
//! - [`NoopVerifier`] — dev-only verifier that parses the quote for logging
//!   but never fails. Emits a warning on construction.

mod intel;
mod noop;

pub use intel::IntelApiVerifier;
pub use noop::NoopVerifier;
