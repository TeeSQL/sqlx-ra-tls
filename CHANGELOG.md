# Changelog

All notable changes to `sqlx-ra-tls` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-04-24

### Added
- `DcapVerifier` — local DCAP quote verifier built on
  [`dcap-qvl`](https://crates.io/crates/dcap-qvl) `0.4.0`. Walks the
  TDX quote's PCK certificate chain up to Intel's root CA (embedded
  in the library) and fetches platform collateral (TCB info, QE
  identity, CRLs) from a PCCS endpoint. Mirrors `dstack-verifier`'s
  usage of the same crate.
- `DcapVerifier::with_pccs_url(url)` to point at a custom PCCS
  (Phala mirror, self-hosted, etc.). Default is Intel public PCS.
- `DcapVerifier::verify_with_collateral(quote, collateral, now,
  options)` for offline / cached-collateral use cases — skips the
  PCCS round trip entirely.
- `DEFAULT_PCCS_URL` constant re-exported from the crate root.
- `tests/dcap_roundtrip.rs` integration tests using the bundled TDX
  quote + collateral fixture lifted from `dcap-qvl` 0.4.0's
  `sample/` directory.

### Changed
- **Default verifier flipped to local DCAP.** The README's
  production example now wires `DcapVerifier`. No Intel Trust
  Authority account is required for new deployments.
- `IntelApiVerifier` is retained as a named advanced option for
  callers who specifically want Intel-signed JWT attestation tokens.

### Migration

- v0.1 callers who used `IntelApiVerifier::new(api_key)` can keep
  doing so — no API break. To drop the Intel API dependency, swap
  `IntelApiVerifier::new(api_key)` for `DcapVerifier::new()` and
  remove the `INTEL_TRUST_AUTHORITY_API_KEY` env var. Same
  `RaTlsOptions` and `VerifyOptions` semantics on both sides.

## [0.1.0] — 2026-04-23

### Added
- `pg_connect_opts_ra_tls(dsn, verifier, opts)` helper that runs an
  RA-TLS probe against a teesql-sidecar before handing options to
  `sqlx::postgres::PgPoolOptions`.
- Built-in verifiers: `IntelApiVerifier` (Intel Trust Authority) and
  `NoopVerifier` (dev only — logs a warning on construction).
- `extract_tdx_quote` supporting both OIDs dstack emits
  (`1.3.6.1.4.1.62397.1.1` and `1.3.6.1.4.1.62397.1.8`).
- `get_dstack_client_cert()` wrapping `dstack-sdk::DstackClient::get_tls_key`
  with a hard failure when no guest-agent endpoint is reachable.
- `RaTlsVerifier` trait with `VerifyOptions` / `VerificationResult`
  mirroring the Python and TypeScript peer SDKs.
- `verify_server` standalone helper for re-verification in
  `PgPoolOptions::before_acquire` callbacks.
