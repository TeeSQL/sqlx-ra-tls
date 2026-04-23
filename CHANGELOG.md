# Changelog

All notable changes to `sqlx-ra-tls` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
