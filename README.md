# sqlx-ra-tls

A sqlx-compatible Postgres connector that verifies **TDX attestation** before allowing any queries through to a Postgres database running inside a Trusted Execution Environment (TEE).

Rust peer of [psycopg-ra-tls](https://github.com/teesql/psycopg-ra-tls) (Python) and [prisma-ra-tls](https://github.com/teesql/prisma-ra-tls) (TypeScript). Built for databases hosted on [dstack](https://github.com/Dstack-TEE/dstack) (Intel TDX) and fronted by a [teesql-sidecar](https://github.com/teesql/teesql-sidecar).

## What it does

When your application opens a connection to the sidecar, `sqlx-ra-tls`:

1. Fetches a short-lived, TDX-attested client certificate from the local dstack guest agent.
2. Performs an RA-TLS handshake with the server, presenting that client certificate for mutual authentication.
3. Extracts the TDX attestation quote from the server's self-signed RA-TLS certificate.
4. Verifies the quote — by default, **locally** via [`dcap-qvl`](https://crates.io/crates/dcap-qvl) (no Intel account required). Validates: TDX root chain up to Intel's CA, debug mode off, TCB status acceptable, and MRTD in allowlist when configured.
5. Only then hands a `PgConnectOptions` back to sqlx so the real connection pool can open.

If verification fails at any step, `pg_connect_opts_ra_tls` returns an error and no SQL is ever issued.

## Install

```toml
[dependencies]
sqlx-ra-tls = "0.2"
sqlx = { version = "0.8", features = ["postgres", "runtime-tokio", "tls-rustls"] }
```

Requires Rust >= 1.92 (for the `edition2024` dependencies pulled in transitively by sqlx 0.8).

## Usage

### Production (default: local DCAP verification)

```rust
use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use sqlx_ra_tls::{pg_connect_opts_ra_tls, DcapVerifier, RaTlsOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // No Intel account required. `DcapVerifier::new()` uses Intel's
    // public PCS for platform collateral; pass `with_pccs_url(...)`
    // to point at the Phala mirror or a self-hosted PCCS.
    let verifier = Arc::new(DcapVerifier::new());

    let dsn = std::env::var("DATABASE_URL")?;
    let opts = pg_connect_opts_ra_tls(
        &dsn,
        verifier,
        RaTlsOptions {
            allowed_mrtds: vec![std::env::var("EXPECTED_MRTD")?],
            ..Default::default()
        },
    )
    .await?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await?;

    let (one,): (i32,) = sqlx::query_as("SELECT 1").fetch_one(&pool).await?;
    println!("got {one}");
    Ok(())
}
```

`DcapVerifier` walks the quote's PCK certificate chain up to Intel's
root CA (embedded in the library). Platform-specific collateral —
TCB info, QE identity, CRLs — is fetched from a PCCS endpoint
(default: `https://api.trustedservices.intel.com`). No Intel
Trust Authority API key, no JWT, no per-connection HTTP round trip
to a third-party verifier service.

### Advanced: Intel Trust Authority opt-in

`IntelApiVerifier` is retained for callers who specifically want
Intel-signed JWT claims — e.g. compliance setups that require a
third-party attestation token signed by Intel. It requires an Intel
Trust Authority account and burns one Intel API call per verifier
invocation. For everyone else, prefer `DcapVerifier` — same claim
mapping, no account requirement, fewer moving parts.

```rust
use std::sync::Arc;
use sqlx_ra_tls::IntelApiVerifier;

let api_key = std::env::var("INTEL_TRUST_AUTHORITY_API_KEY")?;
let verifier = Arc::new(IntelApiVerifier::new(api_key));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`DATABASE_URL` format:

```
postgres://teesql_readwrite:<64-hex-cluster-secret>@<sidecar-host>:5433/<database>
```

The username must be either `teesql_read` (SELECT-only) or `teesql_readwrite` (full CRUD). The password is the 32-byte cluster secret expressed as 64 lowercase hex characters. Anything else is rejected with `Error::BadCredentials` before any network I/O happens.

### Development / tests (skip attestation)

```rust
use std::sync::Arc;
use sqlx_ra_tls::{pg_connect_opts_ra_tls, NoopVerifier, RaTlsOptions};

let verifier = Arc::new(NoopVerifier::new());
let opts = pg_connect_opts_ra_tls(
    &dsn,
    verifier,
    RaTlsOptions {
        allow_simulator: true,  // allow certs with no TDX quote extension
        allow_debug_mode: true, // allow debug TDs (never set in production)
        ..Default::default()
    },
).await?;
```

`NoopVerifier::new()` logs a warning on construction. It only bypasses **server-side** attestation — the client still must present a dstack-issued certificate, so a local dstack simulator has to be running:

```bash
DSTACK_SIMULATOR_ENDPOINT=http://127.0.0.1:8090 cargo test
```

## CVM-only

`sqlx-ra-tls` enforces mutual RA-TLS. The client certificate is sourced at runtime from the dstack guest agent, which means:

- In production, the app must run inside a dstack CVM (default sockets: `/var/run/dstack.sock`, `/run/dstack.sock`, or the dstack/dstack.sock variants).
- For local development, run the [dstack simulator](https://github.com/Dstack-TEE/dstack/tree/master/sdk/simulator) and point `DSTACK_SIMULATOR_ENDPOINT` at it.

If neither is reachable, `pg_connect_opts_ra_tls` returns `Error::MissingDstackSocket`. There is no plain-TLS fallback by design: the sidecar rejects unauthenticated clients, so a fallback would fail later anyway with a less useful error.

## `RaTlsOptions`

```rust
pub struct RaTlsOptions {
    /// Hex (with or without 0x prefix) MRTD values to accept. Empty = any.
    pub allowed_mrtds: Vec<String>,
    /// Allow debug TDs. Never set to true in production.
    pub allow_debug_mode: bool,
    /// Skip server-side verification when the cert carries no TDX quote.
    /// Required for dstack simulator targets.
    pub allow_simulator: bool,
    /// Inject a pre-fetched client cert (for tests). Normally leave `None`.
    pub client_cert_override: Option<DstackClientCert>,
}
```

## Custom verifier

Implement the [`RaTlsVerifier`](./src/types.rs) trait to plug a caching proxy, a different TEE family (AMD SEV-SNP, Nitro), or any other backend in place of `DcapVerifier`:

```rust
use async_trait::async_trait;
use sqlx_ra_tls::{RaTlsVerifier, VerificationResult, VerifyError, VerifyOptions};

pub struct MyVerifier;

#[async_trait]
impl RaTlsVerifier for MyVerifier {
    async fn verify(
        &self,
        quote: &[u8],
        options: &VerifyOptions,
    ) -> Result<VerificationResult, VerifyError> {
        // Verify the quote with your own backend.
        // Return VerificationResult on success, VerifyError on rejection.
        todo!()
    }
}
```

## How RA-TLS works

In a standard TLS handshake, the server's certificate is signed by a trusted CA. In RA-TLS, the server generates a **self-signed** certificate and embeds a hardware attestation quote in a custom X.509 extension. The quote proves:

- The server is running inside a genuine Intel TDX Trusted Domain
- The TD's measurements (MRTD, RTMRs) match the expected software stack
- The platform's TCB (firmware + microcode) is up to date

The TLS public key is bound to the quote via the `REPORTDATA` field, preventing a man-in-the-middle from substituting their own certificate.

`sqlx-ra-tls` parses the Phala RA-TLS extensions (OID `1.3.6.1.4.1.62397.1.1` and the newer `1.3.6.1.4.1.62397.1.8` SCALE-encoded envelope) and delegates quote verification to the verifier you inject. The default `DcapVerifier` walks the PCK chain locally — same primitive `dstack-verifier` uses, no Intel account required.

See also: [`docs/architecture/monitoring-deployment.md`](../../docs/architecture/monitoring-deployment.md) for how the monitoring hub consumes this crate, and [`docs/plans/monitoring-hub-deployment.md`](../../docs/plans/monitoring-hub-deployment.md) for the deployment contract.

## Security considerations

- **Always pin `allowed_mrtds`** in production. Without it, any legitimate TDX CVM running any code is accepted.
- **Never set `allow_debug_mode = true`** in production. Debug TDs can be inspected and have no confidentiality.
- **`allow_simulator = true`** disables server-side quote verification. Never use in production.
- **TOCTOU caveat.** sqlx 0.8 does not expose a ServerCertVerifier hook, so we verify the server's attested identity via a dedicated pre-flight probe before handing options to sqlx. The probe captures the server cert fingerprint — use [`sqlx_ra_tls::verify_server`] in a `PgPoolOptions::before_acquire` callback to re-verify periodically if your threat model requires detection of mid-pool CVM substitution.
- **PCCS availability.** `DcapVerifier` fetches platform certs from a PCCS (Intel's public endpoint by default, or any mirror you configure). Cold-starts for an unseen FMSPC fail until PCCS returns — much softer than the v0.1 Intel-TA hard dependency, but still a network dependency. For air-gapped deployments, fetch + cache `QuoteCollateralV3` out of band and call `DcapVerifier::verify_with_collateral` directly.
- **Intel Trust Authority** (when using `IntelApiVerifier`) is a third-party hosted service. Attestation failures will prevent new connections from being established. Plan for retries and connection pool warmup.

## Roadmap

- [ ] v0.3 — cached verifier wrapper so collateral fetches are only run once per FMSPC per TTL.
- [ ] v0.4 — optional `sqlx::postgres` `before_acquire` helper that runs `verify_server` automatically on pool check-out.

## License

Apache 2.0 — see [LICENSE](LICENSE).

The Apache 2.0 license was chosen because the TEE/attestation space involves patents held by Intel and others. Apache 2.0 includes an explicit patent grant, protecting users of this library.
