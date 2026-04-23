# sqlx-ra-tls

A sqlx-compatible Postgres connector that verifies **TDX attestation** before allowing any queries through to a Postgres database running inside a Trusted Execution Environment (TEE).

Rust peer of [psycopg-ra-tls](https://github.com/teesql/psycopg-ra-tls) (Python) and [prisma-ra-tls](https://github.com/teesql/prisma-ra-tls) (TypeScript). Built for databases hosted on [dstack](https://github.com/Dstack-TEE/dstack) (Intel TDX) and fronted by a [teesql-sidecar](https://github.com/teesql/teesql-sidecar).

## What it does

When your application opens a connection to the sidecar, `sqlx-ra-tls`:

1. Fetches a short-lived, TDX-attested client certificate from the local dstack guest agent.
2. Performs an RA-TLS handshake with the server, presenting that client certificate for mutual authentication.
3. Extracts the TDX attestation quote from the server's self-signed RA-TLS certificate.
4. Submits the quote to [Intel Trust Authority](https://portal.trustauthority.intel.com) (or any custom verifier) and validates the response: debug mode off, TCB status acceptable, MRTD in allowlist when configured.
5. Only then hands a `PgConnectOptions` back to sqlx so the real connection pool can open.

If verification fails at any step, `pg_connect_opts_ra_tls` returns an error and no SQL is ever issued.

## Install

```toml
[dependencies]
sqlx-ra-tls = "0.1"
sqlx = { version = "0.8", features = ["postgres", "runtime-tokio", "tls-rustls"] }
```

Requires Rust >= 1.92 (for the `edition2024` dependencies pulled in transitively by sqlx 0.8).

## Usage

### Production (Intel Trust Authority)

```rust
use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use sqlx_ra_tls::{pg_connect_opts_ra_tls, IntelApiVerifier, RaTlsOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let api_key = std::env::var("INTEL_TRUST_AUTHORITY_API_KEY")?;
    let verifier = Arc::new(IntelApiVerifier::new(api_key));

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

Implement the [`RaTlsVerifier`](./src/types.rs) trait to plug a local DCAP verifier, a caching proxy, or anything else in place of Intel Trust Authority:

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

`sqlx-ra-tls` parses the Phala RA-TLS extensions (OID `1.3.6.1.4.1.62397.1.1` and the newer `1.3.6.1.4.1.62397.1.8` SCALE-encoded envelope) and delegates quote verification to the verifier you inject.

See also: [`docs/architecture/monitoring-deployment.md`](../../docs/architecture/monitoring-deployment.md) for how the monitoring hub consumes this crate, and [`docs/plans/monitoring-hub-deployment.md`](../../docs/plans/monitoring-hub-deployment.md) for the deployment contract.

## Security considerations

- **Always pin `allowed_mrtds`** in production. Without it, any legitimate TDX CVM running any code is accepted.
- **Never set `allow_debug_mode = true`** in production. Debug TDs can be inspected and have no confidentiality.
- **`allow_simulator = true`** disables server-side quote verification. Never use in production.
- **TOCTOU caveat.** sqlx 0.8 does not expose a ServerCertVerifier hook, so we verify the server's attested identity via a dedicated pre-flight probe before handing options to sqlx. The probe captures the server cert fingerprint — use [`sqlx_ra_tls::verify_server`] in a `PgPoolOptions::before_acquire` callback to re-verify periodically if your threat model requires detection of mid-pool CVM substitution.
- Intel Trust Authority is a third-party service. Attestation failures will prevent new connections from being established. Plan for retries and connection pool warmup.

## Roadmap

- [ ] v0.2 — cached verifier wrapper so Intel Trust Authority is only consulted once per server identity per TTL.
- [ ] v0.3 — optional `sqlx::postgres` `before_acquire` helper that runs `verify_server` automatically on pool check-out.
- [ ] v0.4 — local DCAP binary verifier for air-gapped deployments.

## License

Apache 2.0 — see [LICENSE](LICENSE).

The Apache 2.0 license was chosen because the TEE/attestation space involves patents held by Intel and others. Apache 2.0 includes an explicit patent grant, protecting users of this library.
