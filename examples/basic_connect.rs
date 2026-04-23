//! Minimal end-to-end example for `sqlx-ra-tls`.
//!
//! Run with:
//!
//! ```bash
//! DATABASE_URL=postgres://teesql_readwrite:<64-hex>@<host>:5433/<db> \
//! INTEL_TRUST_AUTHORITY_API_KEY=<ita-key> \
//! cargo run --example basic_connect
//! ```
//!
//! In development, substitute `NoopVerifier` and set
//! `DSTACK_SIMULATOR_ENDPOINT`:
//!
//! ```bash
//! DSTACK_SIMULATOR_ENDPOINT=http://127.0.0.1:8090 \
//! cargo run --example basic_connect
//! ```

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use sqlx_ra_tls::{pg_connect_opts_ra_tls, IntelApiVerifier, NoopVerifier, RaTlsOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dsn = std::env::var("DATABASE_URL")?;
    let use_simulator = std::env::var("DSTACK_SIMULATOR_ENDPOINT").is_ok();

    let verifier: Arc<dyn sqlx_ra_tls::RaTlsVerifier> =
        match std::env::var("INTEL_TRUST_AUTHORITY_API_KEY").ok() {
            Some(key) => Arc::new(IntelApiVerifier::new(key)),
            None => {
                eprintln!(
                "INTEL_TRUST_AUTHORITY_API_KEY not set; falling back to NoopVerifier (dev only)"
            );
                Arc::new(NoopVerifier::new())
            }
        };

    let opts = pg_connect_opts_ra_tls(
        &dsn,
        verifier,
        RaTlsOptions {
            allow_simulator: use_simulator,
            ..Default::default()
        },
    )
    .await?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await?;

    let (one,): (i32,) = sqlx::query_as("SELECT 1").fetch_one(&pool).await?;
    println!("SELECT 1 returned {one}");

    pool.close().await;
    Ok(())
}
