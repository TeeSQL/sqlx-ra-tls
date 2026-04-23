//! Live end-to-end test against the monitor cluster's sidecar.
//!
//! Ignored by default because it requires:
//!
//! - A reachable `hub.teesql.com` (or `MONITOR_SIDECAR_HOST` env override).
//! - A valid `TEESQL_CLUSTER_SECRET` (32-byte hex).
//! - Either a dstack CVM host or `DSTACK_SIMULATOR_ENDPOINT` pointed at a
//!   running dstack simulator so the SDK can mint a client cert.
//!
//! Run manually with:
//!
//! ```bash
//! TEESQL_CLUSTER_SECRET=<hex> \
//! DSTACK_SIMULATOR_ENDPOINT=http://127.0.0.1:8090 \
//! cargo test --features live-test -- --ignored live_
//! ```

#![cfg(feature = "live-test")]

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use sqlx_ra_tls::{pg_connect_opts_ra_tls, NoopVerifier, RaTlsOptions};

fn cluster_secret() -> Option<String> {
    std::env::var("TEESQL_CLUSTER_SECRET").ok()
}

fn monitor_host() -> String {
    std::env::var("MONITOR_SIDECAR_HOST").unwrap_or_else(|_| "monitor.teesql.com".to_string())
}

#[tokio::test]
#[ignore]
async fn live_noop_verifier_connects_to_monitor_cluster() {
    let Some(secret) = cluster_secret() else {
        eprintln!("skipping live test: set TEESQL_CLUSTER_SECRET to a 64-char hex cluster secret");
        return;
    };

    let host = monitor_host();
    let dsn = format!("postgres://teesql_readwrite:{secret}@{host}:5433/monitoring_hub");

    let verifier = Arc::new(NoopVerifier::new());
    let opts = pg_connect_opts_ra_tls(
        &dsn,
        verifier,
        RaTlsOptions {
            allow_simulator: true,
            ..Default::default()
        },
    )
    .await
    .expect("pg_connect_opts_ra_tls should succeed against a reachable sidecar");

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("pool should connect through sqlx");

    let (one,): (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("SELECT 1 should return");
    assert_eq!(one, 1);
}
