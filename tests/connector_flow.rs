//! Integration tests for the top-level connector helper.
//!
//! These tests don't require a running dstack endpoint or sidecar; they
//! drive `pg_connect_opts_ra_tls` just far enough to exercise DSN parsing
//! and the mandatory-client-cert invariant.

use std::sync::Arc;

use sqlx_ra_tls::{pg_connect_opts_ra_tls, Error, NoopVerifier, RaTlsOptions};

fn valid_dsn(host: &str) -> String {
    let pwd = "0123456789abcdef".repeat(4);
    assert_eq!(pwd.len(), 64);
    format!("postgres://teesql_readwrite:{pwd}@{host}:5433/monitoring_hub")
}

#[tokio::test]
async fn rejects_bad_username_before_dstack_lookup() {
    let pwd = "0123456789abcdef".repeat(4);
    let dsn = format!("postgres://postgres:{pwd}@127.0.0.1:5433/db");
    let verifier = Arc::new(NoopVerifier::new());
    let err = pg_connect_opts_ra_tls(&dsn, verifier, RaTlsOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::BadCredentials(_)));
}

#[tokio::test]
async fn rejects_missing_password_before_dstack_lookup() {
    let dsn = "postgres://teesql_readwrite@127.0.0.1:5433/db";
    let verifier = Arc::new(NoopVerifier::new());
    let err = pg_connect_opts_ra_tls(dsn, verifier, RaTlsOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::BadCredentials(_)));
}

#[tokio::test]
async fn demands_dstack_when_no_override() {
    // Don't set DSTACK_SIMULATOR_ENDPOINT and assume the test host has no
    // guest-agent socket. If this runs somewhere with a real dstack
    // socket, we'll get past the socket check and fail later on the
    // probe — still evidence that the DSN parsing succeeded.
    let dsn = valid_dsn("127.0.0.1");
    let verifier = Arc::new(NoopVerifier::new());
    let prev = std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok();
    // SAFETY: process-global mutation. The tests in this file each await
    // a single `pg_connect_opts_ra_tls` call and do not spawn threads of
    // their own; tokio's test runtime uses a current-thread scheduler by
    // default so the env touch is effectively single-threaded. The
    // previous value is restored before this test exits.
    unsafe {
        std::env::remove_var("DSTACK_SIMULATOR_ENDPOINT");
    }

    let result = pg_connect_opts_ra_tls(&dsn, verifier, RaTlsOptions::default()).await;

    // Restore env before asserting so failures don't leak state to other
    // tests that might run afterwards in the same process.
    unsafe {
        match prev {
            Some(v) => std::env::set_var("DSTACK_SIMULATOR_ENDPOINT", v),
            None => std::env::remove_var("DSTACK_SIMULATOR_ENDPOINT"),
        }
    }

    match result {
        Err(Error::MissingDstackSocket) => {}
        Err(other) => {
            // If the host happens to have a dstack socket we'll fail
            // during the TLS probe because there's no server on
            // 127.0.0.1:5433. Accept either outcome as "connector tried
            // to do the right thing after DSN validation passed".
            eprintln!("note: dstack socket present on this host, skipping probe check ({other})");
        }
        Ok(_) => panic!("connector should not succeed without a real sidecar"),
    }
}
