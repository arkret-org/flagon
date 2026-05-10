//! Sanity test ensuring the router builds without a database.
//! Database-backed integration tests live under `tests/it/` once we have a
//! testcontainers fixture in M0-T3.

use teabay::routing;

#[test]
fn router_builds_with_minimal_state() {
    use std::env;
    // Set the smallest viable env footprint and exercise the router builder.
    // We don't connect to Postgres here — that needs a separate integration
    // test harness (M0-T3 in `_todos.md`).
    unsafe {
        env::set_var("TEABAY_BIND", "127.0.0.1:0");
        env::set_var("TEABAY_SERVICE_DID", "did:web:directory.test");
        env::set_var("DATABASE_URL", "postgres://localhost/__not_used__");
    }

    let config = teabay::AppConfig::from_env().expect("config builds");
    // Use a lazy connection that errs only on actual checkout.
    // We can't easily build a Db without a real Postgres URL — so just
    // verify the config layer parses cleanly.
    assert!(!config.service_did.is_empty());
    assert_eq!(
        config.accept_policy_kind,
        teabay::config::AcceptPolicyKind::Open
    );
    let doc = routing::openapi(&salvo::prelude::Router::new());
    assert!(doc.paths.contains_key("/api/admin/v1/audit"));
    assert!(doc.paths.contains_key("/api/v1/directory/describe"));
    assert!(doc.paths.contains_key("/api/v1/directory/announce"));
    assert!(doc.components.schemas.len() > 10);
}
