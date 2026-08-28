#![allow(
    unsafe_code,
    reason = "integration tests mutate process environment before server startup and restore it"
)]

//! DID-P0-C04 — the `/metrics` face really exposes the two DID counters the
//! cotest joint call-count contract (`DID-P1-C01`) consumes, and they move.
//!
//! `teabay_did_resolve_total{method,source}` and
//! `teabay_signature_verify_total{kind,outcome}` are the *only* way the
//! black-box joint harness can observe teabay's DID behaviour: cotest talks to
//! a prebuilt binary over HTTP and cannot inject a Rust resolver spy. This test
//! pins the exposition names, the label families, the pre-seeded zero series,
//! and — critically — that
//! `authority_network_call_count` (`source="network"`) stays at zero for a
//! `did:key` signer while `signature_verify_count` grows with every signature.

use std::sync::Mutex;

use arkret_identity::binding::DidBindingPurpose;
use arkret_signatures::jws::sign_jws_ed25519;
use arkret_wire::{Did, DidUrl};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use salvo::test::{ResponseExt, TestClient};
use server::observability::{
    DID_RESOLVE_SOURCE_BINDING_STORE, DID_RESOLVE_SOURCE_DID_KEY, DID_RESOLVE_SOURCE_NETWORK,
    SIGNATURE_KIND_INVITE_TOKEN, SIGNATURE_OUTCOME_OK,
};

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn app_state() -> server::AppState {
    use std::env;
    let _guard = ENV_LOCK.lock().expect("env lock");
    unsafe {
        env::set_var("TEABAY_BIND", "127.0.0.1:0");
        env::set_var("TEABAY_SERVICE_DID", "did:web:directory.test");
        env::set_var(
            "TEABAY_SERVICE_METHOD_HISTORY_HEAD",
            "did-web-document-etag-fixture",
        );
        env::set_var(
            "TEABAY_SERVICE_VERSION_ID",
            "did-web-document-version-fixture",
        );
        env::set_var("DATABASE_URL", "postgres://localhost/__not_used__");
        env::set_var("TEABAY_DEVELOPMENT_MODE", "true");
        env::set_var("TEABAY_REQUIRE_HTTP_SIG", "false");
        env::set_var("TEABAY_ACCEPTED_DID_METHODS", "did:key,did:webvh");
    }
    let config = server::AppConfig::from_env().expect("config builds");
    // No query is issued by `/metrics` (only `pool_stats`), so a lazily built
    // pool is enough here.
    let db = server::Db::connect("postgres://localhost/__not_used__").expect("db handle");
    server::AppState::new(config, db).expect("app state builds")
}

fn did_key_signer(seed: u8) -> (SigningKey, Did, DidUrl) {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        signing_key.verifying_key().as_bytes(),
    );
    let did = Did::new(format!("did:key:{multibase}")).expect("did");
    let verification_method = DidUrl::new(format!("{did}#{multibase}")).expect("did url");
    (signing_key, did, verification_method)
}

async fn scrape(state: &server::AppState) -> String {
    let router = server::metrics_service(state.clone());
    let mut response = TestClient::get("http://teabay.test/metrics")
        .send(&router)
        .await;
    response.take_string().await.expect("metrics body")
}

#[tokio::test]
async fn metrics_expose_did_resolve_and_signature_verify_counters() {
    let state = app_state();

    let before = scrape(&state).await;
    assert!(
        before.contains("# TYPE teabay_did_resolve_total counter"),
        "the DID resolve family must exist before the first resolution:\n{before}"
    );
    assert!(
        before.contains("# TYPE teabay_signature_verify_total counter"),
        "the signature-verify family must exist before the first signature"
    );
    // Pre-seeded zero series so a scraper never sees a missing series.
    assert!(
        before.contains(
            "teabay_signature_verify_total{kind=\"invite_token\",outcome=\"ok\"} 0.000000"
        )
    );
    assert!(before.contains(
        "teabay_signature_verify_total{kind=\"http_signature\",outcome=\"invalid\"} 0.000000"
    ));

    // Drive three real signature verifications through the zero-network query
    // face, exactly as `query::target` / `filter::discoverers` do.
    let (signing_key, did, verification_method) = did_key_signer(29);
    let payload = b"canonical-token-payload";
    let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");
    let bindings = state.did_bindings();
    for _ in 0..3 {
        bindings
            .verify_detached_jws(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIssuer,
                SIGNATURE_KIND_INVITE_TOKEN,
                Utc::now(),
            )
            .expect("did:key token verifies with zero network access");
    }

    let after = scrape(&state).await;
    assert!(
        after.contains("teabay_did_resolve_total{method=\"key\",source=\"did_key\"} 1.000000"),
        "only the first verification decodes the did:key:\n{after}"
    );
    assert!(
        after
            .contains("teabay_did_resolve_total{method=\"key\",source=\"binding_store\"} 2.000000"),
        "the other two reuse the accepted binding:\n{after}"
    );
    // No *sample* line carries `source="network"` (the HELP text mentions the
    // label value, which is why this checks samples rather than the whole body).
    assert!(
        !after
            .lines()
            .any(|line| line.starts_with("teabay_did_resolve_total{")
                && line.contains("source=\"network\"")),
        "a did:key signer must never appear as an authority network call:\n{after}"
    );
    assert!(
        after.contains(
            "teabay_signature_verify_total{kind=\"invite_token\",outcome=\"ok\"} 3.000000"
        ),
        "every signature is counted, independently of the resolution count:\n{after}"
    );

    // And the in-process accessors the unit tests use agree with the exposition.
    let metrics = state.metrics();
    assert_eq!(metrics.did_resolve_count(DID_RESOLVE_SOURCE_NETWORK), 0);
    assert_eq!(metrics.did_resolve_count(DID_RESOLVE_SOURCE_DID_KEY), 1);
    assert_eq!(
        metrics.did_resolve_count(DID_RESOLVE_SOURCE_BINDING_STORE),
        2
    );
    assert_eq!(
        metrics.signature_verify_count(SIGNATURE_KIND_INVITE_TOKEN, SIGNATURE_OUTCOME_OK),
        3
    );
}
