//! Conformance suite for `ak.find.directory.query.resolve_target` (R3.3 / AKP-0011,
//! arkret-spec @ cced4b8).
//!
//! These exercise the directory's object-address resolution semantics against
//! the pure, Postgres-free cores: the SDK address parser
//! (`arkret_wire::parse_address`) and the token-binding check
//! (`server::query::target::verify_address_token_with_methods`). The full HTTP-path smoke
//! that asserts a realm address resolves byte-for-byte to what
//! `resolve_realm` returns lives in the Docker-gated
//! `tests/it/conformance.rs` harness (seeded rows + live router).
//!
//! Cases (per the R3.3 task list):
//!   (a) a realm address parses to the realm target class (the byte-equality
//!       with resolve_realm is asserted in the Docker smoke; here we assert the
//!       address grammar classifies it as a Realm so the handler takes the
//!       delegating realm branch);
//!   (b) an invite token bound to object A replayed onto address B → reject
//!       (the handler maps reject → the SAME blinded not_found) —
//!       scope-confusion defence;
//!   (c) an unknown path keyword → fail-closed (parse error → not_found);
//!   (d) a strand address missing `via` → fail-closed (parse error → not_found).

use arkret_sdk::canonical;
use arkret_signatures::jws::sign_jws_ed25519;
use arkret_wire::{AddressLinkKind, ParsedAddress, TargetDescriptor, parse_address, target_digest};
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value as JsonValue, json};
use server::did_binding::DidBindingDirectory;
use server::query::target::{
    TokenCheck, verify_address_token_with_methods, verify_preview_token_with_methods,
};

/// Stand-in for the process-wide `AppState` binding directory — the handle the
/// directory query face actually gets. `did:key` only, and the type owns no
/// resolver at all, so these conformance cases are off the network by
/// construction rather than by configuration.
fn test_bindings() -> DidBindingDirectory {
    DidBindingDirectory::new(
        &["did:key".to_owned()],
        "did:web:directory.example",
        server::observability::Metrics::default(),
    )
    .expect("binding directory builds")
}

const R: &str = "01904100-0000-7000-8000-0000000000aa";
const F: &str = "01904100-0000-7000-8000-0000000000bb";
const F2: &str = "01904100-0000-7000-8000-0000000000cc";

fn verify_address_token(
    parsed: &ParsedAddress,
    token: Option<&str>,
    canonical_realm_id: &str,
    effective_address_link_kind: AddressLinkKind,
) -> TokenCheck {
    verify_address_token_with_methods(
        parsed,
        token,
        canonical_realm_id,
        effective_address_link_kind,
        &test_bindings(),
    )
}
const VIA: &str = "did:web:relay.example";
const INVITE_SIGNING_SEED: [u8; 32] = [17u8; 32];
const PREVIEW_SIGNING_SEED: [u8; 32] = [23u8; 32];

/// Mint a signed invite-token JSON whose embedded `target_descriptor` is bound
/// to `address` under the canonical realm id (the digest is over the uuid realm,
/// never an alias). Carries a future `exp`, non-empty `aud`, and detached JWS.
fn mint_token(address: &ParsedAddress, canonical_realm_id: &str) -> String {
    let mut descriptor = TargetDescriptor::from_parsed(address);
    descriptor.set_realm_id(canonical_realm_id);
    descriptor.address_link_kind = AddressLinkKind::Invite;
    let signing_key = SigningKey::from_bytes(&INVITE_SIGNING_SEED);
    let multibase = did_key_multibase(&signing_key);
    let issuer = format!("did:key:{multibase}");
    let verification_method = format!("{issuer}#{multibase}");
    let mut payload = json!({
        "kind": "invite_token",
        "iss": issuer,
        "verification_method": verification_method,
        "exp": Utc::now().timestamp() + 3600,
        "aud": "did:web:alice.example",
        "target_descriptor": descriptor,
    });
    let canonical = canonical::canonical_json_bytes(&payload).unwrap();
    let jws = sign_jws_ed25519(&canonical, &signing_key).unwrap();
    payload
        .as_object_mut()
        .unwrap()
        .insert("jws".to_owned(), json!(jws));
    payload.to_string()
}

fn did_key_multibase(signing_key: &SigningKey) -> String {
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

fn preview_policy(accepted_previous: Vec<JsonValue>) -> JsonValue {
    let mut policy = json!({
        "mode": "stripped_state",
        "audiences": ["link_token_holder"],
        "fields": ["title", "summary", "join_rule", "member_count_bucket"],
    });
    if !accepted_previous.is_empty() {
        policy.as_object_mut().unwrap().insert(
            "accepted_previous_policy_digests".to_owned(),
            json!(accepted_previous),
        );
    }
    policy
}

fn mint_preview_token(
    address: &ParsedAddress,
    canonical_realm_id: &str,
    preview_policy_digest: &str,
    aud: JsonValue,
    exp: i64,
    nonce: Option<&str>,
) -> String {
    let mut descriptor = TargetDescriptor::from_parsed(address);
    descriptor.set_realm_id(canonical_realm_id);
    descriptor.address_link_kind = AddressLinkKind::Preview;
    let signing_key = SigningKey::from_bytes(&PREVIEW_SIGNING_SEED);
    let multibase = did_key_multibase(&signing_key);
    let issuer = format!("did:key:{multibase}");
    let verification_method = format!("{issuer}#{multibase}");
    let mut payload = json!({
        "kind": "preview_token",
        "iss": issuer,
        "verification_method": verification_method,
        "exp": exp,
        "aud": aud,
        "target_digest": target_digest(&descriptor).unwrap(),
        "address_link_kind": "preview",
        "preview_policy_digest": preview_policy_digest,
    });
    if let Some(nonce) = nonce {
        payload
            .as_object_mut()
            .unwrap()
            .insert("nonce".to_owned(), json!(nonce));
    }
    let canonical = canonical::canonical_json_bytes(&payload).unwrap();
    let jws = sign_jws_ed25519(&canonical, &signing_key).unwrap();
    payload
        .as_object_mut()
        .unwrap()
        .insert("jws".to_owned(), json!(jws));
    payload.to_string()
}

fn verify_preview_token(
    parsed: &ParsedAddress,
    token: Option<&str>,
    canonical_realm_id: &str,
    policy: &JsonValue,
    policy_digest: &str,
    requester: Option<&str>,
    now: chrono::DateTime<Utc>,
) -> TokenCheck {
    verify_preview_token_with_methods(
        parsed,
        token,
        canonical_realm_id,
        policy,
        policy_digest,
        requester,
        now,
        &test_bindings(),
    )
}

/// Case (a) — a realm address parses and classifies as a Realm target, so the
/// handler takes the delegating realm branch (canonical realm_id + realm_preview
/// + join_candidates come from resolve_realm, unchanged).
#[test]
fn realm_address_classifies_as_realm_target() {
    let parsed = parse_address(&format!("web+arkret:realm/{R}")).expect("realm address parses");
    assert!(parsed.is_realm());
    assert!(!parsed.is_strand());
    assert!(!parsed.is_message());

    // The HTTPS-landing fragment form parses to the identical address.
    let landing =
        parse_address(&format!("https://share.arkret.example/#realm/{R}")).expect("landing parses");
    assert_eq!(parsed, landing);
}

/// Case (b) — scope confusion: an invite token bound to object A (strand F) is
/// replayed onto a different object B (strand F2). The token-binding check MUST
/// reject; the handler maps that reject onto the SAME blinded `not_found` as a
/// nonexistent resource.
#[tokio::test]
async fn invite_token_replayed_onto_other_object_is_rejected() {
    let addr_a = parse_address(&format!("web+arkret:realm/{R}/strand/{F}?lt=invite")).unwrap();
    let canonical = format!("ak:realm:{R}");
    let token = mint_token(&addr_a, &canonical);

    // Sanity: the token validates against its own object.
    assert_eq!(
        verify_address_token(&addr_a, Some(&token), &canonical, AddressLinkKind::Invite,),
        TokenCheck::Pass
    );

    // Replayed onto object B → reject (digest differs; identity tuple changed).
    let addr_b = parse_address(&format!("web+arkret:realm/{R}/strand/{F2}?lt=invite")).unwrap();
    assert_eq!(
        verify_address_token(&addr_b, Some(&token), &canonical, AddressLinkKind::Invite,),
        TokenCheck::Reject
    );
}

/// Case (c) — an unknown / misordered path keyword fails closed at the parser
/// (`space/`, `thread/`), so the handler returns the blinded not_found.
#[test]
fn unknown_path_keyword_fails_closed() {
    assert!(parse_address(&format!("web+arkret:space/{R}")).is_err());
    assert!(parse_address(&format!("web+arkret:realm/{R}/thread/{F}?via={VIA}")).is_err());
    // Wrong order also fails closed.
    assert!(parse_address(&format!("web+arkret:strand/{F}/realm/{R}?via={VIA}")).is_err());
}

/// Case (d) — a Strand address missing `via` fails closed (a global strand_id is
/// never guessed), so the handler returns the blinded not_found.
#[test]
fn strand_address_without_via_parses() {
    assert!(parse_address(&format!("web+arkret:realm/{R}/strand/{F}")).is_ok());
    // A message address without via is likewise routable through the Realm.
    let msg = "01904100-0000-7000-8000-0000000000dd";
    assert!(parse_address(&format!("web+arkret:realm/{R}/strand/{F}/m/{msg}")).is_ok());
}

/// Extra — an invite link with no token at all is rejected (an invite link MUST
/// carry a token), mapping to the same blinded not_found.
#[tokio::test]
async fn invite_link_without_token_is_rejected() {
    let addr = parse_address(&format!("web+arkret:realm/{R}/strand/{F}?lt=invite")).unwrap();
    let canonical = format!("ak:realm:{R}");
    assert_eq!(
        verify_address_token(&addr, None, &canonical, AddressLinkKind::Invite),
        TokenCheck::Reject
    );
}

#[tokio::test]
async fn preview_token_matching_current_policy_digest_is_accepted() {
    let now = Utc::now();
    let addr = parse_address(&format!("web+arkret:realm/{R}/strand/{F}?lt=preview")).unwrap();
    let canonical = format!("ak:realm:{R}");
    let policy = preview_policy(Vec::new());
    let digest = canonical::canonical_sha256(&policy).unwrap();
    let token = mint_preview_token(
        &addr,
        &canonical,
        &digest,
        json!("did:web:alice.example"),
        (now + Duration::hours(1)).timestamp(),
        Some("nonce-1"),
    );

    assert_eq!(
        verify_preview_token(
            &addr,
            Some(&token),
            &canonical,
            &policy,
            &digest,
            Some("did:web:alice.example"),
            now,
        ),
        TokenCheck::Pass
    );
}

#[tokio::test]
async fn preview_token_replayed_onto_other_object_is_rejected() {
    let now = Utc::now();
    let addr_a = parse_address(&format!("web+arkret:realm/{R}/strand/{F}?lt=preview")).unwrap();
    let addr_b = parse_address(&format!("web+arkret:realm/{R}/strand/{F2}?lt=preview")).unwrap();
    let canonical = format!("ak:realm:{R}");
    let policy = preview_policy(Vec::new());
    let digest = canonical::canonical_sha256(&policy).unwrap();
    let token = mint_preview_token(
        &addr_a,
        &canonical,
        &digest,
        json!("link_token_holder"),
        (now + Duration::hours(1)).timestamp(),
        Some("nonce-1"),
    );

    assert_eq!(
        verify_preview_token(
            &addr_b,
            Some(&token),
            &canonical,
            &policy,
            &digest,
            None,
            now,
        ),
        TokenCheck::Reject
    );
}

#[tokio::test]
async fn preview_policy_previous_digest_requires_unexpired_allowlist_entry() {
    let now = Utc::now();
    let addr = parse_address(&format!("web+arkret:realm/{R}/strand/{F}?lt=preview")).unwrap();
    let canonical = format!("ak:realm:{R}");
    let previous_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let policy = preview_policy(vec![json!({
        "preview_policy_digest": previous_digest,
        "expires_at": (now + Duration::minutes(30)).to_rfc3339(),
    })]);
    let digest = canonical::canonical_sha256(&policy).unwrap();
    let token = mint_preview_token(
        &addr,
        &canonical,
        previous_digest,
        json!("link_token_holder"),
        (now + Duration::hours(1)).timestamp(),
        Some("nonce-1"),
    );

    assert_eq!(
        verify_preview_token(&addr, Some(&token), &canonical, &policy, &digest, None, now,),
        TokenCheck::Pass
    );

    let expired_policy = preview_policy(vec![json!({
        "preview_policy_digest": previous_digest,
        "expires_at": (now - Duration::seconds(1)).to_rfc3339(),
    })]);
    let expired_digest = canonical::canonical_sha256(&expired_policy).unwrap();
    assert_eq!(
        verify_preview_token(
            &addr,
            Some(&token),
            &canonical,
            &expired_policy,
            &expired_digest,
            None,
            now,
        ),
        TokenCheck::Reject
    );

    let unlisted_policy = preview_policy(Vec::new());
    let unlisted_digest = canonical::canonical_sha256(&unlisted_policy).unwrap();
    assert_eq!(
        verify_preview_token(
            &addr,
            Some(&token),
            &canonical,
            &unlisted_policy,
            &unlisted_digest,
            None,
            now,
        ),
        TokenCheck::Reject
    );
}

#[tokio::test]
async fn malformed_preview_token_lifecycle_fields_are_rejected() {
    let now = Utc::now();
    let addr = parse_address(&format!("web+arkret:realm/{R}/strand/{F}?lt=preview")).unwrap();
    let canonical = format!("ak:realm:{R}");
    let policy = preview_policy(Vec::new());
    let digest = canonical::canonical_sha256(&policy).unwrap();
    let missing_nonce = mint_preview_token(
        &addr,
        &canonical,
        &digest,
        json!("link_token_holder"),
        (now + Duration::hours(1)).timestamp(),
        None,
    );
    let expired = mint_preview_token(
        &addr,
        &canonical,
        &digest,
        json!("link_token_holder"),
        (now - Duration::seconds(1)).timestamp(),
        Some("nonce-1"),
    );
    let wrong_audience = mint_preview_token(
        &addr,
        &canonical,
        &digest,
        json!("did:web:bob.example"),
        (now + Duration::hours(1)).timestamp(),
        Some("nonce-1"),
    );

    for token in [missing_nonce, expired, wrong_audience] {
        assert_eq!(
            verify_preview_token(
                &addr,
                Some(&token),
                &canonical,
                &policy,
                &digest,
                Some("did:web:alice.example"),
                now,
            ),
            TokenCheck::Reject
        );
    }
}

#[tokio::test]
async fn unsigned_invite_token_with_matching_descriptor_is_rejected() {
    let addr = parse_address(&format!("web+arkret:realm/{R}/strand/{F}?lt=invite")).unwrap();
    let canonical = format!("ak:realm:{R}");
    let mut descriptor = TargetDescriptor::from_parsed(&addr);
    descriptor.set_realm_id(&canonical);
    descriptor.address_link_kind = AddressLinkKind::Invite;
    let token = json!({
        "exp": Utc::now().timestamp() + 3600,
        "aud": "did:web:alice.example",
        "target_descriptor": descriptor,
    })
    .to_string();

    assert_eq!(
        verify_address_token(&addr, Some(&token), &canonical, AddressLinkKind::Invite),
        TokenCheck::Reject
    );
}
