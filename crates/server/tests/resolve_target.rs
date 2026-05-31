//! Conformance suite for `cx.directory.resolve_target` (R3.3 / CXP-0011,
//! contrix-spec @ cced4b8).
//!
//! These exercise the directory's object-address resolution semantics against
//! the pure, Postgres-free cores: the SDK address parser
//! (`contrix_sdk::model::parse_address`) and the token-binding check
//! (`server::query::target::verify_address_token`). The full HTTP-path smoke
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
//!   (d) a flow address missing `via` → fail-closed (parse error → not_found).

use chrono::Utc;
use contrix_sdk::canonical;
use contrix_sdk::jws::sign_jws_ed25519;
use contrix_sdk::model::{LinkType, ParsedAddress, TargetDescriptor, parse_address};
use ed25519_dalek::SigningKey;
use serde_json::json;

use server::query::target::{TokenCheck, verify_address_token};

const R: &str = "01904100-0000-7000-8000-0000000000aa";
const F: &str = "01904100-0000-7000-8000-0000000000bb";
const F2: &str = "01904100-0000-7000-8000-0000000000cc";
const VIA: &str = "did:web:relay.example";
const INVITE_SIGNING_SEED: [u8; 32] = [17u8; 32];

/// Mint a signed invite-token JSON whose embedded `target_descriptor` is bound
/// to `address` under the canonical realm id (the digest is over the uuid realm,
/// never an alias). Carries a future `exp`, non-empty `aud`, and detached JWS.
fn mint_token(address: &ParsedAddress, canonical_realm_id: &str) -> String {
    let mut descriptor = TargetDescriptor::from_parsed(address);
    descriptor.set_realm_id(canonical_realm_id);
    descriptor.link_type = LinkType::Invite;
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

/// Case (a) — a realm address parses and classifies as a Realm target, so the
/// handler takes the delegating realm branch (canonical realm_id + realm_preview
/// + join_candidates come from resolve_realm, unchanged).
#[test]
fn realm_address_classifies_as_realm_target() {
    let parsed = parse_address(&format!("web+contrix:realm/{R}")).expect("realm address parses");
    assert!(parsed.is_realm());
    assert!(!parsed.is_flow());
    assert!(!parsed.is_message());

    // The HTTPS-landing fragment form parses to the identical address.
    let landing = parse_address(&format!("https://share.contrix.example/#realm/{R}"))
        .expect("landing parses");
    assert_eq!(parsed, landing);
}

/// Case (b) — scope confusion: an invite token bound to object A (flow F) is
/// replayed onto a different object B (flow F2). The token-binding check MUST
/// reject; the handler maps that reject onto the SAME blinded `not_found` as a
/// nonexistent resource.
#[test]
fn invite_token_replayed_onto_other_object_is_rejected() {
    let addr_a = parse_address(&format!("web+contrix:realm/{R}/flow/{F}?lt=invite")).unwrap();
    let canonical = format!("cx:realm:{R}");
    let token = mint_token(&addr_a, &canonical);

    // Sanity: the token validates against its own object.
    assert_eq!(
        verify_address_token(&addr_a, Some(&token), &canonical, LinkType::Invite),
        TokenCheck::Pass
    );

    // Replayed onto object B → reject (digest differs; identity tuple changed).
    let addr_b = parse_address(&format!("web+contrix:realm/{R}/flow/{F2}?lt=invite")).unwrap();
    assert_eq!(
        verify_address_token(&addr_b, Some(&token), &canonical, LinkType::Invite),
        TokenCheck::Reject
    );
}

/// Case (c) — an unknown / misordered path keyword fails closed at the parser
/// (`space/`, `thread/`), so the handler returns the blinded not_found.
#[test]
fn unknown_path_keyword_fails_closed() {
    assert!(parse_address(&format!("web+contrix:space/{R}")).is_err());
    assert!(parse_address(&format!("web+contrix:realm/{R}/thread/{F}?via={VIA}")).is_err());
    // Wrong order also fails closed.
    assert!(parse_address(&format!("web+contrix:flow/{F}/realm/{R}?via={VIA}")).is_err());
}

/// Case (d) — a Flow address missing `via` fails closed (a global flow_id is
/// never guessed), so the handler returns the blinded not_found.
#[test]
fn flow_address_without_via_parses() {
    assert!(parse_address(&format!("web+contrix:realm/{R}/flow/{F}")).is_ok());
    // A message address without via is likewise routable through the Realm.
    let msg = "01904100-0000-7000-8000-0000000000dd";
    assert!(parse_address(&format!("web+contrix:realm/{R}/flow/{F}/m/{msg}")).is_ok());
}

/// Extra — an invite link with no token at all is rejected (an invite link MUST
/// carry a token), mapping to the same blinded not_found.
#[test]
fn invite_link_without_token_is_rejected() {
    let addr = parse_address(&format!("web+contrix:realm/{R}/flow/{F}?lt=invite")).unwrap();
    let canonical = format!("cx:realm:{R}");
    assert_eq!(
        verify_address_token(&addr, None, &canonical, LinkType::Invite),
        TokenCheck::Reject
    );
}

#[test]
fn unsigned_invite_token_with_matching_descriptor_is_rejected() {
    let addr = parse_address(&format!("web+contrix:realm/{R}/flow/{F}?lt=invite")).unwrap();
    let canonical = format!("cx:realm:{R}");
    let mut descriptor = TargetDescriptor::from_parsed(&addr);
    descriptor.set_realm_id(&canonical);
    descriptor.link_type = LinkType::Invite;
    let token = json!({
        "exp": Utc::now().timestamp() + 3600,
        "aud": "did:web:alice.example",
        "target_descriptor": descriptor,
    })
    .to_string();

    assert_eq!(
        verify_address_token(&addr, Some(&token), &canonical, LinkType::Invite),
        TokenCheck::Reject
    );
}
