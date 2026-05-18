//! RFC 9421 HTTP Message Signature middleware for teabay's ingest face.
//!
//! Closes the security gap noted in [`crate::ingest::verify`] (step 1 —
//! "transport — assumed enforced by middleware"). Before TB-1 this comment
//! was load-bearing but unbacked: nothing in [`crate::routing`] actually
//! mounted a transport-signature check on `/api/v1/directory/announce`,
//! `/withdraw`, or `/subscribe`, so the 5-step verify chain ran for any
//! caller — including ones who never proved control of the resource's
//! governance key. This module fixes that.
//!
//! Wire shape (must match [`contrix_sdk::http_signature`] / floria / soland):
//!
//! ```text
//! Signature-Input: sig1=("@method" "@target-uri" "@authority" "content-digest");\
//!     created=...;expires=...;keyid="<keyid>";alg="ed25519"
//! Signature: sig1=:BASE64STANDARD:
//! Content-Digest: sha-256=:BASE64STANDARD:
//! ```
//!
//! ## Pluggable key source
//!
//! Pubkey resolution is via the [`HttpSigKeyDirectory`] trait. v1 ships
//! the [`StaticKeyDirectory`] implementation backed by a
//! `HashMap<String, Ed25519PublicKey>` keyed by `keyid` (the same string
//! the signer placed in `Signature-Input` — usually a DID + key fragment
//! like `did:web:alice.example#push`). A future iteration will wire the
//! existing teabay `DidResolver` chain (used by
//! [`crate::ingest::verify::resolve_ed25519_pubkey`]) so the directory
//! does not have to be pre-populated; that's an explicit follow-up, not
//! a blocker for closing the unsigned-ingest hole.
//!
//! ## Failure modes (mapped to teabay error codes)
//!
//! | Condition                                  | HTTP | errcode              |
//! |--------------------------------------------|------|----------------------|
//! | Missing `Signature-Input` / `Signature`    | 401  | `unauthenticated`    |
//! | Malformed `Signature-Input`                | 400  | `signature_invalid`  |
//! | Unknown `keyid`                            | 401  | `invalid_signature`  |
//! | Ed25519 verify failure                     | 401  | `invalid_signature`  |
//! | `Content-Digest` present but mismatches    | 401  | `invalid_signature`  |
//! | Required signed component missing on req   | 400  | `signature_invalid`  |
//!
//! `invalid_signature` is the canonical Contrix v1 code per
//! `error-code-registry.json` (401, scope=both); `signature_invalid` is the
//! ingest-specific §8 code (400) for header-shape problems.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use contrix_sdk::http_signature::{
    Component, ContentDigest, SignatureError, SignedRequestParts, canonical_message,
    parse_signature_header, parse_signature_input, verify_content_digest, verify_signature,
};

pub use contrix_sdk::http_signature::Ed25519PublicKey;
use salvo::prelude::*;

use crate::error::ErrorCode;

const SIGNATURE_INPUT_HEADER: &str = "signature-input";
const SIGNATURE_HEADER: &str = "signature";
const CONTENT_DIGEST_HEADER: &str = "content-digest";
const SIGNATURE_MAX_CLOCK_SKEW_SECONDS: i64 = 5;

/// Pluggable pubkey resolution. The middleware looks up the signer's
/// Ed25519 verifying key from the `keyid` declared in
/// `Signature-Input`. Implementations are responsible for any policy
/// (allowlist, DID resolver hop, cache).
pub trait HttpSigKeyDirectory: Send + Sync + 'static {
    /// Return the Ed25519 verifying key for `key_id`, or `None` if the
    /// signer is not known / not authorised to push to this directory.
    fn lookup(&self, key_id: &str) -> Option<Ed25519PublicKey>;
}

/// In-memory pubkey allowlist — the v1 default. Operators populate it
/// at startup via configuration; the middleware never adds entries on
/// the fly.
#[derive(Debug, Default, Clone)]
pub struct StaticKeyDirectory {
    keys: HashMap<String, Ed25519PublicKey>,
}

impl StaticKeyDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_map(keys: HashMap<String, Ed25519PublicKey>) -> Self {
        Self { keys }
    }

    pub fn insert(&mut self, key_id: impl Into<String>, key: Ed25519PublicKey) {
        self.keys.insert(key_id.into(), key);
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl HttpSigKeyDirectory for StaticKeyDirectory {
    fn lookup(&self, key_id: &str) -> Option<Ed25519PublicKey> {
        self.keys.get(key_id).copied()
    }
}

/// Salvo middleware enforcing RFC 9421 HTTP Message Signatures on the
/// hooped routes (i.e. teabay's ingest face). Construct via
/// [`HttpSigMiddleware::new`] with a [`HttpSigKeyDirectory`] and mount
/// via `Router::hoop`.
pub struct HttpSigMiddleware {
    directory: Arc<dyn HttpSigKeyDirectory>,
    /// When `false`, every request short-circuits the verifier and is
    /// allowed through. Operators set this via `TEABAY_REQUIRE_HTTP_SIG`
    /// (default `true`); the in-process conformance harness flips it to
    /// `false` so its mock pushes don't have to carry signed envelopes.
    enforced: bool,
}

impl HttpSigMiddleware {
    /// Build a middleware that rejects every ingest request that does
    /// not produce a valid Ed25519 signature over the canonical RFC
    /// 9421 signing string.
    pub fn new(directory: Arc<dyn HttpSigKeyDirectory>) -> Self {
        Self {
            directory,
            enforced: true,
        }
    }

    /// Build a middleware that passes every request through unchanged.
    /// Used by tests that exercise the verify chain without producing a
    /// signed transport envelope. Not exposed to production
    /// configurations — `AppConfig::require_http_sig=false` is what
    /// flips this on at runtime.
    pub fn passthrough(directory: Arc<dyn HttpSigKeyDirectory>) -> Self {
        Self {
            directory,
            enforced: false,
        }
    }

    /// Force-set enforcement mode after construction.
    pub fn set_enforced(&mut self, enforced: bool) {
        self.enforced = enforced;
    }
}

#[async_trait]
impl Handler for HttpSigMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if !self.enforced {
            return;
        }

        // -- Phase 1: pull the canonical headers. -------------------------
        let Some(signature_input_raw) = read_header(req, SIGNATURE_INPUT_HEADER) else {
            reject_unauthenticated(res, ctrl, "signature-input header missing");
            return;
        };
        let Some(signature_raw) = read_header(req, SIGNATURE_HEADER) else {
            reject_unauthenticated(res, ctrl, "signature header missing");
            return;
        };

        let signature_input = match parse_signature_input(&signature_input_raw) {
            Ok(parsed) => parsed,
            Err(err) => {
                reject_signature_invalid(
                    res,
                    ctrl,
                    format!("signature-input header could not be parsed: {err}"),
                );
                return;
            }
        };

        // The v1 push profile is Ed25519-only — fail closed on anything
        // else rather than handing an unknown alg to the SDK verifier.
        if !signature_input.algorithm.eq_ignore_ascii_case("ed25519") {
            reject_signature_invalid(
                res,
                ctrl,
                format!(
                    "unsupported signature alg `{}`; only ed25519 is accepted on ingest",
                    signature_input.algorithm
                ),
            );
            return;
        }

        let required_components = [
            Component::Method,
            Component::TargetUri,
            Component::Authority,
            Component::Header(CONTENT_DIGEST_HEADER.to_owned()),
        ];
        if !signature_input.covers_all(&required_components) {
            reject_invalid_signature(
                res,
                ctrl,
                "HTTP Message Signature is missing required covered components",
            );
            return;
        }

        let now = unix_now_secs();
        if signature_input.created > now + SIGNATURE_MAX_CLOCK_SKEW_SECONDS {
            reject_invalid_signature(
                res,
                ctrl,
                "HTTP Message Signature created timestamp is in the future",
            );
            return;
        }
        if signature_input.expires < now - SIGNATURE_MAX_CLOCK_SKEW_SECONDS {
            reject_invalid_signature(res, ctrl, "HTTP Message Signature has expired");
            return;
        }

        let signature_bytes = match parse_signature_header(&signature_raw, &signature_input.label) {
            Ok(bytes) => bytes,
            Err(err) => {
                reject_signature_invalid(res, ctrl, format!("signature header malformed: {err}"));
                return;
            }
        };

        // -- Phase 2: load the body (cached) and validate content-digest --
        // RFC 9530: when `Content-Digest` is present, the digest MUST be
        // recomputed against the request body and rejected on mismatch.
        // We call `req.payload()` which caches the bytes so the
        // downstream handler's `parse_json()` still works.
        let body_bytes = match req.payload().await {
            Ok(bytes) => bytes.clone(),
            Err(err) => {
                ErrorCode::BadJson.render(
                    res,
                    format!("could not read request body for signature check: {err}"),
                );
                ctrl.skip_rest();
                return;
            }
        };

        let Some(content_digest_raw) = read_header(req, CONTENT_DIGEST_HEADER) else {
            reject_invalid_signature(res, ctrl, "content-digest header missing");
            return;
        };
        let parsed_digest = match ContentDigest::parse(&content_digest_raw) {
            Ok(digest) => digest,
            Err(err) => {
                reject_signature_invalid(
                    res,
                    ctrl,
                    format!("content-digest header malformed: {err}"),
                );
                return;
            }
        };
        if let Err(err) = verify_content_digest(&parsed_digest, &body_bytes) {
            reject_invalid_signature(
                res,
                ctrl,
                format!("content-digest does not match request body: {err}"),
            );
            return;
        }

        // -- Phase 3: build SignedRequestParts and canonical message. -----
        let parts = match signed_request_parts(req) {
            Ok(parts) => parts,
            Err(msg) => {
                reject_signature_invalid(res, ctrl, msg);
                return;
            }
        };
        let message = match canonical_message(&parts, &signature_input) {
            Ok(msg) => msg,
            Err(err) => {
                let msg = match err {
                    SignatureError::MissingCoveredComponent(name) => {
                        format!("signed component `{name}` is missing from the request")
                    }
                    other => format!("could not build canonical signing string: {other}"),
                };
                reject_signature_invalid(res, ctrl, msg);
                return;
            }
        };

        // -- Phase 4: look up the signer's pubkey and verify. -------------
        let Some(public_key) = self.directory.lookup(&signature_input.key_id) else {
            reject_invalid_signature(
                res,
                ctrl,
                format!(
                    "no Ed25519 verifying key is registered for keyid `{}`",
                    signature_input.key_id
                ),
            );
            return;
        };

        // The SDK helper takes the signature as base64 string, so we
        // re-encode the bytes we already decoded — this round-trips
        // through the same alphabet (standard) the inner-list `:...:`
        // wrapper produced. Cheap, and keeps the verify step inside the
        // SDK's typed-error surface.
        let signature_b64 = contrix_sdk::http_signature::encode_signature_b64(&signature_bytes);
        if let Err(err) = verify_signature(&message, &signature_b64, &public_key) {
            reject_invalid_signature(
                res,
                ctrl,
                format!("ed25519 signature verification failed: {err}"),
            );
            return;
        }

        // Authenticated. Drop to the next hop in the handler chain —
        // teabay's announce/withdraw/subscribe handlers do their own
        // §8 verify chain on top of this transport guarantee.
    }
}

// ---------------------------------------------------------------------
// Request-projection helpers
// ---------------------------------------------------------------------

/// Build the HTTP-framework-agnostic [`SignedRequestParts`] that
/// `canonical_message` needs from a Salvo `Request`. We deliberately do
/// NOT set `body_digest` here — `canonical_message` will read the
/// `content-digest` header value from `parts.headers`, which is the
/// exact byte sequence the signer canonicalised against. Body integrity
/// is enforced separately in phase 2.
fn signed_request_parts(req: &Request) -> Result<SignedRequestParts, String> {
    let method = req.method().as_str().to_owned();

    let authority = request_authority(req)
        .ok_or_else(|| "request authority (Host / :authority) is missing".to_owned())?;
    let path = req.uri().path().to_owned();
    let scheme = req
        .header::<String>("x-forwarded-proto")
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .or_else(|| req.uri().scheme_str().map(str::to_owned))
        .unwrap_or_else(|| "http".to_owned());
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| path.clone());
    let target_uri = if req.uri().scheme_str().is_some() && req.uri().authority().is_some() {
        req.uri().to_string()
    } else {
        format!("{scheme}://{authority}{path_and_query}")
    };

    let headers = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or("").to_owned(),
            )
        })
        .collect();

    Ok(SignedRequestParts {
        method,
        target_uri,
        authority,
        path,
        headers,
        body_digest: None,
    })
}

fn request_authority(req: &Request) -> Option<String> {
    if let Some(host) = req.header::<String>("host") {
        let trimmed = host.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    req.uri().authority().map(|a| a.to_string())
}

fn read_header(req: &Request, name: &str) -> Option<String> {
    req.headers().get(name).and_then(|value| {
        value
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    })
}

fn unix_now_secs() -> i64 {
    Utc::now().timestamp()
}

// ---------------------------------------------------------------------
// Rejection helpers
// ---------------------------------------------------------------------

fn reject_unauthenticated(res: &mut Response, ctrl: &mut FlowCtrl, message: impl Into<String>) {
    let message = message.into();
    tracing::debug!(reason = %message, "rejecting ingest request: unauthenticated");
    ErrorCode::Unauthenticated.render(res, message);
    ctrl.skip_rest();
}

fn reject_invalid_signature(res: &mut Response, ctrl: &mut FlowCtrl, message: impl Into<String>) {
    let message = message.into();
    tracing::debug!(reason = %message, "rejecting ingest request: invalid_signature");
    ErrorCode::InvalidSignature.render(res, message);
    ctrl.skip_rest();
}

fn reject_signature_invalid(res: &mut Response, ctrl: &mut FlowCtrl, message: impl Into<String>) {
    let message = message.into();
    tracing::debug!(reason = %message, "rejecting ingest request: signature_invalid");
    ErrorCode::SignatureInvalid.render(res, message);
    ctrl.skip_rest();
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use contrix_sdk::http_signature::{
        ContentDigest, ContentDigestAlgorithm, Ed25519SigningKey, canonical_message,
        parse_signature_input, sign_message, signing_key_from_seed,
    };
    use salvo::http::StatusCode;
    use salvo::test::{ResponseExt, TestClient};
    use serde_json::{Value as JsonValue, json};

    const TEST_KEY_ID: &str = "did:web:alice.example#push";
    const TEST_SEED: [u8; 32] = [7u8; 32];

    fn signing_key() -> Ed25519SigningKey {
        signing_key_from_seed(&TEST_SEED)
    }

    fn directory_with_test_key() -> Arc<StaticKeyDirectory> {
        let mut dir = StaticKeyDirectory::new();
        dir.insert(TEST_KEY_ID, signing_key().verifying_key());
        Arc::new(dir)
    }

    fn router(directory: Arc<dyn HttpSigKeyDirectory>) -> Router {
        Router::with_path("api/v1/directory/announce")
            .hoop(HttpSigMiddleware::new(directory))
            .post(ok_handler)
    }

    #[handler]
    async fn ok_handler(res: &mut Response) {
        res.render(Json(json!({ "ok": true })));
    }

    struct SignedRequest {
        body: Vec<u8>,
        signature_input: String,
        signature: String,
        content_digest: String,
    }

    fn build_signed_request(
        method: &str,
        target_uri: &str,
        authority: &str,
        path: &str,
        body: &[u8],
        key_id: &str,
        signing_key: &Ed25519SigningKey,
    ) -> SignedRequest {
        let now = unix_now_secs();
        build_signed_request_with_components_and_window(
            method,
            target_uri,
            authority,
            path,
            body,
            key_id,
            signing_key,
            &["@method", "@target-uri", "@authority", "content-digest"],
            now - 1,
            now + 300,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_signed_request_with_components_and_window(
        method: &str,
        target_uri: &str,
        authority: &str,
        path: &str,
        body: &[u8],
        key_id: &str,
        signing_key: &Ed25519SigningKey,
        covered_components: &[&str],
        created: i64,
        expires: i64,
    ) -> SignedRequest {
        let digest = ContentDigest::compute(body, ContentDigestAlgorithm::Sha256);
        let covered = covered_components
            .iter()
            .map(|component| format!("\"{component}\""))
            .collect::<Vec<_>>()
            .join(" ");
        let signature_input = format!(
            "sig1=({covered});created={created};expires={expires};\
             keyid=\"{key_id}\";alg=\"ed25519\""
        );
        let parsed = parse_signature_input(&signature_input).unwrap();
        let parts = SignedRequestParts {
            method: method.to_owned(),
            target_uri: target_uri.to_owned(),
            authority: authority.to_owned(),
            path: path.to_owned(),
            headers: vec![("content-digest".to_owned(), digest.wire_value.clone())],
            body_digest: None,
        };
        let message = canonical_message(&parts, &parsed).unwrap();
        let signature_b64 = sign_message(&message, signing_key);
        SignedRequest {
            body: body.to_vec(),
            signature_input,
            signature: format!("sig1=:{signature_b64}:"),
            content_digest: digest.wire_value,
        }
    }

    async fn post_signed(router: Router, signed: SignedRequest) -> Response {
        TestClient::post("http://teabay.test/api/v1/directory/announce")
            .add_header("host", "teabay.test", true)
            .add_header("signature-input", signed.signature_input, true)
            .add_header("signature", signed.signature, true)
            .add_header("content-digest", signed.content_digest, true)
            .bytes(signed.body)
            .add_header("content-type", "application/json", true)
            .send(router)
            .await
    }

    #[tokio::test]
    async fn signed_request_passes_middleware() {
        let dir = directory_with_test_key();
        let router = router(dir);
        let body = br#"{"resource_id":"cx:space:tea"}"#;
        let signed = build_signed_request(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            body,
            TEST_KEY_ID,
            &signing_key(),
        );
        let mut res = post_signed(router, signed).await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        let body_text = res.take_string().await.unwrap_or_default();
        assert_eq!(status, StatusCode::OK, "expected 200, body: {body_text}");
    }

    #[tokio::test]
    async fn unsigned_request_returns_unauthenticated() {
        let dir = directory_with_test_key();
        let router = router(dir);
        let mut res = TestClient::post("http://teabay.test/api/v1/directory/announce")
            .add_header("host", "teabay.test", true)
            .add_header("content-type", "application/json", true)
            .bytes(br#"{"resource_id":"cx:space:tea"}"#.to_vec())
            .send(router)
            .await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let body_text = res.take_string().await.unwrap_or_default();
        let body: JsonValue = serde_json::from_str(&body_text).unwrap();
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["error"]["code"], json!("unauthenticated"));
    }

    #[tokio::test]
    async fn wrong_key_signature_returns_invalid_signature() {
        // Sign with one key, register a different key under the same keyid.
        let mut dir = StaticKeyDirectory::new();
        let other_key = signing_key_from_seed(&[42u8; 32]);
        dir.insert(TEST_KEY_ID, other_key.verifying_key());
        let router = router(Arc::new(dir));

        let body = br#"{"resource_id":"cx:space:tea"}"#;
        let signed = build_signed_request(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            body,
            TEST_KEY_ID,
            &signing_key(),
        );
        let mut res = TestClient::post("http://teabay.test/api/v1/directory/announce")
            .add_header("host", "teabay.test", true)
            .add_header("signature-input", signed.signature_input, true)
            .add_header("signature", signed.signature, true)
            .add_header("content-digest", signed.content_digest, true)
            .add_header("content-type", "application/json", true)
            .bytes(signed.body)
            .send(router)
            .await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        let body_text = res.take_string().await.unwrap_or_default();
        assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body_text}");
        let body: JsonValue = serde_json::from_str(&body_text).unwrap();
        assert_eq!(body["error"]["code"], json!("invalid_signature"));
    }

    #[tokio::test]
    async fn missing_content_digest_returns_invalid_signature() {
        let dir = directory_with_test_key();
        let router = router(dir);
        let body = br#"{"resource_id":"cx:space:tea"}"#;
        let signed = build_signed_request(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            body,
            TEST_KEY_ID,
            &signing_key(),
        );
        let mut res = TestClient::post("http://teabay.test/api/v1/directory/announce")
            .add_header("host", "teabay.test", true)
            .add_header("signature-input", signed.signature_input, true)
            .add_header("signature", signed.signature, true)
            .add_header("content-type", "application/json", true)
            .bytes(signed.body)
            .send(router)
            .await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let body_text = res.take_string().await.unwrap_or_default();
        let body: JsonValue = serde_json::from_str(&body_text).unwrap();
        assert_eq!(body["error"]["code"], json!("invalid_signature"));
    }

    #[tokio::test]
    async fn signature_not_covering_content_digest_returns_invalid_signature() {
        let dir = directory_with_test_key();
        let router = router(dir);
        let body = br#"{"resource_id":"cx:space:tea"}"#;
        let now = unix_now_secs();
        let signed = build_signed_request_with_components_and_window(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            body,
            TEST_KEY_ID,
            &signing_key(),
            &["@method", "@target-uri", "@authority"],
            now - 1,
            now + 300,
        );
        let mut res = post_signed(router, signed).await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let body_text = res.take_string().await.unwrap_or_default();
        let body: JsonValue = serde_json::from_str(&body_text).unwrap();
        assert_eq!(body["error"]["code"], json!("invalid_signature"));
    }

    #[tokio::test]
    async fn expired_signature_returns_invalid_signature() {
        let dir = directory_with_test_key();
        let router = router(dir);
        let body = br#"{"resource_id":"cx:space:tea"}"#;
        let now = unix_now_secs();
        let signed = build_signed_request_with_components_and_window(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            body,
            TEST_KEY_ID,
            &signing_key(),
            &["@method", "@target-uri", "@authority", "content-digest"],
            now - 60,
            now - SIGNATURE_MAX_CLOCK_SKEW_SECONDS - 1,
        );
        let mut res = post_signed(router, signed).await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let body_text = res.take_string().await.unwrap_or_default();
        let body: JsonValue = serde_json::from_str(&body_text).unwrap();
        assert_eq!(body["error"]["code"], json!("invalid_signature"));
    }

    #[tokio::test]
    async fn future_signature_returns_invalid_signature() {
        let dir = directory_with_test_key();
        let router = router(dir);
        let body = br#"{"resource_id":"cx:space:tea"}"#;
        let now = unix_now_secs();
        let signed = build_signed_request_with_components_and_window(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            body,
            TEST_KEY_ID,
            &signing_key(),
            &["@method", "@target-uri", "@authority", "content-digest"],
            now + SIGNATURE_MAX_CLOCK_SKEW_SECONDS + 1,
            now + 300,
        );
        let mut res = post_signed(router, signed).await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let body_text = res.take_string().await.unwrap_or_default();
        let body: JsonValue = serde_json::from_str(&body_text).unwrap();
        assert_eq!(body["error"]["code"], json!("invalid_signature"));
    }

    #[tokio::test]
    async fn body_mutation_breaks_content_digest() {
        // Sign one body, post a different body with the same signature
        // headers. RFC 9530 content-digest mismatch must fire before
        // ed25519 verify even gets called.
        let dir = directory_with_test_key();
        let router = router(dir);
        let original = br#"{"resource_id":"cx:space:tea"}"#;
        let signed = build_signed_request(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            original,
            TEST_KEY_ID,
            &signing_key(),
        );
        let tampered_body = br#"{"resource_id":"cx:space:HIJACKED"}"#.to_vec();
        let mut res = TestClient::post("http://teabay.test/api/v1/directory/announce")
            .add_header("host", "teabay.test", true)
            .add_header("signature-input", signed.signature_input, true)
            .add_header("signature", signed.signature, true)
            .add_header("content-digest", signed.content_digest, true)
            .add_header("content-type", "application/json", true)
            .bytes(tampered_body)
            .send(router)
            .await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let body_text = res.take_string().await.unwrap_or_default();
        let body: JsonValue = serde_json::from_str(&body_text).unwrap();
        assert_eq!(body["error"]["code"], json!("invalid_signature"));
    }

    #[tokio::test]
    async fn malformed_signature_input_returns_signature_invalid() {
        let dir = directory_with_test_key();
        let router = router(dir);
        let mut res = TestClient::post("http://teabay.test/api/v1/directory/announce")
            .add_header("host", "teabay.test", true)
            .add_header(
                "signature-input",
                "this-is-not-a-valid-signature-input-header",
                true,
            )
            .add_header(
                "signature",
                format!("sig1=:{}:", BASE64_STANDARD.encode([0u8; 64])),
                true,
            )
            .add_header("content-type", "application/json", true)
            .bytes(br#"{}"#.to_vec())
            .send(router)
            .await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let body_text = res.take_string().await.unwrap_or_default();
        let body: JsonValue = serde_json::from_str(&body_text).unwrap();
        assert_eq!(body["error"]["code"], json!("signature_invalid"));
    }

    #[tokio::test]
    async fn passthrough_mode_skips_verification() {
        // When AppConfig::require_http_sig is false, the middleware MUST
        // pass every request through (used by tests / dev-mode harness).
        let dir = directory_with_test_key();
        let mw = HttpSigMiddleware::passthrough(dir);
        let router = Router::with_path("api/v1/directory/announce")
            .hoop(mw)
            .post(ok_handler);
        let mut res = TestClient::post("http://teabay.test/api/v1/directory/announce")
            .add_header("host", "teabay.test", true)
            .add_header("content-type", "application/json", true)
            .bytes(br#"{}"#.to_vec())
            .send(router)
            .await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        let body_text = res.take_string().await.unwrap_or_default();
        assert_eq!(status, StatusCode::OK, "body: {body_text}");
    }
}
