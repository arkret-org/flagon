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
//! Pubkey resolution is via the [`HttpSigKeyDirectory`] trait. Production
//! routing uses [`DidResolverKeyDirectory`], which first checks the static
//! operator allowlist and then resolves DID-URL `keyid` values via the
//! same DID resolver policy used by ingest proof verification. The
//! [`StaticKeyDirectory`] remains available for unit tests and as a
//! deterministic fallback path.
//!
//! ## Failure modes (mapped to teabay error codes)
//!
//! | Condition                                  | HTTP | errcode              |
//! |--------------------------------------------|------|----------------------|
//! | Missing `Signature-Input` / `Signature`    | 401  | `unauthenticated`    |
//! | Malformed `Signature-Input`                | 400  | `signature_invalid`  |
//! | Unknown `keyid`                            | 401  | `invalid_signature`  |
//! | Ed25519 verify failure                     | 401  | `invalid_signature`  |
//! | Replay of previously accepted signature    | 401  | `invalid_signature`  |
//! | `Content-Digest` present but mismatches    | 401  | `invalid_signature`  |
//! | Required signed component missing on req   | 400  | `signature_invalid`  |
//!
//! `invalid_signature` is the canonical Contrix v1 code per
//! `error-code-registry.json` (401, scope=both); `signature_invalid` is the
//! ingest-specific §8 code (400) for header-shape problems.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
pub use contrix_sdk::http_signature::Ed25519PublicKey;
use contrix_sdk::http_signature::{
    ContentDigest, SignatureError, SignaturePolicyError, SignatureVerificationPolicy,
    SignedRequestParts, canonical_message, parse_signature_header, parse_signature_input,
    verify_content_digest, verify_signature,
};
use contrix_sdk::identity::DidResolver;
use contrix_sdk::jws::resolve_ed25519_pubkey;
use contrix_sdk::{CompositeDidResolver, Did};
use diesel::sql_types::{Bytea, Text, Timestamptz};
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::did_resolver::did_resolver_chain;
use crate::error::ApiErrorCode;

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

/// Key directory used by production routing.
///
/// Static keys are checked first so tests and emergency operator
/// overrides remain deterministic. If the key is not configured
/// statically and `key_id` is a DID URL, the directory lazily builds the
/// teabay DID resolver chain and asks the SDK JWS verifier helper to
/// resolve the Ed25519 verification method.
#[derive(Debug)]
pub struct DidResolverKeyDirectory {
    static_keys: StaticKeyDirectory,
    accepted_did_methods: Vec<String>,
    resolver: Mutex<Option<Arc<CompositeDidResolver>>>,
}

impl DidResolverKeyDirectory {
    pub fn new(
        static_keys: HashMap<String, Ed25519PublicKey>,
        accepted_did_methods: Vec<String>,
    ) -> Self {
        Self {
            static_keys: StaticKeyDirectory::from_map(static_keys),
            accepted_did_methods,
            resolver: Mutex::new(None),
        }
    }

    fn resolver(&self) -> Result<Arc<CompositeDidResolver>, String> {
        let mut resolver = self
            .resolver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = resolver.as_ref() {
            return Ok(Arc::clone(existing));
        }
        let built = Arc::new(did_resolver_chain(&self.accepted_did_methods)?);
        *resolver = Some(Arc::clone(&built));
        Ok(built)
    }
}

impl HttpSigKeyDirectory for DidResolverKeyDirectory {
    fn lookup(&self, key_id: &str) -> Option<Ed25519PublicKey> {
        if let Some(static_key) = self.static_keys.lookup(key_id) {
            return Some(static_key);
        }

        let did = key_id.split_once('#').map(|(did, _)| did).unwrap_or(key_id);
        let did = Did::new(did.to_owned()).ok()?;
        let resolver = match self.resolver() {
            Ok(resolver) => resolver,
            Err(err) => {
                tracing::debug!(%err, %key_id, "HTTP signature DID key resolver init failed");
                return None;
            }
        };
        if !resolver.supports(&did) {
            return None;
        }
        match resolve_ed25519_pubkey(resolver.as_ref(), key_id) {
            Ok(public_key) => Some(public_key),
            Err(err) => {
                tracing::debug!(%err, %key_id, "HTTP signature DID key resolve failed");
                None
            }
        }
    }
}

/// Salvo middleware enforcing RFC 9421 HTTP Message Signatures on the
/// hooped routes (i.e. teabay's ingest face). Construct via
/// [`HttpSigMiddleware::new`] with a [`HttpSigKeyDirectory`] and mount
/// via `Router::hoop`.
pub struct HttpSigMiddleware {
    directory: Arc<dyn HttpSigKeyDirectory>,
    /// Accepted signatures keyed by signer and signature bytes until their
    /// effective `expires` window closes. Production routing wires this to
    /// Postgres so multiple teabay replicas share the replay window; unit tests
    /// use the in-memory implementation.
    replay_store: Arc<dyn HttpSigReplayStore>,
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
        Self::new_with_replay_store(directory, Arc::new(InMemoryReplayStore::default()))
    }

    /// Build a middleware backed by the shared Postgres replay table. If the
    /// table cannot be read/written at request time, verification fails closed.
    pub fn new_with_postgres_replay_store(directory: Arc<dyn HttpSigKeyDirectory>, db: Db) -> Self {
        Self::new_with_replay_store(directory, Arc::new(PostgresReplayStore::new(db)))
    }

    pub(crate) fn new_with_replay_store(
        directory: Arc<dyn HttpSigKeyDirectory>,
        replay_store: Arc<dyn HttpSigReplayStore>,
    ) -> Self {
        Self {
            directory,
            replay_store,
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
            replay_store: Arc::new(InMemoryReplayStore::default()),
            enforced: false,
        }
    }

    /// Force-set enforcement mode after construction.
    pub fn set_enforced(&mut self, enforced: bool) {
        self.enforced = enforced;
    }

    async fn remember_signature(
        &self,
        replay_key: ReplayKey,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, String> {
        self.replay_store
            .remember_signature(replay_key, expires_at, now)
            .await
    }
}

#[async_trait]
pub(crate) trait HttpSigReplayStore: Send + Sync + 'static {
    async fn remember_signature(
        &self,
        replay_key: ReplayKey,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, String>;
}

#[derive(Debug, Default)]
pub(crate) struct InMemoryReplayStore {
    seen_signatures: Mutex<HashMap<ReplayKey, i64>>,
}

#[async_trait]
impl HttpSigReplayStore for InMemoryReplayStore {
    async fn remember_signature(
        &self,
        replay_key: ReplayKey,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, String> {
        let mut seen_signatures = self
            .seen_signatures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        seen_signatures.retain(|_, expires_at| *expires_at >= now);

        Ok(match seen_signatures.entry(replay_key) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(expires_at);
                true
            }
        })
    }
}

pub(crate) struct PostgresReplayStore {
    db: Db,
}

impl PostgresReplayStore {
    fn new(db: Db) -> Self {
        Self { db }
    }
}

#[async_trait]
impl HttpSigReplayStore for PostgresReplayStore {
    async fn remember_signature(
        &self,
        replay_key: ReplayKey,
        expires_at: i64,
        now: i64,
    ) -> Result<bool, String> {
        let now = unix_secs_to_datetime(now)?;
        let expires_at = unix_secs_to_datetime(expires_at)?;
        let replay_digest = replay_key.stable_digest();
        let mut conn = self
            .db
            .get()
            .await
            .map_err(|err| format!("acquire replay-cache connection: {err}"))?;

        diesel::sql_query("DELETE FROM http_signature_replays WHERE expires_at < $1")
            .bind::<Timestamptz, _>(now)
            .execute(&mut *conn)
            .await
            .map_err(|err| format!("purge expired replay-cache rows: {err}"))?;

        let inserted = diesel::sql_query(
            "INSERT INTO http_signature_replays \
             (replay_key, key_id, signature, expires_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (replay_key) DO NOTHING",
        )
        .bind::<Bytea, _>(replay_digest)
        .bind::<Text, _>(replay_key.key_id)
        .bind::<Bytea, _>(replay_key.signature)
        .bind::<Timestamptz, _>(expires_at)
        .execute(&mut *conn)
        .await
        .map_err(|err| format!("insert replay-cache row: {err}"))?;

        Ok(inserted == 1)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ReplayKey {
    key_id: String,
    signature: Vec<u8>,
}

impl ReplayKey {
    fn new(key_id: &str, signature: &[u8]) -> Self {
        Self {
            key_id: key_id.to_owned(),
            signature: signature.to_vec(),
        }
    }

    fn stable_digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update((self.key_id.len() as u64).to_be_bytes());
        hasher.update(self.key_id.as_bytes());
        hasher.update((self.signature.len() as u64).to_be_bytes());
        hasher.update(&self.signature);
        hasher.finalize().to_vec()
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

        let now = unix_now_secs();
        let content_digest_raw = read_header(req, CONTENT_DIGEST_HEADER);
        let policy = SignatureVerificationPolicy::service_ingest()
            .max_clock_skew_seconds(SIGNATURE_MAX_CLOCK_SKEW_SECONDS);
        if let Err(err) = policy.validate(&signature_input, content_digest_raw.as_deref(), now) {
            let message = match err {
                SignaturePolicyError::MissingRequiredCoveredComponent => {
                    "HTTP Message Signature is missing required covered components"
                }
                SignaturePolicyError::MissingContentDigest => "content-digest header missing",
                SignaturePolicyError::InvalidValidityWindow => {
                    "HTTP Message Signature validity window is invalid"
                }
                SignaturePolicyError::CreatedInFuture => {
                    "HTTP Message Signature created timestamp is in the future"
                }
                SignaturePolicyError::Expired => "HTTP Message Signature has expired",
            };
            reject_invalid_signature(res, ctrl, message);
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
                ApiErrorCode::BadJson.render(
                    res,
                    format!("could not read request body for signature check: {err}"),
                );
                ctrl.skip_rest();
                return;
            }
        };

        let content_digest_raw =
            content_digest_raw.expect("policy requires content-digest to be present");
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

        let replay_key = ReplayKey::new(&signature_input.key_id, &signature_bytes);
        let replay_expires_at = signature_input
            .expires
            .saturating_add(SIGNATURE_MAX_CLOCK_SKEW_SECONDS);
        match self
            .remember_signature(replay_key, replay_expires_at, now)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                reject_invalid_signature(
                    res,
                    ctrl,
                    "HTTP Message Signature was already accepted within its validity window",
                );
                return;
            }
            Err(err) => {
                reject_invalid_signature(
                    res,
                    ctrl,
                    format!("HTTP Message Signature replay cache unavailable: {err}"),
                );
                return;
            }
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

fn unix_secs_to_datetime(secs: i64) -> Result<DateTime<Utc>, String> {
    DateTime::<Utc>::from_timestamp(secs, 0)
        .ok_or_else(|| format!("timestamp out of range for replay cache: {secs}"))
}

// ---------------------------------------------------------------------
// Rejection helpers
// ---------------------------------------------------------------------

fn reject_unauthenticated(res: &mut Response, ctrl: &mut FlowCtrl, message: impl Into<String>) {
    let message = message.into();
    tracing::debug!(reason = %message, "rejecting ingest request: unauthenticated");
    ApiErrorCode::Unauthenticated.render(res, message);
    ctrl.skip_rest();
}

fn reject_invalid_signature(res: &mut Response, ctrl: &mut FlowCtrl, message: impl Into<String>) {
    let message = message.into();
    tracing::debug!(reason = %message, "rejecting ingest request: invalid_signature");
    ApiErrorCode::InvalidSignature.render(res, message);
    ctrl.skip_rest();
}

fn reject_signature_invalid(res: &mut Response, ctrl: &mut FlowCtrl, message: impl Into<String>) {
    let message = message.into();
    tracing::debug!(reason = %message, "rejecting ingest request: signature_invalid");
    ApiErrorCode::SignatureInvalid.render(res, message);
    ctrl.skip_rest();
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use contrix_sdk::http_signature::{
        ContentDigest, ContentDigestAlgorithm, Ed25519SigningKey, canonical_message,
        parse_signature_input, sign_message, signing_key_from_seed,
    };
    use salvo::http::StatusCode;
    use salvo::test::{ResponseExt, SendTarget, TestClient};
    use serde_json::{Value as JsonValue, json};

    use super::*;

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

    fn did_key_multibase(signing_key: &Ed25519SigningKey) -> String {
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
        format!("z{}", bs58::encode(bytes).into_string())
    }

    fn router(directory: Arc<dyn HttpSigKeyDirectory>) -> Router {
        router_with_middleware(HttpSigMiddleware::new(directory))
    }

    fn router_with_middleware(middleware: HttpSigMiddleware) -> Router {
        Router::with_path("api/v1/directory/announce")
            .hoop(middleware)
            .post(ok_handler)
    }

    #[handler]
    async fn ok_handler(res: &mut Response) {
        res.render(Json(json!({ "ok": true })));
    }

    #[derive(Clone)]
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

    async fn post_signed(target: impl SendTarget + Send, signed: SignedRequest) -> Response {
        TestClient::post("http://teabay.test/api/v1/directory/announce")
            .add_header("host", "teabay.test", true)
            .add_header("signature-input", signed.signature_input, true)
            .add_header("signature", signed.signature, true)
            .add_header("content-digest", signed.content_digest, true)
            .bytes(signed.body)
            .add_header("content-type", "application/json", true)
            .send(target)
            .await
    }

    #[tokio::test]
    async fn signed_request_passes_middleware() {
        let dir = directory_with_test_key();
        let router = router(dir);
        let body = br#"{"resource_id":"cx:realm:tea"}"#;
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
    async fn did_resolver_key_directory_resolves_did_key_keyid() {
        let signing_key = signing_key();
        let multibase = did_key_multibase(&signing_key);
        let did = format!("did:key:{multibase}");
        let key_id = format!("{did}#{multibase}");
        let dir = DidResolverKeyDirectory::new(
            std::collections::HashMap::new(),
            vec!["did:key".to_owned()],
        );

        assert_eq!(dir.lookup(&key_id), Some(signing_key.verifying_key()));
    }

    #[tokio::test]
    async fn signed_request_passes_with_did_resolver_key_directory() {
        let signing_key = signing_key();
        let multibase = did_key_multibase(&signing_key);
        let did = format!("did:key:{multibase}");
        let key_id = format!("{did}#{multibase}");
        let dir = DidResolverKeyDirectory::new(
            std::collections::HashMap::new(),
            vec!["did:key".to_owned()],
        );
        let router = router(Arc::new(dir));
        let body = br#"{"resource_id":"cx:realm:tea"}"#;
        let signed = build_signed_request(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            body,
            &key_id,
            &signing_key,
        );

        let mut res = post_signed(router, signed).await;
        let status = res.status_code.unwrap_or(StatusCode::OK);
        let body_text = res.take_string().await.unwrap_or_default();
        assert_eq!(status, StatusCode::OK, "expected 200, body: {body_text}");
    }

    #[tokio::test]
    async fn replayed_valid_signature_returns_invalid_signature() {
        let dir = directory_with_test_key();
        let router = Arc::new(router(dir));
        let body = br#"{"resource_id":"cx:realm:tea"}"#;
        let signed = build_signed_request(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            body,
            TEST_KEY_ID,
            &signing_key(),
        );

        let mut first = post_signed(router.clone(), signed.clone()).await;
        let first_status = first.status_code.unwrap_or(StatusCode::OK);
        let first_body = first.take_string().await.unwrap_or_default();
        assert_eq!(
            first_status,
            StatusCode::OK,
            "first request should pass, body: {first_body}"
        );

        let mut second = post_signed(router, signed).await;
        let second_status = second.status_code.unwrap_or(StatusCode::OK);
        assert_eq!(second_status, StatusCode::UNAUTHORIZED);
        let second_body_text = second.take_string().await.unwrap_or_default();
        let body: JsonValue = serde_json::from_str(&second_body_text).unwrap();
        assert_eq!(body["error"]["code"], json!("invalid_signature"));
    }

    #[tokio::test]
    async fn replay_cache_can_be_shared_across_middleware_instances() {
        let directory: Arc<dyn HttpSigKeyDirectory> = directory_with_test_key();
        let replay_store: Arc<dyn HttpSigReplayStore> = Arc::new(InMemoryReplayStore::default());
        let router_a = Arc::new(router_with_middleware(
            HttpSigMiddleware::new_with_replay_store(directory.clone(), replay_store.clone()),
        ));
        let router_b = Arc::new(router_with_middleware(
            HttpSigMiddleware::new_with_replay_store(directory, replay_store),
        ));
        let body = br#"{"resource_id":"cx:realm:tea"}"#;
        let signed = build_signed_request(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            body,
            TEST_KEY_ID,
            &signing_key(),
        );

        let mut first = post_signed(router_a, signed.clone()).await;
        let first_status = first.status_code.unwrap_or(StatusCode::OK);
        let first_body = first.take_string().await.unwrap_or_default();
        assert_eq!(
            first_status,
            StatusCode::OK,
            "first request should pass, body: {first_body}"
        );

        let mut second = post_signed(router_b, signed).await;
        let second_status = second.status_code.unwrap_or(StatusCode::OK);
        assert_eq!(second_status, StatusCode::UNAUTHORIZED);
        let second_body_text = second.take_string().await.unwrap_or_default();
        let body: JsonValue = serde_json::from_str(&second_body_text).unwrap();
        assert_eq!(body["error"]["code"], json!("invalid_signature"));
    }

    #[tokio::test]
    async fn unsigned_request_returns_unauthenticated() {
        let dir = directory_with_test_key();
        let router = router(dir);
        let mut res = TestClient::post("http://teabay.test/api/v1/directory/announce")
            .add_header("host", "teabay.test", true)
            .add_header("content-type", "application/json", true)
            .bytes(br#"{"resource_id":"cx:realm:tea"}"#.to_vec())
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

        let body = br#"{"resource_id":"cx:realm:tea"}"#;
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
        let body = br#"{"resource_id":"cx:realm:tea"}"#;
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
        let body = br#"{"resource_id":"cx:realm:tea"}"#;
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
        let body = br#"{"resource_id":"cx:realm:tea"}"#;
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
        let body = br#"{"resource_id":"cx:realm:tea"}"#;
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
        let original = br#"{"resource_id":"cx:realm:tea"}"#;
        let signed = build_signed_request(
            "POST",
            "http://teabay.test/api/v1/directory/announce",
            "teabay.test",
            "/api/v1/directory/announce",
            original,
            TEST_KEY_ID,
            &signing_key(),
        );
        let tampered_body = br#"{"resource_id":"cx:realm:HIJACKED"}"#.to_vec();
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
