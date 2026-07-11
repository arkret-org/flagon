//! Private Contact Discovery via RFC 9497 VOPRF.
//!
//! Round 1 (`phase=blind`) evaluates client-supplied blinded Ristretto255
//! elements with the current epoch key. Round 2 (`phase=match`) compares
//! finalized VOPRF outputs against this Directory's public contact candidates
//! and returns a fixed-cardinality bitmap.

use arkret_sdk::Did;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand::rngs::OsRng;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use voprf::{BlindedElement, Group, Ristretto255, VoprfServer};

use crate::config::AppConfig;
use crate::error::ApiErrorCode;
use crate::middleware::AuthenticatedHttpSignature;
use crate::schema::psi_epoch_keys;
use crate::state::{AppState, RateLimitOutcome};

pub(crate) const VOPRF_PROFILE: &str = "RFC9497-OPRFV1-ristretto255-SHA512";
const MATCH_CARDINALITY: usize = 256;

type PsiServer = VoprfServer<Ristretto255>;
type PsiBlindedElement = BlindedElement<Ristretto255>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PsiContactDiscoveryRequestBody {
    pub phase: PsiPhase,
    pub requester: String,
    #[serde(default)]
    pub epoch: Option<String>,
    #[serde(default)]
    pub blinded_inputs: Vec<String>,
    #[serde(default)]
    pub query_id: Option<String>,
    #[serde(default)]
    pub match_tokens: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PsiPhase {
    Blind,
    Match,
}

#[derive(Debug, Serialize)]
pub struct PsiBlindOutcome {
    pub phase: &'static str,
    pub epoch: String,
    pub key_id: String,
    pub query_id: String,
    pub evaluations: Vec<String>,
    pub proofs: Vec<String>,
    pub padding_count: usize,
    pub voprf_profile: &'static str,
    pub server_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct PsiMatchOutcome {
    pub phase: &'static str,
    pub epoch: String,
    pub key_id: String,
    pub query_id: String,
    pub hit_bitmap: Vec<bool>,
    pub padding_count: usize,
    pub fixed_cardinality: usize,
    pub voprf_profile: &'static str,
}

#[derive(Debug, Clone, Queryable)]
struct PsiEpochKey {
    epoch: String,
    profile: String,
    server_key: Vec<u8>,
    public_key: Vec<u8>,
    tokens_indexed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = psi_epoch_keys)]
struct NewPsiEpochKey<'a> {
    epoch: &'a str,
    profile: &'a str,
    server_key: &'a [u8],
    public_key: &'a [u8],
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[handler]
pub async fn private_contact_discovery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    if !state.config().private_contact_discovery_enabled {
        ApiErrorCode::UnsupportedFeature.render(res, "private contact discovery is disabled");
        return;
    }

    // Spec §6.4: the PSI face is the most enumeration-sensitive query
    // endpoint, yet historically it was the only query handler that skipped
    // the shared per-IP query rate limit. Apply it on *both* the `blind` and
    // `match` rounds so the actual enumeration surface (the `match` round that
    // returns the hit bitmap) is throttled per client, not just the `blind`
    // opener. `resolve_client_ip` honours the trusted-proxy allowlist.
    if !crate::query::rate_limit::enforce_query_rate_limit(req, res, &state) {
        return;
    }
    let auth = match depot.get_typed::<AuthenticatedHttpSignature>() {
        Ok(auth) => auth.clone(),
        Err(_) => {
            ApiErrorCode::Unauthenticated.render(res, "PSI requires HTTP Message Signature");
            return;
        }
    };

    let body: PsiContactDiscoveryRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::BadJson.render(res, format!("malformed PSI request: {error}"));
            return;
        }
    };
    if body.requester.trim().is_empty() {
        ApiErrorCode::MissingParam.render(res, "requester is required");
        return;
    }
    let requester_did = match Did::new(body.requester.trim().to_owned()) {
        Ok(did) => did,
        Err(error) => {
            ApiErrorCode::InvalidParam.render(res, format!("requester must be a DID: {error}"));
            return;
        }
    };
    let signer_did = match signer_did_from_key_id(&auth.key_id) {
        Ok(did) => did,
        Err(message) => {
            ApiErrorCode::Unauthenticated.render(res, message);
            return;
        }
    };
    if signer_did != requester_did {
        ApiErrorCode::Unauthenticated.render(res, "requester must match HTTP signature keyid DID");
        return;
    }

    // Spec §6.4 anti-enumeration quota: at most `max_psi_queries_per_window`
    // *batches* per requester DID per quota window. A batch is one logical PSI
    // query, i.e. one `blind` round followed by its `match` round — so the
    // quota is charged once, at the `blind` phase that opens the batch. The
    // `match` continuation does not consume an additional unit (otherwise a
    // single legitimate query would cost two and the default of 1 would be
    // unusable).
    //
    // The quota window is a fixed wall-clock roll (default 24h) and MUST be
    // decoupled from the OPRF key epoch — a new epoch MUST NOT reset the
    // quota, and the client-supplied `body.epoch` MUST NOT participate in
    // the quota key (otherwise an attacker could rotate epoch per batch to
    // bypass the limit). `epoch` below selects the OPRF key only; it never
    // feeds the quota bucket.
    if matches!(body.phase, PsiPhase::Blind) {
        let quota_window = std::time::Duration::from_secs(state.config().psi_quota_window_seconds);
        let quota_bucket = Utc::now()
            .timestamp()
            .div_euclid(state.config().psi_quota_window_seconds as i64);
        // §6.4 requires the quota to be counted per authenticable principal /
        // device credential. This handler's wire contract carries requester
        // as a DID, so the PSI quota key is requester-primary. The IP-based
        // generic query limiter above remains a separate auxiliary hardening
        // dimension; it is not the PSI quota key.
        if let RateLimitOutcome::Limited { retry_after } = state.check_rate_limit_window(
            psi_quota_key(&signer_did, quota_bucket),
            state.config().max_psi_queries_per_window,
            quota_window,
        ) {
            if let Ok(value) = retry_after.as_secs().max(1).to_string().parse() {
                res.headers_mut()
                    .insert(salvo::http::header::RETRY_AFTER, value);
            }
            ApiErrorCode::RateLimited.render(res, "PSI quota exhausted");
            return;
        }
    }

    let epoch = body
        .epoch
        .clone()
        .unwrap_or_else(|| current_epoch(state.config()));

    let key = match load_or_create_epoch_key(&state, &epoch).await {
        Ok(key) => key,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("PSI epoch key: {error}"));
            return;
        }
    };

    match body.phase {
        PsiPhase::Blind => handle_blind_phase(body, key, res).await,
        PsiPhase::Match => handle_match_phase(&state, body, key, res).await,
    }
}

async fn handle_blind_phase(
    body: PsiContactDiscoveryRequestBody,
    key: PsiEpochKey,
    res: &mut Response,
) {
    if body.blinded_inputs.is_empty() {
        ApiErrorCode::MissingParam.render(res, "blinded_inputs is required for phase=blind");
        return;
    }
    // §6.2/§6.4: the Provider MUST enforce a fixed `batch_size` upper bound
    // rather than evaluating an attacker-controlled number of (expensive)
    // Ristretto255 group operations per request. Reject anything above the
    // fixed cardinality instead of silently processing it (which was both a
    // CPU/memory amplification DoS and, on the `match` side, a silent
    // truncation that produced wrong results).
    if body.blinded_inputs.len() > MATCH_CARDINALITY {
        ApiErrorCode::InvalidParam.render(
            res,
            format!("blinded_inputs exceeds fixed batch size {MATCH_CARDINALITY}"),
        );
        return;
    }

    let server = match PsiServer::deserialize(&key.server_key) {
        Ok(server) => server,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("PSI server key deserialize: {error}"));
            return;
        }
    };

    let mut evaluations = Vec::with_capacity(MATCH_CARDINALITY);
    let mut proofs = Vec::with_capacity(MATCH_CARDINALITY);
    let mut rng = OsRng;
    for input in &body.blinded_inputs {
        let blinded = match decode_blinded_element(input) {
            Ok(blinded) => blinded,
            Err(message) => {
                ApiErrorCode::InvalidParam.render(res, message);
                return;
            }
        };
        let evaluated = server.blind_evaluate(&mut rng, &blinded);
        evaluations.push(URL_SAFE_NO_PAD.encode(evaluated.message.serialize()));
        proofs.push(URL_SAFE_NO_PAD.encode(evaluated.proof.serialize()));
    }

    // §6.4: the response frame MUST be rewritten to the Provider's fixed
    // `batch_size`. Dummy-pad `evaluations`/`proofs` with real-shaped VOPRF
    // outputs (evaluated over a constant dummy blinded element) up to
    // MATCH_CARDINALITY so the on-wire response size is decoupled from the
    // number of elements the client actually submitted.
    let real_count = evaluations.len();
    if real_count < MATCH_CARDINALITY {
        let dummy_blinded = dummy_blinded_element();
        for _ in real_count..MATCH_CARDINALITY {
            let evaluated = server.blind_evaluate(&mut rng, &dummy_blinded);
            evaluations.push(URL_SAFE_NO_PAD.encode(evaluated.message.serialize()));
            proofs.push(URL_SAFE_NO_PAD.encode(evaluated.proof.serialize()));
        }
    }

    let query_id = random_query_id();
    let padding_count = MATCH_CARDINALITY.saturating_sub(real_count);
    res.render(Json(PsiBlindOutcome {
        phase: "blind",
        epoch: key.epoch.clone(),
        key_id: key.epoch,
        query_id,
        evaluations,
        proofs,
        padding_count,
        voprf_profile: VOPRF_PROFILE,
        server_public_key: URL_SAFE_NO_PAD.encode(key.public_key),
    }));
}

async fn handle_match_phase(
    state: &AppState,
    body: PsiContactDiscoveryRequestBody,
    key: PsiEpochKey,
    res: &mut Response,
) {
    if body.match_tokens.is_empty() {
        ApiErrorCode::MissingParam.render(res, "match_tokens is required for phase=match");
        return;
    }
    // §6.4: enforce the same fixed batch-size bound on the `match` round.
    // Reject overflow explicitly instead of decoding everything and silently
    // `take(MATCH_CARDINALITY)`-ing (which charged the decode cost for the
    // discarded surplus and returned a hit bitmap that silently dropped the
    // client's excess tokens).
    if body.match_tokens.len() > MATCH_CARDINALITY {
        ApiErrorCode::InvalidParam.render(
            res,
            format!("match_tokens exceeds fixed batch size {MATCH_CARDINALITY}"),
        );
        return;
    }

    let query_id = body.query_id.clone().unwrap_or_else(random_query_id);
    let decoded_tokens = match decode_match_tokens(&body.match_tokens) {
        Ok(tokens) => tokens,
        Err(message) => {
            ApiErrorCode::InvalidParam.render(res, message);
            return;
        }
    };
    let matching_tokens =
        match crate::psi_index::load_matching_tokens(state.db(), &key.epoch, &decoded_tokens).await
        {
            Ok(tokens) => tokens,
            Err(error) => {
                ApiErrorCode::InternalError.render(res, format!("PSI match index: {error}"));
                return;
            }
        };

    let mut hit_bitmap = decoded_tokens
        .iter()
        .take(MATCH_CARDINALITY)
        .map(|token| matching_tokens.contains(token))
        .collect::<Vec<_>>();
    let padding_count = MATCH_CARDINALITY.saturating_sub(hit_bitmap.len());
    hit_bitmap.resize(MATCH_CARDINALITY, false);
    res.render(Json(PsiMatchOutcome {
        phase: "match",
        epoch: key.epoch.clone(),
        key_id: key.epoch,
        query_id,
        hit_bitmap,
        padding_count,
        fixed_cardinality: MATCH_CARDINALITY,
        voprf_profile: VOPRF_PROFILE,
    }));
}

async fn load_or_create_epoch_key(
    state: &AppState,
    epoch_value: &str,
) -> anyhow::Result<PsiEpochKey> {
    use crate::schema::psi_epoch_keys::dsl as k;

    let mut conn = state.db().get().await?;
    let now = Utc::now();
    diesel::delete(k::psi_epoch_keys.filter(k::expires_at.lt(now)))
        .execute(&mut *conn)
        .await?;

    if let Some(mut row) = k::psi_epoch_keys
        .filter(k::epoch.eq(epoch_value))
        .select((
            k::epoch,
            k::profile,
            k::server_key,
            k::public_key,
            k::tokens_indexed_at,
        ))
        .first::<PsiEpochKey>(&mut *conn)
        .await
        .optional()?
    {
        ensure_epoch_profile(&row.profile)?;
        ensure_epoch_tokens_indexed(&mut conn, &mut row).await?;
        return Ok(row);
    }

    let mut rng = OsRng;
    let server = PsiServer::new(&mut rng).map_err(|error| anyhow::anyhow!("{error}"))?;
    let server_key = server.serialize().to_vec();
    let public_key = Ristretto255::serialize_elem(server.get_public_key()).to_vec();
    let retention = chrono::Duration::from_std(std::time::Duration::from_secs(
        state.config().psi_key_retention_seconds,
    ))?;
    let expires_at = now + retention;
    diesel::insert_into(k::psi_epoch_keys)
        .values(NewPsiEpochKey {
            epoch: epoch_value,
            profile: VOPRF_PROFILE,
            server_key: &server_key,
            public_key: &public_key,
            created_at: now,
            expires_at,
        })
        .on_conflict(k::epoch)
        .do_nothing()
        .execute(&mut *conn)
        .await?;

    let mut row = k::psi_epoch_keys
        .filter(k::epoch.eq(epoch_value))
        .select((
            k::epoch,
            k::profile,
            k::server_key,
            k::public_key,
            k::tokens_indexed_at,
        ))
        .first::<PsiEpochKey>(&mut *conn)
        .await?;
    ensure_epoch_profile(&row.profile)?;
    ensure_epoch_tokens_indexed(&mut conn, &mut row).await?;
    Ok(row)
}

fn ensure_epoch_profile(profile: &str) -> anyhow::Result<()> {
    if profile != VOPRF_PROFILE {
        anyhow::bail!(
            "PSI epoch profile `{profile}` is not supported by this binary; expected `{VOPRF_PROFILE}`"
        );
    }
    Ok(())
}

async fn ensure_epoch_tokens_indexed(
    conn: &mut diesel_async::AsyncPgConnection,
    key: &mut PsiEpochKey,
) -> anyhow::Result<()> {
    if key.tokens_indexed_at.is_some() {
        return Ok(());
    }
    let server = PsiServer::deserialize(&key.server_key)
        .map_err(|error| anyhow::anyhow!("PSI server key deserialize: {error}"))?;
    crate::psi_index::rebuild_epoch_tokens_on_conn(conn, &key.epoch, &server).await?;
    key.tokens_indexed_at = Some(Utc::now());
    Ok(())
}

fn current_epoch(config: &AppConfig) -> String {
    let epoch = Utc::now()
        .timestamp()
        .div_euclid(config.psi_epoch_seconds as i64);
    format!("psi-epoch-{epoch}")
}

fn psi_quota_key(requester: &Did, quota_bucket: i64) -> String {
    format!("psi-quota:requester:{}:{quota_bucket}", requester.as_str())
}

fn signer_did_from_key_id(key_id: &str) -> Result<Did, String> {
    let did = key_id
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(key_id)
        .trim();
    if did.is_empty() || did == key_id {
        return Err("HTTP signature keyid must be a DID URL for PSI".to_owned());
    }
    Did::new(did.to_owned()).map_err(|error| format!("HTTP signature keyid DID invalid: {error}"))
}

fn random_query_id() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>())
}

/// Constant dummy blinded element used to pad the `blind` round response to
/// the fixed `batch_size` (§6.4). Built from the group base element so it
/// deserializes into a valid `BlindedElement`; the resulting VOPRF outputs are
/// indistinguishable in shape from real evaluations and are discarded by the
/// client (which only consumes the first `MATCH_CARDINALITY - padding_count`).
fn dummy_blinded_element() -> PsiBlindedElement {
    let serialized = Ristretto255::serialize_elem(Ristretto255::base_elem());
    PsiBlindedElement::deserialize(serialized.as_slice())
        .expect("base element serialization is a valid blinded element")
}

fn decode_blinded_element(input: &str) -> Result<PsiBlindedElement, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|error| format!("invalid blinded input base64url: {error}"))?;
    PsiBlindedElement::deserialize(bytes.as_slice())
        .map_err(|error| format!("invalid RFC9497 blinded element: {error}"))
}

fn decode_match_tokens(tokens: &[String]) -> Result<Vec<Vec<u8>>, String> {
    tokens
        .iter()
        .map(|token| {
            URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|error| format!("invalid match token base64url: {error}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn contact_candidates_include_resource_and_projection_identifiers() {
        let inputs = crate::psi_index::contact_candidate_inputs(
            crate::ingest::DirectoryResourceKindDb::Handle,
            "Alice.Example",
            &json!({
                "did": "did:web:alice.example",
                "handle": "alice.example",
                "email_hash": "sha256:abc",
            }),
        );

        assert!(inputs.contains("alice.example"));
        assert!(inputs.contains("did:web:alice.example"));
        assert!(inputs.contains("sha256:abc"));
    }

    #[test]
    fn match_response_does_not_expose_index_size() {
        let value = serde_json::to_value(PsiMatchOutcome {
            phase: "match",
            epoch: "psi-epoch-1".to_owned(),
            key_id: "psi-epoch-1".to_owned(),
            query_id: "query".to_owned(),
            hit_bitmap: vec![false; MATCH_CARDINALITY],
            padding_count: 0,
            fixed_cardinality: MATCH_CARDINALITY,
            voprf_profile: VOPRF_PROFILE,
        })
        .expect("serialize match response");

        assert!(value.get("limited").is_none());
        assert!(value.get("indexed_candidate_count").is_none());
        assert!(value.get("indexed_candidate_limit").is_none());
    }

    #[test]
    fn psi_epoch_profile_mismatch_fails_closed() {
        assert!(ensure_epoch_profile(VOPRF_PROFILE).is_ok());
        assert!(ensure_epoch_profile("RFC9497-OPRFV1-P256-SHA256").is_err());
    }

    #[test]
    fn psi_query_id_is_opaque_random_token() {
        let first = random_query_id();
        let second = random_query_id();

        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 32);
        assert_ne!(first, second);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn psi_quota_key_is_authenticated_requester_primary() {
        let requester = Did::new("did:web:alice.example".to_owned()).unwrap();

        assert_eq!(
            psi_quota_key(&requester, 42),
            "psi-quota:requester:did:web:alice.example:42"
        );
    }

    #[test]
    fn psi_signer_keyid_must_be_did_url() {
        let signer = signer_did_from_key_id("did:web:alice.example#device-1").unwrap();
        assert_eq!(signer.as_str(), "did:web:alice.example");
        assert!(signer_did_from_key_id("operator-key-1").is_err());
    }
}
