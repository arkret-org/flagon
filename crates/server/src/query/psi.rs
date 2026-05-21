//! Private Contact Discovery via RFC 9497 VOPRF.
//!
//! Round 1 (`phase=blind`) evaluates client-supplied blinded Ristretto255
//! elements with the current epoch key. Round 2 (`phase=match`) compares
//! finalized VOPRF outputs against this Directory's public contact candidates
//! and returns a fixed-cardinality bitmap.

use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use rand::rngs::OsRng;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha512};
use voprf::{BlindedElement, Group, Ristretto255, VoprfServer};

use crate::config::AppConfig;
use crate::error::ApiErrorCode;
use crate::ingest::{DiscoverabilityWire, ResourceKindWire};
use crate::schema::psi_epoch_keys;
use crate::state::{AppState, RateLimitOutcome};

const VOPRF_PROFILE: &str = "RFC9497-OPRFV1-ristretto255-SHA512";
const MATCH_CARDINALITY: usize = 256;
const MAX_PSI_INDEX_CANDIDATES: i64 = 10_000;

type PsiServer = VoprfServer<Ristretto255>;
type PsiBlindedElement = BlindedElement<Ristretto255>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PrivateContactDiscoveryReqBody {
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
pub struct BlindResponse {
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
pub struct MatchResponse {
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
    server_key: Vec<u8>,
    public_key: Vec<u8>,
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
    let state = match depot.obtain::<AppState>() {
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

    let body: PrivateContactDiscoveryReqBody = match req.parse_json().await {
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

    let epoch = body
        .epoch
        .clone()
        .unwrap_or_else(|| current_epoch(state.config()));
    if let RateLimitOutcome::Limited { retry_after } = state.check_rate_limit(
        format!("psi:{}:{epoch}", body.requester),
        state.config().max_psi_queries_per_epoch,
    ) {
        if let Ok(value) = retry_after.as_secs().max(1).to_string().parse() {
            res.headers_mut()
                .insert(salvo::http::header::RETRY_AFTER, value);
        }
        ApiErrorCode::RateLimited.render(res, "PSI epoch query budget exceeded");
        return;
    }

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
    body: PrivateContactDiscoveryReqBody,
    key: PsiEpochKey,
    res: &mut Response,
) {
    if body.blinded_inputs.is_empty() {
        ApiErrorCode::MissingParam.render(res, "blinded_inputs is required for phase=blind");
        return;
    }

    let server = match PsiServer::deserialize(&key.server_key) {
        Ok(server) => server,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("PSI server key deserialize: {error}"));
            return;
        }
    };

    let mut evaluations = Vec::with_capacity(body.blinded_inputs.len());
    let mut proofs = Vec::with_capacity(body.blinded_inputs.len());
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

    let query_id = query_id(&body.requester, &key.epoch, &body.blinded_inputs);
    let padding_count = MATCH_CARDINALITY.saturating_sub(evaluations.len());
    res.render(Json(BlindResponse {
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
    body: PrivateContactDiscoveryReqBody,
    key: PsiEpochKey,
    res: &mut Response,
) {
    if body.match_tokens.is_empty() {
        ApiErrorCode::MissingParam.render(res, "match_tokens is required for phase=match");
        return;
    }

    let server = match PsiServer::deserialize(&key.server_key) {
        Ok(server) => server,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("PSI server key deserialize: {error}"));
            return;
        }
    };
    let indexed_tokens = match load_indexed_match_tokens(state, &server).await {
        Ok(tokens) => tokens,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("PSI match index: {error}"));
            return;
        }
    };

    let query_id = body
        .query_id
        .clone()
        .unwrap_or_else(|| query_id(&body.requester, &key.epoch, &body.match_tokens));
    let decoded_tokens = match decode_match_tokens(&body.match_tokens) {
        Ok(tokens) => tokens,
        Err(message) => {
            ApiErrorCode::InvalidParam.render(res, message);
            return;
        }
    };

    let mut hit_bitmap = decoded_tokens
        .iter()
        .take(MATCH_CARDINALITY)
        .map(|token| indexed_tokens.contains(token))
        .collect::<Vec<_>>();
    let padding_count = MATCH_CARDINALITY.saturating_sub(hit_bitmap.len());
    hit_bitmap.resize(MATCH_CARDINALITY, false);
    res.render(Json(MatchResponse {
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

    let mut conn = state.db().get()?;
    let now = Utc::now();
    diesel::delete(k::psi_epoch_keys.filter(k::expires_at.lt(now))).execute(&mut conn)?;

    if let Some(row) = k::psi_epoch_keys
        .filter(k::epoch.eq(epoch_value))
        .select((k::epoch, k::server_key, k::public_key))
        .first::<PsiEpochKey>(&mut conn)
        .optional()?
    {
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
        .execute(&mut conn)?;

    let row = k::psi_epoch_keys
        .filter(k::epoch.eq(epoch_value))
        .select((k::epoch, k::server_key, k::public_key))
        .first::<PsiEpochKey>(&mut conn)?;
    Ok(row)
}

async fn load_indexed_match_tokens(
    state: &AppState,
    server: &PsiServer,
) -> anyhow::Result<HashSet<Vec<u8>>> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get()?;
    let rows: Vec<(ResourceKindWire, String, JsonValue)> = r::directory_resources
        .filter(
            r::resource_kind
                .eq(ResourceKindWire::Actor)
                .or(r::resource_kind.eq(ResourceKindWire::Handle)),
        )
        .filter(
            r::discoverability
                .eq(DiscoverabilityWire::Public)
                .or(r::discoverability.eq(DiscoverabilityWire::Listed)),
        )
        .limit(MAX_PSI_INDEX_CANDIDATES)
        .select((r::resource_kind, r::resource_id, r::public_projection))
        .load(&mut conn)?;

    let mut tokens = HashSet::new();
    for (kind, resource_id, projection) in rows {
        for input in contact_candidate_inputs(kind, &resource_id, &projection) {
            let output = server
                .evaluate(input.as_bytes())
                .map_err(|error| anyhow::anyhow!("VOPRF evaluate `{input}`: {error}"))?;
            tokens.insert(output.to_vec());
        }
    }
    Ok(tokens)
}

fn current_epoch(config: &AppConfig) -> String {
    let epoch = Utc::now()
        .timestamp()
        .div_euclid(config.psi_epoch_seconds as i64);
    format!("psi-epoch-{epoch}")
}

fn query_id(requester: &str, epoch: &str, inputs: &[String]) -> String {
    let mut h = Sha512::new();
    h.update(requester.as_bytes());
    h.update(epoch.as_bytes());
    for input in inputs {
        h.update(input.as_bytes());
    }
    URL_SAFE_NO_PAD.encode(&h.finalize()[..24])
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

fn contact_candidate_inputs(
    kind: ResourceKindWire,
    resource_id: &str,
    projection: &JsonValue,
) -> HashSet<String> {
    let mut out = HashSet::new();
    push_candidate(&mut out, resource_id);

    match kind {
        ResourceKindWire::Actor | ResourceKindWire::Handle => {
            for key in [
                "handle",
                "did",
                "actor_did",
                "email_hash",
                "phone_hash",
                "contact_hash",
            ] {
                if let Some(value) = projection.get(key).and_then(JsonValue::as_str) {
                    push_candidate(&mut out, value);
                }
            }
        }
        ResourceKindWire::Space | ResourceKindWire::Organization | ResourceKindWire::Applet => {}
    }
    out
}

fn push_candidate(out: &mut HashSet<String>, value: &str) {
    let normalized = value.trim().to_ascii_lowercase();
    if !normalized.is_empty() {
        out.insert(normalized);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn contact_candidates_include_resource_and_projection_identifiers() {
        let inputs = contact_candidate_inputs(
            ResourceKindWire::Handle,
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
}
