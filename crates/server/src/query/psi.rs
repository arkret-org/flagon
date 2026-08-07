//! Private Contact Discovery via RFC 9497 VOPRF.
//!
//! Round 1 (`phase=blind`) evaluates client-supplied blinded Ristretto255
//! elements with the current epoch key. Round 2 (`phase=match`) compares
//! finalized VOPRF outputs against this Directory's public contact candidates
//! and returns a fixed-cardinality bitmap.

use arkret_sdk::{
    BatchId, DirectoryPrivateContactDiscoveryOutcome, DirectoryPrivateContactDiscoveryRequestBody,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use rand::rngs::OsRng;
use salvo::prelude::*;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use voprf::{BlindedElement, Group, Ristretto255, VoprfServer};

use crate::config::AppConfig;
use crate::error::ApiErrorCode;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::middleware::AuthenticatedHttpSignature;
use crate::schema::{psi_batches, psi_epoch_keys, psi_quota_windows};
use crate::state::AppState;

pub(crate) const PRIVATE_DISCOVERY_PROFILE: &str = "ak.private_contact_discovery.v1";
pub(crate) const VOPRF_CIPHERSUITE: &str = "OPRF-ristretto255-SHA512";
pub(crate) const PSI_BATCH_SIZE: usize = 256;

type PsiServer = VoprfServer<Ristretto255>;
type PsiBlindedElement = BlindedElement<Ristretto255>;

#[derive(Debug, Clone, Queryable)]
struct PsiEpochKey {
    epoch: String,
    ciphersuite: String,
    server_key: Vec<u8>,
    public_key: Vec<u8>,
    tokens_indexed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = psi_batches)]
struct NewPsiBatch<'a> {
    batch_id: &'a str,
    credential_key_id: &'a str,
    key_epoch: i64,
    blind_request_digest: &'a [u8],
    element_count: i32,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Queryable)]
struct PsiBatchState {
    credential_key_id: String,
    key_epoch: i64,
    blind_request_digest: Vec<u8>,
    element_count: i32,
    match_request_digest: Option<Vec<u8>>,
    match_outcome: Option<JsonValue>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = psi_quota_windows)]
struct NewPsiQuotaWindow<'a> {
    credential_key_id: &'a str,
    quota_bucket: i64,
    query_count: i32,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = psi_epoch_keys)]
struct NewPsiEpochKey<'a> {
    epoch: &'a str,
    ciphersuite: &'a str,
    server_key: &'a [u8],
    public_key: &'a [u8],
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
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

    let body: DirectoryPrivateContactDiscoveryRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::BadJson.render(res, format!("malformed PSI request: {error}"));
            return;
        }
    };
    if let Err(message) = validate_device_credential_key_id(&auth.key_id) {
        ApiErrorCode::Unauthenticated.render(res, message);
        return;
    }

    if body.profile() != PRIVATE_DISCOVERY_PROFILE {
        ApiErrorCode::InvalidParam.render(res, "unsupported private discovery profile");
        return;
    }

    match body {
        DirectoryPrivateContactDiscoveryRequestBody::Blind {
            batch_id,
            ciphersuite,
            key_epoch,
            blinded_elements,
            ..
        } => {
            if ciphersuite != VOPRF_CIPHERSUITE {
                ApiErrorCode::InvalidParam.render(res, "unsupported private discovery ciphersuite");
                return;
            }
            if key_epoch != current_epoch(state.config()) {
                ApiErrorCode::InvalidParam.render(res, "key_epoch is not the current OPRF epoch");
                return;
            }
            let key = match load_or_create_epoch_key(&state, key_epoch).await {
                Ok(key) => key,
                Err(error) => {
                    ApiErrorCode::InternalError.render(res, format!("PSI epoch key: {error}"));
                    return;
                }
            };
            let budget = LatencyBudget::new(
                state.config().query_latency_floor,
                state.config().query_latency_jitter,
            );
            let privacy_key = format!(
                "credential={};batch={};phase=blind",
                auth.key_id,
                batch_id.as_str()
            );
            pad_to_budget_observed(
                budget,
                "ak.find.directory.read.private_contact_discovery",
                &privacy_key,
                |target| {
                    state
                        .metrics()
                        .record_anti_enum_pad("private-contact-discovery", target)
                },
                handle_blind_phase(
                    &state,
                    &auth.key_id,
                    batch_id,
                    key_epoch,
                    blinded_elements,
                    key,
                    res,
                ),
            )
            .await;
        }
        DirectoryPrivateContactDiscoveryRequestBody::Match {
            batch_id,
            key_epoch,
            derived_prefixes,
            ..
        } => {
            let key = match load_epoch_key(&state, key_epoch).await {
                Ok(Some(key)) => key,
                Ok(None) => {
                    ApiErrorCode::InvalidParam.render(res, "key_epoch is unknown or expired");
                    return;
                }
                Err(error) => {
                    ApiErrorCode::InternalError.render(res, format!("PSI epoch key: {error}"));
                    return;
                }
            };
            let budget = LatencyBudget::new(
                state.config().query_latency_floor,
                state.config().query_latency_jitter,
            );
            let privacy_key = format!(
                "credential={};batch={};phase=match",
                auth.key_id,
                batch_id.as_str()
            );
            pad_to_budget_observed(
                budget,
                "ak.find.directory.read.private_contact_discovery",
                &privacy_key,
                |target| {
                    state
                        .metrics()
                        .record_anti_enum_pad("private-contact-discovery", target)
                },
                handle_match_phase(
                    &state,
                    &auth.key_id,
                    batch_id,
                    key_epoch,
                    derived_prefixes,
                    key,
                    res,
                ),
            )
            .await;
        }
    }
}

async fn handle_blind_phase(
    state: &AppState,
    credential_key_id: &str,
    batch_id: BatchId,
    key_epoch: u64,
    blinded_elements: Vec<String>,
    key: PsiEpochKey,
    res: &mut Response,
) {
    if blinded_elements.is_empty() {
        ApiErrorCode::MissingParam.render(res, "blinded_elements is required for phase=blind");
        return;
    }
    if blinded_elements.len() > PSI_BATCH_SIZE {
        ApiErrorCode::InvalidParam.render(
            res,
            format!("blinded_elements exceeds fixed batch size {PSI_BATCH_SIZE}"),
        );
        return;
    }
    let blinded = match blinded_elements
        .iter()
        .map(|input| decode_blinded_element(input))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(blinded) => blinded,
        Err(message) => {
            ApiErrorCode::InvalidParam.render(res, message);
            return;
        }
    };

    match open_psi_batch(
        state,
        credential_key_id,
        &batch_id,
        key_epoch,
        &blinded_elements,
    )
    .await
    {
        Ok(()) => {}
        Err(PsiBatchError::QuotaExhausted) => {
            ApiErrorCode::RateLimited.render(res, "PSI quota exhausted");
            return;
        }
        Err(error) => {
            ApiErrorCode::InvalidParam.render(res, error.to_string());
            return;
        }
    }

    let server = match PsiServer::deserialize(&key.server_key) {
        Ok(server) => server,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("PSI server key deserialize: {error}"));
            return;
        }
    };

    let mut evaluations = Vec::with_capacity(PSI_BATCH_SIZE);
    let mut proofs = Vec::with_capacity(PSI_BATCH_SIZE);
    let mut rng = OsRng;
    for blinded in &blinded {
        let evaluated = server.blind_evaluate(&mut rng, blinded);
        evaluations.push(URL_SAFE_NO_PAD.encode(evaluated.message.serialize()));
        proofs.push(URL_SAFE_NO_PAD.encode(evaluated.proof.serialize()));
    }

    // §6.4: the response frame MUST be rewritten to the Provider's fixed
    // `batch_item_count`. Dummy-pad `evaluations`/`proofs` with real-shaped VOPRF
    // outputs (evaluated over a constant dummy blinded element) up to
    // PSI_BATCH_SIZE so the on-wire response size is decoupled from the
    // number of elements the client actually submitted.
    let real_count = evaluations.len();
    if real_count < PSI_BATCH_SIZE {
        let dummy_blinded = dummy_blinded_element();
        for _ in real_count..PSI_BATCH_SIZE {
            let evaluated = server.blind_evaluate(&mut rng, &dummy_blinded);
            evaluations.push(URL_SAFE_NO_PAD.encode(evaluated.message.serialize()));
            proofs.push(URL_SAFE_NO_PAD.encode(evaluated.proof.serialize()));
        }
    }

    let padding_count = PSI_BATCH_SIZE.saturating_sub(real_count);
    res.render(Json(DirectoryPrivateContactDiscoveryOutcome::Blind {
        profile: PRIVATE_DISCOVERY_PROFILE.to_owned(),
        batch_id,
        ciphersuite: VOPRF_CIPHERSUITE.to_owned(),
        key_epoch,
        evaluated_elements: evaluations,
        proofs,
        digest_prefix_length: crate::psi_index::PSI_DIGEST_PREFIX_LENGTH as u16,
        padding_count: padding_count as u32,
        server_public_key: URL_SAFE_NO_PAD.encode(key.public_key),
    }));
}

async fn handle_match_phase(
    state: &AppState,
    credential_key_id: &str,
    batch_id: BatchId,
    key_epoch: u64,
    derived_prefixes: Vec<String>,
    key: PsiEpochKey,
    res: &mut Response,
) {
    if derived_prefixes.is_empty() {
        ApiErrorCode::MissingParam.render(res, "derived_prefixes is required for phase=match");
        return;
    }
    if derived_prefixes.len() > PSI_BATCH_SIZE {
        ApiErrorCode::InvalidParam.render(
            res,
            format!("derived_prefixes exceeds fixed batch size {PSI_BATCH_SIZE}"),
        );
        return;
    }

    let decoded_prefixes = match decode_derived_prefixes(&derived_prefixes) {
        Ok(prefixes) => prefixes,
        Err(message) => {
            ApiErrorCode::InvalidParam.render(res, message);
            return;
        }
    };

    match prepare_match_batch(
        state,
        credential_key_id,
        &batch_id,
        key_epoch,
        &derived_prefixes,
    )
    .await
    {
        Ok(Some(outcome)) => {
            res.render(Json(outcome));
            return;
        }
        Ok(None) => {}
        Err(error) => {
            ApiErrorCode::InvalidParam.render(res, error.to_string());
            return;
        }
    }

    let matching_prefixes =
        match crate::psi_index::load_matching_prefixes(state.db(), &key.epoch, &decoded_prefixes)
            .await
        {
            Ok(prefixes) => prefixes,
            Err(error) => {
                ApiErrorCode::InternalError.render(res, format!("PSI match index: {error}"));
                return;
            }
        };

    let mut hit_bitmap = decoded_prefixes
        .iter()
        .map(|prefix| matching_prefixes.contains(prefix))
        .collect::<Vec<_>>();
    let padding_count = PSI_BATCH_SIZE.saturating_sub(hit_bitmap.len());
    hit_bitmap.resize(PSI_BATCH_SIZE, false);
    let outcome = DirectoryPrivateContactDiscoveryOutcome::Match {
        profile: PRIVATE_DISCOVERY_PROFILE.to_owned(),
        batch_id: batch_id.clone(),
        key_epoch,
        hit_bitmap,
        padding_count: padding_count as u32,
    };
    if let Err(error) = store_match_outcome(state, &batch_id, &outcome).await {
        ApiErrorCode::InternalError.render(res, format!("PSI batch outcome: {error}"));
        return;
    }
    res.render(Json(outcome));
}

async fn load_or_create_epoch_key(state: &AppState, key_epoch: u64) -> anyhow::Result<PsiEpochKey> {
    use crate::schema::psi_epoch_keys::dsl as k;

    let mut conn = state.db().get().await?;
    let now = Utc::now();
    let epoch_value = key_epoch.to_string();
    diesel::delete(k::psi_epoch_keys.filter(k::expires_at.lt(now)))
        .execute(&mut *conn)
        .await?;

    if let Some(mut row) = k::psi_epoch_keys
        .filter(k::epoch.eq(&epoch_value))
        .select((
            k::epoch,
            k::ciphersuite,
            k::server_key,
            k::public_key,
            k::tokens_indexed_at,
        ))
        .first::<PsiEpochKey>(&mut *conn)
        .await
        .optional()?
    {
        ensure_epoch_ciphersuite(&row.ciphersuite)?;
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
            epoch: &epoch_value,
            ciphersuite: VOPRF_CIPHERSUITE,
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
        .filter(k::epoch.eq(&epoch_value))
        .select((
            k::epoch,
            k::ciphersuite,
            k::server_key,
            k::public_key,
            k::tokens_indexed_at,
        ))
        .first::<PsiEpochKey>(&mut *conn)
        .await?;
    ensure_epoch_ciphersuite(&row.ciphersuite)?;
    ensure_epoch_tokens_indexed(&mut conn, &mut row).await?;
    Ok(row)
}

async fn load_epoch_key(state: &AppState, key_epoch: u64) -> anyhow::Result<Option<PsiEpochKey>> {
    use crate::schema::psi_epoch_keys::dsl as k;

    let mut conn = state.db().get().await?;
    let mut row = k::psi_epoch_keys
        .filter(k::epoch.eq(key_epoch.to_string()))
        .filter(k::expires_at.gt(Utc::now()))
        .select((
            k::epoch,
            k::ciphersuite,
            k::server_key,
            k::public_key,
            k::tokens_indexed_at,
        ))
        .first::<PsiEpochKey>(&mut *conn)
        .await
        .optional()?;
    if let Some(row) = row.as_mut() {
        ensure_epoch_ciphersuite(&row.ciphersuite)?;
        ensure_epoch_tokens_indexed(&mut conn, row).await?;
    }
    Ok(row)
}

fn ensure_epoch_ciphersuite(ciphersuite: &str) -> anyhow::Result<()> {
    if ciphersuite != VOPRF_CIPHERSUITE {
        anyhow::bail!(
            "PSI epoch ciphersuite `{ciphersuite}` is not supported by this binary; expected `{VOPRF_CIPHERSUITE}`"
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

pub(crate) fn current_epoch(config: &AppConfig) -> u64 {
    Utc::now()
        .timestamp()
        .div_euclid(config.psi_epoch_seconds as i64)
        .max(0) as u64
}

fn validate_device_credential_key_id(key_id: &str) -> Result<(), String> {
    let (_, fragment) = key_id
        .rsplit_once('#')
        .ok_or_else(|| "HTTP signature keyid must be a device DID URL for PSI".to_owned())?;
    arkret_sdk::verification_method_did(key_id)
        .map_err(|error| format!("HTTP signature keyid DID invalid: {error}"))?;
    arkret_sdk::DeviceId::new(fragment.to_owned())
        .map_err(|error| format!("HTTP signature keyid is not a device credential: {error}"))?;
    Ok(())
}

#[derive(Debug)]
enum PsiBatchError {
    QuotaExhausted,
    Unknown,
    CredentialMismatch,
    EpochMismatch,
    RequestMismatch,
    Expired,
    Database(String),
    Corrupt(String),
}

impl std::fmt::Display for PsiBatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QuotaExhausted => formatter.write_str("PSI quota exhausted"),
            Self::Unknown => formatter.write_str("unknown PSI batch_id"),
            Self::CredentialMismatch => {
                formatter.write_str("batch_id belongs to a different device credential")
            }
            Self::EpochMismatch => formatter.write_str("batch_id key_epoch mismatch"),
            Self::RequestMismatch => {
                formatter.write_str("batch_id was already used with different request material")
            }
            Self::Expired => formatter.write_str("PSI batch_id expired"),
            Self::Database(message) => write!(formatter, "PSI batch database error: {message}"),
            Self::Corrupt(message) => write!(formatter, "PSI batch state is corrupt: {message}"),
        }
    }
}

impl std::error::Error for PsiBatchError {}

impl From<diesel::result::Error> for PsiBatchError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Database(error.to_string())
    }
}

fn request_list_digest(values: &[String]) -> Vec<u8> {
    let mut digest = Sha256::new();
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.finalize().to_vec()
}

async fn open_psi_batch(
    state: &AppState,
    credential_key_id: &str,
    batch_id: &BatchId,
    key_epoch: u64,
    blinded_elements: &[String],
) -> Result<(), PsiBatchError> {
    use crate::schema::psi_batches::dsl as b;
    use crate::schema::psi_quota_windows::dsl as q;

    let now = Utc::now();
    let window_seconds = state.config().psi_quota_window_seconds as i64;
    let quota_bucket = now.timestamp().div_euclid(window_seconds);
    let expires_at = now + chrono::Duration::seconds(window_seconds);
    let key_epoch = i64::try_from(key_epoch)
        .map_err(|_| PsiBatchError::Corrupt("key_epoch exceeds i64".to_owned()))?;
    let request_digest = request_list_digest(blinded_elements);
    let max_queries = i32::try_from(state.config().max_psi_queries_per_window).unwrap_or(i32::MAX);
    let mut pooled = state
        .db()
        .get()
        .await
        .map_err(|error| PsiBatchError::Database(error.to_string()))?;

    pooled
        .transaction::<_, PsiBatchError, _>(async move |conn| {
            diesel::delete(b::psi_batches.filter(b::expires_at.le(now)))
                .execute(&mut *conn)
                .await?;
            diesel::delete(q::psi_quota_windows.filter(q::expires_at.le(now)))
                .execute(&mut *conn)
                .await?;

            let inserted = diesel::insert_into(b::psi_batches)
                .values(NewPsiBatch {
                    batch_id: batch_id.as_str(),
                    credential_key_id,
                    key_epoch,
                    blind_request_digest: &request_digest,
                    element_count: blinded_elements.len() as i32,
                    created_at: now,
                    expires_at,
                })
                .on_conflict(b::batch_id)
                .do_nothing()
                .execute(&mut *conn)
                .await?;

            if inserted == 0 {
                let existing = b::psi_batches
                    .filter(b::batch_id.eq(batch_id.as_str()))
                    .select((
                        b::credential_key_id,
                        b::key_epoch,
                        b::blind_request_digest,
                        b::element_count,
                        b::match_request_digest,
                        b::match_outcome,
                        b::expires_at,
                    ))
                    .first::<PsiBatchState>(&mut *conn)
                    .await?;
                validate_batch(
                    &existing,
                    credential_key_id,
                    key_epoch,
                    Some(&request_digest),
                    now,
                )?;
                return Ok(());
            }

            diesel::insert_into(q::psi_quota_windows)
                .values(NewPsiQuotaWindow {
                    credential_key_id,
                    quota_bucket,
                    query_count: 0,
                    expires_at,
                })
                .on_conflict((q::credential_key_id, q::quota_bucket))
                .do_nothing()
                .execute(&mut *conn)
                .await?;
            let query_count = q::psi_quota_windows
                .filter(q::credential_key_id.eq(credential_key_id))
                .filter(q::quota_bucket.eq(quota_bucket))
                .select(q::query_count)
                .for_update()
                .first::<i32>(&mut *conn)
                .await?;
            if query_count >= max_queries {
                return Err(PsiBatchError::QuotaExhausted);
            }
            diesel::update(
                q::psi_quota_windows
                    .filter(q::credential_key_id.eq(credential_key_id))
                    .filter(q::quota_bucket.eq(quota_bucket)),
            )
            .set(q::query_count.eq(q::query_count + 1))
            .execute(&mut *conn)
            .await?;
            Ok(())
        })
        .await
}

fn validate_batch(
    batch: &PsiBatchState,
    credential_key_id: &str,
    key_epoch: i64,
    blind_request_digest: Option<&[u8]>,
    now: DateTime<Utc>,
) -> Result<(), PsiBatchError> {
    if batch.expires_at <= now {
        return Err(PsiBatchError::Expired);
    }
    if batch.credential_key_id != credential_key_id {
        return Err(PsiBatchError::CredentialMismatch);
    }
    if batch.key_epoch != key_epoch {
        return Err(PsiBatchError::EpochMismatch);
    }
    if blind_request_digest.is_some_and(|digest| batch.blind_request_digest != digest) {
        return Err(PsiBatchError::RequestMismatch);
    }
    Ok(())
}

async fn prepare_match_batch(
    state: &AppState,
    credential_key_id: &str,
    batch_id: &BatchId,
    key_epoch: u64,
    derived_prefixes: &[String],
) -> Result<Option<DirectoryPrivateContactDiscoveryOutcome>, PsiBatchError> {
    use crate::schema::psi_batches::dsl as b;

    let now = Utc::now();
    let key_epoch = i64::try_from(key_epoch)
        .map_err(|_| PsiBatchError::Corrupt("key_epoch exceeds i64".to_owned()))?;
    let request_digest = request_list_digest(derived_prefixes);
    let mut pooled = state
        .db()
        .get()
        .await
        .map_err(|error| PsiBatchError::Database(error.to_string()))?;
    pooled
        .transaction::<_, PsiBatchError, _>(async move |conn| {
            let batch = b::psi_batches
                .filter(b::batch_id.eq(batch_id.as_str()))
                .select((
                    b::credential_key_id,
                    b::key_epoch,
                    b::blind_request_digest,
                    b::element_count,
                    b::match_request_digest,
                    b::match_outcome,
                    b::expires_at,
                ))
                .for_update()
                .first::<PsiBatchState>(&mut *conn)
                .await
                .optional()?
                .ok_or(PsiBatchError::Unknown)?;
            validate_batch(&batch, credential_key_id, key_epoch, None, now)?;
            if batch.element_count as usize != derived_prefixes.len() {
                return Err(PsiBatchError::RequestMismatch);
            }
            if let Some(existing_digest) = batch.match_request_digest {
                if existing_digest != request_digest {
                    return Err(PsiBatchError::RequestMismatch);
                }
                return batch
                    .match_outcome
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|error| PsiBatchError::Corrupt(error.to_string()));
            }
            diesel::update(b::psi_batches.filter(b::batch_id.eq(batch_id.as_str())))
                .set(b::match_request_digest.eq(Some(request_digest)))
                .execute(&mut *conn)
                .await?;
            Ok(None)
        })
        .await
}

async fn store_match_outcome(
    state: &AppState,
    batch_id: &BatchId,
    outcome: &DirectoryPrivateContactDiscoveryOutcome,
) -> anyhow::Result<()> {
    use crate::schema::psi_batches::dsl as b;

    let value = serde_json::to_value(outcome)?;
    let mut conn = state.db().get().await?;
    let updated = diesel::update(b::psi_batches.filter(b::batch_id.eq(batch_id.as_str())))
        .set(b::match_outcome.eq(Some(value)))
        .execute(&mut *conn)
        .await?;
    if updated != 1 {
        anyhow::bail!("PSI batch expired before its match outcome could be stored");
    }
    Ok(())
}

/// Constant dummy blinded element used to pad the `blind` round response to
/// the fixed `batch_item_count` (§6.4). Built from the group base element so it
/// deserializes into a valid `BlindedElement`; the resulting VOPRF outputs are
/// indistinguishable in shape from real evaluations and are discarded by the
/// client (which only consumes the first `PSI_BATCH_SIZE - padding_count`).
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

fn decode_derived_prefixes(prefixes: &[String]) -> Result<Vec<Vec<u8>>, String> {
    prefixes
        .iter()
        .map(|prefix| {
            let decoded = URL_SAFE_NO_PAD
                .decode(prefix)
                .map_err(|error| format!("invalid derived prefix base64url: {error}"))?;
            if decoded.len() != crate::psi_index::PSI_DIGEST_PREFIX_LENGTH {
                return Err(format!(
                    "derived prefix must be exactly {} bytes",
                    crate::psi_index::PSI_DIGEST_PREFIX_LENGTH
                ));
            }
            Ok(decoded)
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
                "handle": "alice:example.com",
                "email_hash": "sha256:abc",
            }),
        );

        assert!(inputs.contains("alice:example.com"));
        assert!(inputs.contains("did:web:alice.example"));
        assert!(!inputs.contains("sha256:abc"));
    }

    #[test]
    fn match_response_does_not_expose_index_size() {
        let value = serde_json::to_value(DirectoryPrivateContactDiscoveryOutcome::Match {
            profile: PRIVATE_DISCOVERY_PROFILE.to_owned(),
            batch_id: BatchId::new("ak:batch:01964137-0000-7000-8000-000000000777").unwrap(),
            key_epoch: 14,
            hit_bitmap: vec![false; PSI_BATCH_SIZE],
            padding_count: 0,
        })
        .expect("serialize match response");

        assert!(value.get("limited").is_none());
        assert!(value.get("indexed_candidate_count").is_none());
        assert!(value.get("indexed_candidate_limit").is_none());
    }

    #[test]
    fn psi_epoch_ciphersuite_mismatch_fails_closed() {
        assert!(ensure_epoch_ciphersuite(VOPRF_CIPHERSUITE).is_ok());
        assert!(ensure_epoch_ciphersuite("RFC9497-OPRFV1-P256-SHA256").is_err());
    }

    #[test]
    fn derived_prefix_length_fails_closed() {
        assert!(decode_derived_prefixes(&[URL_SAFE_NO_PAD.encode([7_u8; 16])]).is_ok());
        assert!(decode_derived_prefixes(&[URL_SAFE_NO_PAD.encode([7_u8; 15])]).is_err());
    }

    #[test]
    fn psi_signer_keyid_must_be_a_typed_device_did_url() {
        validate_device_credential_key_id(
            "did:web:alice.example#ak:device:01964137-0000-7000-8000-000000000001",
        )
        .unwrap();
        assert!(validate_device_credential_key_id("operator-key-1").is_err());
        assert!(validate_device_credential_key_id("did:web:alice.example#device-1").is_err());
    }
}
