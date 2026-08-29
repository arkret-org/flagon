//! Durable private-contact-discovery state machine kept deliberately dark.
//!
//! This module has no router, configuration, `AppState`, ServiceDescribe, or
//! operation-bundle integration.  It exists solely to close the durable
//! admission semantics before a complete current-v1 VOPRF implementation is
//! ready to expose the canonical endpoint. Outcome storage is deliberately
//! opaque: this module checks only exact current-v1 bucket length, not typed
//! outcome semantics, JCS, or padding contents. It must not be wired to
//! production without the existing SDK validator and a durable snapshot of the
//! complete config (public key, buckets, handoff mode, and related policy).

use std::collections::HashMap;
use std::fmt;

use arkret_sdk::PrivateContactDiscovery;
use chrono::{DateTime, Duration, Utc};
use diesel::sql_types::{BigInt, Bytea, Integer, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName};
use diesel_async::{AsyncConnection, RunQueryDsl};

use crate::Db;

const RETRY_AFTER_QUANTUM_SECONDS: u64 = 300;
const CURRENT_V1_RESPONSE_BUCKETS_BYTES: [u32; 4] =
    PrivateContactDiscovery::RESPONSE_SIZE_BUCKETS_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcdLimits {
    pub batch_item_count: u16,
    pub max_queries_per_window: u64,
    pub quota_window_seconds: u32,
    pub batch_completion_ttl_seconds: u32,
    pub evaluation_lease_seconds: u32,
}

impl PcdLimits {
    pub fn validate(self) -> Result<Self, PcdError> {
        if self.batch_item_count == 0 || self.batch_item_count > 1024 {
            return Err(PcdReject::InvalidConfiguration.into());
        }
        if self.max_queries_per_window == 0
            || self.max_queries_per_window > i64::MAX as u64
            || self.quota_window_seconds == 0
            || self.batch_completion_ttl_seconds == 0
            || self.evaluation_lease_seconds == 0
            || self.evaluation_lease_seconds > self.batch_completion_ttl_seconds
        {
            return Err(PcdReject::InvalidConfiguration.into());
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PcdBatchId(String);

impl PcdBatchId {
    pub fn parse(value: impl Into<String>) -> Result<Self, PcdError> {
        let value = value.into();
        let Some(uuid) = value.strip_prefix("ak:batch:") else {
            return Err(PcdReject::InvalidBatchId.into());
        };
        let bytes = uuid.as_bytes();
        let hyphens = [8, 13, 18, 23];
        let lexical = bytes.len() == 36
            && bytes.iter().enumerate().all(|(index, byte)| {
                hyphens.contains(&index) == (*byte == b'-')
                    && (hyphens.contains(&index) || byte.is_ascii_hexdigit())
            })
            && bytes[14] == b'7'
            && matches!(bytes[19], b'8' | b'9' | b'a' | b'b');
        if !lexical || uuid.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(PcdReject::InvalidBatchId.into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeviceCredentialDigest([u8; 32]);

impl DeviceCredentialDigest {
    pub fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PcdRequestDigest([u8; 32]);

impl PcdRequestDigest {
    /// Wrap the SHA-256 digest of the JCS encoding of a closed, phase-specific
    /// current-v1 request body. This constructor can enforce only digest shape;
    /// the caller remains responsible for closed SDK validation and hashing the
    /// accepted canonical body. It is not authorization to connect this dark
    /// module to production.
    pub fn from_closed_body_sha256(value: [u8; 32]) -> Self {
        Self(value)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Opaque bytes whose length equals one advertised current-v1 response bucket.
///
/// This type intentionally does not claim typed outcome, phase, VOPRF, JCS, or
/// ASCII-SP padding validation. Any eventual product caller must separately use the
/// existing closed SDK validator and the batch-pinned full config snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueExactBucketBytes(Vec<u8>);

impl OpaqueExactBucketBytes {
    pub fn for_advertised_bucket(
        bytes: Vec<u8>,
        advertised_bucket_bytes: u32,
    ) -> Result<Self, PcdError> {
        if !CURRENT_V1_RESPONSE_BUCKETS_BYTES.contains(&advertised_bucket_bytes)
            || usize::try_from(advertised_bucket_bytes).ok() != Some(bytes.len())
        {
            return Err(PcdReject::InvalidOutcome.into());
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_persisted(bytes: Vec<u8>) -> Result<Self, PcdError> {
        if u32::try_from(bytes.len())
            .ok()
            .is_none_or(|length| !CURRENT_V1_RESPONSE_BUCKETS_BYTES.contains(&length))
        {
            return Err(PcdReject::InvalidOutcome.into());
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlindAdmissionRequest {
    pub device_credential_digest: DeviceCredentialDigest,
    pub batch_id: PcdBatchId,
    pub request_digest: PcdRequestDigest,
    pub key_epoch: u64,
    pub item_count: u16,
    pub lease_owner: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchAdmissionRequest {
    pub device_credential_digest: DeviceCredentialDigest,
    pub batch_id: PcdBatchId,
    pub request_digest: PcdRequestDigest,
    pub key_epoch: u64,
    pub item_count: u16,
    pub lease_owner: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PcdAdmission {
    Evaluate {
        pinned_key_epoch: u64,
        lease_version: u64,
        lease_expires_at: DateTime<Utc>,
    },
    PendingRetry {
        pinned_key_epoch: u64,
        lease_version: u64,
        retry_after_seconds: u64,
    },
    Cached {
        pinned_key_epoch: u64,
        outcome: OpaqueExactBucketBytes,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeWrite {
    Recorded,
    ExactRetry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PcdReject {
    InvalidConfiguration,
    InvalidBatchId,
    FixedBatchCardinality,
    QuotaExhausted { retry_after_seconds: u64 },
    DuplicateConflict,
    BatchUnavailable,
    PinnedEpochMismatch,
    BlindOutcomePending,
    OutcomeConflict,
    InvalidOutcome,
    EpochUnavailable,
    LeaseLost,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PcdError {
    Rejected(PcdReject),
    Storage(String),
}

impl From<PcdReject> for PcdError {
    fn from(value: PcdReject) -> Self {
        Self::Rejected(value)
    }
}

impl From<diesel::result::Error> for PcdError {
    fn from(value: diesel::result::Error) -> Self {
        Self::Storage(value.to_string())
    }
}

impl fmt::Display for PcdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(reject) => write!(formatter, "PCD state rejected: {reject:?}"),
            Self::Storage(message) => write!(formatter, "PCD storage failed: {message}"),
        }
    }
}

impl std::error::Error for PcdError {}

#[derive(Clone, Debug)]
struct QuotaWindow {
    expires_at: DateTime<Utc>,
    admitted_queries: u64,
}

#[derive(Clone, Debug)]
struct KeyEpochState {
    public_key: [u8; 32],
    custody_key_ref: String,
    activated_at: DateTime<Utc>,
    retired_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
struct BatchRecord {
    blind_request_digest: PcdRequestDigest,
    match_request_digest: Option<PcdRequestDigest>,
    pinned_key_epoch: u64,
    item_count: u16,
    expires_at: DateTime<Utc>,
    blind_outcome: Option<OpaqueExactBucketBytes>,
    match_outcome: Option<OpaqueExactBucketBytes>,
    blind_lease_owner: [u8; 32],
    blind_lease_version: u64,
    blind_lease_expires_at: DateTime<Utc>,
    match_lease_owner: Option<[u8; 32]>,
    match_lease_version: Option<u64>,
    match_lease_expires_at: Option<DateTime<Utc>>,
}

#[derive(Default)]
pub struct ModelPcdStore {
    epochs: HashMap<u64, KeyEpochState>,
    quotas: HashMap<DeviceCredentialDigest, QuotaWindow>,
    batches: HashMap<(DeviceCredentialDigest, PcdBatchId), BatchRecord>,
}

impl ModelPcdStore {
    pub fn register_key_epoch(
        &mut self,
        key_epoch: u64,
        public_key: [u8; 32],
        custody_key_ref: impl Into<String>,
        activated_at: DateTime<Utc>,
        retired_at: Option<DateTime<Utc>>,
    ) -> Result<(), PcdError> {
        let custody_key_ref = custody_key_ref.into();
        if custody_key_ref.is_empty() || custody_key_ref.len() > 512 {
            return Err(PcdReject::InvalidConfiguration.into());
        }
        if retired_at.is_some_and(|retired| retired < activated_at) {
            return Err(PcdReject::InvalidConfiguration.into());
        }
        let candidate = KeyEpochState {
            public_key,
            custody_key_ref,
            activated_at,
            retired_at,
        };
        if let Some(existing) = self.epochs.get(&key_epoch) {
            return if existing.public_key == candidate.public_key
                && existing.custody_key_ref == candidate.custody_key_ref
                && existing.activated_at == candidate.activated_at
                && existing.retired_at == candidate.retired_at
            {
                Ok(())
            } else {
                Err(PcdReject::DuplicateConflict.into())
            };
        }
        self.epochs.insert(key_epoch, candidate);
        Ok(())
    }

    pub fn admit_blind(
        &mut self,
        limits: PcdLimits,
        now: DateTime<Utc>,
        request: BlindAdmissionRequest,
    ) -> Result<PcdAdmission, PcdError> {
        let limits = validate_limits_for_epoch(limits, request.key_epoch)?;
        let key = (request.device_credential_digest, request.batch_id.clone());
        if let Some(batch) = self.batches.get_mut(&key) {
            return classify_blind_retry(limits, now, &request, batch);
        }
        validate_new_blind_cardinality(limits, request.item_count)?;
        let epoch = self
            .epochs
            .get(&request.key_epoch)
            .ok_or(PcdReject::EpochUnavailable)?;
        if now < epoch.activated_at || epoch.retired_at.is_some_and(|retired| now >= retired) {
            return Err(PcdReject::EpochUnavailable.into());
        }

        let quota = self
            .quotas
            .entry(request.device_credential_digest)
            .or_insert_with(|| QuotaWindow {
                expires_at: now + Duration::seconds(i64::from(limits.quota_window_seconds)),
                admitted_queries: 0,
            });
        if now >= quota.expires_at {
            quota.expires_at = now + Duration::seconds(i64::from(limits.quota_window_seconds));
            quota.admitted_queries = 0;
        }
        if quota.admitted_queries >= limits.max_queries_per_window {
            return Err(PcdReject::QuotaExhausted {
                retry_after_seconds: quota_retry_after_seconds(now, quota.expires_at),
            }
            .into());
        }

        quota.admitted_queries += 1;
        let batch_expires_at =
            now + Duration::seconds(i64::from(limits.batch_completion_ttl_seconds));
        let blind_lease_expires_at = lease_expiry(limits, now, batch_expires_at);
        self.batches.insert(
            key,
            BatchRecord {
                blind_request_digest: request.request_digest,
                match_request_digest: None,
                pinned_key_epoch: request.key_epoch,
                item_count: request.item_count,
                expires_at: batch_expires_at,
                blind_outcome: None,
                match_outcome: None,
                blind_lease_owner: request.lease_owner,
                blind_lease_version: 1,
                blind_lease_expires_at,
                match_lease_owner: None,
                match_lease_version: None,
                match_lease_expires_at: None,
            },
        );
        Ok(PcdAdmission::Evaluate {
            pinned_key_epoch: request.key_epoch,
            lease_version: 1,
            lease_expires_at: blind_lease_expires_at,
        })
    }

    pub fn record_blind_outcome(
        &mut self,
        now: DateTime<Utc>,
        request: &BlindAdmissionRequest,
        lease_version: u64,
        outcome: OpaqueExactBucketBytes,
    ) -> Result<OutcomeWrite, PcdError> {
        let batch = self
            .batches
            .get_mut(&(request.device_credential_digest, request.batch_id.clone()))
            .ok_or(PcdReject::BatchUnavailable)?;
        validate_live_blind(now, request, batch)?;
        if batch.blind_lease_owner != request.lease_owner
            || batch.blind_lease_version != lease_version
            || now >= batch.blind_lease_expires_at
        {
            return Err(PcdReject::LeaseLost.into());
        }
        record_outcome(&mut batch.blind_outcome, outcome)
    }

    pub fn admit_match(
        &mut self,
        limits: PcdLimits,
        now: DateTime<Utc>,
        request: MatchAdmissionRequest,
    ) -> Result<PcdAdmission, PcdError> {
        let limits = validate_limits_for_epoch(limits, request.key_epoch)?;
        let batch = self
            .batches
            .get_mut(&(request.device_credential_digest, request.batch_id.clone()))
            .ok_or(PcdReject::BatchUnavailable)?;
        validate_live_match(now, &request, batch)?;
        match batch.match_request_digest {
            Some(digest) if digest != request.request_digest => {
                Err(PcdReject::DuplicateConflict.into())
            }
            Some(_) => classify_match_retry(limits, now, &request, batch),
            None => {
                batch.match_request_digest = Some(request.request_digest);
                batch.match_lease_owner = Some(request.lease_owner);
                batch.match_lease_version = Some(1);
                batch.match_lease_expires_at = Some(lease_expiry(limits, now, batch.expires_at));
                Ok(PcdAdmission::Evaluate {
                    pinned_key_epoch: batch.pinned_key_epoch,
                    lease_version: 1,
                    lease_expires_at: batch.match_lease_expires_at.expect("set above"),
                })
            }
        }
    }

    pub fn record_match_outcome(
        &mut self,
        now: DateTime<Utc>,
        request: &MatchAdmissionRequest,
        lease_version: u64,
        outcome: OpaqueExactBucketBytes,
    ) -> Result<OutcomeWrite, PcdError> {
        let batch = self
            .batches
            .get_mut(&(request.device_credential_digest, request.batch_id.clone()))
            .ok_or(PcdReject::BatchUnavailable)?;
        if now >= batch.expires_at {
            return Err(PcdReject::BatchUnavailable.into());
        }
        if batch.pinned_key_epoch != request.key_epoch {
            return Err(PcdReject::PinnedEpochMismatch.into());
        }
        match batch.match_request_digest {
            Some(digest)
                if digest == request.request_digest
                    && batch.match_lease_owner == Some(request.lease_owner)
                    && batch.match_lease_version == Some(lease_version)
                    && batch
                        .match_lease_expires_at
                        .is_some_and(|expires| now < expires) =>
            {
                record_outcome(&mut batch.match_outcome, outcome)
            }
            Some(digest) if digest == request.request_digest => Err(PcdReject::LeaseLost.into()),
            Some(_) => Err(PcdReject::DuplicateConflict.into()),
            None => Err(PcdReject::BatchUnavailable.into()),
        }
    }
}

#[derive(Clone)]
pub struct PostgresPcdStore {
    db: Db,
}

impl PostgresPcdStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn register_key_epoch(
        &self,
        key_epoch: u64,
        public_key: [u8; 32],
        custody_key_ref: &str,
        activated_at: DateTime<Utc>,
    ) -> Result<(), PcdError> {
        if custody_key_ref.is_empty() || custody_key_ref.len() > 512 {
            return Err(PcdReject::InvalidConfiguration.into());
        }
        let key_epoch = i64::try_from(key_epoch).map_err(|_| PcdReject::EpochUnavailable)?;
        let mut conn = self.db.get().await.map_err(storage)?;
        let inserted = diesel::sql_query(
            "INSERT INTO pcd_key_epochs \
             (key_epoch, public_key, custody_key_ref, activated_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (key_epoch) DO NOTHING",
        )
        .bind::<BigInt, _>(key_epoch)
        .bind::<Bytea, _>(public_key)
        .bind::<Text, _>(custody_key_ref)
        .bind::<Timestamptz, _>(activated_at)
        .execute(&mut conn)
        .await
        .map_err(storage)?;
        if inserted == 1 {
            return Ok(());
        }
        let existing = diesel::sql_query(
            "SELECT public_key, custody_key_ref, activated_at FROM pcd_key_epochs \
             WHERE key_epoch = $1",
        )
        .bind::<BigInt, _>(key_epoch)
        .get_result::<EpochIdentityRow>(&mut conn)
        .await
        .map_err(storage)?;
        if existing.public_key == public_key
            && existing.custody_key_ref == custody_key_ref
            && existing.activated_at == activated_at
        {
            Ok(())
        } else {
            Err(PcdReject::DuplicateConflict.into())
        }
    }

    pub async fn admit_blind(
        &self,
        limits: PcdLimits,
        now: DateTime<Utc>,
        request: BlindAdmissionRequest,
    ) -> Result<PcdAdmission, PcdError> {
        let limits = validate_limits_for_epoch(limits, request.key_epoch)?;
        let mut conn = self.db.get().await.map_err(storage)?;
        conn.transaction::<_, PcdError, _>(async move |conn| {
            lock_device(conn, request.device_credential_digest).await?;
            if let Some(batch) = load_batch(conn, &request.device_credential_digest, &request.batch_id).await? {
                let old_version = u64::try_from(batch.blind_lease_version).map_err(storage)?;
                let mut record = batch.into_record()?;
                let admission = classify_blind_retry(limits, now, &request, &mut record)?;
                if matches!(admission, PcdAdmission::Evaluate { .. }) {
                    let updated = diesel::sql_query(
                        "UPDATE pcd_batches SET blind_lease_owner = $3, \
                           blind_lease_version = $4, blind_lease_expires_at = $5 \
                         WHERE device_credential_digest = $1 AND batch_id = $2 \
                           AND blind_outcome IS NULL AND blind_lease_version = $6",
                    )
                    .bind::<Bytea, _>(request.device_credential_digest.as_bytes())
                    .bind::<Text, _>(request.batch_id.as_str())
                    .bind::<Bytea, _>(request.lease_owner)
                    .bind::<BigInt, _>(i64::try_from(record.blind_lease_version).map_err(storage)?)
                    .bind::<Timestamptz, _>(record.blind_lease_expires_at)
                    .bind::<BigInt, _>(i64::try_from(old_version).map_err(storage)?)
                    .execute(conn)
                    .await
                    .map_err(storage)?;
                    if updated != 1 {
                        return Err(PcdReject::LeaseLost.into());
                    }
                }
                return Ok(admission);
            }
            validate_new_blind_cardinality(limits, request.item_count)?;
            // The share lock is held through quota admission and batch insert,
            // so a future retirement writer cannot invalidate the pinned epoch
            // between validation and the FK-backed insert. Such a writer MUST
            // lock this same row FOR UPDATE in its retirement transaction.
            let epoch = diesel::sql_query(
                "SELECT key_epoch FROM pcd_key_epochs \
                 WHERE key_epoch = $1 AND activated_at <= $2 \
                   AND (retired_at IS NULL OR retired_at > $2) FOR SHARE",
            )
            .bind::<BigInt, _>(i64::try_from(request.key_epoch).map_err(storage)?)
            .bind::<Timestamptz, _>(now)
            .get_result::<EpochLockRow>(conn)
            .await
            .optional()
            .map_err(storage)?;
            if epoch.is_none() {
                return Err(PcdReject::EpochUnavailable.into());
            }

            let quota = load_quota(conn, &request.device_credential_digest).await?;
            let window_seconds = i64::from(limits.quota_window_seconds);
            let (started_at, expires_at, admitted_queries) = match quota {
                Some(row) if now < row.window_expires_at => {
                    (
                        row.window_started_at,
                        row.window_expires_at,
                        u64::try_from(row.admitted_queries).map_err(storage)?,
                    )
                }
                _ => (now, now + Duration::seconds(window_seconds), 0),
            };
            if admitted_queries >= limits.max_queries_per_window {
                return Err(PcdReject::QuotaExhausted {
                    retry_after_seconds: quota_retry_after_seconds(now, expires_at),
                }
                .into());
            }

            diesel::sql_query(
                "INSERT INTO pcd_quota_windows \
                 (device_credential_digest, window_started_at, window_expires_at, admitted_queries) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (device_credential_digest) DO UPDATE SET \
                   window_started_at = EXCLUDED.window_started_at, \
                   window_expires_at = EXCLUDED.window_expires_at, \
                   admitted_queries = EXCLUDED.admitted_queries",
            )
            .bind::<Bytea, _>(request.device_credential_digest.as_bytes())
            .bind::<Timestamptz, _>(started_at)
            .bind::<Timestamptz, _>(expires_at)
            .bind::<BigInt, _>(i64::try_from(admitted_queries + 1).map_err(storage)?)
            .execute(conn)
            .await
            .map_err(storage)?;

            let key_epoch = i64::try_from(request.key_epoch).map_err(|_| PcdReject::PinnedEpochMismatch)?;
            let batch_expires_at =
                now + Duration::seconds(i64::from(limits.batch_completion_ttl_seconds));
            let blind_lease_expires_at = lease_expiry(limits, now, batch_expires_at);
            diesel::sql_query(
                "INSERT INTO pcd_batches \
                 (device_credential_digest, batch_id, blind_request_digest, pinned_key_epoch, \
                  item_count, admitted_at, expires_at, blind_lease_owner, \
                  blind_lease_version, blind_lease_expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9)",
            )
            .bind::<Bytea, _>(request.device_credential_digest.as_bytes())
            .bind::<Text, _>(request.batch_id.as_str())
            .bind::<Bytea, _>(request.request_digest.as_bytes())
            .bind::<BigInt, _>(key_epoch)
            .bind::<Integer, _>(i32::from(request.item_count))
            .bind::<Timestamptz, _>(now)
            .bind::<Timestamptz, _>(batch_expires_at)
            .bind::<Bytea, _>(request.lease_owner)
            .bind::<Timestamptz, _>(blind_lease_expires_at)
            .execute(conn)
            .await
            .map_err(storage)?;

            Ok(PcdAdmission::Evaluate {
                pinned_key_epoch: request.key_epoch,
                lease_version: 1,
                lease_expires_at: blind_lease_expires_at,
            })
        })
        .await
    }

    pub async fn record_blind_outcome(
        &self,
        now: DateTime<Utc>,
        request: &BlindAdmissionRequest,
        lease_version: u64,
        outcome: OpaqueExactBucketBytes,
    ) -> Result<OutcomeWrite, PcdError> {
        self.record_phase_outcome(
            now,
            request.device_credential_digest,
            &request.batch_id,
            request.request_digest,
            request.key_epoch,
            request.lease_owner,
            lease_version,
            outcome,
            Phase::Blind,
        )
        .await
    }

    pub async fn admit_match(
        &self,
        limits: PcdLimits,
        now: DateTime<Utc>,
        request: MatchAdmissionRequest,
    ) -> Result<PcdAdmission, PcdError> {
        let limits = validate_limits_for_epoch(limits, request.key_epoch)?;
        let mut conn = self.db.get().await.map_err(storage)?;
        conn.transaction::<_, PcdError, _>(async move |conn| {
            lock_device(conn, request.device_credential_digest).await?;
            let row = load_batch(conn, &request.device_credential_digest, &request.batch_id)
                .await?
                .ok_or(PcdReject::BatchUnavailable)?;
            let batch = row.clone().into_record()?;
            validate_live_match(now, &request, &batch)?;
            match batch.match_request_digest {
                Some(digest) if digest != request.request_digest => {
                    Err(PcdReject::DuplicateConflict.into())
                }
                Some(_) => {
                    let old_version = batch
                        .match_lease_version
                        .ok_or(PcdReject::BatchUnavailable)?;
                    let mut mutable = batch;
                    let admission = classify_match_retry(limits, now, &request, &mut mutable)?;
                    if matches!(admission, PcdAdmission::Evaluate { .. }) {
                        let updated = diesel::sql_query(
                            "UPDATE pcd_batches SET match_lease_owner = $3, \
                               match_lease_version = $4, match_lease_expires_at = $5 \
                             WHERE device_credential_digest = $1 AND batch_id = $2 \
                               AND match_outcome IS NULL AND match_lease_version = $6",
                        )
                        .bind::<Bytea, _>(request.device_credential_digest.as_bytes())
                        .bind::<Text, _>(request.batch_id.as_str())
                        .bind::<Bytea, _>(request.lease_owner)
                        .bind::<BigInt, _>(
                            i64::try_from(mutable.match_lease_version.expect("set by classifier"))
                                .map_err(storage)?,
                        )
                        .bind::<Timestamptz, _>(
                            mutable.match_lease_expires_at.expect("set by classifier"),
                        )
                        .bind::<BigInt, _>(i64::try_from(old_version).map_err(storage)?)
                        .execute(conn)
                        .await
                        .map_err(storage)?;
                        if updated != 1 {
                            return Err(PcdReject::LeaseLost.into());
                        }
                    }
                    Ok(admission)
                }
                None => {
                    let match_lease_expires_at = lease_expiry(limits, now, batch.expires_at);
                    let updated = diesel::sql_query(
                        "UPDATE pcd_batches SET match_request_digest = $3, \
                           match_lease_owner = $4, match_lease_version = 1, \
                           match_lease_expires_at = $5 \
                         WHERE device_credential_digest = $1 AND batch_id = $2 \
                           AND match_request_digest IS NULL",
                    )
                    .bind::<Bytea, _>(request.device_credential_digest.as_bytes())
                    .bind::<Text, _>(request.batch_id.as_str())
                    .bind::<Bytea, _>(request.request_digest.as_bytes())
                    .bind::<Bytea, _>(request.lease_owner)
                    .bind::<Timestamptz, _>(match_lease_expires_at)
                    .execute(conn)
                    .await
                    .map_err(storage)?;
                    if updated != 1 {
                        return Err(PcdReject::LeaseLost.into());
                    }
                    Ok(PcdAdmission::Evaluate {
                        pinned_key_epoch: batch.pinned_key_epoch,
                        lease_version: 1,
                        lease_expires_at: match_lease_expires_at,
                    })
                }
            }
        })
        .await
    }

    pub async fn record_match_outcome(
        &self,
        now: DateTime<Utc>,
        request: &MatchAdmissionRequest,
        lease_version: u64,
        outcome: OpaqueExactBucketBytes,
    ) -> Result<OutcomeWrite, PcdError> {
        self.record_phase_outcome(
            now,
            request.device_credential_digest,
            &request.batch_id,
            request.request_digest,
            request.key_epoch,
            request.lease_owner,
            lease_version,
            outcome,
            Phase::Match,
        )
        .await
    }

    async fn record_phase_outcome(
        &self,
        now: DateTime<Utc>,
        device: DeviceCredentialDigest,
        batch_id: &PcdBatchId,
        request_digest: PcdRequestDigest,
        key_epoch: u64,
        lease_owner: [u8; 32],
        lease_version: u64,
        outcome: OpaqueExactBucketBytes,
        phase: Phase,
    ) -> Result<OutcomeWrite, PcdError> {
        let mut conn = self.db.get().await.map_err(storage)?;
        let batch_id = batch_id.clone();
        conn.transaction::<_, PcdError, _>(async move |conn| {
            lock_device(conn, device).await?;
            let row = load_batch(conn, &device, &batch_id)
                .await?
                .ok_or(PcdReject::BatchUnavailable)?;
            let batch = row.into_record()?;
            if now >= batch.expires_at {
                return Err(PcdReject::BatchUnavailable.into());
            }
            if batch.pinned_key_epoch != key_epoch {
                return Err(PcdReject::PinnedEpochMismatch.into());
            }
            let (
                stored_digest,
                stored_outcome,
                stored_owner,
                stored_version,
                lease_expires_at,
                digest_column,
                outcome_column,
                owner_column,
                version_column,
            ) = match phase {
                Phase::Blind => (
                    Some(batch.blind_request_digest),
                    batch.blind_outcome,
                    Some(batch.blind_lease_owner),
                    Some(batch.blind_lease_version),
                    Some(batch.blind_lease_expires_at),
                    "blind_request_digest",
                    "blind_outcome",
                    "blind_lease_owner",
                    "blind_lease_version",
                ),
                Phase::Match => (
                    batch.match_request_digest,
                    batch.match_outcome,
                    batch.match_lease_owner,
                    batch.match_lease_version,
                    batch.match_lease_expires_at,
                    "match_request_digest",
                    "match_outcome",
                    "match_lease_owner",
                    "match_lease_version",
                ),
            };
            match stored_digest {
                Some(digest) if digest == request_digest => {}
                Some(_) => return Err(PcdReject::DuplicateConflict.into()),
                None => return Err(PcdReject::BatchUnavailable.into()),
            }
            if stored_owner != Some(lease_owner) || stored_version != Some(lease_version) {
                return Err(PcdReject::LeaseLost.into());
            }
            if lease_expires_at.is_none_or(|expires| now >= expires) {
                return Err(PcdReject::LeaseLost.into());
            }
            if let Some(existing) = stored_outcome {
                return if existing == outcome {
                    Ok(OutcomeWrite::ExactRetry)
                } else {
                    Err(PcdReject::OutcomeConflict.into())
                };
            }
            let statement = format!(
                "UPDATE pcd_batches SET {outcome_column} = $6 \
                 WHERE device_credential_digest = $1 AND batch_id = $2 \
                   AND {digest_column} = $3 AND {owner_column} = $4 \
                   AND {version_column} = $5 AND {outcome_column} IS NULL"
            );
            let updated = diesel::sql_query(statement)
                .bind::<Bytea, _>(device.as_bytes())
                .bind::<Text, _>(batch_id.as_str())
                .bind::<Bytea, _>(request_digest.as_bytes())
                .bind::<Bytea, _>(lease_owner)
                .bind::<BigInt, _>(i64::try_from(lease_version).map_err(storage)?)
                .bind::<Bytea, _>(outcome.as_bytes())
                .execute(conn)
                .await
                .map_err(storage)?;
            if updated != 1 {
                return Err(PcdReject::OutcomeConflict.into());
            }
            Ok(OutcomeWrite::Recorded)
        })
        .await
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Blind,
    Match,
}

fn validate_limits_for_epoch(limits: PcdLimits, key_epoch: u64) -> Result<PcdLimits, PcdError> {
    let limits = limits.validate()?;
    i64::try_from(key_epoch).map_err(|_| PcdReject::PinnedEpochMismatch)?;
    Ok(limits)
}

fn validate_new_blind_cardinality(limits: PcdLimits, item_count: u16) -> Result<(), PcdError> {
    if item_count != limits.batch_item_count {
        return Err(PcdReject::FixedBatchCardinality.into());
    }
    Ok(())
}

fn validate_live_blind(
    now: DateTime<Utc>,
    request: &BlindAdmissionRequest,
    batch: &BatchRecord,
) -> Result<(), PcdError> {
    if now >= batch.expires_at {
        return Err(PcdReject::BatchUnavailable.into());
    }
    if batch.blind_request_digest != request.request_digest {
        return Err(PcdReject::DuplicateConflict.into());
    }
    if batch.pinned_key_epoch != request.key_epoch {
        return Err(PcdReject::PinnedEpochMismatch.into());
    }
    if batch.item_count != request.item_count {
        return Err(PcdReject::FixedBatchCardinality.into());
    }
    Ok(())
}

fn validate_live_match(
    now: DateTime<Utc>,
    request: &MatchAdmissionRequest,
    batch: &BatchRecord,
) -> Result<(), PcdError> {
    if now >= batch.expires_at {
        return Err(PcdReject::BatchUnavailable.into());
    }
    if batch.pinned_key_epoch != request.key_epoch {
        return Err(PcdReject::PinnedEpochMismatch.into());
    }
    if batch.item_count != request.item_count {
        return Err(PcdReject::FixedBatchCardinality.into());
    }
    if batch.blind_outcome.is_none() {
        return Err(PcdReject::BlindOutcomePending.into());
    }
    Ok(())
}

fn classify_blind_retry(
    limits: PcdLimits,
    now: DateTime<Utc>,
    request: &BlindAdmissionRequest,
    batch: &mut BatchRecord,
) -> Result<PcdAdmission, PcdError> {
    validate_live_blind(now, request, batch)?;
    if let Some(outcome) = &batch.blind_outcome {
        return Ok(PcdAdmission::Cached {
            pinned_key_epoch: batch.pinned_key_epoch,
            outcome: outcome.clone(),
        });
    }
    if now < batch.blind_lease_expires_at {
        return Ok(PcdAdmission::PendingRetry {
            pinned_key_epoch: batch.pinned_key_epoch,
            lease_version: batch.blind_lease_version,
            retry_after_seconds: lease_retry_after_seconds(now, batch.blind_lease_expires_at),
        });
    }
    batch.blind_lease_owner = request.lease_owner;
    batch.blind_lease_version = batch.blind_lease_version.saturating_add(1);
    batch.blind_lease_expires_at = lease_expiry(limits, now, batch.expires_at);
    Ok(PcdAdmission::Evaluate {
        pinned_key_epoch: batch.pinned_key_epoch,
        lease_version: batch.blind_lease_version,
        lease_expires_at: batch.blind_lease_expires_at,
    })
}

fn classify_match_retry(
    limits: PcdLimits,
    now: DateTime<Utc>,
    request: &MatchAdmissionRequest,
    batch: &mut BatchRecord,
) -> Result<PcdAdmission, PcdError> {
    if let Some(outcome) = &batch.match_outcome {
        return Ok(PcdAdmission::Cached {
            pinned_key_epoch: batch.pinned_key_epoch,
            outcome: outcome.clone(),
        });
    }
    let lease_version = batch
        .match_lease_version
        .ok_or(PcdReject::BatchUnavailable)?;
    let lease_expires_at = batch
        .match_lease_expires_at
        .ok_or(PcdReject::BatchUnavailable)?;
    if now < lease_expires_at {
        return Ok(PcdAdmission::PendingRetry {
            pinned_key_epoch: batch.pinned_key_epoch,
            lease_version,
            retry_after_seconds: lease_retry_after_seconds(now, lease_expires_at),
        });
    }
    let new_version = lease_version.saturating_add(1);
    let new_expiry = lease_expiry(limits, now, batch.expires_at);
    batch.match_lease_owner = Some(request.lease_owner);
    batch.match_lease_version = Some(new_version);
    batch.match_lease_expires_at = Some(new_expiry);
    Ok(PcdAdmission::Evaluate {
        pinned_key_epoch: batch.pinned_key_epoch,
        lease_version: new_version,
        lease_expires_at: new_expiry,
    })
}

fn record_outcome(
    slot: &mut Option<OpaqueExactBucketBytes>,
    outcome: OpaqueExactBucketBytes,
) -> Result<OutcomeWrite, PcdError> {
    match slot {
        Some(existing) if *existing == outcome => Ok(OutcomeWrite::ExactRetry),
        Some(_) => Err(PcdReject::OutcomeConflict.into()),
        None => {
            *slot = Some(outcome);
            Ok(OutcomeWrite::Recorded)
        }
    }
}

fn lease_expiry(
    limits: PcdLimits,
    now: DateTime<Utc>,
    batch_expires_at: DateTime<Utc>,
) -> DateTime<Utc> {
    (now + Duration::seconds(i64::from(limits.evaluation_lease_seconds))).min(batch_expires_at)
}

fn remaining_seconds_ceil(now: DateTime<Utc>, expires_at: DateTime<Utc>) -> u64 {
    let remaining_millis = (expires_at - now).num_milliseconds().max(1);
    u64::try_from((remaining_millis + 999) / 1_000).unwrap_or(1)
}

fn lease_retry_after_seconds(now: DateTime<Utc>, expires_at: DateTime<Utc>) -> u64 {
    remaining_seconds_ceil(now, expires_at)
}

fn quota_retry_after_seconds(now: DateTime<Utc>, expires_at: DateTime<Utc>) -> u64 {
    let remaining_seconds = remaining_seconds_ceil(now, expires_at);
    remaining_seconds
        .div_ceil(RETRY_AFTER_QUANTUM_SECONDS)
        .saturating_mul(RETRY_AFTER_QUANTUM_SECONDS)
}

fn storage(error: impl fmt::Display) -> PcdError {
    PcdError::Storage(error.to_string())
}

async fn lock_device(
    conn: &mut diesel_async::AsyncPgConnection,
    device: DeviceCredentialDigest,
) -> Result<(), PcdError> {
    diesel::sql_query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
        .bind::<Bytea, _>(device.as_bytes())
        .execute(conn)
        .await
        .map_err(storage)?;
    Ok(())
}

#[derive(QueryableByName)]
struct QuotaRow {
    #[diesel(sql_type = Timestamptz)]
    window_started_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    window_expires_at: DateTime<Utc>,
    #[diesel(sql_type = BigInt)]
    admitted_queries: i64,
}

#[derive(QueryableByName)]
struct EpochIdentityRow {
    #[diesel(sql_type = Bytea)]
    public_key: Vec<u8>,
    #[diesel(sql_type = Text)]
    custody_key_ref: String,
    #[diesel(sql_type = Timestamptz)]
    activated_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct EpochLockRow {
    #[diesel(sql_type = BigInt)]
    #[allow(dead_code, reason = "row existence plus FOR SHARE is the contract")]
    key_epoch: i64,
}

async fn load_quota(
    conn: &mut diesel_async::AsyncPgConnection,
    device: &DeviceCredentialDigest,
) -> Result<Option<QuotaRow>, PcdError> {
    diesel::sql_query(
        "SELECT window_started_at, window_expires_at, admitted_queries FROM pcd_quota_windows \
         WHERE device_credential_digest = $1 FOR UPDATE",
    )
    .bind::<Bytea, _>(device.as_bytes())
    .get_result(conn)
    .await
    .optional()
    .map_err(storage)
}

#[derive(Clone, QueryableByName)]
struct BatchRow {
    #[diesel(sql_type = Bytea)]
    blind_request_digest: Vec<u8>,
    #[diesel(sql_type = Nullable<Bytea>)]
    match_request_digest: Option<Vec<u8>>,
    #[diesel(sql_type = BigInt)]
    pinned_key_epoch: i64,
    #[diesel(sql_type = Integer)]
    item_count: i32,
    #[diesel(sql_type = Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Bytea>)]
    blind_outcome: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Bytea>)]
    match_outcome: Option<Vec<u8>>,
    #[diesel(sql_type = Bytea)]
    blind_lease_owner: Vec<u8>,
    #[diesel(sql_type = BigInt)]
    blind_lease_version: i64,
    #[diesel(sql_type = Timestamptz)]
    blind_lease_expires_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Bytea>)]
    match_lease_owner: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<BigInt>)]
    match_lease_version: Option<i64>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    match_lease_expires_at: Option<DateTime<Utc>>,
}

impl BatchRow {
    fn into_record(self) -> Result<BatchRecord, PcdError> {
        Ok(BatchRecord {
            blind_request_digest: PcdRequestDigest(bytes32(self.blind_request_digest)?),
            match_request_digest: self
                .match_request_digest
                .map(bytes32)
                .transpose()?
                .map(PcdRequestDigest),
            pinned_key_epoch: u64::try_from(self.pinned_key_epoch).map_err(storage)?,
            item_count: u16::try_from(self.item_count).map_err(storage)?,
            expires_at: self.expires_at,
            blind_outcome: self
                .blind_outcome
                .map(OpaqueExactBucketBytes::from_persisted)
                .transpose()?,
            match_outcome: self
                .match_outcome
                .map(OpaqueExactBucketBytes::from_persisted)
                .transpose()?,
            blind_lease_owner: bytes32(self.blind_lease_owner)?,
            blind_lease_version: u64::try_from(self.blind_lease_version).map_err(storage)?,
            blind_lease_expires_at: self.blind_lease_expires_at,
            match_lease_owner: self.match_lease_owner.map(bytes32).transpose()?,
            match_lease_version: self
                .match_lease_version
                .map(u64::try_from)
                .transpose()
                .map_err(storage)?,
            match_lease_expires_at: self.match_lease_expires_at,
        })
    }
}

fn bytes32(value: Vec<u8>) -> Result<[u8; 32], PcdError> {
    value
        .try_into()
        .map_err(|value: Vec<u8>| storage(format!("expected 32-byte digest, got {}", value.len())))
}

async fn load_batch(
    conn: &mut diesel_async::AsyncPgConnection,
    device: &DeviceCredentialDigest,
    batch_id: &PcdBatchId,
) -> Result<Option<BatchRow>, PcdError> {
    diesel::sql_query(
        "SELECT blind_request_digest, match_request_digest, pinned_key_epoch, item_count, \
                expires_at, blind_outcome, match_outcome, blind_lease_owner, \
                blind_lease_version, blind_lease_expires_at, match_lease_owner, \
                match_lease_version, match_lease_expires_at \
         FROM pcd_batches WHERE device_credential_digest = $1 AND batch_id = $2 FOR UPDATE",
    )
    .bind::<Bytea, _>(device.as_bytes())
    .bind::<Text, _>(batch_id.as_str())
    .get_result(conn)
    .await
    .optional()
    .map_err(storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> PcdLimits {
        PcdLimits {
            batch_item_count: 4,
            max_queries_per_window: 1,
            quota_window_seconds: 86_400,
            batch_completion_ttl_seconds: 3_600,
            evaluation_lease_seconds: 30,
        }
    }

    fn now() -> DateTime<Utc> {
        "2026-08-29T00:00:00Z".parse().expect("timestamp")
    }

    fn padded(label: &[u8]) -> OpaqueExactBucketBytes {
        let mut bytes = vec![b' '; 4096];
        bytes[..label.len()].copy_from_slice(label);
        OpaqueExactBucketBytes::for_advertised_bucket(bytes, 4096)
            .expect("test bytes occupy one exact current-v1 bucket")
    }

    fn blind(device: u8, batch: u8, digest: u8) -> BlindAdmissionRequest {
        BlindAdmissionRequest {
            device_credential_digest: DeviceCredentialDigest::new([device; 32]),
            batch_id: PcdBatchId::parse(format!("ak:batch:0196429a-0000-7000-8000-{batch:012x}"))
                .expect("batch id"),
            request_digest: PcdRequestDigest::from_closed_body_sha256([digest; 32]),
            key_epoch: 14,
            item_count: 4,
            lease_owner: [7; 32],
        }
    }

    fn matching(blind: &BlindAdmissionRequest, digest: u8) -> MatchAdmissionRequest {
        MatchAdmissionRequest {
            device_credential_digest: blind.device_credential_digest,
            batch_id: blind.batch_id.clone(),
            request_digest: PcdRequestDigest::from_closed_body_sha256([digest; 32]),
            key_epoch: blind.key_epoch,
            item_count: blind.item_count,
            lease_owner: [8; 32],
        }
    }

    fn store() -> ModelPcdStore {
        let mut store = ModelPcdStore::default();
        store
            .register_key_epoch(
                14,
                [3; 32],
                "kms://teabay/pcd/epoch/14",
                now() - Duration::seconds(1),
                None,
            )
            .expect("register epoch");
        store
    }

    #[test]
    fn epoch_registration_is_exactly_idempotent_and_rejects_identity_changes() {
        let mut store = store();
        assert_eq!(
            store.register_key_epoch(
                14,
                [3; 32],
                "kms://teabay/pcd/epoch/14",
                now() - Duration::seconds(1),
                None,
            ),
            Ok(())
        );
        assert_eq!(
            store.register_key_epoch(
                14,
                [4; 32],
                "kms://teabay/pcd/epoch/14",
                now() - Duration::seconds(1),
                None,
            ),
            Err(PcdReject::DuplicateConflict.into())
        );
    }

    #[test]
    fn fixed_batch_and_quota_admission_are_atomic_in_the_model() {
        let mut store = store();
        let mut invalid = blind(1, 1, 1);
        invalid.item_count = 3;
        assert_eq!(
            store.admit_blind(limits(), now(), invalid),
            Err(PcdReject::FixedBatchCardinality.into())
        );

        let first = blind(1, 1, 1);
        assert_eq!(
            store.admit_blind(limits(), now(), first.clone()),
            Ok(PcdAdmission::Evaluate {
                pinned_key_epoch: 14,
                lease_version: 1,
                lease_expires_at: now() + Duration::seconds(30),
            })
        );
        assert!(matches!(
            store.admit_blind(limits(), now(), blind(1, 2, 2)),
            Err(PcdError::Rejected(PcdReject::QuotaExhausted { .. }))
        ));
        assert_eq!(
            store.admit_blind(limits(), now(), first),
            Ok(PcdAdmission::PendingRetry {
                pinned_key_epoch: 14,
                lease_version: 1,
                retry_after_seconds: 30,
            })
        );
    }

    #[test]
    fn existing_batches_keep_stored_cardinality_across_current_config_changes() {
        let mut store = store();
        let existing = blind(1, 1, 1);
        store
            .admit_blind(limits(), now(), existing.clone())
            .expect("admit under old fixed batch");

        let mut current = limits();
        current.batch_item_count = 8;
        assert_eq!(
            store.admit_blind(current, now(), existing.clone()),
            Ok(PcdAdmission::PendingRetry {
                pinned_key_epoch: 14,
                lease_version: 1,
                retry_after_seconds: 30,
            })
        );
        store
            .record_blind_outcome(now(), &existing, 1, padded(b"old-batch"))
            .expect("record old batch");
        assert!(matches!(
            store.admit_match(current, now(), matching(&existing, 2)),
            Ok(PcdAdmission::Evaluate { .. })
        ));

        let stale_new = blind(2, 2, 3);
        assert_eq!(
            store.admit_blind(current, now(), stale_new.clone()),
            Err(PcdReject::FixedBatchCardinality.into())
        );
        let mut current_new = stale_new;
        current_new.item_count = 8;
        assert!(matches!(
            store.admit_blind(current, now(), current_new),
            Ok(PcdAdmission::Evaluate { .. })
        ));
    }

    #[test]
    fn exact_retries_reuse_cached_phase_outcomes_and_conflicts_fail_closed() {
        let mut store = store();
        let blind = blind(1, 1, 1);
        store
            .admit_blind(limits(), now(), blind.clone())
            .expect("admit blind");
        assert_eq!(
            store.record_blind_outcome(now(), &blind, 1, padded(b"blind-body")),
            Ok(OutcomeWrite::Recorded)
        );
        assert!(matches!(
            store.admit_blind(limits(), now(), blind.clone()),
            Ok(PcdAdmission::Cached { outcome, .. }) if outcome == padded(b"blind-body")
        ));
        let mut conflict = blind.clone();
        conflict.request_digest = PcdRequestDigest::from_closed_body_sha256([9; 32]);
        assert_eq!(
            store.admit_blind(limits(), now(), conflict),
            Err(PcdReject::DuplicateConflict.into())
        );

        let matching = matching(&blind, 2);
        assert!(matches!(
            store.admit_match(limits(), now(), matching.clone()),
            Ok(PcdAdmission::Evaluate { .. })
        ));
        store
            .record_match_outcome(now(), &matching, 1, padded(b"match-body"))
            .expect("record match");
        assert!(matches!(
            store.admit_match(limits(), now(), matching),
            Ok(PcdAdmission::Cached { outcome, .. }) if outcome == padded(b"match-body")
        ));
    }

    #[test]
    fn pinned_epoch_and_ttl_survive_quota_window_independently() {
        let mut store = store();
        let blind = blind(1, 1, 1);
        store
            .admit_blind(limits(), now(), blind.clone())
            .expect("admit blind");
        store
            .record_blind_outcome(now(), &blind, 1, padded(b"blind-body"))
            .expect("record blind");
        let mut wrong_epoch = matching(&blind, 2);
        wrong_epoch.key_epoch = 15;
        assert_eq!(
            store.admit_match(limits(), now(), wrong_epoch),
            Err(PcdReject::PinnedEpochMismatch.into())
        );
        assert_eq!(
            store.admit_match(
                limits(),
                now() + Duration::seconds(3_600),
                matching(&blind, 2)
            ),
            Err(PcdReject::BatchUnavailable.into())
        );
    }

    #[test]
    fn wrong_device_is_indistinguishable_from_unknown_batch() {
        let mut store = store();
        let blind = blind(1, 1, 1);
        store
            .admit_blind(limits(), now(), blind.clone())
            .expect("admit blind");
        store
            .record_blind_outcome(now(), &blind, 1, padded(b"blind-body"))
            .expect("record blind");
        let mut wrong_device = matching(&blind, 2);
        wrong_device.device_credential_digest = DeviceCredentialDigest::new([2; 32]);
        assert_eq!(
            store.admit_match(limits(), now(), wrong_device),
            Err(PcdReject::BatchUnavailable.into())
        );
    }

    #[test]
    fn expired_phase_leases_are_taken_over_and_stale_workers_lose_cas() {
        let mut store = store();
        let first_owner = blind(1, 1, 1);
        store
            .admit_blind(limits(), now(), first_owner.clone())
            .expect("admit blind");

        let takeover_at = now() + Duration::seconds(31);
        let mut blind_takeover = first_owner.clone();
        blind_takeover.lease_owner = [9; 32];
        assert!(matches!(
            store.admit_blind(limits(), takeover_at, blind_takeover.clone()),
            Ok(PcdAdmission::Evaluate {
                lease_version: 2,
                ..
            })
        ));
        assert_eq!(
            store.record_blind_outcome(takeover_at, &first_owner, 1, padded(b"stale")),
            Err(PcdReject::LeaseLost.into())
        );
        store
            .record_blind_outcome(takeover_at, &blind_takeover, 2, padded(b"blind"))
            .expect("takeover records blind outcome");

        let first_match_owner = matching(&blind_takeover, 2);
        store
            .admit_match(limits(), takeover_at, first_match_owner.clone())
            .expect("admit match");
        let match_takeover_at = takeover_at + Duration::seconds(31);
        let mut match_takeover = first_match_owner.clone();
        match_takeover.lease_owner = [10; 32];
        assert!(matches!(
            store.admit_match(limits(), match_takeover_at, match_takeover.clone()),
            Ok(PcdAdmission::Evaluate {
                lease_version: 2,
                ..
            })
        ));
        assert_eq!(
            store.record_match_outcome(match_takeover_at, &first_match_owner, 1, padded(b"stale"),),
            Err(PcdReject::LeaseLost.into())
        );
        assert_eq!(
            store.record_match_outcome(match_takeover_at, &match_takeover, 2, padded(b"match"),),
            Ok(OutcomeWrite::Recorded)
        );
    }

    #[test]
    fn leases_are_clamped_at_ttl_minus_one_for_both_phases() {
        let mut store = store();
        let batch_expires_at = now() + Duration::seconds(3_600);
        let near_expiry = batch_expires_at - Duration::seconds(1);

        let first_blind_owner = blind(3, 3, 3);
        store
            .admit_blind(limits(), now(), first_blind_owner.clone())
            .expect("admit blind");
        let mut blind_takeover = first_blind_owner.clone();
        blind_takeover.lease_owner = [9; 32];
        assert!(matches!(
            store.admit_blind(limits(), near_expiry, blind_takeover.clone()),
            Ok(PcdAdmission::Evaluate {
                lease_version: 2,
                lease_expires_at,
                ..
            }) if lease_expires_at == batch_expires_at
        ));
        store
            .record_blind_outcome(near_expiry, &blind_takeover, 2, padded(b"near-ttl-blind"))
            .expect("record clamped blind outcome");
        let first_match = matching(&blind_takeover, 4);
        assert!(matches!(
            store.admit_match(limits(), near_expiry, first_match.clone()),
            Ok(PcdAdmission::Evaluate {
                lease_version: 1,
                lease_expires_at,
                ..
            }) if lease_expires_at == batch_expires_at
        ));
        assert_eq!(
            store.admit_match(limits(), batch_expires_at, first_match),
            Err(PcdReject::BatchUnavailable.into())
        );

        let second_blind = blind(4, 4, 5);
        store
            .admit_blind(limits(), now(), second_blind.clone())
            .expect("admit second blind");
        store
            .record_blind_outcome(now(), &second_blind, 1, padded(b"blind"))
            .expect("record second blind");
        let first_match_owner = matching(&second_blind, 6);
        store
            .admit_match(limits(), now(), first_match_owner.clone())
            .expect("admit initial match");
        let mut match_takeover = first_match_owner;
        match_takeover.lease_owner = [10; 32];
        assert!(matches!(
            store.admit_match(limits(), near_expiry, match_takeover.clone()),
            Ok(PcdAdmission::Evaluate {
                lease_version: 2,
                lease_expires_at,
                ..
            }) if lease_expires_at == batch_expires_at
        ));
        assert_eq!(
            store.record_match_outcome(batch_expires_at, &match_takeover, 2, padded(b"too-late"),),
            Err(PcdReject::BatchUnavailable.into())
        );
    }

    #[test]
    fn padded_outcomes_require_the_exact_declared_bucket() {
        assert!(OpaqueExactBucketBytes::for_advertised_bucket(vec![b' '; 4096], 4096,).is_ok());
        assert_eq!(
            OpaqueExactBucketBytes::for_advertised_bucket(vec![b' '; 4095], 4096,),
            Err(PcdReject::InvalidOutcome.into())
        );
        assert_eq!(
            OpaqueExactBucketBytes::for_advertised_bucket(vec![b' '; 8192], 8192),
            Err(PcdReject::InvalidOutcome.into())
        );
    }

    #[test]
    fn quota_retry_is_quantized_but_lease_retry_is_exact() {
        assert_eq!(
            lease_retry_after_seconds(now(), now() + Duration::seconds(30)),
            30
        );
        assert_eq!(
            quota_retry_after_seconds(now(), now() + Duration::seconds(1)),
            300
        );
        assert_eq!(
            quota_retry_after_seconds(now(), now() + Duration::seconds(300)),
            300
        );
        assert_eq!(
            quota_retry_after_seconds(now(), now() + Duration::seconds(301)),
            600
        );
    }

    #[test]
    fn dark_core_has_no_product_integration_points() {
        for (label, source) in [
            ("router/openapi", include_str!("routing.rs")),
            ("configuration", include_str!("config.rs")),
            ("app state", include_str!("state.rs")),
            ("product entrypoint", include_str!("main.rs")),
        ] {
            for forbidden in [
                "pcd_dark",
                "private_contact_discovery",
                "private-contact-discovery",
                "ak.operation_bundle.directory_service.private_contact_discovery.v1",
            ] {
                assert!(
                    !source.contains(forbidden),
                    "{label} exposed dark PCD token {forbidden}"
                );
            }
        }
    }
}
