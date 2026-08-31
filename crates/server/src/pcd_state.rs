//! Durable private-contact-discovery state machine.
//!
//! Outcome storage remains byte-oriented because exact retries must reproduce
//! the original entity body. The production caller in `crate::pcd` constructs,
//! pads, validates, and canonically encodes the closed SDK outcome before these
//! bytes can enter the store. This module owns the transaction, quota, lease,
//! pinned epoch/config, derived-index, restart, and rotation invariants.

use std::collections::{HashMap, HashSet};
use std::fmt;

use arkret_sdk::{InviteConsentHandoffStub, PrivateContactDiscovery};
use chrono::{DateTime, Duration, Utc};
use diesel::sql_types::{Array, BigInt, Bytea, Integer, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName};
use diesel_async::{AsyncConnection, RunQueryDsl};
use sha2::{Digest, Sha256};

use crate::Db;

const RETRY_AFTER_QUANTUM_SECONDS: u64 = 300;
const CURRENT_V1_RESPONSE_BUCKETS_BYTES: [u32; 4] =
    PrivateContactDiscovery::RESPONSE_SIZE_BUCKETS_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcdOperationalLimits {
    pub evaluation_lease_seconds: u32,
}

impl PcdOperationalLimits {
    fn validate(self) -> Result<Self, PcdError> {
        if self.evaluation_lease_seconds == 0 {
            return Err(PcdReject::InvalidConfiguration.into());
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug)]
struct PcdLimits {
    batch_item_count: u16,
    max_queries_per_window: u64,
    quota_window_seconds: u32,
    batch_completion_ttl_seconds: u32,
    evaluation_lease_seconds: u32,
}

impl PcdLimits {
    fn from_config(
        config: &PrivateContactDiscovery,
        operational: PcdOperationalLimits,
    ) -> Result<Self, PcdError> {
        config
            .validate()
            .map_err(|_| PcdReject::InvalidConfiguration)?;
        let operational = operational.validate()?;
        if config.max_psi_queries_per_window > i64::MAX as u64 {
            return Err(PcdReject::InvalidConfiguration.into());
        }
        Ok(Self {
            batch_item_count: config.batch_item_count,
            max_queries_per_window: config.max_psi_queries_per_window,
            quota_window_seconds: config.quota_window_seconds,
            batch_completion_ttl_seconds: config.batch_completion_ttl_seconds,
            // This is operational policy rather than wire configuration.  It
            // may change while an older batch is live, so clamp it to that
            // batch's pinned TTL instead of rejecting the pinned snapshot.
            evaluation_lease_seconds: operational
                .evaluation_lease_seconds
                .min(config.batch_completion_ttl_seconds),
        })
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PcdConfigDigest([u8; 32]);

impl PcdConfigDigest {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Immutable canonical SDK configuration pinned by each admitted batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcdConfigSnapshot {
    digest: PcdConfigDigest,
    canonical_bytes: Vec<u8>,
    config: PrivateContactDiscovery,
}

impl PcdConfigSnapshot {
    pub fn digest(&self) -> PcdConfigDigest {
        self.digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn config(&self) -> &PrivateContactDiscovery {
        &self.config
    }

    pub(crate) fn validated(config: &PrivateContactDiscovery) -> Result<Self, PcdError> {
        config
            .validate()
            .map_err(|_| PcdReject::InvalidConfiguration)?;
        let canonical_bytes = arkret_sdk::canonical::canonical_json_bytes(config)
            .map_err(|_| PcdReject::InvalidConfiguration)?;
        let digest = PcdConfigDigest(Sha256::digest(&canonical_bytes).into());
        Ok(Self {
            digest,
            canonical_bytes,
            config: config.clone(),
        })
    }

    fn from_persisted(
        digest: Vec<u8>,
        canonical_bytes: Vec<u8>,
        stored_key_epoch: i64,
    ) -> Result<Self, PcdError> {
        let digest = PcdConfigDigest(bytes32(digest)?);
        let config: PrivateContactDiscovery =
            arkret_sdk::canonical::from_canonical_json_slice(&canonical_bytes).map_err(storage)?;
        config.validate().map_err(storage)?;
        if u64::try_from(stored_key_epoch).map_err(storage)? != config.key_epoch {
            return Err(storage("persisted PCD config epoch mismatch"));
        }
        let expected = PcdConfigDigest(Sha256::digest(&canonical_bytes).into());
        if digest != expected {
            return Err(storage("persisted PCD config digest mismatch"));
        }
        Ok(Self {
            digest,
            canonical_bytes,
            config,
        })
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
        pinned_config: PcdConfigSnapshot,
        lease_version: u64,
        lease_expires_at: DateTime<Utc>,
    },
    PendingRetry {
        pinned_key_epoch: u64,
        pinned_config: PcdConfigSnapshot,
        lease_version: u64,
        retry_after_seconds: u64,
    },
    Cached {
        pinned_key_epoch: u64,
        pinned_config: PcdConfigSnapshot,
        outcome: OpaqueExactBucketBytes,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeWrite {
    Recorded,
    ExactRetry,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GarbageCollectionStats {
    pub expired_batches: u64,
    pub expired_quota_windows: u64,
    pub unreferenced_config_snapshots: u64,
    pub retired_key_epochs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcdIndexEntry {
    pub derived_prefix: [u8; 16],
    pub handoff_stub: Option<InviteConsentHandoffStub>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcdIndexMatch {
    pub hit: bool,
    pub handoff_stub: Option<InviteConsentHandoffStub>,
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
    pinned_config_digest: PcdConfigDigest,
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
    config_snapshots: HashMap<PcdConfigDigest, PcdConfigSnapshot>,
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
        current_config: &PrivateContactDiscovery,
        operational: PcdOperationalLimits,
        now: DateTime<Utc>,
        request: BlindAdmissionRequest,
    ) -> Result<PcdAdmission, PcdError> {
        validate_key_epoch_shape(request.key_epoch)?;
        let key = (request.device_credential_digest, request.batch_id.clone());
        if let Some(pinned_digest) = self
            .batches
            .get(&key)
            .map(|batch| batch.pinned_config_digest)
        {
            let pinned_config = self
                .config_snapshots
                .get(&pinned_digest)
                .cloned()
                .ok_or_else(|| storage("model batch lost pinned config snapshot"))?;
            let limits = PcdLimits::from_config(pinned_config.config(), operational)?;
            let batch = self.batches.get_mut(&key).expect("checked above");
            return classify_blind_retry(limits, now, &request, batch, pinned_config);
        }
        let current_snapshot = PcdConfigSnapshot::validated(current_config)?;
        let limits = PcdLimits::from_config(current_config, operational)?;
        validate_new_blind_cardinality(limits, request.item_count)?;
        if request.key_epoch != current_config.key_epoch {
            return Err(PcdReject::PinnedEpochMismatch.into());
        }
        let epoch = self
            .epochs
            .get(&request.key_epoch)
            .ok_or(PcdReject::EpochUnavailable)?;
        if now < epoch.activated_at || epoch.retired_at.is_some_and(|retired| now >= retired) {
            return Err(PcdReject::EpochUnavailable.into());
        }
        if epoch.public_key != config_public_key(current_config)? {
            return Err(PcdReject::EpochUnavailable.into());
        }
        match self.config_snapshots.get(&current_snapshot.digest) {
            Some(existing) if existing != &current_snapshot => {
                return Err(PcdReject::DuplicateConflict.into());
            }
            Some(_) => {}
            None => {}
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
        self.config_snapshots
            .entry(current_snapshot.digest)
            .or_insert_with(|| current_snapshot.clone());
        let batch_expires_at =
            now + Duration::seconds(i64::from(limits.batch_completion_ttl_seconds));
        let blind_lease_expires_at = lease_expiry(limits, now, batch_expires_at);
        self.batches.insert(
            key,
            BatchRecord {
                blind_request_digest: request.request_digest,
                match_request_digest: None,
                pinned_key_epoch: request.key_epoch,
                pinned_config_digest: current_snapshot.digest,
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
            pinned_config: current_snapshot,
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
        operational: PcdOperationalLimits,
        now: DateTime<Utc>,
        request: MatchAdmissionRequest,
    ) -> Result<PcdAdmission, PcdError> {
        validate_key_epoch_shape(request.key_epoch)?;
        let key = (request.device_credential_digest, request.batch_id.clone());
        let pinned_digest = self
            .batches
            .get(&key)
            .map(|batch| batch.pinned_config_digest)
            .ok_or(PcdReject::BatchUnavailable)?;
        let pinned_config = self
            .config_snapshots
            .get(&pinned_digest)
            .cloned()
            .ok_or_else(|| storage("model batch lost pinned config snapshot"))?;
        let limits = PcdLimits::from_config(pinned_config.config(), operational)?;
        let batch = self.batches.get_mut(&key).expect("checked above");
        validate_live_match(now, &request, batch)?;
        match batch.match_request_digest {
            Some(digest) if digest != request.request_digest => {
                Err(PcdReject::DuplicateConflict.into())
            }
            Some(_) => classify_match_retry(limits, now, &request, batch, pinned_config),
            None => {
                batch.match_request_digest = Some(request.request_digest);
                batch.match_lease_owner = Some(request.lease_owner);
                batch.match_lease_version = Some(1);
                batch.match_lease_expires_at = Some(lease_expiry(limits, now, batch.expires_at));
                Ok(PcdAdmission::Evaluate {
                    pinned_key_epoch: batch.pinned_key_epoch,
                    pinned_config,
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

    /// Mark an epoch retired under the same immutable-identity contract as the
    /// PostgreSQL row. Existing unexpired batches remain retryable via their
    /// pinned snapshot; only new admissions require an active epoch.
    pub fn retire_key_epoch(
        &mut self,
        key_epoch: u64,
        retired_at: DateTime<Utc>,
    ) -> Result<(), PcdError> {
        let epoch = self
            .epochs
            .get_mut(&key_epoch)
            .ok_or(PcdReject::EpochUnavailable)?;
        if retired_at < epoch.activated_at {
            return Err(PcdReject::InvalidConfiguration.into());
        }
        match epoch.retired_at {
            Some(existing) if existing == retired_at => Ok(()),
            Some(_) => Err(PcdReject::DuplicateConflict.into()),
            None => {
                epoch.retired_at = Some(retired_at);
                Ok(())
            }
        }
    }

    /// Explicit bounded-retention primitive. `retained_config_digest` is the
    /// caller's current validated config marker; unpinned older snapshots are
    /// deleted even when they share an active epoch. No worker invokes this
    /// dark API.
    pub fn garbage_collect(
        &mut self,
        now: DateTime<Utc>,
        retained_config_digest: PcdConfigDigest,
    ) -> GarbageCollectionStats {
        let before_batches = self.batches.len();
        self.batches.retain(|_, batch| batch.expires_at > now);

        let before_quotas = self.quotas.len();
        self.quotas.retain(|_, quota| quota.expires_at > now);

        let live_config_digests: HashSet<_> = self
            .batches
            .values()
            .map(|batch| batch.pinned_config_digest)
            .collect();
        let before_snapshots = self.config_snapshots.len();
        self.config_snapshots.retain(|digest, _| {
            live_config_digests.contains(digest) || *digest == retained_config_digest
        });

        let snapshot_epochs: HashSet<_> = self
            .config_snapshots
            .values()
            .map(|snapshot| snapshot.config.key_epoch)
            .collect();
        let before_epochs = self.epochs.len();
        self.epochs.retain(|key_epoch, epoch| {
            !epoch.retired_at.is_some_and(|retired| retired <= now)
                || snapshot_epochs.contains(key_epoch)
        });

        GarbageCollectionStats {
            expired_batches: (before_batches - self.batches.len()) as u64,
            expired_quota_windows: (before_quotas - self.quotas.len()) as u64,
            unreferenced_config_snapshots: (before_snapshots - self.config_snapshots.len()) as u64,
            retired_key_epochs: (before_epochs - self.epochs.len()) as u64,
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
             (key_epoch, public_key, custody_key_ref, activated_at, index_ready_at) \
             VALUES ($1, $2, $3, $4, $4) ON CONFLICT (key_epoch) DO NOTHING",
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
            "SELECT public_key, custody_key_ref, activated_at, retired_at FROM pcd_key_epochs \
             WHERE key_epoch = $1",
        )
        .bind::<BigInt, _>(key_epoch)
        .get_result::<EpochIdentityRow>(&mut conn)
        .await
        .map_err(storage)?;
        if existing.public_key == public_key
            && existing.custody_key_ref == custody_key_ref
            && existing.activated_at.timestamp_micros() == activated_at.timestamp_micros()
            && existing.retired_at.is_none()
        {
            Ok(())
        } else {
            Err(PcdReject::DuplicateConflict.into())
        }
    }

    /// Atomically install a custody-verified epoch and its complete derived
    /// contact index. The row becomes visible to blind admission only when the
    /// transaction containing every index entry commits.
    #[allow(clippy::too_many_arguments)]
    pub async fn activate_key_epoch(
        &self,
        key_epoch: u64,
        public_key: [u8; 32],
        custody_key_ref: &str,
        index_generation: &str,
        index_digest: [u8; 32],
        index_entries: &[PcdIndexEntry],
        activated_at: DateTime<Utc>,
    ) -> Result<(), PcdError> {
        if custody_key_ref.is_empty()
            || custody_key_ref.len() > 512
            || index_generation.is_empty()
            || index_generation.len() > 256
        {
            return Err(PcdReject::InvalidConfiguration.into());
        }
        let key_epoch = i64::try_from(key_epoch).map_err(|_| PcdReject::EpochUnavailable)?;
        let entry_count =
            i32::try_from(index_entries.len()).map_err(|_| PcdReject::InvalidConfiguration)?;
        let expected_entries = index_entries
            .iter()
            .map(|entry| (entry.derived_prefix, entry.handoff_stub.as_ref()))
            .collect::<HashMap<_, _>>();
        if expected_entries.len() != index_entries.len() {
            return Err(PcdReject::InvalidConfiguration.into());
        }
        let mut conn = self.db.get().await.map_err(storage)?;
        conn.transaction::<_, PcdError, _>(async move |conn| {
            let inserted = diesel::sql_query(
                "INSERT INTO pcd_key_epochs \
                 (key_epoch, public_key, custody_key_ref, index_generation, index_digest, \
                  index_entry_count, index_ready_at, activated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                 ON CONFLICT (key_epoch) DO NOTHING",
            )
            .bind::<BigInt, _>(key_epoch)
            .bind::<Bytea, _>(public_key)
            .bind::<Text, _>(custody_key_ref)
            .bind::<Text, _>(index_generation)
            .bind::<Bytea, _>(index_digest)
            .bind::<Integer, _>(entry_count)
            .bind::<Timestamptz, _>(activated_at)
            .execute(conn)
            .await
            .map_err(storage)?;

            if inserted == 0 {
                let existing = diesel::sql_query(
                    "SELECT public_key, custody_key_ref, index_generation, index_digest, \
                            index_entry_count, index_ready_at, activated_at, retired_at \
                     FROM pcd_key_epochs WHERE key_epoch = $1 FOR UPDATE",
                )
                .bind::<BigInt, _>(key_epoch)
                .get_result::<ActivatedEpochIdentityRow>(conn)
                .await
                .map_err(storage)?;
                if existing.public_key != public_key
                    || existing.custody_key_ref != custody_key_ref
                    || existing.index_generation != index_generation
                    || existing.index_digest != index_digest
                    || existing.index_entry_count != entry_count
                    || existing.index_ready_at.timestamp_micros() != activated_at.timestamp_micros()
                    || existing.activated_at.timestamp_micros() != activated_at.timestamp_micros()
                    || existing.retired_at.is_some()
                {
                    return Err(PcdReject::DuplicateConflict.into());
                }
                let persisted_entries = diesel::sql_query(
                    "SELECT derived_prefix, handoff_stub FROM pcd_index_entries \
                     WHERE key_epoch = $1",
                )
                .bind::<BigInt, _>(key_epoch)
                .load::<PersistedIndexEntryRow>(conn)
                .await
                .map_err(storage)?;
                if persisted_entries.len() != index_entries.len() {
                    return Err(PcdReject::DuplicateConflict.into());
                }
                for persisted in persisted_entries {
                    let derived_prefix: [u8; 16] = persisted
                        .derived_prefix
                        .try_into()
                        .map_err(|_| storage("persisted PCD index prefix has invalid length"))?;
                    let handoff_stub = persisted
                        .handoff_stub
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(storage)?;
                    if expected_entries.get(&derived_prefix).copied() != Some(handoff_stub.as_ref())
                    {
                        return Err(PcdReject::DuplicateConflict.into());
                    }
                }
            } else {
                for entry in index_entries {
                    let handoff_stub = entry
                        .handoff_stub
                        .as_ref()
                        .map(serde_json::to_value)
                        .transpose()
                        .map_err(storage)?;
                    diesel::sql_query(
                        "INSERT INTO pcd_index_entries (key_epoch, derived_prefix, handoff_stub) \
                         VALUES ($1, $2, $3)",
                    )
                    .bind::<BigInt, _>(key_epoch)
                    .bind::<Bytea, _>(entry.derived_prefix)
                    .bind::<Nullable<Jsonb>, _>(handoff_stub)
                    .execute(conn)
                    .await
                    .map_err(storage)?;
                }
            }
            diesel::sql_query(
                "UPDATE pcd_key_epochs SET retired_at = $2 \
                 WHERE key_epoch <> $1 AND retired_at IS NULL",
            )
            .bind::<BigInt, _>(key_epoch)
            .bind::<Timestamptz, _>(activated_at)
            .execute(conn)
            .await
            .map_err(storage)?;
            Ok(())
        })
        .await
    }

    pub async fn match_index(
        &self,
        key_epoch: u64,
        derived_prefixes: &[[u8; 16]],
    ) -> Result<Vec<PcdIndexMatch>, PcdError> {
        let key_epoch = i64::try_from(key_epoch).map_err(|_| PcdReject::EpochUnavailable)?;
        let values = derived_prefixes
            .iter()
            .map(|prefix| prefix.to_vec())
            .collect::<Vec<_>>();
        let mut conn = self.db.get().await.map_err(storage)?;
        let rows = diesel::sql_query(
            "SELECT input.ordinality::bigint AS ordinality, entry.derived_prefix IS NOT NULL AS hit, \
                    entry.handoff_stub \
             FROM unnest($2::bytea[]) WITH ORDINALITY AS input(derived_prefix, ordinality) \
             LEFT JOIN pcd_index_entries AS entry \
               ON entry.key_epoch = $1 AND entry.derived_prefix = input.derived_prefix \
             ORDER BY input.ordinality",
        )
        .bind::<BigInt, _>(key_epoch)
        .bind::<Array<Bytea>, _>(values)
        .load::<IndexMatchRow>(&mut conn)
        .await
        .map_err(storage)?;
        if rows.len() != derived_prefixes.len()
            || rows
                .iter()
                .enumerate()
                .any(|(index, row)| row.ordinality != i64::try_from(index + 1).unwrap_or(-1))
        {
            return Err(storage("PCD index query lost request cardinality/order"));
        }
        rows.into_iter()
            .map(|row| {
                let handoff_stub = row
                    .handoff_stub
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(storage)?;
                Ok(PcdIndexMatch {
                    hit: row.hit,
                    handoff_stub,
                })
            })
            .collect()
    }

    /// Retire an epoch while holding the exclusive counterpart of admission's
    /// `FOR SHARE` lock. The custody reference remains durable until explicit
    /// GC proves that no retained snapshot or batch pins this epoch.
    pub async fn retire_key_epoch(
        &self,
        key_epoch: u64,
        retired_at: DateTime<Utc>,
    ) -> Result<(), PcdError> {
        let key_epoch = i64::try_from(key_epoch).map_err(|_| PcdReject::EpochUnavailable)?;
        let mut conn = self.db.get().await.map_err(storage)?;
        conn.transaction::<_, PcdError, _>(async move |conn| {
            let row = diesel::sql_query(
                "SELECT activated_at, retired_at FROM pcd_key_epochs \
                 WHERE key_epoch = $1 FOR UPDATE",
            )
            .bind::<BigInt, _>(key_epoch)
            .get_result::<EpochRetirementRow>(conn)
            .await
            .optional()
            .map_err(storage)?
            .ok_or(PcdReject::EpochUnavailable)?;
            if retired_at < row.activated_at {
                return Err(PcdReject::InvalidConfiguration.into());
            }
            match row.retired_at {
                Some(existing) if existing == retired_at => Ok(()),
                Some(_) => Err(PcdReject::DuplicateConflict.into()),
                None => {
                    diesel::sql_query(
                        "UPDATE pcd_key_epochs SET retired_at = $2 WHERE key_epoch = $1",
                    )
                    .bind::<BigInt, _>(key_epoch)
                    .bind::<Timestamptz, _>(retired_at)
                    .execute(conn)
                    .await
                    .map_err(storage)?;
                    Ok(())
                }
            }
        })
        .await
    }

    pub async fn admit_blind(
        &self,
        current_config: &PrivateContactDiscovery,
        operational: PcdOperationalLimits,
        now: DateTime<Utc>,
        request: BlindAdmissionRequest,
    ) -> Result<PcdAdmission, PcdError> {
        validate_key_epoch_shape(request.key_epoch)?;
        let current_config = current_config.clone();
        let mut conn = self.db.get().await.map_err(storage)?;
        conn.transaction::<_, PcdError, _>(async move |conn| {
            lock_device(conn, request.device_credential_digest).await?;
            if let Some(batch) = load_batch(conn, &request.device_credential_digest, &request.batch_id).await? {
                let old_version = u64::try_from(batch.blind_lease_version).map_err(storage)?;
                let mut record = batch.into_record()?;
                let pinned_config = load_config_snapshot(conn, record.pinned_config_digest)
                    .await?
                    .ok_or_else(|| storage("batch lost pinned config snapshot"))?;
                let limits = PcdLimits::from_config(pinned_config.config(), operational)?;
                let admission = classify_blind_retry(
                    limits,
                    now,
                    &request,
                    &mut record,
                    pinned_config,
                )?;
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
            let current_snapshot = PcdConfigSnapshot::validated(&current_config)?;
            let limits = PcdLimits::from_config(&current_config, operational)?;
            validate_new_blind_cardinality(limits, request.item_count)?;
            if request.key_epoch != current_snapshot.config.key_epoch {
                return Err(PcdReject::PinnedEpochMismatch.into());
            }
            // The share lock is held through quota admission and batch insert,
            // so a future retirement writer cannot invalidate the pinned epoch
            // between validation and the FK-backed insert. Such a writer MUST
            // lock this same row FOR UPDATE in its retirement transaction.
            let epoch = diesel::sql_query(
                "SELECT key_epoch FROM pcd_key_epochs \
                 WHERE key_epoch = $1 AND activated_at <= $2 \
                   AND index_ready_at <= $2 \
                   AND (retired_at IS NULL OR retired_at > $2) \
                   AND public_key = $3 FOR SHARE",
            )
            .bind::<BigInt, _>(i64::try_from(request.key_epoch).map_err(storage)?)
            .bind::<Timestamptz, _>(now)
            .bind::<Bytea, _>(config_public_key(&current_snapshot.config)?)
            .get_result::<EpochLockRow>(conn)
            .await
            .optional()
            .map_err(storage)?;
            if epoch.is_none() {
                return Err(PcdReject::EpochUnavailable.into());
            }

            diesel::sql_query(
                "INSERT INTO pcd_config_snapshots \
                 (config_digest, canonical_config, key_epoch, created_at) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT (config_digest) DO NOTHING",
            )
            .bind::<Bytea, _>(current_snapshot.digest.as_bytes())
            .bind::<Bytea, _>(&current_snapshot.canonical_bytes)
            .bind::<BigInt, _>(i64::try_from(current_snapshot.config.key_epoch).map_err(storage)?)
            .bind::<Timestamptz, _>(now)
            .execute(conn)
            .await
            .map_err(storage)?;
            let persisted_snapshot = load_config_snapshot(conn, current_snapshot.digest)
                .await?
                .ok_or_else(|| storage("inserted PCD config snapshot disappeared"))?;
            if persisted_snapshot != current_snapshot {
                return Err(PcdReject::DuplicateConflict.into());
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
                  pinned_config_digest, \
                  item_count, admitted_at, expires_at, blind_lease_owner, \
                  blind_lease_version, blind_lease_expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, $10)",
            )
            .bind::<Bytea, _>(request.device_credential_digest.as_bytes())
            .bind::<Text, _>(request.batch_id.as_str())
            .bind::<Bytea, _>(request.request_digest.as_bytes())
            .bind::<BigInt, _>(key_epoch)
            .bind::<Bytea, _>(current_snapshot.digest.as_bytes())
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
                pinned_config: current_snapshot,
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
            PhaseOutcomeRequest {
                device: request.device_credential_digest,
                batch_id: &request.batch_id,
                request_digest: request.request_digest,
                key_epoch: request.key_epoch,
                lease_owner: request.lease_owner,
                lease_version,
                outcome,
                phase: Phase::Blind,
            },
        )
        .await
    }

    pub async fn admit_match(
        &self,
        operational: PcdOperationalLimits,
        now: DateTime<Utc>,
        request: MatchAdmissionRequest,
    ) -> Result<PcdAdmission, PcdError> {
        validate_key_epoch_shape(request.key_epoch)?;
        let mut conn = self.db.get().await.map_err(storage)?;
        conn.transaction::<_, PcdError, _>(async move |conn| {
            lock_device(conn, request.device_credential_digest).await?;
            let row = load_batch(conn, &request.device_credential_digest, &request.batch_id)
                .await?
                .ok_or(PcdReject::BatchUnavailable)?;
            let batch = row.clone().into_record()?;
            let pinned_config = load_config_snapshot(conn, batch.pinned_config_digest)
                .await?
                .ok_or_else(|| storage("batch lost pinned config snapshot"))?;
            let limits = PcdLimits::from_config(pinned_config.config(), operational)?;
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
                    let admission =
                        classify_match_retry(limits, now, &request, &mut mutable, pinned_config)?;
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
                        pinned_config,
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
            PhaseOutcomeRequest {
                device: request.device_credential_digest,
                batch_id: &request.batch_id,
                request_digest: request.request_digest,
                key_epoch: request.key_epoch,
                lease_owner: request.lease_owner,
                lease_version,
                outcome,
                phase: Phase::Match,
            },
        )
        .await
    }

    /// Explicit bounded-retention transaction. `retained_config_digest` is the
    /// caller's current validated config marker, and `now` must come from its
    /// trusted database-time policy. This method is intentionally not connected
    /// to a scheduler or worker while the PCD product surface is dark.
    pub async fn garbage_collect(
        &self,
        now: DateTime<Utc>,
        retained_config_digest: PcdConfigDigest,
    ) -> Result<GarbageCollectionStats, PcdError> {
        let mut conn = self.db.get().await.map_err(storage)?;
        conn.transaction::<_, PcdError, _>(async move |conn| {
            let expired_batches =
                diesel::sql_query("DELETE FROM pcd_batches WHERE expires_at <= $1")
                    .bind::<Timestamptz, _>(now)
                    .execute(conn)
                    .await
                    .map_err(storage)?;
            let expired_quota_windows =
                diesel::sql_query("DELETE FROM pcd_quota_windows WHERE window_expires_at <= $1")
                    .bind::<Timestamptz, _>(now)
                    .execute(conn)
                    .await
                    .map_err(storage)?;
            let unreferenced_config_snapshots = diesel::sql_query(
                "DELETE FROM pcd_config_snapshots AS snapshot \
                 WHERE snapshot.config_digest <> $1 \
                   AND NOT EXISTS (SELECT 1 FROM pcd_batches AS batch \
                                   WHERE batch.pinned_config_digest = snapshot.config_digest)",
            )
            .bind::<Bytea, _>(retained_config_digest.as_bytes())
            .execute(conn)
            .await
            .map_err(storage)?;
            let retired_key_epochs = diesel::sql_query(
                "DELETE FROM pcd_key_epochs AS epoch \
                 WHERE epoch.retired_at IS NOT NULL AND epoch.retired_at <= $1 \
                   AND NOT EXISTS (SELECT 1 FROM pcd_config_snapshots AS snapshot \
                                   WHERE snapshot.key_epoch = epoch.key_epoch) \
                   AND NOT EXISTS (SELECT 1 FROM pcd_batches AS batch \
                                   WHERE batch.pinned_key_epoch = epoch.key_epoch)",
            )
            .bind::<Timestamptz, _>(now)
            .execute(conn)
            .await
            .map_err(storage)?;
            Ok(GarbageCollectionStats {
                expired_batches: expired_batches as u64,
                expired_quota_windows: expired_quota_windows as u64,
                unreferenced_config_snapshots: unreferenced_config_snapshots as u64,
                retired_key_epochs: retired_key_epochs as u64,
            })
        })
        .await
    }

    async fn record_phase_outcome(
        &self,
        now: DateTime<Utc>,
        request: PhaseOutcomeRequest<'_>,
    ) -> Result<OutcomeWrite, PcdError> {
        let mut conn = self.db.get().await.map_err(storage)?;
        let batch_id = request.batch_id.clone();
        conn.transaction::<_, PcdError, _>(async move |conn| {
            lock_device(conn, request.device).await?;
            let row = load_batch(conn, &request.device, &batch_id)
                .await?
                .ok_or(PcdReject::BatchUnavailable)?;
            let batch = row.into_record()?;
            if now >= batch.expires_at {
                return Err(PcdReject::BatchUnavailable.into());
            }
            if batch.pinned_key_epoch != request.key_epoch {
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
            ) = match request.phase {
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
                Some(digest) if digest == request.request_digest => {}
                Some(_) => return Err(PcdReject::DuplicateConflict.into()),
                None => return Err(PcdReject::BatchUnavailable.into()),
            }
            if stored_owner != Some(request.lease_owner)
                || stored_version != Some(request.lease_version)
            {
                return Err(PcdReject::LeaseLost.into());
            }
            if lease_expires_at.is_none_or(|expires| now >= expires) {
                return Err(PcdReject::LeaseLost.into());
            }
            if let Some(existing) = stored_outcome {
                return if existing == request.outcome {
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
                .bind::<Bytea, _>(request.device.as_bytes())
                .bind::<Text, _>(batch_id.as_str())
                .bind::<Bytea, _>(request.request_digest.as_bytes())
                .bind::<Bytea, _>(request.lease_owner)
                .bind::<BigInt, _>(i64::try_from(request.lease_version).map_err(storage)?)
                .bind::<Bytea, _>(request.outcome.as_bytes())
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

struct PhaseOutcomeRequest<'a> {
    device: DeviceCredentialDigest,
    batch_id: &'a PcdBatchId,
    request_digest: PcdRequestDigest,
    key_epoch: u64,
    lease_owner: [u8; 32],
    lease_version: u64,
    outcome: OpaqueExactBucketBytes,
    phase: Phase,
}

fn validate_key_epoch_shape(key_epoch: u64) -> Result<(), PcdError> {
    i64::try_from(key_epoch).map_err(|_| PcdReject::PinnedEpochMismatch)?;
    Ok(())
}

fn config_public_key(config: &PrivateContactDiscovery) -> Result<[u8; 32], PcdError> {
    let decoded = arkret_sdk::canonical::base64url_decode(&config.public_key)
        .map_err(|_| PcdReject::InvalidConfiguration)?;
    decoded
        .try_into()
        .map_err(|_| PcdReject::InvalidConfiguration.into())
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
    pinned_config: PcdConfigSnapshot,
) -> Result<PcdAdmission, PcdError> {
    validate_live_blind(now, request, batch)?;
    if let Some(outcome) = &batch.blind_outcome {
        return Ok(PcdAdmission::Cached {
            pinned_key_epoch: batch.pinned_key_epoch,
            pinned_config,
            outcome: outcome.clone(),
        });
    }
    if now < batch.blind_lease_expires_at {
        return Ok(PcdAdmission::PendingRetry {
            pinned_key_epoch: batch.pinned_key_epoch,
            pinned_config,
            lease_version: batch.blind_lease_version,
            retry_after_seconds: lease_retry_after_seconds(now, batch.blind_lease_expires_at),
        });
    }
    batch.blind_lease_owner = request.lease_owner;
    batch.blind_lease_version = batch.blind_lease_version.saturating_add(1);
    batch.blind_lease_expires_at = lease_expiry(limits, now, batch.expires_at);
    Ok(PcdAdmission::Evaluate {
        pinned_key_epoch: batch.pinned_key_epoch,
        pinned_config,
        lease_version: batch.blind_lease_version,
        lease_expires_at: batch.blind_lease_expires_at,
    })
}

fn classify_match_retry(
    limits: PcdLimits,
    now: DateTime<Utc>,
    request: &MatchAdmissionRequest,
    batch: &mut BatchRecord,
    pinned_config: PcdConfigSnapshot,
) -> Result<PcdAdmission, PcdError> {
    if let Some(outcome) = &batch.match_outcome {
        return Ok(PcdAdmission::Cached {
            pinned_key_epoch: batch.pinned_key_epoch,
            pinned_config,
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
            pinned_config,
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
        pinned_config,
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
    #[diesel(sql_type = Nullable<Timestamptz>)]
    retired_at: Option<DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct ActivatedEpochIdentityRow {
    #[diesel(sql_type = Bytea)]
    public_key: Vec<u8>,
    #[diesel(sql_type = Text)]
    custody_key_ref: String,
    #[diesel(sql_type = Text)]
    index_generation: String,
    #[diesel(sql_type = Bytea)]
    index_digest: Vec<u8>,
    #[diesel(sql_type = Integer)]
    index_entry_count: i32,
    #[diesel(sql_type = Timestamptz)]
    index_ready_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    activated_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    retired_at: Option<DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct IndexMatchRow {
    #[diesel(sql_type = BigInt)]
    ordinality: i64,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    hit: bool,
    #[diesel(sql_type = Nullable<Jsonb>)]
    handoff_stub: Option<serde_json::Value>,
}

#[derive(QueryableByName)]
struct PersistedIndexEntryRow {
    #[diesel(sql_type = Bytea)]
    derived_prefix: Vec<u8>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    handoff_stub: Option<serde_json::Value>,
}

#[derive(QueryableByName)]
struct EpochLockRow {
    #[diesel(sql_type = BigInt)]
    #[allow(dead_code, reason = "row existence plus FOR SHARE is the contract")]
    key_epoch: i64,
}

#[derive(QueryableByName)]
struct EpochRetirementRow {
    #[diesel(sql_type = Timestamptz)]
    activated_at: DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    retired_at: Option<DateTime<Utc>>,
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

#[derive(QueryableByName)]
struct ConfigSnapshotRow {
    #[diesel(sql_type = Bytea)]
    config_digest: Vec<u8>,
    #[diesel(sql_type = Bytea)]
    canonical_config: Vec<u8>,
    #[diesel(sql_type = BigInt)]
    key_epoch: i64,
}

async fn load_config_snapshot(
    conn: &mut diesel_async::AsyncPgConnection,
    digest: PcdConfigDigest,
) -> Result<Option<PcdConfigSnapshot>, PcdError> {
    let row = diesel::sql_query(
        "SELECT config_digest, canonical_config, key_epoch FROM pcd_config_snapshots \
         WHERE config_digest = $1",
    )
    .bind::<Bytea, _>(digest.as_bytes())
    .get_result::<ConfigSnapshotRow>(conn)
    .await
    .optional()
    .map_err(storage)?;
    row.map(|row| {
        PcdConfigSnapshot::from_persisted(row.config_digest, row.canonical_config, row.key_epoch)
    })
    .transpose()
}

#[derive(Clone, QueryableByName)]
struct BatchRow {
    #[diesel(sql_type = Bytea)]
    blind_request_digest: Vec<u8>,
    #[diesel(sql_type = Nullable<Bytea>)]
    match_request_digest: Option<Vec<u8>>,
    #[diesel(sql_type = BigInt)]
    pinned_key_epoch: i64,
    #[diesel(sql_type = Bytea)]
    pinned_config_digest: Vec<u8>,
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
            pinned_config_digest: PcdConfigDigest(bytes32(self.pinned_config_digest)?),
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
        "SELECT blind_request_digest, match_request_digest, pinned_key_epoch, \
                pinned_config_digest, item_count, \
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

    const PUBLIC_KEY: &str = "yAPizGsF_BUGRUm1kgZZykp3ssym8E9rNXAJM1R2rU4";

    fn config(batch_item_count: u16) -> PrivateContactDiscovery {
        config_at(14, batch_item_count)
    }

    fn config_at(key_epoch: u64, batch_item_count: u16) -> PrivateContactDiscovery {
        let config = PrivateContactDiscovery::new(
            PUBLIC_KEY,
            key_epoch,
            batch_item_count,
            arkret_sdk::PrivateContactDiscoveryHandoffStubsMode::Never,
            4096,
            4096,
            3_600,
            1,
            86_400,
            arkret_sdk::AntiEnumerationDelay {
                minimum_ms: 100,
                jitter_ms: 50,
                distribution: arkret_sdk::AntiEnumerationDelayDistribution::Uniform,
            },
        );
        config.validate().expect("valid test PCD config");
        config
    }

    fn changed_config() -> PrivateContactDiscovery {
        let mut config = config(8);
        config.handoff_stubs_mode = arkret_sdk::PrivateContactDiscoveryHandoffStubsMode::Always;
        config.anti_enumeration_delay.minimum_ms = 200;
        config.validate().expect("valid changed test PCD config");
        config
    }

    fn operational() -> PcdOperationalLimits {
        PcdOperationalLimits {
            evaluation_lease_seconds: 30,
        }
    }

    fn public_key() -> [u8; 32] {
        arkret_sdk::canonical::base64url_decode(PUBLIC_KEY)
            .expect("valid public key")
            .try_into()
            .expect("32-byte public key")
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
                public_key(),
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
                public_key(),
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
            store.admit_blind(&config(4), operational(), now(), invalid),
            Err(PcdReject::FixedBatchCardinality.into())
        );

        let first = blind(1, 1, 1);
        assert_eq!(
            store.admit_blind(&config(4), operational(), now(), first.clone()),
            Ok(PcdAdmission::Evaluate {
                pinned_key_epoch: 14,
                pinned_config: PcdConfigSnapshot::validated(&config(4)).expect("snapshot"),
                lease_version: 1,
                lease_expires_at: now() + Duration::seconds(30),
            })
        );
        assert!(matches!(
            store.admit_blind(&config(4), operational(), now(), blind(1, 2, 2)),
            Err(PcdError::Rejected(PcdReject::QuotaExhausted { .. }))
        ));
        assert_eq!(
            store.admit_blind(&config(4), operational(), now(), first),
            Ok(PcdAdmission::PendingRetry {
                pinned_key_epoch: 14,
                pinned_config: PcdConfigSnapshot::validated(&config(4)).expect("snapshot"),
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
            .admit_blind(&config(4), operational(), now(), existing.clone())
            .expect("admit under old fixed batch");

        let current = changed_config();
        assert!(matches!(
            store.admit_blind(&current, operational(), now(), existing.clone()),
            Ok(PcdAdmission::PendingRetry { pinned_config, retry_after_seconds: 30, .. })
                if pinned_config.config() == &config(4)
        ));
        let mut temporarily_invalid_current = current.clone();
        temporarily_invalid_current.batch_item_count = 0;
        assert!(matches!(
            store.admit_blind(
                &temporarily_invalid_current,
                operational(),
                now(),
                existing.clone(),
            ),
            Ok(PcdAdmission::PendingRetry { pinned_config, .. })
                if pinned_config.config() == &config(4)
        ));
        store
            .record_blind_outcome(now(), &existing, 1, padded(b"old-batch"))
            .expect("record old batch");
        assert!(matches!(
            store.admit_match(operational(), now(), matching(&existing, 2)),
            Ok(PcdAdmission::Evaluate { pinned_config, .. })
                if pinned_config.config() == &config(4)
        ));

        let stale_new = blind(2, 2, 3);
        assert_eq!(
            store.admit_blind(&current, operational(), now(), stale_new.clone()),
            Err(PcdReject::FixedBatchCardinality.into())
        );
        let mut current_new = stale_new;
        current_new.item_count = 8;
        assert!(matches!(
            store.admit_blind(&current, operational(), now(), current_new),
            Ok(PcdAdmission::Evaluate { .. })
        ));
    }

    #[test]
    fn exact_retries_reuse_cached_phase_outcomes_and_conflicts_fail_closed() {
        let mut store = store();
        let blind = blind(1, 1, 1);
        store
            .admit_blind(&config(4), operational(), now(), blind.clone())
            .expect("admit blind");
        assert_eq!(
            store.record_blind_outcome(now(), &blind, 1, padded(b"blind-body")),
            Ok(OutcomeWrite::Recorded)
        );
        assert!(matches!(
            store.admit_blind(&config(4), operational(), now(), blind.clone()),
            Ok(PcdAdmission::Cached { outcome, .. }) if outcome == padded(b"blind-body")
        ));
        let mut conflict = blind.clone();
        conflict.request_digest = PcdRequestDigest::from_closed_body_sha256([9; 32]);
        assert_eq!(
            store.admit_blind(&config(4), operational(), now(), conflict),
            Err(PcdReject::DuplicateConflict.into())
        );

        let matching = matching(&blind, 2);
        assert!(matches!(
            store.admit_match(operational(), now(), matching.clone()),
            Ok(PcdAdmission::Evaluate { .. })
        ));
        store
            .record_match_outcome(now(), &matching, 1, padded(b"match-body"))
            .expect("record match");
        assert!(matches!(
            store.admit_match(operational(), now(), matching),
            Ok(PcdAdmission::Cached { outcome, .. }) if outcome == padded(b"match-body")
        ));
    }

    #[test]
    fn pinned_epoch_and_ttl_survive_quota_window_independently() {
        let mut store = store();
        let blind = blind(1, 1, 1);
        store
            .admit_blind(&config(4), operational(), now(), blind.clone())
            .expect("admit blind");
        store
            .record_blind_outcome(now(), &blind, 1, padded(b"blind-body"))
            .expect("record blind");
        let mut wrong_epoch = matching(&blind, 2);
        wrong_epoch.key_epoch = 15;
        assert_eq!(
            store.admit_match(operational(), now(), wrong_epoch),
            Err(PcdReject::PinnedEpochMismatch.into())
        );
        assert_eq!(
            store.admit_match(
                operational(),
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
            .admit_blind(&config(4), operational(), now(), blind.clone())
            .expect("admit blind");
        store
            .record_blind_outcome(now(), &blind, 1, padded(b"blind-body"))
            .expect("record blind");
        let mut wrong_device = matching(&blind, 2);
        wrong_device.device_credential_digest = DeviceCredentialDigest::new([2; 32]);
        assert_eq!(
            store.admit_match(operational(), now(), wrong_device),
            Err(PcdReject::BatchUnavailable.into())
        );
    }

    #[test]
    fn expired_phase_leases_are_taken_over_and_stale_workers_lose_cas() {
        let mut store = store();
        let first_owner = blind(1, 1, 1);
        store
            .admit_blind(&config(4), operational(), now(), first_owner.clone())
            .expect("admit blind");

        let takeover_at = now() + Duration::seconds(31);
        let mut blind_takeover = first_owner.clone();
        blind_takeover.lease_owner = [9; 32];
        assert!(matches!(
            store.admit_blind(
                &config(4),
                operational(),
                takeover_at,
                blind_takeover.clone()
            ),
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
            .admit_match(operational(), takeover_at, first_match_owner.clone())
            .expect("admit match");
        let match_takeover_at = takeover_at + Duration::seconds(31);
        let mut match_takeover = first_match_owner.clone();
        match_takeover.lease_owner = [10; 32];
        assert!(matches!(
            store.admit_match(operational(), match_takeover_at, match_takeover.clone()),
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
            .admit_blind(&config(4), operational(), now(), first_blind_owner.clone())
            .expect("admit blind");
        let mut blind_takeover = first_blind_owner.clone();
        blind_takeover.lease_owner = [9; 32];
        assert!(matches!(
            store.admit_blind(&config(4), operational(), near_expiry, blind_takeover.clone()),
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
            store.admit_match(operational(), near_expiry, first_match.clone()),
            Ok(PcdAdmission::Evaluate {
                lease_version: 1,
                lease_expires_at,
                ..
            }) if lease_expires_at == batch_expires_at
        ));
        assert_eq!(
            store.admit_match(operational(), batch_expires_at, first_match),
            Err(PcdReject::BatchUnavailable.into())
        );

        let second_blind = blind(4, 4, 5);
        store
            .admit_blind(&config(4), operational(), now(), second_blind.clone())
            .expect("admit second blind");
        store
            .record_blind_outcome(now(), &second_blind, 1, padded(b"blind"))
            .expect("record second blind");
        let first_match_owner = matching(&second_blind, 6);
        store
            .admit_match(operational(), now(), first_match_owner.clone())
            .expect("admit initial match");
        let mut match_takeover = first_match_owner;
        match_takeover.lease_owner = [10; 32];
        assert!(matches!(
            store.admit_match(operational(), near_expiry, match_takeover.clone()),
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
    fn config_snapshot_is_canonical_hashed_and_epoch_bound() {
        let snapshot = PcdConfigSnapshot::validated(&config(4)).expect("snapshot");
        let exact = PcdConfigSnapshot::from_persisted(
            snapshot.digest.as_bytes().to_vec(),
            snapshot.canonical_bytes.clone(),
            14,
        )
        .expect("exact persisted snapshot");
        assert_eq!(exact, snapshot);
        assert_ne!(
            snapshot.digest,
            PcdConfigSnapshot::validated(&changed_config())
                .expect("changed snapshot")
                .digest
        );
        assert!(matches!(
            PcdConfigSnapshot::from_persisted(
                [9; 32].to_vec(),
                snapshot.canonical_bytes.clone(),
                14,
            ),
            Err(PcdError::Storage(_))
        ));
        assert!(matches!(
            PcdConfigSnapshot::from_persisted(
                snapshot.digest.as_bytes().to_vec(),
                snapshot.canonical_bytes,
                15,
            ),
            Err(PcdError::Storage(_))
        ));
    }

    #[test]
    fn explicit_gc_bounds_config_history_without_breaking_live_pins() {
        let mut store = store();
        let old_config = config(4);
        let old_request = blind(1, 1, 1);
        let old_digest = match store
            .admit_blind(&old_config, operational(), now(), old_request)
            .expect("admit old config")
        {
            PcdAdmission::Evaluate { pinned_config, .. } => pinned_config.digest(),
            other => panic!("unexpected admission: {other:?}"),
        };

        let current_epoch_config = changed_config();
        let mut current_epoch_request = blind(2, 2, 2);
        current_epoch_request.item_count = 8;
        let current_epoch_digest = match store
            .admit_blind(
                &current_epoch_config,
                operational(),
                now(),
                current_epoch_request,
            )
            .expect("admit changed config in same epoch")
        {
            PcdAdmission::Evaluate { pinned_config, .. } => pinned_config.digest(),
            other => panic!("unexpected admission: {other:?}"),
        };
        store
            .retire_key_epoch(14, now() + Duration::seconds(3_599))
            .expect("retire old epoch");
        assert_eq!(
            store.register_key_epoch(
                14,
                public_key(),
                "kms://teabay/pcd/epoch/14",
                now() - Duration::seconds(1),
                None,
            ),
            Err(PcdReject::DuplicateConflict.into())
        );

        let live_gc = store.garbage_collect(now() + Duration::seconds(3_599), current_epoch_digest);
        assert_eq!(live_gc, GarbageCollectionStats::default());

        let first_gc =
            store.garbage_collect(now() + Duration::seconds(3_600), current_epoch_digest);
        assert_eq!(first_gc.expired_batches, 2);
        assert_eq!(first_gc.unreferenced_config_snapshots, 1);
        assert_eq!(first_gc.retired_key_epochs, 0);
        assert!(!store.config_snapshots.contains_key(&old_digest));
        assert!(store.config_snapshots.contains_key(&current_epoch_digest));
        assert!(store.epochs.contains_key(&14));

        store
            .register_key_epoch(
                15,
                public_key(),
                "kms://teabay/pcd/epoch/15",
                now() + Duration::seconds(3_599),
                None,
            )
            .expect("register replacement epoch");
        let replacement_config = config_at(15, 4);
        let mut replacement_request = blind(3, 3, 3);
        replacement_request.key_epoch = 15;
        let replacement_digest = match store
            .admit_blind(
                &replacement_config,
                operational(),
                now() + Duration::seconds(3_600),
                replacement_request,
            )
            .expect("admit replacement config")
        {
            PcdAdmission::Evaluate { pinned_config, .. } => pinned_config.digest(),
            other => panic!("unexpected admission: {other:?}"),
        };
        let second_gc = store.garbage_collect(now() + Duration::seconds(7_200), replacement_digest);
        assert_eq!(second_gc.expired_batches, 1);
        assert_eq!(second_gc.unreferenced_config_snapshots, 1);
        assert_eq!(second_gc.retired_key_epochs, 1);
        assert!(!store.config_snapshots.contains_key(&current_epoch_digest));
        assert!(!store.epochs.contains_key(&14));
        assert!(store.config_snapshots.contains_key(&replacement_digest));
        assert!(store.epochs.contains_key(&15));

        let quota_gc = store.garbage_collect(now() + Duration::seconds(90_000), replacement_digest);
        assert_eq!(quota_gc.expired_quota_windows, 3);
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
}
