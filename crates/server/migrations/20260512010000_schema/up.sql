-- Squashed initial migration (teabay).
-- Consolidates the complete migration history through 2026-06-25.

-- teabay schema bootstrap (spec discovery-directory.md §7-§9 / §11).
--
-- Fresh-install schema; new databases should bootstrap from this file only.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---- Enums ---------------------------------------------------------------

CREATE TYPE resource_kind AS ENUM (
    'realm',
    'organization',
    'actor',
    'applet',
    'handle'
);

CREATE TYPE discoverability AS ENUM (
    'public',
    'listed',
    'restricted',
    'unlisted',
    'invite_only',
    'secret'
);

CREATE TYPE ingest_mode AS ENUM ('push');

CREATE TYPE accept_policy_kind AS ENUM (
    'open',
    'allowlist',
    'trust_root_signed',
    'operator_review'
);

CREATE TYPE withdrawal_kind AS ENUM (
    'resource_state_change',
    'resource_withdraw',
    'operator_takedown'
);

CREATE TYPE audit_event_kind AS ENUM (
    'ingest_accepted',
    'ingest_rejected',
    'revalidation_succeeded',
    'revalidation_failed',
    'withdrawal',
    'operator_takedown',
    'allowlist_added',
    'allowlist_removed',
    'admin_resource_upserted',
    'admin_resource_deleted',
    'expiry_purged'
);

-- ---- Search helpers ------------------------------------------------------

CREATE OR REPLACE FUNCTION directory_resource_search_text(projection jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT btrim(
        coalesce(projection->>'name', '') || ' ' ||
        coalesce(projection->>'summary', '') || ' ' ||
        coalesce(projection->>'alias', '') || ' ' ||
        coalesce(projection->>'handle', '')
    )
$$;

-- ---- Effective entries ---------------------------------------------------

CREATE TABLE directory_resources (
    resource_kind     resource_kind     NOT NULL,
    resource_id       TEXT              NOT NULL,
    station_id TEXT           NOT NULL,
    discovery_state   JSONB             NOT NULL,
    public_projection JSONB             NOT NULL,
    discoverability   discoverability   NOT NULL,
    as_of             TIMESTAMPTZ       NOT NULL,
    source_refs       TEXT[]            NOT NULL,
    policy_revision   TEXT              NOT NULL,
    indexed_at        TIMESTAMPTZ       NOT NULL DEFAULT now(),
    effective_ttl_seconds INTEGER       NOT NULL,
    next_revalidation_after TIMESTAMPTZ NOT NULL,
    stale             BOOLEAN           NOT NULL DEFAULT false,
    divergent         BOOLEAN           NOT NULL DEFAULT false,
    -- Stable service core ids only. DIDs and URL-shaped route hints are
    -- rejected by application admission and never persisted as authority.
    via_services      TEXT[]            NOT NULL DEFAULT '{}',
    last_announce_id  TEXT,
    search_text       TEXT GENERATED ALWAYS AS (
        directory_resource_search_text(public_projection)
    ) STORED,
    search_vector     tsvector GENERATED ALWAYS AS (
        to_tsvector('simple', directory_resource_search_text(public_projection))
    ) STORED,
    PRIMARY KEY (resource_kind, resource_id)
);

CREATE INDEX directory_resources_discoverability_idx
    ON directory_resources (discoverability);

CREATE INDEX directory_resources_indexed_at_idx
    ON directory_resources (indexed_at DESC);

CREATE INDEX directory_resources_next_revalidation_idx
    ON directory_resources (next_revalidation_after)
    WHERE stale = false;

CREATE INDEX directory_resources_public_projection_gin
    ON directory_resources USING GIN (public_projection jsonb_path_ops);

CREATE INDEX directory_resources_search_text_trgm_idx
    ON directory_resources USING GIN (search_text gin_trgm_ops);

CREATE INDEX directory_resources_search_vector_gin_idx
    ON directory_resources USING GIN (search_vector);

CREATE INDEX directory_resources_realm_scope_org_idx
    ON directory_resources ((public_projection->>'organization_id'))
    WHERE resource_kind = 'realm';

CREATE INDEX directory_resources_realm_scope_parent_idx
    ON directory_resources ((public_projection->>'parent_realm_id'))
    WHERE resource_kind = 'realm';

-- ---- Ingest audit (every accepted announce, push and pull) ---------------

CREATE TABLE ingest_announces (
    announce_id       TEXT              PRIMARY KEY,
    resource_kind     resource_kind     NOT NULL,
    resource_id       TEXT              NOT NULL,
    station_id TEXT           NOT NULL,
    ingest_mode       ingest_mode       NOT NULL,
    discovery_state   JSONB             NOT NULL,
    source_refs       TEXT[]            NOT NULL,
    policy_revision   TEXT              NOT NULL,
    as_of             TIMESTAMPTZ       NOT NULL,
    indexed_at        TIMESTAMPTZ       NOT NULL DEFAULT now(),
    effective_ttl_seconds INTEGER       NOT NULL,
    supersedes_announce_id TEXT
        REFERENCES ingest_announces (announce_id),
    request_digest    BYTEA             NOT NULL,
    UNIQUE (resource_kind, resource_id, as_of)
);

CREATE INDEX ingest_announces_resource_idx
    ON ingest_announces (resource_kind, resource_id, as_of DESC);

CREATE INDEX ingest_announces_request_digest_idx
    ON ingest_announces (request_digest);

-- ---- Withdrawals ---------------------------------------------------------

CREATE TABLE withdrawals (
    withdraw_id       TEXT              PRIMARY KEY,
    resource_kind     resource_kind     NOT NULL,
    resource_id       TEXT              NOT NULL,
    kind              withdrawal_kind   NOT NULL,
    reason            TEXT              NOT NULL,
    proof             JSONB             NOT NULL,
    effective_at      TIMESTAMPTZ       NOT NULL,
    acked_at          TIMESTAMPTZ       NOT NULL DEFAULT now(),
    operator          TEXT,
    notified_at       TIMESTAMPTZ,
    overturned_at     TIMESTAMPTZ,
    overturn_appeal_id TEXT,
    overturn_receipt  JSONB
);

CREATE INDEX withdrawals_resource_idx
    ON withdrawals (resource_kind, resource_id, effective_at DESC);

CREATE INDEX withdrawals_active_takedown_idx
    ON withdrawals (resource_kind, resource_id, effective_at DESC)
    WHERE overturned_at IS NULL;

-- ---- Object access and invite revocation --------------------------------

CREATE TABLE directory_object_access (
    realm_id        TEXT        NOT NULL,
    object_kind     TEXT        NOT NULL
        CHECK (object_kind IN ('strand', 'message')),
    strand_id         TEXT        NOT NULL,
    message_id      TEXT        NOT NULL DEFAULT '',
    public_projection JSONB     NOT NULL,
    allowed_requesters TEXT[]   NOT NULL DEFAULT '{}',
    required_claims JSONB       NOT NULL DEFAULT '[]'::jsonb,
    as_of           TIMESTAMPTZ NOT NULL,
    source_refs     TEXT[]      NOT NULL,
    policy_revision TEXT,
    indexed_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    stale           BOOLEAN     NOT NULL DEFAULT false,
    divergent       BOOLEAN     NOT NULL DEFAULT false,
    CHECK (
        (object_kind = 'strand' AND message_id = '')
        OR (object_kind = 'message' AND message_id <> '')
    ),
    PRIMARY KEY (realm_id, object_kind, strand_id, message_id)
);

CREATE INDEX directory_object_access_lookup_idx
    ON directory_object_access (realm_id, object_kind, strand_id, message_id)
    WHERE stale = false;

CREATE INDEX directory_object_access_requesters_gin_idx
    ON directory_object_access USING GIN (allowed_requesters);

CREATE TABLE directory_invite_revocations (
    token_payload_digest BYTEA       PRIMARY KEY,
    target_digest        TEXT        NOT NULL,
    revoked_at           TIMESTAMPTZ NOT NULL,
    revoked_by        TEXT        NOT NULL,
    reason               TEXT,
    expires_at           TIMESTAMPTZ
);

CREATE INDEX directory_invite_revocations_target_idx
    ON directory_invite_revocations (target_digest, revoked_at DESC);

-- ---- Operator allowlist --------------------------------------------------

CREATE TABLE accept_allowlist (
    resource_did      TEXT              PRIMARY KEY,
    added_by       TEXT              NOT NULL,
    added_at          TIMESTAMPTZ       NOT NULL DEFAULT now(),
    note              TEXT
);

-- ---- Audit log -----------------------------------------------------------

CREATE TABLE directory_audit (
    audit_id          BIGSERIAL         PRIMARY KEY,
    occurred_at       TIMESTAMPTZ       NOT NULL DEFAULT now(),
    kind              audit_event_kind  NOT NULL,
    resource_kind     resource_kind,
    resource_id       TEXT,
    actor_id          TEXT,
    authenticated_credential_id TEXT,
    asserted_operator_localpart TEXT,
    authentication_method TEXT,
    detail            JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_digest       BYTEA,
    audit_digest      BYTEA
);

CREATE INDEX directory_audit_resource_idx
    ON directory_audit (resource_kind, resource_id, occurred_at DESC);

CREATE INDEX directory_audit_occurred_at_idx
    ON directory_audit (occurred_at DESC);

-- Realm terminal state — `ak.realm.destroy` anchor marker. Resolve /
--      search projections collapse to a tombstone once `realm_destroyed_at`
--      is non-null.
-- Consent revoke scope=any directory reachability invalidation — soft
--      delete via `reachability_revoked_at` (audit-preserving) plus a
--      mirror flag on `directory_resources` so the query face can shed
--      cached projections without losing the underlying row.
-- Federation idempotency cache key extension — `ingest_announces`
--      gains the four-field cache key tuple plus a `historical_only`
--      marker for replays after a revoked service key.

ALTER TABLE directory_resources
    ADD COLUMN realm_destroyed_at TIMESTAMPTZ,
    ADD COLUMN reachability_revoked_at TIMESTAMPTZ,
    ADD COLUMN reachability_revoked_reason TEXT;

CREATE INDEX directory_resources_realm_destroyed_idx
    ON directory_resources (resource_kind)
    WHERE realm_destroyed_at IS NOT NULL;

CREATE INDEX directory_resources_reachability_revoked_idx
    ON directory_resources (resource_kind, resource_id)
    WHERE reachability_revoked_at IS NOT NULL;

ALTER TABLE ingest_announces
    ADD COLUMN source_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN verification_method TEXT NOT NULL DEFAULT '',
    ADD COLUMN service_binding_ref TEXT NOT NULL DEFAULT '',
    ADD COLUMN origin_key_state_digest BYTEA NOT NULL DEFAULT '\x'::bytea,
    ADD COLUMN historical_only BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX ingest_announces_cache_key_idx
    ON ingest_announces (
        source_id,
        verification_method,
        service_binding_ref,
        origin_key_state_digest
    );

-- Audit event kinds for the tombstone / reachability / replay markers above.
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'consent_revoke_invalidation';
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'realm_destroyed';
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'ingest_historical_only';

-- Freshness columns.
--
-- `directory_resources.indexed_at + effective_ttl_seconds` already
-- gives us `next_revalidation_after`, but the operator-facing TTL
-- story (announce refreshes, explicit expiry) needs two more derived columns:
--
--   * `last_refreshed_at` — most recent successful announce or
--     refresh. Equals `indexed_at` on row insert; each accepted announce
--     bumps it forward.
--   * `expires_at`        — explicit row-level expiry. Equals
--     `last_refreshed_at + effective_ttl_seconds`. A background
--     worker treats rows past `expires_at` as stale and ultimately
--     evicts them (the expiry worker runs on a
--     timer; the eviction job is layered on top).
--
-- Both columns are populated from the existing
-- `indexed_at` + `effective_ttl_seconds` pair.

ALTER TABLE directory_resources
    ADD COLUMN last_refreshed_at TIMESTAMPTZ,
    ADD COLUMN expires_at        TIMESTAMPTZ;

UPDATE directory_resources
   SET last_refreshed_at = indexed_at,
       expires_at = indexed_at + (effective_ttl_seconds || ' seconds')::INTERVAL;

ALTER TABLE directory_resources
    ALTER COLUMN last_refreshed_at SET NOT NULL,
    ALTER COLUMN expires_at        SET NOT NULL,
    ALTER COLUMN last_refreshed_at SET DEFAULT now();

-- The background expiry sweep filters by `expires_at < now()` so we
-- want a B-tree index keyed on expiry. Partial index on the rows
-- that haven't already been marked stale to keep the index small.
CREATE INDEX directory_resources_expires_at_idx
    ON directory_resources (expires_at)
    WHERE stale = false;

-- A.8.4 — admin token rotation table.
--
-- Static `TEABAY_ADMIN_TOKEN` bearer is development-only. Production
-- admin callers provision rotating HMAC-SHA256 tokens with a 30-minute
-- window. Each row is one shared
-- HMAC secret + a key id that's surfaced in audit so we can attribute
-- admin actions to a specific operator credential.
CREATE TABLE IF NOT EXISTS admin_tokens (
    key_id TEXT PRIMARY KEY,
    secret BYTEA NOT NULL,
    label TEXT,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_tokens_active_idx
    ON admin_tokens (key_id)
    WHERE revoked_at IS NULL;

-- A.8.5 — chained audit digest.
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'expiry_purged';

-- A.8.5 — chained audit digest.
--
-- Append `audit_digest = sha256(canonical(row) || prev_digest)` so an
-- operator can verify the audit log was not tampered with after the
-- fact. Identity categories are separate at table creation: `actor_id` is
-- an Arkret permanent principal, `authenticated_credential_id` is a local
-- credential id, and `asserted_operator_localpart` is an unverified byline.

-- Append-only safeguard: block UPDATEs on the audit log. Inserts and
-- DELETEs are still permitted (DELETEs are used by the data-retention
-- sweep when one is added later) but UPDATEs would invalidate the
-- digest chain.
CREATE OR REPLACE FUNCTION directory_audit_block_update()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'directory_audit is append-only; UPDATE forbidden by chained digest invariant';
END;
$$;

DROP TRIGGER IF EXISTS directory_audit_block_update ON directory_audit;
CREATE TRIGGER directory_audit_block_update
    BEFORE UPDATE ON directory_audit
    FOR EACH ROW
    EXECUTE FUNCTION directory_audit_block_update();

-- B.8.8 — operator takedown proposals and their notifier fanout.
--
-- `discovery-directory.md` defines unilateral operator takedown with an
-- immutable audit log and a resource notification; v1 core defines no
-- multi-operator approval or quorum, so this table carries the proposal and
-- `notification_status` drives the takedown-notifier webhook fanout, which is
-- the only writer of these rows.
CREATE TABLE IF NOT EXISTS pending_takedowns (
    pending_id TEXT PRIMARY KEY,
    resource_kind resource_kind NOT NULL,
    resource_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    proposed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- `pending|approved|executed|rejected|expired`
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at TIMESTAMPTZ NOT NULL,
    executed_at TIMESTAMPTZ,
    executed_withdraw_id TEXT,
    notification_status TEXT,
    next_notification_after TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS pending_takedowns_status_idx
    ON pending_takedowns (status, expires_at);

CREATE INDEX IF NOT EXISTS pending_takedowns_notification_due_idx
    ON pending_takedowns (next_notification_after)
    WHERE notification_status IS NULL
       OR notification_status = 'pending'
       OR notification_status LIKE 'retry:%';

-- Operator notification endpoints for pending takedown proposal and
-- approval transitions. This internal audit notifier is not a discovery
-- update subscription surface.
CREATE TABLE IF NOT EXISTS pending_takedown_webhooks (
    webhook_id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    secret BYTEA,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Identity core/full split — stable-identity shape audit.
--
-- `discovery-directory.md` §8.3 types the Organization / Actor / Applet
-- `resource_id` and the `station_id` as `did_core_id`, not
-- as resolvable DIDs. Both columns therefore carry the stable core form
-- `ak:did_core:<method>:<core>` (lowercase ASCII method, non-empty
-- whitespace-free core). These diagnostic CHECK constraints mirror the SDK
-- `DidCoreId::new` parser so any future direct INSERT (e.g. a replay tool,
-- an admin-side data load) also fails closed against a DID smuggled
-- into a stable-identity column. The constraint is intentionally a superset
-- of what the application enforces — application-layer validation runs first
-- and is more precise; this is a last-resort DB safety net.
--
-- Round-trip clean: the constraint is enforced immediately. Aggressive-mode
-- policy is fail-closed on both existing rows and new inserts.

ALTER TABLE directory_resources
    ADD CONSTRAINT directory_resources_resource_id_core_shape_chk
        CHECK (
            resource_kind NOT IN ('organization', 'actor', 'applet')
            OR resource_id ~ '^ak:did_core:[a-z0-9]+:[^[:space:]]+$'
        );

ALTER TABLE directory_resources
    ADD CONSTRAINT directory_resources_station_id_core_shape_chk
        CHECK (station_id ~ '^ak:did_core:[a-z0-9]+:[^[:space:]]+$');

-- Mirror on ingest_announces so the announce ledger and the
-- projected table agree on stable-identity shape.
ALTER TABLE ingest_announces
    ADD CONSTRAINT ingest_announces_resource_id_core_shape_chk
        CHECK (
            resource_kind NOT IN ('organization', 'actor', 'applet')
            OR resource_id ~ '^ak:did_core:[a-z0-9]+:[^[:space:]]+$'
        );

ALTER TABLE ingest_announces
    ADD CONSTRAINT ingest_announces_station_id_core_shape_chk
        CHECK (station_id ~ '^ak:did_core:[a-z0-9]+:[^[:space:]]+$');

COMMENT ON CONSTRAINT directory_resources_resource_id_core_shape_chk
    ON directory_resources IS
    'Stable identity core syntax: ^ak:did_core:[a-z0-9]+:[^\s]+$. Application layer enforces first.';

COMMENT ON CONSTRAINT directory_resources_station_id_core_shape_chk
    ON directory_resources IS
    'Stable identity core syntax: ^ak:did_core:[a-z0-9]+:[^\s]+$. Application layer enforces first.';

CREATE TABLE IF NOT EXISTS http_signature_replays (
    replay_key BYTEA PRIMARY KEY,
    key_id TEXT NOT NULL,
    signature BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS http_signature_replays_expires_at_idx
    ON http_signature_replays (expires_at);

-- Private-contact-discovery durable state. These tables retain only
-- authenticated credential/request digests, exact-bucket outcome bytes,
-- canonical config snapshots, custody references, and 16-byte evaluated index
-- prefixes; no raw connection identifiers or VOPRF private key material are
-- stored.
CREATE TABLE pcd_key_epochs (
    key_epoch          BIGINT      PRIMARY KEY CHECK (key_epoch >= 0),
    public_key         BYTEA       NOT NULL CHECK (octet_length(public_key) = 32),
    custody_key_ref    TEXT        NOT NULL CHECK (length(custody_key_ref) BETWEEN 1 AND 512),
    index_generation   TEXT        NOT NULL DEFAULT 'empty'
        CHECK (length(index_generation) BETWEEN 1 AND 256),
    index_digest       BYTEA       NOT NULL DEFAULT decode(repeat('00', 32), 'hex')
        CHECK (octet_length(index_digest) = 32),
    index_entry_count  INTEGER     NOT NULL DEFAULT 0 CHECK (index_entry_count >= 0),
    index_ready_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at       TIMESTAMPTZ NOT NULL,
    retired_at         TIMESTAMPTZ,
    CHECK (index_ready_at >= activated_at),
    CHECK (retired_at IS NULL OR retired_at >= activated_at)
);

CREATE TABLE pcd_index_entries (
    key_epoch       BIGINT NOT NULL
        REFERENCES pcd_key_epochs (key_epoch) ON DELETE CASCADE,
    derived_prefix BYTEA  NOT NULL CHECK (octet_length(derived_prefix) = 16),
    handoff_stub   JSONB,
    PRIMARY KEY (key_epoch, derived_prefix)
);

CREATE TABLE pcd_config_snapshots (
    config_digest       BYTEA       PRIMARY KEY CHECK (octet_length(config_digest) = 32),
    canonical_config    BYTEA       NOT NULL UNIQUE
        CHECK (octet_length(canonical_config) BETWEEN 1 AND 65536),
    key_epoch           BIGINT      NOT NULL
        REFERENCES pcd_key_epochs (key_epoch) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL,
    UNIQUE (config_digest, key_epoch)
);

CREATE INDEX pcd_config_snapshots_epoch_idx ON pcd_config_snapshots (key_epoch);

CREATE TABLE pcd_quota_windows (
    device_credential_digest BYTEA       PRIMARY KEY
        CHECK (octet_length(device_credential_digest) = 32),
    window_started_at        TIMESTAMPTZ NOT NULL,
    window_expires_at        TIMESTAMPTZ NOT NULL,
    admitted_queries         BIGINT      NOT NULL CHECK (admitted_queries >= 0),
    CHECK (window_expires_at > window_started_at)
);

CREATE INDEX pcd_quota_windows_expires_at_idx
    ON pcd_quota_windows (window_expires_at);

CREATE TABLE pcd_batches (
    device_credential_digest BYTEA       NOT NULL
        CHECK (octet_length(device_credential_digest) = 32),
    batch_id                 TEXT        NOT NULL
        CHECK (batch_id ~ '^ak:batch:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    blind_request_digest     BYTEA       NOT NULL
        CHECK (octet_length(blind_request_digest) = 32),
    match_request_digest     BYTEA
        CHECK (match_request_digest IS NULL OR octet_length(match_request_digest) = 32),
    pinned_key_epoch         BIGINT      NOT NULL
        REFERENCES pcd_key_epochs (key_epoch) ON DELETE RESTRICT,
    pinned_config_digest     BYTEA       NOT NULL
        CHECK (octet_length(pinned_config_digest) = 32),
    item_count               INTEGER     NOT NULL CHECK (item_count BETWEEN 1 AND 1024),
    admitted_at              TIMESTAMPTZ NOT NULL,
    expires_at               TIMESTAMPTZ NOT NULL,
    blind_outcome            BYTEA
        CHECK (blind_outcome IS NULL OR octet_length(blind_outcome) BETWEEN 1 AND 262144),
    match_outcome            BYTEA
        CHECK (match_outcome IS NULL OR octet_length(match_outcome) BETWEEN 1 AND 262144),
    blind_lease_owner        BYTEA       NOT NULL CHECK (octet_length(blind_lease_owner) = 32),
    blind_lease_version      BIGINT      NOT NULL CHECK (blind_lease_version >= 1),
    blind_lease_expires_at   TIMESTAMPTZ NOT NULL,
    match_lease_owner        BYTEA       CHECK (match_lease_owner IS NULL OR octet_length(match_lease_owner) = 32),
    match_lease_version      BIGINT      CHECK (match_lease_version IS NULL OR match_lease_version >= 1),
    match_lease_expires_at   TIMESTAMPTZ,
    PRIMARY KEY (device_credential_digest, batch_id),
    FOREIGN KEY (pinned_config_digest, pinned_key_epoch)
        REFERENCES pcd_config_snapshots (config_digest, key_epoch) ON DELETE RESTRICT,
    CHECK (expires_at > admitted_at),
    CHECK (blind_lease_expires_at <= expires_at),
    CHECK (match_outcome IS NULL OR match_request_digest IS NOT NULL),
    CHECK (match_request_digest IS NULL OR blind_outcome IS NOT NULL),
    CHECK ((match_request_digest IS NULL) = (match_lease_owner IS NULL)),
    CHECK ((match_request_digest IS NULL) = (match_lease_version IS NULL)),
    CHECK ((match_request_digest IS NULL) = (match_lease_expires_at IS NULL)),
    CHECK (match_lease_expires_at IS NULL OR match_lease_expires_at <= expires_at)
);

CREATE INDEX pcd_batches_expiry_idx ON pcd_batches (expires_at);
CREATE INDEX pcd_batches_pinned_epoch_idx ON pcd_batches (pinned_key_epoch, expires_at);
CREATE INDEX pcd_batches_pinned_config_idx ON pcd_batches (pinned_config_digest, expires_at);

-- Any future key-epoch retirement writer MUST lock its pcd_key_epochs row
-- FOR UPDATE in the same transaction. Blind admission locks the active row
-- FOR SHARE through quota consumption and the FK-backed batch insert.

-- Spec §3 `bucketed` member_count anti-enumeration: hysteresis / minimum
-- residency for the publicly-emitted member-count bucket.
--
-- The real (instantaneous) bucket can oscillate across a grid boundary
-- (e.g. 10↔11) on every announce refresh. Emitting it verbatim lets an
-- attacker who polls the directory watch the bucket flip and binary-search
-- the exact member count. §3 therefore requires the emitted bucket to stay
-- pinned for a minimum residency window (default SHOULD ≥ the entry's
-- refresh TTL) after it changes.
--
-- Three bookkeeping columns make the residency stateful:
--   * `member_count_real_bucket`    — bucket of the latest *real* count.
--   * `member_count_bucket_locked`  — bucket currently emitted publicly
--     (mirrored into `public_projection->>'member_count_bucket'`).
--   * `member_count_bucket_since`   — when `member_count_bucket_locked`
--     last changed; residency is measured from here.
--
-- Backfill: existing rows adopt their current projection bucket as both the
-- real and locked value, pinned since `last_refreshed_at`.

ALTER TABLE directory_resources
    ADD COLUMN member_count_real_bucket   TEXT,
    ADD COLUMN member_count_bucket_locked TEXT,
    ADD COLUMN member_count_bucket_since  TIMESTAMPTZ;

UPDATE directory_resources
   SET member_count_real_bucket   = public_projection->>'member_count_bucket',
       member_count_bucket_locked = public_projection->>'member_count_bucket',
       member_count_bucket_since  = last_refreshed_at
 WHERE public_projection ? 'member_count_bucket';

-- Verified `ak.realm.organization` relationship index.
--
-- The directory MUST NOT treat a bare `organization_id` /
-- `owning_organization_ids` projection hint as an official organization
-- relationship. An official badge, organization scoping, or
-- directory-certifier relationship is only valid when it derives from an
-- `active`, in-validity-window, scope-covering `ak.realm.organization`
-- statement that passed the SDK verifier
-- (`verify_realm_organization_statement`).
--
-- Each verified statement is keyed by `(realm_id, organization_id,
-- relationship)` as a directory projection key, so a newer statement for the
-- same triple supersedes (or revokes) the prior one. `statement_issued_at`
-- is the monotonic ordering key used to reject replayed older statements
-- (TBY-ORG-03 replay protection).

CREATE TABLE verified_realm_organizations (
    realm_id            TEXT        NOT NULL,
    organization_id    TEXT        NOT NULL,
    relationship        TEXT        NOT NULL
        CHECK (relationship IN ('owner', 'governance', 'sponsor', 'directory_certifier')),
    -- Verified machine-readable endorsement scopes (e.g. `official_badge`,
    -- `realm_admin`, `directory_listing`). Stored as the canonical snake_case
    -- scope strings the SDK enum serializes to.
    control_scopes      TEXT[]      NOT NULL DEFAULT '{}',
    statement_id        TEXT        NOT NULL,
    -- Statement validity window (from the verified payload). `expires_at`
    -- NULL ⇒ no expiry.
    statement_issued_at TIMESTAMPTZ NOT NULL,
    not_before          TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    -- Realm authority revision the organization evaluated, when present.
    -- The column name follows the current relationship-statement wire field;
    -- it is not a commit-stream frontier or ordering primitive.
    realm_frontier_digest TEXT,
    -- Whether the relationship is currently considered fresh. A relationship is
    -- marked stale (rather than deleted) when the authority revision the
    -- organization evaluated differs from current, so it stops surfacing as
    -- an effective verified badge without losing the audit trail.
    stale               BOOLEAN     NOT NULL DEFAULT false,
    verified_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_announce_id  TEXT,
    PRIMARY KEY (realm_id, organization_id, relationship)
);

CREATE INDEX verified_realm_organizations_realm_idx
    ON verified_realm_organizations (realm_id)
    WHERE stale = false;

CREATE INDEX verified_realm_organizations_org_idx
    ON verified_realm_organizations (organization_id)
    WHERE stale = false;

CREATE INDEX verified_realm_organizations_expiry_idx
    ON verified_realm_organizations (expires_at)
    WHERE expires_at IS NOT NULL;
