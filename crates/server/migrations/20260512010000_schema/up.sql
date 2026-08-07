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
    'expiry_purged',
    'takedown_appeal_submitted',
    'takedown_appeal_decided'
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
    principal_server_did TEXT           NOT NULL,
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
    ON directory_resources ((public_projection->>'organization_did'))
    WHERE resource_kind = 'realm';

CREATE INDEX directory_resources_realm_scope_parent_idx
    ON directory_resources ((public_projection->>'parent_realm_id'))
    WHERE resource_kind = 'realm';

-- ---- Ingest audit (every accepted announce, push and pull) ---------------

CREATE TABLE ingest_announces (
    announce_id       TEXT              PRIMARY KEY,
    resource_kind     resource_kind     NOT NULL,
    resource_id       TEXT              NOT NULL,
    principal_server_did TEXT           NOT NULL,
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

CREATE TABLE takedown_appeals (
    appeal_id         TEXT              PRIMARY KEY,
    takedown_id       TEXT              NOT NULL
        REFERENCES withdrawals (withdraw_id) ON DELETE CASCADE,
    resource_kind     resource_kind     NOT NULL,
    resource_id       TEXT              NOT NULL,
    appellant_did     TEXT              NOT NULL,
    requested_outcome TEXT              NOT NULL,
    -- Spec wire carries only a sha256 digest of the appeal argument/evidence;
    -- the directory never stores plaintext appeal content (privacy: the
    -- directory is a deanonymized-metadata index, not an appeal-body store).
    argument_digest   TEXT              NOT NULL,
    appeal_packet     JSONB             NOT NULL,
    status            TEXT              NOT NULL DEFAULT 'pending',
    accepted_at       TIMESTAMPTZ       NOT NULL DEFAULT now(),
    decided_at        TIMESTAMPTZ,
    decided_by        TEXT,
    decision          TEXT,
    decision_reason   TEXT,
    decision_receipt  JSONB,
    created_at        TIMESTAMPTZ       NOT NULL,
    CHECK (status IN ('pending', 'upheld', 'overturned')),
    CHECK (decision IS NULL OR decision IN ('upheld', 'overturned'))
);

CREATE INDEX takedown_appeals_takedown_idx
    ON takedown_appeals (takedown_id, accepted_at DESC);

CREATE INDEX takedown_appeals_status_idx
    ON takedown_appeals (status, accepted_at DESC);

-- ---- Webhook subscriptions ----------------------------------------------

CREATE TABLE webhook_subscriptions (
    subscription_id   TEXT              PRIMARY KEY,
    subscriber_did    TEXT              NOT NULL,
    resource_filter   JSONB             NOT NULL,
    webhook_endpoint  TEXT              NOT NULL,
    secret            BYTEA,
    expires_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ       NOT NULL DEFAULT now()
);

CREATE INDEX webhook_subscriptions_subscriber_idx
    ON webhook_subscriptions (subscriber_did);

-- ---- PSI epoch keys ------------------------------------------------------

CREATE TABLE psi_epoch_keys (
    epoch        TEXT        PRIMARY KEY,
    ciphersuite  TEXT        NOT NULL,
    server_key   BYTEA       NOT NULL,
    public_key   BYTEA       NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    tokens_indexed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX psi_epoch_keys_expires_at_idx
    ON psi_epoch_keys (expires_at);

CREATE TABLE psi_contact_tokens (
    epoch         TEXT          NOT NULL
        REFERENCES psi_epoch_keys (epoch) ON DELETE CASCADE,
    resource_kind resource_kind NOT NULL,
    resource_id   TEXT          NOT NULL,
    token         BYTEA         NOT NULL,
    token_prefix  BYTEA         NOT NULL,
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT now(),
    PRIMARY KEY (epoch, resource_kind, resource_id, token)
);

CREATE INDEX psi_contact_tokens_lookup_idx
    ON psi_contact_tokens (epoch, token_prefix);

CREATE INDEX psi_contact_tokens_resource_idx
    ON psi_contact_tokens (resource_kind, resource_id);

CREATE TABLE psi_batches (
    batch_id             TEXT        PRIMARY KEY,
    credential_key_id    TEXT        NOT NULL,
    key_epoch            BIGINT      NOT NULL CHECK (key_epoch >= 0),
    blind_request_digest BYTEA       NOT NULL,
    element_count        INTEGER     NOT NULL CHECK (element_count BETWEEN 1 AND 256),
    match_request_digest BYTEA,
    match_outcome        JSONB,
    expires_at           TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX psi_batches_expires_at_idx ON psi_batches (expires_at);

CREATE TABLE psi_quota_windows (
    credential_key_id TEXT        NOT NULL,
    quota_bucket      BIGINT      NOT NULL,
    query_count       INTEGER     NOT NULL CHECK (query_count >= 0),
    expires_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (credential_key_id, quota_bucket)
);

CREATE INDEX psi_quota_windows_expires_at_idx ON psi_quota_windows (expires_at);

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
    revoked_by           TEXT        NOT NULL,
    reason               TEXT,
    expires_at           TIMESTAMPTZ
);

CREATE INDEX directory_invite_revocations_target_idx
    ON directory_invite_revocations (target_digest, revoked_at DESC);

-- ---- Operator allowlist --------------------------------------------------

CREATE TABLE accept_allowlist (
    resource_did      TEXT              PRIMARY KEY,
    added_by          TEXT              NOT NULL,
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
    actor             TEXT,
    detail            JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX directory_audit_resource_idx
    ON directory_audit (resource_kind, resource_id, occurred_at DESC);

CREATE INDEX directory_audit_occurred_at_idx
    ON directory_audit (occurred_at DESC);

-- Squashed from 20260520010000_round23.
-- Round R2/R3 (2026-05-20) schema extensions.
--
-- T07 Realm terminal state — `ak.realm.destroy` anchor marker. Resolve /
--      search projections collapse to a tombstone once `realm_destroyed_at`
--      is non-null.
-- T17 Consent revoke scope=any directory reachability invalidation — soft
--      delete via `reachability_revoked_at` (audit-preserving) plus a
--      mirror flag on `directory_resources` so the query face can shed
--      cached projections without losing the underlying row.
-- T14 Federation idempotency cache key extension — `ingest_announces`
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
    ADD COLUMN source_service_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN verification_method TEXT NOT NULL DEFAULT '',
    ADD COLUMN service_binding_ref TEXT NOT NULL DEFAULT '',
    ADD COLUMN origin_key_state_digest BYTEA NOT NULL DEFAULT '\x'::bytea,
    ADD COLUMN historical_only BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX ingest_announces_cache_key_idx
    ON ingest_announces (
        source_service_id,
        verification_method,
        service_binding_ref,
        origin_key_state_digest
    );

-- New audit event kinds — Round R2/R3.
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'consent_revoke_invalidation';
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'realm_destroyed';
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'ingest_historical_only';

-- Squashed from 20260526010000_add_freshness.
-- P2E.5 — freshness columns.
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

-- Squashed from 20260526020000_admin_tokens_and_audit_chain.
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
-- fact. The `authentication_method` column records which credential
-- the actor authenticated with (development static token, rotating HMAC,
-- or service signature); the `asserted_operator` column carries the
-- operator the actor claimed to be (separate from the
-- authenticated_actor identity).
ALTER TABLE directory_audit
    ADD COLUMN IF NOT EXISTS authentication_method TEXT,
    ADD COLUMN IF NOT EXISTS authenticated_actor TEXT,
    ADD COLUMN IF NOT EXISTS asserted_operator TEXT,
    ADD COLUMN IF NOT EXISTS prev_digest BYTEA,
    ADD COLUMN IF NOT EXISTS audit_digest BYTEA;

-- Backfill: existing rows keep `actor` as both `authenticated_actor`
-- and `asserted_operator` until the operator restamps them, and an
-- empty digest is acceptable for pre-chain history. New writes through
-- the audit module compute the chained digest going forward.
UPDATE directory_audit
   SET authenticated_actor = COALESCE(authenticated_actor, actor),
       asserted_operator = COALESCE(asserted_operator, actor)
 WHERE authenticated_actor IS NULL OR asserted_operator IS NULL;

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

-- Squashed from 20260526030000_pending_takedowns.
-- B.8.8 — multi-approval takedown workflow skeleton.
--
-- An operator-initiated takedown can require N approvals before it
-- takes effect. The `pending_takedowns` row tracks the proposal and
-- the `pending_takedown_approvals` rows track each operator's vote.
-- Once `quorum` distinct, non-revoked approvals are recorded, the
-- worker (TODO follow-up) flips the row to executed and runs the
-- usual `operator_takedown` path.
--
-- For this commit we only land the schema and an audit-only skeleton;
-- the executor + webhook fanout will be wired in a follow-up.
CREATE TABLE IF NOT EXISTS pending_takedowns (
    pending_id TEXT PRIMARY KEY,
    resource_kind resource_kind NOT NULL,
    resource_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    proposed_by TEXT NOT NULL,
    proposed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    quorum INT NOT NULL DEFAULT 2 CHECK (quorum >= 1),
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

CREATE TABLE IF NOT EXISTS pending_takedown_approvals (
    pending_id TEXT NOT NULL REFERENCES pending_takedowns(pending_id) ON DELETE CASCADE,
    approver TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    note TEXT,
    PRIMARY KEY (pending_id, approver)
);

-- Webhook subscribers that want to be pinged on every proposal /
-- approval transition. Distinct from the resource-discovery webhook
-- channel (`webhook_subscriptions`) so a takedown reviewer can opt
-- into the approval strand without subscribing to ingest events.
CREATE TABLE IF NOT EXISTS pending_takedown_webhooks (
    webhook_id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    secret BYTEA,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Squashed from 20260526040000_did_normalization_audit.
-- Phase P2 (spec 37ce729 / B-D) — DID format normalization audit.
--
-- The ingest verify-chain now rejects any `resource_id` /
-- `principal_server_did` that does not conform to the tightened DID
-- syntax `^did:[a-z0-9]+:[^\s]+$` (lowercase ASCII method, non-empty
-- whitespace-free method-specific-id). This migration adds a
-- diagnostic CHECK constraint that mirrors the SDK `Did::new` parser
-- so any future direct INSERT into `directory_resources` (e.g. a
-- replay tool, an admin-side data load) also fails closed against
-- malformed DID shapes. The constraint is intentionally a superset of
-- what the application enforces — application-layer validation runs
-- first and is more precise; this is a last-resort DB safety net.
--
-- Round-trip clean: the constraint is enforced immediately. Aggressive-mode
-- policy is fail-closed on both existing rows and new inserts.

ALTER TABLE directory_resources
    ADD CONSTRAINT directory_resources_resource_id_did_shape_chk
        CHECK (
            resource_kind NOT IN ('organization', 'actor', 'applet')
            OR resource_id ~ '^did:[a-z0-9]+:[^[:space:]]+$'
        );

ALTER TABLE directory_resources
    ADD CONSTRAINT directory_resources_principal_server_did_shape_chk
        CHECK (principal_server_did ~ '^did:[a-z0-9]+:[^[:space:]]+$');

-- Mirror on ingest_announces so the announce ledger and the
-- projected table agree on DID shape.
ALTER TABLE ingest_announces
    ADD CONSTRAINT ingest_announces_resource_id_did_shape_chk
        CHECK (
            resource_kind NOT IN ('organization', 'actor', 'applet')
            OR resource_id ~ '^did:[a-z0-9]+:[^[:space:]]+$'
        );

ALTER TABLE ingest_announces
    ADD CONSTRAINT ingest_announces_principal_server_did_shape_chk
        CHECK (principal_server_did ~ '^did:[a-z0-9]+:[^[:space:]]+$');

COMMENT ON CONSTRAINT directory_resources_resource_id_did_shape_chk
    ON directory_resources IS
    'Round 4 (spec 37ce729) DID syntax: ^did:[a-z0-9]+:[^\s]+$. Application layer enforces first.';

COMMENT ON CONSTRAINT directory_resources_principal_server_did_shape_chk
    ON directory_resources IS
    'Round 4 (spec 37ce729) DID syntax: ^did:[a-z0-9]+:[^\s]+$. Application layer enforces first.';

-- Squashed from 20260531010000_http_signature_replays.
CREATE TABLE IF NOT EXISTS http_signature_replays (
    replay_key BYTEA PRIMARY KEY,
    key_id TEXT NOT NULL,
    signature BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS http_signature_replays_expires_at_idx
    ON http_signature_replays (expires_at);

-- Squashed from 20260605010000_member_count_bucket_residency.
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

-- Squashed from 20260625010000_verified_realm_organizations.
-- TBY-ORG-01/02/03 — verified `ak.realm.organization` relationship index.
--
-- The directory MUST NOT treat a bare `organization_did` /
-- `owning_organizations` projection hint as an official organization
-- relationship. An official badge, organization scoping, or
-- directory-certifier relationship is only valid when it derives from an
-- `active`, in-validity-window, scope-covering `ak.realm.organization`
-- statement that passed the SDK verifier
-- (`verify_realm_organization_statement`).
--
-- Each verified statement is keyed by `(realm_id, organization_did,
-- relationship)` — the spec reducer cell subject — so a newer statement for
-- the same triple supersedes (or revokes) the prior one. `statement_issued_at`
-- is the monotonic ordering key used to reject replayed older statements
-- (TBY-ORG-03 replay protection).

CREATE TABLE verified_realm_organizations (
    realm_id            TEXT        NOT NULL,
    organization_did    TEXT        NOT NULL,
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
    -- Realm control frontier digest the organization evaluated, when present.
    -- Used by TBY-ORG-03 staleness detection: when the live Realm frontier has
    -- advanced past this digest the verified relationship is marked stale.
    realm_frontier_digest TEXT,
    -- Whether the relationship is currently considered fresh. A relationship is
    -- marked stale (rather than deleted) when the Realm frontier digest the
    -- organization evaluated has fallen behind, so it stops surfacing as an
    -- effective verified badge without losing the audit trail.
    stale               BOOLEAN     NOT NULL DEFAULT false,
    verified_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_announce_id  TEXT,
    PRIMARY KEY (realm_id, organization_did, relationship)
);

CREATE INDEX verified_realm_organizations_realm_idx
    ON verified_realm_organizations (realm_id)
    WHERE stale = false;

CREATE INDEX verified_realm_organizations_org_idx
    ON verified_realm_organizations (organization_did)
    WHERE stale = false;

CREATE INDEX verified_realm_organizations_expiry_idx
    ON verified_realm_organizations (expires_at)
    WHERE expires_at IS NOT NULL;
