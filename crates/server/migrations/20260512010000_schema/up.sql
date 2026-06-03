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

CREATE TYPE ingest_mode AS ENUM ('push', 'pull');

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
    'admin_resource_deleted'
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
    policy_revision   TEXT,
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
    notified_at       TIMESTAMPTZ
);

CREATE INDEX withdrawals_resource_idx
    ON withdrawals (resource_kind, resource_id, effective_at DESC);

-- ---- Pull-mode and webhook subscriptions --------------------------------

CREATE TABLE pull_subscriptions (
    resource_kind     resource_kind     NOT NULL,
    resource_id       TEXT              NOT NULL,
    principal_server_did TEXT           NOT NULL,
    last_revision     TEXT,
    last_pulled_at    TIMESTAMPTZ,
    next_pull_after   TIMESTAMPTZ       NOT NULL DEFAULT now(),
    consecutive_failures INTEGER        NOT NULL DEFAULT 0,
    last_error        TEXT,
    PRIMARY KEY (resource_kind, resource_id)
);

CREATE INDEX pull_subscriptions_next_pull_idx
    ON pull_subscriptions (next_pull_after);

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
    epoch      TEXT        PRIMARY KEY,
    profile    TEXT        NOT NULL,
    server_key BYTEA       NOT NULL,
    public_key BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX psi_epoch_keys_expires_at_idx
    ON psi_epoch_keys (expires_at);

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
