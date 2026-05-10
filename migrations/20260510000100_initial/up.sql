-- chadex initial schema (spec discovery-directory.md §7-§9 / §11).
--
-- Storage model:
--   * `directory_resources` is the *current effective entry* per resource —
--     one row per (resource_kind, resource_id). Updated on each accepted
--     announce or pull-refresh.
--   * `ingest_announces` is the audit log of every accepted announce
--     (idempotent on (resource_id, as_of) per §8.6).
--   * `withdrawals` records resource-initiated withdraws (§8.7 path 2)
--     and operator takedowns (§8.7 path 3); a withdrawal blocks future
--     announces with `as_of <= effective_at` (§8.10 撤销规避).
--   * `pull_subscriptions` and `webhook_subscriptions` track pull-mode and
--     subscriber-side webhook fanout state.
--   * `directory_audit` is the operator-readable append-only audit log
--     (§7.3 inv. 5 + §8.7 takedown).

-- ---- Enums ---------------------------------------------------------------

CREATE TYPE resource_kind AS ENUM (
    'space',
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
    'allowlist_removed'
);

-- ---- Effective entries ---------------------------------------------------

CREATE TABLE directory_resources (
    resource_kind     resource_kind     NOT NULL,
    -- For Space: cx:space:...; for Organization/Actor/Applet: DID; for Handle:
    -- canonical handle string. Stored as text for cross-kind uniformity.
    resource_id       TEXT              NOT NULL,
    -- Truth-source Principal Server service DID — populated from announce
    -- (`principal_server_did`) or from the DID document during pull-mode.
    principal_server_did TEXT           NOT NULL,
    -- Snapshot of the signed `cx.{kind}.discovery` payload (byte-for-byte as
    -- supplied by the resource — including its `proof`). Stored as JSON so
    -- searches can index public-projection fields, but the canonical form is
    -- the original signed bytes; clients verify via `source_refs`.
    discovery_state   JSONB             NOT NULL,
    -- Strict subset of the public projection (extracted for search index +
    -- result envelope): name, summary, avatar, discoverability, join_rule,
    -- history_visibility, member_count_bucket, official_organizations[],
    -- profile_visibility, etc. Schema-on-read.
    public_projection JSONB             NOT NULL,
    discoverability   discoverability   NOT NULL,
    -- §9.1 result envelope inputs — canonical, not derived per query.
    as_of             TIMESTAMPTZ       NOT NULL,
    source_refs       TEXT[]            NOT NULL,
    policy_revision   TEXT,
    -- TTL bookkeeping (§8.6).
    indexed_at        TIMESTAMPTZ       NOT NULL DEFAULT now(),
    effective_ttl_seconds INTEGER       NOT NULL,
    next_revalidation_after TIMESTAMPTZ NOT NULL,
    stale             BOOLEAN           NOT NULL DEFAULT false,
    -- Set true when a parallel directory views the same resource at a
    -- materially different `policy_revision`; populated by the optional cross-
    -- check worker (§9.1 `divergent`). Default false.
    divergent         BOOLEAN           NOT NULL DEFAULT false,
    -- Fanout / join hint — populated from DID document service entry resolution.
    via_services      TEXT[]            NOT NULL DEFAULT '{}',
    -- Latest ingest record id (for audit chaining).
    last_announce_id  TEXT,
    PRIMARY KEY (resource_kind, resource_id)
);

CREATE INDEX directory_resources_discoverability_idx
    ON directory_resources (discoverability);

CREATE INDEX directory_resources_indexed_at_idx
    ON directory_resources (indexed_at DESC);

CREATE INDEX directory_resources_next_revalidation_idx
    ON directory_resources (next_revalidation_after)
    WHERE stale = false;

-- Public-projection text search over name/summary. Hardened indexing
-- (trigram / language-specific) is a follow-up task — see _todos.md M4.
CREATE INDEX directory_resources_public_projection_gin
    ON directory_resources USING GIN (public_projection jsonb_path_ops);

-- ---- Ingest audit (every accepted announce, push *and* pull) ------------

CREATE TABLE ingest_announces (
    announce_id       TEXT              PRIMARY KEY, -- cx:announce:<ULID>
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
    -- Hash of the canonical announce request body for replay detection.
    request_digest    BYTEA             NOT NULL,
    UNIQUE (resource_kind, resource_id, as_of)
);

CREATE INDEX ingest_announces_resource_idx
    ON ingest_announces (resource_kind, resource_id, as_of DESC);

CREATE INDEX ingest_announces_request_digest_idx
    ON ingest_announces (request_digest);

-- ---- Withdrawals (resource-initiated and operator takedowns) ------------

CREATE TABLE withdrawals (
    withdraw_id       TEXT              PRIMARY KEY, -- cx:withdraw:<ULID>
    resource_kind     resource_kind     NOT NULL,
    resource_id       TEXT              NOT NULL,
    kind              withdrawal_kind   NOT NULL,
    reason            TEXT              NOT NULL,
    -- For resource_withdraw: governance proof envelope; for operator_takedown:
    -- operator identity + supporting evidence.
    proof             JSONB             NOT NULL,
    effective_at      TIMESTAMPTZ       NOT NULL,
    acked_at          TIMESTAMPTZ       NOT NULL DEFAULT now(),
    -- Operator identity for takedowns (NULL for resource-initiated paths).
    operator          TEXT,
    -- Whether the resource governance contact has been notified.
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
    -- Last error message for operator triage. Free text.
    last_error        TEXT,
    PRIMARY KEY (resource_kind, resource_id)
);

CREATE INDEX pull_subscriptions_next_pull_idx
    ON pull_subscriptions (next_pull_after);

CREATE TABLE webhook_subscriptions (
    subscription_id   TEXT              PRIMARY KEY, -- cx:subscription:<ULID>
    subscriber_did    TEXT              NOT NULL,
    resource_filter   JSONB             NOT NULL,
    webhook_endpoint  TEXT              NOT NULL,
    secret            BYTEA,
    expires_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ       NOT NULL DEFAULT now()
);

CREATE INDEX webhook_subscriptions_subscriber_idx
    ON webhook_subscriptions (subscriber_did);

-- ---- Operator allowlist (only consulted when accept_policy_kind=allowlist) -

CREATE TABLE accept_allowlist (
    resource_did      TEXT              PRIMARY KEY,
    added_by          TEXT              NOT NULL,
    added_at          TIMESTAMPTZ       NOT NULL DEFAULT now(),
    note              TEXT
);

-- ---- Audit log (operator-readable, append-only) -------------------------

CREATE TABLE directory_audit (
    audit_id          BIGSERIAL         PRIMARY KEY,
    occurred_at       TIMESTAMPTZ       NOT NULL DEFAULT now(),
    kind              audit_event_kind  NOT NULL,
    resource_kind     resource_kind,
    resource_id       TEXT,
    actor             TEXT, -- service DID / operator DID for the trigger
    detail            JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX directory_audit_resource_idx
    ON directory_audit (resource_kind, resource_id, occurred_at DESC);

CREATE INDEX directory_audit_occurred_at_idx
    ON directory_audit (occurred_at DESC);
