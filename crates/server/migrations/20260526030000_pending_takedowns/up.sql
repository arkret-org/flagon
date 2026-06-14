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
    notification_status TEXT
);

CREATE INDEX IF NOT EXISTS pending_takedowns_status_idx
    ON pending_takedowns (status, expires_at);

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
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ
);
