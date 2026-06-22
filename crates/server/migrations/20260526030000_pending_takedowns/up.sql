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
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ
);

-- Directory operator takedown appeal / recovery loop.
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'takedown_appeal_submitted';
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'takedown_appeal_decided';

ALTER TABLE withdrawals
    ADD COLUMN IF NOT EXISTS overturned_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS overturn_appeal_id TEXT,
    ADD COLUMN IF NOT EXISTS overturn_receipt JSONB;

CREATE TABLE IF NOT EXISTS takedown_appeals (
    appeal_id TEXT PRIMARY KEY,
    takedown_id TEXT NOT NULL REFERENCES withdrawals(withdraw_id) ON DELETE CASCADE,
    resource_kind resource_kind NOT NULL,
    resource_id TEXT NOT NULL,
    appellant_did TEXT NOT NULL,
    requested_outcome TEXT NOT NULL,
    argument TEXT NOT NULL,
    evidence_digest TEXT NOT NULL,
    appeal_packet JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    decided_by TEXT,
    decision TEXT,
    decision_reason TEXT,
    decision_receipt JSONB,
    CHECK (status IN ('pending', 'upheld', 'overturned')),
    CHECK (decision IS NULL OR decision IN ('upheld', 'overturned'))
);

CREATE INDEX IF NOT EXISTS takedown_appeals_takedown_idx
    ON takedown_appeals (takedown_id, accepted_at DESC);

CREATE INDEX IF NOT EXISTS takedown_appeals_status_idx
    ON takedown_appeals (status, accepted_at DESC);

CREATE INDEX IF NOT EXISTS withdrawals_active_takedown_idx
    ON withdrawals (resource_kind, resource_id, effective_at DESC)
    WHERE overturned_at IS NULL;
