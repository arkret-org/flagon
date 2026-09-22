-- Squashed fresh-install schema for the read-only Realm Directory.
-- The public index starts empty. There is no current write-admission path:
-- legacy source-ref rows must never be imported into this table.

CREATE TYPE resource_kind AS ENUM ('realm');

-- Operator audit is operational history, not a public discovery index.
-- Retain the event vocabulary so historical audit rows remain readable.
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
    'consent_revoke_invalidation',
    'realm_destroyed',
    'ingest_historical_only'
);

CREATE TABLE directory_public_realm_entries (
    realm_id TEXT PRIMARY KEY,
    public_metadata JSONB NOT NULL,
    indexed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT directory_public_realm_metadata_object
        CHECK (jsonb_typeof(public_metadata) = 'object'),
    CONSTRAINT directory_public_realm_expiry_after_index
        CHECK (expires_at > indexed_at)
);

CREATE TABLE admin_tokens (
    key_id TEXT PRIMARY KEY,
    secret BYTEA NOT NULL,
    label TEXT,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX admin_tokens_active_idx
    ON admin_tokens (key_id)
    WHERE revoked_at IS NULL;

CREATE TABLE directory_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind audit_event_kind NOT NULL,
    resource_kind resource_kind,
    resource_id TEXT,
    actor_id TEXT,
    authenticated_credential_id TEXT,
    asserted_operator_localpart TEXT,
    authentication_method TEXT,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_digest BYTEA,
    audit_digest BYTEA
);

CREATE INDEX directory_audit_resource_idx
    ON directory_audit (resource_kind, resource_id, occurred_at DESC);
CREATE INDEX directory_audit_occurred_at_idx
    ON directory_audit (occurred_at DESC);

CREATE FUNCTION directory_audit_block_update()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'directory_audit is append-only; UPDATE forbidden by chained digest invariant';
END;
$$;

CREATE TRIGGER directory_audit_block_update
    BEFORE UPDATE ON directory_audit
    FOR EACH ROW
    EXECUTE FUNCTION directory_audit_block_update();
