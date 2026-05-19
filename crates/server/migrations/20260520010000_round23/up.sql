-- Round R2/R3 (2026-05-20) schema extensions.
--
-- T07 Realm terminal state — `cx.realm.destroy` anchor marker. Resolve /
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
    ADD COLUMN source_service_did TEXT NOT NULL DEFAULT '',
    ADD COLUMN verification_method TEXT NOT NULL DEFAULT '',
    ADD COLUMN service_binding_ref TEXT NOT NULL DEFAULT '',
    ADD COLUMN origin_key_state_hash BYTEA NOT NULL DEFAULT '\x'::bytea,
    ADD COLUMN historical_only BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX ingest_announces_cache_key_idx
    ON ingest_announces (
        source_service_did,
        verification_method,
        service_binding_ref,
        origin_key_state_hash
    );

-- New audit event kinds — Round R2/R3.
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'consent_revoke_invalidation';
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'realm_destroyed';
ALTER TYPE audit_event_kind ADD VALUE IF NOT EXISTS 'ingest_historical_only';
