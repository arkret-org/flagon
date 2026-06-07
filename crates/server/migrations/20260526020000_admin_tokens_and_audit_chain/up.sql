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
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS admin_tokens_active_idx
    ON admin_tokens (key_id)
    WHERE revoked_at IS NULL;

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
