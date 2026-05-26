-- Phase P2 (spec 37ce729 / B-D) — DID format normalization audit.
--
-- The ingest verify-chain now rejects any `resource_id` /
-- `principal_server_did` that does not conform to the tightened DID
-- syntax `^did:[a-z0-9]+:[^\s]+$` (lowercase ASCII method, non-empty
-- whitespace-free method-specific-id). This migration adds a
-- diagnostic CHECK constraint that mirrors the SDK `Did::new` parser
-- so any future direct INSERT into `directory_resources` (e.g. a
-- replay tool, an admin-side data load) also fails closed against
-- legacy DID shapes. The constraint is intentionally a superset of
-- what the application enforces — application-layer validation runs
-- first and is more precise; this is a last-resort DB safety net.
--
-- Round-trip clean: the constraint is NOT VALID'd against historical
-- rows on purpose. Aggressive-mode policy is "fail-closed on new
-- inserts"; operators clean up legacy rows via the existing audit
-- chain and admin tooling.

ALTER TABLE directory_resources
    ADD CONSTRAINT directory_resources_resource_id_did_shape_chk
        CHECK (
            resource_kind NOT IN ('organization', 'actor', 'applet')
            OR resource_id ~ '^did:[a-z0-9]+:[^[:space:]]+$'
        ) NOT VALID;

ALTER TABLE directory_resources
    ADD CONSTRAINT directory_resources_principal_server_did_shape_chk
        CHECK (principal_server_did ~ '^did:[a-z0-9]+:[^[:space:]]+$')
        NOT VALID;

-- Mirror on ingest_announces so the announce ledger and the
-- projected table agree on DID shape.
ALTER TABLE ingest_announces
    ADD CONSTRAINT ingest_announces_resource_id_did_shape_chk
        CHECK (
            resource_kind NOT IN ('organization', 'actor', 'applet')
            OR resource_id ~ '^did:[a-z0-9]+:[^[:space:]]+$'
        ) NOT VALID;

ALTER TABLE ingest_announces
    ADD CONSTRAINT ingest_announces_principal_server_did_shape_chk
        CHECK (principal_server_did ~ '^did:[a-z0-9]+:[^[:space:]]+$')
        NOT VALID;

COMMENT ON CONSTRAINT directory_resources_resource_id_did_shape_chk
    ON directory_resources IS
    'Round 4 (spec 37ce729) DID syntax: ^did:[a-z0-9]+:[^\s]+$. Application layer enforces first.';

COMMENT ON CONSTRAINT directory_resources_principal_server_did_shape_chk
    ON directory_resources IS
    'Round 4 (spec 37ce729) DID syntax: ^did:[a-z0-9]+:[^\s]+$. Application layer enforces first.';
