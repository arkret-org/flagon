-- Move pre-realm-rework security-boundary rows onto the dedicated `realm`
-- enum value, then add Realm-specific lookup indexes. At this point the
-- `realm` enum value was committed by the preceding migration.

UPDATE directory_resources
SET resource_kind = 'realm'
WHERE resource_kind = 'space';

UPDATE ingest_announces
SET resource_kind = 'realm'
WHERE resource_kind = 'space';

UPDATE withdrawals
SET resource_kind = 'realm'
WHERE resource_kind = 'space';

UPDATE pull_subscriptions
SET resource_kind = 'realm'
WHERE resource_kind = 'space';

UPDATE directory_audit
SET resource_kind = 'realm'
WHERE resource_kind = 'space';

CREATE INDEX IF NOT EXISTS directory_resources_realm_scope_org_idx
    ON directory_resources ((public_projection->>'organization_did'))
    WHERE resource_kind = 'realm';

CREATE INDEX IF NOT EXISTS directory_resources_realm_scope_parent_idx
    ON directory_resources ((public_projection->>'parent_space_id'))
    WHERE resource_kind = 'realm';
