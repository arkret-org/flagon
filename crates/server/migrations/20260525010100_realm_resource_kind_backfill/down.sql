-- Keep the `realm` enum value available, but roll Realm rows back to the
-- legacy `space` value for older code and remove the Realm-specific indexes.

DROP INDEX IF EXISTS directory_resources_realm_scope_parent_idx;
DROP INDEX IF EXISTS directory_resources_realm_scope_org_idx;

UPDATE directory_audit
SET resource_kind = 'space'
WHERE resource_kind = 'realm';

UPDATE pull_subscriptions
SET resource_kind = 'space'
WHERE resource_kind = 'realm';

UPDATE withdrawals
SET resource_kind = 'space'
WHERE resource_kind = 'realm';

UPDATE ingest_announces
SET resource_kind = 'space'
WHERE resource_kind = 'realm';

UPDATE directory_resources
SET resource_kind = 'space'
WHERE resource_kind = 'realm';
