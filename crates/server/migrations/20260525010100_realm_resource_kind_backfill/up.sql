-- Move security-boundary rows onto the dedicated `realm` enum value,
-- normalize Realm URI prefixes / projection keys, then add Realm-specific
-- lookup indexes. At this point the `realm` enum value was committed by
-- the preceding migration.

UPDATE directory_resources
SET resource_kind = 'realm',
    resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'space';

UPDATE directory_resources
SET resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'realm'
  AND resource_id LIKE 'cx:space:%';

UPDATE ingest_announces
SET resource_kind = 'realm',
    resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'space';

UPDATE ingest_announces
SET resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'realm'
  AND resource_id LIKE 'cx:space:%';

UPDATE withdrawals
SET resource_kind = 'realm',
    resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'space';

UPDATE withdrawals
SET resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'realm'
  AND resource_id LIKE 'cx:space:%';

UPDATE pull_subscriptions
SET resource_kind = 'realm',
    resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'space';

UPDATE pull_subscriptions
SET resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'realm'
  AND resource_id LIKE 'cx:space:%';

UPDATE directory_audit
SET resource_kind = 'realm',
    resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'space';

UPDATE directory_audit
SET resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'realm'
  AND resource_id LIKE 'cx:space:%';

UPDATE directory_resources
SET discovery_state = replace(discovery_state::text, 'cx:space:', 'cx:realm:')::jsonb,
    public_projection = replace(public_projection::text, 'cx:space:', 'cx:realm:')::jsonb
WHERE discovery_state::text LIKE '%cx:space:%'
   OR public_projection::text LIKE '%cx:space:%';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'space_id', '{realm_id}', public_projection->'space_id')
WHERE public_projection ? 'space_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'space_ids', '{realm_ids}', public_projection->'space_ids')
WHERE public_projection ? 'space_ids';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'common_space_id', '{common_realm_id}', public_projection->'common_space_id')
WHERE public_projection ? 'common_space_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'common_space_ids', '{common_realm_ids}', public_projection->'common_space_ids')
WHERE public_projection ? 'common_space_ids';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'primary_space_id', '{primary_realm_id}', public_projection->'primary_space_id')
WHERE public_projection ? 'primary_space_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'member_of_spaces', '{member_of_realms}', public_projection->'member_of_spaces')
WHERE public_projection ? 'member_of_spaces';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'spaces', '{realms}', public_projection->'spaces')
WHERE public_projection ? 'spaces';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'parent_space_id', '{parent_realm_id}', public_projection->'parent_space_id')
WHERE public_projection ? 'parent_space_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'parent_space_ids', '{parent_realm_ids}', public_projection->'parent_space_ids')
WHERE public_projection ? 'parent_space_ids';

CREATE INDEX IF NOT EXISTS directory_resources_realm_scope_org_idx
    ON directory_resources ((public_projection->>'organization_did'))
    WHERE resource_kind = 'realm';

CREATE INDEX IF NOT EXISTS directory_resources_realm_scope_parent_idx
    ON directory_resources ((public_projection->>'parent_realm_id'))
    WHERE resource_kind = 'realm';
