-- Keep the `realm` enum value available, but roll Realm rows back to the
-- prior `space` representation for rollback and remove Realm-specific
-- indexes.

DROP INDEX IF EXISTS directory_resources_realm_scope_parent_idx;
DROP INDEX IF EXISTS directory_resources_realm_scope_org_idx;

UPDATE directory_audit
SET resource_kind = 'space',
    resource_id = regexp_replace(resource_id, '^cx:realm:', 'cx:space:')
WHERE resource_kind = 'realm';

UPDATE pull_subscriptions
SET resource_kind = 'space',
    resource_id = regexp_replace(resource_id, '^cx:realm:', 'cx:space:')
WHERE resource_kind = 'realm';

UPDATE withdrawals
SET resource_kind = 'space',
    resource_id = regexp_replace(resource_id, '^cx:realm:', 'cx:space:')
WHERE resource_kind = 'realm';

UPDATE ingest_announces
SET resource_kind = 'space',
    resource_id = regexp_replace(resource_id, '^cx:realm:', 'cx:space:')
WHERE resource_kind = 'realm';

UPDATE directory_resources
SET resource_kind = 'space',
    resource_id = regexp_replace(resource_id, '^cx:realm:', 'cx:space:')
WHERE resource_kind = 'realm';

UPDATE directory_resources
SET discovery_state = replace(discovery_state::text, 'cx:realm:', 'cx:space:')::jsonb,
    public_projection = replace(public_projection::text, 'cx:realm:', 'cx:space:')::jsonb
WHERE discovery_state::text LIKE '%cx:realm:%'
   OR public_projection::text LIKE '%cx:realm:%';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'realm_id', '{space_id}', public_projection->'realm_id')
WHERE public_projection ? 'realm_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'realm_ids', '{space_ids}', public_projection->'realm_ids')
WHERE public_projection ? 'realm_ids';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'common_realm_id', '{common_space_id}', public_projection->'common_realm_id')
WHERE public_projection ? 'common_realm_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'common_realm_ids', '{common_space_ids}', public_projection->'common_realm_ids')
WHERE public_projection ? 'common_realm_ids';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'primary_realm_id', '{primary_space_id}', public_projection->'primary_realm_id')
WHERE public_projection ? 'primary_realm_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'member_of_realms', '{member_of_spaces}', public_projection->'member_of_realms')
WHERE public_projection ? 'member_of_realms';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'realms', '{spaces}', public_projection->'realms')
WHERE public_projection ? 'realms';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'parent_realm_id', '{parent_space_id}', public_projection->'parent_realm_id')
WHERE public_projection ? 'parent_realm_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'parent_realm_ids', '{parent_space_ids}', public_projection->'parent_realm_ids')
WHERE public_projection ? 'parent_realm_ids';
