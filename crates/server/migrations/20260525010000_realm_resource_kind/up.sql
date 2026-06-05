-- No-op on fresh installs: the dedicated `realm` directory resource kind
-- now ships directly in the bootstrap `resource_kind` enum
-- (20260512010000_schema). Teabay indexes Realm directory resources, not
-- Space containers, so there is nothing to add here.
SELECT 1;
