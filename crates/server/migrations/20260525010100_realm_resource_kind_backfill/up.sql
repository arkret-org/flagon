-- No-op on fresh installs. Teabay indexes Realm directory resources only; it
-- does not index Space containers as directory resources. The Realm-scope lookup indexes
-- (`directory_resources_realm_scope_org_idx` /
-- `directory_resources_realm_scope_parent_idx`) ship in the bootstrap schema.
SELECT 1;
