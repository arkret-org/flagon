-- No-op on fresh installs. This migration historically rewrote pre-inversion
-- `space` rows/URIs/projection keys into their `realm` equivalents. The
-- `space` enum value and all container-Space indexing have since been removed
-- from teabay, and fresh databases never carry `space` rows, so there is
-- nothing to backfill. The Realm-scope lookup indexes
-- (`directory_resources_realm_scope_org_idx` /
-- `directory_resources_realm_scope_parent_idx`) ship in the bootstrap schema.
SELECT 1;
