-- No-op on fresh installs: the dedicated `realm` directory resource kind
-- now ships directly in the bootstrap `resource_kind` enum
-- (20260512010000_schema). The pre-inversion `space` enum value has been
-- removed entirely — teabay no longer indexes container Spaces, so there is
-- nothing to add or rename here.
SELECT 1;
