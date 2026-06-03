-- No-op. The pre-inversion `space` resource kind has been removed from
-- teabay entirely; there is no `space` enum value to roll back to. The
-- Realm-scope indexes are owned by the bootstrap schema's down migration.
SELECT 1;
