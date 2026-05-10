DROP INDEX IF EXISTS directory_resources_space_scope_parent_idx;
DROP INDEX IF EXISTS directory_resources_space_scope_org_idx;
DROP INDEX IF EXISTS directory_resources_search_vector_gin_idx;
DROP INDEX IF EXISTS directory_resources_search_text_trgm_idx;

ALTER TABLE directory_resources
    DROP COLUMN IF EXISTS search_vector,
    DROP COLUMN IF EXISTS search_text;

DROP FUNCTION IF EXISTS directory_resource_search_text(jsonb);
