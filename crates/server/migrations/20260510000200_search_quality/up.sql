CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE OR REPLACE FUNCTION directory_resource_search_text(projection jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT btrim(
        coalesce(projection->>'name', '') || ' ' ||
        coalesce(projection->>'summary', '') || ' ' ||
        coalesce(projection->>'alias', '') || ' ' ||
        coalesce(projection->>'handle', '')
    )
$$;

ALTER TABLE directory_resources
    ADD COLUMN search_text TEXT GENERATED ALWAYS AS (
        directory_resource_search_text(public_projection)
    ) STORED,
    ADD COLUMN search_vector tsvector GENERATED ALWAYS AS (
        to_tsvector(
            'simple',
            directory_resource_search_text(public_projection)
        )
    ) STORED;

CREATE INDEX directory_resources_search_text_trgm_idx
    ON directory_resources USING GIN (search_text gin_trgm_ops);

CREATE INDEX directory_resources_search_vector_gin_idx
    ON directory_resources USING GIN (search_vector);

CREATE INDEX directory_resources_space_scope_org_idx
    ON directory_resources ((public_projection->>'organization_did'))
    WHERE resource_kind = 'space';

CREATE INDEX directory_resources_space_scope_parent_idx
    ON directory_resources ((public_projection->>'parent_space_id'))
    WHERE resource_kind = 'space';
