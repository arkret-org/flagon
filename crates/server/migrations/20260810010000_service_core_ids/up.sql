-- Service routing/business identifiers are stable core ids. Retain already
-- canonical core ids, adapter-project active full DID methods, and discard
-- legacy URL/unknown values rather than treating them as network authority.
UPDATE directory_resources AS resource
SET via_services = COALESCE(
    (
        SELECT array_agg(projected.service_id ORDER BY projected.ordinality)
        FROM (
            SELECT
                service.ordinality,
                CASE
                    WHEN service.value ~ '^ak:did_core:webvh:[^[:space:]/?#:]+$'
                        THEN service.value
                    WHEN service.value ~ '^ak:did_core:(web|key):[^[:space:]/?#]+$'
                        THEN service.value
                    WHEN service.value ~ '^did:webvh:[^[:space:]/?#:]+:[^[:space:]?#]+$'
                        THEN 'ak:did_core:webvh:' || split_part(
                            substring(service.value FROM length('did:webvh:') + 1),
                            ':',
                            1
                        )
                    WHEN service.value ~ '^did:web:[^[:space:]/?#]+$'
                        THEN 'ak:did_core:web:' || substring(
                            service.value FROM length('did:web:') + 1
                        )
                    WHEN service.value ~ '^did:key:[^[:space:]/?#]+$'
                        THEN 'ak:did_core:key:' || substring(
                            service.value FROM length('did:key:') + 1
                        )
                    ELSE NULL
                END AS service_id
            FROM unnest(resource.via_services) WITH ORDINALITY AS service(value, ordinality)
        ) AS projected
        WHERE projected.service_id IS NOT NULL
    ),
    ARRAY[]::TEXT[]
);
