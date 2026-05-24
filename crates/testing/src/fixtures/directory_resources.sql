INSERT INTO directory_resources (
    resource_kind,
    resource_id,
    principal_server_did,
    discovery_state,
    public_projection,
    discoverability,
    as_of,
    source_refs,
    policy_revision,
    indexed_at,
    effective_ttl_seconds,
    next_revalidation_after,
    stale,
    divergent,
    via_services,
    last_announce_id
) VALUES
(
    'realm'::resource_kind,
    'cx:space:tea',
    'did:web:principal.test',
    -- Round 4 (spec a77b995): the §3 discovery event kind for the
    -- Realm/Space security boundary is `cx.realm.discovery`. The
    -- legacy `cx.space.discovery` was a pre-realm-rework residue and
    -- is wire-broken under aggressive mode.
    '{"kind":"cx.realm.discovery","discoverability":"public"}'::jsonb,
    -- Spec sync 0a5ab85 / governance/join-policy §5.1.3 (post realm-rework):
    -- Realms publish `delivery_binding_policy.allowed_recipient_services` and
    -- (when narrowing) `allow_binding_sources`. `trusted_audiences` is the
    -- audience-binding allow-list `resolve_handle(intent=member_add)` consults.
    -- The `cx:space:tea` resource_id is retained for cross-service fixture
    -- compatibility; resource_kind now records the security boundary as a
    -- Realm directly.
    '{"name":"Tea Research","summary":"Public teabay conformance space","member_count_bucket":"1-10","delivery_binding_policy":{"allowed_recipient_services":["did:web:principal.test"],"allow_binding_sources":["join_policy","invite","organization_policy"],"trusted_audiences":["did:web:tea-org.example"]}}'::jsonb,
    'public'::discoverability,
    now(),
    ARRAY['evt-space-tea'],
    'rev-space-1',
    now(),
    86400,
    now() + interval '1 day',
    false,
    false,
    ARRAY['did:web:principal.test'],
    'cx:announce:test-space'
),
(
    'realm'::resource_kind,
    'cx:space:tea-lab',
    'did:web:principal.test',
    '{"kind":"cx.realm.discovery","discoverability":"listed"}'::jsonb,
    '{"name":"Tea Protocol Lab","summary":"Second public conformance space","member_count_bucket":"11-50"}'::jsonb,
    'listed'::discoverability,
    now() - interval '1 minute',
    ARRAY['evt-space-tea-lab'],
    'rev-space-2',
    now() - interval '1 minute',
    86400,
    now() + interval '1 day',
    false,
    false,
    ARRAY['did:web:principal.test'],
    'cx:announce:test-space-lab'
),
(
    'realm'::resource_kind,
    'cx:space:restricted',
    'did:web:principal.test',
    '{"kind":"cx.realm.discovery","discoverability":"restricted"}'::jsonb,
    '{"name":"Restricted Tea","summary":"Gated conformance space","allowed_discoverers":[{"requester":"did:web:alice.example"}]}'::jsonb,
    'restricted'::discoverability,
    now(),
    ARRAY['evt-space-restricted'],
    'rev-space-restricted',
    now(),
    86400,
    now() + interval '1 day',
    false,
    false,
    ARRAY['did:web:principal.test'],
    'cx:announce:test-space-restricted'
),
(
    'realm'::resource_kind,
    'cx:space:secret',
    'did:web:principal.test',
    '{"kind":"cx.realm.discovery","discoverability":"secret"}'::jsonb,
    '{"name":"Secret Tea","summary":"Must collapse to not_found"}'::jsonb,
    'secret'::discoverability,
    now(),
    ARRAY['evt-space-secret'],
    'rev-space-secret',
    now(),
    86400,
    now() + interval '1 day',
    false,
    false,
    ARRAY['did:web:principal.test'],
    'cx:announce:test-space-secret'
),
(
    'organization'::resource_kind,
    'did:web:tea-org.example',
    'did:web:principal.test',
    '{"kind":"cx.organization.discovery","discoverability":"public"}'::jsonb,
    '{"name":"Tea Org","handle":"tea-org","summary":"Organization conformance fixture"}'::jsonb,
    'public'::discoverability,
    now(),
    ARRAY['evt-org-tea'],
    'rev-org-1',
    now(),
    86400,
    now() + interval '1 day',
    false,
    false,
    ARRAY['did:web:principal.test'],
    'cx:announce:test-org'
),
(
    'actor'::resource_kind,
    'did:web:alice.example',
    'did:web:principal.test',
    '{"kind":"cx.actor.discovery","discoverability":"public"}'::jsonb,
    '{"handle":"alice.example","display_name":"Alice Tea","space_ids":["cx:space:tea"],"organization_did":"did:web:tea-org.example"}'::jsonb,
    'public'::discoverability,
    now(),
    ARRAY['evt-actor-alice'],
    'rev-actor-1',
    now(),
    86400,
    now() + interval '1 day',
    false,
    false,
    ARRAY['did:web:principal.test'],
    'cx:announce:test-actor'
),
(
    'handle'::resource_kind,
    'alice.example',
    'did:web:principal.test',
    '{"kind":"cx.handle.discovery","discoverability":"public"}'::jsonb,
    -- Spec sync 0a5ab85 / handle-claim.schema.json §3.7: a verified handle
    -- carries `member_delivery_binding.recipient_service_did` + binding_source
    -- so `resolve_handle(intent=member_add)` can run the Space policy filter.
    '{"handle":"alice.example","did":"did:web:alice.example","verified":true,"member_delivery_binding":{"recipient_service_did":"did:web:principal.test","binding_source":"join_policy"}}'::jsonb,
    'public'::discoverability,
    now(),
    ARRAY['evt-handle-alice'],
    'rev-handle-1',
    now(),
    86400,
    now() + interval '1 day',
    false,
    false,
    ARRAY['did:web:principal.test'],
    'cx:announce:test-handle'
);
