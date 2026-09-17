# Authority-Commit Capability Migration

teabay is the public Directory service: push-mode ingest (`announce` /
`withdraw`), the anti-enumeration query face (`search-*` / `resolve-*` /
`list-handles-for-subject` / `private-contact-discovery`), Private Contact
Discovery, the operator/admin API, the Dioxus admin console, and four background
workers.

teabay authors no Realm Event. It *consumes* authority-committed references: a
Directory row's truth source is a closed set of `CommittedEventRef`s, and
accepting one for the first time requires verifying the `RealmCommit` that
carries it. This file records, per product entry point, where the capability
lives now and which test covers it. Empty implementations, unverified seams and
untested routes are named as such.

Three findings were load-bearing for acceptance when this file was first
written; all three are now closed, and each is kept below with what it was and
what closed it, because a ledger that deletes its own findings cannot be
audited:

1. the ingest verify chain's `RealmCommit` authority step had no shipped
   implementation ("Authority seam" below) — **closed**: the production
   verifier is `ingest/authority_chain.rs:RealmAuthorityChainVerifier`;
2. `search-realms` / `resolve-realm` returned HTTP 500 for projections the
   ingest face accepts ("Realm preview" below) — **closed**: the Realm preview
   is assembled field by field and ingest validates against it;
3. the Docker-backed suite reported seven skipped tests as passed
   ("Docker reporting" below) — **closed**: those tests are `#[ignore]`, so a
   default run reports them as ignored and CI fails if any is.

## Protocol invariants every row is measured against

- [x] teabay produces no Event. Nothing it builds carries a predecessor,
  ordering, basis, frontier, Seal or Cell field.
- [x] A Directory source reference is the closed tuple, not a bare id:
  `CommittedEventRef { event_id, commit_id, stream_ref, stream_position }`.
  `crates/server/src/source_refs.rs:CommittedEventRefs` is a typed JSONB newtype
  whose whole purpose is that a row cannot silently degrade back to
  `Vec<String>` of Event ids.
- [x] `CommitStreamRef` is the closed enum `Realm` / `Circle` / `Sidecar`. teabay
  stores whatever stream a ref names and never compares positions across two
  streams, and it never builds a Realm-global chain or a global position.
- [x] Acceptance authority comes from the `RealmCommit` signed by the Realm's
  *current governance Station*, verified back through the genesis-to-current
  handoff chain. Exact DTO equality (`CommittedEventRef::matches`) and an
  authenticated HTTP transport are explicitly **not** substitutes — the trait
  doc says so and `ingest/authority_chain.rs:RealmAuthorityChainVerifier`
  enforces it by fetching a nonce-bound `RealmAuthorityBundle` from the source
  Station's open face and handing it to
  `arkret_identity::verify_realm_authority_bundle`. See "Authority seam" below.
- [x] `policy_revision` is SHA-256 over the canonical closed source-ref tuples,
  not over Event ids alone (`ingest/verify.rs:VerifyContext::verify`), so a ref
  set that differs only in commit or stream coordinate is a different revision.
- [x] The organization control scope is spelled as the registry spells it:
  `realm_authority` (`RealmOrganizationControlScope::RealmAuthority`). The old
  `notary_control` spelling exists nowhere in the specification, so a verified
  statement carrying it was indexed under a name no query could ask for.
- [x] No Seal / Cell / CBS / ControlProposal / frontier / `actor_seq` /
  `policy_root` / `state_root` vocabulary survives.

## Product capabilities preserved

Route entry points are as declared in `crates/server/src/routing.rs:router`.

### Ingest face (`/_arkret/find/directory/*`, HTTP Message Signature required)

| Capability | Implementation (`file:symbol`) | Tests |
|---|---|---|
| `POST announce` — push-mode ingest: body parse, shape validation, rate limit, replay cache, 5-step verify chain, projection, persist, audit | `crates/server/src/ingest/announce/mod.rs:announce` | `ingest/announce/tests.rs` (12); end-to-end only in `tests/it/conformance.rs:postgres_query_conformance_smoke` (**Docker-gated**, see Verification gates) |
| Step 1 — RFC 9421 transport signature, replay store, canonical-JSON enforcement | `crates/server/src/middleware/http_sig.rs:HttpSigMiddleware` | 16 tests incl. `signed_request_passes_middleware`, `replayed_valid_signature_returns_invalid_signature`, `signed_noncanonical_json_is_rejected_even_when_digest_matches`, `signature_not_covering_content_digest_returns_invalid_signature`, `body_mutation_breaks_content_digest`, `expired_signature_returns_invalid_signature`, `passthrough_mode_skips_verification` |
| Step 2 — discovery-Event producer proof against the resource governance key | `crates/server/src/ingest/verify.rs:verify_discovery_event_proofs` | `discovery_event_verifies_producer_binding_and_rejects_metadata_or_station_tampering` |
| Step 3 — directory authorization (`discovery_state.directory_ids` lists this service as a core id) | `verify.rs:directory_ids_lists_self`, `:directory_ids_are_core_ids`, `:derive_via_services` | `directory_authority_list_accepts_only_service_core_ids`, `derive_via_services_dedupes_valid_service_core_ids_and_caps_count`, `derive_via_services_falls_back_to_the_announced_principal_service_id` |
| Step 4 — source-ref authority: non-empty closed refs, bounded fetch from the authenticated source Station, `RealmCommit` authority-chain verification on first ingest only | `verify.rs:verify_directory_source_ref_access`, `:verify_first_source_ref_resolves`, `:CommittedEventAuthorityVerifier` | `first_ingest_fetches_one_bounded_ref_from_the_authenticated_source_service`, `first_ingest_rejects_matching_commit_without_verified_authority_chain`, `first_ingest_rejects_source_ref_after_withdraw_supersession_or_other_announce` |
| Step 5 — accept policy (open / allowlist / operator_review) and takedown-in-force cross-check | `verify.rs:enforce_accept_policy`, `:previously_withdrawn`, `:is_in_allowlist` | covered through `conformance` (**Docker-gated**) |
| `POST withdraw` — resource-initiated withdrawal with a verifiable governance proof | `crates/server/src/ingest/withdraw.rs:withdraw`, `verify.rs:verify_governance_proof` | `resource_kind_inference_requires_a_canonical_id`; `valid_withdraw_governance_proof_verifies`, `cross_directory_replay_is_rejected`, `stale_governance_proof_is_rejected`, `signature_under_another_context_is_rejected`, `tampered_request_body_breaks_the_payload_digest_binding`, `signer_must_be_the_governance_controller` |
| Federation trust-domain header pair and cache-key separation | `crates/server/src/ingest/announce/federation.rs` | `trust_domain_verifier_skips_non_federation_announce`, `:rejects_partial_pair`, `:rejects_destination_mismatch`, `:emits_transcript_fragment`, `federation_source_service_id_rejects_did_authority`, `cache_key_separates_by_trust_domain` |
| Realm-organization statement verification, validity window, revocation, delegated-role fail-closed, `realm_authority` control scope | `crates/server/src/ingest/organization_statement.rs:control_scope_as_str` and the verify path | `active_owner_statement_is_verified`, `missing_proof_statement_is_rejected`, `expired_statement_is_rejected`, `realm_id_mismatch_is_rejected`, `revoked_statement_is_marked_revocation`, `delegated_role_without_resolver_fails_closed`, `effective_active_respects_validity_window` |
| Handle-claim ingest gating | `crates/server/src/ingest/announce/projection.rs` | `handle_claim_ingest_rejects_service_handle_claim_type`, `:rejects_non_principal_subject`, `:accepts_principal_did_and_non_handle_bodies` |
| Circle isolation on ingest (no Circle id may cross into the public index, including inside free text and arrays) | `crates/server/src/filter/circle_isolation.rs` | 14 tests incl. two proptests: `property_random_circle_injection_is_always_caught`, `property_clean_realm_payloads_are_accepted` |
| Ingest rate limit and announce replay cache | `crates/server/src/ingest/rate_limit.rs`, `crates/server/src/state.rs:AnnounceReplayCache` | `state.rs:rate_limiter_reports_retry_for_exhausted_window`; replay path via `conformance` (**Docker-gated**) |
| Signed operator receipt | `crates/server/src/ingest/receipt.rs` | `signed_operator_receipt_is_locally_verifiable` |

### Query face (`/_arkret/find/directory/*`, read-only)

| Capability | Implementation | Tests |
|---|---|---|
| `GET describe` — role-scoped Describe, canonical/x-namespaced key discipline, PCD advertisement only when activated | `crates/server/src/query/describe.rs:describe` | `describe_emits_required_fields`, `describe_carries_directory_overlay_fields`, `describe_rejects_dev_mode_with_verified_profiles`, `describe_top_level_keys_are_canonical_or_x_namespaced`, `describe_omits_pcd_without_an_activated_runtime`, `describe_advertises_only_the_activated_closed_pcd_configuration` |
| `POST search-realms`, `POST resolve-realm` | `crates/server/src/query/realm.rs` | `restricted_projection_requires_verified_claim`, `unlisted_realm_is_not_search_visible`; end-to-end via `conformance` (**Docker-gated**) |
| `POST resolve-target` — object-level resolve with invite/preview token binding | `crates/server/src/query/target.rs:resolve_target` | 13 unit tests (`token_binds_to_matching_object`, `token_replayed_onto_other_object_is_rejected`, `expired_token_is_rejected`, `tampered_signed_token_payload_is_rejected`, `token_bound_to_alias_resolves_via_canonical_id`, `object_access_gate_requires_verified_policy_or_invite`, …) plus `tests/resolve_target.rs` (10) |
| `POST search-organizations`, `POST resolve-organization` | `crates/server/src/query/organization.rs` | `public_org_preview_excludes_internal_policy_and_preserves_typed_fields`, `public_org_preview_rejects_invalid_registered_field_types` |
| `POST search-actors`, `POST search-users` | `crates/server/src/query/actor.rs` | `actor_preview_preserves_signed_station_and_rejects_missing_or_mismatched_carriers` |
| `POST resolve-handle` — IDNA profile, canonical localpart, restricted-claim disclosure | `crates/server/src/query/handle.rs` | 10 unit tests incl. `restricted_handle_accepts_verified_claim_presentation`, `restricted_handle_rejects_unverified_requester`, `invite_only_and_secret_handles_remain_hidden`, `resolution_returns_principal_and_station_as_account_id` |
| `POST list-handles-for-subject` — reverse handle lookup with disclosure / issuer-trust / audience filters and cursor paging | `crates/server/src/query/handles_for_subject.rs` | 4 unit tests plus `tests/list_handles_for_subject.rs` (9): `happy_path_single_active_claim`, `non_visible_row_is_dropped_by_disclosure_gate`, `restricted_claim_handle_is_never_disclosed_on_this_surface`, `audience_out_of_scope_is_filtered`, `cursor_pagination_boundary`, … |
| `POST private-contact-discovery` — VOPRF PSI, padded outcomes, quota, lease CAS, key epochs | `crates/server/src/pcd.rs`, `crates/server/src/pcd_state.rs` | `pcd_state.rs` (12 model tests); `tests/pcd_http.rs:pcd_http_closes_proof_padding_retry_quota_restart_and_rotation` and `tests/it/pcd_state.rs` (3) — both **Docker-gated** |
| Requester proof families: per-family registered context, replay and audience binding, 300 s window | `crates/server/src/query/requester_proof.rs` | 11 tests incl. `whole_proof_replayed_across_families_is_rejected`, `proof_outside_the_300_second_window_is_rejected`, `proof_for_another_directory_audience_is_rejected`, `request_without_proofs_is_accepted` |
| Anti-enumeration: count bucketing, bucket residency/hysteresis, branch-independent latency floor + jitter | `crates/server/src/filter/enumeration.rs` | 12 tests plus `tests/timing_variance.rs` (2): `latency_budget_targets_are_branch_independent_and_bounded`, `zero_jitter_budget_collapses_to_exact_floor` |
| Public-projection sanitiser and the fixed locked Circle stub | `crates/server/src/filter/circle_directory.rs`, `crates/server/src/filter/selector.rs`, `crates/server/src/filter/discoverers.rs` | `locked_stub_has_fixed_shape_and_commitment_length`, `public_projection_sanitizer_collapses_circle_directory_to_one_stub`, `realm_members_visibility_still_collapses_in_the_public_index`, `selector.rs` (5), `signed_restricted_claim_presentation_authorizes_claim_selector` |
| Result envelope carrying closed `CommittedEventRef`s, canonical-millisecond `as_of`, mandatory `policy_revision` | `crates/server/src/filter/result.rs:ResultEnvelope` | `result_envelope_serializes_as_of_as_canonical_milliseconds` (fixture is now `source_refs::fixture_committed_event_ref()`) |
| `GET /_teabay/handle/probe` — private handle probe | `crates/server/src/query/handle.rs:private_handle_probe` | **no test at any level** — see "Uncovered entry points" |

### Zero-network DID acceptance, egress, observability

| Capability | Implementation | Tests |
|---|---|---|
| Accepted-binding directory: query paths cannot express a network resolution; purposes do not cross-authorise; deactivated bindings stop authorising | `crates/server/src/did_binding.rs:DidBindingDirectory` | 13 tests incl. `did_key_signature_verifies_with_zero_network_and_caches`, `unknown_did_web_issuer_fails_closed_instead_of_resolving`, `purposes_do_not_cross_authorize`, `deactivated_binding_stops_authorizing_without_any_resolution`, `an_empty_allowlist_cannot_be_configured_at_all` |
| DID resolver + method allowlist + policy digest | `crates/server/src/did_resolver.rs` | 14 tests; `tests/did_binding_metrics.rs:metrics_expose_did_resolve_and_signature_verify_counters` |
| SSRF-hardened egress for DID documents and Station stream fetches | `crates/server/src/egress.rs`, `verify.rs:strict_http_client_for_egress` | `production_rejects_http_and_non_public_targets`, `development_only_adds_http_loopback`, `development_locks_resolved_host_to_current_addresses`, `production_rejects_all_transition_forms`, `ip_literal_does_not_need_dns_override` |
| Prometheus series inventory | `crates/server/src/observability.rs` | `prometheus_render_includes_required_series`, `:p5_series`, `:r3_2_directory_counters`, `:r3_3_resolve_target_counters` |
| Typed ids (UUIDv7, closed public DTO prefixes) | `crates/server/src/ids.rs` | `new_id_round_trips_through_parse`, `audit_ack_prefix_is_not_abbreviated`, `withdrawal_references_use_the_closed_public_dto_prefix`, `parse_rejects_non_uuidv7_suffix` |
| `/health`, `/healthz`, `/readyz`, config boot rules | `crates/server/src/routing.rs:health`, `:readyz`, `crates/server/src/config.rs` | `tests/health.rs`: `config_rejects_missing_resolution_commitment_even_in_development`, `config_builds_with_minimal_state`, `hardening_status_shape_matches_cross_service_contract` |

### Admin / operator face (`/_teabay/admin/*`, admin token)

| Capability | Implementation | Tests |
|---|---|---|
| `GET/POST/DELETE resources` — resource browser and operator upsert/delete | `crates/server/src/query/admin/resources.rs` | GET + POST via `conformance` (**Docker-gated**); **DELETE has no test** |
| `GET/POST/DELETE allowlist` | `crates/server/src/query/admin/allowlist.rs` | GET + POST via `conformance` (**Docker-gated**); **DELETE has no test** |
| `POST takedown` — operator takedown, notifier-visible pending status | `crates/server/src/ingest/operator.rs:operator_takedown` | `takedown_contact_starts_notifier_visible_pending_status`; end-to-end via `conformance` (**Docker-gated**) |
| `GET audit` — audit feed | `crates/server/src/query/admin/audit.rs` | via `conformance` (**Docker-gated**) |
| `GET dashboard` | `crates/server/src/query/admin/dashboard.rs` | **no test at any level** |
| `GET audit/verify` — audit chain verification | `crates/server/src/query/admin/audit.rs:audit_chain_verify` | **no test at any level** |
| `GET takedowns` — takedown audit export | `crates/server/src/query/admin/takedown.rs` | **no test at any level** |
| `POST consent-revoke` — peer-service consent invalidation | `crates/server/src/query/admin/consent.rs` | **no test at any level** |
| Admin bearer middleware | `crates/server/src/middleware/admin_auth.rs` | 1 test |
| Dioxus admin console (shell, dashboard/moderation/resources panels, API client, form parsing) | `crates/admin/src/{main,shell,api,model,icons}.rs`, `crates/admin/src/panels/*` | **zero tests in the entire crate** — see "Uncovered entry points" |

### Background workers

| Capability | Implementation | Tests |
|---|---|---|
| Expiry worker (purge past grace) | `crates/server/src/workers/expiry.rs` | `tests/it/workers.rs:expiry_worker_purges_rows_past_grace` (**Docker-gated**) |
| Freshness revalidation worker | `crates/server/src/ingest/freshness_worker.rs` | `tests/it/workers.rs:freshness_worker_waits_until_revalidation_grace_elapsed` (**Docker-gated**) |
| Takedown notifier (HMAC-signed webhook fanout, 3-attempt backoff, DLQ) | `crates/server/src/workers/takedown_notifier.rs` | `tests/it/workers.rs:takedown_notifier_dlqs_after_three_retries` (**Docker-gated**) |
| PCD maintenance worker | `crates/server/src/workers/private_contact_discovery.rs` | `tests/it/pcd_state.rs` (3, **Docker-gated**) |

### Authority seam — closed

`ingest/verify.rs` step 4 requires a `CommittedEventAuthorityVerifier` that
validates each `RealmCommit` signature, its authority generation, and the
genesis-to-current governance handoff chain.

**What it was.** teabay shipped no implementation. The only two implementors
were `FailClosedCommittedEventAuthorityVerifier`, whose whole body was
`Err("RealmCommit authority-chain verifier is not configured")`, and a
`#[cfg(test)]` stand-in that accepted on `reference.matches(item)` alone —
exactly what the trait doc forbids. `AppState::new_with_dependencies` was an
injection seam with no caller. In a default deployment the first-ever announce
of any Directory resource was rejected with `source_refs_unverifiable`.

**What closed it.** `arkret-rust-sdk` commit `514762cc` landed
`arkret_identity::realm_authority_chain`: `verify_realm_authority_bundle`
verifies genesis → current cryptographically and returns a
`VerifiedRealmAuthority` that is the only thing able to judge an individual
`RealmCommit`. teabay now consumes it and re-implements none of it:

- `crates/server/src/ingest/authority_chain.rs` —
  `RealmAuthorityChainVerifier` generates a 32-byte nonce, fetches the bundle
  from the source Station's `ak.open.realm_authority.read.bundle.v1` face
  (derived from the accepted `ArkretStation` peer endpoint; a base that is not
  a peer face is refused rather than guessed), verifies it with a 300-second
  freshness window, requires the answering Station to *be* the Realm's current
  governance authority, and then calls `verify_committed_item` on the resolved
  `(RealmCommit, Event)` pair.
- `crates/server/src/did_resolver.rs` — `SharedDidResolver` implements
  `arkret_identity::RealmAuthorityKeyDirectory` through the ordinary
  `DidBindingPurpose::Service` acceptance path. A verification method it cannot
  produce is `MaterialIncomplete`, never a pass.
- `crates/server/src/state.rs` — the production verifier is the **default**.
  `new_with_dependencies` takes an `Option`, and `None` builds
  `RealmAuthorityChainVerifier` from the process resolver, so "forgot to inject
  a verifier" can no longer degrade into accepting an unverified commit.
- `verify.rs` gained `SourceStation<'a> { service_id, did }`. The two spellings
  are not derivable from one another (`project_did_to_core_id` is one-way), and
  the caller has already bound both to the announce.

**What tests it.** `crates/server/src/ingest/verify.rs` now drives the real
verifier: the fixture Station serves both its peer face (the exact
committed-event resolve) and its open face (the nonce-bound bundle, signed at
request time against the nonce actually asked for), over a genesis-generation
chain built with real Ed25519 keys.
`first_ingest_rejects_matching_commit_without_verified_authority_chain` is a
true negative — the resolved commit satisfies `CommittedEventRef::matches`, has
a valid shape and carries a signature that really verifies, and is refused
solely because its signer is not the Station the verified chain names.
`authority_chain.rs` additionally pins the open-face derivation and nonce
freshness.

**Still open.** The Docker conformance smoke does not reach this path: its
fixture Station is a `did:key`, which `identity/identity-did.md` does not
register as a service method, so admission fails earlier at endpoint
resolution (asserted at `conformance.rs`), and the refresh half of that test
goes through `resource_already_indexed`. End-to-end coverage of a first ingest
that *succeeds* would need a `did:web` fixture Station and is not in this
round.

## Removed as complete old-protocol units

Verified against `git show` for this repository's migration round
(`eccc2fd` .. `62dbed3`, 2026-09-11 .. 2026-09-16).

- **`crates/server/src/ingest/subscribe.rs`, 486 lines, deleted whole**, together
  with the `webhook_subscriptions` table, its `subscriber_id` index, its
  `diesel::table!` block, its routes, its `DashboardStats.webhook_subscriptions`
  counter and its dashboard panel row (`0da157e`). This was the resource-discovery
  *push-update subscription* channel: a subscriber registered a resource filter
  and teabay pushed it every matching ingest transition. Every responsibility in
  it belonged to the superseded model, in which a directory could stream
  "something changed" without naming an authority-committed object. In the
  authority-commit protocol there is nothing for teabay to push that a client
  cannot verify for itself from the closed `CommittedEventRef` set already on
  every result envelope, and a directory-authored change feed would be a second,
  unverifiable ordering alongside the Station's. The table's SQL drop went with
  it in both `up.sql` and `down.sql`.
  *Deliberately kept:* `pending_takedown_webhooks` and
  `workers/takedown_notifier.rs`. That is an internal operator audit notifier for
  takedown proposal/approval transitions, not a discovery-update subscription;
  the migration comment was rewritten to say exactly that.
- **`RealmOrganizationControlScope::NotaryControl` → `RealmAuthority`**, and its
  wire spelling `notary_control` → `realm_authority` (`62dbed3`). The registry's
  `control_scope` enum in `event-payload.schema.json` spells the scope
  `realm_authority`; `notary_control` appears nowhere in the specification. The
  mapping was indexing a verified organization statement under a name no query
  could ask for, so the row existed and was unreachable. (This also closes the
  SDK/spec conflict that `coauth/CAPABILITY-MIGRATION.md` reported as item 3
  under "SDK / spec conflicts to resolve upstream": the SDK enum has since been
  renamed, and teabay now renders the corrected value.)
- **`source_refs -> Array<Text>`**, in both `directory_resources` and
  `directory_announces`, replaced by `Jsonb` carrying closed
  `CommittedEventRef` objects (`e6d5232`, `8c99a67`). A `Text[]` column can only
  hold bare Event ids. Under the authority-commit protocol an Event id alone is
  not a verifiable reference — the commit id, the stream and the position are
  what make it checkable — so the array type itself was an old-protocol
  structure, not just an old-protocol value.
- **`ResourceEditorForm` default `source_refs = ["admin:manual"]`**
  (`crates/admin/src/model.rs`, `e6d5232`). The literal string `admin:manual`
  was a sentinel meaning "an operator vouched for this"; there is no such thing
  as a hand-written authority reference. The default is now `[]` and the field
  parses as a `CommittedEventRef` JSON array, so the form cannot produce a row
  whose truth source is a sentence.
- **`verified_realm_organizations.realm_frontier_digest` → `realm_commit_ref`**
  (`8c99a67`), with the fixture and the conformance assertion following. A
  frontier digest is not an object; the `RealmCommitId` is.
- **`describe` capability declarations that restated SDK-derived facts**
  (`09b83c9`), and the `ingest_modes` advertisement the conformance test now
  asserts is absent.
- **Retired signing shape pin** (`4d8b927`) and the **multi-operator takedown
  approval skeleton** (`c4a9628`) — the latter was a signature-only scaffold
  with no approval logic behind it, i.e. exactly the kind of shell this audit is
  meant to catch; it was deleted rather than left compiling.

## Migrated mixed areas, with the evidence

- **`crates/server/src/ingest/verify.rs`** — split, not deleted. All five steps
  survive with their original responsibilities. Step 4 was rewritten
  (+323 lines in `e6d5232`) from "compare the announced source refs against what
  the Station serves" to "resolve one bounded ref from the authenticated source
  service, then require a verified `RealmCommit` authority chain, and refuse to
  accept on structural equality alone". The trait doc states the prohibition
  explicitly, and `first_ingest_rejects_matching_commit_without_verified_authority_chain`
  is the regression.
- **`crates/server/src/source_refs.rs`** — new, and the reason the migration is
  not reversible by accident. `CommittedEventRefs` is a `Jsonb`-backed newtype
  with `FromSql`/`ToSql`; a future change back to `Vec<String>` would not
  compile against `directory_resources::source_refs`.
- **`crates/server/src/filter/result.rs:ResultEnvelope`** — the public result
  shape kept every member (`payload`, `as_of`, `policy_revision`, `stale`,
  `divergent`, join candidates). Only `source_refs` changed type, and
  `from_row` now takes `impl Into<Vec<CommittedEventRef>>` so call sites cannot
  pass a string list.
- **`crates/contracts/src/lib.rs`** — the admin/server contract kept every DTO.
  `DirectoryAdminResourceUpsertRequestBody.source_refs` and
  `ResourceItem.source_refs` became `Vec<CommittedEventRef>`; only
  `DashboardStats.webhook_subscriptions` was dropped, with the removed table.
- **`crates/server/migrations/20260512010000_schema/`** — every product table was
  retained. `webhook_subscriptions` is the only table dropped, and the two
  `source_refs` columns are the only retyped ones. The
  `pending_takedown_webhooks` comment was rewritten to state that it is an
  operator audit notifier and not a subscription surface.
- **`crates/server/src/query/target.rs`** — object resolution, invite/preview
  token binding and the anti-enumeration floor all stayed; only the freshness
  fields it reads changed type.
- **`crates/server/src/ingest/announce/`** — the four sub-modules
  (`federation`, `ingest_body`, `persist`, `projection`) kept their roles. The
  `subscribe` fanout call sites were removed from `mod.rs`; nothing else in the
  announce path was cut.

## Verification gates

Every result below was produced on this machine during this task. Commands were
run from `D:\Works\arkret-org\teabay`.

| Command | Result |
|---|---|
| `cargo test -p server --lib` | **201 passed, 0 failed, 0 ignored.** |
| `cargo test --locked -p server --test it -- --include-ignored` | **7 passed, 0 failed, 0 ignored** (`conformance` 1, `workers` 3, `pcd_state` 3). |
| `cargo test --locked -p server --test pcd_http -- --include-ignored` | **1 passed, 0 ignored.** |
| `cargo test --workspace --no-fail-fast` (default configuration) | The seven Docker-backed tests are reported as **ignored**, not passed. That is the point: the count no longer claims coverage the run did not execute. |
| module reachability self-check | 3 crates (`admin`, `contracts`, `server`), 11 crate roots; **85 `.rs` files on disk under `crates/*/src`, `crates/*/tests`; 85 reachable by walking `mod` from those roots; 0 orphans.** The walk resolves `#[path]` attributes and nested inline `mod` blocks, and treats every integration-test file as its own crate root (required here: `crates/server/tests/it/` is a multi-file test crate rooted at `main.rs`, and `tests/common/mod.rs` is shared by several roots). No file in this repository is excluded from compilation. |
| residue scan (`git grep -i` for `Seal`, `Cell`, `CBS`, `ControlProposal`, `frontier`, `lattice`, `RHRK`, `history_secret`, `policy_root`, `state_root`, `actor_seq`, `encryption_floor`, `governance_profile`, `security_frontier`, `ordinary_authoring`, `Deprecated`) | **Zero hits.** `Retired` matches 47 times and `Legacy` twice, and every one is ordinary English or an unrelated domain term: 43 of the `Retired` hits are `retired_at` / `retired_key_epochs` in `pcd_state.rs`, `schema.rs`, `up.sql` and `tests/it/pcd_state.rs` — the PCD key-epoch lifecycle column, which has nothing to do with the protocol; the rest are `docs/deployment.md` describing the GC interval, `docs/did-normalization.md` stating that no compatibility aliases exist, and one comment in `query/handle.rs:654` noting that the `arkret://` URI form is gone. `CHANGELOG.md:56` uses "legacy DIDs" about `via_services`. |
| `cargo fmt -p server -p teabay-contracts` | Applied. `--all` is never used here: it reaches into the sibling `arkret-rust-sdk` path-dependency checkout, which other agents are editing concurrently. |

### Docker reporting — closed

**What it was.** `crates/server/tests/common/mod.rs:docker_tests_enabled`
returned false unless `TEABAY_RUN_DOCKER_TESTS=1`, and every Docker-backed test
then did `eprintln!("skipping …"); return Ok(())`. libtest counts that as
**passed**. A default `cargo test` reported green for
`postgres_query_conformance_smoke` — the only end-to-end coverage for
`announce`, `withdraw`, every `search-*`/`resolve-*` route and the admin
resources/allowlist/takedown/audit routes — plus the three `workers` tests, the
three `pcd_state` tests and `pcd_http`, having executed none of them.

**What closed it.** All seven now carry `#[ignore]` with the reason spelled
out, and the environment switch is gone entirely — a second way to skip is a
second way to be silently green. libtest reports ignored separately from passed
in every counter, summary line and machine-readable output, so a default run
says `N passed; 7 ignored` and claims nothing it did not do. Run them with
`-- --include-ignored`; `boot_postgres` then turns an unreachable Docker daemon
into a loud failure, because the test was asked for explicitly.

The gate says it out loud: `.github/workflows/ci.yml` runs both Docker-backed
targets with `--include-ignored`, tees the output, and **fails the job** if the
summary line reports any ignored test or if no test executed at all. Skipping
can no longer be mistaken for passing by a machine either.

### Realm preview — closed

**What it was.** `query/realm.rs:realm_preview_from_envelope` built a
`RealmPreview` by serialising the whole `ResultEnvelope` and deserialising the
result into `arkret_models_discovery::RealmPreview`. `ResultEnvelope.payload` is
a `DirectoryPublicProjection`, which `crates/contracts/src/lib.rs:json_boundary!`
defines as a **transparent `serde_json::Value` newtype** — every key of the
stored projection was flattened into the candidate preview, and `RealmPreview`
is `#[serde(deny_unknown_fields)]` (`additionalProperties: false` in
`directory-operations.schema.json`). The function removed exactly two keys and
nothing else, so any other stored member produced HTTP 500 at query time.

The instance that was not test data: `filter/discoverers.rs:allowed_discoverers`
reads `allowed_discoverers` out of the stored `public_projection` to decide
restricted visibility, so the Directory *must* store it and `realm_preview`
*must not* carry it. `resolve-realm` therefore returned 500 for **every**
restricted Realm that reached preview conversion.

**What closed it.** Two halves, because a read-side fix alone would only have
moved the failure:

- read side — `realm_preview_from_envelope` assembles the closed DTO field by
  field through `query::projection_field`, the same shape
  `organization_preview_from_envelope` already had. A projection key that is not
  a preview member is simply not carried, and a member of the wrong type is a
  named error rather than a coerced value
  (`a_wrongly_typed_preview_member_is_refused_rather_than_coerced`).
- write side — `ingest/announce/projection.rs:validate_preview_projection`
  checks, at announce time, that the projection about to be stored can produce
  its preview, so a projection the read face cannot serve is rejected with
  `schema_violation` instead of being indexed and 500ing later. It mirrors the
  row-level members the read face injects (`realm_id` and `discoverability` for
  Realms, `organization_id` and `discoverability` for organizations) — without
  that, every organization announce would have been falsely rejected.

**The two faces held for review.** `actor_preview`
(`query/actor.rs:actor_preview_from_envelope`) and `object_preview`
(`query/target.rs`, both construction sites) were checked and are already
assembled member by member; neither ever deserialised an open projection into a
closed DTO. `applet` and `handle` rows are not served through a `*_preview` DTO
at all. The Realm face was the only one with this defect.

**What proves it.** `conformance::postgres_query_conformance_smoke` installs a
genuinely restricted Realm (`install_restricted_realm_claim_selector` writes
`allowed_discoverers` into the stored projection) and then asserts
`resolve-realm` returns `200 OK` for a signed claim presentation. That
assertion runs against a real PostgreSQL and passes; it is the coverage this
row previously lacked.

## Uncovered entry points

Routes reachable in production with **no test at any level** — not a unit test,
not an HTTP test, not the Docker-gated conformance smoke:

- `GET /_teabay/admin/dashboard` (`query/admin/dashboard.rs`)
- `GET /_teabay/admin/audit/verify` (`query/admin/audit.rs:audit_chain_verify`)
- `GET /_teabay/admin/takedowns` (`query/admin/takedown.rs`)
- `POST /_teabay/admin/consent-revoke` (`query/admin/consent.rs`)
- `DELETE /_teabay/admin/allowlist`, `DELETE /_teabay/admin/resources`
- `GET /_teabay/handle/probe` (`query/handle.rs:private_handle_probe`)

Crates with **zero test functions anywhere**:

- `crates/admin` — the whole Dioxus console: `api.rs` (the HTTP client plus
  about fifteen pure parsing/formatting helpers, including
  `parse_optional_json_object`, `parse_string_array`, `parse_evidence`,
  `optional_u32`, `resource_key`, `audit_badge_class`), `model.rs` (including
  the `ResourceEditorForm` round-trip that this migration just retyped to
  `CommittedEventRef`), `shell.rs`, `panels/{dashboard,moderation,resources}.rs`.
  The `source_refs` retype in `model.rs` is precisely the kind of change a unit
  test would pin, and there is none.

None of these is a regression from this migration round; all predate it. They
are listed because an acceptance criterion of "the original product entry points
still have an implementation *and a test*" is not met for them.

## External blockers

1. **The sibling `arkret-rust-sdk` checkout is under concurrent edit and went
   red four separate times during this task.** teabay depends on `arkret-canonical`,
   `arkret-egress-reqwest`, `arkret-identifiers`, `arkret-identity`,
   `arkret-models-collaboration`, `arkret-models-discovery`,
   `arkret-models-identity`, `arkret-policy`, `arkret-rate-limit`,
   `arkret-schema`, `arkret` (sdk), `arkret-server`, `arkret-signatures` and
   `arkret-wire` by path, so any SDK error stops the whole workspace. Observed,
   in order:
   - `crates/models-identity/src/signer_key_operations.rs` — three errors
     (`validate_for_selector` missing on `ResolvedSignerKey`;
     `SignerKeyQueryResult::selector` used as a field at lines 278 and 308).
   - `crates/signatures/src/detached_object.rs:134` —
     `verify_ed25519_raw_transcript_signature` not found at the crate root.
   - `crates/http-client/src/endpoints/events.rs:275` — `limit` is `u16`, a
     `u32` was passed.
   - `arkret-models-crypto` — two errors, the reported one being the trait
     bound `EventCommitSubmission: ToSchema` not satisfied.

   The 230/0 default run and the Docker-enabled `it` run were both taken in
   windows where the SDK compiled. **Nothing in the SDK was changed to obtain
   them**, and no teabay source was changed to make anything go green.

   Reproduce the Docker-backed suite with `cargo test --locked -p server --test
   it -- --include-ignored` whenever the SDK tree compiles.

2. **Nothing is blocked externally now.** The authority-chain verifier this
   file previously recorded as unshippable was unblocked by `arkret-rust-sdk`
   `514762cc`; teabay consumes that API and hand-rolls no cryptography of its
   own.
