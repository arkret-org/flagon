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

Two findings below are load-bearing for acceptance and are stated up front:
the ingest verify chain's `RealmCommit` authority step has no shipped
implementation ("Unverified seam"), and `search-realms` / `resolve-realm`
currently return HTTP 500 for projections the ingest face accepts
("Live defect"). Neither is visible in a default `cargo test` run.

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
  doc says so and `FailClosedCommittedEventAuthorityVerifier` enforces it.
  See "Unverified seam" below for what actually ships.
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

### Unverified seam — the one that matters

`ingest/verify.rs` step 4 requires a `CommittedEventAuthorityVerifier` that
validates each `RealmCommit` signature, its authority generation, and the
genesis-to-current governance handoff chain. **teabay ships no implementation of
that trait.** The only two implementors in the repository are:

- `FailClosedCommittedEventAuthorityVerifier` (`verify.rs:90`) — its `verify`
  body is one line: `Err("RealmCommit authority-chain verifier is not configured")`.
- `TestCommitAuthorityVerifier` (`verify.rs:1950`, `#[cfg(test)]`) — and this one
  accepts on `reference.matches(item)` alone, which is exactly what the trait
  doc forbids a real implementation from doing. It is a stand-in that lets the
  surrounding tests exercise the *fetch* path; it is not, and does not claim to
  be, an authority-chain verifier. So no code in this repository, test or
  production, verifies a `RealmCommit` signature or a governance handoff chain.

`AppState::new` installs the fail-closed one; `AppState::new_with_dependencies`
is the injection seam and has **no caller outside `AppState::new` itself**. The
consequence is exact and worth stating plainly: in a default deployment, the
first-ever announce of any Directory resource is rejected with
`source_refs_unverifiable`. Resources already in the index skip step 4
(`resource_already_indexed`) and keep updating normally.

This is a deliberate, documented fail-closed gap, not an accident — it is
written up in `docs/deployment.md` under "RealmCommit authority verification"
and guarded by `first_ingest_rejects_matching_commit_without_verified_authority_chain`.
It is recorded here because "compiles and the suite is green" is not the same as
"the capability works end to end", and for first-time remote ingest it does not.

A second, narrower gap in the same area: the operator upsert path
(`query/admin/resources.rs`) validates `source_refs` for shape only — non-empty,
canonically sorted, unique — and never calls the authority verifier. An admin
token can therefore install a Directory row with syntactically well-formed but
unverified committed refs. That is presumably intended (the operator is the
trust root for that route), but it is the one way a row reaches the index
without step 4, and nothing in the code says so.

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
| `cargo test --workspace --no-fail-fast` (default configuration) | **230 passed, 0 failed, 0 ignored.** Breakdown: 196 `server` unit tests, 9 `list_handles_for_subject`, 10 `resolve_target`, 7 `it`, 3 `health`, 2 `timing_variance`, 1 `did_binding_metrics`, 1 `pcd_http`, 1 `teabay-contracts`. |
| `TEABAY_RUN_DOCKER_TESTS=1 cargo test --workspace --no-fail-fast` | **The `it` suite is 6 passed / 1 failed.** `conformance::postgres_query_conformance_smoke` fails once the Docker-backed database is actually provided, with a live HTTP 500 — root cause in "Live defect" below. `tests/pcd_http.rs`, `tests/it/pcd_state.rs` and `tests/it/workers.rs` all pass with Docker enabled (1 / 3 / 3). **This is the headline verification result: the 230/0 figure above is obtained with the integration suite short-circuited.** |
| module reachability self-check | 3 crates (`admin`, `contracts`, `server`), 11 crate roots; **85 `.rs` files on disk under `crates/*/src`, `crates/*/tests`; 85 reachable by walking `mod` from those roots; 0 orphans.** The walk resolves `#[path]` attributes and nested inline `mod` blocks, and treats every integration-test file as its own crate root (required here: `crates/server/tests/it/` is a multi-file test crate rooted at `main.rs`, and `tests/common/mod.rs` is shared by several roots). No file in this repository is excluded from compilation. |
| residue scan (`git grep -i` for `Seal`, `Cell`, `CBS`, `ControlProposal`, `frontier`, `lattice`, `RHRK`, `history_secret`, `policy_root`, `state_root`, `actor_seq`, `encryption_floor`, `governance_profile`, `security_frontier`, `ordinary_authoring`, `Deprecated`) | **Zero hits.** `Retired` matches 47 times and `Legacy` twice, and every one is ordinary English or an unrelated domain term: 43 of the `Retired` hits are `retired_at` / `retired_key_epochs` in `pcd_state.rs`, `schema.rs`, `up.sql` and `tests/it/pcd_state.rs` — the PCD key-epoch lifecycle column, which has nothing to do with the protocol; the rest are `docs/deployment.md` describing the GC interval, `docs/did-normalization.md` stating that no compatibility aliases exist, and one comment in `query/handle.rs:654` noting that the `arkret://` URI form is gone. `CHANGELOG.md:56` uses "legacy DIDs" about `via_services`. |
| `cargo fmt` | Not run. `--all` reaches into the sibling `arkret-rust-sdk` path-dependency checkout, which other agents are editing concurrently. |

### How the Docker gate hides work

`crates/server/tests/common/mod.rs:docker_tests_enabled` returns false unless
`TEABAY_RUN_DOCKER_TESTS=1`. Every Docker-backed test then does
`eprintln!("skipping …"); return Ok(())` — and libtest counts that as **passed**.
A default `cargo test` therefore reports green for
`postgres_query_conformance_smoke`, the three `workers` tests, the three
`pcd_state` tests and `pcd_http`, having executed none of them. Since
`postgres_query_conformance_smoke` is the only end-to-end coverage for
`announce`, `withdraw`, every `search-*`/`resolve-*` route and the admin
resources/allowlist/takedown/audit routes, the default green run proves far less
about this repository than its count suggests. The design rationale (a checkout
without a Docker daemon still runs the rest of the suite) is written down in the
same file and is reasonable; the reporting is what misleads.

### Live defect — the Realm preview rejects the projection it is built from

This is what the Docker gate was hiding, and it is not stale test data.

`query/realm.rs:realm_preview_from_envelope` builds a `RealmPreview` by
serialising the whole `ResultEnvelope` and deserialising the result into
`arkret_models_discovery::RealmPreview`. `ResultEnvelope.payload` is a
`DirectoryPublicProjection`, which `crates/contracts/src/lib.rs:json_boundary!`
defines as a **transparent `serde_json::Value` newtype** — every key of the
stored projection is flattened into the candidate preview. `RealmPreview` is
`#[serde(deny_unknown_fields)]`, matching the specification's `realm_preview`
(`spec/v1/artifacts/schemas/directory-operations.schema.json`,
`additionalProperties: false`). `realm_preview_from_envelope` removes exactly
two keys before deserialising — `owning_organization_ids` and
`organization_id` — and nothing else.

Nothing upstream constrains the projection to that closed shape.
`ingest/announce/projection.rs:derive_public_projection` strips `proof`,
`directory_ids` and `official_organizations` and normalises the member count;
it never validates against `realm_preview`. **So a projection carrying any
other field is accepted at ingest and then produces HTTP 500 at query time**,
instead of being rejected at ingest with `schema_violation`.

Two concrete instances, both reproduced on this machine:

1. `"name"` — `search-realms` returns 500 (`conformance.rs:350`):
   `realm preview is not SDK-compatible: unknown field 'name', expected one of
   realm_id, alias, title, …`. No directory preview in the specification has a
   `name` field (`realm_preview` and `object_preview` have `title`;
   `actor_preview` and `organization_preview` have neither), so this one is
   fixture data that drifted from the schema.
2. `"allowed_discoverers"` — `resolve-realm` returns 500 for the restricted
   Realm (`conformance.rs:678`). **This one is not test data.**
   `filter/discoverers.rs:allowed_discoverers` reads that field out of the
   stored `public_projection` to decide restricted visibility, so the directory
   *must* store it, and `realm_preview` *must not* carry it. The consequence is
   that `resolve-realm` 500s for every restricted Realm that reaches preview
   conversion.

I established that (2) is independent of (1) by a throwaway probe: renaming
the fixture's `name` to `title` moved the failure from line 350 to line 678
with the new field named in the error. **The probe was reverted (the fixture is
byte-identical to `HEAD`) and no fixture change is committed** — patching test
data would have turned the suite green without touching the defect.

The organization face does not have this bug and shows the shape of the fix:
`query/organization.rs:organization_preview_from_envelope` assembles the
preview field by field through `organization_projection_field`, so a projection
key that is not a preview member is simply not carried.
`public_org_preview_excludes_internal_policy_and_preserves_typed_fields`
asserts precisely that, including for `name`. The Realm face is the only one
that does whole-value deserialisation of an open projection into a closed DTO.

This is a product-capability failure, not a test-harness artefact: two of the
Directory's primary read entry points return 500 for inputs the ingest face
accepts. It is out of scope for this file to fix, and it is recorded here
rather than worked around.

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

   Capturing the conformance failure took several attempts for this reason: the
   first Docker-enabled run reported `FAILED` but the panic text scrolled past
   the captured tail, and the retries were stopped by SDK errors before the
   test could build. It did eventually run — the result is written up under
   "Live defect" above. Reproduce with `TEABAY_RUN_DOCKER_TESTS=1 cargo test -p
   server --test it --no-fail-fast conformance` whenever the SDK tree compiles.

2. **Nothing else is blocked externally.** The one red test is teabay's own
   defect, not an upstream one.
