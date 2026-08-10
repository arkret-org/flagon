# Changelog

All notable changes to teabay (Arkret v1 Directory Service) live here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## R3.4 — Spec sync 2026-05-31 (arkret-spec @ c2848a4)

- Synced protocol-facing names and fixtures to `c2848a4`: event envelope schema naming, `_ids` grant constraints, accountability principal vocabulary, `ak:rtc_participant:` media participants, agent session start fields, and key-backup signature algorithm naming where applicable.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## R3.3 — AKP-0011 (arkret-spec @ cced4b8)

- New operation `ak.find.directory.read.resolve_target` (`POST /_arkret/find/directory/resolve-target`, `Directory/ResolveTarget`): the object-level generalization of `resolve_realm`. Resolves a client-agnostic shareable object address (`web+arkret:` URI form or HTTPS-landing fragment form) pointing at a Realm / Strand / Message into `target_kind` + (`realm_preview` | `object_preview`) + `join_rule` + the §9.1 common fields (`as_of`, `source_refs`); `via_services` is a delegation/projection field, not a §9.1 common field.
- **Realm resolution DELEGATES** to the existing `resolve_realm` path (`crates/server/src/query/realm.rs::resolve_realm_visible`) so the canonical `realm_id`, `realm_preview`, `via_services`, and the hidden/withdrawn/unknown → blinded `not_found` collapse stay byte-for-byte identical.
- **Token target binding** (scope-confusion defence): an `lt=invite` address carries an opaque `tok`; the token's embedded `target_descriptor` is compared against the address-derived descriptor via the SDK `verify_token_target` (`sha256:` digest over `realm_id` + `strand_id` + `message_id` + `address_link_kind` only — `via`/`action`/`tok`/`lt` are NOT in the digest). A token minted for object A cannot be replayed onto object B; alias realms are normalized to the canonical `ak:realm:<44-char-token>` before comparison. Any mismatch → the SAME blinded `not_found`.
- Anti-enumeration: routed through the SAME latency floor + deterministic jitter + 50ms stochastic resolve jitter as `resolve-realm` / `resolve-handle`; unauthorized and nonexistent are byte- and timing-indistinguishable.
- `/metrics`: `teabay_directory_query_total{op="resolve-target",outcome=...}` with a new `token_reject` outcome (metrics-only split from `not_found`); anti-enum pad histogram for the op. 6-case conformance suite (`tests/resolve_target.rs`): realm classification, invite-token scope-confusion replay reject, unknown keyword fail-closed, strand-missing-`via` fail-closed, invite-without-token reject.
- **Deferred `TODO(R3.3.1)`**: the per-object Strand / Message access-gate returns a deterministic `object_preview` placeholder (the enclosing Realm is fully resolved + visibility-gated). Invite tokens now perform target-digest binding, `exp`/`aud` checks, Ed25519 detached-JWS signature verification, and join-policy revocation lookup. Admin SPA "resolve target" diagnostic tab + docs section deferred.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## R3.2 — Spec sync 2026-05-28 (arkret-spec @ b56cab1)

- New operation `ak.find.directory.read.list_handles_for_subject` (`POST /_arkret/find/directory/list-handles-for-subject`, `Directory/ListHandlesForSubject`): subject DID → current visible handle claims with disclosure/issuer-trust/audience filtering, cursor pagination, fail-closed `claims[].subject == subject`.
- Ingest validators reject `claim_type=service_handle` (`claim_type_unsupported`) and non-principal-DID subjects (`handle_claim_subject_not_principal_did`).
- `/metrics` now exposes directory query/filter-drop/cardinality-guard counters. Anti-enumeration jitter + latency floor applied to the new endpoint. 8-case conformance suite.
- `as_of` historical replay + full per-claim disclosure engine deferred `TODO(R3.2.1)`.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.
## R3 — Spec sync 2026-05-27 (arkret-spec @ b47ff6ec)

- HDL-1: directory handle resolve enforces NFC + UTS#39 confusable skeleton + script-mixed reject for both query and ingest-announce paths; emits `handle_homograph_forbidden`.
- WK-1: `POST /_arkret/find/directory/resolve-handle` stays on the spec Directory surface; the unsigned resolver/index probe moved off `/.well-known/arkret/handle` to product-private `GET /_teabay/handle/probe?localpart=<localpart>`.
- REC-1: directory recovery-resource-pointer indexing validates against the `recovery-policy` / `recovery-receipt` schemas; not-used path stubbed.
- SEL-1: directory query filter now accepts the `circle` selector kind (`ak:circle:<event-token>`).

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## [Unreleased]

### circle-rollout · AKP-0007 enforcement (P2E, arkret-spec `2b0d70d`)

The Circle primitive lands in the spec as an intra-Realm encrypted
sub-boundary. teabay does not index Circle as a top-level directory
resource; Realm announcements that carry Circle directory material are
reduced to the spec preview/stub forms.

- **Changed** Ingest still rejects `ak:circle:` outside recognized Circle
  directory preview-entry id fields, but a Realm announcement may now carry
  exact Circle ids under the Circle directory preview container. Public
  projection/fanout collapses those subtrees to a fixed locked envelope, and
  the internal preview builder supports the parent-Realm-member whitelist for
  `directory_visibility=realm_members`.
- **Added** `crates/admin/` is now an actual source tree (the prior
  state shipped only `teabay-admin/` build artifacts). Dioxus SPA with
  six tabs: Dashboard / Resources / Allowlist / Takedown / Audit /
  Review. Bearer-token login. New Dashboard tab fans out to a new
  `GET /api/admin/v1/dashboard` endpoint that returns aggregate
  COUNT(*) over the directory tables for an operator overview.
- **Added** `Dockerfile.server` (renamed from `Dockerfile`, plus
  HEALTHCHECK on `/health`, non-root) and `Dockerfile.admin`
  (multi-stage Rust + dx wasm build served via nginx:alpine).
  `docker-compose.yml` brings the full stack (postgres + teabay-server
  + teabay-admin) online with one `docker compose up --build`.
- **Added** Trivy scan coverage for both images (P2E.4.4). The CI
  `container-scan` job now builds `Dockerfile.server` and
  `Dockerfile.admin` separately and runs `aquasecurity/trivy-action`
  against each (HIGH+CRITICAL, `--ignore-unfixed`, exit-code 1).
  `scripts/trivy-scan.sh` mirrors the same workflow for local use
  and bails out cleanly if `trivy` is not on PATH. A local execution
  in the rollout environment was deferred because (a) `trivy` is not
  installed locally and (b) Docker Hub rate-limited the unauthenticated
  base-image pull (`debian:bookworm-slim`, `rust:1.88-bookworm`,
  `nginx:1.27-alpine`); the CI runner is authenticated and faces no
  rate limit, so P2E.4.4 is satisfied by the workflow gate.
- **Added** TTL freshness story. Migration
  `20260526010000_add_freshness` adds
  `directory_resources.last_refreshed_at` and
  `directory_resources.expires_at`, backfilled from the existing
  `indexed_at` + `effective_ttl_seconds` pair. Freshness is refreshed
  by re-submitting `ak.find.directory.command.announce` for the current
  discovery state. The background freshness worker sweeps on
  `expires_at` instead of the pull worker's
  `next_revalidation_after` cadence.
- **Added** Connection-pool tuning surface. New env vars
  `TEABAY_DB_POOL_MAX_SIZE`, `TEABAY_DB_POOL_MIN_IDLE`,
  `TEABAY_DB_POOL_CONNECTION_TIMEOUT_SECS`,
  `TEABAY_DB_POOL_IDLE_TIMEOUT_SECS`; defaults documented in
  `docs/scaling.md`. The Prometheus scrape gains four new gauges
  (`teabay_db_pool_connections` / `_idle` / `_in_use` / `_max_size`)
  sourced directly from the live r2d2 pool — no risk of drift
  between a tracked counter and the actual state.
- **Added** `docs/scaling.md` walks operators through sizing the pool
  for a target QPS, the interplay with `TEABAY_RATE_LIMIT_PER_RESOURCE_PER_MIN`,
  the Postgres `max_connections` ceiling, and the recommended
  in_use/max_size > 0.8 alert.
- **Note** Version stays at 0.1.0; no tag, no release this round.

### Round R4 — protocol review closures (2026-05-20, arkret-spec `2a4d39b..a77b995`)

Closes the round-4 protocol-review commits on the directory-service
surface. See [`../_todos.md`](../_todos.md) for the workstream context.

- **BREAKING** `/directory/describe` switched to the `ServiceDescribe` v2
  envelope (17 required fields including `trust_domain` /
  `plaintext_visibility` / `claimed_profiles` / `verified_profiles` /
  `development_mode`).
- **BREAKING** Federation S2S transport now verifies the three new
  headers `Source-Trust-Domain` / `Destination-Trust-Domain` /
  `Request-Canonical-Digest` and folds them into the HTTP-message-signature
  transcript. Mismatch rejects as `cross_domain_replay_rejected`.
- **Added** Federation idempotency cache adopts the soland `historical_only`
  semantics: post-key-revoke cache hits return the cached body with
  diagnostic `reason_code=historical_only`, with capability re-check, no
  new side effects.
- **Added** handle-claim and member-delivery-binding-candidate schemas
  swept for the tightened DID method-name regex
  (`^did:[a-z0-9]+:[^\s]+$`); fixture SQL refreshed.
- **BREAKING** Realm rows are now distinct from container Space rows:
  Realm query surfaces use `resource_kind=realm`, `realm_id` projection keys,
  and `ak:realm:` fixture identifiers; `space` remains available only as the
  separate container resource kind.

### Round R2/R3 (2026-05-20) — 17 P0/P1 tasks closed against arkret-spec

#### Added

- **T14 — Federation idempotency cache key extension.** The `ak.directory.
  announce` replay cache key now includes the four federation-identity
  fields: `Source-Service-ID` header, `verification_method` (from the
  discovery proof), `service_binding_ref` header, and
  `origin_key_state_digest` header. On a cache hit the announce handler
  re-runs the §8.5 capability chain; if the new check fails (e.g. the
  source service key has been revoked) the cached body is served with
  `historical_only=true` and no new side effects are triggered. New audit
  kind `ingest_historical_only` records the replay-after-revocation path.
  `ingest_announces` grew matching columns (`source_service_id`,
  `verification_method`, `service_binding_ref`, `origin_key_state_digest`,
  `historical_only`) so the audit trail captures the full cache key.
- **T17 — `consent_revoke{scope=any}` directory reachability
  invalidation.** New admin endpoint `POST /api/admin/v1/consent-revoke`
  (bearer-auth) takes a `consent_revoke` broadcast from soland and
  **soft-deletes** affected `directory_resources` rows via the new
  `reachability_revoked_at` / `reachability_revoked_reason` columns —
  audit-preserving UPDATE, never DELETE. Search face hides revoked rows;
  resolve still surfaces them so in-flight callers can observe the
  tombstone. Best-effort tombstone webhook fanout reuses the
  `ak.find.directory.push.command.register` channel. New audit kind
  `consent_revoke_invalidation`.
- **T07 — Realm terminal state.** When the ingest face observes a
  `ak.realm.destroy` anchor (signalled either by `terminal_state:
  "destroyed"` or `realm_destroyed: true` on the verified
  `discovery_state`), the directory marks the row with
  `realm_destroyed_at`. Resolve and search project the row as a
  deterministic `[erased]` tombstone instead of the historical
  governance state. In-flight subscribers receive a `realm_destroyed`
  tombstone notification over the existing webhook channel. New audit
  kind `realm_destroyed`. Once set, `realm_destroyed_at` is never
  cleared (`COALESCE` on the upsert).

#### Database

- New migration `20260520010000_round23` adds five columns to
  `ingest_announces`, three columns + two partial indexes to
  `directory_resources`, and three values to the `audit_event_kind`
  enum. Runs with `run_in_transaction = false` because Postgres rejects
  consumption of new enum values inside the same transaction that
  introduced them.

#### Wire-format notes

- `AnnounceResponse` gains an optional `historical_only` boolean
  (omitted when false). Callers that ignore it remain compatible — the
  semantics only matter on the federation replay path.
- New tombstone webhook payload shape: `{ tombstone: { kind, reason,
  revoked_at }, resource_kind, resource_id, principal_server_did }`
  delivered with `x-arkret-webhook-event: reachability_tombstone`.

#### Internal markers

Closed in the Phase 2 `§1`-`§3` slice:

- `round4-fed-canonical` — announce replay digests now use the canonical
  JSON body hash, matching `Request-Canonical-Digest`.
- `round23-T07` — Realm discovery rows use the dedicated `realm`
  `resource_kind`; `space` is rejected at the wire boundary.
- `round23-T14` — the pull worker records `Source-Service-ID` and
  origin key state digest inputs so pull-mode replays align with push-mode
  cache keys.
