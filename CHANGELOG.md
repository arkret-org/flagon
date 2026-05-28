# Changelog

All notable changes to teabay (Contrix v1 Directory Service) live here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## R3.2 — Spec sync 2026-05-28 (contrix-spec @ b56cab1)

- New operation `cx.directory.list_handles_for_subject` (`POST /api/v1/directory/list-handles-for-subject`, `Directory/ListHandlesForSubject`): subject DID → current visible handle claims with disclosure/issuer-trust/audience filtering, cursor pagination, fail-closed `claims[].subject == subject`.
- Ingest validators reject `claim_type=service_handle` (`claim_type_unsupported`) and non-principal-DID subjects (`handle_claim_subject_not_principal_did`).
- `/metrics` now exposes directory query/filter-drop/cardinality-guard counters. Anti-enumeration jitter + latency floor applied to the new endpoint. 8-case conformance suite.
- `as_of` historical replay + full per-claim disclosure engine deferred `TODO(R3.2.1)`.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.
## R3 — Spec sync 2026-05-27 (contrix-spec @ b47ff6ec)

- HDL-1: directory handle resolve enforces NFC + UTS#39 confusable skeleton + script-mixed reject for both query and ingest-announce paths; emits `handle_homograph_forbidden`.
- WK-1: `POST /api/v1/directory/resolve-handle` and the well-known proxy aligned to the new spec form `/.well-known/contrix/handle?localpart=<localpart>`.
- REC-1: directory recovery-resource-pointer indexing validates against the `recovery-policy` / `recovery-receipt` schemas; not-used path stubbed.
- SEL-1: directory query filter now accepts the `circle` selector kind (`cx:circle:<uuid>`).

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## [Unreleased]

### circle-rollout · CXP-0007 enforcement (P2E, contrix-spec `2b0d70d`)

The Circle primitive lands in the spec as an intra-Realm encrypted
sub-boundary. teabay's job is to make sure the directory never sees
one.

- **BREAKING** Ingest now hard-rejects any payload that carries Circle
  metadata. `circle_id` / `circle_members` / `scope_circle_id` /
  `default_scope_circle_id` (at any nesting depth) and any string
  value containing `cx:circle:` (case-insensitive, anywhere — not
  only as a prefix) yield `schema_violation`. The wire response is
  deliberately low-information to preserve the anti-enumeration story
  (the rejection message does NOT echo the field name or the typed
  id). Audit row captures the violation for operator review.
  Mirrored on `POST /api/v1/directory/announce`,
  `POST /api/v1/directory/announce/heartbeat`, and
  `POST /api/v1/directory/subscribe`.
- **BREAKING** The SDK's CXP-0007 `forbidden-wire-fields` list is
  mirrored at the directory edge (`discussion_realm_ref`,
  `discussion_space_ref`, `parent_ref`, `default_realm_ref`,
  `scope_ref`, `default_scope_ref`, `retention_policy_ref`,
  `disclosure_policy_ref`, `rate_limit_policy_ref` are hard-rejected
  on ingest).
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
- **Added** TTL/heartbeat freshness story. Migration
  `20260526010000_add_freshness` adds
  `directory_resources.last_refreshed_at` and
  `directory_resources.expires_at`, backfilled from the existing
  `indexed_at` + `effective_ttl_seconds` pair. New endpoint
  `POST /api/v1/directory/announce/heartbeat` lets an owner bump
  `last_refreshed_at` + `expires_at` forward by one TTL window
  without re-signing the full discovery_state body. Owner check via
  `X-Principal-Server-DID`; blinded `not_found` for unknown
  `announce_id`. Followup: a dedicated background expiry worker that
  sweeps on `expires_at` (vs. the existing
  `next_revalidation_after`-driven pull worker) is tracked as
  `TODO(circle-rollout-P2E.5)` in
  `crates/server/src/ingest/heartbeat.rs`.
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

### Round R4 — protocol review closures (2026-05-20, contrix-spec `2a4d39b..a77b995`)

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
  and `cx:realm:` fixture identifiers; `space` remains available only as the
  separate container resource kind.

### Round R2/R3 (2026-05-20) — 17 P0/P1 tasks closed against contrix-spec

#### Added

- **T14 — Federation idempotency cache key extension.** The `cx.directory.
  announce` replay cache key now includes the four federation-identity
  fields: `Source-Service-DID` header, `verification_method` (from the
  discovery proof), `service_binding_ref` header, and
  `origin_key_state_digest` header. On a cache hit the announce handler
  re-runs the §8.5 capability chain; if the new check fails (e.g. the
  source service key has been revoked) the cached body is served with
  `historical_only=true` and no new side effects are triggered. New audit
  kind `ingest_historical_only` records the replay-after-revocation path.
  `ingest_announces` grew matching columns (`source_service_did`,
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
  `cx.directory.push.register` channel. New audit kind
  `consent_revoke_invalidation`.
- **T07 — Realm terminal state.** When the ingest face observes a
  `cx.realm.destroy` anchor (signalled either by `terminal_state:
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
  delivered with `x-contrix-webhook-event: reachability_tombstone`.

#### Internal markers

Closed in the Phase 2 `§1`-`§3` slice:

- `round4-fed-canonical` — announce replay digests now use the canonical
  JSON body hash, matching `Request-Canonical-Digest`.
- `round23-T07` — new Realm discovery rows use the dedicated `realm`
  `resource_kind`; the legacy `space` variant remains readable for old rows.
- `round23-T14` — the pull worker records `Source-Service-DID` and
  origin key state digest inputs so pull-mode replays align with push-mode
  cache keys.
