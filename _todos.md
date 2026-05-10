# chadex — _todos.md

Reference Contrix v1 Directory Service. Spec source of truth:
[`contrix-spec/spec/v1/zh/discovery/discovery-directory.md`](../contrix-spec/spec/v1/zh/discovery/discovery-directory.md)
(§7 role / §8 ingest protocol / §9 service surface / §11 security / §12
conformance).

## Milestone overview

| ID  | Name                              | Status | Goal                                                                                  |
| --- | --------------------------------- | ------ | ------------------------------------------------------------------------------------- |
| M0  | Project skeleton                  |   ▣    | Project compiles, migrations run, /health works.                                       |
| M1  | Query face MVP                    |   ▣ʷ   | search-* / resolve-* land documents that have already been pushed via raw SQL.         |
| M2  | Ingest face — push + verify chain |   ▣ʷ   | `cx.directory.announce` accepts signed state and rejects invalid ingest per §8.5/§8.10. |
| M3  | Pull-mode + freshness worker      |   ☐    | TTL revalidation worker actually pulls + re-verifies signed state.                     |
| M4  | Search index quality              |   ☐    | Full-text + trigram ranking + scope filters; pagination cursors.                       |
| M5  | Private Contact Discovery (PSI)   |   ☐    | RFC 9497 VOPRF + 2-round PSI per spec §6.                                              |
| M6  | Anti-enumeration hardening        |   ☐    | Time-equalization beyond pad floor, query-budget rate limiter, audit-log feed.         |
| M7  | Operator console (Dioxus admin)   |   ☐    | Allowlist mgmt + takedown + audit log viewer.                                          |
| M8  | Conformance suite + cotest hookup |   ☐    | Cover §12 query and ingest tests; run as part of cotest.                               |

Legend: ▣ done, ▣ʷ partially done (handler shell + happy path; deferred
 work tracked below), ☐ not started.

The parallelism guide is in §"Parallelization map" at the bottom — skim it
before picking up tasks so two contributors do not collide.

---

## M0 — Project skeleton ✅

- [x] **M0-T1** Cargo.toml with salvo / diesel / tokio / contrix-sdk pinned to
      the same versions soland uses.
- [x] **M0-T2** Migration framework wired up via `diesel_migrations`. Initial
      schema covers `directory_resources`, `ingest_announces`, `withdrawals`,
      `pull_subscriptions`, `webhook_subscriptions`, `accept_allowlist`,
      `directory_audit`. Enums modeled with native PG types.
- [x] **M0-T3** `src/lib.rs` re-exports the public surface; `src/main.rs`
      runs migrations + binds the listener + spawns the pull worker.
- [x] **M0-T4** `_todos.md` (this file) and a complete README.

### M0 follow-ups (small but real)

- [x] **M0-F1** Add `Dockerfile` (FROM rust:1.85 with multi-stage build).
- [x] **M0-F2** Add `scripts/dev-up.sh` that boots a docker-compose Postgres,
      runs migrations, and `cargo run`.
- [x] **M0-F3** Generate a real OpenAPI doc using `salvo-oapi` like soland
      does in `register_soland_specific_schemas` (mirror with chadex
      operations). See `soland/src/lib.rs::register_contrix_oapi_components`.
- [x] **M0-F4** Wire `contrix-sdk::salvo_adapter::register_contrix_oapi_components`
      so chadex's exported OpenAPI carries the canonical schemas.

---

## M1 — Query face MVP ✅ (with ranking + auth deferred)

- [x] **M1-T1** `cx.directory.describe` — exposes §8.9 ingest fields.
- [x] **M1-T2** `cx.directory.search_spaces` — recency-ordered listing
      filtered to public/listed.
- [x] **M1-T3** `cx.directory.resolve_space` — accepts space_id / alias /
      invite_token / signed_link; blinded `not_found`.
- [x] **M1-T4** `cx.directory.search_organizations` + `resolve_organization`.
- [x] **M1-T5** `cx.directory.search_actors`.
- [x] **M1-T6** `cx.directory.resolve_handle`.
- [x] **M1-T7** §9.1 normative result envelope (`as_of` / `source_refs` /
      `policy_revision` / `stale?` / `divergent?` / `via_services`).
- [x] **M1-T8** §10 timing equalization floor (`MIN_RESPONSE_LATENCY` pad).

### M1 deferred to M4 / M6

- [ ] **M1-D1** Real ranking — currently `query::space::run_space_search`
      ignores the `needle` argument; needs `pg_trgm` + tsvector.
- [ ] **M1-D2** `requester` + `proofs[]` enforcement on `restricted` rows.
      Today restricted Spaces are silently filtered out; spec §3 lets them
      surface when the requester presents the right claim.
- [ ] **M1-D3** Pagination cursors. `next_cursor` is always `null`.
- [ ] **M1-D4** `cx.directory.search_users` — currently returns `[]` because
      it needs a "common Space" gating mechanism (M3-T6).

---

## M2 — Ingest face: push announce + verify chain ✅ (verify chain
shape-only)

- [x] **M2-T1** `cx.directory.announce` — request shape parsed, persists
      both `ingest_announces` (audit) and `directory_resources` (effective)
      transactionally.
- [x] **M2-T1a** Idempotency on `(resource_id, as_of)` per §8.6.
- [x] **M2-T1b** §8.10 anti-rollback (reject `as_of < indexed.as_of`).
- [x] **M2-T1c** §8.10 takedown-in-force gate (reject `as_of <= effective_at`).
- [x] **M2-T1d** §8.10 skew window (`signature_stale` for `as_of` past
      `CHADEX_AS_OF_SKEW_SECONDS`).
- [x] **M2-T7** `cx.directory.withdraw` — happy path + delete from index +
      audit log.

### M2 deferred (these are real and required)

- [ ] **M2-T2** **JWS verification of `discovery_state.proof`**. Today we
      only check the proof envelope shape. We must:
      1. Resolve the resource DID document (integrate `contrix-sdk`
         resolver chain — see soland's `did_resolver_chain` + `jws_verify`
         for a working pattern).
      2. Resolve the `proof.verification_method` to a public key.
      3. Confirm the key is currently authoritative under the DID method's
         key-history (webvh witness chain, web fallback, etc.).
      4. Verify the detached JWS over the canonical `discovery_state` minus
         `proof.jws`.
      Same chain applies to `withdraw.governance_proof`.
- [ ] **M2-T3** **Source-ref sanity** for first ingest of a resource: pull
      at least `source_refs[0]` via `GET /api/v1/events?...` against the
      claimed `principal_server_did` and confirm it resolves. Cache result
      to skip on subsequent re-announces of same resource.
- [ ] **M2-T4** `accept_policy_kind=trust_root_signed` — accept a separate
      VC / governance signature accompanying the announce.
- [ ] **M2-T5** Pull-mode worker actually fetches and verifies. The worker
      shell exists in `src/ingest/pull_worker.rs`; it currently only logs
      eligible work. See M3 for the full integration.
- [ ] **M2-T6** **Webhook fanout** for `cx.directory.subscribe`. Today the
      route returns `unsupported_feature`. Implement HMAC-signed POST to
      `webhook_endpoint` on every accepted ingest matching the
      subscription's `resource_filter`. Replay-protect by including
      `subscription_id + indexed_at` in the signed body.
- [ ] **M2-T8** Operator-takedown path (§8.7 path 3). Add an admin-only
      handler `POST /api/admin/v1/takedown` that writes a `withdrawals` row
      with `kind=operator_takedown`, audit row with `OperatorTakedown`
      kind, and emails / DIDcomms the resource governance contact (§8.7
      explicitly requires both audit and notification).
- [ ] **M2-T9** Per-resource / per-IP rate limiting. Drop excess requests
      with `rate_limited`. soland's `RateLimiterMiddleware` is the
      reference pattern.

---

## M3 — Pull-mode + freshness worker ☐

The worker shell `PullWorker::spawn` already wakes on the configured
period and selects entries past `next_revalidation_after`. All the
follow-through is here.

- [ ] **M3-T1** HTTP client to fetch
      `GET {principal_server_did → endpoint}/api/v1/events?subject=...
       &kind=cx.{kind}.discovery&state_only=true&after_revision=...`.
- [ ] **M3-T2** Resolve `principal_server_did` to an HTTPS endpoint via
      DID document `service` entries.
- [ ] **M3-T3** Run M2-T2 verify chain on the pulled state and re-upsert
      `directory_resources` exactly as `announce` does.
- [ ] **M3-T4** Mark `consecutive_failures` and `last_error` on
      `pull_subscriptions` rows on transient failures; back off
      exponentially.
- [ ] **M3-T5** After grace expiry without success, mark `stale=true`;
      after another 24h delete the entry and write
      `RevalidationFailed` audit.
- [ ] **M3-T6** Common-Space gating for `search_users` — once we can
      fetch authoritative membership lists from `principal_server_did`,
      we can let search_users return matching members the requester
      shares a Space with.

---

## M4 — Search index quality ☐

- [ ] **M4-T1** Add `pg_trgm` extension migration; create trigram index on
      `(public_projection->>'name')` and `(public_projection->>'summary')`.
- [ ] **M4-T2** Add tsvector column + GIN index for full-text search;
      maintain via trigger.
- [ ] **M4-T3** Implement scope filters (`organization_did`,
      `parent_space_id`) in `search_spaces`.
- [ ] **M4-T4** Implement keyset pagination cursors (encoding
      `(score, indexed_at, resource_id)`).
- [ ] **M4-T5** Bucket-based ordering for `member_count_bucket` so client
      ranking does not leak ordering bias on hidden buckets (§3 normative
      bucket grid).

---

## M5 — Private Contact Discovery (PSI) ☐

Spec: discovery-directory.md §6.

- [ ] **M5-T1** Implement RFC 9497 VOPRF (`OPRF(ristretto255, SHA-512)`)
      using `voprf` crate or hand-roll on `curve25519-dalek`.
- [ ] **M5-T2** Build server OPRF key with epoch rotation (default 7-day
      rotation, max 90).
- [ ] **M5-T3** Implement Round 1 (`phase=blind`) — return blind-evaluated
      points + `padding_count`.
- [ ] **M5-T4** Implement Round 2 (`phase=match`) — fixed-cardinality
      hit bitmap with dummy padding.
- [ ] **M5-T5** Per-epoch `max_psi_queries_per_epoch` enforcement.
- [ ] **M5-T6** Update `cx.directory.describe.discovery_profiles` to
      include `cx.private_contact_discovery.v1` only when M5 is feature-
      complete.

---

## M6 — Anti-enumeration hardening ☐

- [ ] **M6-T1** Real timing equalization beyond floor: variance
      modulation + per-route latency budget so the average difference
      between hit and miss is below a configurable threshold.
- [ ] **M6-T2** Member-count bucketing pipeline: when a Space ingest
      carries an exact `member_count`, project to bucket per §3.x and
      reject any non-grid value with `invalid_response`.
- [ ] **M6-T3** Cross-directory divergence detector — periodically poll
      *other* directories that index the same DID and flag rows where
      `policy_revision` materially differs.
- [ ] **M6-T4** Audit log feed (`GET /api/admin/v1/audit?since=...`) for
      operator dashboards.
- [ ] **M6-T5** Replay-detection bloom-filter on `request_digest` so very
      large announce traffic does not blow up the table scan we use
      today.

---

## M7 — Operator console (Dioxus) ☐

- [ ] **M7-T1** Set up Dioxus crate `chadex-admin/` (single-page web app).
- [ ] **M7-T2** Page: allowlist management (CRUD on `accept_allowlist`).
- [ ] **M7-T3** Page: pending operator-review queue.
- [ ] **M7-T4** Page: takedown form + audit log viewer.
- [ ] **M7-T5** Page: `directory_resources` browser with search +
      `divergent?` filter.

---

## M8 — Conformance + cotest hookup ☐

- [ ] **M8-T1** Add `cx.profile.directory_service.v1` profile entry to
      `contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json`.
- [ ] **M8-T2** Implement the §12 conformance test list under `tests/it/`
      using `testcontainers` for an ephemeral Postgres + a mock resource
      Principal Server.
- [ ] **M8-T3** Wire chadex into cotest (`../cotest`) so
      multi-server scenarios can include a real Directory.
- [ ] **M8-T4** Publish a baseline conformance report to
      `contrix-spec/spec/v1/artifacts/reports/`.

---

## Cross-cutting / cleanup backlog

- [ ] **C-1** Replace the manual diesel `ToSql`/`FromSql` impls with
      `#[derive(diesel_derive_enum::DbEnum)]` once the version aligns with
      diesel 2.3.
- [ ] **C-2** Move test fixtures to `chadex-testing` crate so cotest can
      reuse them.
- [x] **C-3** Add `tarpaulin.toml` for code coverage parity with the SDK.
- [x] **C-4** Add `deny.toml` (license + advisory checks) like soland.
- [x] **C-5** Add `typos.toml` matching the SDK's tolerances.

---

## Parallelization map

Tasks that can be picked up in parallel without merge conflicts:

| Stream            | Tasks                                                                         |
| ----------------- | ----------------------------------------------------------------------------- |
| **Stream A — verify chain**   | M2-T2, M2-T3 (one contributor; touches `src/ingest/verify.rs` + DID resolver)  |
| **Stream B — pull + worker**  | M3-T1..T5 (touches `src/ingest/pull_worker.rs`)                                |
| **Stream C — search quality** | M4-T1..T5, M1-D1, M1-D3 (touches `src/query/*` and migrations)                 |
| **Stream D — PSI**            | M5-T1..T6 (new module `src/query/psi/` — independent of all others)            |
| **Stream E — anti-enum**      | M6-T1..T5 (touches `src/filter/*` only)                                        |
| **Stream F — admin UI**       | M7-T1..T5 (separate crate `chadex-admin/`)                                     |
| **Stream G — conformance**    | M8-T1..T4 (touches `tests/it/` and external profile JSON)                      |

Streams A and B share the `principal_server_did` HTTP client; pick one
contributor for that helper to avoid duplicated work.

Streams D and F have no shared files with the rest — best for new
contributors.

---

## Spec ↔ implementation cross-reference

| Spec clause                                   | Code                                            |
| --------------------------------------------- | ----------------------------------------------- |
| §7 Directory Service Role                     | `src/lib.rs` module decomposition; README       |
| §7.3 invariants 1-6                           | `src/ingest/announce.rs`, `src/audit.rs`        |
| §8.1 bidirectional opt-in                     | `src/ingest/verify.rs::directory_services_lists_self` |
| §8.2 ingest modes                             | `src/config.rs::ingest_modes`                   |
| §8.3 announce request shape                   | `src/ingest/announce.rs::AnnounceRequest`       |
| §8.4 pull mode                                | `src/ingest/pull_worker.rs` (skeleton)          |
| §8.5 5-step verify chain                      | `src/ingest/verify.rs::VerifyContext::verify`   |
| §8.6 freshness / TTL                          | `src/config.rs` + `pull_worker::mark_stale_past_grace` |
| §8.7 withdrawal three paths                   | `src/ingest/withdraw.rs` (path 2); M2-T8 (path 3) |
| §8.9 describe extensions                      | `src/query/describe.rs`                         |
| §8.10 anti-abuse                              | `src/ingest/verify.rs` + announce rollback gate |
| §9.1 result envelope                          | `src/filter/result.rs::ResultEnvelope`          |
| §3 / §10 anti-enumeration                     | `src/filter/enumeration.rs`                     |
| §12 conformance tests                         | M8-T2                                           |
