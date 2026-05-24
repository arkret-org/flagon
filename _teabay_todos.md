# teabay — Release-Readiness Tasks

> Parent plan: [`../_todos_all.md`](../_todos_all.md)
> Project role: contrix Directory Service (spec §7-§9).
> Phase: **2 (track 2d)**.

## State at start (2026-05-24)

- 3 crates (server 10.0 k LoC, admin 1.8 k LoC, testing 9 LoC); Salvo + Diesel + Postgres + Dioxus admin.
- Full §7-§9 endpoint coverage: ingest (announce + withdraw + subscribe + pull-mode), query (search + resolve + private-contact-discovery), admin (audit/allowlist/resources/takedown/consent-revoke).
- Anti-enumeration: 6-tier bucketing + 25ms latency floor + SHA256-based jitter.
- Auth: RFC 9421 HTTP Message Signature (Ed25519); pluggable `HttpSigKeyDirectory`.
- Admin SPA: 5 tabs feature-complete (Resources, Allowlist, Takedown, Audit, Review).
- 0 scoped code TODO markers remain; release-readiness tasks continue below.
- CI: fmt + check + test + cargo-deny + clippy + typos + cargo audit + tarpaulin threshold + Trivy.
- Tests: 850-LoC conformance suite + health + timing-variance.
- Tarpaulin: 70% threshold configured in `tarpaulin.toml` and CI.
- Prometheus metrics + `/readyz` implemented; OTEL handoff documented via collector-side scrape/log collection until the next dependency-refresh slice can add in-process `tracing-opentelemetry`.
- Secret handling: env vars only; no vault integration.

## Phase 2 tasks

### Round-4 + round23 closures
- [x] §1 `crates/server/src/ingest/announce.rs:250,276,284` — finalize canonical-body digest domain once spec confirms (round4-fed-canonical).
- [x] §2 `crates/server/src/ingest/announce.rs:805` + `pull_worker.rs:225` — observe `Source-Service-DID` for cache-key alignment (round23-T14).
- [x] §3 `crates/server/src/ingest/announce.rs:637` — emit dedicated `realm` resource_kind once spec finalizes (round23-T07).

### Realm-rework refactor
- [x] §4 `crates/server/src/query/realm.rs:12` — split directory rows by `resource_kind` (realm vs space).
- [x] §5 `crates/server/src/query/actor.rs:10` — add explicit `realm_id` alias on actor scope.
- [x] §6 `crates/server/src/query/handle.rs` + migrations — rename Postgres `space` columns/indexes to `realm` (migration); generate compatibility view if needed.
- [x] §7 Run a final sweep — `grep -rni "chadex\|place_id\|Place\b" crates/` — expect zero hits.

### CI hygiene (master plan §5 — currently the biggest gap)
- [x] §8 Add `cargo clippy --all-targets --all-features -- -D warnings` to `ci.yml`.
- [x] §9 Add `typos` workflow.
- [x] §10 Add `cargo audit` (weekly + on PR).
- [x] §11 Set tarpaulin target ≥ 70%; fail CI on regression.
- [x] §12 Add Trivy scan to docker build.
- [x] §13 Add local cosign/SBOM artifact commands; do not push images or tags.

### Observability
- [x] §14 Document OpenTelemetry collector handoff; keep in-process `tracing-opentelemetry` exporter for the next dependency-refresh slice so this lock-preserving local slice does not touch `Cargo.lock`.
- [x] §15 Add Prometheus `/metrics` endpoint on a separate port via `TEABAY_METRICS_BIND` (default `127.0.0.1:9095`). Required series:
  - `teabay_ingest_total{kind,outcome}` (announce/withdraw/subscribe × verify-ok/digest-mismatch/etc.)
  - `teabay_query_latency_seconds{op}` (search-realms/resolve-realm/etc.)
  - `teabay_query_anti_enum_pad_seconds` (histogram)
  - `teabay_pull_worker_revalidations_total{outcome}`
  - `teabay_divergence_detected_total`
- [x] §16 Add `/readyz` (Postgres reachable + workers running) separate from `/health`.

### Secret handling
- [x] §17 Document `TEABAY_HTTP_SIG_PUBKEYS` provisioning end-to-end in `README.md` deployment section.
- [x] §18 Add a vault-adapter feature flag (optional Vault / AWS Secrets Manager). Or formally document env-var-only for 1.0.
- [x] §19 Confirm `TEABAY_ADMIN_TOKEN` enforcement when production mode = true (already in `/health` hardening probe — verify).

### Audit + receipts
- [ ] §20 Spec § 8.7 mentions signed receipts on takedown. Confirm `withdrawals.proof` carries enough signature info to be a verifiable receipt. If not, extend the schema.
- [ ] §21 Add an integration test that walks the 3-path takedown flow (resource state-change, resource withdraw, operator) end-to-end.

### Docs
- [x] §22 Add `docs/` directory with: architecture, deployment, operations, freshness model, anti-enumeration design rationale.
- [x] §23 Add `SECURITY.md` (currently missing).
- [x] §24 Add `CONTRIBUTING.md` (currently missing).
- [x] §25 Document admin-SPA build (`dx serve --platform web`) for contributors.

## Phase 5

- [ ] §26 External security review focused on anti-enumeration correctness + transport-signature auth.
- [ ] §27 Record local `v1.0.0` milestone.

## Exit gate (phase 2)

All of:
1. §1-§7 closed (round4 + realm-rework + round23 markers gone).
2. §8-§13 closed (CI hygiene matches master plan §5 baseline).
3. §14-§16 closed (observability deliverables).
4. Tarpaulin ≥ 70%.
5. Local internal milestone `v0.9.0` recorded in docs/todos.

## Notes

- The conformance test suite (`crates/server/tests/it/conformance.rs`) is excellent — preserve and extend it through phase 2.
- The `testing/` crate is a 9-LoC placeholder; consider deleting it or populating it with shared fixtures used by both teabay and cotest.
- The CHANGELOG already tracks R4 / R2/R3 wire breaks meticulously; keep that discipline.
