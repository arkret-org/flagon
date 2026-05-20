# Changelog

All notable changes to teabay (Contrix v1 Directory Service) live here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Round R2/R3 (2026-05-20) — 17 P0/P1 tasks closed against contrix-spec

#### Added

- **T14 — Federation idempotency cache key extension.** The `cx.directory.
  announce` replay cache key now includes the four federation-identity
  fields: `Source-Service-DID` header, `verification_method` (from the
  discovery proof), `service_binding_ref` header, and
  `origin_key_state_hash` header. On a cache hit the announce handler
  re-runs the §8.5 capability chain; if the new check fails (e.g. the
  source service key has been revoked) the cached body is served with
  `historical_only=true` and no new side effects are triggered. New audit
  kind `ingest_historical_only` records the replay-after-revocation path.
  `ingest_announces` grew matching columns (`source_service_did`,
  `verification_method`, `service_binding_ref`, `origin_key_state_hash`,
  `historical_only`) so the audit trail captures the full cache key.
- **T17 — `consent_revoke{scope=any}` directory reachability
  invalidation.** New admin endpoint `POST /api/admin/v1/consent-revoke`
  (bearer-auth) takes a `consent_revoke` broadcast from soland and
  **soft-deletes** affected `directory_resources` rows via the new
  `reachability_revoked_at` / `reachability_revoked_reason` columns —
  audit-preserving UPDATE, never DELETE. Search face hides revoked rows;
  resolve still surfaces them so in-flight callers can observe the
  tombstone. Best-effort tombstone webhook fanout reuses the
  `cx.directory.subscribe` channel. New audit kind
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

Round-scoped follow-up markers (grep for `TODO(round23-T07)` /
`TODO(round23-T14)`):

- `round23-T07` — split the directory row by introducing a distinct
  `realm` resource_kind (currently piggybacking on `space`).
- `round23-T14` — plumb `Source-Service-DID` and
  `origin_key_state_hash` into the pull worker so pull-mode replays
  share cache keys with push-mode replays.
