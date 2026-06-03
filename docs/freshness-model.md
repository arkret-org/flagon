# Freshness Model

teabay indexes resource discovery state with explicit freshness fields so query
clients can reason about how recently the directory observed source truth.

## Stored Fields

`directory_resources` stores:

- `as_of`: source timestamp carried by the accepted discovery state.
- `indexed_at`: local time when teabay accepted the state.
- `source_refs`: source event IDs clients can re-fetch from the Principal
  Server.
- `policy_revision`: optional source policy revision.
- `effective_ttl_seconds`: TTL selected by teabay after applying defaults and
  caps.
- `next_revalidation_after`: `indexed_at + effective_ttl_seconds`.
- `stale`: true after revalidation remains overdue past the configured grace.
- `divergent`: true when the optional divergence worker observes inconsistent
  peer directory state.
- `via_services`: Principal Server service DIDs clients should use for follow-up
  protocol work.

Query responses surface the protocol result envelope fields, including `as_of`,
`source_refs`, `policy_revision`, `stale`, `divergent`, and `via_services` when
applicable.

## TTL Selection

Announce requests may include `ttl_seconds`.

- Missing `ttl_seconds` uses `TEABAY_DEFAULT_TTL_SECONDS`.
- Requested TTLs must be positive.
- Requested TTLs cannot exceed `TEABAY_MAX_TTL_SECONDS`.
- `TEABAY_MAX_TTL_SECONDS` itself cannot exceed the 30-day hard ceiling.

The effective TTL is persisted with both the announce audit row and the current
resource row.

## Monotonic `as_of`

teabay rejects an announce when its `as_of` is older than the currently indexed
row for the same `(resource_kind, resource_id)`. This prevents rollback of the
effective index through stale signed state.

The verification chain also enforces `TEABAY_AS_OF_SKEW_SECONDS` so incoming
state cannot be too far from local server time.

## Push Path

Push announce stores:

1. The accepted announce in `ingest_announces`.
2. The effective public projection in `directory_resources`.
3. `next_revalidation_after` from the local accept time and effective TTL.
4. An audit event.

An idempotent replay of the same natural key returns cached freshness metadata
instead of creating a second logical accept.

## Pull Path

Pull mode is enabled when `TEABAY_PULL_INTERVAL_SECONDS` is greater than zero.
The worker scans due rows and fetches state from the resource Principal Server
events endpoint. A successful pull follows the same verify, projection, storage,
and audit path as push announce.

On failure, teabay records failure state in `pull_subscriptions` and schedules a
retry with exponential backoff capped at one day.

## Stale And Delete Windows

When `next_revalidation_after` is older than
`TEABAY_REVALIDATION_GRACE_SECONDS`, teabay marks the row `stale=true`.

If the row remains stale for another 24 hours beyond the grace cutoff, the pull
worker deletes it from `directory_resources` and writes a revalidation-failed
audit event. The source announce history remains in `ingest_announces`.

## Divergence

The divergence worker is disabled by default
(`TEABAY_DIVERGENCE_INTERVAL_SECONDS=0`). When enabled, it can mark rows
`divergent=true` if peer directory checks disagree with the local view.

## Heartbeat (P2E.5)

Migration `20260526010000_add_freshness` adds two operator-facing columns:

- `last_refreshed_at`: most recent successful heartbeat or announce.
- `expires_at`: `last_refreshed_at + effective_ttl_seconds`; the
  expiry sweep treats rows past this as stale.

A heartbeat is the cheap "I'm still here" signal. An announcer that
already has an up-to-date `discovery_state` in the directory does not
need to re-sign + re-submit the full announce body; it calls
`POST /_cokret/find/directory/announce/heartbeat` with the `announce_id` it
received from the original announce, and the directory bumps
`last_refreshed_at` / `expires_at` forward by one TTL window.

Request shape:

```json
{
  "announce_id": "anc_01J...",
  "ttl_seconds": 3600
}
```

`ttl_seconds` is optional; when omitted, the row's existing
`effective_ttl_seconds` is reused. When present, the directory caps it
at `TEABAY_MAX_TTL_SECONDS`.

Recommended cadence: half the row's `effective_ttl_seconds` (e.g.
30-minute heartbeats for an 1-hour TTL). The endpoint is rate-limited
on the same per-resource and per-IP buckets as `ck.directory.announce`.

Authorization:
- transport: RFC 9421 HTTP Message Signature middleware
  (`crate::middleware::http_sig`).
- content: the `X-Principal-Server-DID` header MUST match the row's
  `principal_server_did`. A mismatch returns
  `directory_not_authorized`. A missing or unknown `announce_id`
  returns the blinded `not_found`.

Behaviour after expiry: once `expires_at < now()`, the existing pull
worker stale-marking logic flips the row to `stale=true` after the
configured grace window and the deletion path takes over (see "Stale
And Delete Windows" above). The expiry sweep that runs purely on
`expires_at` (instead of on `next_revalidation_after`) is tracked by
`TODO(circle-rollout-P2E.5)` in `crates/server/src/ingest/heartbeat.rs`.

