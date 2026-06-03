# Heartbeat Operator Guide

P2E.5 introduced heartbeat-driven freshness for `directory_resources`. This
page covers the operator-facing surface: how to send a heartbeat, what
metrics to watch, and how teabay reacts when a resource stops heartbeating.

## What A Heartbeat Does

A heartbeat is a lightweight `POST /_cokret/find/directory/heartbeat` from a
Principal Server that already owns a published resource. The body identifies
the resource and the operator-claimed `expires_at`. teabay validates the
HTTP signature, then updates `directory_resources.last_refreshed_at` and
`expires_at` for the matching row.

A heartbeat is the cheap path: no announce envelope, no projection diff, no
discovery state churn. It exists so a long-lived resource can keep its row
out of the "stale" bucket without re-publishing the full state on every
TTL cycle.

## When To Send

- Whenever the previous `expires_at` is within `revalidation_grace`
  (default 1h) of now.
- Whenever the operator wants to extend `expires_at` ahead of the published
  TTL — e.g. a maintenance window or a known burst.

The teabay-side cap is the configured `TEABAY_MAX_TTL_SECONDS` (default 7d,
hard ceiling 30d). A heartbeat that requests a longer TTL is clamped, not
rejected.

## What Happens If You Stop

Two background workers cooperate:

1. **Freshness sweep** (`crate::ingest::freshness_worker`) runs every 10
   minutes. It marks `stale = true` for rows whose `expires_at < now()`.
   Query handlers filter on `stale = false`, so a stale row is hidden from
   search/resolve within one sweep cycle.
2. **Expiry purge** (`crate::workers::expiry`, P5) runs every 30 minutes
   (env: `TEABAY_EXPIRY_INTERVAL_SECONDS`). It deletes rows whose
   `expires_at < now() - 24h`, removing them from the database entirely.
   The 24h grace window gives operators a one-business-day window to
   recover a wrongly-expired row.

## Metrics To Monitor

- `teabay_expired_rows_purged_total{table="directory_resources"}` — counter
  incremented by the expiry worker on every successful purge. A sudden spike
  signals that a Principal Server stopped heartbeating; a flat line means
  nothing is being deleted.
- `teabay_ingest_total{kind="heartbeat"}` *(planned)* — once the heartbeat
  ingest ships its own per-outcome counter, alert on a missing-refresh
  pattern: heartbeat-volume drop > 50% over a 1h window against a 7d
  baseline.

## Missed Heartbeat Playbook

1. Confirm the source Principal Server is up (`/health` on its side).
2. Confirm time sync between teabay and the source — clock skew greater
   than `TEABAY_AS_OF_SKEW_SECONDS` (default 5 min) will reject the
   heartbeat at the verify step.
3. Inspect `directory_audit` for the most recent heartbeat or announce
   event for the resource.
4. If the row was already purged by the expiry worker, the operator must
   re-announce the resource with a fresh `announce_id`; heartbeat alone
   will not resurrect a deleted row.
