# Webhook Retry, DLQ, and Monitoring

This page covers the HMAC-signed best-effort fanout used by the pending
takedown notifier (P5 HIGH) and the matching operator dashboard signals.

## Surface

`crate::workers::takedown_notifier::TakedownNotifier` scans
`pending_takedowns` rows whose `notification_status` is `NULL`, `"pending"`,
or `"retry:*"` and whose `next_notification_after <= now()`, then dispatches a
signed POST to every endpoint registered in `pending_takedown_webhooks`.

## Wire Contract

```http
POST /your-webhook
content-type: application/json
x-teabay-event: pending-takedown
x-teabay-webhook-id: <opaque>
x-teabay-signature: sha256=<hex>

{
  "pending_id": "...",
  "resource_kind": "realm",
  "resource_id": "ak:realm:...",
  "reason": "...",
  "proposed_by": "ak:did_core:web:operator.example",
  "proposed_at": "2026-05-27T08:00:00Z"
}
```

The signature is `HMAC-SHA256(secret, raw_body_bytes)`, hex-encoded, where
`secret` is the per-row `pending_takedown_webhooks.secret` BYTEA. Subscribers
MUST verify the signature before treating the payload as authentic.

## Retry Schedule

Each dispatch attempt is recorded by mutating `notification_status`. After
the first failure the row is rescheduled to `retry:attempt:1:after:60s`,
then `retry:attempt:2:after:300s`, then `retry:attempt:3:after:900s`.
The retry text is diagnostic; the actual gate is
`pending_takedowns.next_notification_after`, which is advanced to
`now() + backoff` on every retry.

The minimum attempt budget before DLQ is `TAKEDOWN_MIN_ATTEMPTS = 3`. The
backoff schedule is intentionally short on the first hop (1 min) so a
flaky endpoint does not block urgent takedown propagation, then widens to
15 minutes so a sustained outage does not saturate the worker pool.

## DLQ

After three consecutive failed dispatches the row is marked
`notification_status = "dlq:attempt:3"`. The notifier skips DLQed rows on
subsequent passes; operators recover a row by manually updating the status
back to `"retry:attempt:0:after:0s"` and setting
`next_notification_after <= now()`.

Every DLQ transition emits exactly one
`teabay_takedown_notification_failures_total{stage="dlq"}` increment.

## Metrics

| Metric | Type | Meaning |
| --- | --- | --- |
| `teabay_takedown_notification_failures_total{stage="attempt_failed"}` | counter | Single dispatch attempt failed (network error or non-2xx response). Multiple per row are expected before DLQ. |
| `teabay_takedown_notification_failures_total{stage="dlq"}` | counter | Row exhausted its retry budget and was moved to DLQ. Alert: `rate(... ) > 0` over 5m. |

Suggested dashboards:

- **Dispatch failure rate**: `rate(teabay_takedown_notification_failures_total{stage="attempt_failed"}[5m])`.
- **DLQ count (alerting)**: `increase(teabay_takedown_notification_failures_total{stage="dlq"}[15m])`.
- **Per-endpoint health**: pair with reverse-proxy access logs keyed on
  `x-teabay-webhook-id` for endpoint-level dashboards.

## Configuration

| Variable | Default | Purpose |
| --- | ---: | --- |
| `TEABAY_TAKEDOWN_NOTIFIER_INTERVAL_SECONDS` | `60` | Worker tick. 0 disables the worker entirely. |

The worker uses the shared db pool, so its concurrency is bounded by
`TEABAY_DB_POOL_MAX_SIZE`.
