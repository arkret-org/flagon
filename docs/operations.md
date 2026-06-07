# Operations

This document covers day-two operation for teabay.

## Health And Readiness

`GET /health` returns:

- `ok`
- `service`
- `hardening`

The hardening block is derived from live configuration and includes
development-mode, HTTP signature, CORS, secret, admin auth, log redaction, and
rate-limit signals.

`GET /readyz` is the readiness probe. It returns `200` only when PostgreSQL is
reachable and every enabled background worker has emitted a recent heartbeat.
Disabled workers are reported with `enabled=false` and do not block readiness.

Use `/health` for process liveness and `/readyz` for load-balancer admission.

## Metrics And Telemetry

Prometheus metrics are exposed on a separate listener controlled by
`TEABAY_METRICS_BIND`; the default is `127.0.0.1:9095`.

```bash
curl http://127.0.0.1:9095/metrics
```

Required series:

- `teabay_ingest_total{kind,outcome}`
- `teabay_query_latency_seconds{op}`
- `teabay_query_anti_enum_pad_seconds`
- `teabay_pull_worker_revalidations_total{outcome}`
- `teabay_divergence_detected_total`
- `teabay_expired_rows_purged_total{table}` (P5 — expiry worker)
- `teabay_takedown_notification_failures_total{stage}` (P5 — takedown notifier)

## Log Redaction Defaults

In production mode (`TEABAY_DEVELOPMENT_MODE=false`) the following fields are
masked by default in structured logs:

- `resource_id` — emitted as the first 16 characters followed by `...` when the
  value exceeds 16 chars.
- `service_did` — emitted as the DID method (`did:web`, `did:webvh`, etc.) plus
  a SHA-256 prefix; the bare identifier is never logged.

Set `TEABAY_DEVELOPMENT_MODE=true` to disable masking for local debugging. The
hardening block on `/health` reports `log_redaction=production` when masking is
active and `log_redaction=disabled` in development mode so dashboards can alert
on accidental dev-mode deploys.

For OpenTelemetry backends, run an OTel Collector sidecar or agent that scrapes
the Prometheus endpoint and collects stdout/stderr tracing logs. The in-process
`tracing-opentelemetry` OTLP exporter is reserved for a dependency-refresh
slice; this release-hygiene slice keeps `Cargo.lock` unchanged.

## Logs

teabay uses `tracing`. Set `RUST_LOG` for local or production log verbosity:

```bash
RUST_LOG=info cargo run -p server
```

Use `RUST_LOG=debug` only for short investigations because ingest and query logs
can include identifiers that operators should treat as sensitive.

## Database Tasks

Migrations are embedded in the server crate and run at boot. For local manual
setup:

```bash
diesel setup
```

Back up PostgreSQL before deploying migrations or changing retention policy.
Keep backups encrypted and access controlled, because `directory_resources`,
`ingest_announces`, `withdrawals`, and `directory_audit` can contain sensitive
resource metadata.

Useful tables for operator inspection:

- `directory_resources`: current effective rows and freshness flags.
- `pull_subscriptions`: pull-mode state and failure counts.
- `directory_audit`: operator-readable ingest, takedown, admin, and
  revalidation activity.
- `withdrawals`: takedown and withdrawal receipts.

## Realm resource-kind migration

Fresh teabay installs use `realm` as the directory resource kind for
discoverable collaboration boundaries. Space containers are not indexed as
directory resources.

**Pre-flight (large datasets).** Take a backup before running schema changes.
Plan for ~1–2 ms per touched row on commodity SSD,
i.e. ~3 minutes per million rows of `directory_resources` plus
proportional time for `ingest_announces` and `directory_audit`.

**Run.**

```bash
DATABASE_URL=postgres://teabay@.../teabay diesel migration run
```

The migration is idempotent; fresh databases already carry the Realm resource
kind in the bootstrap schema.

**Verification.**

```sql
SELECT count(*) FILTER (WHERE resource_kind = 'realm') AS realms
  FROM directory_resources;
```

The `realms` count should match the number of discoverable Realm directory
entries expected for the deployment.

## Admin Console

The admin SPA runs from `crates/admin/` and talks to `/_cokret/local/admin/*` using the
development-only `TEABAY_ADMIN_TOKEN` bearer token or a production rotating
HMAC bearer.

```bash
cd crates/admin
dx serve --platform web --port 8080
```

Point the API base field at the teabay service, usually
`http://localhost:7781`, and use the configured development token or HMAC
credential.

## Pull Revalidation

Pull mode is enabled when `TEABAY_PULL_INTERVAL_SECONDS` is greater than zero.
The worker:

1. Finds non-stale rows whose `next_revalidation_after` has passed.
2. Fetches state from the resource Principal Server events endpoint.
3. Runs the same verification and projection path as push announce.
4. Resets failure state on success.
5. Uses exponential backoff on failure, capped at one day.
6. Marks rows stale after TTL plus grace.
7. Deletes rows after the stale grace window plus 24 hours.

Common checks:

```sql
select resource_kind, resource_id, next_pull_after, consecutive_failures, last_error
from pull_subscriptions
order by next_pull_after asc
limit 20;
```

```sql
select resource_kind, resource_id, stale, divergent, next_revalidation_after
from directory_resources
order by next_revalidation_after asc
limit 20;
```

## Audit Review

Use the admin console or `GET /_cokret/local/admin/audit` to review:

- accepted or rejected ingest
- pull revalidation success or failure
- resource withdrawal
- operator takedown
- allowlist changes
- direct admin resource edits

Every direct admin resource mutation writes an audit row.

## Incident Checklist

For suspected unauthorized ingest:

1. Rotate the affected key material outside the repository.
2. Update `TEABAY_HTTP_SIG_PUBKEYS`.
3. Restart the service.
4. Review `directory_audit` and `ingest_announces` for affected resource IDs.
5. Use operator takedown or resource withdrawal for rows that should no longer
   be searchable.

For receipt verification:

1. Load the `withdrawals.proof` JSONB value for the target `withdraw_id`.
2. For `kind=resource_withdraw`, verify `governance_proof.jws` over
   `signed_payload`.
3. For `kind=operator_takedown`, verify `receipt_proof.jws` over `statement`
   using `receipt_proof.verification_method`.
4. Confirm statement fields match the row's resource, reason, and timestamps.
5. See [Takedown receipts](takedown-receipts.md) for the exact receipt shapes.

For admin access checks:

1. Confirm `TEABAY_DEVELOPMENT_MODE=false` in production.
2. Confirm an active `admin_tokens` row exists for the caller's `key_id`.
3. Confirm requests use `Authorization: Bearer hmac:<key_id>:<ts>:<mac_base64>`.
4. Check `/health` and require `hardening.admin_auth_mode` to be `rotating_hmac`.
   A development/static bearer value in production means the deployment is using
   the wrong credential path and requests should be rejected.

For stale or missing resources:

1. Check `pull_subscriptions.last_error`.
2. Confirm the resource Principal Server events endpoint is reachable.
3. Confirm `TEABAY_ACCEPTED_DID_METHODS` and accept policy still allow the
   resource.
4. Check whether the row was withdrawn or deleted after stale grace.
