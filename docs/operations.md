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

A separate `/readyz` endpoint is not implemented yet. Until it exists, pair
`/health` with an external PostgreSQL connection check in production probes.

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

## Admin Console

The admin SPA runs from `crates/admin/` and talks to `/api/admin/v1/*` using the
`TEABAY_ADMIN_TOKEN` bearer token.

```bash
cd crates/admin
dx serve --platform web --port 8080
```

Point the API base field at the teabay service, usually
`http://localhost:7781`, and use the configured admin token.

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

Use the admin console or `GET /api/admin/v1/audit` to review:

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

For stale or missing resources:

1. Check `pull_subscriptions.last_error`.
2. Confirm the resource Principal Server events endpoint is reachable.
3. Confirm `TEABAY_ACCEPTED_DID_METHODS` and accept policy still allow the
   resource.
4. Check whether the row was withdrawn or deleted after stale grace.
