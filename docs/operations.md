# Operations

`GET /health` reports process liveness; `GET /readyz` checks PostgreSQL
readiness. Prometheus metrics are on the separate `TEABAY_METRICS_BIND`
listener (default `127.0.0.1:9095`) at `/metrics`. Only mounted Realm search
and resolve latency series are emitted. The public index is intentionally
empty in a fresh installation, so empty search/resolve is expected.

For operator review, use `GET /_teabay/admin/audit` with a valid bearer token
and `GET /_teabay/admin/audit/verify` to check the append-only digest chain.
The Dioxus console in `crates/admin` exposes only those two actions. Audit
data is operational history and never a public discovery index.

There is no Directory write admission, takedown, allowlist, revalidation
worker, webhook retry, or PCD batch to operate in current-v1. If an old
database contains rows from retired schema, do not copy them into
`directory_public_realm_entries`. Use the fresh-schema test and the mounted
OpenAPI/ServiceDescribe surfaces when auditing deployment drift.
