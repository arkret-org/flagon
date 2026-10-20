# Deploying the read-only Directory

This service implements only the public Realm read bundle. Deploying it does
not enroll any Realm or populate a fresh index. Do not import old
`directory_resources` rows: their Station authority and opt-in were not
verified against the current governance contract.

Set `DATABASE_URL`, `FLAGON_SERVICE_DID`, and the operator-verified
`FLAGON_SERVICE_METHOD_HISTORY_HEAD` and `FLAGON_SERVICE_VERSION_ID`.
Production should set `FLAGON_TRUST_DOMAIN` explicitly and
`FLAGON_DEVELOPMENT_MODE=false`. See `.env.example` for the supported
listener, CORS, connection-pool, and Realm query-rate-limit knobs. The
fresh-install squash migration is applied at startup. Treat schema replacement
as a development clean break, not as a production migration plan; recover an
existing production database from a reviewed backup and migration procedure.

`/_flagon/admin/audit` and `audit/verify` require admin authentication.
`FLAGON_ADMIN_TOKEN` is honored only when development mode is true. Production
uses an active rotating HMAC credential from `admin_tokens` and requires
`FLAGON_ADMIN_CSRF_TOKEN` at startup. Serve the API behind TLS and restrict
browser CORS to trusted origins.

Validate the release before exposure:

```bash
cargo check --all-targets
cargo test --workspace
cargo test -p server --lib fresh_schema_has_only_empty_public_realm_index -- --include-ignored --nocapture
```

The real-PostgreSQL test checks the exact fresh schema whitelist and that the
public Realm index is empty. CI runs this test explicitly. Retired
announce/withdraw operation selectors remain unknown and fail closed.

After starting with the current fresh schema, follow [private index maintenance](operations.md) to populate the index. The maintenance process uses a separately provisioned PostgreSQL role and opens no HTTP listener.
