# Deploying the D2 read-only Directory

This candidate serves only the public Realm read bundle. Deploying it does
not enroll any Realm or populate a fresh index. Do not import old
`directory_resources` rows: their Station authority and opt-in were not
verified against the current governance contract.

Set `DATABASE_URL`, `TEABAY_SERVICE_DID`, and the operator-verified
`TEABAY_SERVICE_METHOD_HISTORY_HEAD` and `TEABAY_SERVICE_VERSION_ID`.
Production should set `TEABAY_TRUST_DOMAIN` explicitly and
`TEABAY_DEVELOPMENT_MODE=false`. See `.env.example` for the supported
listener, CORS, connection-pool, and Realm query-rate-limit knobs. The
fresh-install squash migration is applied at startup. Treat schema replacement
as a development clean break, not as a production migration plan; recover an
existing production database from a reviewed backup and migration procedure.

`/_teabay/admin/audit` and `audit/verify` require admin authentication.
`TEABAY_ADMIN_TOKEN` is honored only when development mode is true. Production
uses an active rotating HMAC credential from `admin_tokens` and requires
`TEABAY_ADMIN_CSRF_TOKEN` at startup. Serve the API behind TLS and restrict
browser CORS to trusted origins.

Validate the release candidate before exposure:

```bash
cargo check --all-targets
cargo test --workspace
cargo test -p server --lib fresh_schema_has_only_empty_public_realm_index -- --include-ignored --nocapture
```

The Docker-backed test checks the exact fresh schema whitelist and that the
public Realm index is empty. CI runs this test explicitly. Announce/withdraw
are unsupported and must remain fail-closed until spec-open 0350 is closed by
a formal contract and its implementation.
