# External Security Review Readiness

This is a local readiness record for an external review package. It does not
claim that a vendor review has happened.

## Review Scope

Primary focus:

- anti-enumeration correctness for query and resolve endpoints
- RFC 9421 HTTP Message Signature enforcement on ingest routes
- withdrawal and takedown receipt verifiability
- admin bearer-token fail-closed behavior
- replay, idempotency, freshness, and rollback rejection

Out of scope for this readiness record:

- vendor attestation
- production penetration-test result
- public disclosure process signoff
- cryptographic audit of upstream dependencies

## Local Package Inventory

Include these files for reviewers:

- `README.md`
- `SECURITY.md`
- `docs/architecture.md`
- `docs/deployment.md`
- `docs/operations.md`
- `docs/anti-enumeration.md`
- `docs/freshness-model.md`
- `docs/takedown-receipts.md`
- `.github/workflows/ci.yml`
- `.github/workflows/audit.yml`
- `.github/workflows/typos.yml`
- `deny.toml`
- `tarpaulin.toml`
- `crates/server/src/middleware/http_sig.rs`
- `crates/server/src/filter/enumeration.rs`
- `crates/server/src/query/`
- `crates/server/src/ingest/`
- `crates/server/tests/`

## Evidence Commands

Run locally before sending the review package:

```bash
cargo +nightly fmt --all -- --check
cargo check --locked --all-targets
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
typos --config typos.toml .
cargo deny check
cargo audit --ignore RUSTSEC-2025-0111 --ignore RUSTSEC-2025-0134
cargo tarpaulin --config tarpaulin.toml --fail-under 70
scripts/trivy-scan.sh
scripts/local-artifacts.sh
```

If local path dependencies are temporarily ahead of the teabay manifest
constraint, record the exact `cargo` resolver error with the review package.

## Reviewer Questions

- Are hidden, unauthorized, withdrawn, and unknown resources
  indistinguishable on public query surfaces?
- Are anti-enumeration latency targets recorded and applied before result
  branch disclosure?
- Does HTTP signature enforcement fail closed for missing, unknown, malformed,
  or stale signatures?
- Are federation replay-cache keys bound to the round-4 trust-domain triad?
- Are operator takedown receipts independently verifiable from
  `withdrawals.proof` and the configured receipt verification method?
- Are resource-initiated withdrawals verifiable from the stored governance
  proof and signed payload?
