# Security Policy

## Reporting Vulnerabilities

Report suspected vulnerabilities privately to the Cokret maintainers. Do not
open a public issue with exploit details, credentials, private keys, admin
tokens, or production resource identifiers.

Include:

- affected commit or release
- affected endpoint or workflow
- reproduction steps
- expected impact
- logs or traces with secrets redacted

## Supported Versions

teabay is pre-1.0. Security fixes are applied to the active `main` development
line unless a release owner declares a supported release branch.

## Security-Sensitive Areas

- RFC 9421 HTTP Message Signature enforcement on ingest endpoints.
- DID method and trust-domain verification.
- Accept policy and allowlist enforcement.
- Admin bearer authentication for `/_teabay/admin/*`.
- Anti-enumeration filtering and timing equalization.
- Private Contact Discovery rate limits and epoch key retention.
- Pull-mode revalidation and stale-row deletion.
- Audit log integrity for ingest, takedown, and admin resource edits.
- **Circle isolation (CKP-0007).** See "Hard Invariants" below.

## Hard Invariants

### Circle is intra-Realm only — it MUST NEVER appear in the directory

CKP-0007 (spec floor `2b0d70d`) introduces `ck:circle:` as an
intra-Realm encrypted sub-boundary. teabay's anti-enumeration story
depends on the directory only ever indexing Realm-level discovery
state: a leak of Circle existence, membership, or routing metadata
into a directory query response (or even into the audit feed of a
divergent peer) would immediately defeat the bucket-grid /
blinded-miss / latency-tier protections that the rest of the
service relies on.

Enforcement points (all in `crates/server/src/`):

- `filter/circle_isolation.rs` is the single hard-reject point.
  - Any string value containing `ck:circle:` (case-insensitive,
    anywhere — not only as a prefix) → reject.
- `ingest/announce.rs` calls the rejector on `discovery_state` AND
  on the full serialized request envelope (catches smuggling via
  top-level `resource_id` / `principal_server_did` /
  `supersedes_announce_id`).
- `ingest/subscribe.rs` calls the rejector on `resource_filter`.
- `filter/enumeration.rs` documents that the `member_count_bucket`
  grid is Realm-only and that this guarantee depends on the
  circle_isolation guard above.

Wire response on reject is a stable low-information `schema_violation`
that does NOT echo the typed id back. The audit row captures the
violation for operator review.

### Anti-enumeration invariants

- A blinded miss (`not_found`) MUST be indistinguishable in shape,
  HTTP status, and latency tier from a clean miss. See
  `filter/enumeration.rs` (`pad_to_budget` + bucket grid).
- The bucket grid for `member_count_bucket` is the only directory
  surface that ever discloses membership cardinality. Implementations
  MUST emit one of the six normative bucket strings and MUST NOT add
  finer-grained buckets.
- A subscribe filter MUST NOT be allowed to leak the existence of any
  resource the subscriber wouldn't already be authorized to see.

## Deployment Guidance

Production deployments should set:

- `TEABAY_DEVELOPMENT_MODE=false`
- `TEABAY_REQUIRE_HTTP_SIG=true`
- `TEABAY_HTTP_SIG_PUBKEYS` with only trusted Ed25519 keys
- `TEABAY_ADMIN_TOKEN` to a strong bearer token
- `TEABAY_CORS_ALLOW_ORIGIN` to exact trusted origins
- `TEABAY_TRUST_DOMAIN` explicitly

Store secrets outside the repository and rotate them through the deployment
environment. teabay currently reads secrets from environment variables; a vault
adapter is not implemented.

For 1.0, environment variables are the formal secret backend. Vault, AWS Secrets
Manager, and similar adapters are out of scope until a post-1.0 design is
accepted.

`TEABAY_HTTP_SIG_PUBKEYS` must contain only trusted raw Ed25519 verifying keys
encoded as `keyid=BASE64URL32` pairs. The `keyid` must match the HTTP Message
Signature `keyid` sent by the Principal Server.

`TEABAY_ADMIN_TOKEN` is fail-closed for `/_teabay/admin/*`: unset, empty,
missing, or mismatched bearer tokens are rejected as unauthenticated. The
hardening status reports admin auth as `production` only when development mode
is off and this token is configured.

## Dependency Checks

Local and CI security checks include:

```bash
cargo deny check
cargo audit --ignore RUSTSEC-2025-0111 --ignore RUSTSEC-2025-0134
```

The ignored advisories match the current supply-chain policy for dev-only
Testcontainers dependency chains. Revisit them whenever those upstream packages
offer a safe upgrade path.
