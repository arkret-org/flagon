# Security Policy

## Reporting Vulnerabilities

Report suspected vulnerabilities privately to the Contrix maintainers. Do not
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
- Admin bearer authentication for `/api/admin/v1/*`.
- Anti-enumeration filtering and timing equalization.
- Private Contact Discovery rate limits and epoch key retention.
- Pull-mode revalidation and stale-row deletion.
- Audit log integrity for ingest, takedown, and admin resource edits.

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

`TEABAY_ADMIN_TOKEN` is fail-closed for `/api/admin/v1/*`: unset, empty,
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
