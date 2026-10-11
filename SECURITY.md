# Security policy

Report suspected vulnerabilities privately to the Arkret maintainers. Do not
publish credentials, private keys, production Realm identifiers, or exploit
details. Include the affected commit, endpoint, reproduction, expected
impact, and redacted logs.

Flagon is pre-1.0; security fixes target active `main` unless a release owner
names another supported branch.

The D2 candidate is read-only. `announce` and `withdraw` have no mounted
route because authenticated current-governance and opt-in evidence are not
yet normatively closed (arkret-work spec-open 0350). Never treat a public
Directory hit as membership, capability, join, history, or governance proof.
Never migrate legacy unverified rows into the new public Realm index.

Security-sensitive surfaces are current service DID resolution commitments,
Realm query anti-enumeration and rate limits, production admin rotating-HMAC
authentication, the audit digest chain, database credentials, and strict
separation between the public index and operator audit data. Production
should use TLS at the reverse proxy, explicit trusted CORS origins, protected
secret injection, and `FLAGON_DEVELOPMENT_MODE=false`.
