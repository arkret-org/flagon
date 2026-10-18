# Security policy

Report suspected vulnerabilities privately to the Arkret maintainers. Do not
publish credentials, private keys, production Realm identifiers, or exploit
details. Include the affected commit, endpoint, reproduction, expected
impact, and redacted logs.

Flagon is pre-1.0; security fixes target active `main` unless a release owner
names another supported branch.

Current-v1 is read-only by final protocol ruling. Only describe,
search_realms, and resolve_realm are advertised. Retired `announce` and
`withdraw` requests must fail closed without changing the index; private
contact discovery and PSI are unavailable. See the normative
[Directory contract](https://github.com/arkret-org/arkret-spec/blob/main/spec/v1/zh/discovery/discovery-directory.md)
and [server threat model](https://github.com/arkret-org/arkret-spec/blob/main/spec/v1/zh/security/server-threat-model.md).
Never treat a public Directory hit as membership, capability, join, history,
or current-authority evidence. Never migrate legacy unverified rows into
the public Realm index.

Deployment-private index maintenance is outside the Arkret interoperability
surface. Its authorization, input validation, expiry, and operator audit
must be assessed within the deployment; it must not be exposed as a protocol
write through ServiceDescribe, an SDK, or a private HTTP alias. Query results
remain limited to closed, unexpired public Realm metadata. Hidden, expired,
unconfirmed, and absent entries remain indistinguishable.

Security-sensitive surfaces are current service DID resolution commitments,
Realm query anti-enumeration and rate limits, production admin rotating-HMAC
authentication, the audit digest chain, database credentials, and strict
separation between the public index and operator audit data. Production
should use TLS at the reverse proxy, explicit trusted CORS origins, protected
secret injection, and `FLAGON_DEVELOPMENT_MODE=false`.
