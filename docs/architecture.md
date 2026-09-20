# D2 Directory architecture

Teabay is a rebuildable public Realm metadata discovery hint. A centrally
governing Station, not the Directory, is authoritative for Realm governance,
membership, history, capabilities, and join. Directory results cannot prove
current governance or opt-in.

The mounted public surface is `describe`, `search-realms`, and `resolve-realm`
only. ServiceDescribe advertises the exact
`ak.operation_bundle.directory_service.public_read.v1` bundle and does not
claim the full Directory profile or HTTP core. Search and resolve read only
from `directory_public_realm_entries`; a fresh installation starts with zero
rows. Legacy source-ref projections are never copied into that table.

The initial schema creates only the public Realm table, `admin_tokens`, and
`directory_audit` (plus Diesel's migration ledger). The latter two are
operational, not public discovery resources. The admin HTTP surface supports
audit feed and digest-chain verification only; it cannot edit Realm metadata.

No announce/withdraw admission, callback, exact committed-event resolve,
PCD/PSI, or Organization/Actor/Applet/Handle discovery route is mounted.
Before a write path can exist, spec-open 0350 must settle authenticated
current-governance and opt-in evidence and its exact wire contract.
