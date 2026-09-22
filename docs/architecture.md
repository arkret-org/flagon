# Read-only Directory architecture

Teabay is a rebuildable public Realm metadata discovery hint. A centrally
governing Station, not the Directory, is authoritative for Realm governance,
membership, history, capabilities, and join. Directory results cannot prove
current governance or opt-in.

The mounted public surface is `describe`, `search-realms`, and `resolve-realm`
only. ServiceDescribe advertises the exact
`ak.operation_bundle.directory_service.public_read.v1` bundle and does not
advertise any HTTP-core write bundle. The Directory profile itself is
read-only and is advertised separately from third-party verification evidence.
Search and resolve read only
from `directory_public_realm_entries`; a fresh installation starts with zero
rows. Legacy source-ref projections are never copied into that table.

The initial schema creates only the public Realm table, `admin_tokens`, and
`directory_audit` (plus Diesel's migration ledger). The latter two are
operational, not public discovery resources. The admin HTTP surface supports
audit feed and digest-chain verification only; it cannot edit Realm metadata.

No announce/withdraw admission, callback, exact committed-event resolve,
PCD/PSI, or Organization/Actor/Applet/Handle discovery route is mounted. The
old write operations, DTOs, proof carrier, and announce identifier namespace
are retired rather than dormant compatibility surfaces.
