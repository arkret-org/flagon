//! Private Contact Discovery via OPRF (spec §6).
//!
//! v1 core requires RFC 9497 VOPRF with `OPRF(ristretto255, SHA-512)`. This
//! file is a deliberate scaffold — implementing OPRF + 2-round PSI is a
//! non-trivial cryptographic effort tracked separately under M5 in
//! `_todos.md`. The handler currently advertises support via `describe`
//! (`discovery_profiles` will list `cx.private_contact_discovery.v1` once
//! M5 lands) but rejects any actual request with `unsupported_feature`.

use salvo::prelude::*;

use crate::error::ErrorCode;

#[handler]
pub async fn private_contact_discovery(_req: &mut Request, res: &mut Response) {
    ErrorCode::UnsupportedFeature.render(
        res,
        "cx.private_contact_discovery.v1 not yet implemented (chadex _todos.md M5)",
    );
}
