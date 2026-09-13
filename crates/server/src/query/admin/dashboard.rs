//! P2E.3 — operator dashboard stats endpoint.

use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use teabay_contracts::{DashboardKindCount, DashboardStats};

use super::require_admin;
use crate::error::ApiErrorCode;
use crate::ingest::DirectoryResourceKindDb;
use crate::state::AppState;

/// P2E.3 — operator dashboard stats. Cheap COUNT(*) aggregates over
/// the directory tables so the admin SPA can render a single-shot
/// overview without scanning the full audit feed.
#[handler]
pub async fn dashboard_stats(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(state) => state.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    if let Err(error) = require_admin(req, &state).await {
        error.render(res, "admin bearer token required");
        return;
    }
    let stats = match collect_dashboard_stats(&state).await {
        Ok(stats) => stats,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("dashboard stats: {error}"));
            return;
        }
    };
    res.render(Json(stats));
}

async fn collect_dashboard_stats(state: &AppState) -> anyhow::Result<DashboardStats> {
    use crate::schema::accept_allowlist::dsl as al;
    use crate::schema::directory_audit::dsl as au;
    use crate::schema::directory_resources::dsl as r;
    use crate::schema::ingest_announces::dsl as a;

    let mut conn = state.db().get().await?;

    let directory_resources: i64 = r::directory_resources
        .count()
        .get_result(&mut *conn)
        .await?;
    let stale_resources: i64 = r::directory_resources
        .filter(r::stale.eq(true))
        .count()
        .get_result(&mut *conn)
        .await?;
    let divergent_resources: i64 = r::directory_resources
        .filter(r::divergent.eq(true))
        .count()
        .get_result(&mut *conn)
        .await?;
    let realm_destroyed: i64 = r::directory_resources
        .filter(r::realm_destroyed_at.is_not_null())
        .count()
        .get_result(&mut *conn)
        .await?;
    let ingest_announces: i64 = a::ingest_announces.count().get_result(&mut *conn).await?;
    let audit_events: i64 = au::directory_audit.count().get_result(&mut *conn).await?;
    let allowlist_entries: i64 = al::accept_allowlist.count().get_result(&mut *conn).await?;

    let mut per_kind = Vec::with_capacity(5);
    for kind in [
        DirectoryResourceKindDb::Realm,
        DirectoryResourceKindDb::Organization,
        DirectoryResourceKindDb::Actor,
        DirectoryResourceKindDb::Applet,
        DirectoryResourceKindDb::Handle,
    ] {
        let count: i64 = r::directory_resources
            .filter(r::resource_kind.eq(kind))
            .count()
            .get_result(&mut *conn)
            .await?;
        per_kind.push(DashboardKindCount {
            resource_kind: kind.as_pg().to_owned(),
            count,
        });
    }
    per_kind.sort_by_key(|k| std::cmp::Reverse(k.count));

    Ok(DashboardStats {
        directory_resources,
        stale_resources,
        divergent_resources,
        realm_destroyed,
        ingest_announces,
        audit_events,
        allowlist_entries,
        per_kind,
        as_of: chrono::Utc::now().to_rfc3339(),
    })
}
