//! Public Realm metadata reads. Directory results are discovery hints, never
//! membership, join, history, capability or current-authority evidence.

use arkret_sdk::{
    DirectoryRealmSearchOutcome, DirectoryResolveRealmRequestBody,
    DirectorySearchRealmsRequestBody, PublicRealmDirectoryEntry, PublicRealmMetadata, RealmId,
};
use arkret_server::CursorBindingContext;
use chrono::{DateTime, Utc};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::error::ApiErrorCode;
use crate::query::rate_limit::{
    enforce_query_rate_limit, enforce_resolve_rate_limit, enforce_search_needle_rate_limit,
};
use crate::state::AppState;

#[allow(
    clippy::redundant_field_names,
    reason = "Diesel QueryableByName generates redundant initializers in this row mapping."
)]
mod public_row {
    use super::*;
    #[derive(Debug, diesel::QueryableByName)]
    pub(super) struct PublicRealmRow {
        #[diesel(sql_type = Text)]
        pub(super) realm_id: String,
        #[diesel(sql_type = Jsonb)]
        pub(super) public_metadata: JsonValue,
        #[diesel(sql_type = Timestamptz)]
        pub(super) indexed_at: DateTime<Utc>,
        #[diesel(sql_type = Timestamptz)]
        pub(super) expires_at: DateTime<Utc>,
    }
}
use public_row::PublicRealmRow;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SearchCursor {
    last_realm_id: String,
}

impl TryFrom<PublicRealmRow> for PublicRealmDirectoryEntry {
    type Error = String;

    fn try_from(row: PublicRealmRow) -> Result<Self, Self::Error> {
        // Never deserialize or migrate old source-ref projections:
        // they lack current-governance and public opt-in provenance.
        let entry = Self {
            realm_id: RealmId::new(row.realm_id).map_err(|error| error.to_string())?,
            public_metadata: serde_json::from_value::<PublicRealmMetadata>(row.public_metadata)
                .map_err(|error| format!("invalid closed public Realm metadata: {error}"))?,
            indexed_at: row.indexed_at,
            expires_at: row.expires_at,
        };
        entry.validate().map_err(|error| error.to_string())?;
        Ok(entry)
    }
}

#[handler]
pub async fn search_realms(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(state) => state.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("search-realms");
    if !enforce_query_rate_limit(req, res, &state) {
        return;
    }
    let body: DirectorySearchRealmsRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed search body: {error}"));
            return;
        }
    };
    if let Err(error) = body.validate() {
        ApiErrorCode::SchemaViolation.render(res, error.to_string());
        return;
    }

    let needle = body.query.unwrap_or_default().trim().to_owned();
    if !enforce_search_needle_rate_limit(res, &state, &needle) {
        return;
    }
    let limit = body.limit.unwrap_or(20).min(100) as i64;
    let filter_digest = match arkret_server::cursor_filter_digest(&serde_json::json!({
        "operation": arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
        "query": needle,
        "limit": limit,
    })) {
        Ok(digest) => digest,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("realm search cursor: {error}"));
            return;
        }
    };
    let cursor_context = CursorBindingContext::new(
        "anonymous",
        None,
        state.service_core_id().clone(),
        filter_digest,
    );
    let cursor = match body.cursor.as_deref() {
        Some(token) => match state
            .cursor_authority()
            .resolve_stream(token, &cursor_context)
            .and_then(|value| {
                serde_json::from_value::<SearchCursor>(value)
                    .map_err(|_| arkret_server::CursorAuthorityError::IntegrityInvalid)
            }) {
            Ok(cursor) => cursor,
            Err(error) => {
                super::render_cursor_error(res, error);
                return;
            }
        },
        None => SearchCursor {
            last_realm_id: String::new(),
        },
    };
    let rows = match load_search_rows(state.db(), &cursor.last_realm_id, &needle, limit + 1).await {
        Ok(rows) => rows,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("realm search: {error}"));
            return;
        }
    };
    let mut entries = match rows
        .into_iter()
        .map(PublicRealmDirectoryEntry::try_from)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(entries) => entries,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, error);
            return;
        }
    };
    let has_more = entries.len() > limit as usize;
    if has_more {
        entries.truncate(limit as usize);
    }
    let next_cursor = if has_more {
        entries
            .last()
            .map(|entry| {
                state.cursor_authority().mint_stream(
                    cursor_context,
                    serde_json::json!(SearchCursor {
                        last_realm_id: entry.realm_id.as_str().to_owned(),
                    }),
                    60 * 60 * 1000,
                )
            })
            .transpose()
    } else {
        Ok(None)
    };
    match next_cursor {
        Ok(next_cursor) => res.render(Json(DirectoryRealmSearchOutcome {
            realms: entries,
            has_more,
            next_cursor,
        })),
        Err(error) => ApiErrorCode::InternalError.render(res, format!("realm cursor: {error}")),
    };
}

async fn load_search_rows(
    db: &crate::db::Db,
    after: &str,
    needle: &str,
    limit: i64,
) -> anyhow::Result<Vec<PublicRealmRow>> {
    let mut conn = db.get().await?;
    let rows = diesel::sql_query(
        "SELECT realm_id, public_metadata, indexed_at, expires_at \
         FROM directory_public_realm_entries \
         WHERE removed_at IS NULL AND confirmed_public_at IS NOT NULL AND confirmed_public_at <= now() AND expires_at > now() AND realm_id > $1 \
           AND ($2 = '' OR public_metadata->>'display_name' ILIKE '%' || $2 || '%') \
         ORDER BY realm_id LIMIT $3",
    )
    .bind::<Text, _>(after)
    .bind::<Text, _>(needle)
    .bind::<BigInt, _>(limit)
    .load(&mut *conn)
    .await?;
    Ok(rows)
}

#[handler]
pub async fn resolve_realm(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(state) => state.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("resolve-realm");
    let body: DirectoryResolveRealmRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed resolve body: {error}"));
            return;
        }
    };
    if !enforce_resolve_rate_limit(req, res, &state, body.realm_id.as_str()) {
        return;
    }
    match load_realm_row(state.db(), &body.realm_id).await {
        Ok(Some(row)) => match PublicRealmDirectoryEntry::try_from(row) {
            Ok(entry) => res.render(Json(entry)),
            Err(error) => ApiErrorCode::InternalError.render(res, error),
        },
        Ok(None) => ApiErrorCode::NotFound.render(res, "not found"),
        Err(error) => ApiErrorCode::InternalError.render(res, format!("realm resolve: {error}")),
    };
}

async fn load_realm_row(
    db: &crate::db::Db,
    realm_id: &RealmId,
) -> anyhow::Result<Option<PublicRealmRow>> {
    let mut conn = db.get().await?;
    let mut rows: Vec<PublicRealmRow> = diesel::sql_query(
        "SELECT realm_id, public_metadata, indexed_at, expires_at \
         FROM directory_public_realm_entries \
         WHERE realm_id = $1 AND removed_at IS NULL AND confirmed_public_at IS NOT NULL AND confirmed_public_at <= now() AND expires_at > now() LIMIT 1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load(&mut *conn)
    .await?;
    Ok(rows.pop())
}

#[cfg(test)]
mod tests {
    use diesel::sql_types::Bool;
    use diesel_async::RunQueryDsl;
    use serde_json::json;

    use super::*;

    #[allow(
        clippy::redundant_field_names,
        reason = "Diesel QueryableByName generates redundant initializers in this row mapping."
    )]
    mod schema_row {
        use super::*;
        #[derive(diesel::QueryableByName)]
        pub(super) struct FreshSchemaShape {
            #[diesel(sql_type = Bool)]
            pub(super) public_index_present: bool,
            #[diesel(sql_type = Bool)]
            pub(super) retired_pcd_absent: bool,
            #[diesel(sql_type = Bool)]
            pub(super) retired_directory_tables_absent: bool,
            #[diesel(sql_type = Bool)]
            pub(super) only_current_tables_present: bool,
        }
    }
    use schema_row::FreshSchemaShape;

    fn row(projection: JsonValue) -> PublicRealmRow {
        let indexed_at = Utc::now();
        PublicRealmRow {
            realm_id: "ak:realm:AXXwKm5bWs7Plj3J5iRyqGeeNU99_oZCMnjtWom6sFeR".to_owned(),
            public_metadata: projection,
            indexed_at,
            expires_at: indexed_at + chrono::Duration::hours(1),
        }
    }

    #[test]
    fn public_entry_contains_only_closed_metadata_and_local_times() {
        let entry = PublicRealmDirectoryEntry::try_from(row(json!({
            "display_name": "Public Realm",
            "summary": "A discovery hint",
        })))
        .unwrap();
        let value = serde_json::to_value(entry).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["public_metadata"]["display_name"], "Public Realm");
    }

    #[test]
    fn old_join_and_authority_projection_is_not_returned() {
        for forbidden in [
            "join_rule",
            "source_refs",
            "authority_generation",
            "member_count",
        ] {
            let mut projection = json!({"display_name": "Public Realm"});
            projection[forbidden] = json!("legacy");
            assert!(PublicRealmDirectoryEntry::try_from(row(projection)).is_err());
        }
    }

    #[tokio::test]
    async fn fresh_schema_has_only_empty_public_realm_index() -> anyhow::Result<()> {
        // A dedicated empty database is required: this assertion audits the
        // entire public schema and must never share a runtime database.
        let database_url = std::env::var("FLAGON_TEST_DATABASE_URL").map_err(|_| {
            anyhow::anyhow!("set FLAGON_TEST_DATABASE_URL to an isolated empty PostgreSQL database")
        })?;
        let db = crate::db::Db::connect(&database_url)?;
        db.run_migrations(&database_url).await?;
        let mut conn = db.get().await?;
        let shape: FreshSchemaShape = diesel::sql_query(
            "SELECT to_regclass('public.directory_public_realm_entries') IS NOT NULL \
                    AS public_index_present, \
                    (to_regclass('public.pcd_key_epochs') IS NULL \
                     AND to_regclass('public.pcd_index_entries') IS NULL \
                     AND to_regclass('public.pcd_config_snapshots') IS NULL \
                     AND to_regclass('public.pcd_quota_windows') IS NULL \
                     AND to_regclass('public.pcd_batches') IS NULL) \
                    AS retired_pcd_absent, \
                    (to_regclass('public.directory_resources') IS NULL \
                     AND to_regclass('public.ingest_announces') IS NULL \
                     AND to_regclass('public.withdrawals') IS NULL \
                     AND to_regclass('public.directory_object_access') IS NULL \
                     AND to_regclass('public.directory_invite_revocations') IS NULL \
                     AND to_regclass('public.accept_allowlist') IS NULL \
                     AND to_regclass('public.pending_takedowns') IS NULL \
                     AND to_regclass('public.pending_takedown_webhooks') IS NULL \
                     AND to_regclass('public.verified_realm_organizations') IS NULL) \
                    AS retired_directory_tables_absent, \
                    NOT EXISTS (SELECT 1 FROM information_schema.tables \
                                WHERE table_schema = 'public' \
                                  AND table_type = 'BASE TABLE' \
                                  AND table_name NOT IN ( \
                                      '__diesel_schema_migrations', \
                                      'directory_public_realm_entries', \
                                      'directory_audit', 'admin_tokens')) \
                    AS only_current_tables_present",
        )
        .get_result(&mut *conn)
        .await?;
        assert!(shape.public_index_present);
        assert!(shape.retired_pcd_absent);
        assert!(shape.retired_directory_tables_absent);
        assert!(shape.only_current_tables_present);
        let realm_id =
            RealmId::new("ak:realm:AXXwKm5bWs7Plj3J5iRyqGeeNU99_oZCMnjtWom6sFeR".to_owned())?;
        drop(conn);

        assert!(load_search_rows(&db, "", "", 10).await?.is_empty());
        assert!(load_realm_row(&db, &realm_id).await?.is_none());
        Ok(())
    }
}
