//! Persistent PSI contact-token index.
//!
//! The match phase must not evaluate the directory's full contact corpus on
//! every request. Tokens are materialized per OPRF epoch and refreshed when
//! eligible Actor / Handle resources change.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value as JsonValue;
use voprf::{Ristretto255, VoprfServer};

use crate::db::Db;
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};
use crate::schema::psi_contact_tokens;

const PSI_INDEX_BATCH_SIZE: i64 = 1_024;
pub(crate) const PSI_DIGEST_PREFIX_LENGTH: usize = 16;

type PsiServer = VoprfServer<Ristretto255>;

#[derive(Debug, Insertable)]
#[diesel(table_name = psi_contact_tokens)]
struct NewPsiContactToken<'a> {
    epoch: &'a str,
    token: &'a [u8],
    token_prefix: &'a [u8],
    resource_kind: DirectoryResourceKindDb,
    resource_id: &'a str,
    created_at: DateTime<Utc>,
}

pub(crate) async fn sync_resource_tokens(
    db: &Db,
    kind: DirectoryResourceKindDb,
    resource_id: &str,
    discoverability: DiscoverabilityDb,
    stale: bool,
    projection: &JsonValue,
) -> anyhow::Result<()> {
    let mut conn = db.get().await?;
    sync_resource_tokens_on_conn(
        &mut conn,
        kind,
        resource_id,
        discoverability,
        stale,
        projection,
    )
    .await
}

pub(crate) async fn sync_resource_tokens_on_conn(
    conn: &mut AsyncPgConnection,
    kind: DirectoryResourceKindDb,
    resource_id: &str,
    discoverability: DiscoverabilityDb,
    stale: bool,
    projection: &JsonValue,
) -> anyhow::Result<()> {
    use crate::schema::psi_contact_tokens::dsl as p;
    use crate::schema::psi_epoch_keys::dsl as k;

    delete_resource_tokens_on_conn(conn, kind, resource_id).await?;

    if stale || !is_contact_indexed(kind, discoverability) {
        return Ok(());
    }

    let candidates = contact_candidate_inputs(kind, resource_id, projection);
    if candidates.is_empty() {
        return Ok(());
    }

    let now = Utc::now();
    let epoch_keys: Vec<(String, Vec<u8>)> = k::psi_epoch_keys
        .filter(k::expires_at.gt(now))
        .filter(k::ciphersuite.eq(crate::query::psi::VOPRF_CIPHERSUITE))
        .select((k::epoch, k::server_key))
        .load(conn)
        .await?;

    for (epoch, server_key) in epoch_keys {
        let server = PsiServer::deserialize(&server_key)
            .map_err(|error| anyhow::anyhow!("PSI server key deserialize: {error}"))?;
        for candidate in &candidates {
            let token = server
                .evaluate(candidate.as_bytes())
                .map_err(|error| anyhow::anyhow!("VOPRF evaluate `{candidate}`: {error}"))?;
            let token = token.to_vec();
            let token_prefix = &token[..PSI_DIGEST_PREFIX_LENGTH];
            diesel::insert_into(p::psi_contact_tokens)
                .values(NewPsiContactToken {
                    epoch: &epoch,
                    token: token.as_slice(),
                    token_prefix,
                    resource_kind: kind,
                    resource_id,
                    created_at: now,
                })
                .on_conflict_do_nothing()
                .execute(conn)
                .await?;
        }
    }

    Ok(())
}

pub(crate) async fn delete_resource_tokens(
    db: &Db,
    kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> anyhow::Result<()> {
    let mut conn = db.get().await?;
    delete_resource_tokens_on_conn(&mut conn, kind, resource_id).await
}

pub(crate) async fn delete_resource_tokens_on_conn(
    conn: &mut AsyncPgConnection,
    kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> anyhow::Result<()> {
    use crate::schema::psi_contact_tokens::dsl as p;

    diesel::delete(
        p::psi_contact_tokens
            .filter(p::resource_kind.eq(kind))
            .filter(p::resource_id.eq(resource_id)),
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub(crate) async fn rebuild_epoch_tokens_on_conn(
    conn: &mut AsyncPgConnection,
    epoch: &str,
    server: &PsiServer,
) -> anyhow::Result<()> {
    use crate::schema::directory_resources::dsl as r;
    use crate::schema::psi_contact_tokens::dsl as p;
    use crate::schema::psi_epoch_keys::dsl as k;

    diesel::delete(p::psi_contact_tokens.filter(p::epoch.eq(epoch)))
        .execute(conn)
        .await?;

    let now = Utc::now();
    for kind in [
        DirectoryResourceKindDb::Actor,
        DirectoryResourceKindDb::Handle,
    ] {
        let mut after_resource_id: Option<String> = None;
        loop {
            let mut query = r::directory_resources
                .filter(r::resource_kind.eq(kind))
                .filter(r::stale.eq(false))
                .filter(
                    r::discoverability
                        .eq(DiscoverabilityDb::Public)
                        .or(r::discoverability.eq(DiscoverabilityDb::Listed)),
                )
                .into_boxed();
            if let Some(cursor) = after_resource_id.as_ref() {
                query = query.filter(r::resource_id.gt(cursor.clone()));
            }
            let rows: Vec<(DirectoryResourceKindDb, String, JsonValue)> = query
                .order(r::resource_id.asc())
                .limit(PSI_INDEX_BATCH_SIZE)
                .select((r::resource_kind, r::resource_id, r::public_projection))
                .load(conn)
                .await?;
            if rows.is_empty() {
                break;
            }
            let fetched = rows.len();
            for (kind, resource_id, projection) in rows {
                after_resource_id = Some(resource_id.clone());
                for candidate in contact_candidate_inputs(kind, &resource_id, &projection) {
                    let token = server.evaluate(candidate.as_bytes()).map_err(|error| {
                        anyhow::anyhow!("VOPRF evaluate `{candidate}`: {error}")
                    })?;
                    let token = token.to_vec();
                    let token_prefix = &token[..PSI_DIGEST_PREFIX_LENGTH];
                    diesel::insert_into(p::psi_contact_tokens)
                        .values(NewPsiContactToken {
                            epoch,
                            token: token.as_slice(),
                            token_prefix,
                            resource_kind: kind,
                            resource_id: &resource_id,
                            created_at: now,
                        })
                        .on_conflict_do_nothing()
                        .execute(conn)
                        .await?;
                }
            }
            if fetched < PSI_INDEX_BATCH_SIZE as usize {
                break;
            }
        }
    }

    diesel::update(k::psi_epoch_keys.filter(k::epoch.eq(epoch)))
        .set(k::tokens_indexed_at.eq(Some(now)))
        .execute(conn)
        .await?;
    Ok(())
}

pub(crate) async fn load_matching_prefixes(
    db: &Db,
    epoch: &str,
    prefixes: &[Vec<u8>],
) -> anyhow::Result<HashSet<Vec<u8>>> {
    use crate::schema::psi_contact_tokens::dsl as p;

    if prefixes.is_empty() {
        return Ok(HashSet::new());
    }

    let mut conn = db.get().await?;
    let rows: Vec<Vec<u8>> = p::psi_contact_tokens
        .filter(p::epoch.eq(epoch))
        .filter(p::token_prefix.eq_any(prefixes.to_vec()))
        .select(p::token_prefix)
        .distinct()
        .load(&mut *conn)
        .await?;
    Ok(rows.into_iter().collect())
}

fn is_contact_indexed(kind: DirectoryResourceKindDb, discoverability: DiscoverabilityDb) -> bool {
    matches!(
        kind,
        DirectoryResourceKindDb::Actor | DirectoryResourceKindDb::Handle
    ) && matches!(
        discoverability,
        DiscoverabilityDb::Public | DiscoverabilityDb::Listed
    )
}

pub(crate) fn contact_candidate_inputs(
    kind: DirectoryResourceKindDb,
    resource_id: &str,
    projection: &JsonValue,
) -> HashSet<String> {
    let mut out = HashSet::new();
    push_candidate(&mut out, resource_id);

    match kind {
        DirectoryResourceKindDb::Actor | DirectoryResourceKindDb::Handle => {
            for key in ["handle", "did", "actor_id"] {
                if let Some(value) = projection.get(key).and_then(JsonValue::as_str) {
                    push_candidate(&mut out, value);
                }
            }
        }
        DirectoryResourceKindDb::Realm
        | DirectoryResourceKindDb::Organization
        | DirectoryResourceKindDb::Applet => {}
    }
    out
}

fn push_candidate(out: &mut HashSet<String>, value: &str) {
    let normalized = value.trim().to_ascii_lowercase();
    if !normalized.is_empty() {
        out.insert(normalized);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn contact_candidates_include_resource_and_projection_identifiers() {
        let inputs = contact_candidate_inputs(
            DirectoryResourceKindDb::Handle,
            "Alice.Example",
            &json!({
                "did": "did:web:alice.example",
                "handle": "alice.example",
                "email_hash": "sha256:abc",
            }),
        );

        assert!(inputs.contains("alice.example"));
        assert!(inputs.contains("did:web:alice.example"));
        assert!(!inputs.contains("sha256:abc"));
    }
}
