//! Deployment-local public index maintenance, deliberately absent from HTTP/SDK surfaces.
use std::io::Read;

use anyhow::{Context, bail, ensure};
use arkret_sdk::{Discoverability, PublicRealmDirectoryEntry, PublicRealmMetadata, RealmId};
use chrono::{DateTime, Duration, Utc};
use diesel::OptionalExtension;
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Db;
use crate::audit::{self, ActorIdentity, AuditEventKind, DirectoryResourceKindDb};

/// Deployment policy, not an Arkret wire/profile lifetime.
pub const MAX_CONFIRMATION_SECONDS: i64 = 24 * 60 * 60;
pub const USAGE: &str = "flagon-index [--config FILE] [--no-env-overrides] load FILE --confirm-public | remove REALM_ID --reason TEXT | purge-expired --reason TEXT";

/// Private operator input. Protocol objects remain SDK-owned and closed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicIndexConfirmation {
    pub realm_id: RealmId,
    pub public_metadata: PublicRealmMetadata,
    pub discoverability: Discoverability,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub confirmed_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub reason: String,
}

impl PublicIndexConfirmation {
    fn validate(&self, now: DateTime<Utc>) -> anyhow::Result<()> {
        ensure!(
            self.discoverability == Discoverability::Public,
            "only explicitly confirmed public metadata may be loaded; use remove for a privacy change"
        );
        self.public_metadata.validate()?;
        validate_reason(&self.reason)?;
        ensure!(
            self.confirmed_at <= now && now < self.expires_at,
            "confirmation must already be effective and not expired"
        );
        ensure!(
            self.expires_at <= self.confirmed_at + Duration::seconds(MAX_CONFIRMATION_SECONDS),
            "confirmation exceeds the deployment maximum of 24 hours"
        );
        Ok(())
    }
}

#[derive(Debug)]
pub enum MaintenanceCommand {
    Load {
        record: Box<PublicIndexConfirmation>,
        confirm_public: bool,
    },
    Remove {
        realm_id: RealmId,
        reason: String,
    },
    PurgeExpired {
        reason: String,
    },
}

fn validate_reason(reason: &str) -> anyhow::Result<()> {
    ensure!(
        !reason.trim().is_empty() && reason.chars().count() <= 512,
        "reason must contain 1..=512 characters"
    );
    Ok(())
}

pub fn command_from_args(args: &[String]) -> anyhow::Result<MaintenanceCommand> {
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                index += 1;
                ensure!(args.get(index).is_some(), "--config requires a file");
            }
            "--no-env-overrides" => {}
            value if value.starts_with("--config=") => {
                ensure!(value.len() > 9, "--config requires a file");
            }
            _ => positional.push(args[index].as_str()),
        }
        index += 1;
    }
    match positional.as_slice() {
        ["load", path, "--confirm-public"] => {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(16 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 16 * 1024, "confirmation file exceeds 16 KiB");
            let record = serde_json::from_slice(&bytes)
                .context("invalid private public-index confirmation")?;
            Ok(MaintenanceCommand::Load {
                record: Box::new(record),
                confirm_public: true,
            })
        }
        ["remove", id, "--reason", reason] => {
            validate_reason(reason)?;
            Ok(MaintenanceCommand::Remove {
                realm_id: RealmId::new(*id)?,
                reason: (*reason).to_owned(),
            })
        }
        ["purge-expired", "--reason", reason] => {
            validate_reason(reason)?;
            Ok(MaintenanceCommand::PurgeExpired {
                reason: (*reason).to_owned(),
            })
        }
        _ => bail!("{USAGE}"),
    }
}

#[allow(
    clippy::redundant_field_names,
    reason = "Diesel QueryableByName generated initializers"
)]
mod rows {
    use super::*;
    #[derive(diesel::QueryableByName)]
    pub(super) struct ContextRow {
        #[diesel(sql_type = Timestamptz)]
        pub now: DateTime<Utc>,
        #[diesel(sql_type = Text)]
        pub role: String,
        #[diesel(sql_type = Text)]
        pub login_role: String,
        #[diesel(sql_type = Text)]
        pub database: String,
    }
    #[derive(diesel::QueryableByName)]
    pub(super) struct IndexedAt {
        #[diesel(sql_type = Timestamptz)]
        pub indexed_at: DateTime<Utc>,
    }
}

/// Direct DB privileges authorize this local process. No asserted Arkret principal is accepted.
pub async fn execute(db: &Db, command: MaintenanceCommand) -> anyhow::Result<Value> {
    if let MaintenanceCommand::Load {
        confirm_public: false,
        ..
    } = &command
    {
        bail!("load requires explicit --confirm-public acknowledgement");
    }
    let mut conn = db.get().await?;
    conn.transaction::<_, anyhow::Error, _>(async move |conn| {
        audit::lock_chain(conn).await?;
        let context = diesel::sql_query("SELECT date_trunc('milliseconds', clock_timestamp()) AS now, current_user::text AS role, session_user::text AS login_role, current_database()::text AS database")
            .get_result::<rows::ContextRow>(conn).await?;
        let identity = json!({"database":context.database,"role":context.role,"login_role":context.login_role});
        let credential = format!("postgresql:{}", crate::util::lower_hex(&Sha256::digest(arkret_canonical::canonical::canonical_json_bytes(&identity)?)));
        let (kind, resource, detail, result) = match command {
            MaintenanceCommand::Load { record, .. } => {
                record.validate(context.now)?;
                let metadata = serde_json::to_value(&record.public_metadata)?;
                let row = diesel::sql_query(
                    "INSERT INTO directory_public_realm_entries (realm_id, public_metadata, indexed_at, expires_at, confirmed_public_at) VALUES ($1,$2,$3,$4,$5) \
                     ON CONFLICT (realm_id) DO UPDATE SET public_metadata=EXCLUDED.public_metadata, \
                       indexed_at=CASE WHEN directory_public_realm_entries.confirmed_public_at=EXCLUDED.confirmed_public_at THEN directory_public_realm_entries.indexed_at ELSE EXCLUDED.indexed_at END, \
                       expires_at=EXCLUDED.expires_at, confirmed_public_at=EXCLUDED.confirmed_public_at, removed_at=NULL \
                     WHERE (directory_public_realm_entries.removed_at IS NULL OR directory_public_realm_entries.removed_at < EXCLUDED.confirmed_public_at) AND (directory_public_realm_entries.confirmed_public_at IS NULL \
                        OR directory_public_realm_entries.confirmed_public_at < EXCLUDED.confirmed_public_at \
                        OR (directory_public_realm_entries.confirmed_public_at=EXCLUDED.confirmed_public_at AND directory_public_realm_entries.public_metadata=EXCLUDED.public_metadata AND directory_public_realm_entries.expires_at=EXCLUDED.expires_at)) \
                     RETURNING indexed_at")
                    .bind::<Text,_>(record.realm_id.as_str()).bind::<Jsonb,_>(&metadata)
                    .bind::<Timestamptz,_>(context.now).bind::<Timestamptz,_>(record.expires_at)
                    .bind::<Timestamptz,_>(record.confirmed_at)
                    .get_result::<rows::IndexedAt>(conn).await.optional()?;
                let row = row.context("stale or conflicting confirmation; supply a newly verified public confirmation")?;
                let entry = PublicRealmDirectoryEntry { realm_id: record.realm_id.clone(), public_metadata: record.public_metadata, indexed_at: row.indexed_at, expires_at: record.expires_at };
                entry.validate()?;
                (AuditEventKind::AdminResourceUpserted, Some(record.realm_id.to_string()),
                 json!({"operation":"local_index_load","reason":record.reason,"confirmed_at":record.confirmed_at,"expires_at":record.expires_at,"database_identity":identity}), serde_json::to_value(entry)?)
            }
            MaintenanceCommand::Remove { realm_id, reason } => {
                validate_reason(&reason)?;
                // Keep a bounded fence so a delayed pre-removal confirmation cannot resurrect a row.
                diesel::sql_query("INSERT INTO directory_public_realm_entries (realm_id, public_metadata, indexed_at, expires_at, confirmed_public_at, removed_at) VALUES ($1,'{}',$2,$3,NULL,$2) ON CONFLICT(realm_id) DO UPDATE SET public_metadata='{}', indexed_at=EXCLUDED.indexed_at, expires_at=EXCLUDED.expires_at, confirmed_public_at=NULL, removed_at=EXCLUDED.removed_at")
                    .bind::<Text,_>(realm_id.as_str()).bind::<Timestamptz,_>(context.now)
                    .bind::<Timestamptz,_>(context.now + Duration::seconds(MAX_CONFIRMATION_SECONDS)).execute(conn).await?;
                (AuditEventKind::AdminResourceDeleted, Some(realm_id.to_string()), json!({"operation":"local_index_remove","reason":reason,"hidden":true,"database_identity":identity}), json!({"hidden":true}))
            }
            MaintenanceCommand::PurgeExpired { reason } => {
                validate_reason(&reason)?;
                let removed = diesel::sql_query("DELETE FROM directory_public_realm_entries WHERE expires_at <= $1")
                    .bind::<Timestamptz,_>(context.now).execute(conn).await?;
                (AuditEventKind::ExpiryPurged, None, json!({"operation":"local_index_purge_expired","reason":reason,"removed":removed,"database_identity":identity}), json!({"removed":removed}))
            }
        };
        audit::record_on_connection(conn, kind, resource.as_ref().map(|_| DirectoryResourceKindDb::Realm), resource.as_deref(), None, detail,
            ActorIdentity { authentication_method:Some("postgresql_role"), authenticated_credential_id:Some(&credential), asserted_operator_localpart:None }).await?;
        Ok(result)
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonpublic_invalid_and_stale_confirmations_are_rejected() {
        let now = DateTime::parse_from_rfc3339("2026-10-20T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let value = json!({"realm_id":"ak:realm:AXXwKm5bWs7Plj3J5iRyqGeeNU99_oZCMnjtWom6sFeR","public_metadata":{"display_name":"Public hint"},"discoverability":"public","confirmed_at":"2026-10-20T00:00:00.000Z","expires_at":"2026-10-20T01:00:00.000Z","reason":"manual public confirmation"});
        let valid: PublicIndexConfirmation = serde_json::from_value(value.clone()).unwrap();
        valid.validate(now).unwrap();
        for visibility in ["listed", "restricted", "unlisted", "invite_only", "secret"] {
            let mut input = value.clone();
            input["discoverability"] = json!(visibility);
            assert!(
                serde_json::from_value::<PublicIndexConfirmation>(input)
                    .unwrap()
                    .validate(now)
                    .is_err()
            );
        }
        for changed in [
            json!({"private":"forbidden"}),
            json!({"display_name":"x","source_refs":[]}),
        ] {
            let mut input = value.clone();
            input["public_metadata"] = changed;
            assert!(serde_json::from_value::<PublicIndexConfirmation>(input).is_err());
        }
        let mut invalid = valid.clone();
        invalid.expires_at = now;
        assert!(invalid.validate(now).is_err());
        invalid = valid.clone();
        invalid.confirmed_at = now + Duration::seconds(1);
        assert!(invalid.validate(now).is_err());
        invalid = valid;
        invalid.expires_at = now + Duration::hours(25);
        assert!(invalid.validate(now).is_err());
        assert!(command_from_args(&["load".into(), "missing.json".into()]).is_err());
        assert!(command_from_args(&["announce".into()]).is_err());
    }
}
