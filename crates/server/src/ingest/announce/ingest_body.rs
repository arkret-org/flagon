//! Parsed `ak.find.directory.command.announce.v1` request body.

use arkret_sdk::{DidCoreId, DirectoryAnnounceRequestBody};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value as JsonValue;
use teabay_contracts::DirectoryDiscoveryState;

use crate::ingest::DirectoryResourceKindDb;

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryAnnounceIngest {
    /// Original accepted Event; this is the sole signed discovery carrier.
    pub discovery_event: arkret_wire::Event,
    #[serde(skip_serializing)]
    pub resource_kind: DirectoryResourceKindDb,
    #[serde(skip_serializing)]
    pub resource_id: String,
    /// Stable service core id of the Principal Server that owns the resource's
    /// truth source (`discovery-directory.md` §8.3). This is **not** a
    /// resolvable DID: mapping it to a current `did` / URL requires a
    /// verified `ServiceResolutionRecord`, and the spec forbids handing this
    /// value to a DID resolver.
    pub principal_server_service_id: DidCoreId,
    #[serde(skip_serializing)]
    pub discovery_state: DirectoryDiscoveryState,
    pub source_refs: Vec<String>,
    pub as_of: DateTime<Utc>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub supersedes_announce_id: Option<String>,
}

impl TryFrom<DirectoryAnnounceRequestBody> for DirectoryAnnounceIngest {
    type Error = String;

    fn try_from(value: DirectoryAnnounceRequestBody) -> Result<Self, Self::Error> {
        let event = value.discovery_event;
        let (resource_kind, resource_id) = match event.kind.as_str() {
            "ak.realm.discovery" => (DirectoryResourceKindDb::Realm, event.realm_id.to_string()),
            "ak.organization.discovery" => (
                DirectoryResourceKindDb::Organization,
                event
                    .payload
                    .get("organization_principal_id")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| {
                        "organization discovery_event requires payload.organization_principal_id"
                            .to_owned()
                    })?
                    .to_owned(),
            ),
            "ak.actor.discovery" => (DirectoryResourceKindDb::Actor, event_resource_id(&event)?),
            "ak.applet.discovery" => (DirectoryResourceKindDb::Applet, event_resource_id(&event)?),
            "ak.handle.discovery" => (DirectoryResourceKindDb::Handle, event_resource_id(&event)?),
            _ => return Err("unsupported discovery_event kind".to_owned()),
        };
        let discovery_state = DirectoryDiscoveryState::from_json_object(
            event
                .payload
                .get("value")
                .cloned()
                .ok_or_else(|| "discovery_event.payload.value is required".to_owned())?,
            "discovery_event.payload.value",
        )?;
        Ok(Self {
            discovery_event: event,
            resource_kind,
            resource_id,
            principal_server_service_id: value.principal_server_service_id,
            discovery_state,
            source_refs: value.source_refs,
            as_of: value.as_of,
            ttl_seconds: value
                .ttl_seconds
                .map(i64::try_from)
                .transpose()
                .map_err(|_| "ttl_seconds is too large".to_owned())?,
            supersedes_announce_id: value.supersedes_announce_id,
        })
    }
}

fn event_resource_id(event: &arkret_wire::Event) -> Result<String, String> {
    event
        .payload
        .get("resource_id")
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "discovery_event requires payload.resource_id".to_owned())
}
