//! Parsed `ak.find.directory.command.announce.v1` request body.

use arkret_sdk::{DidCoreId, DirectoryAnnounceRequestBody};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value as JsonValue;
use teabay_contracts::DirectoryDiscoveryState;

use crate::ingest::DirectoryResourceKindDb;
use crate::middleware::http_sig::AuthenticatedHttpSignature;

pub(super) fn transport_origin_matches_actor(
    signature: &AuthenticatedHttpSignature,
    actor: &arkret_sdk::ActorId,
) -> bool {
    let expected = actor.route_service_id();
    signature.source_service_id.as_ref() == Some(expected)
        && crate::did_resolver::verification_method_controller_core_id(&signature.key_id).as_ref()
            == Some(expected)
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectoryAnnounceIngest {
    /// Original accepted Event; this is the sole signed discovery carrier.
    pub discovery_event: arkret_wire::Event,
    #[serde(skip_serializing)]
    pub resource_kind: DirectoryResourceKindDb,
    #[serde(skip_serializing)]
    pub resource_id: String,
    /// Stable service core id of the Station that owns the resource's
    /// truth source (`discovery-directory.md` §8.3). This is **not** a
    /// resolvable DID: mapping it to a current `did` / URL requires a
    /// verified DID service endpoint, and the spec forbids handing this
    /// value to a DID resolver.
    pub station_id: DidCoreId,
    #[serde(skip_serializing)]
    pub discovery_state: DirectoryDiscoveryState,
    #[serde(skip_serializing)]
    pub source_ref_access: arkret_models_collaboration::history_key::DirectorySourceRefAccess,
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
        // The signed author is the only origin carrier; the request cannot
        // override its route with an independent Station identity.
        let station_id = event.actor_id.route_service_id().clone();
        let (resource_kind, resource_id) = match event.kind.as_str() {
            "ak.realm.discovery" => (DirectoryResourceKindDb::Realm, event.realm_id.to_string()),
            "ak.organization.discovery" => (
                DirectoryResourceKindDb::Organization,
                event
                    .payload
                    .get("organization_id")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| {
                        "organization discovery_event requires payload.organization_id".to_owned()
                    })?
                    .to_owned(),
            ),
            "ak.actor.discovery" => (
                DirectoryResourceKindDb::Actor,
                event_resource_id(&event, DirectoryResourceKindDb::Actor)?,
            ),
            "ak.applet.discovery" => (
                DirectoryResourceKindDb::Applet,
                event_resource_id(&event, DirectoryResourceKindDb::Applet)?,
            ),
            "ak.handle.discovery" => (
                DirectoryResourceKindDb::Handle,
                event_resource_id(&event, DirectoryResourceKindDb::Handle)?,
            ),
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
        value
            .source_ref_access
            .validate()
            .map_err(|error| error.to_string())?;
        if value.source_ref_access.discovery_event_id.as_str() != event.event_id.as_str()
            || value.source_ref_access.as_of != value.as_of
            || value.source_ref_access.source_id != station_id
            || value.source_ref_access.realm_id != event.realm_id
        {
            return Err("source_ref_access does not bind the exact announce".to_owned());
        }
        let source_refs = value
            .source_ref_access
            .source_refs
            .iter()
            .map(ToString::to_string)
            .collect();
        Ok(Self {
            discovery_event: event,
            resource_kind,
            resource_id,
            station_id,
            discovery_state,
            source_ref_access: value.source_ref_access,
            source_refs,
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

fn event_resource_id(
    event: &arkret_wire::Event,
    kind: DirectoryResourceKindDb,
) -> Result<String, String> {
    let value = event
        .payload
        .get("resource_id")
        .ok_or_else(|| "discovery_event requires payload.resource_id".to_owned())?;
    match kind {
        DirectoryResourceKindDb::Actor => {
            let actor: arkret_sdk::ActorId = serde_json::from_value(value.clone())
                .map_err(|error| format!("actor discovery resource_id must be ActorId: {error}"))?;
            arkret_canonical::canonical_json_string(&actor)
                .map_err(|error| format!("canonical actor resource_id: {error}"))
        }
        DirectoryResourceKindDb::Applet => value
            .as_str()
            .ok_or_else(|| "applet discovery resource_id must be AppletId".to_owned())
            .and_then(|raw| {
                arkret_sdk::AppletId::new(raw.to_owned())
                    .map(|id| id.to_string())
                    .map_err(|error| format!("applet discovery resource_id: {error}"))
            }),
        DirectoryResourceKindDb::Handle => value
            .as_str()
            .filter(|raw| raw.contains(':') && !raw.starts_with('@'))
            .map(str::to_owned)
            .ok_or_else(|| "handle discovery resource_id must be canonical handle".to_owned()),
        _ => Err("resource kind does not use payload.resource_id".to_owned()),
    }
}
