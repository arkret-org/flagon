use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::api::{
    option_string, parse_json_object, parse_optional_i64, parse_optional_json_object,
    parse_string_array, pretty_json, pretty_string_array,
};

pub const BADGE_NEUTRAL: &str = "badge neutral";
pub const BADGE_OK: &str = "badge ok";
pub const BADGE_WARN: &str = "badge warn";
pub const BADGE_DANGER: &str = "badge danger";

/// Map a tone name to a full badge class, avoiding a `format!` on every render.
pub fn badge_class_for(tone: &str) -> &'static str {
    match tone {
        "ok" => BADGE_OK,
        "warn" => BADGE_WARN,
        "danger" => BADGE_DANGER,
        _ => BADGE_NEUTRAL,
    }
}

pub const RESOURCE_KINDS: [&str; 5] = ["realm", "organization", "actor", "applet", "handle"];
pub const DISCOVERABILITY_LEVELS: [&str; 6] = [
    "public",
    "listed",
    "restricted",
    "unlisted",
    "invite_only",
    "secret",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Resources,
    Diagnostics,
    Allowlist,
    Takedown,
    Audit,
    Review,
}

impl Tab {
    pub const ALL: [Self; 7] = [
        Self::Dashboard,
        Self::Resources,
        Self::Diagnostics,
        Self::Allowlist,
        Self::Takedown,
        Self::Audit,
        Self::Review,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Resources => "Resources",
            Self::Diagnostics => "Diagnostics",
            Self::Allowlist => "Allowlist",
            Self::Takedown => "Takedown",
            Self::Audit => "Audit",
            Self::Review => "Review",
        }
    }
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct DashboardStats {
    #[serde(default)]
    pub directory_resources: i64,
    #[serde(default)]
    pub stale_resources: i64,
    #[serde(default)]
    pub divergent_resources: i64,
    #[serde(default)]
    pub realm_destroyed: i64,
    #[serde(default)]
    pub ingest_announces: i64,
    #[serde(default)]
    pub webhook_subscriptions: i64,
    #[serde(default)]
    pub audit_events: i64,
    #[serde(default)]
    pub allowlist_entries: i64,
    #[serde(default)]
    pub per_kind: Vec<DashboardKindCount>,
    #[serde(default)]
    pub as_of: String,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct DashboardKindCount {
    #[serde(default)]
    pub resource_kind: String,
    #[serde(default)]
    pub count: i64,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct ResourceList {
    #[serde(default)]
    pub items: Vec<ResourceItem>,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct ResourceItem {
    #[serde(default)]
    pub resource_kind: String,
    #[serde(default)]
    pub resource_id: String,
    #[serde(default)]
    pub principal_server_did: String,
    #[serde(default)]
    pub discovery_state: JsonValue,
    #[serde(default)]
    pub public_projection: JsonValue,
    #[serde(default)]
    pub discoverability: String,
    #[serde(default)]
    pub as_of: String,
    #[serde(default)]
    pub source_refs: Vec<String>,
    #[serde(default)]
    pub policy_revision: Option<String>,
    #[serde(default)]
    pub indexed_at: String,
    #[serde(default)]
    pub effective_ttl_seconds: i32,
    #[serde(default)]
    pub next_revalidation_after: String,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub divergent: bool,
    #[serde(default)]
    pub via_services: Vec<String>,
    #[serde(default)]
    pub last_announce_id: Option<String>,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct AllowlistEnvelope {
    #[serde(default)]
    pub items: Vec<AllowlistItem>,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct AllowlistItem {
    #[serde(default)]
    pub resource_did: String,
    #[serde(default)]
    pub added_by: String,
    #[serde(default)]
    pub added_at: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct AuditEnvelope {
    #[serde(default)]
    pub events: Vec<AuditEvent>,
    #[serde(default)]
    pub next_since: Option<String>,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct AuditEvent {
    #[serde(default)]
    pub audit_id: i64,
    #[serde(default)]
    pub occurred_at: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub resource_kind: Option<String>,
    #[serde(default)]
    pub resource_id: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub detail: JsonValue,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct OperatorTakedownOutcome {
    #[serde(default)]
    pub withdraw_id: String,
    #[serde(default)]
    pub acked_at: String,
    #[serde(default)]
    pub effective_at: String,
    #[serde(default)]
    pub notification_status: String,
}

#[derive(Serialize)]
pub struct DirectoryAdminAllowlistUpsertRequestBody {
    pub resource_did: String,
    pub added_by: Option<String>,
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct OperatorTakedownRequestBody {
    pub resource_kind: String,
    pub resource_id: String,
    pub reason: String,
    pub operator: Option<String>,
    pub evidence: JsonValue,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct ResourceMutationEnvelope {
    #[serde(default)]
    pub item: ResourceItem,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
pub struct DeleteCount {
    #[serde(default)]
    pub deleted: i64,
}

#[derive(Clone, Serialize)]
pub struct DirectoryAdminResourceUpsertRequestBody {
    pub resource_kind: String,
    pub resource_id: String,
    pub principal_server_did: String,
    pub discoverability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
    pub source_refs: Vec<String>,
    pub policy_revision: Option<String>,
    pub effective_ttl_seconds: Option<i64>,
    pub stale: bool,
    pub divergent: bool,
    pub via_services: Vec<String>,
    pub public_projection: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_state: Option<JsonValue>,
    pub last_announce_id: Option<String>,
}

#[derive(Clone, PartialEq)]
pub struct ResourceEditorForm {
    pub resource_kind: String,
    pub resource_id: String,
    pub principal_server_did: String,
    pub discoverability: String,
    pub as_of: String,
    pub source_refs: String,
    pub policy_revision: String,
    pub effective_ttl_seconds: String,
    pub stale: bool,
    pub divergent: bool,
    pub via_services: String,
    pub public_projection: String,
    pub discovery_state: String,
    pub last_announce_id: String,
}

impl Default for ResourceEditorForm {
    fn default() -> Self {
        Self {
            resource_kind: "realm".to_string(),
            resource_id: String::new(),
            principal_server_did: String::new(),
            discoverability: "public".to_string(),
            as_of: String::new(),
            source_refs: "[\n  \"admin:manual\"\n]".to_string(),
            policy_revision: String::new(),
            effective_ttl_seconds: "86400".to_string(),
            stale: false,
            divergent: false,
            via_services: "[]".to_string(),
            public_projection: "{\n  \"name\": \"\",\n  \"summary\": \"\"\n}".to_string(),
            discovery_state: String::new(),
            last_announce_id: String::new(),
        }
    }
}

impl ResourceEditorForm {
    pub fn reset_for_kind(kind: &str) -> Self {
        let mut next = Self::default();
        if RESOURCE_KINDS.contains(&kind) {
            next.resource_kind = kind.to_string();
        }
        next
    }

    pub fn from_item(item: &ResourceItem) -> Self {
        Self {
            resource_kind: item.resource_kind.clone(),
            resource_id: item.resource_id.clone(),
            principal_server_did: item.principal_server_did.clone(),
            discoverability: item.discoverability.clone(),
            as_of: item.as_of.clone(),
            source_refs: pretty_string_array(&item.source_refs),
            policy_revision: item.policy_revision.clone().unwrap_or_default(),
            effective_ttl_seconds: item.effective_ttl_seconds.to_string(),
            stale: item.stale,
            divergent: item.divergent,
            via_services: pretty_string_array(&item.via_services),
            public_projection: pretty_json(&item.public_projection),
            discovery_state: pretty_json(&item.discovery_state),
            last_announce_id: item.last_announce_id.clone().unwrap_or_default(),
        }
    }

    pub fn to_body(&self) -> Result<DirectoryAdminResourceUpsertRequestBody, String> {
        let resource_id = self.resource_id.trim().to_string();
        if resource_id.is_empty() {
            return Err("resource_id is required".to_string());
        }

        let principal_server_did = self.principal_server_did.trim().to_string();
        if principal_server_did.is_empty() {
            return Err("principal_server_did is required".to_string());
        }

        if !RESOURCE_KINDS.contains(&self.resource_kind.as_str()) {
            return Err("resource_kind is invalid".to_string());
        }
        if !DISCOVERABILITY_LEVELS.contains(&self.discoverability.as_str()) {
            return Err("discoverability is invalid".to_string());
        }

        Ok(DirectoryAdminResourceUpsertRequestBody {
            resource_kind: self.resource_kind.clone(),
            resource_id,
            principal_server_did,
            discoverability: self.discoverability.clone(),
            as_of: option_string(self.as_of.clone()),
            source_refs: parse_string_array(&self.source_refs, "source_refs")?,
            policy_revision: option_string(self.policy_revision.clone()),
            effective_ttl_seconds: parse_optional_i64(
                &self.effective_ttl_seconds,
                "effective_ttl_seconds",
            )?,
            stale: self.stale,
            divergent: self.divergent,
            via_services: parse_string_array(&self.via_services, "via_services")?,
            public_projection: parse_json_object(&self.public_projection, "public_projection")?,
            discovery_state: parse_optional_json_object(&self.discovery_state, "discovery_state")?,
            last_announce_id: option_string(self.last_announce_id.clone()),
        })
    }
}
