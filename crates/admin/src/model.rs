use chrono::{DateTime, Utc};
pub use teabay_contracts::{
    AllowlistEnvelope, AllowlistItem, AuditChainVerificationOutcome, AuditEnvelope, AuditEvent,
    DISCOVERABILITY_TOKENS, DashboardStats, DeleteCount, DirectoryAdminAllowlistUpsertRequestBody,
    DirectoryAdminResourceUpsertRequestBody, DirectoryDiscoveryState, DirectoryPublicProjection,
    OperatorTakedownOutcome, OperatorTakedownRequestBody, RESOURCE_KIND_TOKENS, ResourceItem,
    ResourceList, ResourceMutationEnvelope, TakedownAppealDecision, TakedownAppealDecisionOutcome,
    TakedownAppealDecisionRequestBody, parse_directory_discoverability,
    parse_directory_resource_kind,
};

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

pub const RESOURCE_KINDS: [&str; 5] = RESOURCE_KIND_TOKENS;
pub const DISCOVERABILITY_LEVELS: [&str; 6] = DISCOVERABILITY_TOKENS;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Resources,
    Diagnostics,
    Allowlist,
    Takedown,
    Appeals,
    Audit,
    Review,
}

impl Tab {
    pub const ALL: [Self; 8] = [
        Self::Dashboard,
        Self::Resources,
        Self::Diagnostics,
        Self::Allowlist,
        Self::Takedown,
        Self::Appeals,
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
            Self::Appeals => "Appeals",
            Self::Audit => "Audit",
            Self::Review => "Review",
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct ResourceEditorForm {
    pub resource_kind: String,
    pub resource_id: String,
    pub principal_server_service_id: String,
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
            principal_server_service_id: String::new(),
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
            principal_server_service_id: item.principal_server_service_id.clone(),
            discoverability: item.discoverability.clone(),
            as_of: item.as_of.clone(),
            source_refs: pretty_string_array(&item.source_refs),
            policy_revision: item.policy_revision.clone(),
            effective_ttl_seconds: item.effective_ttl_seconds.to_string(),
            stale: item.stale,
            divergent: item.divergent,
            via_services: pretty_string_array(&item.via_services),
            public_projection: pretty_json(item.public_projection.as_value()),
            discovery_state: pretty_json(item.discovery_state.as_value()),
            last_announce_id: item.last_announce_id.clone().unwrap_or_default(),
        }
    }

    pub fn to_body(&self) -> Result<DirectoryAdminResourceUpsertRequestBody, String> {
        let resource_id = self.resource_id.trim().to_string();
        if resource_id.is_empty() {
            return Err("resource_id is required".to_string());
        }

        let principal_server_service_id = self.principal_server_service_id.trim().to_string();
        if principal_server_service_id.is_empty() {
            return Err("principal_server_service_id is required".to_string());
        }

        if !RESOURCE_KINDS.contains(&self.resource_kind.as_str()) {
            return Err("resource_kind is invalid".to_string());
        }
        if !DISCOVERABILITY_LEVELS.contains(&self.discoverability.as_str()) {
            return Err("discoverability is invalid".to_string());
        }

        let policy_revision = self.policy_revision.trim().to_string();
        if policy_revision.is_empty() {
            return Err("policy_revision is required".to_string());
        }

        Ok(DirectoryAdminResourceUpsertRequestBody {
            resource_kind: parse_directory_resource_kind(self.resource_kind.as_str())?,
            resource_id,
            principal_server_service_id,
            discoverability: parse_directory_discoverability(self.discoverability.as_str())?,
            as_of: parse_optional_datetime(&self.as_of, "as_of")?,
            source_refs: parse_string_array(&self.source_refs, "source_refs")?,
            policy_revision,
            effective_ttl_seconds: parse_optional_i64(
                &self.effective_ttl_seconds,
                "effective_ttl_seconds",
            )?,
            stale: self.stale,
            divergent: self.divergent,
            via_services: parse_string_array(&self.via_services, "via_services")?,
            public_projection: DirectoryPublicProjection::from_json_object(
                parse_json_object(&self.public_projection, "public_projection")?,
                "public_projection",
            )?,
            discovery_state: parse_optional_json_object(&self.discovery_state, "discovery_state")?
                .map(|value| DirectoryDiscoveryState::from_json_object(value, "discovery_state"))
                .transpose()?,
            last_announce_id: option_string(self.last_announce_id.clone()),
        })
    }
}

fn parse_optional_datetime(raw: &str, field: &str) -> Result<Option<DateTime<Utc>>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        DateTime::parse_from_rfc3339(trimmed)
            .map(|value| Some(value.with_timezone(&Utc)))
            .map_err(|error| format!("{field}: {error}"))
    }
}
