//! Shared operator-admin HTTP contracts for teabay.

use std::ops::{Deref, DerefMut};

pub use arkret_sdk::{Did, DidCoreId, DirectoryResourceKind, Discoverability};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Directory-local identifier of the credential that authenticated an admin
/// request. It is not an Arkret principal identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AuthenticatedCredentialId(String);

impl AuthenticatedCredentialId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_whitespace) {
            return Err(
                "authenticated credential id must be 1..=256 non-whitespace characters".to_owned(),
            );
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AuthenticatedCredentialId {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<AuthenticatedCredentialId> for String {
    fn from(value: AuthenticatedCredentialId) -> Self {
        value.0
    }
}

macro_rules! json_boundary {
    ($name:ident) => {
        #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub JsonValue);

        impl $name {
            pub fn from_json(value: JsonValue) -> Self {
                Self(value)
            }

            pub fn from_json_object(value: JsonValue, field: &str) -> Result<Self, String> {
                if value.is_object() {
                    Ok(Self(value))
                } else {
                    Err(format!("{field} must be a JSON object"))
                }
            }

            pub fn as_value(&self) -> &JsonValue {
                &self.0
            }

            pub fn into_value(self) -> JsonValue {
                self.0
            }
        }

        impl Deref for $name {
            type Target = JsonValue;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl PartialEq<JsonValue> for $name {
            fn eq(&self, other: &JsonValue) -> bool {
                &self.0 == other
            }
        }

        impl PartialEq<$name> for JsonValue {
            fn eq(&self, other: &$name) -> bool {
                self == &other.0
            }
        }
    };
}

json_boundary!(OperatorEvidence);
json_boundary!(DirectoryDecisionReceipt);
json_boundary!(DirectoryPublicProjection);
json_boundary!(DirectoryDiscoveryState);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAdminAllowlistUpsertRequestBody {
    pub resource_did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorTakedownRequestBody {
    pub resource_kind: DirectoryResourceKind,
    pub resource_id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default)]
    pub evidence: OperatorEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OperatorTakedownOutcome {
    pub withdraw_id: String,
    pub acked_at: DateTime<Utc>,
    pub effective_at: DateTime<Utc>,
    pub notification_status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAdminResourceUpsertRequestBody {
    pub resource_kind: DirectoryResourceKind,
    pub resource_id: String,
    pub station_id: DidCoreId,
    pub discoverability: Discoverability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(default)]
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub divergent: bool,
    #[serde(default)]
    pub via_services: Vec<DidCoreId>,
    pub public_projection: DirectoryPublicProjection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_state: Option<DirectoryDiscoveryState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_announce_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DashboardStats {
    pub directory_resources: i64,
    pub stale_resources: i64,
    pub divergent_resources: i64,
    pub realm_destroyed: i64,
    pub ingest_announces: i64,
    pub webhook_subscriptions: i64,
    pub audit_events: i64,
    pub allowlist_entries: i64,
    pub per_kind: Vec<DashboardKindCount>,
    pub as_of: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DashboardKindCount {
    pub resource_kind: String,
    pub count: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceList {
    pub items: Vec<ResourceItem>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceItem {
    pub resource_kind: String,
    pub resource_id: String,
    pub station_id: DidCoreId,
    pub discovery_state: DirectoryDiscoveryState,
    pub public_projection: DirectoryPublicProjection,
    pub discoverability: String,
    pub as_of: String,
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    pub indexed_at: String,
    pub effective_ttl_seconds: i32,
    pub next_revalidation_after: String,
    pub stale: bool,
    pub divergent: bool,
    pub via_services: Vec<DidCoreId>,
    pub last_announce_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceMutationEnvelope {
    pub item: ResourceItem,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DeleteCount {
    pub deleted: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AllowlistEnvelope {
    pub items: Vec<AllowlistItem>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AllowlistItem {
    pub resource_did: Did,
    pub added_by: DidCoreId,
    pub added_at: String,
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AllowlistMutationEnvelope {
    pub item: AllowlistItem,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditEnvelope {
    pub events: Vec<AuditEvent>,
    pub next_since: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_id: i64,
    pub occurred_at: String,
    pub kind: String,
    pub resource_kind: Option<String>,
    pub resource_id: Option<String>,
    pub actor_id: Option<DidCoreId>,
    pub authenticated_credential_id: Option<AuthenticatedCredentialId>,
    pub asserted_operator_localpart: Option<String>,
    pub authentication_method: Option<String>,
    pub detail: JsonValue,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditChainVerificationOutcome {
    pub ok: bool,
    pub checked_rows: i64,
    pub chain_rows: i64,
    pub first_audit_id: Option<i64>,
    pub last_audit_id: Option<i64>,
    pub head_digest: Option<String>,
    pub failure: Option<AuditChainVerificationFailure>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditChainVerificationFailure {
    pub audit_id: i64,
    pub reason: String,
    pub expected: Option<String>,
    pub actual: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SDK enum accessors are the only token source and must agree with serde.
    #[test]
    fn tokens_match_the_sdk_serde_representation() {
        for value in DirectoryResourceKind::ALL {
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                JsonValue::String(value.as_str().to_string())
            );
        }
        for value in Discoverability::ALL {
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                JsonValue::String(value.as_str().to_string())
            );
        }
    }
}
