//! Shared audit-only operator-admin HTTP contracts for teabay.

pub use arkret_sdk::{DidCoreId, DirectoryResourceKind};
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

    #[test]
    fn authenticated_credential_id_rejects_ambiguous_values() {
        assert!(AuthenticatedCredentialId::new("admin-token-1").is_ok());
        assert!(AuthenticatedCredentialId::new("").is_err());
        assert!(AuthenticatedCredentialId::new("admin token").is_err());
    }
}
