//! §9.1 normative result envelope.
//!
//! Every search/resolve result MUST carry these fields. We expose a thin
//! wrapper that handlers populate from the `directory_resources` row plus
//! the per-query freshness check.

use chrono::{DateTime, Utc};
use contrix_sdk::RealmJoinCandidate;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultEnvelope {
    /// The actual public-projection payload (Space preview, Org preview, etc.).
    #[serde(flatten)]
    pub payload: JsonValue,
    /// Directory's last refresh timestamp for this entry (§9.1).
    pub as_of: DateTime<Utc>,
    /// Truth-source event id list — clients verify by re-fetching these.
    pub source_refs: Vec<String>,
    /// Effective discovery-state revision marker (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
    /// True iff TTL+grace expired without successful revalidation.
    #[serde(skip_serializing_if = "is_false")]
    pub stale: bool,
    /// Set by the optional cross-directory consistency probe (§9.1).
    #[serde(skip_serializing_if = "is_false")]
    pub divergent: bool,
    /// Candidate ingress services for Realm join / invite-accept / knock.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub join_candidates: Vec<RealmJoinCandidate>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl ResultEnvelope {
    /// Construct from the columns we store on `directory_resources`. The
    /// caller picks the public-projection JSON to embed; we don't enforce
    /// any particular shape here so that Space / Organization / Actor
    /// previews can each have their own payload schema.
    #[allow(clippy::too_many_arguments)]
    pub fn from_row(
        payload: JsonValue,
        as_of: DateTime<Utc>,
        source_refs: Vec<String>,
        policy_revision: Option<String>,
        stale: bool,
        divergent: bool,
        _via_services: Vec<String>,
    ) -> Self {
        Self {
            payload,
            as_of,
            source_refs,
            policy_revision,
            stale,
            divergent,
            join_candidates: Vec::new(),
        }
    }

    pub fn with_join_candidates(mut self, join_candidates: Vec<RealmJoinCandidate>) -> Self {
        self.join_candidates = join_candidates;
        self
    }
}
