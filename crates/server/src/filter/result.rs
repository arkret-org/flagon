//! §9.1 normative result envelope.
//!
//! Every search/resolve result MUST carry these fields. We expose a thin
//! wrapper that handlers populate from the `directory_resources` row plus
//! the per-query freshness check.

use chrono::{DateTime, Utc};
use cokret_sdk::RealmJoinCandidate;
use serde::ser::{Error as _, SerializeMap};
use serde::{Serialize, Serializer};
use serde_json::Value as JsonValue;
use teabay_contracts::DirectoryPublicProjection;

#[derive(Debug, Clone)]
pub struct ResultEnvelope {
    /// The actual public-projection payload (Realm preview, Org preview, etc.).
    pub payload: DirectoryPublicProjection,
    /// Directory's last refresh timestamp for this entry (§9.1).
    pub as_of: DateTime<Utc>,
    /// Truth-source event id list — clients verify by re-fetching these.
    pub source_refs: Vec<String>,
    /// Effective discovery-state revision marker. §9.1 makes this a MUST on
    /// every result and forbids omission.
    pub policy_revision: String,
    /// True iff TTL+grace expired without successful revalidation.
    pub stale: bool,
    /// Set by the optional cross-directory consistency probe (§9.1).
    pub divergent: bool,
    /// Candidate ingress services for Realm join / invite-accept / knock.
    pub join_candidates: Vec<RealmJoinCandidate>,
}

impl ResultEnvelope {
    /// Construct from the columns we store on `directory_resources`. The
    /// caller picks the public-projection JSON to embed; we don't enforce
    /// any particular shape here so that Realm / Organization / Actor
    /// previews can each have their own payload schema.
    ///
    /// Note: `via_services` is accepted but intentionally NOT stored as an
    /// envelope field — §9.1 has no `via_services` field; that information is
    /// expressed via `join_candidates[].service_did` (see
    /// [`Self::with_join_candidates`]). The parameter is kept so callers can
    /// pass the row column uniformly across resource kinds.
    #[allow(clippy::too_many_arguments)]
    pub fn from_row(
        payload: JsonValue,
        as_of: DateTime<Utc>,
        source_refs: Vec<String>,
        policy_revision: String,
        stale: bool,
        divergent: bool,
        _via_services: Vec<String>,
    ) -> Self {
        Self {
            payload: DirectoryPublicProjection::from_json(payload),
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

impl Serialize for ResultEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let payload = self
            .payload
            .as_object()
            .ok_or_else(|| S::Error::custom("result envelope payload must be an object"))?;
        let optional_fields = usize::from(self.stale)
            + usize::from(self.divergent)
            + usize::from(!self.join_candidates.is_empty());
        let mut map = serializer.serialize_map(Some(payload.len() + 3 + optional_fields))?;
        for (key, value) in payload {
            map.serialize_entry(key, value)?;
        }
        map.serialize_entry("as_of", &self.as_of)?;
        map.serialize_entry("source_refs", &self.source_refs)?;
        map.serialize_entry("policy_revision", &self.policy_revision)?;
        if self.stale {
            map.serialize_entry("stale", &self.stale)?;
        }
        if self.divergent {
            map.serialize_entry("divergent", &self.divergent)?;
        }
        if !self.join_candidates.is_empty() {
            map.serialize_entry("join_candidates", &self.join_candidates)?;
        }
        map.end()
    }
}
