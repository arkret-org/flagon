//! 5-step verify chain for ingest (spec §8.5).
//!
//! 1. Transport layer — HTTP Message Signature for push, or service binding +
//!    TLS for pull. We surface a hook here; the actual HTTP signature check
//!    lives in middleware (`crate::routing::http_sig`) so the handler always
//!    sees an already-authenticated transport.
//! 2. Discovery proof — verify `discovery_state.proof.detached_jws` against
//!    the resource governance key resolved via DID document.
//! 3. Directory authorization — `discovery_state.directory_services`
//!    contains *this* directory's service DID.
//! 4. Source-ref sanity — for first ingest, MAY pull at least one anchor
//!    from the resource's Principal Server to confirm `source_refs[0]` is
//!    resolvable.
//! 5. Accept policy — local accept_policy (open / allowlist / trust_root_signed
//!    / operator_review) decision.
//!
//! Any failure MUST short-circuit; we never partially accept (§8.5 last line).

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde_json::Value as JsonValue;

use crate::{
    config::{AcceptPolicyKind, AppConfig},
    db::Db,
    error::ErrorCode,
    ingest::{ResourceKindWire, announce::AnnounceRequest},
};

#[derive(Debug)]
pub struct VerifyOutcome {
    /// Effective `discoverability` parsed from discovery_state.
    pub discoverability: super::DiscoverabilityWire,
    /// `via_services` to populate from DID document (or fallback to
    /// `principal_server_did`).
    pub via_services: Vec<String>,
    /// Effective `policy_revision` if the discovery_state carries one.
    pub policy_revision: Option<String>,
}

pub struct VerifyContext<'a> {
    pub config: &'a AppConfig,
    pub db: &'a Db,
    pub now: DateTime<Utc>,
}

impl<'a> VerifyContext<'a> {
    pub fn new(config: &'a AppConfig, db: &'a Db) -> Self {
        Self {
            config,
            db,
            now: Utc::now(),
        }
    }

    /// Run all five steps. Returns `Err((code, msg))` on rejection — caller
    /// renders that via `ErrorCode::render`. Returns `Ok(VerifyOutcome)` on
    /// acceptance with the derived facts the announce handler needs.
    pub async fn verify(
        &self,
        req: &AnnounceRequest,
    ) -> Result<VerifyOutcome, (ErrorCode, String)> {
        // --- Step 1: transport — assumed enforced by middleware. -----------

        // --- Step 0 (housekeeping): freshness window. ----------------------
        let skew = chrono::Duration::from_std(self.config.as_of_skew)
            .map_err(|_| (ErrorCode::InternalError, "invalid skew config".to_string()))?;
        let drift = (req.as_of - self.now).num_seconds().abs();
        if drift > skew.num_seconds() {
            return Err((
                ErrorCode::SignatureStale,
                format!(
                    "as_of skew {drift}s exceeds configured tolerance {}s",
                    skew.num_seconds()
                ),
            ));
        }

        // --- Step 2: discovery proof verification. -------------------------
        // Real implementation must:
        //   (a) extract `discovery_state.proof.verification_method` DID URL,
        //   (b) resolve the controlling DID document at `req.resource_id`,
        //   (c) confirm the verification method is currently authoritative
        //       under the DID method's key history (webvh witnesses, etc.),
        //   (d) verify the detached JWS against the canonical
        //       `discovery_state` minus `proof.jws`.
        //
        // We delegate to `contrix-sdk` once the resolver chain is wired in
        // (see _todos.md M2-T2). For now, perform structural checks that
        // catch the common shape errors and short-circuit obvious garbage.
        verify_discovery_proof_shape(&req.discovery_state)?;

        // --- Step 3: directory authorization (this DID listed). ------------
        let listed = directory_services_lists_self(&req.discovery_state, &self.config.service_did);
        if !listed {
            return Err((
                ErrorCode::DirectoryNotAuthorized,
                format!(
                    "discovery_state.directory_services does not list this directory ({})",
                    self.config.service_did
                ),
            ));
        }

        // --- Step 4: source-ref sanity (deferred — TODO M2-T3). -----------
        // For first ingest of this resource we should pull at least one
        // anchor from `principal_server_did` to confirm `source_refs[0]`
        // resolves. Today we only structurally check non-emptiness.
        if req.source_refs.is_empty() {
            return Err((
                ErrorCode::SourceRefsUnverifiable,
                "source_refs MUST contain at least one anchor event id".into(),
            ));
        }

        // --- Step 5: accept policy enforcement. ----------------------------
        self.enforce_accept_policy(req)?;

        // --- Cross-checks: takedown-in-force --------------------------------
        if let Some(effective_at) =
            previously_withdrawn(self.db, req.resource_kind, &req.resource_id)
                .map_err(|e| (ErrorCode::InternalError, format!("withdrawal check: {e}")))?
        {
            if req.as_of <= effective_at {
                return Err((
                    ErrorCode::TakedownInForce,
                    format!(
                        "a withdrawal is in force as of {effective_at}; \
                         announce as_of {} is not strictly later",
                        req.as_of
                    ),
                ));
            }
        }

        // --- Derive outcome from verified state. ---------------------------
        let discoverability = read_discoverability(&req.discovery_state)?;
        let via_services = derive_via_services(&req.discovery_state, &req.principal_server_did);
        let policy_revision = req
            .discovery_state
            .get("policy_revision")
            .and_then(JsonValue::as_str)
            .map(str::to_string);

        Ok(VerifyOutcome {
            discoverability,
            via_services,
            policy_revision,
        })
    }

    fn enforce_accept_policy(&self, req: &AnnounceRequest) -> Result<(), (ErrorCode, String)> {
        // DID method allowlist (applies regardless of accept policy kind).
        if matches!(
            req.resource_kind,
            ResourceKindWire::Organization | ResourceKindWire::Actor | ResourceKindWire::Applet
        ) {
            let method = did_method(&req.resource_id).unwrap_or_default();
            if !self
                .config
                .accepted_did_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&method))
            {
                return Err((
                    ErrorCode::AcceptPolicyDenied,
                    format!("DID method {method} not in CHADEX_ACCEPTED_DID_METHODS"),
                ));
            }
        }

        match self.config.accept_policy_kind {
            AcceptPolicyKind::Open => Ok(()),
            AcceptPolicyKind::Allowlist => {
                if is_in_allowlist(self.db, &req.resource_id)
                    .map_err(|e| (ErrorCode::InternalError, format!("allowlist read: {e}")))?
                {
                    Ok(())
                } else {
                    Err((
                        ErrorCode::AcceptPolicyDenied,
                        format!("{} not in operator allowlist", req.resource_id),
                    ))
                }
            }
            AcceptPolicyKind::TrustRootSigned => {
                // TODO M2-T4 — verify a trust-root attestation (separate VC
                // / governance signature) accompanies the announce.
                Err((
                    ErrorCode::AcceptPolicyDenied,
                    "trust_root_signed accept policy not yet implemented".into(),
                ))
            }
            AcceptPolicyKind::OperatorReview => {
                // Operator-review mode requires out-of-band approval; the
                // queue lives in the audit log + operator UI. For now we
                // reject with a structured message so callers know to apply
                // through `accept_policy_ref`.
                Err((
                    ErrorCode::AcceptPolicyDenied,
                    self.config
                        .accept_policy_ref
                        .clone()
                        .unwrap_or_else(|| "operator review required".to_string()),
                ))
            }
        }
    }
}

fn verify_discovery_proof_shape(discovery_state: &JsonValue) -> Result<(), (ErrorCode, String)> {
    let proof = discovery_state.get("proof").ok_or((
        ErrorCode::SignatureInvalid,
        "discovery_state.proof is missing".into(),
    ))?;
    let kind = proof
        .get("kind")
        .and_then(JsonValue::as_str)
        .ok_or((ErrorCode::SignatureInvalid, "proof.kind missing".into()))?;
    if kind != "detached_jws" {
        return Err((
            ErrorCode::SignatureInvalid,
            format!("unsupported proof.kind {kind}; expected detached_jws"),
        ));
    }
    if proof
        .get("verification_method")
        .and_then(JsonValue::as_str)
        .is_none()
    {
        return Err((
            ErrorCode::SignatureInvalid,
            "proof.verification_method missing".into(),
        ));
    }
    if proof.get("jws").and_then(JsonValue::as_str).is_none() {
        return Err((ErrorCode::SignatureInvalid, "proof.jws missing".into()));
    }
    // TODO M2-T2 — actually verify the JWS against the resolved key.
    Ok(())
}

fn directory_services_lists_self(discovery_state: &JsonValue, self_did: &str) -> bool {
    discovery_state
        .get("directory_services")
        .and_then(JsonValue::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(JsonValue::as_str)
                .any(|d| d.eq_ignore_ascii_case(self_did))
        })
        .unwrap_or(false)
}

fn read_discoverability(
    discovery_state: &JsonValue,
) -> Result<super::DiscoverabilityWire, (ErrorCode, String)> {
    let s = discovery_state
        .get("discoverability")
        .and_then(JsonValue::as_str)
        .ok_or((
            ErrorCode::SchemaViolation,
            "discovery_state.discoverability missing".into(),
        ))?;
    match s {
        "public" => Ok(super::DiscoverabilityWire::Public),
        "listed" => Ok(super::DiscoverabilityWire::Listed),
        "restricted" => Ok(super::DiscoverabilityWire::Restricted),
        "unlisted" => Ok(super::DiscoverabilityWire::Unlisted),
        "invite_only" => Ok(super::DiscoverabilityWire::InviteOnly),
        "secret" => Ok(super::DiscoverabilityWire::Secret),
        other => Err((
            ErrorCode::SchemaViolation,
            format!("unknown discoverability {other}"),
        )),
    }
}

fn derive_via_services(discovery_state: &JsonValue, principal_server_did: &str) -> Vec<String> {
    if let Some(arr) = discovery_state
        .get("via_services")
        .and_then(JsonValue::as_array)
    {
        let v: Vec<_> = arr
            .iter()
            .filter_map(JsonValue::as_str)
            .map(str::to_string)
            .collect();
        if !v.is_empty() {
            return v;
        }
    }
    vec![principal_server_did.to_string()]
}

fn did_method(did: &str) -> Option<String> {
    let trimmed = did.strip_prefix("did:")?;
    let end = trimmed.find(':').unwrap_or(trimmed.len());
    Some(format!("did:{}", &trimmed[..end]))
}

fn is_in_allowlist(db: &Db, resource_did: &str) -> anyhow::Result<bool> {
    use crate::schema::accept_allowlist::dsl;
    let mut conn = db.get()?;
    let n: i64 = dsl::accept_allowlist
        .filter(dsl::resource_did.eq(resource_did))
        .count()
        .get_result(&mut conn)?;
    Ok(n > 0)
}

fn previously_withdrawn(
    db: &Db,
    resource_kind: ResourceKindWire,
    resource_id: &str,
) -> anyhow::Result<Option<DateTime<Utc>>> {
    use crate::schema::withdrawals::dsl;
    let mut conn = db.get()?;
    let row: Option<DateTime<Utc>> = dsl::withdrawals
        .filter(dsl::resource_kind.eq(resource_kind))
        .filter(dsl::resource_id.eq(resource_id))
        .order(dsl::effective_at.desc())
        .select(dsl::effective_at)
        .first(&mut conn)
        .optional()?;
    Ok(row)
}
