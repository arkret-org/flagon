//! `ak.find.directory.command.announce.v1` handler — push-mode ingest.
//!
//! Spec: discovery-directory.md §8.3 (request shape), §8.5 (verify chain),
//! §8.6 (TTL), §8.10 (anti-abuse / replay).

mod federation;
mod ingest_body;
mod persist;
mod projection;

#[cfg(test)]
mod tests;

use arkret_sdk::DirectoryAnnounceOutcome;
use chrono::{DateTime, Utc};
use federation::verify_federation_trust_domain_headers;
pub(crate) use federation::{FederationCacheKeyInputs, FederationCachePersist};
pub(crate) use ingest_body::DirectoryAnnounceIngest;
use persist::find_announce_by_natural_key;
pub(crate) use persist::{
    digest_request, latest_policy_revision_for, policy_revision_seen_before,
    upsert_resource_and_audit,
};
use projection::validate_request_shape;
pub(crate) use projection::{
    derive_public_projection, derive_realm_terminal_state, effective_ttl_seconds,
};
use salvo::prelude::*;
use serde_json::json;
use teabay_contracts::DirectoryPublicProjection;

use crate::audit::{self, AuditEventKind};
use crate::error::ApiErrorCode;
use crate::filter::circle_isolation;
use crate::ids::{IdClass, new_id};
use crate::ingest::rate_limit::enforce_ingest_rate_limit;
use crate::ingest::subscribe::{AcceptedIngestEvent, fanout_accepted_ingest};
use crate::ingest::verify::VerifyContext;
use crate::ingest::{DirectoryResourceKindDb, IngestModeWire};
use crate::state::{AppState, CachedDirectoryAnnounceOutcome};

fn announce_outcome(
    announce_id: String,
    indexed_at: DateTime<Utc>,
    effective_ttl_seconds: i64,
    next_revalidation_after: DateTime<Utc>,
    warnings: Vec<String>,
) -> DirectoryAnnounceOutcome {
    DirectoryAnnounceOutcome {
        announce_id,
        indexed_at,
        effective_ttl_seconds: effective_ttl_seconds.max(0) as u64,
        next_revalidation_after,
        warnings,
    }
}

#[handler]
pub async fn announce(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let mut ingest_metric = state.metrics().ingest_guard("announce");

    let wire_body: arkret_sdk::DirectoryAnnounceRequestBody = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ingest_metric.set_outcome("json_invalid");
            ApiErrorCode::JsonInvalid.render(res, format!("malformed announce body: {e}"));
            return;
        }
    };
    let body = match DirectoryAnnounceIngest::try_from(wire_body) {
        Ok(body) => body,
        Err(message) => {
            ingest_metric.set_outcome("schema_rejected");
            ApiErrorCode::SchemaViolation.render(res, message);
            return;
        }
    };

    if state.config().require_http_sig
        && !depot
            .get_typed::<crate::middleware::http_sig::AuthenticatedHttpSignature>()
            .is_ok_and(|signature| {
                ingest_body::transport_origin_matches_actor(
                    signature,
                    &body.discovery_event.actor_id,
                )
            })
    {
        ingest_metric.set_outcome("signature_invalid");
        ApiErrorCode::SignatureInvalid.render(res,
            "verified Source-Service-ID and signing service must equal discovery Event author route");
        return;
    }

    // Circle directory preview/stub convergence: a Realm discovery event may
    // carry Circle directory entry ids, but only under the recognized preview
    // containers. Every other Circle typed-id occurrence is still rejected
    // before indexing, and `derive_public_projection` collapses the subtree to
    // a fixed locked envelope for public fanout.
    if let Err(rejection) =
        circle_isolation::reject_circle_payload_allowing_directory_preview(&body.discovery_state)
    {
        ingest_metric.set_outcome("circle_isolation_violation");
        let _ = audit::record(
            state.db(),
            AuditEventKind::IngestRejected,
            Some(body.resource_kind),
            Some(&body.resource_id),
            Some(body.station_id.as_str()),
            json!({
                "code": ApiErrorCode::SchemaViolation.wire_code(),
                "reason": "circle_isolation_violation",
                "violation": rejection.audit_label(),
            }),
        )
        .await;
        ApiErrorCode::SchemaViolation.render(res, rejection.safe_message());
        return;
    }
    // Defence in depth: a few top-level announce fields are free-form
    // strings (`resource_id`, `station_id`,
    // `supersedes_announce_id`) and could carry a smuggled
    // `ak:circle:` id if a caller is misbehaving. Re-run the typed-id
    // sentinel over the whole request envelope while preserving the same
    // narrow `/discovery_state/...circle_id` exception.
    if let Ok(envelope) = serde_json::to_value(&body)
        && let Err(rejection) =
            circle_isolation::reject_circle_payload_allowing_directory_preview(&envelope)
    {
        ingest_metric.set_outcome("circle_isolation_violation");
        let _ = audit::record(
            state.db(),
            AuditEventKind::IngestRejected,
            Some(body.resource_kind),
            Some(&body.resource_id),
            Some(body.station_id.as_str()),
            json!({
                "code": ApiErrorCode::SchemaViolation.wire_code(),
                "reason": "circle_isolation_violation",
                "violation": rejection.audit_label(),
            }),
        )
        .await;
        ApiErrorCode::SchemaViolation.render(res, rejection.safe_message());
        return;
    }

    // Handle announcements use the SDK's RFC 8265-derived localpart profile.
    // UTS #39 skeleton collision state is optional authority-local registrar
    // policy and is not canonical equality or a query-time rejection rule.
    if matches!(body.resource_kind, DirectoryResourceKindDb::Handle)
        && arkret_sdk::Handle::parse(&body.resource_id).is_err()
    {
        ingest_metric.set_outcome("schema_rejected");
        let _ = audit::record(
            state.db(),
            AuditEventKind::IngestRejected,
            Some(body.resource_kind),
            Some(&body.resource_id),
            Some(body.station_id.as_str()),
            json!({
                "code": ApiErrorCode::SchemaViolation.wire_code(),
                "reason": "noncanonical_handle",
            }),
        )
        .await;
        ApiErrorCode::SchemaViolation.render(res, "handle is not canonical");
        return;
    }

    if let Err((code, msg)) = validate_request_shape(&body, state.config().max_ttl) {
        ingest_metric.set_outcome("schema_rejected");
        code.render(res, msg);
        return;
    }
    if !enforce_ingest_rate_limit(
        req,
        res,
        &state,
        &body.resource_id,
        Some(body.station_id.as_str()),
    ) {
        ingest_metric.set_outcome("rate_limited");
        return;
    }

    let request_digest = match digest_request(&body) {
        Ok(digest) => digest,
        Err(message) => {
            ingest_metric.set_outcome("schema_rejected");
            ApiErrorCode::SchemaViolation.render(
                res,
                format!("announce body is not canonical-json serializable: {message}"),
            );
            return;
        }
    };
    // The federation idempotency cache key is the
    // SHA-256 over (request_digest || Source-Service-ID ||
    // verification_method || service_binding_ref ||
    // origin_key_state_digest || Source-Trust-Domain ||
    // Destination-Trust-Domain). On hit we
    // still re-do the capability check; if it now fails (e.g. revoked
    // service key), we serve the cached body with
    // `historical_only=true` and trigger no new side effects.
    let cache_inputs = FederationCacheKeyInputs::extract(req, &body);

    // Federation S2S requests MUST carry
    // the trust-domain pair and we verify it BEFORE looking at the
    // idempotency cache. A misaddressed replay from another trust
    // domain is rejected with `cross_domain_replay_rejected`; the
    // signing-transcript fragment (when the request validates) is
    // logged for downstream verifier chains.
    let _trust_domain_transcript =
        match verify_federation_trust_domain_headers(&cache_inputs, &state.config().trust_domain) {
            Ok(fragment) => fragment,
            Err((code, msg)) => {
                ingest_metric.set_outcome("digest_mismatch");
                let _ = audit::record(
                    state.db(),
                    AuditEventKind::IngestRejected,
                    Some(body.resource_kind),
                    Some(&body.resource_id),
                    Some(body.station_id.as_str()),
                    json!({
                        "code": code.wire_code(),
                        "message": msg,
                        "source_trust_domain": cache_inputs.source_trust_domain,
                        "destination_trust_domain": cache_inputs.destination_trust_domain,
                    }),
                )
                .await;
                code.render(res, msg);
                return;
            }
        };

    let cache_key = cache_inputs.key(&request_digest);

    // INVARIANT: the federation trust-domain pair has already been verified
    // for THIS request above (we only reach here on `Ok(..)`), and the
    // request digest is the first input to `cache_key` — so a cache hit can
    // never serve a response for different body bytes. The hit path below
    // therefore does NOT need to re-run the pair check; it re-runs only the
    // §8.5 capability verify to decide `historical_only`.
    if let Some(cached) = state.cached_federation_replay(&cache_key) {
        let ctx = VerifyContext::new(state.config(), state.db(), state.did_resolver());
        let capability = ctx.verify(&body).await;
        let historical_only = capability.is_err();
        if historical_only {
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestHistoricalOnly,
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(body.station_id.as_str()),
                json!({
                    "announce_id": cached.announce_id,
                    "reason": capability.as_ref().err().map(|(c, m)| json!({
                        "code": c.wire_code(),
                        "message": m,
                    })),
                    "source_id": cache_inputs.source_id,
                    "verification_method": cache_inputs.verification_method,
                    "service_binding_ref": cache_inputs.service_binding_ref,
                }),
            )
            .await;
        }
        let warning = if historical_only {
            ingest_metric.set_outcome("historical_only");
            "federation_cache_historical_only"
        } else {
            ingest_metric.set_outcome("replay");
            "digest_replay_cache"
        };
        res.render(Json(announce_outcome(
            cached.announce_id,
            cached.indexed_at,
            cached.effective_ttl_seconds,
            cached.next_revalidation_after,
            vec![warning.into()],
        )));
        return;
    }

    let ctx = VerifyContext::new(state.config(), state.db(), state.did_resolver());
    let verified = match ctx.verify(&body).await {
        Ok(v) => v,
        Err((code, msg)) => {
            ingest_metric.set_outcome("verify_rejected");
            // Rejection audit (§7.4 — every rejection is logged).
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestRejected,
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(body.station_id.as_str()),
                json!({ "code": code.wire_code(), "message": msg }),
            )
            .await;
            code.render(res, msg);
            return;
        }
    };

    // Idempotency on (resource_id, as_of) per §8.6.
    let existing = match find_announce_by_natural_key(
        state.db(),
        body.resource_kind,
        &body.resource_id,
        body.as_of,
    )
    .await
    {
        Ok(existing) => existing,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("announce replay check: {error}"));
            return;
        }
    };
    if let Some(existing) = existing {
        let effective_ttl_seconds = existing.effective_ttl_seconds as i64;
        let next_revalidation_after =
            existing.indexed_at + chrono::Duration::seconds(effective_ttl_seconds);
        let response = announce_outcome(
            existing.announce_id,
            existing.indexed_at,
            effective_ttl_seconds,
            next_revalidation_after,
            vec!["idempotent_replay".into()],
        );
        state.remember_federation_replay(
            cache_key.clone(),
            CachedDirectoryAnnounceOutcome {
                announce_id: response.announce_id.clone(),
                indexed_at: response.indexed_at,
                effective_ttl_seconds,
                next_revalidation_after: response.next_revalidation_after,
            },
        );
        ingest_metric.set_outcome("replay");
        res.render(Json(response));
        return;
    }

    // Reject as_of older than the current row and policy_revision values that
    // already appeared before the current row (§8.10 rollback).
    let latest =
        match latest_policy_revision_for(state.db(), body.resource_kind, &body.resource_id).await {
            Ok(latest) => latest,
            Err(error) => {
                ApiErrorCode::InternalError.render(res, format!("policy rollback lookup: {error}"));
                return;
            }
        };
    if let Some(latest) = latest {
        if body.as_of < latest.as_of {
            ingest_metric.set_outcome("rollback_rejected");
            ApiErrorCode::PolicyRevisionRollback.render(
                res,
                format!(
                    "incoming as_of {} is older than indexed {}",
                    body.as_of, latest.as_of
                ),
            );
            return;
        }
        if verified.policy_revision != latest.policy_revision {
            match policy_revision_seen_before(
                state.db(),
                body.resource_kind,
                &body.resource_id,
                &verified.policy_revision,
                latest.as_of,
            )
            .await
            {
                Ok(true) => {
                    ingest_metric.set_outcome("rollback_rejected");
                    ApiErrorCode::PolicyRevisionRollback.render(
                        res,
                        format!(
                            "incoming policy_revision {} was already superseded by indexed {}",
                            verified.policy_revision, latest.policy_revision
                        ),
                    );
                    return;
                }
                Ok(false) => {}
                Err(error) => {
                    ApiErrorCode::InternalError
                        .render(res, format!("policy_revision rollback check: {error}"));
                    return;
                }
            }
        }
    }

    let effective_ttl = effective_ttl_seconds(body.ttl_seconds, state.config());
    let announce_id = new_id(IdClass::Announce);
    let indexed_at = Utc::now();
    let next_revalidation = indexed_at + chrono::Duration::seconds(effective_ttl);
    let public_projection = match derive_public_projection(
        &body.discovery_state,
        verified.discoverability,
    ) {
        Ok(projection) => projection,
        Err((code, msg)) => {
            ingest_metric.set_outcome("projection_rejected");
            // HC-TBY-1/2 — projection rejections include the R3.2 handle-claim
            // scope rejections (`claim_type_unsupported`,
            // `handle_claim_subject_not_principal_did`). Write the audit row so
            // the operator console surfaces the reason.
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestRejected,
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(body.station_id.as_str()),
                json!({ "code": code.wire_code(), "message": msg, "reason": "projection_rejected" }),
            )
            .await;
            code.render(res, msg);
            return;
        }
    };

    // discovery_state can carry a `terminal_state`
    // marker after `ak.realm.destroy` anchors. Surface it as a row-level
    // tombstone so the resolve / search projections collapse to a
    // placeholder. See `derive_realm_terminal_state`.
    let realm_terminal = derive_realm_terminal_state(body.resource_kind, &body.discovery_state);

    let insert_outcome = upsert_resource_and_audit(
        state.db(),
        &body,
        &verified,
        IngestModeWire::Push,
        &announce_id,
        indexed_at,
        effective_ttl,
        next_revalidation,
        request_digest.clone(),
        public_projection,
        FederationCachePersist {
            source_id: cache_inputs.source_id.clone(),
            verification_method: cache_inputs.verification_method.clone(),
            service_binding_ref: cache_inputs.service_binding_ref.clone(),
            origin_key_state_digest: cache_inputs.origin_key_state_digest.clone(),
            historical_only: false,
        },
        realm_terminal,
    )
    .await;

    let public_projection = match insert_outcome {
        Ok(projection) => projection,
        Err(e) => {
            ingest_metric.set_outcome("persist_error");
            ApiErrorCode::InternalError.render(res, format!("persist announce: {e}"));
            return;
        }
    };

    // TBY-ORG-01/03 — verify and project any `ak.realm.organization` relationship
    // statements the Realm announce carries. Only `active`, in-validity-window,
    // proof-bearing, scope-covering statements that pass the SDK verifier enter
    // the verified index; a bare `organization_id` / `owning_organization_ids`
    // hint is NOT treated as an official relationship. Failures are audited but
    // never block the announce (the projection hint still lands).
    if matches!(body.resource_kind, DirectoryResourceKindDb::Realm) {
        let statement_outcome = crate::ingest::organization_statement::verify_announced_statements(
            &body.discovery_state,
            &body.resource_id,
            indexed_at,
        );
        if !statement_outcome.rejected.is_empty() {
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestRejected,
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(body.station_id.as_str()),
                json!({
                    "reason": "realm_organization_statement_rejected",
                    "rejected": statement_outcome
                        .rejected
                        .iter()
                        .map(|rejected| json!({
                            "statement_id": rejected.statement_id,
                            "message": rejected.reason,
                        }))
                        .collect::<Vec<_>>(),
                }),
            )
            .await;
        }
        if let Err(e) = crate::ingest::organization_statement::persist_verified_statements(
            state.db(),
            &statement_outcome.verified,
            &announce_id,
        )
        .await
        {
            // A statement-projection failure must not lose the indexed row; log
            // and continue so the declared-hint projection is still served.
            tracing::warn!(
                resource_id = %body.resource_id,
                error = %e,
                "failed to persist verified realm organization statements"
            );
        }

        // TBY-ORG-03 — when the Realm advertises its current control-frontier
        // digest, mark any verified relationship sealed against an older
        // frontier as stale so it stops surfacing as an effective badge. A
        // statement re-announced in THIS batch already refreshed the matching
        // cell (its digest matches the current frontier), so it is unaffected.
        if let Some(current_frontier) = body
            .discovery_state
            .get("realm_frontier_digest")
            .and_then(serde_json::Value::as_str)
            && let Err(e) = crate::ingest::organization_statement::mark_stale_behind_frontier(
                state.db(),
                &body.resource_id,
                current_frontier,
            )
            .await
        {
            tracing::warn!(
                resource_id = %body.resource_id,
                error = %e,
                "failed to mark stale verified realm organizations"
            );
        }
    }

    let _ = audit::record(
        state.db(),
        AuditEventKind::IngestAccepted,
        Some(body.resource_kind),
        Some(&body.resource_id),
        Some(body.station_id.as_str()),
        json!({
            "announce_id": announce_id,
            "ingest_mode": "push",
            "discoverability": verified.discoverability.as_pg(),
            "policy_revision": verified.policy_revision,
            "realm_destroyed": realm_terminal.is_some(),
        }),
    )
    .await;

    if let Some(destroyed_at) = realm_terminal {
        let _ = audit::record(
            state.db(),
            AuditEventKind::RealmDestroyed,
            Some(body.resource_kind),
            Some(&body.resource_id),
            Some(body.station_id.as_str()),
            json!({
                "announce_id": announce_id,
                "as_of": body.as_of,
            }),
        )
        .await;
        // Tombstone fanout to in-flight subscribers.
        let tombstone = crate::ingest::subscribe::ReachabilityTombstone {
            kind: crate::ingest::subscribe::TombstoneKind::RealmDestroyed,
            resource_kind: body.resource_kind,
            resource_id: body.resource_id.clone(),
            station_id: body.station_id.clone(),
            reason: arkret_wire::CapabilityActionId::REALM_DESTROY.into(),
            revoked_at: destroyed_at,
        };
        let _ =
            crate::ingest::subscribe::fanout_reachability_tombstone(state.clone(), &[tombstone])
                .await;
    }

    fanout_accepted_ingest(
        state.clone(),
        AcceptedIngestEvent {
            announce_id: announce_id.clone(),
            ingest_mode: IngestModeWire::Push,
            resource_kind: body.resource_kind,
            resource_id: body.resource_id.clone(),
            station_id: body.station_id.clone(),
            indexed_at,
            as_of: body.as_of,
            source_refs: body.source_refs.clone(),
            policy_revision: Some(verified.policy_revision.clone()),
            discoverability: verified.discoverability,
            public_projection: DirectoryPublicProjection::from_json(public_projection),
        },
    )
    .await;

    state.remember_federation_replay(
        cache_key,
        CachedDirectoryAnnounceOutcome {
            announce_id: announce_id.clone(),
            indexed_at,
            effective_ttl_seconds: effective_ttl,
            next_revalidation_after: next_revalidation,
        },
    );

    ingest_metric.set_outcome("verify_ok");
    res.render(Json(announce_outcome(
        announce_id,
        indexed_at,
        effective_ttl,
        next_revalidation,
        vec![],
    )));
}
