use std::rc::Rc;

use dioxus::prelude::*;
use serde_json::Value as JsonValue;

use crate::api::{
    delete_admin, get_admin, is_review_event, nonempty_or, option_string, parse_evidence,
    post_admin, pretty_json, push_param,
};
use crate::icons::{ListIcon, RefreshIcon, SaveIcon, SendIcon, TrashIcon};
use crate::model::{
    AllowlistEnvelope, AllowlistItem, AuditChainVerificationOutcome, AuditEnvelope, AuditEvent,
    BADGE_NEUTRAL, BADGE_WARN, DirectoryAdminAllowlistUpsertRequestBody, DirectoryResourceKind,
    OperatorTakedownOutcome, OperatorTakedownRequestBody, TakedownAppealDecision,
    TakedownAppealDecisionOutcome, TakedownAppealDecisionRequestBody,
};
use crate::shell::{AuditTable, PanelHeader, StatusLine};

#[component]
pub fn AllowlistPanel(base_url: String, token: String) -> Element {
    let base_url: Rc<str> = Rc::from(base_url);
    let token: Rc<str> = Rc::from(token);
    let mut rows = use_signal(Vec::<AllowlistItem>::new);
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);
    let mut resource_did = use_signal(String::new);
    let mut added_by = use_signal(String::new);
    let mut note = use_signal(String::new);
    let mut limit = use_signal(|| "100".to_string());

    let rows_view = rows();
    let loading_now = loading();
    let status_text = status();
    let error_text = error();
    let did_value = resource_did();
    let actor_value = added_by();
    let note_value = note();
    let limit_value = limit();
    let row_count = rows_view.len();

    let reload_base_url = base_url.clone();
    let reload_token = token.clone();
    let reload_for_button = move |_| {
        load_allowlist_entries(
            reload_base_url.clone(),
            reload_token.clone(),
            limit(),
            rows,
            loading,
            status,
            error,
        );
    };
    let save_base_url = base_url.clone();
    let save_token = token.clone();
    let save = move |_| {
        let did = resource_did().trim().to_string();
        if did.is_empty() {
            error.set("resource_did is required".to_string());
            return;
        }
        let body = DirectoryAdminAllowlistUpsertRequestBody {
            resource_did: did,
            added_by: option_string(added_by()),
            note: option_string(note()),
        };
        let base_url = save_base_url.clone();
        let token = save_token.clone();
        let reload_base_url = save_base_url.clone();
        let reload_token = save_token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Saving allowlist entry".to_string());
        spawn(async move {
            match post_admin::<DirectoryAdminAllowlistUpsertRequestBody, JsonValue>(
                base_url,
                token,
                "allowlist",
                &body,
            )
            .await
            {
                Ok(_) => {
                    status.set("Allowlist entry saved".to_string());
                    load_allowlist_entries(
                        reload_base_url,
                        reload_token,
                        limit(),
                        rows,
                        loading,
                        status,
                        error,
                    );
                }
                Err(message) => {
                    error.set(message);
                    status.set("Allowlist save failed".to_string());
                    loading.set(false);
                }
            }
        });
    };

    rsx! {
        div { class: "panel",
            PanelHeader {
                title: "Accept allowlist",
                badges: rsx! {
                    span { class: BADGE_NEUTRAL, "{row_count} rows" }
                },
                actions: rsx! {
                    button {
                        class: "button",
                        disabled: loading_now,
                        onclick: reload_for_button,
                        RefreshIcon {}
                        "Refresh"
                    }
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: save,
                        SaveIcon {}
                        "Save"
                    }
                },
            }
            div { class: "form-grid",
                div { class: "field span-5",
                    label { "Resource DID" }
                    input {
                        value: "{did_value}",
                        oninput: move |event| resource_did.set(event.value()),
                    }
                }
                div { class: "field span-3",
                    label { "Added by" }
                    input {
                        value: "{actor_value}",
                        oninput: move |event| added_by.set(event.value()),
                    }
                }
                div { class: "field span-2",
                    label { "Limit" }
                    input {
                        r#type: "number",
                        min: "1",
                        max: "500",
                        value: "{limit_value}",
                        oninput: move |event| limit.set(event.value()),
                    }
                }
                div { class: "field span-12",
                    label { "Note" }
                    input {
                        value: "{note_value}",
                        oninput: move |event| note.set(event.value()),
                    }
                }
            }
            StatusLine { status: status_text, error: error_text }
            div { class: "table-wrap",
                table {
                    thead {
                        tr {
                            th { "Resource DID" }
                            th { "Added by" }
                            th { "Added at" }
                            th { "Note" }
                            th { "Actions" }
                        }
                    }
                    tbody {
                        for item in rows_view {
                            AllowlistRow {
                                key: "{item.resource_did}",
                                item,
                                base_url: base_url.clone(),
                                token: token.clone(),
                                on_deleted: move |deleted: String| {
                                    let mut next = rows();
                                    next.retain(|row| row.resource_did != deleted);
                                    let count = next.len();
                                    rows.set(next);
                                    status.set(format!("{count} allowlist entries"));
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn AllowlistRow(
    item: AllowlistItem,
    base_url: Rc<str>,
    token: Rc<str>,
    on_deleted: EventHandler<String>,
) -> Element {
    let mut deleting = use_signal(|| false);
    let mut row_error = use_signal(String::new);
    let deleting_now = deleting();
    let row_error_text = row_error();
    let resource_did = item.resource_did.clone();
    let note_text = item.note.clone().unwrap_or_default();

    let delete = move |_| {
        let did = resource_did.clone();
        let deleted_did = resource_did.clone();
        let base_url = base_url.clone();
        let token = token.clone();
        deleting.set(true);
        row_error.set(String::new());
        spawn(async move {
            let params = vec![("resource_did", did)];
            match delete_admin::<JsonValue>(base_url, token, "allowlist", params).await {
                Ok(_) => on_deleted.call(deleted_did),
                Err(message) => row_error.set(message),
            }
            deleting.set(false);
        });
    };

    rsx! {
        tr {
            td { class: "mono", "{item.resource_did}" }
            td { "{item.added_by}" }
            td { class: "mono", "{item.added_at}" }
            td {
                "{note_text}"
                if !row_error_text.is_empty() {
                    div { class: "muted", "{row_error_text}" }
                }
            }
            td {
                button {
                    class: "button danger icon-only",
                    disabled: deleting_now,
                    onclick: delete,
                    TrashIcon {}
                }
            }
        }
    }
}

#[component]
pub fn TakedownPanel(base_url: String, token: String) -> Element {
    let base_url: Rc<str> = Rc::from(base_url);
    let token: Rc<str> = Rc::from(token);
    let mut resource_kind = use_signal(|| "realm".to_string());
    let mut resource_id = use_signal(String::new);
    let mut reason = use_signal(String::new);
    let mut operator = use_signal(|| "admin-console".to_string());
    let mut evidence = use_signal(|| "{\n  \"source\": \"operator_console\"\n}".to_string());
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);
    let mut response = use_signal(Option::<OperatorTakedownOutcome>::default);

    let kind_value = resource_kind();
    let id_value = resource_id();
    let reason_value = reason();
    let operator_value = operator();
    let evidence_value = evidence();
    let loading_now = loading();
    let status_text = status();
    let error_text = error();
    let response_view = response();

    let submit = move |_| {
        let id = resource_id().trim().to_string();
        let reason_text = reason().trim().to_string();
        if id.is_empty() {
            error.set("resource_id is required".to_string());
            return;
        }
        if reason_text.is_empty() {
            error.set("reason is required".to_string());
            return;
        }
        let evidence_json = match parse_evidence(&evidence()) {
            Ok(value) => value,
            Err(message) => {
                error.set(message);
                return;
            }
        };
        let kind = match serde_json::from_value(JsonValue::String(resource_kind())) {
            Ok(kind) => kind,
            Err(parse_error) => {
                error.set(format!("invalid resource_kind: {parse_error}"));
                return;
            }
        };
        let body = OperatorTakedownRequestBody {
            resource_kind: kind,
            resource_id: id,
            reason: reason_text,
            operator: option_string(operator()),
            evidence: evidence_json,
            effective_at: None,
        };
        let base_url = base_url.clone();
        let token = token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Submitting takedown".to_string());
        spawn(async move {
            match post_admin::<OperatorTakedownRequestBody, OperatorTakedownOutcome>(
                base_url, token, "takedown", &body,
            )
            .await
            {
                Ok(payload) => {
                    response.set(Some(payload));
                    status.set("Takedown accepted".to_string());
                }
                Err(message) => {
                    error.set(message);
                    status.set("Takedown failed".to_string());
                }
            }
            loading.set(false);
        });
    };

    rsx! {
        div { class: "panel",
            PanelHeader {
                title: "Operator takedown",
                actions: rsx! {
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: submit,
                        SendIcon {}
                        "Submit"
                    }
                },
            }
            div { class: "split",
                div { class: "form-surface",
                    div { class: "field",
                        label { "Kind" }
                        select {
                            value: "{kind_value}",
                            onchange: move |event| resource_kind.set(event.value()),
                            for item in DirectoryResourceKind::ALL.map(DirectoryResourceKind::as_str) {
                                option { value: "{item}", "{item}" }
                            }
                        }
                    }
                    div { class: "field",
                        label { "Resource id" }
                        input {
                            value: "{id_value}",
                            oninput: move |event| resource_id.set(event.value()),
                        }
                    }
                    div { class: "field",
                        label { "Reason" }
                        input {
                            value: "{reason_value}",
                            oninput: move |event| reason.set(event.value()),
                        }
                    }
                    div { class: "field",
                        label { "Operator" }
                        input {
                            value: "{operator_value}",
                            oninput: move |event| operator.set(event.value()),
                        }
                    }
                    div { class: "field",
                        label { "Evidence JSON" }
                        textarea {
                            value: "{evidence_value}",
                            oninput: move |event| evidence.set(event.value()),
                        }
                    }
                }
                div {
                    StatusLine { status: status_text, error: error_text }
                    div { class: "result-box mono",
                        match response_view {
                            Some(payload) => rsx! {
                                div { "withdraw_id: {payload.withdraw_id}" }
                                div { "acked_at: {payload.acked_at}" }
                                div { "effective_at: {payload.effective_at}" }
                                div { "notification_status: {payload.notification_status}" }
                            },
                            None => rsx! { div { class: "muted", "No submission" } },
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn AppealDecisionPanel(base_url: String, token: String) -> Element {
    let base_url: Rc<str> = Rc::from(base_url);
    let token: Rc<str> = Rc::from(token);
    let mut appeal_id = use_signal(String::new);
    let mut decision = use_signal(|| "upheld".to_string());
    let mut reason = use_signal(String::new);
    let mut decided_by = use_signal(|| "admin-console".to_string());
    let mut evidence_digest = use_signal(String::new);
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);
    let mut response = use_signal(Option::<TakedownAppealDecisionOutcome>::default);

    let appeal_id_value = appeal_id();
    let decision_value = decision();
    let reason_value = reason();
    let decided_by_value = decided_by();
    let evidence_digest_value = evidence_digest();
    let loading_now = loading();
    let status_text = status();
    let error_text = error();
    let response_detail = response().as_ref().map(|payload| {
        (
            payload.appeal_id.clone(),
            payload.takedown_id.clone(),
            payload.decision.as_str().to_string(),
            payload.decided_at.to_string(),
            pretty_json(payload.receipt.as_value()),
        )
    });

    let submit = move |_| {
        let appeal_id_text = appeal_id().trim().to_string();
        let reason_text = reason().trim().to_string();
        if appeal_id_text.is_empty() {
            error.set("appeal_id is required".to_string());
            return;
        }
        if reason_text.is_empty() {
            error.set("reason is required".to_string());
            return;
        }
        let decision_kind = match decision().as_str() {
            "overturned" => TakedownAppealDecision::Overturned,
            _ => TakedownAppealDecision::Upheld,
        };
        let body = TakedownAppealDecisionRequestBody {
            appeal_id: appeal_id_text,
            decision: decision_kind,
            reason: reason_text,
            decided_by: option_string(decided_by()),
            evidence_digest: option_string(evidence_digest()),
        };
        let base_url = base_url.clone();
        let token = token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Submitting appeal decision".to_string());
        spawn(async move {
            match post_admin::<TakedownAppealDecisionRequestBody, TakedownAppealDecisionOutcome>(
                base_url,
                token,
                "takedown/appeals/decision",
                &body,
            )
            .await
            {
                Ok(payload) => {
                    response.set(Some(payload));
                    status.set("Appeal decision recorded".to_string());
                }
                Err(message) => {
                    error.set(message);
                    status.set("Appeal decision failed".to_string());
                }
            }
            loading.set(false);
        });
    };

    rsx! {
        div { class: "panel",
            PanelHeader {
                title: "Appeal decision",
                actions: rsx! {
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: submit,
                        SendIcon {}
                        "Submit"
                    }
                },
            }
            div { class: "split",
                div { class: "form-surface",
                    div { class: "field",
                        label { "Appeal id" }
                        input {
                            value: "{appeal_id_value}",
                            oninput: move |event| appeal_id.set(event.value()),
                        }
                    }
                    div { class: "field",
                        label { "Decision" }
                        select {
                            value: "{decision_value}",
                            onchange: move |event| decision.set(event.value()),
                            option { value: "upheld", "upheld" }
                            option { value: "overturned", "overturned" }
                        }
                    }
                    div { class: "field",
                        label { "Reason" }
                        input {
                            value: "{reason_value}",
                            oninput: move |event| reason.set(event.value()),
                        }
                    }
                    div { class: "field",
                        label { "Decided by" }
                        input {
                            value: "{decided_by_value}",
                            oninput: move |event| decided_by.set(event.value()),
                        }
                    }
                    div { class: "field",
                        label { "Evidence digest" }
                        input {
                            value: "{evidence_digest_value}",
                            oninput: move |event| evidence_digest.set(event.value()),
                        }
                    }
                }
                div {
                    StatusLine { status: status_text, error: error_text }
                    div { class: "result-box mono",
                        match response_detail {
                            Some((appeal_id, takedown_id, decision, decided_at, receipt)) => rsx! {
                                div { "appeal_id: {appeal_id}" }
                                div { "takedown_id: {takedown_id}" }
                                div { "decision: {decision}" }
                                div { "decided_at: {decided_at}" }
                                pre { "{receipt}" }
                            },
                            None => rsx! { div { class: "muted", "No decision" } },
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn AuditPanel(base_url: String, token: String) -> Element {
    let base_url: Rc<str> = Rc::from(base_url);
    let token: Rc<str> = Rc::from(token);
    let mut rows = use_signal(Vec::<AuditEvent>::new);
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);
    let mut since = use_signal(String::new);
    let mut limit = use_signal(|| "100".to_string());
    let mut verification = use_signal(Option::<AuditChainVerificationOutcome>::default);

    let rows_view = rows();
    let loading_now = loading();
    let status_text = status();
    let error_text = error();
    let since_value = since();
    let limit_value = limit();
    let row_count = rows_view.len();
    let verification_view = verification();

    let load_base_url = base_url.clone();
    let load_token = token.clone();
    let load = move |_| {
        let mut params = vec![("limit", nonempty_or(&limit(), "100"))];
        push_param(&mut params, "since", since());
        let base_url = load_base_url.clone();
        let token = load_token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Loading audit feed".to_string());
        spawn(async move {
            match get_admin::<AuditEnvelope>(base_url, token, "audit", params).await {
                Ok(payload) => {
                    let count = payload.events.len();
                    rows.set(payload.events);
                    status.set(format!("{count} audit events"));
                }
                Err(message) => {
                    error.set(message);
                    status.set("Audit query failed".to_string());
                }
            }
            loading.set(false);
        });
    };
    let verify_base_url = base_url.clone();
    let verify_token = token.clone();
    let verify = move |_| {
        let base_url = verify_base_url.clone();
        let token = verify_token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Verifying audit chain".to_string());
        spawn(async move {
            match get_admin::<AuditChainVerificationOutcome>(
                base_url,
                token,
                "audit/verify",
                vec![],
            )
            .await
            {
                Ok(payload) => {
                    status.set(if payload.ok {
                        format!("Audit chain ok: {} rows", payload.chain_rows)
                    } else {
                        "Audit chain verification failed".to_string()
                    });
                    verification.set(Some(payload));
                }
                Err(message) => {
                    error.set(message);
                    status.set("Audit chain verify failed".to_string());
                }
            }
            loading.set(false);
        });
    };

    rsx! {
        div { class: "panel",
            PanelHeader {
                title: "Audit log",
                badges: rsx! {
                    span { class: BADGE_NEUTRAL, "{row_count} rows" }
                },
                actions: rsx! {
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: load,
                        RefreshIcon {}
                        "Load"
                    }
                    button {
                        class: "button",
                        disabled: loading_now,
                        onclick: verify,
                        ListIcon {}
                        "Verify"
                    }
                },
            }
            div { class: "toolbar",
                div { class: "field span-8",
                    label { "Since" }
                    input {
                        placeholder: "2026-05-10T00:00:00Z",
                        value: "{since_value}",
                        oninput: move |event| since.set(event.value()),
                    }
                }
                div { class: "field span-2",
                    label { "Limit" }
                    input {
                        r#type: "number",
                        min: "1",
                        max: "500",
                        value: "{limit_value}",
                        oninput: move |event| limit.set(event.value()),
                    }
                }
            }
            StatusLine { status: status_text, error: error_text }
            if let Some(outcome) = verification_view {
                AuditChainVerificationBox { outcome }
            }
            AuditTable { rows: rows_view }
        }
    }
}

#[component]
fn AuditChainVerificationBox(outcome: AuditChainVerificationOutcome) -> Element {
    let tone = if outcome.ok {
        BADGE_NEUTRAL
    } else {
        BADGE_WARN
    };
    let status_label = if outcome.ok { "ok" } else { "failed" };
    let head_digest = outcome.head_digest.clone().unwrap_or_default();
    let first_audit_id = outcome
        .first_audit_id
        .map(|value| value.to_string())
        .unwrap_or_default();
    let last_audit_id = outcome
        .last_audit_id
        .map(|value| value.to_string())
        .unwrap_or_default();
    let failure_text = outcome.failure.as_ref().map(|failure| {
        format!(
            "{} at audit_id {} expected={} actual={}",
            failure.reason,
            failure.audit_id,
            failure.expected.as_deref().unwrap_or(""),
            failure.actual.as_deref().unwrap_or("")
        )
    });
    rsx! {
        div { class: "result-box mono",
            div { span { class: tone, "{status_label}" } }
            div { "checked_rows: {outcome.checked_rows}" }
            div { "chain_rows: {outcome.chain_rows}" }
            div { "first_audit_id: {first_audit_id}" }
            div { "last_audit_id: {last_audit_id}" }
            div { "head_digest: {head_digest}" }
            if let Some(failure) = failure_text {
                div { "{failure}" }
            }
        }
    }
}

#[component]
pub fn ReviewPanel(base_url: String, token: String) -> Element {
    let base_url: Rc<str> = Rc::from(base_url);
    let token: Rc<str> = Rc::from(token);
    let mut rows = use_signal(Vec::<AuditEvent>::new);
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);
    let mut limit = use_signal(|| "100".to_string());

    let rows_view = rows();
    let loading_now = loading();
    let status_text = status();
    let error_text = error();
    let limit_value = limit();
    let row_count = rows_view.len();

    let load = move |_| {
        let params = vec![("limit", nonempty_or(&limit(), "100"))];
        let base_url = base_url.clone();
        let token = token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Loading review queue".to_string());
        spawn(async move {
            match get_admin::<AuditEnvelope>(base_url, token, "audit", params).await {
                Ok(payload) => {
                    let filtered: Vec<_> =
                        payload.events.into_iter().filter(is_review_event).collect();
                    let count = filtered.len();
                    rows.set(filtered);
                    status.set(format!("{count} review items"));
                }
                Err(message) => {
                    error.set(message);
                    status.set("Review load failed".to_string());
                }
            }
            loading.set(false);
        });
    };

    rsx! {
        div { class: "panel",
            PanelHeader {
                title: "Operator review",
                badges: rsx! {
                    span { class: BADGE_NEUTRAL, "{row_count} items" }
                    span { class: BADGE_WARN, "audit-backed" }
                },
                actions: rsx! {
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: load,
                        ListIcon {}
                        "Load"
                    }
                },
            }
            div { class: "toolbar",
                div { class: "field span-2",
                    label { "Limit" }
                    input {
                        r#type: "number",
                        min: "1",
                        max: "500",
                        value: "{limit_value}",
                        oninput: move |event| limit.set(event.value()),
                    }
                }
            }
            StatusLine { status: status_text, error: error_text }
            AuditTable { rows: rows_view }
        }
    }
}

fn load_allowlist_entries(
    base_url: Rc<str>,
    token: Rc<str>,
    limit: String,
    mut rows: Signal<Vec<AllowlistItem>>,
    mut loading: Signal<bool>,
    mut status: Signal<String>,
    mut error: Signal<String>,
) {
    let params = vec![("limit", nonempty_or(&limit, "100"))];
    loading.set(true);
    error.set(String::new());
    status.set("Loading allowlist".to_string());
    spawn(async move {
        match get_admin::<AllowlistEnvelope>(base_url, token, "allowlist", params).await {
            Ok(payload) => {
                let count = payload.items.len();
                rows.set(payload.items);
                status.set(format!("{count} allowlist entries"));
            }
            Err(message) => {
                error.set(message);
                status.set("Allowlist query failed".to_string());
            }
        }
        loading.set(false);
    });
}
