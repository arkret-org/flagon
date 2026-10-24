use std::rc::Rc;

use dioxus::prelude::*;

use crate::api::{compact_json, get_admin};
use crate::icons::{DatabaseIcon, ListIcon, RefreshIcon, ShieldIcon};
use crate::model::{
    AuditChainVerificationOutcome, AuditEnvelope, AuditEvent, BADGE_NEUTRAL, BADGE_WARN,
};

#[allow(non_snake_case)]
pub fn App() -> Element {
    let base_url = use_signal(|| "http://localhost:7781".to_string());
    let token = use_signal(String::new);
    rsx! {
        document::Stylesheet { href: asset!("/assets/main.css") }
        main { class: "app-shell",
            TopBar { base_url, token }
            section { class: "workspace",
                AuditPanel { base_url: base_url(), token: token() }
            }
        }
    }
}

#[component]
fn TopBar(mut base_url: Signal<String>, mut token: Signal<String>) -> Element {
    let api_base = base_url();
    let api_token = token();
    rsx! {
        header { class: "topbar",
            div { class: "brand",
                div { class: "brand-title", "flagon admin" }
                div { class: "brand-subtitle", "audit-only operator console" }
            }
            div { class: "field",
                label { "API base" }
                input { value: "{api_base}", oninput: move |event| base_url.set(event.value()) }
            }
            div { class: "field",
                label { "Bearer token" }
                input {
                    r#type: "password",
                    value: "{api_token}",
                    oninput: move |event| token.set(event.value()),
                }
            }
        }
    }
}

#[component]
fn AuditPanel(base_url: String, token: String) -> Element {
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
        let mut parameters = vec![(
            "limit",
            if limit().trim().is_empty() {
                "100".to_string()
            } else {
                limit()
            },
        )];
        if !since().trim().is_empty() {
            parameters.push(("since", since()));
        }
        let base_url = load_base_url.clone();
        let token = load_token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Loading audit feed".to_string());
        spawn(async move {
            match get_admin::<AuditEnvelope>(base_url, token, "audit", parameters).await {
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
            div { class: "panel-head",
                div { class: "panel-title",
                    h1 { "Audit log" }
                    div { class: "metric-row", span { class: BADGE_NEUTRAL, "{row_count} rows" } }
                }
                div { class: "actions",
                    button { class: "button primary", disabled: loading_now, onclick: load,
                        RefreshIcon {}
                        "Load"
                    }
                    button { class: "button", disabled: loading_now, onclick: verify,
                        ListIcon {}
                        "Verify"
                    }
                }
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
                        r#type: "number", min: "1", max: "500", value: "{limit_value}",
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
fn StatusLine(status: String, error: String) -> Element {
    let has_error = !error.is_empty();
    rsx! {
        div { class: if has_error { "status-line error" } else { "status-line" },
            if has_error { ShieldIcon {} span { "{error}" } }
            else { DatabaseIcon {} span { "{status}" } }
        }
    }
}

#[component]
fn AuditTable(rows: Vec<AuditEvent>) -> Element {
    rsx! {
        div { class: "table-wrap",
            table {
                thead { tr { th { "Time" } th { "Kind" } th { "Resource" } th { "Actor" } th { "Detail" } } }
                tbody { for item in rows { AuditRow { key: "{item.audit_id}", item } } }
            }
        }
    }
}

#[component]
fn AuditRow(item: AuditEvent) -> Element {
    let resource_id = item.resource_id.clone().unwrap_or_default();
    let resource_kind = item.resource_kind.clone().unwrap_or_default();
    let actor = item
        .actor_id
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    let detail = compact_json(&item.detail);
    rsx! {
        tr {
            td { class: "mono", "{item.occurred_at}" }
            td { span { class: BADGE_NEUTRAL, "{item.kind}" } }
            td { div { class: "mono", "{resource_id}" } div { class: "muted", "{resource_kind}" } }
            td { "{actor}" }
            td { class: "mono", "{detail}" }
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
            if let Some(failure) = failure_text { div { "{failure}" } }
        }
    }
}
