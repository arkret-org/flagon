use std::rc::Rc;

use dioxus::prelude::*;
use serde_json::{Value as JsonValue, json};

use crate::api::{get_admin, insert_optional_string, optional_u32, post_directory, pretty_json};
use crate::icons::{DashboardIcon, SearchIcon};
use crate::model::{BADGE_NEUTRAL, DashboardStats, badge_class_for};
use crate::shell::{PanelHeader, StatusLine};

#[component]
pub fn DashboardPanel(base_url: String, token: String) -> Element {
    let base_url: Rc<str> = Rc::from(base_url);
    let token: Rc<str> = Rc::from(token);
    let mut stats = use_signal(Option::<DashboardStats>::default);
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);

    let stats_view = stats();
    let loading_now = loading();
    let status_text = status();
    let error_text = error();

    let load = move |_| {
        let base_url = Rc::clone(&base_url);
        let token = Rc::clone(&token);
        loading.set(true);
        error.set(String::new());
        status.set("Loading directory stats".to_string());
        spawn(async move {
            match get_admin::<DashboardStats>(base_url, token, "dashboard", vec![]).await {
                Ok(payload) => {
                    status.set(format!("Snapshot as of {}", payload.as_of));
                    stats.set(Some(payload));
                }
                Err(message) => {
                    error.set(message);
                    status.set("Dashboard query failed".to_string());
                }
            }
            loading.set(false);
        });
    };

    rsx! {
        div { class: "panel",
            PanelHeader {
                title: "Directory dashboard",
                badges: rsx! {
                    span { class: BADGE_NEUTRAL, "operator overview" }
                },
                actions: rsx! {
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: load,
                        DashboardIcon {}
                        "Refresh"
                    }
                },
            }
            StatusLine { status: status_text, error: error_text }
            match stats_view {
                Some(payload) => rsx! {
                    div { class: "form-grid",
                        DashboardTile {
                            label: "Directory resources",
                            value: payload.directory_resources.to_string(),
                            tone: "ok".to_string(),
                        }
                        DashboardTile {
                            label: "Freshness stale rows",
                            value: payload.stale_resources.to_string(),
                            tone: if payload.stale_resources > 0 { "warn".to_string() } else { "ok".to_string() },
                        }
                        DashboardTile {
                            label: "Divergent",
                            value: payload.divergent_resources.to_string(),
                            tone: if payload.divergent_resources > 0 { "danger".to_string() } else { "ok".to_string() },
                        }
                        DashboardTile {
                            label: "Realms destroyed",
                            value: payload.realm_destroyed.to_string(),
                            tone: "neutral".to_string(),
                        }
                        DashboardTile {
                            label: "Ingest announces",
                            value: payload.ingest_announces.to_string(),
                            tone: "neutral".to_string(),
                        }
                        DashboardTile {
                            label: "Webhook subscriptions",
                            value: payload.webhook_subscriptions.to_string(),
                            tone: "neutral".to_string(),
                        }
                        DashboardTile {
                            label: "Audit events",
                            value: payload.audit_events.to_string(),
                            tone: "neutral".to_string(),
                        }
                        DashboardTile {
                            label: "Allowlist entries",
                            value: payload.allowlist_entries.to_string(),
                            tone: "neutral".to_string(),
                        }
                    }
                    div { class: "table-wrap",
                        table {
                            thead {
                                tr {
                                    th { "Resource kind" }
                                    th { "Indexed rows" }
                                }
                            }
                            tbody {
                                for row in payload.per_kind {
                                    tr {
                                        td { span { class: BADGE_NEUTRAL, "{row.resource_kind}" } }
                                        td { class: "mono", "{row.count}" }
                                    }
                                }
                            }
                        }
                    }
                },
                None => rsx! { div { class: "muted", "Press Refresh to load directory statistics." } },
            }
        }
    }
}

#[component]
fn DashboardTile(label: String, value: String, tone: String) -> Element {
    let badge_class = badge_class_for(&tone);
    rsx! {
        div { class: "field span-3",
            label { "{label}" }
            div { class: "metric-row",
                span { class: badge_class, "{value}" }
            }
        }
    }
}

#[component]
pub fn DiagnosticsPanel(base_url: String) -> Element {
    let base_url: Rc<str> = Rc::from(base_url);
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);
    let mut subject = use_signal(String::new);
    let mut subject_realm = use_signal(String::new);
    let mut subject_requester = use_signal(String::new);
    let mut subject_intent = use_signal(String::new);
    let mut subject_limit = use_signal(|| "20".to_string());
    let mut subject_cursor = use_signal(String::new);
    let mut subject_result = use_signal(|| "{}".to_string());
    let mut target_address = use_signal(String::new);
    let mut target_requester = use_signal(String::new);
    let mut target_token = use_signal(String::new);
    let mut target_result = use_signal(|| "{}".to_string());

    let loading_now = loading();
    let status_text = status();
    let error_text = error();
    let subject_value = subject();
    let subject_realm_value = subject_realm();
    let subject_requester_value = subject_requester();
    let subject_intent_value = subject_intent();
    let subject_limit_value = subject_limit();
    let subject_cursor_value = subject_cursor();
    let subject_result_value = subject_result();
    let target_address_value = target_address();
    let target_requester_value = target_requester();
    let target_token_value = target_token();
    let target_result_value = target_result();

    let handles_base_url = Rc::clone(&base_url);
    let run_subject_lookup = move |_| {
        let subject_text = subject().trim().to_string();
        if subject_text.is_empty() {
            error.set("subject is required".to_string());
            return;
        }
        let limit_text = subject_limit();
        let limit = match optional_u32(&limit_text, "limit") {
            Ok(value) => value,
            Err(message) => {
                error.set(message);
                return;
            }
        };
        let mut body = serde_json::Map::new();
        body.insert("subject".to_string(), JsonValue::String(subject_text));
        insert_optional_string(&mut body, "realm_id", &subject_realm());
        insert_optional_string(&mut body, "requester", &subject_requester());
        insert_optional_string(&mut body, "intent", &subject_intent());
        insert_optional_string(&mut body, "cursor", &subject_cursor());
        if let Some(limit) = limit {
            body.insert("limit".to_string(), json!(limit));
        }

        let base_url = handles_base_url.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Querying subject handles".to_string());
        spawn(async move {
            let body = JsonValue::Object(body);
            match post_directory::<JsonValue, JsonValue>(
                base_url,
                "list-handles-for-subject",
                &body,
            )
            .await
            {
                Ok(payload) => {
                    subject_result.set(pretty_json(&payload));
                    status.set("Subject handles loaded".to_string());
                }
                Err(message) => {
                    error.set(message);
                    status.set("Subject handles query failed".to_string());
                }
            }
            loading.set(false);
        });
    };

    let target_base_url = base_url.clone();
    let run_target_resolve = move |_| {
        let address = target_address().trim().to_string();
        if address.is_empty() {
            error.set("address is required".to_string());
            return;
        }
        let mut body = serde_json::Map::new();
        body.insert("address".to_string(), JsonValue::String(address));
        insert_optional_string(&mut body, "requester", &target_requester());
        insert_optional_string(&mut body, "token", &target_token());

        let base_url = target_base_url.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Resolving target".to_string());
        spawn(async move {
            let body = JsonValue::Object(body);
            match post_directory::<JsonValue, JsonValue>(base_url, "resolve-target", &body).await {
                Ok(payload) => {
                    target_result.set(pretty_json(&payload));
                    status.set("Target resolved".to_string());
                }
                Err(message) => {
                    error.set(message);
                    status.set("Target resolve failed".to_string());
                }
            }
            loading.set(false);
        });
    };

    rsx! {
        div { class: "panel",
            PanelHeader {
                title: "Directory diagnostics",
                badges: rsx! {
                    span { class: BADGE_NEUTRAL, "query face" }
                },
            }
            StatusLine { status: status_text, error: error_text }
            div { class: "form-surface",
                div { class: "panel-title",
                    h1 { "Subject to handles" }
                }
                div { class: "form-grid",
                    div { class: "field span-4",
                        label { "Subject DID" }
                        input {
                            value: "{subject_value}",
                            oninput: move |event| subject.set(event.value()),
                        }
                    }
                    div { class: "field span-4",
                        label { "Realm ID" }
                        input {
                            value: "{subject_realm_value}",
                            oninput: move |event| subject_realm.set(event.value()),
                        }
                    }
                    div { class: "field span-4",
                        label { "Requester DID" }
                        input {
                            value: "{subject_requester_value}",
                            oninput: move |event| subject_requester.set(event.value()),
                        }
                    }
                    div { class: "field span-4",
                        label { "Intent" }
                        input {
                            value: "{subject_intent_value}",
                            oninput: move |event| subject_intent.set(event.value()),
                        }
                    }
                    div { class: "field span-4",
                        label { "Cursor" }
                        input {
                            value: "{subject_cursor_value}",
                            oninput: move |event| subject_cursor.set(event.value()),
                        }
                    }
                    div { class: "field span-2",
                        label { "Limit" }
                        input {
                            value: "{subject_limit_value}",
                            oninput: move |event| subject_limit.set(event.value()),
                        }
                    }
                    div { class: "actions span-2",
                        button {
                            class: "button primary",
                            disabled: loading_now,
                            onclick: run_subject_lookup,
                            SearchIcon {}
                            "Query"
                        }
                    }
                    div { class: "field span-12",
                        label { "Response JSON" }
                        textarea {
                            class: "mono",
                            value: "{subject_result_value}",
                        }
                    }
                }
            }
            div { class: "form-surface",
                div { class: "panel-title",
                    h1 { "Resolve target" }
                }
                div { class: "form-grid",
                    div { class: "field span-6",
                        label { "Address" }
                        input {
                            value: "{target_address_value}",
                            oninput: move |event| target_address.set(event.value()),
                        }
                    }
                    div { class: "field span-3",
                        label { "Requester DID" }
                        input {
                            value: "{target_requester_value}",
                            oninput: move |event| target_requester.set(event.value()),
                        }
                    }
                    div { class: "field span-3",
                        label { "Invite token" }
                        input {
                            value: "{target_token_value}",
                            oninput: move |event| target_token.set(event.value()),
                        }
                    }
                    div { class: "actions span-12",
                        button {
                            class: "button primary",
                            disabled: loading_now,
                            onclick: run_target_resolve,
                            SearchIcon {}
                            "Resolve"
                        }
                    }
                    div { class: "field span-12",
                        label { "Response JSON" }
                        textarea {
                            class: "mono",
                            value: "{target_result_value}",
                        }
                    }
                }
            }
        }
    }
}
