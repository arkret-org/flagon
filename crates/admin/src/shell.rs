use dioxus::prelude::*;

use crate::api::{audit_badge_class, compact_json};
use crate::icons::{DatabaseIcon, ShieldIcon};
use crate::model::{AuditEvent, Tab};
use crate::panels::dashboard::{DashboardPanel, DiagnosticsPanel};
use crate::panels::moderation::{
    AllowlistPanel, AppealDecisionPanel, AuditPanel, ReviewPanel, TakedownPanel,
};
use crate::panels::resources::ResourcesPanel;

#[allow(non_snake_case)]
pub fn App() -> Element {
    // These signals are only passed down as props; App itself does not read
    // (subscribe to) them, so topbar input or tab switches never re-run the
    // whole App.
    let active_tab = use_signal(|| Tab::Resources);
    let base_url = use_signal(|| "http://localhost:7781".to_string());
    let token = use_signal(String::new);

    rsx! {
        document::Stylesheet { href: asset!("/assets/main.css") }
        main { class: "app-shell",
            TopBar { base_url, token }
            TabBar { active_tab }
            Workspace { active_tab, base_url, token }
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
                div { class: "brand-title", "teabay admin" }
                div { class: "brand-subtitle", "operator console" }
            }
            div { class: "field",
                label { "API base" }
                input {
                    value: "{api_base}",
                    oninput: move |event| base_url.set(event.value()),
                }
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
fn TabBar(mut active_tab: Signal<Tab>) -> Element {
    let selected = active_tab();
    rsx! {
        nav { class: "tabs", aria_label: "Admin sections",
            for tab in Tab::ALL {
                button {
                    class: if selected == tab { "tab active" } else { "tab" },
                    onclick: move |_| active_tab.set(tab),
                    "{tab.label()}"
                }
            }
        }
    }
}

#[component]
fn Workspace(active_tab: Signal<Tab>, base_url: Signal<String>, token: Signal<String>) -> Element {
    // Only this component subscribes to active_tab/base_url/token; switching
    // tabs or editing the connection params only re-runs the active panel.
    let selected = active_tab();
    let api_base = base_url();
    let api_token = token();
    rsx! {
        section { class: "workspace",
            match selected {
                Tab::Dashboard => rsx! { DashboardPanel { base_url: api_base.clone(), token: api_token.clone() } },
                Tab::Resources => rsx! { ResourcesPanel { base_url: api_base.clone(), token: api_token.clone() } },
                Tab::Diagnostics => rsx! { DiagnosticsPanel { base_url: api_base.clone() } },
                Tab::Allowlist => rsx! { AllowlistPanel { base_url: api_base.clone(), token: api_token.clone() } },
                Tab::Takedown => rsx! { TakedownPanel { base_url: api_base.clone(), token: api_token.clone() } },
                Tab::Appeals => rsx! { AppealDecisionPanel { base_url: api_base.clone(), token: api_token.clone() } },
                Tab::Audit => rsx! { AuditPanel { base_url: api_base.clone(), token: api_token.clone() } },
                Tab::Review => rsx! { ReviewPanel { base_url: api_base.clone(), token: api_token.clone() } },
            }
        }
    }
}

/// Shared panel header shell: `.panel-head > (.panel-title(h1 + .metric-row
/// badges)) + .actions`. `badges` / `actions` are optional slots; callers pass
/// `rsx! { ... }`, or omit them.
#[component]
pub fn PanelHeader(
    title: String,
    #[props(default)] badges: Option<Element>,
    #[props(default)] actions: Option<Element>,
) -> Element {
    rsx! {
        div { class: "panel-head",
            div { class: "panel-title",
                h1 { "{title}" }
                if let Some(badges) = badges {
                    div { class: "metric-row", {badges} }
                }
            }
            if let Some(actions) = actions {
                div { class: "actions", {actions} }
            }
        }
    }
}

#[component]
pub fn StatusLine(status: String, error: String) -> Element {
    let has_error = !error.is_empty();
    rsx! {
        div { class: if has_error { "status-line error" } else { "status-line" },
            if has_error {
                ShieldIcon {}
                span { "{error}" }
            } else {
                DatabaseIcon {}
                span { "{status}" }
            }
        }
    }
}

#[component]
pub fn AuditTable(rows: Vec<AuditEvent>) -> Element {
    rsx! {
        div { class: "table-wrap",
            table {
                thead {
                    tr {
                        th { "Time" }
                        th { "Kind" }
                        th { "Resource" }
                        th { "Actor" }
                        th { "Detail" }
                    }
                }
                tbody {
                    for item in rows {
                        AuditRow { key: "{item.audit_id}", item }
                    }
                }
            }
        }
    }
}

#[component]
fn AuditRow(item: AuditEvent) -> Element {
    let resource_id = item.resource_id.clone().unwrap_or_default();
    let resource_kind = item.resource_kind.clone().unwrap_or_default();
    let actor = item.actor.clone().unwrap_or_default();
    let detail = compact_json(&item.detail);
    let badge_class = audit_badge_class(&item.kind);

    rsx! {
        tr {
            td { class: "mono", "{item.occurred_at}" }
            td { span { class: badge_class, "{item.kind}" } }
            td {
                div { class: "mono", "{resource_id}" }
                div { class: "muted", "{resource_kind}" }
            }
            td { "{actor}" }
            td { class: "mono", "{detail}" }
        }
    }
}
