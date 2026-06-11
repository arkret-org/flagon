use std::rc::Rc;

use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::ld_icons::{
    LdDatabase, LdFileText, LdLayoutDashboard, LdListChecks, LdPlus, LdRefreshCw, LdSave, LdSearch,
    LdSend, LdShield, LdTrash2,
};
use gloo_net::http::{Request, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

const BADGE_NEUTRAL: &str = "badge neutral";
const BADGE_OK: &str = "badge ok";
const BADGE_WARN: &str = "badge warn";
const BADGE_DANGER: &str = "badge danger";

/// 把 tone 名称映射到完整的 badge class,避免每次渲染都 `format!`。
fn badge_class_for(tone: &str) -> &'static str {
    match tone {
        "ok" => BADGE_OK,
        "warn" => BADGE_WARN,
        "danger" => BADGE_DANGER,
        _ => BADGE_NEUTRAL,
    }
}

const RESOURCE_KINDS: [&str; 5] = ["realm", "organization", "actor", "applet", "handle"];
const DISCOVERABILITY_LEVELS: [&str; 6] = [
    "public",
    "listed",
    "restricted",
    "unlisted",
    "invite_only",
    "secret",
];

fn main() {
    dioxus::launch(App);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Resources,
    Diagnostics,
    Allowlist,
    Takedown,
    Audit,
    Review,
}

impl Tab {
    const ALL: [Self; 7] = [
        Self::Dashboard,
        Self::Resources,
        Self::Diagnostics,
        Self::Allowlist,
        Self::Takedown,
        Self::Audit,
        Self::Review,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Resources => "Resources",
            Self::Diagnostics => "Diagnostics",
            Self::Allowlist => "Allowlist",
            Self::Takedown => "Takedown",
            Self::Audit => "Audit",
            Self::Review => "Review",
        }
    }
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct DashboardStats {
    #[serde(default)]
    directory_resources: i64,
    #[serde(default)]
    stale_resources: i64,
    #[serde(default)]
    divergent_resources: i64,
    #[serde(default)]
    realm_destroyed: i64,
    #[serde(default)]
    ingest_announces: i64,
    #[serde(default)]
    webhook_subscriptions: i64,
    #[serde(default)]
    audit_events: i64,
    #[serde(default)]
    allowlist_entries: i64,
    #[serde(default)]
    per_kind: Vec<DashboardKindCount>,
    #[serde(default)]
    as_of: String,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct DashboardKindCount {
    #[serde(default)]
    resource_kind: String,
    #[serde(default)]
    count: i64,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct ResourceList {
    #[serde(default)]
    items: Vec<ResourceItem>,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct ResourceItem {
    #[serde(default)]
    resource_kind: String,
    #[serde(default)]
    resource_id: String,
    #[serde(default)]
    principal_server_did: String,
    #[serde(default)]
    discovery_state: JsonValue,
    #[serde(default)]
    public_projection: JsonValue,
    #[serde(default)]
    discoverability: String,
    #[serde(default)]
    as_of: String,
    #[serde(default)]
    source_refs: Vec<String>,
    #[serde(default)]
    policy_revision: Option<String>,
    #[serde(default)]
    indexed_at: String,
    #[serde(default)]
    effective_ttl_seconds: i32,
    #[serde(default)]
    next_revalidation_after: String,
    #[serde(default)]
    stale: bool,
    #[serde(default)]
    divergent: bool,
    #[serde(default)]
    via_services: Vec<String>,
    #[serde(default)]
    last_announce_id: Option<String>,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct AllowlistEnvelope {
    #[serde(default)]
    items: Vec<AllowlistItem>,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct AllowlistItem {
    #[serde(default)]
    resource_did: String,
    #[serde(default)]
    added_by: String,
    #[serde(default)]
    added_at: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct AuditEnvelope {
    #[serde(default)]
    events: Vec<AuditEvent>,
    #[serde(default)]
    next_since: Option<String>,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct AuditEvent {
    #[serde(default)]
    audit_id: i64,
    #[serde(default)]
    occurred_at: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    resource_kind: Option<String>,
    #[serde(default)]
    resource_id: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    detail: JsonValue,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct OperatorTakedownOutcome {
    #[serde(default)]
    withdraw_id: String,
    #[serde(default)]
    acked_at: String,
    #[serde(default)]
    effective_at: String,
    #[serde(default)]
    notification_status: String,
}

#[derive(Serialize)]
struct DirectoryAdminAllowlistUpsertRequestBody {
    resource_did: String,
    added_by: Option<String>,
    note: Option<String>,
}

#[derive(Serialize)]
struct OperatorTakedownRequestBody {
    resource_kind: String,
    resource_id: String,
    reason: String,
    operator: Option<String>,
    evidence: JsonValue,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct ResourceMutationEnvelope {
    #[serde(default)]
    item: ResourceItem,
}

#[derive(Clone, Default, Deserialize, PartialEq)]
struct DeleteCount {
    #[serde(default)]
    deleted: i64,
}

#[derive(Clone, Serialize)]
struct DirectoryAdminResourceUpsertRequestBody {
    resource_kind: String,
    resource_id: String,
    principal_server_did: String,
    discoverability: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    as_of: Option<String>,
    source_refs: Vec<String>,
    policy_revision: Option<String>,
    effective_ttl_seconds: Option<i64>,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
    public_projection: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    discovery_state: Option<JsonValue>,
    last_announce_id: Option<String>,
}

#[derive(Clone, PartialEq)]
struct ResourceEditorForm {
    resource_kind: String,
    resource_id: String,
    principal_server_did: String,
    discoverability: String,
    as_of: String,
    source_refs: String,
    policy_revision: String,
    effective_ttl_seconds: String,
    stale: bool,
    divergent: bool,
    via_services: String,
    public_projection: String,
    discovery_state: String,
    last_announce_id: String,
}

impl Default for ResourceEditorForm {
    fn default() -> Self {
        Self {
            resource_kind: "realm".to_string(),
            resource_id: String::new(),
            principal_server_did: String::new(),
            discoverability: "public".to_string(),
            as_of: String::new(),
            source_refs: "[\n  \"admin:manual\"\n]".to_string(),
            policy_revision: String::new(),
            effective_ttl_seconds: "86400".to_string(),
            stale: false,
            divergent: false,
            via_services: "[]".to_string(),
            public_projection: "{\n  \"name\": \"\",\n  \"summary\": \"\"\n}".to_string(),
            discovery_state: String::new(),
            last_announce_id: String::new(),
        }
    }
}

impl ResourceEditorForm {
    fn reset_for_kind(kind: &str) -> Self {
        let mut next = Self::default();
        if RESOURCE_KINDS.contains(&kind) {
            next.resource_kind = kind.to_string();
        }
        next
    }

    fn from_item(item: &ResourceItem) -> Self {
        Self {
            resource_kind: item.resource_kind.clone(),
            resource_id: item.resource_id.clone(),
            principal_server_did: item.principal_server_did.clone(),
            discoverability: item.discoverability.clone(),
            as_of: item.as_of.clone(),
            source_refs: pretty_string_array(&item.source_refs),
            policy_revision: item.policy_revision.clone().unwrap_or_default(),
            effective_ttl_seconds: item.effective_ttl_seconds.to_string(),
            stale: item.stale,
            divergent: item.divergent,
            via_services: pretty_string_array(&item.via_services),
            public_projection: pretty_json(&item.public_projection),
            discovery_state: pretty_json(&item.discovery_state),
            last_announce_id: item.last_announce_id.clone().unwrap_or_default(),
        }
    }

    fn to_body(&self) -> Result<DirectoryAdminResourceUpsertRequestBody, String> {
        let resource_id = self.resource_id.trim().to_string();
        if resource_id.is_empty() {
            return Err("resource_id is required".to_string());
        }

        let principal_server_did = self.principal_server_did.trim().to_string();
        if principal_server_did.is_empty() {
            return Err("principal_server_did is required".to_string());
        }

        if !RESOURCE_KINDS.contains(&self.resource_kind.as_str()) {
            return Err("resource_kind is invalid".to_string());
        }
        if !DISCOVERABILITY_LEVELS.contains(&self.discoverability.as_str()) {
            return Err("discoverability is invalid".to_string());
        }

        Ok(DirectoryAdminResourceUpsertRequestBody {
            resource_kind: self.resource_kind.clone(),
            resource_id,
            principal_server_did,
            discoverability: self.discoverability.clone(),
            as_of: option_string(self.as_of.clone()),
            source_refs: parse_string_array(&self.source_refs, "source_refs")?,
            policy_revision: option_string(self.policy_revision.clone()),
            effective_ttl_seconds: parse_optional_i64(
                &self.effective_ttl_seconds,
                "effective_ttl_seconds",
            )?,
            stale: self.stale,
            divergent: self.divergent,
            via_services: parse_string_array(&self.via_services, "via_services")?,
            public_projection: parse_json_object(&self.public_projection, "public_projection")?,
            discovery_state: parse_optional_json_object(&self.discovery_state, "discovery_state")?,
            last_announce_id: option_string(self.last_announce_id.clone()),
        })
    }
}

#[allow(non_snake_case)]
fn App() -> Element {
    // 这些 signal 仅作为 props 向下传递,App 本身不读取(不订阅),
    // 因此 topbar 输入或切 tab 都不会触发整个 App 重跑。
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
    // 只有此组件订阅 active_tab/base_url/token,切 tab 或改连接参数仅重跑当前面板。
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
                Tab::Audit => rsx! { AuditPanel { base_url: api_base.clone(), token: api_token.clone() } },
                Tab::Review => rsx! { ReviewPanel { base_url: api_base.clone(), token: api_token.clone() } },
            }
        }
    }
}

#[component]
fn DashboardPanel(base_url: String, token: String) -> Element {
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
fn DiagnosticsPanel(base_url: String) -> Element {
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

#[component]
fn ResourcesPanel(base_url: String, token: String) -> Element {
    let base_url: Rc<str> = Rc::from(base_url);
    let token: Rc<str> = Rc::from(token);
    let mut rows = use_signal(Vec::<ResourceItem>::new);
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);
    let mut kind = use_signal(String::new);
    let mut query = use_signal(String::new);
    let mut divergent = use_signal(|| "any".to_string());
    let mut stale = use_signal(|| "any".to_string());
    let mut limit = use_signal(|| "100".to_string());
    let mut selected_key = use_signal(String::new);
    let mut editor = use_signal(ResourceEditorForm::default);

    let rows_view = rows();
    let loading_now = loading();
    let status_text = status();
    let error_text = error();
    let kind_value = kind();
    let query_value = query();
    let divergent_value = divergent();
    let stale_value = stale();
    let limit_value = limit();
    let row_count = rows_view.len();
    let selected_key_value = selected_key();
    // 仅订阅“resource_id 是否为空”这一派生布尔,编辑器内逐字段打字不会触发本面板重渲染。
    let editor_id_empty = use_memo(move || editor.read().resource_id.trim().is_empty());
    let editor_id_empty = editor_id_empty();

    let load_base_url = base_url.clone();
    let load_token = token.clone();
    let load_rows = move |_| {
        let mut params = vec![("limit", nonempty_or(&limit(), "100"))];
        push_param(&mut params, "resource_kind", kind());
        push_param(&mut params, "q", query());
        push_param(&mut params, "divergent", bool_filter(divergent()));
        push_param(&mut params, "stale", bool_filter(stale()));
        let base_url = load_base_url.clone();
        let token = load_token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Loading resources".to_string());
        spawn(async move {
            match get_admin::<ResourceList>(base_url, token, "resources", params).await {
                Ok(payload) => {
                    let count = payload.items.len();
                    let selected = selected_key();
                    let selected_item = payload
                        .items
                        .iter()
                        .find(|item| resource_key(item) == selected)
                        .cloned();
                    rows.set(payload.items);
                    if let Some(item) = selected_item {
                        editor.set(ResourceEditorForm::from_item(&item));
                    } else if !selected.is_empty() {
                        selected_key.set(String::new());
                    }
                    status.set(format!("{count} resources"));
                }
                Err(message) => {
                    error.set(message);
                    status.set("Resource query failed".to_string());
                }
            }
            loading.set(false);
        });
    };

    let new_draft = move |_| {
        let next_kind = if kind().is_empty() {
            editor().resource_kind
        } else {
            kind()
        };
        selected_key.set(String::new());
        editor.set(ResourceEditorForm::reset_for_kind(&next_kind));
        error.set(String::new());
        status.set("New resource draft".to_string());
    };

    let save_base_url = base_url.clone();
    let save_token = token.clone();
    let save_resource = move |_| {
        let form = editor();
        let body = match form.to_body() {
            Ok(body) => body,
            Err(message) => {
                error.set(message);
                return;
            }
        };
        let base_url = save_base_url.clone();
        let token = save_token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Saving resource".to_string());
        spawn(async move {
            match post_admin::<DirectoryAdminResourceUpsertRequestBody, ResourceMutationEnvelope>(
                base_url,
                token,
                "resources",
                &body,
            )
            .await
            {
                Ok(payload) => {
                    let item = payload.item;
                    let item_key = resource_key(&item);
                    let mut next = rows();
                    upsert_resource_row(&mut next, item.clone());
                    rows.set(next);
                    selected_key.set(item_key);
                    editor.set(ResourceEditorForm::from_item(&item));
                    status.set(format!("Saved {}", item.resource_id));
                }
                Err(message) => {
                    error.set(message);
                    status.set("Resource save failed".to_string());
                }
            }
            loading.set(false);
        });
    };

    let delete_base_url = base_url.clone();
    let delete_token = token.clone();
    let delete_resource = move |_| {
        let form = editor();
        if form.resource_id.trim().is_empty() {
            error.set("resource_id is required to delete".to_string());
            return;
        }

        let filter_kind = if kind().is_empty() {
            form.resource_kind.clone()
        } else {
            kind()
        };
        let params = vec![
            ("resource_kind", form.resource_kind.clone()),
            ("resource_id", form.resource_id.trim().to_string()),
        ];
        let base_url = delete_base_url.clone();
        let token = delete_token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Deleting resource".to_string());
        spawn(async move {
            let deleted_id = form.resource_id.trim().to_string();
            let deleted_key = resource_form_key(&form.resource_kind, &deleted_id);
            match delete_admin::<DeleteCount>(base_url, token, "resources", params).await {
                Ok(payload) => {
                    let mut next = rows();
                    next.retain(|row| resource_key(row) != deleted_key);
                    rows.set(next);
                    selected_key.set(String::new());
                    editor.set(ResourceEditorForm::reset_for_kind(&filter_kind));
                    status.set(if payload.deleted > 0 {
                        format!("Deleted {deleted_id}")
                    } else {
                        format!("{deleted_id} was not found")
                    });
                }
                Err(message) => {
                    error.set(message);
                    status.set("Resource delete failed".to_string());
                }
            }
            loading.set(false);
        });
    };

    rsx! {
        div { class: "panel",
            PanelHeader {
                title: "Directory resources",
                badges: rsx! {
                    span { class: BADGE_NEUTRAL, "{row_count} rows" }
                    if !selected_key_value.is_empty() {
                        span { class: BADGE_OK, "selected" }
                    }
                },
                actions: rsx! {
                    button {
                        class: "button",
                        disabled: loading_now,
                        onclick: new_draft,
                        PlusIcon {}
                        "New"
                    }
                    button {
                        class: "button",
                        disabled: loading_now,
                        onclick: load_rows,
                        SearchIcon {}
                        "Load"
                    }
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: save_resource,
                        SaveIcon {}
                        "Save"
                    }
                    button {
                        class: "button danger",
                        disabled: loading_now || editor_id_empty,
                        onclick: delete_resource,
                        TrashIcon {}
                        "Delete"
                    }
                },
            }
            StatusLine { status: status_text, error: error_text }
            div { class: "resource-shell",
                div { class: "stack",
                    div { class: "toolbar",
                        div { class: "field span-3",
                            label { "Kind" }
                            select {
                                value: "{kind_value}",
                                onchange: move |event| kind.set(event.value()),
                                option { value: "", "Any" }
                                for item in RESOURCE_KINDS {
                                    option { value: "{item}", "{item}" }
                                }
                            }
                        }
                        div { class: "field span-3",
                            label { "Resource id" }
                            input {
                                value: "{query_value}",
                                oninput: move |event| query.set(event.value()),
                            }
                        }
                        div { class: "field span-2",
                            label { "Divergent" }
                            select {
                                value: "{divergent_value}",
                                onchange: move |event| divergent.set(event.value()),
                                option { value: "any", "Any" }
                                option { value: "true", "Yes" }
                                option { value: "false", "No" }
                            }
                        }
                        div { class: "field span-2",
                            label { "Stale" }
                            select {
                                value: "{stale_value}",
                                onchange: move |event| stale.set(event.value()),
                                option { value: "any", "Any" }
                                option { value: "true", "Yes" }
                                option { value: "false", "No" }
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
                    div { class: "table-wrap",
                        table {
                            thead {
                                tr {
                                    th { "Kind" }
                                    th { "Resource" }
                                    th { "Principal" }
                                    th { "State" }
                                    th { "Indexed" }
                                    th { "Projection" }
                                    th { "Actions" }
                                }
                            }
                            tbody {
                                for item in rows_view {
                                    ResourceRow {
                                        key: "{resource_key(&item)}",
                                        is_selected: selected_key_value == resource_key(&item),
                                        item,
                                        on_load: move |item: ResourceItem| {
                                            selected_key.set(resource_key(&item));
                                            editor.set(ResourceEditorForm::from_item(&item));
                                            error.set(String::new());
                                            status.set(format!("Loaded {}", item.resource_id));
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
                ResourceEditor { editor }
            }
        }
    }
}

#[component]
fn ResourceRow(
    item: ResourceItem,
    is_selected: bool,
    on_load: EventHandler<ResourceItem>,
) -> Element {
    rsx! {
        tr { class: if is_selected { "row-selected" } else { "" },
            td { span { class: BADGE_NEUTRAL, "{item.resource_kind}" } }
            td { class: "mono", "{item.resource_id}" }
            td { class: "mono", "{item.principal_server_did}" }
            td {
                div { class: "metric-row",
                    span { class: BADGE_NEUTRAL, "{item.discoverability}" }
                    span { class: if item.stale { BADGE_WARN } else { BADGE_OK },
                        if item.stale { "stale" } else { "fresh" }
                    }
                    span { class: if item.divergent { BADGE_DANGER } else { BADGE_OK },
                        if item.divergent { "divergent" } else { "aligned" }
                    }
                }
            }
            td {
                div { class: "mono", "{item.indexed_at}" }
                div { class: "muted mono", "next {item.next_revalidation_after}" }
            }
            td { class: "mono", "{compact_json(&item.public_projection)}" }
            td {
                button {
                    class: "button",
                    onclick: move |_| on_load.call(item.clone()),
                    FileIcon {}
                    "Load"
                }
            }
        }
    }
}

/// 资源编辑器表单。独立子组件:逐字段打字只重渲染本组件,不会波及左侧列表/工具栏。
/// 各字段写入用 `with_mut` 原地修改单字段,避免读取整 form -> 改一字段 -> set 写回的双重克隆。
#[component]
fn ResourceEditor(mut editor: Signal<ResourceEditorForm>) -> Element {
    let form = editor.read();
    let resource_id = form.resource_id.clone();
    let id_empty = resource_id.trim().is_empty();
    let kind = form.resource_kind.clone();
    let principal = form.principal_server_did.clone();
    let discoverability = form.discoverability.clone();
    let as_of = form.as_of.clone();
    let ttl = form.effective_ttl_seconds.clone();
    let last_announce_id = form.last_announce_id.clone();
    let policy_revision = form.policy_revision.clone();
    let stale_value = if form.stale { "true" } else { "false" };
    let divergent_value = if form.divergent { "true" } else { "false" };
    let source_refs = form.source_refs.clone();
    let via_services = form.via_services.clone();
    let public_projection = form.public_projection.clone();
    let discovery_state = form.discovery_state.clone();
    drop(form);

    rsx! {
        div { class: "form-surface editor-surface",
            div { class: "editor-head",
                div { class: "panel-title",
                    h1 { "Data manager" }
                    div { class: "metric-row",
                        span { class: BADGE_NEUTRAL,
                            if id_empty { "draft" } else { "editing" }
                        }
                        if !id_empty {
                            span { class: BADGE_OK, "{resource_id}" }
                        }
                    }
                }
            }
            div { class: "form-grid",
                div { class: "field span-4",
                    label { "Kind" }
                    select {
                        value: "{kind}",
                        onchange: move |event| editor.with_mut(|f| f.resource_kind = event.value()),
                        for item in RESOURCE_KINDS {
                            option { value: "{item}", "{item}" }
                        }
                    }
                }
                div { class: "field span-8",
                    label { "Resource id" }
                    input {
                        value: "{resource_id}",
                        oninput: move |event| editor.with_mut(|f| f.resource_id = event.value()),
                    }
                }
                div { class: "field span-8",
                    label { "Principal server DID" }
                    input {
                        value: "{principal}",
                        oninput: move |event| editor.with_mut(|f| f.principal_server_did = event.value()),
                    }
                }
                div { class: "field span-4",
                    label { "Discoverability" }
                    select {
                        value: "{discoverability}",
                        onchange: move |event| editor.with_mut(|f| f.discoverability = event.value()),
                        for item in DISCOVERABILITY_LEVELS {
                            option { value: "{item}", "{item}" }
                        }
                    }
                }
                div { class: "field span-6",
                    label { "As of (RFC3339, optional)" }
                    input {
                        placeholder: "2026-05-12T00:00:00Z",
                        value: "{as_of}",
                        oninput: move |event| editor.with_mut(|f| f.as_of = event.value()),
                    }
                }
                div { class: "field span-3",
                    label { "TTL seconds" }
                    input {
                        r#type: "number",
                        min: "1",
                        value: "{ttl}",
                        oninput: move |event| editor.with_mut(|f| f.effective_ttl_seconds = event.value()),
                    }
                }
                div { class: "field span-3",
                    label { "Last announce id" }
                    input {
                        value: "{last_announce_id}",
                        oninput: move |event| editor.with_mut(|f| f.last_announce_id = event.value()),
                    }
                }
                div { class: "field span-6",
                    label { "Policy revision" }
                    input {
                        value: "{policy_revision}",
                        oninput: move |event| editor.with_mut(|f| f.policy_revision = event.value()),
                    }
                }
                div { class: "field span-3",
                    label { "Stale" }
                    select {
                        value: "{stale_value}",
                        onchange: move |event| editor.with_mut(|f| f.stale = event.value() == "true"),
                        option { value: "false", "false" }
                        option { value: "true", "true" }
                    }
                }
                div { class: "field span-3",
                    label { "Divergent" }
                    select {
                        value: "{divergent_value}",
                        onchange: move |event| editor.with_mut(|f| f.divergent = event.value() == "true"),
                        option { value: "false", "false" }
                        option { value: "true", "true" }
                    }
                }
                div { class: "field span-6",
                    label { "Source refs JSON" }
                    textarea {
                        value: "{source_refs}",
                        oninput: move |event| editor.with_mut(|f| f.source_refs = event.value()),
                    }
                }
                div { class: "field span-6",
                    label { "Via services JSON" }
                    textarea {
                        value: "{via_services}",
                        oninput: move |event| editor.with_mut(|f| f.via_services = event.value()),
                    }
                }
                div { class: "field span-12",
                    label { "Public projection JSON" }
                    textarea {
                        value: "{public_projection}",
                        oninput: move |event| editor.with_mut(|f| f.public_projection = event.value()),
                    }
                }
                div { class: "field span-12",
                    label { "Discovery state JSON (optional)" }
                    textarea {
                        value: "{discovery_state}",
                        oninput: move |event| editor.with_mut(|f| f.discovery_state = event.value()),
                    }
                }
            }
            div { class: "muted",
                "Direct edits write to the indexed directory store and generate admin audit events."
            }
        }
    }
}

#[component]
fn AllowlistPanel(base_url: String, token: String) -> Element {
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
fn TakedownPanel(base_url: String, token: String) -> Element {
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
        let body = OperatorTakedownRequestBody {
            resource_kind: resource_kind(),
            resource_id: id,
            reason: reason_text,
            operator: option_string(operator()),
            evidence: evidence_json,
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
                            for item in RESOURCE_KINDS {
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
fn AuditPanel(base_url: String, token: String) -> Element {
    let base_url: Rc<str> = Rc::from(base_url);
    let token: Rc<str> = Rc::from(token);
    let mut rows = use_signal(Vec::<AuditEvent>::new);
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);
    let mut since = use_signal(String::new);
    let mut limit = use_signal(|| "100".to_string());

    let rows_view = rows();
    let loading_now = loading();
    let status_text = status();
    let error_text = error();
    let since_value = since();
    let limit_value = limit();
    let row_count = rows_view.len();

    let load = move |_| {
        let mut params = vec![("limit", nonempty_or(&limit(), "100"))];
        push_param(&mut params, "since", since());
        let base_url = base_url.clone();
        let token = token.clone();
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
            AuditTable { rows: rows_view }
        }
    }
}

#[component]
fn ReviewPanel(base_url: String, token: String) -> Element {
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

#[component]
fn AuditTable(rows: Vec<AuditEvent>) -> Element {
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

/// 统一的面板头部外壳:`.panel-head > (.panel-title(h1 + .metric-row badges)) + .actions`。
/// `badges` / `actions` 为可选插槽,调用方传 `rsx! {{ ... }}`,不需要时省略。
#[component]
fn PanelHeader(
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
fn StatusLine(status: String, error: String) -> Element {
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
fn RefreshIcon() -> Element {
    rsx! {
        Icon {
            icon: LdRefreshCw,
            class: "button-icon",
            title: Some("Refresh".to_string()),
            style: None,
        }
    }
}

#[component]
fn SearchIcon() -> Element {
    rsx! {
        Icon {
            icon: LdSearch,
            class: "button-icon",
            title: Some("Search".to_string()),
            style: None,
        }
    }
}

#[component]
fn SaveIcon() -> Element {
    rsx! {
        Icon {
            icon: LdSave,
            class: "button-icon",
            title: Some("Save".to_string()),
            style: None,
        }
    }
}

#[component]
fn TrashIcon() -> Element {
    rsx! {
        Icon {
            icon: LdTrash2,
            class: "button-icon",
            title: Some("Delete".to_string()),
            style: None,
        }
    }
}

#[component]
fn SendIcon() -> Element {
    rsx! {
        Icon {
            icon: LdSend,
            class: "button-icon",
            title: Some("Submit".to_string()),
            style: None,
        }
    }
}

#[component]
fn ListIcon() -> Element {
    rsx! {
        Icon {
            icon: LdListChecks,
            class: "button-icon",
            title: Some("Load".to_string()),
            style: None,
        }
    }
}

#[component]
fn ShieldIcon() -> Element {
    rsx! {
        Icon {
            icon: LdShield,
            class: "button-icon",
            title: Some("Status".to_string()),
            style: None,
        }
    }
}

#[component]
fn DashboardIcon() -> Element {
    rsx! {
        Icon {
            icon: LdLayoutDashboard,
            class: "button-icon",
            title: Some("Dashboard".to_string()),
            style: None,
        }
    }
}

#[component]
fn DatabaseIcon() -> Element {
    rsx! {
        Icon {
            icon: LdDatabase,
            class: "button-icon",
            title: Some("Status".to_string()),
            style: None,
        }
    }
}

#[component]
fn FileIcon() -> Element {
    rsx! {
        Icon {
            icon: LdFileText,
            class: "button-icon",
            title: Some("File".to_string()),
            style: None,
        }
    }
}

#[component]
fn PlusIcon() -> Element {
    rsx! {
        Icon {
            icon: LdPlus,
            class: "button-icon",
            title: Some("Add".to_string()),
            style: None,
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

async fn get_admin<T: DeserializeOwned>(
    base_url: Rc<str>,
    token: Rc<str>,
    path: &'static str,
    params: Vec<(&'static str, String)>,
) -> Result<T, String> {
    let url = admin_url(&base_url, path);
    let request = with_auth(
        Request::get(&url).query(params.iter().map(|(key, value)| (*key, value.as_str()))),
        &token,
    );
    decode_response(request.send().await.map_err(net_error)?).await
}

async fn post_admin<B: Serialize + ?Sized, T: DeserializeOwned>(
    base_url: Rc<str>,
    token: Rc<str>,
    path: &'static str,
    body: &B,
) -> Result<T, String> {
    let url = admin_url(&base_url, path);
    let request = with_auth(Request::post(&url), &token)
        .json(body)
        .map_err(net_error)?;
    decode_response(request.send().await.map_err(net_error)?).await
}

async fn delete_admin<T: DeserializeOwned>(
    base_url: Rc<str>,
    token: Rc<str>,
    path: &'static str,
    params: Vec<(&'static str, String)>,
) -> Result<T, String> {
    let url = admin_url(&base_url, path);
    let request = with_auth(
        Request::delete(&url).query(params.iter().map(|(key, value)| (*key, value.as_str()))),
        &token,
    );
    decode_response(request.send().await.map_err(net_error)?).await
}

async fn post_directory<B: Serialize + ?Sized, T: DeserializeOwned>(
    base_url: Rc<str>,
    path: &'static str,
    body: &B,
) -> Result<T, String> {
    let url = directory_url(&base_url, path);
    let request = Request::post(&url).json(body).map_err(net_error)?;
    decode_response(request.send().await.map_err(net_error)?).await
}

fn with_auth(builder: RequestBuilder, token: &str) -> RequestBuilder {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        builder
    } else {
        builder.header("Authorization", &format!("Bearer {trimmed}"))
    }
}

async fn decode_response<T: DeserializeOwned>(response: Response) -> Result<T, String> {
    let status = response.status();
    if response.ok() {
        response
            .json()
            .await
            .map_err(|error| format!("decode response: {error}"))
    } else {
        let body = response.text().await.unwrap_or_default();
        Err(format!("HTTP {status}: {}", truncate(&body, 320)))
    }
}

fn admin_url(base_url: &str, path: &str) -> String {
    format!(
        "{}/_teabay/admin/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn directory_url(base_url: &str, path: &str) -> String {
    format!(
        "{}/_cokret/find/directory/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn push_param(params: &mut Vec<(&'static str, String)>, key: &'static str, value: String) {
    if !value.trim().is_empty() {
        params.push((key, value.trim().to_string()));
    }
}

fn bool_filter(value: String) -> String {
    match value.as_str() {
        "true" | "false" => value,
        _ => String::new(),
    }
}

fn insert_optional_string(body: &mut serde_json::Map<String, JsonValue>, key: &str, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        body.insert(key.to_string(), JsonValue::String(trimmed.to_string()));
    }
}

fn optional_u32(value: &str, field: &str) -> Result<Option<u32>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        trimmed
            .parse::<u32>()
            .map(Some)
            .map_err(|error| format!("{field}: {error}"))
    }
}

fn nonempty_or(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn option_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_optional_i64(raw: &str, field: &str) -> Result<Option<i64>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        trimmed
            .parse::<i64>()
            .map(Some)
            .map_err(|error| format!("{field}: {error}"))
    }
}

fn parse_json_object(raw: &str, field: &str) -> Result<JsonValue, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} is required"));
    }

    let value: JsonValue =
        serde_json::from_str(trimmed).map_err(|error| format!("{field}: {error}"))?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(format!("{field} must be a JSON object"))
    }
}

fn parse_optional_json_object(raw: &str, field: &str) -> Result<Option<JsonValue>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        parse_json_object(trimmed, field).map(Some)
    }
}

fn parse_string_array(raw: &str, field: &str) -> Result<Vec<String>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(Vec::new())
    } else {
        serde_json::from_str(trimmed).map_err(|error| format!("{field}: {error}"))
    }
}

fn pretty_json(value: &JsonValue) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
}

fn pretty_string_array(values: &[String]) -> String {
    serde_json::to_string_pretty(values).unwrap_or_else(|_| "[]".to_string())
}

fn resource_form_key(kind: &str, resource_id: &str) -> String {
    format!("{}::{resource_id}", kind.trim())
}

fn resource_key(item: &ResourceItem) -> String {
    resource_form_key(&item.resource_kind, &item.resource_id)
}

fn upsert_resource_row(rows: &mut Vec<ResourceItem>, item: ResourceItem) {
    let key = resource_key(&item);
    if let Some(existing) = rows.iter_mut().find(|row| resource_key(row) == key) {
        *existing = item;
    } else {
        rows.insert(0, item);
    }
}

fn parse_evidence(raw: &str) -> Result<JsonValue, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_str(trimmed).map_err(|error| format!("evidence JSON: {error}"))
    }
}

fn compact_json(value: &JsonValue) -> String {
    truncate(
        &serde_json::to_string(value).unwrap_or_else(|_| "null".to_string()),
        220,
    )
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        let mut out: String = value.chars().take(max.saturating_sub(3)).collect();
        out.push_str("...");
        out
    }
}

fn audit_badge_class(kind: &str) -> &'static str {
    match kind {
        "ingest_rejected" | "revalidation_failed" | "operator_takedown" => BADGE_DANGER,
        "allowlist_added" | "allowlist_removed" | "withdrawal" | "admin_resource_deleted" => {
            BADGE_WARN
        }
        "admin_resource_upserted" => BADGE_OK,
        _ => BADGE_NEUTRAL,
    }
}

fn is_review_event(event: &AuditEvent) -> bool {
    matches!(
        event.kind.as_str(),
        "ingest_rejected" | "revalidation_failed" | "operator_takedown"
    )
}

fn net_error(error: gloo_net::Error) -> String {
    error.to_string()
}
