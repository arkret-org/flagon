use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::ld_icons::{
    LdDatabase, LdFileText, LdListChecks, LdPlus, LdRefreshCw, LdSave, LdSearch, LdSend, LdShield,
    LdTrash2,
};
use gloo_net::http::{Request, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

const RESOURCE_KINDS: [&str; 5] = ["space", "organization", "actor", "applet", "handle"];

fn main() {
    dioxus::launch(App);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Resources,
    Allowlist,
    Takedown,
    Audit,
    Review,
}

impl Tab {
    const ALL: [Self; 5] = [
        Self::Resources,
        Self::Allowlist,
        Self::Takedown,
        Self::Audit,
        Self::Review,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Resources => "Resources",
            Self::Allowlist => "Allowlist",
            Self::Takedown => "Takedown",
            Self::Audit => "Audit",
            Self::Review => "Review",
        }
    }
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
struct TakedownResponse {
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
struct AllowlistUpsertBody {
    resource_did: String,
    added_by: Option<String>,
    note: Option<String>,
}

#[derive(Serialize)]
struct TakedownBody {
    resource_kind: String,
    resource_id: String,
    reason: String,
    operator: Option<String>,
    evidence: JsonValue,
}

#[allow(non_snake_case)]
fn App() -> Element {
    let mut active_tab = use_signal(|| Tab::Resources);
    let mut base_url = use_signal(|| "http://localhost:7781".to_string());
    let mut token = use_signal(String::new);

    let selected = active_tab();
    let api_base = base_url();
    let api_token = token();

    rsx! {
        document::Stylesheet { href: asset!("/assets/main.css") }
        main { class: "app-shell",
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
            nav { class: "tabs", aria_label: "Admin sections",
                for tab in Tab::ALL {
                    button {
                        class: if selected == tab { "tab active" } else { "tab" },
                        onclick: move |_| active_tab.set(tab),
                        "{tab.label()}"
                    }
                }
            }
            section { class: "workspace",
                match selected {
                    Tab::Resources => rsx! { ResourcesPanel { base_url: api_base.clone(), token: api_token.clone() } },
                    Tab::Allowlist => rsx! { AllowlistPanel { base_url: api_base.clone(), token: api_token.clone() } },
                    Tab::Takedown => rsx! { TakedownPanel { base_url: api_base.clone(), token: api_token.clone() } },
                    Tab::Audit => rsx! { AuditPanel { base_url: api_base.clone(), token: api_token.clone() } },
                    Tab::Review => rsx! { ReviewPanel { base_url: api_base.clone(), token: api_token.clone() } },
                }
            }
        }
    }
}

#[component]
fn ResourcesPanel(base_url: String, token: String) -> Element {
    let mut rows = use_signal(Vec::<ResourceItem>::new);
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);
    let mut kind = use_signal(String::new);
    let mut query = use_signal(String::new);
    let mut divergent = use_signal(|| "any".to_string());
    let mut stale = use_signal(|| "any".to_string());
    let mut limit = use_signal(|| "100".to_string());

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

    let load_rows = move |_| {
        let mut params = vec![("limit", nonempty_or(&limit(), "100"))];
        push_param(&mut params, "resource_kind", kind());
        push_param(&mut params, "q", query());
        push_param(&mut params, "divergent", bool_filter(divergent()));
        push_param(&mut params, "stale", bool_filter(stale()));
        let base_url = base_url.clone();
        let token = token.clone();
        loading.set(true);
        error.set(String::new());
        status.set("Loading resources".to_string());
        spawn(async move {
            match get_admin::<ResourceList>(base_url, token, "resources", params).await {
                Ok(payload) => {
                    let count = payload.items.len();
                    rows.set(payload.items);
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

    rsx! {
        div { class: "panel",
            div { class: "panel-head",
                div { class: "panel-title",
                    h1 { "Directory resources" }
                    div { class: "metric-row",
                        span { class: "badge neutral", "{row_count} rows" }
                    }
                }
                div { class: "actions",
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: load_rows,
                        SearchIcon {}
                        "Search"
                    }
                }
            }
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
            StatusLine { status: status_text, error: error_text }
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
                        }
                    }
                    tbody {
                        for item in rows_view {
                            tr {
                                td { span { class: "badge neutral", "{item.resource_kind}" } }
                                td { class: "mono", "{item.resource_id}" }
                                td { class: "mono", "{item.principal_server_did}" }
                                td {
                                    div { class: "metric-row",
                                        span { class: "badge neutral", "{item.discoverability}" }
                                        span { class: if item.stale { "badge warn" } else { "badge ok" },
                                            if item.stale { "stale" } else { "fresh" }
                                        }
                                        span { class: if item.divergent { "badge danger" } else { "badge ok" },
                                            if item.divergent { "divergent" } else { "aligned" }
                                        }
                                    }
                                }
                                td {
                                    div { class: "mono", "{item.indexed_at}" }
                                    div { class: "muted mono", "next {item.next_revalidation_after}" }
                                }
                                td { class: "mono", "{compact_json(&item.public_projection)}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn AllowlistPanel(base_url: String, token: String) -> Element {
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
        let body = AllowlistUpsertBody {
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
            match post_admin::<AllowlistUpsertBody, JsonValue>(base_url, token, "allowlist", &body)
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
            div { class: "panel-head",
                div { class: "panel-title",
                    h1 { "Accept allowlist" }
                    div { class: "metric-row",
                        span { class: "badge neutral", "{row_count} rows" }
                    }
                }
                div { class: "actions",
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
                }
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
    base_url: String,
    token: String,
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
    let mut resource_kind = use_signal(|| "space".to_string());
    let mut resource_id = use_signal(String::new);
    let mut reason = use_signal(String::new);
    let mut operator = use_signal(|| "teabay-admin".to_string());
    let mut evidence = use_signal(|| "{\n  \"source\": \"operator_console\"\n}".to_string());
    let mut loading = use_signal(|| false);
    let mut status = use_signal(|| "Idle".to_string());
    let mut error = use_signal(String::new);
    let mut response = use_signal(Option::<TakedownResponse>::default);

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
        let body = TakedownBody {
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
            match post_admin::<TakedownBody, TakedownResponse>(base_url, token, "takedown", &body)
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
            div { class: "panel-head",
                div { class: "panel-title",
                    h1 { "Operator takedown" }
                }
                div { class: "actions",
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: submit,
                        SendIcon {}
                        "Submit"
                    }
                }
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
            div { class: "panel-head",
                div { class: "panel-title",
                    h1 { "Audit log" }
                    div { class: "metric-row",
                        span { class: "badge neutral", "{row_count} rows" }
                    }
                }
                div { class: "actions",
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: load,
                        RefreshIcon {}
                        "Load"
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
            div { class: "panel-head",
                div { class: "panel-title",
                    h1 { "Operator review" }
                    div { class: "metric-row",
                        span { class: "badge neutral", "{row_count} items" }
                        span { class: "badge warn", "audit-backed" }
                    }
                }
                div { class: "actions",
                    button {
                        class: "button primary",
                        disabled: loading_now,
                        onclick: load,
                        ListIcon {}
                        "Load"
                    }
                }
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
                        AuditRow { item }
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    base_url: String,
    token: String,
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
    base_url: String,
    token: String,
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
    base_url: String,
    token: String,
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
    base_url: String,
    token: String,
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
        "{}/api/admin/v1/{}",
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
        "ingest_rejected" | "revalidation_failed" | "operator_takedown" => "badge danger",
        "allowlist_added" | "allowlist_removed" | "withdrawal" => "badge warn",
        _ => "badge neutral",
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
