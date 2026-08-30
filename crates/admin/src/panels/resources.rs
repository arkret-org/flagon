use std::rc::Rc;

use dioxus::prelude::*;

use crate::api::{
    bool_filter, compact_json, delete_admin, get_admin, nonempty_or, post_admin, push_param,
    resource_form_key, resource_key, upsert_resource_row,
};
use crate::icons::{FileIcon, PlusIcon, SaveIcon, SearchIcon, TrashIcon};
use crate::model::{
    BADGE_DANGER, BADGE_NEUTRAL, BADGE_OK, BADGE_WARN, DeleteCount,
    DirectoryAdminResourceUpsertRequestBody, DirectoryResourceKind, Discoverability,
    ResourceEditorForm, ResourceItem, ResourceList, ResourceMutationEnvelope,
};
use crate::shell::{PanelHeader, StatusLine};

#[component]
pub fn ResourcesPanel(base_url: String, token: String) -> Element {
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
    // Subscribe only to the derived "resource_id is empty" boolean; typing in
    // the editor field-by-field does not re-render this panel.
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
                                for item in DirectoryResourceKind::ALL.map(DirectoryResourceKind::as_str) {
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
            td { class: "mono", "{item.station_id}" }
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
            td { class: "mono", "{compact_json(item.public_projection.as_value())}" }
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

/// Resource editor form. Standalone child component: typing field-by-field
/// only re-renders this component, never the left-hand list/toolbar. Each
/// field writes via `with_mut` to mutate a single field in place, avoiding the
/// read-whole-form -> change-one-field -> set-write-back double clone.
#[component]
fn ResourceEditor(mut editor: Signal<ResourceEditorForm>) -> Element {
    let form = editor.read();
    let resource_id = form.resource_id.clone();
    let id_empty = resource_id.trim().is_empty();
    let kind = form.resource_kind.clone();
    let principal = form.station_id.clone();
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
                        for item in DirectoryResourceKind::ALL.map(DirectoryResourceKind::as_str) {
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
                    label { "Station service core id" }
                    input {
                        value: "{principal}",
                        oninput: move |event| editor.with_mut(|f| f.station_id = event.value()),
                    }
                }
                div { class: "field span-4",
                    label { "Discoverability" }
                    select {
                        value: "{discoverability}",
                        onchange: move |event| editor.with_mut(|f| f.discoverability = event.value()),
                        for item in Discoverability::ALL.map(Discoverability::as_str) {
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
