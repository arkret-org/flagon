use std::cell::RefCell;
use std::rc::Rc;

use glory::prelude::*;
use glory::ui::Mounted;

use crate::api::{compact_json, get_admin};
use crate::icons::icon;
use crate::model::{
    AuditChainVerificationVerdict, AuditEnvelope, AuditEvent, BADGE_NEUTRAL, BADGE_WARN,
};

type View = Box<dyn Widget>;

#[derive(Clone)]
struct VerificationSnapshot {
    service: String,
    completed_at: String,
    verdict: AuditChainVerificationVerdict,
}

#[derive(Clone, Copy)]
struct AuditState {
    base_url: Cage<String>,
    token: Cage<String>,
    rows: Cage<Vec<AuditEvent>>,
    loading: Cage<bool>,
    status: Cage<String>,
    error: Cage<String>,
    since: Cage<String>,
    limit: Cage<String>,
    verification: Cage<Option<VerificationSnapshot>>,
    generation: Cage<u64>,
    connection_open: Cage<bool>,
    query_snapshot: Cage<Option<String>>,
}

pub fn app(scope: &Scope) -> impl Widget + use<> {
    let state = AuditState {
        base_url: scope.cage("http://localhost:7781".to_owned()),
        token: scope.cage(String::new()),
        rows: scope.cage(Vec::new()),
        loading: scope.cage(false),
        status: scope.cage("Idle".to_owned()),
        error: scope.cage(String::new()),
        since: scope.cage(String::new()),
        limit: scope.cage("100".to_owned()),
        verification: scope.cage(None),
        generation: scope.cage(0),
        connection_open: scope.cage(true),
        query_snapshot: scope.cage(None),
    };
    scope.effect(move || {
        let _ = (state.base_url.get(), state.token.get());
        state.generation.revise(|n| *n = n.wrapping_add(1));
        state.rows.revise(Vec::clear);
        state.query_snapshot.revise(|value| *value = None);
        state.verification.revise(|v| *v = None);
        state.loading.revise(|v| *v = false);
        state.error.revise(String::clear);
        state.status.revise(|v| {
            *v = "Connection changed. Load the audit log or verify the full chain.".into()
        });
    });
    view().role(Role::Main).class("app-shell").fill((
        view().role(Role::Banner).class("topbar").fill((
            view().class("brand").fill((
                view()
                    .class("brand-title")
                    .fill(text().content("Flagon Audit")),
                view()
                    .class("brand-subtitle")
                    .fill(text().content("audit-only operator console")),
            )),
            view().class("connection-summary").fill((
                text().content(scope.bond(move || format!("Service: {}", state.base_url.get()))),
                text().class("muted").content(scope.bond(move || {
                    if state.token.get().is_empty() {
                        "No token entered · credentials stay in memory".to_owned()
                    } else {
                        "Token entered · credentials stay in memory".to_owned()
                    }
                })),
            )),
        )),
        sapid::collapsible("audit-connection")
            .unstyled()
            .class("connection-settings")
            .label("Connection settings")
            .open(state.connection_open)
            .on_open_change(move |value| state.connection_open.revise(|current| *current = value))
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .content(move || {
                view().class("connection-fields").fill((
                    field(
                        "api-base",
                        "API base",
                        "field",
                        state.base_url,
                        Purpose::Text,
                        "",
                    ),
                    field(
                        "token",
                        "Bearer token",
                        "field",
                        state.token,
                        Purpose::Password,
                        "",
                    ),
                ))
            }),
        view().class("workspace").fill(audit_panel(scope, state)),
    ))
}

fn field(
    key: &str,
    label: &str,
    class: &str,
    value: Cage<String>,
    purpose: Purpose,
    placeholder: &str,
) -> impl Widget + use<> {
    let placeholder = placeholder.to_owned();
    sapid::field(key)
        .unstyled()
        .class(class.to_owned())
        .label(label.to_owned())
        .control(move |context| -> View {
            if purpose == Purpose::Password {
                Box::new(
                    sapid::password_input()
                        .field(context)
                        .placeholder(placeholder.clone())
                        .value(value)
                        .on_value_change(move |next| value.revise(|current| *current = next)),
                )
            } else {
                Box::new(
                    sapid::text_field()
                        .field(context)
                        .placeholder(placeholder.clone())
                        .value(value)
                        .purpose(purpose)
                        .on_value_change(move |next| value.revise(|current| *current = next)),
                )
            }
        })
}

fn audit_panel(scope: &Scope, state: AuditState) -> impl Widget + use<> {
    let enabled = scope.bond(move || !state.loading.get());
    let count = scope.bond(move || {
        if state.query_snapshot.get().is_none() {
            "Not loaded".to_owned()
        } else {
            format!("{} rows", state.rows.with(Vec::len))
        }
    });
    let query_error = scope.bond(move || {
        audit_query(&state.since.get(), &state.limit.get())
            .err()
            .unwrap_or_default()
    });
    let can_load = scope.bond(move || {
        !state.loading.get() && audit_query(&state.since.get(), &state.limit.get()).is_ok()
    });
    let status_class = scope.bond(move || {
        if state.error.with(String::is_empty) {
            "status-line"
        } else {
            "status-line error"
        }
        .to_owned()
    });
    let status_icon = scope.bond(move || {
        if state.error.with(String::is_empty) {
            "button-icon icon-database"
        } else {
            "button-icon icon-shield"
        }
        .to_owned()
    });
    let message = scope.bond(move || {
        if state.error.with(String::is_empty) {
            state.status.get()
        } else {
            state.error.get()
        }
    });
    let load_scope = scope.downgrade();
    let verify_scope = scope.downgrade();
    view().class("panel").fill((
        view().class("panel-head").fill((
            view().class("panel-title").fill((
                text().kind(TextKind::Heading(1)).content("Audit log"),
                view().class("metric-row").fill(
                    sapid::badge()
                        .unstyled()
                        .class(BADGE_NEUTRAL)
                        .content(count),
                ),
            )),
            view().class("actions").fill((
                sapid::button()
                    .unstyled()
                    .class("button primary")
                    .label("Load")
                    .left_section(icon("refresh"))
                    .enabled(can_load)
                    .on_press(move || {
                        if let Some(scope) = load_scope.upgrade() {
                            load(&scope, state)
                        }
                    }),
                sapid::button()
                    .unstyled()
                    .class("button")
                    .label("Verify")
                    .left_section(icon("list"))
                    .enabled(enabled)
                    .on_press(move || {
                        if let Some(scope) = verify_scope.upgrade() {
                            verify(&scope, state)
                        }
                    }),
            )),
        )),
        view().class("toolbar").fill((
            field(
                "since",
                "Since",
                "field span-8",
                state.since,
                Purpose::Text,
                "2026-05-10T00:00:00Z",
            ),
            field(
                "limit",
                "Limit",
                "field span-2",
                state.limit,
                Purpose::Number,
                "",
            ),
        )),
        text().class("muted query-help").content("Since is an RFC 3339 timestamp: Z means UTC; explicit offsets are accepted. Leave it empty for all available times. Limit: 1–500 rows."),
        view().role(Role::Alert).class("query-error").fill(text().content(query_error)),
        view().class("limit-presets").fill([50,100,250,500].into_iter().map(move |limit| sapid::button().unstyled().class("button").label(limit.to_string()).enabled(enabled).on_press(move || state.limit.revise(|value| *value = limit.to_string()))).collect::<Vec<_>>()),
        view().role(Role::Status).class(status_class).fill((
            text().kind(TextKind::Inline).class(status_icon).content(""),
            text().content(message),
        )),
        reactive(state.verification, move |outcome| match outcome {
            Some(outcome) => verification_box(outcome),
            None => Box::new(group()),
        }),
        reactive(state.rows, audit_table),
        reactive(state.query_snapshot, move |snapshot| Box::new(text().class("query-context muted").content(snapshot.unwrap_or_else(|| "No audit query has completed. Choose a connection, then load the log.".to_owned())))),
    ))
}

fn load(scope: &Scope, state: AuditState) {
    if state.loading.get_untracked() {
        return;
    }
    let parameters = match audit_query(&state.since.get_untracked(), &state.limit.get_untracked()) {
        Ok(value) => value,
        Err(message) => {
            state.error.revise(|value| *value = message);
            return;
        }
    };
    let query = format!(
        "Results from {} · since {} · limit {}",
        state.base_url.get_untracked(),
        if state.since.get_untracked().trim().is_empty() {
            "all available times".to_owned()
        } else {
            state.since.get_untracked()
        },
        state.limit.get_untracked()
    );
    let base = Rc::from(state.base_url.get_untracked());
    let token = Rc::from(state.token.get_untracked());
    let serial = begin(state, "Loading audit feed");
    if let Err(error) = scope.owner().spawn(async move {
        let result = get_admin::<AuditEnvelope>(base, token, "audit", parameters).await;
        if state.generation.get_untracked() != serial {
            return;
        }
        match result {
            Ok(payload) => {
                state.status.revise(|value| {
                    *value = if payload.events.is_empty() {
                        "No audit events match this query.".to_owned()
                    } else {
                        format!("{} audit events", payload.events.len())
                    }
                });
                state.rows.revise(|value| *value = payload.events);
                state.query_snapshot.revise(|value| *value = Some(query));
                state.connection_open.revise(|value| *value = false);
            }
            Err(error) => {
                state.error.revise(|value| *value = error);
                state
                    .status
                    .revise(|value| *value = "Audit query failed".to_owned());
            }
        }
        state.loading.revise(|value| *value = false);
    }) {
        state.error.revise(|value| *value = error.to_string());
        state.loading.revise(|value| *value = false);
    }
}

fn verify(scope: &Scope, state: AuditState) {
    if state.loading.get_untracked() {
        return;
    }
    let base = Rc::from(state.base_url.get_untracked());
    let token = Rc::from(state.token.get_untracked());
    let service = state
        .base_url
        .get_untracked()
        .trim_end_matches('/')
        .to_owned();
    let serial = begin(state, "Verifying full audit chain");
    if let Err(error) = scope.owner().spawn(async move {
        let result =
            get_admin::<AuditChainVerificationVerdict>(base, token, "audit/verify", vec![]).await;
        if state.generation.get_untracked() != serial {
            return;
        }
        match result {
            Ok(payload) => {
                state.connection_open.revise(|value| *value = false);
                state.status.revise(|value| {
                    *value = if payload.ok {
                        format!("Audit chain ok: {} rows", payload.chain_rows)
                    } else {
                        "Audit chain verification failed".to_owned()
                    }
                });
                state.verification.revise(|value| {
                    *value = Some(VerificationSnapshot {
                        service,
                        completed_at: chrono::Utc::now()
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        verdict: payload,
                    })
                });
            }
            Err(error) => {
                state.error.revise(|value| *value = error);
                state
                    .status
                    .revise(|value| *value = "Audit chain verify failed".to_owned());
            }
        }
        state.loading.revise(|value| *value = false);
    }) {
        state.error.revise(|value| *value = error.to_string());
        state.loading.revise(|value| *value = false);
    }
}

fn begin(state: AuditState, message: &str) -> u64 {
    state.generation.revise(|n| *n = n.wrapping_add(1));
    state.verification.revise(|v| *v = None);
    state.loading.revise(|value| *value = true);
    state.error.revise(String::clear);
    state.status.revise(|value| *value = message.to_owned());
    state.generation.get_untracked()
}

fn audit_query(
    since: &str,
    limit: &str,
) -> std::result::Result<Vec<(&'static str, String)>, String> {
    let limit = limit
        .trim()
        .parse::<u16>()
        .map_err(|_| "Enter a whole-number limit from 1 to 500.".to_owned())?;
    if !(1..=500).contains(&limit) {
        return Err("Limit must be between 1 and 500.".to_owned());
    }
    let mut parameters = vec![("limit", limit.to_string())];
    if !since.trim().is_empty() {
        chrono::DateTime::parse_from_rfc3339(since.trim()).map_err(|_| {
            "Since must include a valid date, time and UTC Z or timezone offset.".to_owned()
        })?;
        parameters.push(("since", since.trim().to_owned()));
    }
    Ok(parameters)
}

fn reactive<T: Clone + 'static>(source: Cage<T>, render: impl Fn(T) -> View + 'static) -> View {
    let render = Rc::new(render);
    Box::new(view().class("reactive-region").fill(widget(move |scope| {
        let mounted = Rc::new(RefCell::new(None::<Mounted>));
        scope.retain(mounted.clone())?;
        let weak = scope.downgrade();
        let render = render.clone();
        scope.effect(move || {
            let value = source.get();
            let Some(scope) = weak.upgrade() else {
                return;
            };
            mounted.borrow_mut().take();
            let render = render.clone();
            match scope.mount_with(|| widget(move |child| render(value.clone()).build(child))) {
                Ok(next) => *mounted.borrow_mut() = Some(next),
                Err(error) => {
                    #[cfg(target_arch = "wasm32")]
                    web_sys::console::error_1(
                        &format!("flagon region render failed: {error}").into(),
                    );
                    #[cfg(not(target_arch = "wasm32"))]
                    eprintln!("flagon region render failed: {error}");
                }
            }
        });
        Ok(())
    })))
}

fn audit_table(rows: Vec<AuditEvent>) -> View {
    let head = sapid::table_head().row(
        sapid::table_row("head").cells(
            ["Time", "Kind", "Resource", "Actor", "Detail"]
                .into_iter()
                .enumerate()
                .map(|(i, title)| sapid::table_header_cell(format!("header-{i}")).text(title)),
        ),
    );
    let body = sapid::table_body().rows(rows.into_iter().map(|item| {
        let full = serde_json::to_string_pretty(&item).expect("audit response serializes as JSON");
        let resource = item.resource_id.unwrap_or_default();
        let resource_kind = item.resource_kind.unwrap_or_default();
        let actor = item
            .actor_id
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        let detail = compact_json(&item.detail);
        sapid::table_row(item.audit_id.to_string()).cells([
            sapid::table_cell("time")
                .class("mono")
                .text(item.occurred_at),
            sapid::table_cell("kind").content(move || {
                sapid::badge()
                    .unstyled()
                    .class(BADGE_NEUTRAL)
                    .content(item.kind.clone())
            }),
            sapid::table_cell("resource").content(move || {
                view().fill((
                    view().class("mono").fill(text().content(resource.clone())),
                    view()
                        .class("muted")
                        .fill(text().content(resource_kind.clone())),
                ))
            }),
            sapid::table_cell("actor").text(actor),
            sapid::table_cell("detail")
                .content(move || audit_detail(item.audit_id, detail.clone(), full.clone())),
        ])
    }));
    Box::new(
        view().class("table-wrap").fill(
            sapid::table("flagon-audit")
                .unstyled()
                .head(head)
                .body(body)
                .striped(false),
        ),
    )
}

fn audit_detail(id: i64, summary: String, json: String) -> impl Widget {
    widget(move |scope| {
        let open = scope.cage(false);
        let json = json.clone();
        view()
            .class("audit-detail-cell")
            .fill((
                text().class("mono audit-excerpt").content(summary.clone()),
                sapid::dialog(format!("audit-record-{id}"))
                    .unstyled()
                    .class("audit-record-dialog")
                    .label("View full record")
                    .title(format!("Audit record #{id}"))
                    .close_label("Close")
                    .open(open)
                    .on_open_change(move |value| open.revise(|current| *current = value))
                    .content(move || audit_record_body(json.clone())),
            ))
            .show_in(scope)
    })
}

fn audit_record_body(json: String) -> View {
    let copy: View = if json.len() <= glory::render::MAX_CLIPBOARD_BYTES {
        Box::new(
            sapid::copy_button()
                .unstyled()
                .class("button")
                .label("Copy full JSON")
                .source(json.clone())
                .failed_label("Copy failed — select JSON below"),
        )
    } else {
        Box::new(text().content("Large record: select the JSON field and use Ctrl+A, Ctrl+C (or your platform's copy command)."))
    };
    Box::new(view().class("audit-record-content").fill((
        text().content("Complete authorized response record. The table summary is shortened; this JSON is not."),
        copy,
        sapid::text_field().unstyled().class("audit-json mono").name("Full audit record JSON").multiline(true).readonly(true).value(json),
    )))
}

#[cfg(test)]
mod query_tests {
    use super::audit_query;
    #[test]
    fn query_accepts_endpoint_bounds_and_preserves_explicit_timezone() {
        assert!(audit_query("", "1").is_ok());
        assert!(
            audit_query("2026-11-14T10:00:00+08:00", "500")
                .unwrap()
                .contains(&("since", "2026-11-14T10:00:00+08:00".to_owned()))
        );
    }
    #[test]
    fn query_rejects_unbounded_limits_and_ambiguous_time() {
        for value in ["", "0", "501", "-1", "2.5", "huge"] {
            assert!(audit_query("", value).is_err());
        }
        assert!(audit_query("2026-11-14T10:00:00", "100").is_err());
    }
}

fn verification_box(snapshot: VerificationSnapshot) -> View {
    let outcome = snapshot.verdict;
    let mut lines: Vec<View> = vec![
        Box::new(text().kind(TextKind::Heading(2)).content("Full audit chain verification")),
        Box::new(text().content(format!("Service: {}", snapshot.service))),
        Box::new(text().content(format!("Completed at (this device, UTC): {}", snapshot.completed_at))),
        Box::new(text().content("This result covers the service's full audit chain, independently of the list filters. It is a point-in-time result, not continuous monitoring.")),
        Box::new(
        view().fill(
            sapid::badge()
                .unstyled()
                .class(if outcome.ok {
                    BADGE_NEUTRAL
                } else {
                    BADGE_WARN
                })
                .content(if outcome.ok { "ok" } else { "failed" }),
        ),
    )];
    for line in [
        format!("checked_rows: {}", outcome.checked_rows),
        format!("chain_rows: {}", outcome.chain_rows),
        format!(
            "first_audit_id: {}",
            outcome
                .first_audit_id
                .map(|value| value.to_string())
                .unwrap_or_default()
        ),
        format!(
            "last_audit_id: {}",
            outcome
                .last_audit_id
                .map(|value| value.to_string())
                .unwrap_or_default()
        ),
        format!("head_digest: {}", outcome.head_digest.unwrap_or_default()),
    ] {
        lines.push(Box::new(view().class("mono").fill(text().content(line))));
    }
    if let Some(failure) = outcome.failure {
        lines.push(Box::new(view().class("mono").fill(text().content(
            format!(
                "{} at audit_id {} expected={} actual={}",
                failure.reason,
                failure.audit_id,
                failure.expected.as_deref().unwrap_or(""),
                failure.actual.as_deref().unwrap_or("")
            ),
        ))));
    }
    Box::new(view().class("result-box verification-result").fill(lines))
}
