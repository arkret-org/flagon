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
    verification: Cage<Option<AuditChainVerificationVerdict>>,
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
    };
    view().role(Role::Main).class("app-shell").fill((
        view().role(Role::Banner).class("topbar").fill((
            view().class("brand").fill((
                view()
                    .class("brand-title")
                    .fill(text().content("flagon admin")),
                view()
                    .class("brand-subtitle")
                    .fill(text().content("audit-only operator console")),
            )),
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
        )),
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
        .control(move |context| {
            sapid::text_field()
                .field(context)
                .value(value)
                .purpose(purpose)
                .placeholder(placeholder.clone())
                .on_value_change(move |next| value.revise(|current| *current = next))
        })
}

fn audit_panel(scope: &Scope, state: AuditState) -> impl Widget + use<> {
    let enabled = scope.bond(move || !state.loading.get());
    let count = scope.bond(move || format!("{} rows", state.rows.with(Vec::len)));
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
                    .enabled(enabled)
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
        view().role(Role::Status).class(status_class).fill((
            text().kind(TextKind::Inline).class(status_icon).content(""),
            text().content(message),
        )),
        reactive(state.verification, move |outcome| match outcome {
            Some(outcome) => verification_box(outcome),
            None => Box::new(group()),
        }),
        reactive(state.rows, audit_table),
    ))
}

fn load(scope: &Scope, state: AuditState) {
    if state.loading.get_untracked() {
        return;
    }
    let mut parameters = vec![(
        "limit",
        if state.limit.with(|value| value.trim().is_empty()) {
            "100".to_owned()
        } else {
            state.limit.get_untracked()
        },
    )];
    if !state.since.with(|value| value.trim().is_empty()) {
        parameters.push(("since", state.since.get_untracked()));
    }
    let base = Rc::from(state.base_url.get_untracked());
    let token = Rc::from(state.token.get_untracked());
    begin(state, "Loading audit feed");
    if let Err(error) = scope.owner().spawn(async move {
        match get_admin::<AuditEnvelope>(base, token, "audit", parameters).await {
            Ok(payload) => {
                state
                    .status
                    .revise(|value| *value = format!("{} audit events", payload.events.len()));
                state.rows.revise(|value| *value = payload.events);
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
    begin(state, "Verifying audit chain");
    if let Err(error) = scope.owner().spawn(async move {
        match get_admin::<AuditChainVerificationVerdict>(base, token, "audit/verify", vec![]).await
        {
            Ok(payload) => {
                state.status.revise(|value| {
                    *value = if payload.ok {
                        format!("Audit chain ok: {} rows", payload.chain_rows)
                    } else {
                        "Audit chain verification failed".to_owned()
                    }
                });
                state.verification.revise(|value| *value = Some(payload));
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

fn begin(state: AuditState, message: &str) {
    state.loading.revise(|value| *value = true);
    state.error.revise(String::clear);
    state.status.revise(|value| *value = message.to_owned());
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
            sapid::table_cell("detail").class("mono").text(detail),
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

fn verification_box(outcome: AuditChainVerificationVerdict) -> View {
    let mut lines: Vec<View> = vec![Box::new(
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
        lines.push(Box::new(view().fill(text().content(line))));
    }
    if let Some(failure) = outcome.failure {
        lines.push(Box::new(view().fill(text().content(format!(
            "{} at audit_id {} expected={} actual={}",
            failure.reason,
            failure.audit_id,
            failure.expected.as_deref().unwrap_or(""),
            failure.actual.as_deref().unwrap_or("")
        )))));
    }
    Box::new(view().class("result-box mono").fill(lines))
}
