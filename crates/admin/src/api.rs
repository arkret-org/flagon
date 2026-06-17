use std::rc::Rc;

use gloo_net::http::{Request, RequestBuilder, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value as JsonValue, json};

use crate::model::{AuditEvent, BADGE_DANGER, BADGE_NEUTRAL, BADGE_OK, BADGE_WARN, ResourceItem};

pub async fn get_admin<T: DeserializeOwned>(
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

pub async fn post_admin<B: Serialize + ?Sized, T: DeserializeOwned>(
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

pub async fn delete_admin<T: DeserializeOwned>(
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

pub async fn post_directory<B: Serialize + ?Sized, T: DeserializeOwned>(
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

pub fn push_param(params: &mut Vec<(&'static str, String)>, key: &'static str, value: String) {
    if !value.trim().is_empty() {
        params.push((key, value.trim().to_string()));
    }
}

pub fn bool_filter(value: String) -> String {
    match value.as_str() {
        "true" | "false" => value,
        _ => String::new(),
    }
}

pub fn insert_optional_string(
    body: &mut serde_json::Map<String, JsonValue>,
    key: &str,
    value: &str,
) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        body.insert(key.to_string(), JsonValue::String(trimmed.to_string()));
    }
}

pub fn optional_u32(value: &str, field: &str) -> Result<Option<u32>, String> {
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

pub fn nonempty_or(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn option_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub fn parse_optional_i64(raw: &str, field: &str) -> Result<Option<i64>, String> {
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

pub fn parse_json_object(raw: &str, field: &str) -> Result<JsonValue, String> {
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

pub fn parse_optional_json_object(raw: &str, field: &str) -> Result<Option<JsonValue>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        parse_json_object(trimmed, field).map(Some)
    }
}

pub fn parse_string_array(raw: &str, field: &str) -> Result<Vec<String>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(Vec::new())
    } else {
        serde_json::from_str(trimmed).map_err(|error| format!("{field}: {error}"))
    }
}

pub fn pretty_json(value: &JsonValue) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
}

pub fn pretty_string_array(values: &[String]) -> String {
    serde_json::to_string_pretty(values).unwrap_or_else(|_| "[]".to_string())
}

pub fn resource_form_key(kind: &str, resource_id: &str) -> String {
    format!("{}::{resource_id}", kind.trim())
}

pub fn resource_key(item: &ResourceItem) -> String {
    resource_form_key(&item.resource_kind, &item.resource_id)
}

pub fn upsert_resource_row(rows: &mut Vec<ResourceItem>, item: ResourceItem) {
    let key = resource_key(&item);
    if let Some(existing) = rows.iter_mut().find(|row| resource_key(row) == key) {
        *existing = item;
    } else {
        rows.insert(0, item);
    }
}

pub fn parse_evidence(raw: &str) -> Result<JsonValue, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_str(trimmed).map_err(|error| format!("evidence JSON: {error}"))
    }
}

pub fn compact_json(value: &JsonValue) -> String {
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

pub fn audit_badge_class(kind: &str) -> &'static str {
    match kind {
        "ingest_rejected" | "revalidation_failed" | "operator_takedown" => BADGE_DANGER,
        "allowlist_added" | "allowlist_removed" | "withdrawal" | "admin_resource_deleted" => {
            BADGE_WARN
        }
        "admin_resource_upserted" => BADGE_OK,
        _ => BADGE_NEUTRAL,
    }
}

pub fn is_review_event(event: &AuditEvent) -> bool {
    matches!(
        event.kind.as_str(),
        "ingest_rejected" | "revalidation_failed" | "operator_takedown"
    )
}

fn net_error(error: gloo_net::Error) -> String {
    error.to_string()
}
