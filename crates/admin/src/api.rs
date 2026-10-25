use std::rc::Rc;

use gloo_net::http::{Request, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;

pub async fn get_admin<T: DeserializeOwned>(
    base_url: Rc<str>,
    token: Rc<str>,
    path: &'static str,
    parameters: Vec<(&'static str, String)>,
) -> Result<T, String> {
    let url = format!("{}/_flagon/admin/{}", base_url.trim_end_matches('/'), path);
    let request = with_auth(
        Request::get(&url).query(parameters.iter().map(|(key, value)| (*key, value.as_str()))),
        &token,
    );
    decode_response(request.send().await.map_err(|error| error.to_string())?).await
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_details_bound_unicode_scalars_without_corrupting_text() {
        let text = compact_json(&serde_json::json!({"reason":"秘密🙂".repeat(100)}));
        assert_eq!(text.chars().count(), 220);
        assert!(text.ends_with("..."));
        assert!(!text.contains('�'));
        assert_eq!(
            compact_json(&serde_json::json!({"count":2})),
            "{\"count\":2}"
        );
    }
    #[test]
    fn response_excerpt_preserves_short_and_boundary_strings() {
        assert_eq!(truncate("", 0), "");
        assert_eq!(truncate("秘密", 2), "秘密");
        assert_eq!(truncate(&"界".repeat(321), 320).chars().count(), 320);
    }
}
