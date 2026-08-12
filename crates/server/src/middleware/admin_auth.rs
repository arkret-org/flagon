//! Admin bearer authentication with HMAC-SHA256 rotation support.
//!
//! Two credential forms are accepted, but the static bearer is limited
//! to development mode:
//!
//! * **Development static bearer** — `Authorization: Bearer <TEABAY_ADMIN_TOKEN>`. Existing local
//!   operator scripts and the in-process conformance harness continue to work while
//!   `TEABAY_DEVELOPMENT_MODE=true`; production rejects this long-lived credential shape.
//!
//! * **Rotating HMAC** — `Authorization: Bearer hmac:<key_id>:<ts>:<mac_base64>`. The shared secret
//!   is provisioned by row in `admin_tokens`. Clients compute `mac = HMAC_SHA256(secret,
//!   format!("{key_id}:{ts}"))` and include the timestamp so teabay can drop replays after the
//!   rotation window (default 30 minutes).
//!
//! The verification result carries the authentication method and the
//! key id (when applicable) so the chained-audit writer can attribute
//! every admin write to a specific credential.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use hmac::{Hmac, KeyInit, Mac};
use salvo::http::header;
use salvo::prelude::*;
use sha2::Sha256;

use crate::error::ApiErrorCode;
use crate::state::AppState;

/// Identity established by `verify_admin_credential`. The audit writer
/// uses these fields to populate `authentication_method` and
/// `authenticated_actor`.
#[derive(Debug, Clone)]
pub struct AdminCredential {
    pub method: AdminAuthMethod,
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum AdminAuthMethod {
    StaticBearer,
    RotatingHmac,
}

impl AdminAuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaticBearer => "static_bearer",
            Self::RotatingHmac => "rotating_hmac",
        }
    }
}

impl AdminCredential {
    pub fn authentication_method(&self) -> &'static str {
        self.method.as_str()
    }

    /// Human-readable actor identifier for the audit row. Defaults to
    /// the key id for HMAC credentials and to a static literal for the
    /// development-only bearer (the static bearer is not pinned to a
    /// single operator identity).
    pub fn authenticated_actor(&self) -> String {
        match (self.method, self.key_id.as_deref()) {
            (AdminAuthMethod::RotatingHmac, Some(key_id)) => format!("admin:{key_id}"),
            (AdminAuthMethod::RotatingHmac, None) => "admin:unknown".to_owned(),
            (AdminAuthMethod::StaticBearer, _) => "admin:static-bearer".to_owned(),
        }
    }
}

/// Verify the `Authorization` header on an admin endpoint. Returns the
/// resolved credential metadata on success, or an `ApiErrorCode` the
/// caller renders directly (so the existing handler shape is
/// preserved).
pub async fn verify_admin_credential(
    req: &Request,
    state: &AppState,
) -> Result<AdminCredential, ApiErrorCode> {
    let raw = extract_bearer(req).ok_or(ApiErrorCode::Unauthenticated)?;

    if let Some(rest) = raw.strip_prefix("hmac:") {
        return verify_rotating_hmac(state, rest).await;
    }

    if !static_admin_bearer_allowed(state.config().development_mode) {
        return Err(ApiErrorCode::Unauthenticated);
    }

    let expected = state
        .config()
        .admin_token
        .as_deref()
        .ok_or(ApiErrorCode::Unauthenticated)?;
    if constant_time_eq(raw.as_bytes(), expected.as_bytes()) {
        Ok(AdminCredential {
            method: AdminAuthMethod::StaticBearer,
            key_id: None,
        })
    } else {
        Err(ApiErrorCode::Unauthenticated)
    }
}

fn static_admin_bearer_allowed(development_mode: bool) -> bool {
    development_mode
}

fn extract_bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

async fn verify_rotating_hmac(
    state: &AppState,
    raw: &str,
) -> Result<AdminCredential, ApiErrorCode> {
    // Wire format: `<key_id>:<unix_ts>:<base64(mac)>`. Splits are
    // bounded so an oversized payload cannot allocate unbounded.
    let mut parts = raw.splitn(3, ':');
    let key_id = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(ApiErrorCode::Unauthenticated)?;
    let ts = parts
        .next()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .ok_or(ApiErrorCode::Unauthenticated)?;
    let mac_b64 = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(ApiErrorCode::Unauthenticated)?;

    let signed_at = DateTime::<Utc>::from_timestamp(ts, 0).ok_or(ApiErrorCode::Unauthenticated)?;
    let window = chrono::Duration::from_std(state.config().admin_token_rotation_window)
        .map_err(|_| ApiErrorCode::InternalError)?;
    let now = Utc::now();
    let drift = (now - signed_at).num_seconds().abs();
    if drift > window.num_seconds() {
        return Err(ApiErrorCode::Unauthenticated);
    }

    let mac_bytes = STANDARD_NO_PAD
        .decode(mac_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(mac_b64))
        .map_err(|_| ApiErrorCode::Unauthenticated)?;

    let secret = lookup_admin_secret(state, key_id).await?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&secret).map_err(|_| ApiErrorCode::InternalError)?;
    mac.update(format!("{key_id}:{ts}").as_bytes());
    mac.verify_slice(&mac_bytes)
        .map_err(|_| ApiErrorCode::Unauthenticated)?;

    Ok(AdminCredential {
        method: AdminAuthMethod::RotatingHmac,
        key_id: Some(key_id.to_owned()),
    })
}

async fn lookup_admin_secret(state: &AppState, key_id: &str) -> Result<Vec<u8>, ApiErrorCode> {
    use crate::schema::admin_tokens::dsl as t;

    type AdminTokenRow = (Vec<u8>, Option<DateTime<Utc>>, Option<DateTime<Utc>>);

    let mut conn = state
        .db()
        .get()
        .await
        .map_err(|_| ApiErrorCode::InternalError)?;
    let now = Utc::now();
    let row: Option<AdminTokenRow> = t::admin_tokens
        .filter(t::key_id.eq(key_id))
        .select((t::secret, t::expires_at, t::revoked_at))
        .first(&mut *conn)
        .await
        .optional()
        .map_err(|_| ApiErrorCode::InternalError)?;
    let (secret, expires_at, revoked_at) = row.ok_or(ApiErrorCode::Unauthenticated)?;
    if let Some(revoked_at) = revoked_at
        && revoked_at <= now
    {
        return Err(ApiErrorCode::Unauthenticated);
    }
    if let Some(expires_at) = expires_at
        && expires_at <= now
    {
        return Err(ApiErrorCode::Unauthenticated);
    }
    Ok(secret)
}

/// C.10.10 — enforce the configured CSRF token on state-changing
/// admin requests. The request must carry an `X-CSRF-Token` header matching
/// the configured value. Safe reads (GET / HEAD / OPTIONS) are exempt because
/// they cannot mutate state; an unset token is only tolerated in development
/// mode, since `AppConfig::from_env` refuses to boot production without one.
pub fn require_admin_csrf(req: &Request, state: &AppState) -> Result<(), ApiErrorCode> {
    let method = req.method();
    if matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        return Ok(());
    }
    let Some(expected) = state.config().admin_csrf_token.as_deref() else {
        if state.config().development_mode {
            return Ok(());
        }
        return Err(ApiErrorCode::Unauthenticated);
    };
    let supplied = req
        .headers()
        .get("X-CSRF-Token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default();
    if constant_time_eq(supplied.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(ApiErrorCode::Unauthenticated)
    }
}

/// Router-level admin guard. Individual handlers still verify credentials so
/// audit attribution remains local to the write path, but this hoop prevents a
/// newly added admin route from silently shipping without auth.
pub struct AdminAuthHoop;

#[async_trait]
impl Handler for AdminAuthHoop {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if req.method().as_str() == "OPTIONS" {
            return;
        }

        let state = match depot.get_typed::<AppState>() {
            Ok(state) => state.clone(),
            Err(_) => {
                ApiErrorCode::InternalError.render(res, "AppState not injected");
                ctrl.skip_rest();
                return;
            }
        };

        if let Err(error) = verify_admin_credential(req, &state).await {
            error.render(res, "admin bearer token required");
            ctrl.skip_rest();
            return;
        }
        if let Err(error) = require_admin_csrf(req, &state) {
            error.render(res, "admin CSRF token required");
            ctrl.skip_rest();
        }
    }
}

/// Constant-time byte comparison so a development static bearer cannot
/// be probed byte-by-byte against the configured token.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_admin_bearer_is_development_only() {
        assert!(static_admin_bearer_allowed(true));
        assert!(!static_admin_bearer_allowed(false));
    }
}
