//! Salvo middleware modules.
//!
//! Admin authentication middleware for the read-only Directory service.

pub mod admin_auth;

pub use admin_auth::{AdminAuthHoop, require_admin_csrf, verify_admin_credential};
