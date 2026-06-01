//! Salvo middleware modules.
//!
//! HTTP-layer enforcement that runs before handlers see the request.
//! Currently:
//!
//! - `http_sig` — RFC 9421 HTTP Message Signature verification (Ed25519) plus optional RFC 9530
//!   `Content-Digest` body integrity check, mounted on the ingest route group so unsigned / forged
//!   pushes never reach [`crate::ingest::verify::VerifyContext`].

pub mod admin_auth;
pub mod http_sig;

pub use admin_auth::{
    AdminAuthHoop, AdminAuthMethod, AdminCredential, require_admin_csrf, verify_admin_credential,
};
pub use http_sig::{
    DidResolverKeyDirectory, Ed25519PublicKey, HttpSigKeyDirectory, HttpSigMiddleware,
    StaticKeyDirectory,
};
