//! P5 — long-running background tasks that operate against the directory
//! database but live outside the ingest hot path.
//!
//! - [`expiry`] purges `directory_resources` rows whose `expires_at` lapsed by more than a
//!   configurable grace window (default 24h).
//! - [`takedown_notifier`] dispatches HMAC-signed webhooks for pending takedown proposals, with
//!   exponential-backoff retry and DLQ on permanent failure.
//!
//! Both workers are configured by env in [`crate::config::AppConfig`]
//! and wired in `main.rs` alongside the existing freshness, pull, and
//! divergence workers.

pub mod expiry;
pub mod takedown_notifier;
