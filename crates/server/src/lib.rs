//! teabay — Cokret v1 Directory Service reference implementation.
//!
//! Crate-level entry: re-export the public surface so `main.rs` and tests
//! can compose the service in one line.

#![recursion_limit = "256"]

pub mod audit;
pub mod config;
pub mod db;
mod did_resolver;
mod egress;
pub mod error;
pub mod filter;
pub mod ids;
pub mod ingest;
pub mod kinds;
pub mod middleware;
pub mod observability;
pub mod profile;
pub mod query;
pub mod routing;
pub mod schema;
pub mod state;
pub mod workers;

pub use config::AppConfig;
pub use db::Db;
pub use error::ApiErrorCode;
pub use routing::{metrics_service, router, service};
pub use state::AppState;
