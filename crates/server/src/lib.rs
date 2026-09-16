//! teabay — Arkret v1 Directory Service reference implementation.
//!
//! Crate-level entry: re-export the public surface so `main.rs` and tests
//! can compose the service in one line.

#![recursion_limit = "256"]

pub mod audit;
pub mod config;
pub mod db;
mod db_enum;
pub mod did_binding;
pub mod did_resolver;
mod egress;
pub mod error;
pub mod filter;
pub mod ids;
pub mod ingest;
pub mod middleware;
pub mod observability;
pub mod pcd;
pub mod pcd_state;
pub mod query;
pub mod routing;
pub mod schema;
mod source_refs;
pub mod state;
mod util;
pub mod workers;

pub use config::AppConfig;
pub use db::Db;
pub use error::ApiErrorCode;
pub use routing::{metrics_service, router, service};
pub use state::AppState;
