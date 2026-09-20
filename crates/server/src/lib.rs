//! teabay — Arkret v1 Directory Service reference implementation.
//!
//! Crate-level entry: re-export the public surface so `main.rs` and tests
//! can compose the service in one line.

#![recursion_limit = "256"]

pub mod audit;
pub mod config;
pub mod db;
mod db_enum;
pub mod error;
pub mod middleware;
pub mod observability;
pub mod query;
pub mod routing;
pub mod schema;
pub mod state;
mod util;

pub use config::AppConfig;
pub use db::Db;
pub use error::ApiErrorCode;
pub use routing::{metrics_service, router, service};
pub use state::AppState;
