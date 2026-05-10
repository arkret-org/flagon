//! chadex — Contrix v1 Directory Service reference implementation.
//!
//! Crate-level entry: re-export the public surface so `main.rs` and tests
//! can compose the service in one line.

#![recursion_limit = "256"]

#[macro_use]
extern crate diesel;

pub mod audit;
pub mod config;
pub mod db;
pub mod error;
pub mod filter;
pub mod ids;
pub mod ingest;
pub mod query;
pub mod routing;
pub mod schema;
pub mod state;

pub use config::AppConfig;
pub use db::Db;
pub use error::ErrorCode;
pub use routing::{router, service};
pub use state::AppState;
