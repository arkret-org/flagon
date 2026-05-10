//! Process-wide shared state injected via salvo affix-state.

use std::sync::Arc;

use crate::{config::AppConfig, db::Db};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: AppConfig,
    db: Db,
}

impl AppState {
    pub fn new(config: AppConfig, db: Db) -> Self {
        Self {
            inner: Arc::new(Inner { config, db }),
        }
    }

    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }
}
