use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use aegis_engine::{load_rules, CompiledRules, LoadError, LoadOptions};
use arc_swap::ArcSwap;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum ReloadError {
    #[error(transparent)]
    Load(#[from] LoadError),
    #[error("reload task failed: {0}")]
    Task(String),
}

pub struct RulesManager {
    files: Vec<PathBuf>,
    lenient: bool,
    current: ArcSwap<CompiledRules>,
    reload_lock: Mutex<()>,
    loaded_at: StdMutex<String>,
}

impl RulesManager {
    pub fn load_initial(files: &[PathBuf], lenient: bool) -> Result<Self, LoadError> {
        let rules = load_rules(
            files,
            &LoadOptions {
                lenient,
                version: 1,
            },
        )?;
        Ok(Self {
            files: files.to_vec(),
            lenient,
            current: ArcSwap::from_pointee(rules),
            reload_lock: Mutex::new(()),
            loaded_at: StdMutex::new(now_rfc3339()),
        })
    }

    pub fn snapshot(&self) -> Arc<CompiledRules> {
        self.current.load_full()
    }

    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    pub fn loaded_at(&self) -> String {
        self.loaded_at
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default()
    }

    pub async fn reload(&self) -> Result<Arc<CompiledRules>, ReloadError> {
        let _guard = self.reload_lock.lock().await;
        let files = self.files.clone();
        let lenient = self.lenient;
        let version = self.current.load().version + 1;
        let loaded = tokio::task::spawn_blocking(move || {
            load_rules(&files, &LoadOptions { lenient, version })
        })
        .await
        .map_err(|error| ReloadError::Task(error.to_string()))?
        .map_err(ReloadError::Load)?;
        let loaded = Arc::new(loaded);
        self.current.store(loaded.clone());
        if let Ok(mut value) = self.loaded_at.lock() {
            *value = now_rfc3339();
        }
        Ok(loaded)
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
