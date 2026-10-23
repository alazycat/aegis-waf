use std::path::PathBuf;
use std::sync::Arc;

use aegis_engine::{load_rules, CompiledRules, LoadError, LoadOptions};
use arc_swap::ArcSwap;

pub struct RulesManager {
    files: Vec<PathBuf>,
    lenient: bool,
    current: ArcSwap<CompiledRules>,
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
        })
    }

    pub fn snapshot(&self) -> Arc<CompiledRules> {
        self.current.load_full()
    }

    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    #[allow(dead_code)]
    pub fn lenient(&self) -> bool {
        self.lenient
    }
}
