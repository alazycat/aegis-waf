use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

pub trait CollectionStore: Send + Sync + std::fmt::Debug {
    fn get(&self, collection: &str, key: &str, name: &str) -> Option<String>;
    fn set(&self, collection: &str, key: &str, name: &str, value: String);
    fn remove(&self, collection: &str, key: &str, name: &str) -> Option<String>;
    fn entries(&self, collection: &str, key: &str) -> Vec<(String, String)>;
    fn clear(&self, collection: &str, key: &str);
}

pub type SharedCollectionStore = Arc<dyn CollectionStore>;

#[derive(Debug, Default)]
pub struct MemoryCollectionStore {
    inner: Mutex<HashMap<(String, String), BTreeMap<String, String>>>,
}

impl MemoryCollectionStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(String, String), BTreeMap<String, String>>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl CollectionStore for MemoryCollectionStore {
    fn get(&self, collection: &str, key: &str, name: &str) -> Option<String> {
        self.lock()
            .get(&(collection.to_string(), key.to_string()))
            .and_then(|values| values.get(&name.to_ascii_lowercase()).cloned())
    }

    fn set(&self, collection: &str, key: &str, name: &str, value: String) {
        self.lock()
            .entry((collection.to_string(), key.to_string()))
            .or_default()
            .insert(name.to_ascii_lowercase(), value);
    }

    fn remove(&self, collection: &str, key: &str, name: &str) -> Option<String> {
        self.lock()
            .get_mut(&(collection.to_string(), key.to_string()))
            .and_then(|values| values.remove(&name.to_ascii_lowercase()))
    }

    fn entries(&self, collection: &str, key: &str) -> Vec<(String, String)> {
        self.lock()
            .get(&(collection.to_string(), key.to_string()))
            .map(|values| {
                values
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn clear(&self, collection: &str, key: &str) {
        self.lock()
            .remove(&(collection.to_string(), key.to_string()));
    }
}
