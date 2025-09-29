use std::{borrow::Borrow, fmt::Debug, hash::Hash, sync::Arc};

use dashmap::DashMap;

#[derive(Debug, Clone)]
pub struct EntryGuard<K: Hash + Eq + Borrow<Q>, V, Q: Hash + Eq = K> {
    map: Arc<DashMap<K, V>>,
    query: Q,
}

impl<K: Hash + Eq + Borrow<Q>, V, Q: Hash + Eq> EntryGuard<K, V, Q> {
    pub fn new(map: Arc<DashMap<K, V>>, query: Q) -> Self {
        Self { map, query }
    }
}

impl<K: Hash + Eq + Borrow<Q>, V, Q: Hash + Eq> Drop for EntryGuard<K, V, Q> {
    fn drop(&mut self) {
        self.map.remove(&self.query);
    }
}
