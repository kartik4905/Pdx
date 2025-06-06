use lopdf::{Object, Dictionary}; // Removed `Array` from the import
use std::collections::HashMap;

pub struct DocumentMetrics;

impl DocumentMetrics {
    pub fn collect_metrics(&self, dictionary: &Dictionary) -> HashMap<Vec<u8>, Object> {
        dictionary.iter().map(|(key, value)| (key.clone(), value.clone())).collect()
    }
}
