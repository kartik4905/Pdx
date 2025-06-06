//! Utilities for extracting and decoding PDF metadata

use crate::types::Object;
use std::collections::HashMap;

/// Extract a UTF-8 string from an Info dictionary entry
pub fn get_metadata_string(info: &HashMap<Vec<u8>, Object>, key: &[u8]) -> Option<String> {
    info.get(key).and_then(|obj| {
        if let Object::String(s) = obj {
            String::from_utf8(s.clone()).ok()
        } else {
            None
        }
    })
}
