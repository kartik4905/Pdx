//! Config utilities for merging runtime options and validating key-value entries.

use std::collections::HashMap;

/// Merge two configuration maps, with `override_cfg` taking precedence.
pub fn merge_configs(
    base_cfg: &HashMap<String, String>,
    override_cfg: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut merged = base_cfg.clone();
    for (k, v) in override_cfg {
        merged.insert(k.clone(), v.clone());
    }
    merged
}
