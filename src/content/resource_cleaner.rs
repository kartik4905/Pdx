//! Resource Cleaner
//! Author: kartik4091
//! Cleans unused font/image resources from PDF pages.

use crate::{
    error::Result,
    types::{Document, Object, ObjectId},
    utils::Logger,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{info, warn};

/// Cleans up unused resources in PDF pages
pub struct ResourceCleaner {
    logger: Arc<Logger>,
}

impl ResourceCleaner {
    pub fn new() -> Self {
        Self {
            logger: Arc::new(Logger::default()),
        }
    }

    /// Removes unused resources like fonts and images
    pub async fn clean(&self, doc: &mut Document) -> Result<()> {
        let used_resources = self.collect_used_resources(&doc.structure.objects);
        let mut removed = 0;

        for (_id, obj) in &mut doc.structure.objects {
            if let Object::Dictionary(dict) = obj {
                if let Some(Object::Dictionary(resources)) = dict.get_mut(b"Resources") {
                    removed += self.remove_unused(resources, &used_resources);
                }
            }
        }

        if removed > 0 {
            info!("ResourceCleaner removed {} unused resources", removed);
            self.logger
                .log(
                    crate::utils::logging::LogLevel::Info,
                    &format!("Removed {} unused resources", removed),
                    module_path!(),
                    file!(),
                    line!(),
                )
                .await?;
        }

        Ok(())
    }

    fn collect_used_resources(&self, objects: &HashMap<ObjectId, Object>) -> HashSet<Vec<u8>> {
        let mut used = HashSet::new();

        for (_id, obj) in objects {
            if let Object::Stream(stream) = obj {
                let data = &stream.data;
                for token in data.split(|&b| b == b' ' || b == b'\n') {
                    if token.starts_with(b"/") && token.len() > 1 {
                        used.insert(token[1..].to_vec());
                    }
                }
            }
        }

        used
    }

    fn remove_unused(
        &self,
        resource_dict: &mut HashMap<Vec<u8>, Object>,
        used_resources: &HashSet<Vec<u8>>,
    ) -> usize {
        let mut removed = 0;
        let keys: Vec<Vec<u8>> = resource_dict
            .keys()
            .filter(|k| !used_resources.contains(*k))
            .cloned()
            .collect();

        for k in keys {
            resource_dict.remove(&k);
            removed += 1;
        }

        removed
    }
}
