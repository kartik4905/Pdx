//! PDF Cleaner Implementation
//! Author: kartik4091
//! Cleans known risky annotations, scripts, actions, and embedded objects.

use crate::error::Error;
use crate::types::{Document, Object, ObjectId};
use crate::utils::metrics::Metrics;

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::structure_cleaner::{CleanResult, CleanStats, CleanMetrics, Cleaner};

#[derive(Debug, Default)]
pub struct PdfCleanerConfig {
    pub remove_names: bool,
    pub remove_actions: bool,
    pub remove_scripts: bool,
}

#[derive(Debug)]
pub struct PdfCleaner {
    config: PdfCleanerConfig,
    stats: Arc<RwLock<CleanStats>>,
    metrics: Arc<Metrics>,
}

impl PdfCleaner {
    pub fn new() -> Self {
        Self {
            config: PdfCleanerConfig::default(),
            stats: Arc::new(RwLock::new(CleanStats::default())),
            metrics: Arc::new(Metrics::new()),
        }
    }

    pub async fn clean(&self, doc: &mut Document) -> Result<(), Error> {
        let start = std::time::Instant::now();
        let mut to_remove = HashSet::new();

        for (id, obj) in &doc.content {
            if let Object::Dictionary(dict) = obj {
                if self.config.remove_names && dict.contains_key(b"Names") {
                    to_remove.insert(*id);
                }
                if self.config.remove_scripts && (dict.contains_key(b"JavaScript") || dict.contains_key(b"JS")) {
                    to_remove.insert(*id);
                }
                if self.config.remove_actions && dict.contains_key(b"AA") {
                    to_remove.insert(*id);
                }
                if self.config.remove_actions && dict.contains_key(b"OpenAction") {
                    to_remove.insert(*id);
                }
            }
        }

        for id in &to_remove {
            doc.content.remove(id);
        }

        let duration = start.elapsed();
        let mut stats = self.stats.write().await;
        stats.total_ops += 1;
        stats.successful_ops += 1;
        stats.total_bytes += to_remove.len() as u64;
        stats.avg_op_time = duration;

        info!("PDF cleaner removed {} risky objects", to_remove.len());
        Ok(())
    }
}

#[async_trait]
impl Cleaner for PdfCleaner {
    async fn clean_file(&self, _path: &PathBuf) -> Result<CleanResult, Error> {
        Err(Error::Unsupported("Direct file cleaning not supported for PdfCleaner".into()))
    }

    async fn validate(&self, _path: &PathBuf) -> Result<(), Error> {
        Ok(())
    }

    async fn cleanup(&self) -> Result<(), Error> {
        let mut stats = self.stats.write().await;
        *stats = CleanStats::default();
        Ok(())
    }

    async fn get_stats(&self) -> Result<CleanStats, Error> {
        Ok(self.stats.read().await.clone())
    }
      }
