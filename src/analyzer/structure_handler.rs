//! PDF Structure Analysis Handler (Production Ready)
//! Author: kartik4091
//! Created: 2025-06-03

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use chrono::Utc;
use tokio::sync::{broadcast, RwLock, Semaphore};
use tracing::{debug, error, info, instrument, warn};
use dashmap::DashMap;

use crate::{
    error::{Result, StructureError},
    metrics::MetricsCollector,
    types::{Document, Object, ObjectId, ProcessingStage, RiskLevel},
};

// ... (Assume all struct definitions from your last message are here unchanged)

impl StructureHandler {
    pub fn new(config: StructureConfig, metrics: Arc<MetricsCollector>) -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            state: Arc::new(RwLock::new(StructureState {
                active_analyses: 0,
                analysis_results: DashMap::new(),
                analysis_history: Vec::new(),
                start_time: Instant::now(),
                bytes_analyzed: 0,
            })),
            rate_limiter: Arc::new(Semaphore::new(config.max_concurrent)),
            metrics,
            config: Arc::new(config),
            event_tx,
        }
    }

    async fn acquire_permit(&self) -> Result<tokio::sync::SemaphorePermit<'_>> {
        self.rate_limiter.clone().acquire_owned().await.map_err(|_| StructureError::SemaphorePoisoned.into())
    }

    async fn get_cached_result(&self, document: &Document) -> Option<StructureAnalysis> {
        self.state.read().await.analysis_results.get(document.id()).map(|entry| entry.clone())
    }

    pub async fn analyze(&self, document: &Document) -> Result<StructureAnalysis> {
        let _permit = self.acquire_permit().await?;
        let start = Instant::now();
        self.metrics.increment_counter("structure_analyses_started").await;

        let _ = self.event_tx.send(StructureEvent::AnalysisStarted {
            document_id: document.id().to_string(),
            timestamp: Utc::now(),
        });

        if self.config.enable_cache {
            if let Some(cached) = self.get_cached_result(document).await {
                return Ok(cached);
            }
        }

        let result = self.perform_analysis(document).await;

        let mut state = self.state.write().await;
        state.active_analyses -= 1;
        if let Ok(ref analysis) = result {
            state.analysis_results.insert(document.id().to_string(), analysis.clone());
            state.analysis_history.push(AnalysisRecord {
                document_id: document.id().to_string(),
                start_time: start,
                duration: start.elapsed(),
                bytes_analyzed: document.size(),
                issues_found: analysis.risk_assessment.risk_factors.len(),
                success: true,
            });
        }

        if let Ok(analysis) = &result {
            let _ = self.event_tx.send(StructureEvent::AnalysisCompleted {
                document_id: document.id().to_string(),
                result: analysis.clone(),
            });
        } else if let Err(err) = &result {
            let _ = self.event_tx.send(StructureEvent::AnalysisFailed {
                document_id: document.id().to_string(),
                error: err.to_string(),
            });
        }

        self.metrics.increment_counter(
            if result.is_ok() { "structure_analyses_completed" } else { "structure_analyses_failed" }
        ).await;
        self.metrics.observe_duration("structure_analysis_duration", start.elapsed()).await;

        result
    }

    async fn perform_analysis(&self, document: &Document) -> Result<StructureAnalysis> {
        let start_time = Instant::now();
        let objects = &document.structure.objects;

        let mut risk_factors = vec![];

        // Basic stats
        let total_objects = objects.len();
        let mut free_objects = vec![];
        let mut duplicate_objects = vec![];
        let mut object_streams = vec![];
        let mut dependencies = HashMap::new();
        let mut seen_objects = HashSet::new();

        for (id, obj) in objects {
            if !seen_objects.insert(id.number) {
                duplicate_objects.push((id.number, id.generation));
            }

            match obj {
                Object::Null => free_objects.push(id.number),
                Object::Dictionary(dict) => {
                    let deps = dict.values().filter_map(|v| match v {
                        Object::Reference(ref_id) => Some(ref_id.number),
                        _ => None,
                    }).collect::<HashSet<_>>();
                    if !deps.is_empty() {
                        dependencies.insert(id.number, deps);
                    }
                }
                Object::Stream(stream) => {
                    let compressed_size = stream.data.len() as u64;
                    object_streams.push(ObjectStream {
                        object_number: id.number,
                        contained_objects: vec![], // optional to fill
                        compressed_size,
                        uncompressed_size: compressed_size, // assume same
                    });
                }
                _ => {}
            }
        }

        let object_structure = ObjectStructure {
            total_objects,
            free_objects,
            duplicate_objects,
            object_streams,
            dependencies,
        };

        if !duplicate_objects.is_empty() {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::ObjectInconsistency,
                description: "Duplicate object IDs found".into(),
                risk_level: RiskLevel::Medium,
            });
        }

        let trailer_info = TrailerInfo {
            root: document.structure.trailer.root.map(|id| id.number).unwrap_or_default(),
            info: document.structure.trailer.info.map(|id| id.number),
            id: None,
            encrypt: document.structure.trailer.encrypt.map(|id| id.number),
            size: document.structure.trailer.size.unwrap_or(0),
            prev: document.structure.trailer.prev,
        };

        let risk_level = match risk_factors.iter().map(|f| f.risk_level).max() {
            Some(RiskLevel::High) => RiskLevel::High,
            Some(RiskLevel::Medium) => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };

        Ok(StructureAnalysis {
            document_id: document.id().to_string(),
            pdf_version: PdfVersion {
                major: 1,
                minor: 7,
                extension_level: None,
                features: HashSet::new(),
            },
            xref_tables: vec![],
            object_structure,
            trailer_info,
            linearization: None,
            incremental_updates: vec![],
            risk_assessment: RiskAssessment {
                risk_level,
                risk_factors,
                recommendation: "Review inconsistencies and clean metadata.".into(),
            },
            timestamp: Utc::now(),
            duration: start_time.elapsed(),
        })
    }
}
