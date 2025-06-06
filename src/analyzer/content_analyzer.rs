//! Content Analyzer Implementation
//! Author: kartik4091
//! Created: 2025-06-03 08:43:09 UTC

use super::*;
use crate::utils::{metrics::Metrics, cache::Cache};
use std::{
    sync::Arc,
    time::{Duration, Instant},
    collections::{HashMap, HashSet, BTreeMap},
};
use tokio::sync::{RwLock, Semaphore, broadcast};
use tracing::{info, warn, error, debug, instrument};
use serde::{Serialize, Deserialize};

/// Content type for analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContentType {
    Text,
    Binary,
    Image,
    Executable,
    Script,
    Unknown,
}

/// Content analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAnalyzerConfig {
    /// Base configuration
    pub base: AnalyzerConfig,
    /// Content types to analyze
    pub content_types: HashSet<ContentType>,
    /// Pattern matching rules
    pub patterns: HashMap<String, String>,
    /// Maximum content size to analyze
    pub max_content_size: usize,
    /// Analysis depth level (1-5)
    pub analysis_depth: u8,
}

/// Content analyzer state
#[derive(Debug)]
struct ContentAnalyzerState {
    initialized: bool,
    history: Vec<AnalyzerEvent>,
    patterns: HashMap<String, regex::Regex>,
    content_cache: HashMap<String, CachedContent>,
    stats: ContentStats,
}

/// Statistics for content analysis
#[derive(Debug, Default)]
struct ContentStats {
    content_analyzed: u64,
    patterns_matched: u64,
    risks_identified: u64,
    processing_time: Duration,
}

/// Cached content analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedContent {
    content_type: ContentType,
    risks: Vec<RiskFinding>,
    patterns_found: HashSet<String>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

/// Content analyzer implementation
pub struct ContentAnalyzer {
    base: Arc<BaseAnalyzer>,
    config: Arc<ContentAnalyzerConfig>,
    metrics: Arc<Metrics>,
    state: Arc<RwLock<ContentAnalyzerState>>,
    cache: Arc<Cache<CachedContent>>,
    alert_tx: broadcast::Sender<RiskFinding>,
}

impl ContentAnalyzer {
    /// Creates a new content analyzer instance
    pub fn new(config: ContentAnalyzerConfig) -> Self {
        let (alert_tx, _) = broadcast::channel(100);
        let patterns = Self::compile_patterns(&config.patterns);

        Self {
            base: Arc::new(BaseAnalyzer::new(config.base.clone())),
            config: Arc::new(config),
            metrics: Arc::new(Metrics::new()),
            state: Arc::new(RwLock::new(ContentAnalyzerState {
                initialized: false,
                history: Vec::new(),
                patterns,
                content_cache: HashMap::new(),
                stats: ContentStats::default(),
            })),
            cache: Arc::new(Cache::new(Duration::from_secs(3600))), // 1 hour cache
            alert_tx,
        }
    }

    /// Compiles regex patterns from configuration
    fn compile_patterns(patterns: &HashMap<String, String>) -> HashMap<String, regex::Regex> {
        patterns.iter()
            .filter_map(|(name, pattern)| {
                regex::Regex::new(pattern)
                    .map(|r| (name.clone(), r))
                    .ok()
            })
            .collect()
    }

    /// Determines content type
    #[instrument(skip(self, data))]
    async fn detect_content_type(&self, data: &[u8]) -> Result<ContentType> {
        if data.is_empty() {
            return Ok(ContentType::Unknown);
        }

        // Check for text content
        if data.iter().all(|&b| b.is_ascii()) {
            return Ok(ContentType::Text);
        }

        // Check for executable
        if data.starts_with(b"MZ") || data.starts_with(b"\x7FELF") {
            return Ok(ContentType::Executable);
        }

        // Check for images
        if data.starts_with(b"\x89PNG") || data.starts_with(b"JFIF") {
            return Ok(ContentType::Image);
        }

        // Check for scripts
        if data.starts_with(b"#!/") || data.windows(5).any(|w| w == b"<?php") {
            return Ok(ContentType::Script);
        }

        Ok(ContentType::Binary)
    }

    /// Analyzes content for patterns
    #[instrument(skip(self, data))]
    async fn analyze_patterns(&self, data: &[u8]) -> Result<Vec<(String, Vec<usize>)>> {
        let mut matches = Vec::new();
        let content = String::from_utf8_lossy(data);

        let state = self.state.read().await;
        for (name, pattern) in &state.patterns {
            let positions: Vec<_> = pattern.find_iter(&content)
                .map(|m| m.start())
                .collect();
            if !positions.is_empty() {
                matches.push((name.clone(), positions));
            }
        }

        Ok(matches)
    }

    /// Analyzes content for potential risks
    #[instrument(skip(self, data, content_type))]
    async fn analyze_content_risks(
        &self,
        data: &[u8],
        content_type: ContentType,
        pattern_matches: &[(String, Vec<usize>)]
    ) -> Result<Vec<RiskFinding>> {
        let mut risks = Vec::new();
        let start = Instant::now();

        // Check for content-specific risks
        match content_type {
            ContentType::Executable => {
                risks.push(RiskFinding {
                    severity: RiskSeverity::High,
                    category: RiskCategory::Security,
                    description: "Executable content detected".into(),
                    location: "Content body".into(),
                    recommendation: "Review executable content for security risks".into(),
                    timestamp: chrono::Utc::now(),
                });
            },
            ContentType::Script => {
                risks.push(RiskFinding {
                    severity: RiskSeverity::Medium,
                    category: RiskCategory::Security,
                    description: "Script content detected".into(),
                    location: "Content body".into(),
                    recommendation: "Review script content for potential risks".into(),
                    timestamp: chrono::Utc::now(),
                });
            },
            _ => {}
        }

        // Process pattern matches
        for (pattern_name, positions) in pattern_matches {
            risks.push(RiskFinding {
                severity: RiskSeverity::Medium,
                category: RiskCategory::Content,
                description: format!("Pattern match: {}", pattern_name),
                location: format!("Positions: {:?}", positions),
                recommendation: "Review matched content".into(),
                timestamp: chrono::Utc::now(),
            });
        }

        // Broadcast high severity risks
        for risk in risks.iter().filter(|r| r.severity == RiskSeverity::High) {
            let _ = self.alert_tx.send(risk.clone());
        }

        self.metrics.record_operation("risk_analysis", start.elapsed()).await;
        Ok(risks)
    }

    /// Subscribes to risk alerts
    pub fn subscribe(&self) -> broadcast::Receiver<RiskFinding> {
        self.alert_tx.subscribe()
    }
}

#[async_trait]
impl Analyzer for ContentAnalyzer {
    #[instrument(skip(self, data))]
    async fn analyze(&self, data: &[u8]) -> Result<AnalysisResult> {
        let start = Instant::now();

        // Get rate limiting permit
        let _permit = self.base.semaphore.acquire().await
            .map_err(|e| AnalyzerError::ProcessingError(e.to_string()))?;

        // Validate input
        self.validate(data).await?;

        // Generate cache key
        let cache_key = format!("content_{}", md5::compute(data).0.to_vec().as_slice());
        
        // Check cache
        if let Some(cached) = self.cache.get(&cache_key).await {
            let cached: CachedContent = bincode::deserialize(&cached)
                .map_err(|e| AnalyzerError::ProcessingError(e.to_string()))?;
            
            return Ok(AnalysisResult {
                file_type: format!("{:?}", cached.content_type),
                metadata: HashMap::new(),
                risks: cached.risks,
                stats: AnalysisStats {
                    file_size: data.len(),
                    memory_used: std::mem::size_of_val(data),
                    operation_count: 1,
                },
                processing_time: Duration::from_secs(0),
            });
        }

        // Analyze content
        let content_type = self.detect_content_type(data).await?;
        let pattern_matches = self.analyze_patterns(data).await?;
        let risks = self.analyze_content_risks(data, content_type, &pattern_matches).await?;

        // Update statistics
        let duration = start.elapsed();
        self.base.update_stats(duration, true).await;

        let mut state = self.state.write().await;
        state.stats.content_analyzed += 1;
        state.stats.patterns_matched += pattern_matches.len() as u64;
        state.stats.risks_identified += risks.len() as u64;
        state.stats.processing_time += duration;

        // Cache results
        let cache_entry = CachedContent {
            content_type,
            risks: risks.clone(),
            patterns_found: pattern_matches.iter()
                .map(|(name, _)| name.clone())
                .collect(),
            timestamp: chrono::Utc::now(),
        };

        self.cache.set(
            cache_key,
            bincode::serialize(&cache_entry)
                .map_err(|e| AnalyzerError::ProcessingError(e.to_string()))?,
        ).await;

        Ok(AnalysisResult {
            file_type: format!("{:?}", content_type),
            metadata: HashMap::new(),
            risks,
            stats: AnalysisStats {
                file_size: data.len(),
                memory_used: std::mem::size_of_val(data),
                operation_count: 1,
            },
            processing_time: duration,
        })
    }

    #[instrument(skip(self, data))]
    async fn validate(&self, data: &[u8]) -> Result<()> {
        // Validate resource limits
        self.base.validate_limits(data).await?;

        // Validate content size
        if data.len() > self.config.max_content_size {
            return Err(AnalyzerError::ResourceLimit(
                format!("Content size {} exceeds limit {}", 
                    data.len(), self.config.max_content_size)
            ));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn cleanup(&self) -> Result<()> {
        // Clear cache
        self.cache.clear().await;

        // Reset state
        let mut state = self.state.write().await;
        state.content_cache.clear();
        state.history.clear();
        state.stats = ContentStats::default();

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_stats(&self) -> Result<AnalyzerStats> {
        let state = self.state.read().await;
        Ok(AnalyzerStats {
            total_operations: state.stats.content_analyzed,
            successful_operations: state.stats.content_analyzed,
            failed_operations: 0,
            total_processing_time: state.stats.processing_time,
            avg_processing_time: if state.stats.content_analyzed > 0 {
                state.stats.processing_time / state.stats.content_analyzed
            } else {
                Duration::default()
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ContentAnalyzerConfig {
        ContentAnalyzerConfig {
            base: AnalyzerConfig::default(),
            content_types: [
                ContentType::Text,
                ContentType::Binary,
                ContentType::Executable,
            ].iter().cloned().collect(),
            patterns: [
                ("password".to_string(), r"password=\S+".to_string()),
                ("email".to_string(), r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string()),
            ].iter().cloned().collect(),
            max_content_size: 1024 * 1024, // 1MB
            analysis_depth: 3,
        }
    }

    #[tokio::test]
    async fn test_content_type_detection() {
        let analyzer = ContentAnalyzer::new(create_test_config());
        
        assert_eq!(
            analyzer.detect_content_type(b"Hello, World!").await.unwrap(),
            ContentType::Text
        );
        assert_eq!(
            analyzer.detect_content_type(b"MZ").await.unwrap(),
            ContentType::Executable
        );
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        let analyzer = ContentAnalyzer::new(create_test_config());
        let data = b"password=secret123\nuser@example.com";
        
        let matches = analyzer.analyze_patterns(data).await.unwrap();
        assert_eq!(matches.len(), 2);
    }

    #[tokio::test]
    async fn test_risk_detection() {
        let analyzer = ContentAnalyzer::new(create_test_config());
        let data = b"#!/bin/bash\necho 'Hello'";
        
        let result = analyzer.analyze(data).await.unwrap();
        assert!(!result.risks.is_empty());
    }

    #[tokio::test]
    async fn test_concurrent_analysis() {
        let analyzer = ContentAnalyzer::new(create_test_config());
        let data = b"Test content with patterns: password=secret123";

        let handles: Vec<_> = (0..4).map(|_| {
            let analyzer = analyzer.clone();
            let data = data.to_vec();
            tokio::spawn(async move {
                analyzer.analyze(&data).await
            })
        }).collect();

        let results = futures::future::join_all(handles).await;
        for result in results {
            assert!(result.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn test_risk_alerts() {
        let analyzer = ContentAnalyzer::new(create_test_config());
        let mut rx = analyzer.subscribe();
        
        let data = b"MZ\x00\x00Executable content";
        analyzer.analyze(data).await.unwrap();
        
        if let Ok(risk) = rx.try_recv() {
            assert_eq!(risk.severity, RiskSeverity::High);
        }
    }

    #[tokio::test]
    async fn test_cleanup() {
        let analyzer = ContentAnalyzer::new(create_test_config());
        assert!(analyzer.cleanup().await.is_ok());
    }

    #[tokio::test]
    async fn test_stats() {
        let analyzer = ContentAnalyzer::new(create_test_config());
        let data = b"Test content";
        
        analyzer.analyze(data).await.unwrap();
        let stats = analyzer.get_stats().await.unwrap();
        assert_eq!(stats.total_operations, 1);
        assert_eq!(stats.failed_operations, 0);
    }
              }
