//! Pattern analyzer implementation for PDF document analysis
//! Author: kartik4091
//! Created: 2025-06-03 06:43:59 UTC
//! This module provides pattern matching and analysis capabilities for PDF documents,
//! detecting specific patterns that may indicate security risks or forensic artifacts.

use std::{
    sync::Arc,
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use tracing::{info, warn, error, debug, trace, instrument};
use regex::Regex;

use super::{Analyzer, AnalyzerConfig, AnalysisResult, AnalyzerMetrics, BaseAnalyzer};
use crate::antiforensics::{
    Document,
    PdfError,
    RiskLevel,
    ForensicArtifact,
    ArtifactType,
    ScanResult,
};

/// Pattern definition for matching forensic artifacts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// Unique identifier for the pattern
    pub id: String,
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: String,
    /// Regular expression pattern
    pub regex: String,
    /// Pattern category
    pub category: PatternCategory,
    /// Associated risk level
    pub risk_level: RiskLevel,
    /// Detection context requirements
    pub context: Vec<PatternContext>,
    /// False positive probability
    pub false_positive_rate: f64,
    /// Pattern version
    pub version: String,
    /// Last updated timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Pattern metadata
    pub metadata: HashMap<String, String>,
}

/// Categories of patterns to match
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PatternCategory {
    /// Metadata patterns
    Metadata,
    /// Content patterns
    Content,
    /// Structure patterns
    Structure,
    /// JavaScript patterns
    JavaScript,
    /// Binary patterns
    Binary,
    /// Custom patterns
    Custom(String),
}

/// Context for pattern matching
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PatternContext {
    /// Global document context
    Global,
    /// Object-specific context
    Object(String),
    /// Stream context
    Stream,
    /// Resource context
    Resource(String),
}

/// Pattern analyzer implementation
pub struct PatternAnalyzer {
    /// Base analyzer implementation
    base: BaseAnalyzer,
    /// Compiled patterns
    patterns: Arc<Vec<(Pattern, Regex)>>,
    /// Pattern categories
    categories: Arc<HashSet<PatternCategory>>,
    /// Last pattern update
    last_update: Arc<RwLock<chrono::DateTime<chrono::Utc>>>,
}

impl PatternAnalyzer {
    /// Creates a new pattern analyzer instance
    #[instrument(skip(config))]
    pub async fn new(config: AnalyzerConfig) -> Result<Self, PdfError> {
        debug!("Initializing PatternAnalyzer");
        
        // Load and compile patterns
        let patterns = Self::load_patterns(&config)?;
        let categories = Self::extract_categories(&patterns);

        Ok(Self {
            base: BaseAnalyzer::new(config),
            patterns: Arc::new(patterns),
            categories: Arc::new(categories),
            last_update: Arc::new(RwLock::new(chrono::Utc::now())),
        })
    }

    /// Loads and compiles patterns
    fn load_patterns(config: &AnalyzerConfig) -> Result<Vec<(Pattern, Regex)>, PdfError> {
        let mut patterns = vec![
            // Metadata patterns
            Pattern {
                id: "PAT001".into(),
                name: "Author Information".into(),
                description: "Author metadata detection".into(),
                regex: r"(?i)/Author\s*\(([^)]+)\)".into(),
                category: PatternCategory::Metadata,
                risk_level: RiskLevel::Low,
                context: vec![PatternContext::Global],
                false_positive_rate: 0.01,
                version: "1.0".into(),
                updated_at: chrono::Utc::now(),
                metadata: HashMap::new(),
            },
            // JavaScript patterns
            Pattern {
                id: "PAT002".into(),
                name: "JavaScript Execution".into(),
                description: "JavaScript code execution detection".into(),
                regex: r"(?i)/JS\s*<<.*?>>".into(),
                category: PatternCategory::JavaScript,
                risk_level: RiskLevel::High,
                context: vec![PatternContext::Stream],
                false_positive_rate: 0.001,
                version: "1.0".into(),
                updated_at: chrono::Utc::now(),
                metadata: HashMap::new(),
            },
            // Structure patterns
            Pattern {
                id: "PAT003".into(),
                name: "Hidden Content".into(),
                description: "Hidden or invisible content detection".into(),
                regex: r"/Type\s*/Annot.*?/F\s*\d+".into(),
                category: PatternCategory::Structure,
                risk_level: RiskLevel::Medium,
                context: vec![PatternContext::Object("Annot".into())],
                false_positive_rate: 0.05,
                version: "1.0".into(),
                updated_at: chrono::Utc::now(),
                metadata: HashMap::new(),
            },
        ];

        // Load custom patterns if provided
        if let Some(custom_rules) = &config.custom_rules {
            let custom_patterns: Vec<Pattern> = serde_yaml::from_str(custom_rules)
                .map_err(|e| PdfError::Config(format!("Invalid custom patterns: {}", e)))?;
            patterns.extend(custom_patterns);
        }

        // Compile regular expressions
        patterns.into_iter()
            .map(|p| {
                let regex = Regex::new(&p.regex)
                    .map_err(|e| PdfError::Pattern(format!("Invalid pattern {}: {}", p.id, e)))?;
                Ok((p, regex))
            })
            .collect::<Result<Vec<_>, PdfError>>()
    }

    /// Extracts unique pattern categories
    fn extract_categories(patterns: &[(Pattern, Regex)]) -> HashSet<PatternCategory> {
        patterns.iter()
            .map(|(p, _)| p.category.clone())
            .collect()
    }

    /// Analyzes document content with patterns
    async fn analyze_with_patterns(
        &self,
        doc: &Document,
        scan_result: &ScanResult,
    ) -> Result<Vec<ForensicArtifact>, PdfError> {
        let mut artifacts = Vec::new();
        let content = doc.get_content()?;

        for (pattern, regex) in self.patterns.iter() {
            trace!("Applying pattern: {}", pattern.id);
            
            for capture in regex.captures_iter(&content) {
                let location = capture[0].to_string();
                
                // Skip if context doesn't match
                if !self.validate_context(doc, &pattern.context, &location)? {
                    continue;
                }

                artifacts.push(ForensicArtifact {
                    id: uuid::Uuid::new_v4().to_string(),
                    artifact_type: match pattern.category {
                        PatternCategory::Metadata => ArtifactType::Metadata,
                        PatternCategory::JavaScript => ArtifactType::JavaScript,
                        PatternCategory::Binary => ArtifactType::Binary,
                        _ => ArtifactType::Custom(pattern.category.to_string()),
                    },
                    location,
                    description: pattern.description.clone(),
                    risk_level: pattern.risk_level,
                    remediation: format!("Remove or sanitize the detected pattern: {}", pattern.name),
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("pattern_id".into(), pattern.id.clone());
                        m.insert("pattern_version".into(), pattern.version.clone());
                        m.extend(pattern.metadata.clone());
                        m
                    },
                    detection_timestamp: chrono::Utc::now(),
                    hash: self.calculate_artifact_hash(&capture[0]),
                });
            }
        }

        Ok(artifacts)
    }

    /// Validates pattern context against document
    fn validate_context(
        &self,
        doc: &Document,
        contexts: &[PatternContext],
        location: &str,
    ) -> Result<bool, PdfError> {
        for context in contexts {
            match context {
                PatternContext::Global => return Ok(true),
                PatternContext::Object(obj_type) => {
                    if !doc.has_object_type(obj_type, location)? {
                        return Ok(false);
                    }
                },
                PatternContext::Stream => {
                    if !doc.is_in_stream(location)? {
                        return Ok(false);
                    }
                },
                PatternContext::Resource(res_type) => {
                    if !doc.has_resource_type(res_type, location)? {
                        return Ok(false);
                    }
                },
            }
        }
        Ok(true)
    }

    /// Calculates hash for forensic artifacts
    fn calculate_artifact_hash(&self, content: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[async_trait]
impl Analyzer for PatternAnalyzer {
    #[instrument(skip(self, doc, scan_result), err(Display))]
    async fn analyze(&self, doc: &Document, scan_result: &ScanResult) -> Result<AnalysisResult, PdfError> {
        let start_time = Instant::now();
        
        // Check cache first
        let cache_key = self.base.generate_cache_key(doc);
        if let Some(cached_result) = self.base.cache.write().await.get(&cache_key) {
            debug!("Cache hit for pattern analysis");
            return Ok(cached_result);
        }

        debug!("Starting pattern analysis");
        let artifacts = self.analyze_with_patterns(doc, scan_result).await?;

        let duration = start_time.elapsed();
        let result = AnalysisResult {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            risk_level: self.calculate_risk_level(&artifacts),
            artifacts,
            recommendations: self.generate_recommendations(),
            duration,
            metadata: {
                let mut m = HashMap::new();
                m.insert("analyzer_version".into(), env!("CARGO_PKG_VERSION").into());
                m.insert("patterns_analyzed".into(), self.patterns.len().to_string());
                m.insert("last_pattern_update".into(), 
                    self.last_update.read().await.to_rfc3339());
                m
            },
            confidence: 1.0 - self.patterns.iter()
                .map(|(p, _)| p.false_positive_rate)
                .sum::<f64>() / self.patterns.len() as f64,
        };

        // Cache the result
        self.base.cache.write().await.put(
            cache_key,
            result.clone(),
            Duration::from_secs(3600)
        );

        // Update metrics
        self.base.update_metrics(duration, true).await;

        Ok(result)
    }

    async fn get_metrics(&self) -> AnalyzerMetrics {
        self.base.metrics.read().await.clone()
    }

    fn validate_result(&self, result: &AnalysisResult) -> bool {
        result.confidence >= self.base.config.min_confidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_pattern_analyzer_creation() {
        let config = AnalyzerConfig::default();
        let analyzer = PatternAnalyzer::new(config).await;
        assert!(analyzer.is_ok());
    }

    #[test]
    async fn test_custom_pattern_loading() {
        let config = AnalyzerConfig {
            custom_rules: Some(r#"
                - id: "CUSTOM001"
                  name: "Custom Pattern"
                  description: "Custom pattern test"
                  regex: "test"
                  category: "Custom"
                  risk_level: "High"
                  context: ["Global"]
                  false_positive_rate: 0.1
                  version: "1.0"
                  updated_at: "2025-06-03T06:43:59Z"
                  metadata: {}
            "#.into()),
            ..AnalyzerConfig::default()
        };

        let analyzer = PatternAnalyzer::new(config).await.unwrap();
        assert!(analyzer.patterns.len() > 3); // Base patterns + custom pattern
    }

    #[test]
    async fn test_pattern_context_validation() {
        let analyzer = PatternAnalyzer::new(AnalyzerConfig::default()).await.unwrap();
        let doc = Document::new(); // Mock document
        
        assert!(analyzer.validate_context(
            &doc,
            &[PatternContext::Global],
            "test"
        ).unwrap());
    }

    #[test]
    async fn test_artifact_generation() {
        let analyzer = PatternAnalyzer::new(AnalyzerConfig::default()).await.unwrap();
        let doc = Document::new(); // Mock document with JavaScript content
        doc.set_content("/JS << /S /JavaScript /JS (alert(1)) >>").unwrap();
        
        let scan_result = ScanResult::default();
        let artifacts = analyzer.analyze_with_patterns(&doc, &scan_result).await.unwrap();
        
        assert!(!artifacts.is_empty());
        assert_eq!(artifacts[0].artifact_type, ArtifactType::JavaScript);
    }
}
