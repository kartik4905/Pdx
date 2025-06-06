//! Threat analyser for PDF document analysis
//! Author: kartik4091
//! Created: 2025-06-03 04:42:17 UTC
//! This module provides threat analysis capabilities for PDF documents,
//! including threat detection, risk assessment, and CVSS scoring.

use std::{
    sync::Arc,
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use tracing::{info, warn, error, debug, trace, instrument};

use super::{AnalyserConfig, ThreatInfo};
use crate::antiforensics::{
    Document,
    PdfError,
    RiskLevel,
    ForensicArtifact,
    ArtifactType,
};

/// Threat analyser implementation
pub struct ThreatAnalyser {
    /// Analyser configuration
    config: Arc<AnalyserConfig>,
    /// Known threat patterns
    threat_patterns: Vec<ThreatPattern>,
    /// CVSS calculator
    cvss_calculator: CvssCalculator,
}

/// Threat pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ThreatPattern {
    /// Pattern identifier
    id: String,
    /// Pattern name
    name: String,
    /// Pattern description
    description: String,
    /// Required artifact types
    required_artifacts: Vec<ArtifactType>,
    /// Required risk levels
    required_risk_levels: Vec<RiskLevel>,
    /// CVSS vector string
    cvss_vector: String,
    /// Detection confidence threshold
    confidence_threshold: f32,
}

/// CVSS calculator
struct CvssCalculator {
    /// Base metrics
    base_metrics: HashMap<String, f32>,
    /// Temporal metrics
    temporal_metrics: HashMap<String, f32>,
    /// Environmental metrics
    environmental_metrics: HashMap<String, f32>,
}

impl ThreatAnalyser {
    /// Creates a new threat analyser instance
    #[instrument(skip(config))]
    pub fn new(config: AnalyserConfig) -> Self {
        debug!("Initializing ThreatAnalyser");

        Self {
            config: Arc::new(config),
            threat_patterns: Self::load_threat_patterns(),
            cvss_calculator: CvssCalculator::new(),
        }
    }

    /// Loads threat pattern definitions
    fn load_threat_patterns() -> Vec<ThreatPattern> {
        vec![
            ThreatPattern {
                id: "THREAT-001".into(),
                name: "JavaScript Execution".into(),
                description: "Document contains potentially malicious JavaScript code".into(),
                required_artifacts: vec![ArtifactType::JavaScript],
                required_risk_levels: vec![RiskLevel::High, RiskLevel::Critical],
                cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H".into(),
                confidence_threshold: 0.8,
            },
            ThreatPattern {
                id: "THREAT-002".into(),
                name: "Data Exfiltration".into(),
                description: "Document contains mechanisms for data exfiltration".into(),
                required_artifacts: vec![ArtifactType::Content, ArtifactType::JavaScript],
                required_risk_levels: vec![RiskLevel::High],
                cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N".into(),
                confidence_threshold: 0.7,
            },
            ThreatPattern {
                id: "THREAT-003".into(),
                name: "Remote Code Execution".into(),
                description: "Document contains potential remote code execution vectors".into(),
                required_artifacts: vec![ArtifactType::Structure, ArtifactType::JavaScript],
                required_risk_levels: vec![RiskLevel::Critical],
                cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H".into(),
                confidence_threshold: 0.9,
            },
        ]
    }

    /// Analyzes threats in a document
    #[instrument(skip(self, doc, artifacts), err(Display))]
    pub async fn analyze(
        &self,
        doc: &Document,
        artifacts: &[ForensicArtifact],
    ) -> Result<Vec<ThreatInfo>, PdfError> {
        let mut threats = Vec::new();
        
        // Group artifacts by type
        let mut artifact_groups: HashMap<ArtifactType, Vec<&ForensicArtifact>> = HashMap::new();
        for artifact in artifacts {
            artifact_groups
                .entry(artifact.artifact_type.clone())
                .or_default()
                .push(artifact);
        }

        // Analyze each threat pattern
        for pattern in &self.threat_patterns {
            if let Some(threat) = self.analyze_pattern(pattern, &artifact_groups).await? {
                threats.push(threat);
            }
        }

        // Correlate threats
        self.correlate_threats(&mut threats);

        Ok(threats)
    }

    /// Analyzes a specific threat pattern
    async fn analyze_pattern(
        &self,
        pattern: &ThreatPattern,
        artifact_groups: &HashMap<ArtifactType, Vec<&ForensicArtifact>>,
    ) -> Result<Option<ThreatInfo>, PdfError> {
        // Check if required artifact types are present
        for required_type in &pattern.required_artifacts {
            if !artifact_groups.contains_key(required_type) {
                return Ok(None);
            }
        }

        // Calculate confidence score
        let mut confidence = 0.0;
        let mut related_artifacts = Vec::new();

        for (artifact_type, artifacts) in artifact_groups {
            if pattern.required_artifacts.contains(artifact_type) {
                for artifact in artifacts {
                    if pattern.required_risk_levels.contains(&artifact.risk_level) {
                        confidence += 1.0;
                        related_artifacts.push(artifact.id.clone());
                    }
                }
            }
        }

        // Normalize confidence score
        confidence /= pattern.required_artifacts.len() as f32;

        // Check confidence threshold
        if confidence >= pattern.confidence_threshold {
            // Calculate CVSS score
            let cvss_score = self.cvss_calculator.calculate_score(&pattern.cvss_vector)?;

            Ok(Some(ThreatInfo {
                id: uuid::Uuid::new_v4().to_string(),
                name: pattern.name.clone(),
                description: pattern.description.clone(),
                risk_level: self.determine_risk_level(cvss_score),
                cvss_score: Some(cvss_score),
                related_artifacts,
                confidence,
            }))
        } else {
            Ok(None)
        }
    }

    /// Correlates detected threats
    fn correlate_threats(&self, threats: &mut Vec<ThreatInfo>) {
        // Build artifact relationship map
        let mut artifact_relations: HashMap<String, HashSet<String>> = HashMap::new();
        
        for threat in threats.iter() {
            for artifact_id in &threat.related_artifacts {
                for other_id in &threat.related_artifacts {
                    if artifact_id != other_id {
                        artifact_relations
                            .entry(artifact_id.clone())
                            .or_default()
                            .insert(other_id.clone());
                    }
                }
            }
        }

        // Adjust threat confidence based on relationships
        for threat in threats.iter_mut() {
            let mut relationship_score = 0.0;
            let mut total_relationships = 0;

            for artifact_id in &threat.related_artifacts {
                if let Some(relations) = artifact_relations.get(artifact_id) {
                    relationship_score += relations.len() as f32;
                    total_relationships += 1;
                }
            }

            if total_relationships > 0 {
                // Adjust confidence based on relationship density
                let relationship_factor = relationship_score / (total_relationships as f32);
                threat.confidence = (threat.confidence + relationship_factor) / 2.0;
            }
        }

        // Sort threats by confidence and risk level
        threats.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap()
                .then(b.risk_level.cmp(&a.risk_level))
        });
    }

    /// Determines risk level based on CVSS score
    fn determine_risk_level(&self, cvss_score: f32) -> RiskLevel {
        match cvss_score {
            score if score >= 9.0 => RiskLevel::Critical,
            score if score >= 7.0 => RiskLevel::High,
            score if score >= 4.0 => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }
}

impl CvssCalculator {
    /// Creates a new CVSS calculator
    fn new() -> Self {
        let mut calc = Self {
            base_metrics: HashMap::new(),
            temporal_metrics: HashMap::new(),
            environmental_metrics: HashMap::new(),
        };

        calc.initialize_metrics();
        calc
    }

    /// Initializes CVSS metrics
    fn initialize_metrics(&mut self) {
        // Base metrics
        self.base_metrics.insert("AV:N".into(), 0.85);
        self.base_metrics.insert("AV:A".into(), 0.62);
        self.base_metrics.insert("AV:L".into(), 0.55);
        self.base_metrics.insert("AV:P".into(), 0.2);

        self.base_metrics.insert("AC:L".into(), 0.77);
        self.base_metrics.insert("AC:H".into(), 0.44);

        self.base_metrics.insert("PR:N".into(), 0.85);
        self.base_metrics.insert("PR:L".into(), 0.62);
        self.base_metrics.insert("PR:H".into(), 0.27);

        // Temporal metrics
        self.temporal_metrics.insert("E:U".into(), 0.91);
        self.temporal_metrics.insert("E:P".into(), 0.94);
        self.temporal_metrics.insert("E:F".into(), 1.0);

        self.temporal_metrics.insert("RL:O".into(), 0.95);
        self.temporal_metrics.insert("RL:T".into(), 0.96);
        self.temporal_metrics.insert("RL:W".into(), 0.97);
        self.temporal_metrics.insert("RL:U".into(), 1.0);

        // Environmental metrics
        self.environmental_metrics.insert("CR:L".into(), 0.5);
        self.environmental_metrics.insert("CR:M".into(), 1.0);
        self.environmental_metrics.insert("CR:H".into(), 1.5);

        self.environmental_metrics.insert("IR:L".into(), 0.5);
        self.environmental_metrics.insert("IR:M".into(), 1.0);
        self.environmental_metrics.insert("IR:H".into(), 1.5);
    }

    /// Calculates CVSS score from vector string
    fn calculate_score(&self, vector: &str) -> Result<f32, PdfError> {
        let mut score = 0.0;
        let metrics: Vec<&str> = vector.split('/').collect();

        for metric in metrics {
            if let Some(value) = self.base_metrics.get(metric) {
                score += value;
            }
            if let Some(value) = self.temporal_metrics.get(metric) {
                score *= value;
            }
            if let Some(value) = self.environmental_metrics.get(metric) {
                score *= value;
            }
        }

        // Normalize score to 0-10 range
        Ok((score * 10.0).min(10.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_threat_pattern_detection() {
        let analyser = ThreatAnalyser::new(AnalyserConfig::default());
        
        let artifacts = vec![
            ForensicArtifact {
                artifact_type: ArtifactType::JavaScript,
                risk_level: RiskLevel::Critical,
                ..Default::default()
            },
        ];

        let mut artifact_groups = HashMap::new();
        artifact_groups.insert(ArtifactType::JavaScript, vec![&artifacts[0]]);

        let pattern = &analyser.threat_patterns[0];
        let threat = analyser.analyze_pattern(pattern, &artifact_groups).await.unwrap();
        
        assert!(threat.is_some());
        assert_eq!(threat.unwrap().risk_level, RiskLevel::Critical);
    }

    #[test]
    async fn test_threat_correlation() {
        let analyser = ThreatAnalyser::new(AnalyserConfig::default());
        
        let mut threats = vec![
            ThreatInfo {
                id: "1".into(),
                name: "Threat 1".into(),
                description: "Test threat 1".into(),
                risk_level: RiskLevel::High,
                cvss_score: Some(8.0),
                related_artifacts: vec!["a1".into(), "a2".into()],
                confidence: 0.8,
            },
            ThreatInfo {
                id: "2".into(),
                name: "Threat 2".into(),
                description: "Test threat 2".into(),
                risk_level: RiskLevel::High,
                cvss_score: Some(8.0),
                related_artifacts: vec!["a2".into(), "a3".into()],
                confidence: 0.7,
            },
        ];

        analyser.correlate_threats(&mut threats);
        assert!(threats[0].confidence > threats[1].confidence);
    }

    #[test]
    async fn test_cvss_calculation() {
        let calculator = CvssCalculator::new();
        
        let score = calculator
            .calculate_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
            .unwrap();
            
        assert!(score > 0.0);
        assert!(score <= 10.0);
    }

    #[test]
    async fn test_risk_level_determination() {
        let analyser = ThreatAnalyser::new(AnalyserConfig::default());
        
        assert_eq!(analyser.determine_risk_level(9.5), RiskLevel::Critical);
        assert_eq!(analyser.determine_risk_level(7.5), RiskLevel::High);
        assert_eq!(analyser.determine_risk_level(5.0), RiskLevel::Medium);
        assert_eq!(analyser.determine_risk_level(2.0), RiskLevel::Low);
    }
          }
