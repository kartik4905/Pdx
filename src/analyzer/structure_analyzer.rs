//! Structure analyser for PDF document analysis
//! Author: kartik4091
//! Created: 2025-06-03 04:40:35 UTC
//! This module provides document structure analysis capabilities,
//! including dictionary, array, and tree structure analysis.

use std::{
    sync::Arc,
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};
use async_trait::async_trait;
use tracing::{info, warn, error, debug, trace, instrument};

use super::AnalyserConfig;
use crate::antiforensics::{
    Document,
    PdfError,
    RiskLevel,
    ForensicArtifact,
    ArtifactType,
};

/// Structure analyser implementation
pub struct StructureAnalyser {
    /// Analyser configuration
    config: Arc<AnalyserConfig>,
    /// Known risky dictionary keys
    risky_keys: HashSet<String>,
    /// Known safe object types
    safe_types: HashSet<String>,
}

/// Structure analysis context
#[derive(Debug)]
struct AnalysisContext {
    /// Memory usage in bytes
    memory_usage: usize,
    /// Analysis depth
    depth: usize,
    /// Processed objects
    processed_objects: HashSet<String>,
    /// Object references
    references: HashMap<String, Vec<String>>,
    /// Circular references
    circular_refs: Vec<Vec<String>>,
}

/// Structure analysis finding
#[derive(Debug)]
struct StructureFinding {
    /// Finding identifier
    id: String,
    /// Finding description
    description: String,
    /// Risk level
    risk_level: RiskLevel,
    /// Object path
    path: Vec<String>,
    /// Related objects
    related_objects: Vec<String>,
}

impl StructureAnalyser {
    /// Creates a new structure analyser instance
    #[instrument(skip(config))]
    pub fn new(config: AnalyserConfig) -> Self {
        debug!("Initializing StructureAnalyser");

        let mut analyser = Self {
            config: Arc::new(config),
            risky_keys: HashSet::new(),
            safe_types: HashSet::new(),
        };

        analyser.initialize_risky_keys();
        analyser.initialize_safe_types();

        analyser
    }

    /// Initializes set of risky dictionary keys
    fn initialize_risky_keys(&mut self) {
        let risky_keys = [
            "JavaScript", "JS", "Launch", "SubmitForm", "ImportData",
            "GoTo", "GoToR", "GoToE", "URI", "AA", "OpenAction",
            "RichMedia", "Movie", "Sound", "Rendition", "Trans",
        ];

        self.risky_keys.extend(risky_keys.iter().map(|&s| s.to_string()));
    }

    /// Initializes set of safe object types
    fn initialize_safe_types(&mut self) {
        let safe_types = [
            "Font", "XObject", "ExtGState", "ColorSpace",
            "Pattern", "Shading", "Properties", "Metadata",
        ];

        self.safe_types.extend(safe_types.iter().map(|&s| s.to_string()));
    }

    /// Analyzes document structure
    #[instrument(skip(self, doc), err(Display))]
    pub async fn analyze(&self, doc: &Document) -> Result<Vec<ForensicArtifact>, PdfError> {
        let mut context = AnalysisContext {
            memory_usage: 0,
            depth: 0,
            processed_objects: HashSet::new(),
            references: HashMap::new(),
            circular_refs: Vec::new(),
        };

        let mut findings = Vec::new();

        // Analyze catalog dictionary
        if let Some(catalog) = doc.get_catalog()? {
            findings.extend(self.analyze_dictionary(catalog, &mut context).await?);
        }

        // Analyze page tree
        if let Some(page_tree) = doc.get_page_tree()? {
            findings.extend(self.analyze_page_tree(page_tree, &mut context).await?);
        }

        // Analyze name trees
        if let Some(names) = doc.get_names()? {
            findings.extend(self.analyze_name_trees(names, &mut context).await?);
        }

        // Analyze structure tree
        if let Some(struct_tree) = doc.get_structure_tree()? {
            findings.extend(self.analyze_structure_tree(struct_tree, &mut context).await?);
        }

        // Detect circular references
        self.detect_circular_references(&mut context);

        // Convert findings to artifacts
        Ok(self.create_artifacts(findings, &context))
    }

    /// Analyzes a dictionary object
    async fn analyze_dictionary(
        &self,
        dict: &Dictionary,
        context: &mut AnalysisContext,
    ) -> Result<Vec<StructureFinding>, PdfError> {
        let mut findings = Vec::new();
        
        // Check recursion depth
        context.depth += 1;
        if context.depth > self.config.max_memory_per_analysis {
            warn!("Maximum recursion depth exceeded");
            return Ok(findings);
        }

        // Analyze dictionary entries
        for (key, value) in dict.iter() {
            // Check for risky keys
            if self.risky_keys.contains(key) {
                findings.push(StructureFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    description: format!("Potentially risky key '{}' found", key),
                    risk_level: RiskLevel::High,
                    path: vec![key.clone()],
                    related_objects: vec![],
                });
            }

            // Track references
            if let Some(ref_id) = value.as_reference() {
                context.references
                    .entry(dict.get_id()?.to_string())
                    .or_default()
                    .push(ref_id.to_string());
            }

            // Recursively analyze nested dictionaries
            match value {
                PdfObject::Dictionary(d) => {
                    findings.extend(self.analyze_dictionary(d, context).await?);
                }
                PdfObject::Array(a) => {
                    findings.extend(self.analyze_array(a, context).await?);
                }
                _ => {}
            }
        }

        context.depth -= 1;
        Ok(findings)
    }

    /// Analyzes an array object
    async fn analyze_array(
        &self,
        array: &[PdfObject],
        context: &mut AnalysisContext,
    ) -> Result<Vec<StructureFinding>, PdfError> {
        let mut findings = Vec::new();

        // Check recursion depth
        context.depth += 1;
        if context.depth > self.config.max_memory_per_analysis {
            warn!("Maximum recursion depth exceeded");
            return Ok(findings);
        }

        // Analyze array elements
        for (index, value) in array.iter().enumerate() {
            // Track references
            if let Some(ref_id) = value.as_reference() {
                context.references
                    .entry(format!("array_{}", index))
                    .or_default()
                    .push(ref_id.to_string());
            }

            // Recursively analyze nested objects
            match value {
                PdfObject::Dictionary(d) => {
                    findings.extend(self.analyze_dictionary(d, context).await?);
                }
                PdfObject::Array(a) => {
                    findings.extend(self.analyze_array(a, context).await?);
                }
                _ => {}
            }
        }

        context.depth -= 1;
        Ok(findings)
    }

    /// Analyzes page tree structure
    async fn analyze_page_tree(
        &self,
        tree: &PageTree,
        context: &mut AnalysisContext,
    ) -> Result<Vec<StructureFinding>, PdfError> {
        let mut findings = Vec::new();

        // Check for unusual page tree structures
        if tree.get_depth()? > 10 {
            findings.push(StructureFinding {
                id: uuid::Uuid::new_v4().to_string(),
                description: "Unusually deep page tree structure detected".into(),
                risk_level: RiskLevel::Medium,
                path: vec!["Pages".into()],
                related_objects: vec![],
            });
        }

        // Analyze page objects
        for page in tree.get_pages() {
            findings.extend(self.analyze_dictionary(page.get_dictionary()?, context).await?);
        }

        Ok(findings)
    }

    /// Analyzes name trees
    async fn analyze_name_trees(
        &self,
        names: &Names,
        context: &mut AnalysisContext,
    ) -> Result<Vec<StructureFinding>, PdfError> {
        let mut findings = Vec::new();

        // Check for JavaScript name tree
        if let Some(js_names) = names.get_javascript()? {
            findings.push(StructureFinding {
                id: uuid::Uuid::new_v4().to_string(),
                description: "JavaScript name tree found".into(),
                risk_level: RiskLevel::High,
                path: vec!["Names".into(), "JavaScript".into()],
                related_objects: js_names.get_keys()?,
            });
        }

        // Check for embedded files
        if let Some(ef_names) = names.get_embedded_files()? {
            findings.push(StructureFinding {
                id: uuid::Uuid::new_v4().to_string(),
                description: "Embedded files name tree found".into(),
                risk_level: RiskLevel::Medium,
                path: vec!["Names".into(), "EmbeddedFiles".into()],
                related_objects: ef_names.get_keys()?,
            });
        }

        Ok(findings)
    }

    /// Analyzes structure tree
    async fn analyze_structure_tree(
        &self,
        tree: &StructureTree,
        context: &mut AnalysisContext,
    ) -> Result<Vec<StructureFinding>, PdfError> {
        let mut findings = Vec::new();

        // Check for unusual structure types
        for element in tree.get_elements() {
            if !self.safe_types.contains(&element.get_type()?) {
                findings.push(StructureFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    description: format!("Unusual structure element type '{}' found", element.get_type()?),
                    risk_level: RiskLevel::Low,
                    path: vec!["StructTreeRoot".into()],
                    related_objects: vec![element.get_id()?],
                });
            }
        }

        Ok(findings)
    }

    /// Detects circular references in the document structure
    fn detect_circular_references(&self, context: &mut AnalysisContext) {
        for start_obj in context.references.keys() {
            let mut visited = HashSet::new();
            let mut path = Vec::new();
            let mut queue = VecDeque::new();

            queue.push_back(start_obj.clone());
            path.push(start_obj.clone());

            while let Some(current) = queue.pop_front() {
                if let Some(refs) = context.references.get(&current) {
                    for next in refs {
                        if !visited.insert(next.clone()) {
                            // Found circular reference
                            if let Some(cycle_start) = path.iter().position(|x| x == next) {
                                let cycle = path[cycle_start..].to_vec();
                                if !context.circular_refs.contains(&cycle) {
                                    context.circular_refs.push(cycle);
                                }
                            }
                        } else {
                            queue.push_back(next.clone());
                            path.push(next.clone());
                        }
                    }
                }
            }
        }
    }

    /// Creates forensic artifacts from structure findings
    fn create_artifacts(
        &self,
        findings: Vec<StructureFinding>,
        context: &AnalysisContext,
    ) -> Vec<ForensicArtifact> {
        let mut artifacts = Vec::new();

        // Convert findings to artifacts
        for finding in findings {
            let mut metadata = HashMap::new();
            metadata.insert("path".into(), finding.path.join("/"));
            metadata.insert("related_objects".into(), finding.related_objects.join(","));

            artifacts.push(ForensicArtifact {
                id: finding.id,
                artifact_type: ArtifactType::Structure,
                location: finding.path.join("/"),
                description: finding.description,
                risk_level: finding.risk_level,
                remediation: self.generate_remediation(&finding),
                metadata,
                detection_timestamp: chrono::Utc::now(),
                hash: self.calculate_hash(&finding.path.join("/")),
            });
        }

        // Add circular reference artifacts
        for cycle in &context.circular_refs {
            let mut metadata = HashMap::new();
            metadata.insert("cycle".into(), cycle.join(" -> "));

            artifacts.push(ForensicArtifact {
                id: uuid::Uuid::new_v4().to_string(),
                artifact_type: ArtifactType::Structure,
                location: "circular_reference".into(),
                description: "Circular reference detected in document structure".into(),
                risk_level: RiskLevel::High,
                remediation: "Review and break circular references in document structure".into(),
                metadata,
                detection_timestamp: chrono::Utc::now(),
                hash: self.calculate_hash(&cycle.join("")),
            });
        }

        artifacts
    }

    /// Generates remediation advice for a finding
    fn generate_remediation(&self, finding: &StructureFinding) -> String {
        match finding.risk_level {
            RiskLevel::Critical | RiskLevel::High => {
                format!(
                    "Remove or disable potentially malicious content at {}",
                    finding.path.join("/")
                )
            }
            RiskLevel::Medium => {
                format!(
                    "Review and validate structure at {} for potential risks",
                    finding.path.join("/")
                )
            }
            RiskLevel::Low => {
                format!(
                    "Consider cleaning or simplifying structure at {}",
                    finding.path.join("/")
                )
            }
        }
    }

    /// Calculates hash of a value
    fn calculate_hash(&self, value: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_risky_key_detection() {
        let analyser = StructureAnalyser::new(AnalyserConfig::default());
        let mut dict = Dictionary::new();
        dict.insert("JavaScript", PdfObject::String("alert()".into()));
        
        let mut context = AnalysisContext {
            memory_usage: 0,
            depth: 0,
            processed_objects: HashSet::new(),
            references: HashMap::new(),
            circular_refs: Vec::new(),
        };

        let findings = analyser.analyze_dictionary(&dict, &mut context).await.unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].risk_level, RiskLevel::High);
    }

    #[test]
    async fn test_circular_reference_detection() {
        let analyser = StructureAnalyser::new(AnalyserConfig::default());
        let mut context = AnalysisContext {
            memory_usage: 0,
            depth: 0,
            processed_objects: HashSet::new(),
            references: HashMap::new(),
            circular_refs: Vec::new(),
        };

        // Create circular reference
        context.references.insert("obj1".into(), vec!["obj2".into()]);
        context.references.insert("obj2".into(), vec!["obj3".into()]);
        context.references.insert("obj3".into(), vec!["obj1".into()]);

        analyser.detect_circular_references(&mut context);
        assert!(!context.circular_refs.is_empty());
    }

    #[test]
    async fn test_structure_tree_analysis() {
        let analyser = StructureAnalyser::new(AnalyserConfig::default());
        let mut tree = StructureTree::new();
        tree.add_element(StructureElement::new("CustomType"));
        
        let mut context = AnalysisContext {
            memory_usage: 0,
            depth: 0,
            processed_objects: HashSet::new(),
            references: HashMap::new(),
            circular_refs: Vec::new(),
        };

        let findings = analyser.analyze_structure_tree(&tree, &mut context).await.unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].risk_level, RiskLevel::Low);
    }

    #[test]
    async fn test_name_tree_analysis() {
        let analyser = StructureAnalyser::new(AnalyserConfig::default());
        let mut names = Names::new();
        names.add_javascript("test", "alert()");
        
        let mut context = AnalysisContext {
            memory_usage: 0,
            depth: 0,
            processed_objects: HashSet::new(),
            references: HashMap::new(),
            circular_refs: Vec::new(),
        };

        let findings = analyser.analyze_name_trees(&names, &mut context).await.unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].risk_level, RiskLevel::High);
    }
          }
