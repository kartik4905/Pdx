
//! Stage 1: Deep Structure Analysis
//! Normalizes PDF structure, validates XRef tables, detects anomalies
//! Author: kartik4091

use crate::{
    types::{Document, ProcessingResult},
    error::{Result, PipelineError},
    structure::{StructureHandler, CrossRefHandler, LinearizationHandler},
    utils::{Logger, Metrics},
};
use async_trait::async_trait;
use tracing::{info, warn, instrument};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage1Result {
    pub success: bool,
    pub structure_normalized: bool,
    pub xref_repaired: bool,
    pub linearization_handled: bool,
    pub ghost_objects_detected: usize,
    pub dangling_references: usize,
    pub anomalies_fixed: usize,
    pub issues: Vec<Stage1Issue>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage1Issue {
    pub severity: IssueSeverity,
    pub description: String,
    pub remediation: Option<String>,
    pub object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[async_trait]
pub trait Stage1Processor {
    async fn execute(&self, document: &mut Document) -> Result<Stage1Result>;
}

#[derive(Debug)]
pub struct Stage1ProcessorImpl {
    structure_handler: StructureHandler,
    xref_handler: CrossRefHandler,
    linearization_handler: LinearizationHandler,
    logger: Logger,
    metrics: Metrics,
}

impl Stage1ProcessorImpl {
    pub fn new() -> Self {
        Self {
            structure_handler: StructureHandler::new(),
            xref_handler: CrossRefHandler::new(),
            linearization_handler: LinearizationHandler::new(),
            logger: Logger::default(),
            metrics: Metrics::new(),
        }
    }

    async fn normalize_pdf_structure(&self, document: &mut Document, result: &mut Stage1Result) -> Result<()> {
        info!("Normalizing PDF structure and trailer");
        
        // Normalize trailer dictionary
        self.normalize_trailer(document)?;
        
        // Fix startxref positioning
        self.fix_startxref_positioning(document)?;
        
        // Validate and normalize EOF markers
        self.normalize_eof_markers(document)?;
        
        result.structure_normalized = true;
        Ok(())
    }

    fn normalize_trailer(&self, document: &mut Document) -> Result<()> {
        // Remove auto-generated trailer entries
        let mut trailer = document.structure.trailer.clone();
        
        // Remove /Info if empty or auto-generated
        if let Some(info_ref) = trailer.get(b"Info") {
            if self.is_auto_generated_info(document, info_ref)? {
                trailer.remove(b"Info");
            }
        }
        
        // Remove /ID if user hasn't explicitly set it
        if !document.metadata.user_specified_id {
            trailer.remove(b"ID");
        }
        
        // Ensure required entries are present
        if !trailer.has(b"Size") {
            return Err(PipelineError::StructureError("Missing required /Size in trailer".to_string()).into());
        }
        
        document.structure.trailer = trailer;
        Ok(())
    }

    fn fix_startxref_positioning(&self, document: &mut Document) -> Result<()> {
        // Validate startxref points to valid XRef table
        let startxref_offset = document.structure.startxref_offset;
        
        if startxref_offset >= document.content.len() {
            return Err(PipelineError::StructureError("Invalid startxref offset".to_string()).into());
        }
        
        // Verify XRef table at startxref position
        let xref_data = &document.content[startxref_offset..];
        if !xref_data.starts_with(b"xref") {
            // Fix startxref to point to actual XRef table
            if let Some(xref_pos) = self.find_xref_table(&document.content)? {
                document.structure.startxref_offset = xref_pos;
            } else {
                return Err(PipelineError::StructureError("No valid XRef table found".to_string()).into());
            }
        }
        
        Ok(())
    }

    fn normalize_eof_markers(&self, document: &mut Document) -> Result<()> {
        // Count EOF markers
        let eof_count = document.content.windows(6).filter(|w| w == b"%%EOF\n" || w == b"%%EOF\r").count();
        
        if eof_count != 1 {
            // Remove all EOF markers and add exactly one at the end
            let mut content = document.content.clone();
            
            // Remove existing EOF markers
            content = content.replace(b"%%EOF\n", b"");
            content = content.replace(b"%%EOF\r", b"");
            content = content.replace(b"%%EOF", b"");
            
            // Add single EOF at end
            content.extend_from_slice(b"\n%%EOF\n");
            document.content = content;
        }
        
        Ok(())
    }

    async fn validate_and_repair_xref(&self, document: &mut Document, result: &mut Stage1Result) -> Result<()> {
        info!("Validating and repairing cross-reference table");
        
        let repair_result = self.xref_handler.validate_and_repair(document).await?;
        
        if repair_result.repairs_made > 0 {
            result.issues.push(Stage1Issue {
                severity: IssueSeverity::Medium,
                description: format!("XRef table repaired: {} entries fixed", repair_result.repairs_made),
                remediation: Some("Cross-reference table has been rebuilt".to_string()),
                object_id: None,
            });
        }
        
        result.xref_repaired = repair_result.repairs_made > 0;
        Ok(())
    }

    async fn handle_linearization(&self, document: &mut Document, result: &mut Stage1Result) -> Result<()> {
        info!("Processing linearization hints");
        
        if document.structure.is_linearized {
            // Remove linearization if user hasn't explicitly requested it
            if !document.config.preserve_linearization {
                self.linearization_handler.remove_linearization(document).await?;
                result.issues.push(Stage1Issue {
                    severity: IssueSeverity::Low,
                    description: "Linearization removed for security".to_string(),
                    remediation: Some("Document is no longer web-optimized".to_string()),
                    object_id: None,
                });
            }
        }
        
        result.linearization_handled = true;
        Ok(())
    }

    async fn detect_anomalies(&self, document: &mut Document, result: &mut Stage1Result) -> Result<()> {
        info!("Detecting structural anomalies");
        
        // Detect ghost objects
        let ghost_objects = self.detect_ghost_objects(document)?;
        result.ghost_objects_detected = ghost_objects.len();
        
        for ghost in &ghost_objects {
            result.issues.push(Stage1Issue {
                severity: IssueSeverity::High,
                description: format!("Ghost object detected: {}", ghost),
                remediation: Some("Object will be removed".to_string()),
                object_id: Some(ghost.clone()),
            });
        }
        
        // Detect dangling references
        let dangling_refs = self.detect_dangling_references(document)?;
        result.dangling_references = dangling_refs.len();
        
        for dangle in &dangling_refs {
            result.issues.push(Stage1Issue {
                severity: IssueSeverity::Medium,
                description: format!("Dangling reference: {}", dangle),
                remediation: Some("Reference will be removed or repaired".to_string()),
                object_id: Some(dangle.clone()),
            });
        }
        
        // Detect recursion
        self.detect_recursion(document, result)?;
        
        Ok(())
    }

    fn detect_ghost_objects(&self, document: &Document) -> Result<Vec<String>> {
        let mut ghost_objects = Vec::new();
        
        // Objects in XRef but not referenced anywhere
        for (obj_id, _) in &document.structure.objects {
            if !self.is_object_referenced(document, obj_id)? {
                // Check if it's a required object (Root, Info, etc.)
                if !self.is_required_object(document, obj_id)? {
                    ghost_objects.push(format!("{}", obj_id));
                }
            }
        }
        
        Ok(ghost_objects)
    }

    fn detect_dangling_references(&self, document: &Document) -> Result<Vec<String>> {
        let mut dangling_refs = Vec::new();
        
        // Find references to non-existent objects
        for (obj_id, object) in &document.structure.objects {
            let refs = self.extract_object_references(object)?;
            for ref_id in refs {
                if !document.structure.objects.contains_key(&ref_id) {
                    dangling_refs.push(format!("{}->{}",obj_id, ref_id));
                }
            }
        }
        
        Ok(dangling_refs)
    }

    fn detect_recursion(&self, document: &Document, result: &mut Stage1Result) -> Result<()> {
        let mut visited = std::collections::HashSet::new();
        let mut stack = std::collections::HashSet::new();
        
        for obj_id in document.structure.objects.keys() {
            if !visited.contains(obj_id) {
                if self.has_cycle(document, obj_id, &mut visited, &mut stack)? {
                    result.issues.push(Stage1Issue {
                        severity: IssueSeverity::Critical,
                        description: format!("Circular reference detected involving object {}", obj_id),
                        remediation: Some("Circular reference will be broken".to_string()),
                        object_id: Some(format!("{}", obj_id)),
                    });
                }
            }
        }
        
        Ok(())
    }

    // Helper methods
    fn is_auto_generated_info(&self, _document: &Document, _info_ref: &lopdf::Object) -> Result<bool> {
        // Check if Info dictionary contains only auto-generated fields
        // Implementation would examine the Info object for typical auto-generated content
        Ok(false) // Placeholder - implement actual logic
    }

    fn find_xref_table(&self, content: &[u8]) -> Result<Option<usize>> {
        // Find the position of the XRef table in content
        if let Some(pos) = content.windows(4).position(|w| w == b"xref") {
            return Ok(Some(pos));
        }
        Ok(None)
    }

    fn is_object_referenced(&self, _document: &Document, _obj_id: &u32) -> Result<bool> {
        // Check if object is referenced by other objects
        Ok(true) // Placeholder - implement actual reference checking
    }

    fn is_required_object(&self, document: &Document, obj_id: &u32) -> Result<bool> {
        // Check if object is required (Root, Info, etc.)
        if let Some(root_ref) = document.structure.trailer.get(b"Root") {
            // Extract object ID from reference and compare
            // Implementation would parse the reference
        }
        Ok(false) // Placeholder
    }

    fn extract_object_references(&self, _object: &lopdf::Object) -> Result<Vec<u32>> {
        // Extract all object references from an object
        Vec::new() // Placeholder - implement actual reference extraction
    }

    fn has_cycle(&self, _document: &Document, _obj_id: &u32, _visited: &mut std::collections::HashSet<u32>, _stack: &mut std::collections::HashSet<u32>) -> Result<bool> {
        // Detect cycles in object references
        Ok(false) // Placeholder - implement cycle detection
    }
}

#[async_trait]
impl Stage1Processor for Stage1ProcessorImpl {
    #[instrument(skip(self, document))]
    async fn execute(&self, document: &mut Document) -> Result<Stage1Result> {
        let start_time = std::time::Instant::now();
        let mut result = Stage1Result {
            success: false,
            structure_normalized: false,
            xref_repaired: false,
            linearization_handled: false,
            ghost_objects_detected: 0,
            dangling_references: 0,
            anomalies_fixed: 0,
            issues: Vec::new(),
            processing_time_ms: 0,
        };

        // Normalize PDF structure and trailer
        self.normalize_pdf_structure(document, &mut result).await?;

        // Validate and repair cross-reference table
        self.validate_and_repair_xref(document, &mut result).await?;

        // Handle linearization
        self.handle_linearization(document, &mut result).await?;

        // Detect and fix anomalies
        self.detect_anomalies(document, &mut result).await?;

        result.processing_time_ms = start_time.elapsed().as_millis() as u64;
        result.success = true;

        info!("Stage 1 completed: {} issues found", result.issues.len());
        Ok(result)
    }
}

impl Default for Stage1ProcessorImpl {
    fn default() -> Self {
        Self::new()
    }
}
