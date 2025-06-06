
//! Stage 6: Final Verification
//! 
//! This stage performs comprehensive forensic verification to ensure anti-forensic compliance:
//! - Run forensic scanner post-cleaning
//! - Validate EOF count (exactly 1)
//! - Object-to-XRef consistency checks
//! - Stream count aligns with page count
//! - No unreferenced or orphaned objects
//! - Verify all anti-forensic requirements are met

use crate::{
    config::ProcessingConfig,
    error::{Result, PipelineError},
    types::Document,
    forensics::{
        verification_engine::VerificationEngine,
        forensic_scanner::ForensicScanner,
    },
    verification::forensic_verifier::ForensicVerifier,
    scanner::deep_scanner::DeepScanner,
    utils::{Logger, Metrics},
};
use lopdf::{Dictionary, Object, Stream};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn, debug, error, instrument};

pub struct Stage6 {
    config: ProcessingConfig,
    logger: Logger,
    metrics: Metrics,
    verification_engine: VerificationEngine,
    forensic_scanner: ForensicScanner,
    forensic_verifier: ForensicVerifier,
    deep_scanner: DeepScanner,
}

#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub eof_count: usize,
    pub object_consistency: bool,
    pub stream_page_ratio: f64,
    pub orphaned_objects: Vec<u32>,
    pub unreferenced_objects: Vec<u32>,
    pub forensic_issues: Vec<ForensicIssue>,
    pub compliance_status: ComplianceStatus,
}

#[derive(Debug, Clone)]
pub struct ForensicIssue {
    pub severity: IssueSeverity,
    pub category: IssueCategory,
    pub description: String,
    pub object_id: Option<u32>,
    pub recommendation: String,
}

#[derive(Debug, Clone)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone)]
pub enum IssueCategory {
    Structure,
    Metadata,
    Security,
    Compliance,
    Performance,
}

#[derive(Debug, Clone)]
pub struct ComplianceStatus {
    pub eof_compliance: bool,
    pub object_consistency: bool,
    pub stream_compliance: bool,
    pub metadata_compliance: bool,
    pub security_compliance: bool,
    pub overall_compliant: bool,
}

impl Stage6 {
    pub fn new(config: ProcessingConfig) -> Self {
        Self {
            config,
            logger: Logger::default(),
            metrics: Metrics::new(),
            verification_engine: VerificationEngine::new(),
            forensic_scanner: ForensicScanner::new(),
            forensic_verifier: ForensicVerifier::new(),
            deep_scanner: DeepScanner::new(),
        }
    }

    #[instrument(skip(self, document))]
    pub async fn execute(&mut self, document: &mut Document) -> Result<VerificationReport> {
        info!("Stage 6: Final Verification - Starting comprehensive forensic validation");
        
        // Step 1: Run post-cleaning forensic scan
        let forensic_results = self.run_post_cleaning_scan(document).await?;
        
        // Step 2: Validate EOF count (exactly 1)
        let eof_count = self.validate_eof_count(document).await?;
        
        // Step 3: Verify object-to-XRef consistency
        let consistency_check = self.verify_object_xref_consistency(document).await?;
        
        // Step 4: Validate stream-to-page ratio
        let stream_ratio = self.validate_stream_page_ratio(document).await?;
        
        // Step 5: Detect orphaned and unreferenced objects
        let (orphaned, unreferenced) = self.detect_orphaned_objects(document).await?;
        
        // Step 6: Verify anti-forensic compliance
        let compliance = self.verify_anti_forensic_compliance(document).await?;
        
        // Step 7: Generate comprehensive verification report
        let report = self.generate_verification_report(
            eof_count,
            consistency_check,
            stream_ratio,
            orphaned,
            unreferenced,
            forensic_results,
            compliance
        ).await?;
        
        // Step 8: Validate overall compliance
        self.validate_overall_compliance(&report).await?;
        
        info!("Stage 6: Final Verification completed - Compliance: {}", report.compliance_status.overall_compliant);
        Ok(report)
    }

    async fn run_post_cleaning_scan(&mut self, document: &Document) -> Result<Vec<ForensicIssue>> {
        info!("Running post-cleaning forensic scan");
        
        let mut issues = Vec::new();
        
        // Scan for residual forensic artifacts
        let scan_results = self.forensic_scanner.scan_document(document).await?;
        
        // Convert scan results to forensic issues
        for result in scan_results.suspicious_patterns {
            issues.push(ForensicIssue {
                severity: match result.confidence {
                    conf if conf > 0.9 => IssueSeverity::Critical,
                    conf if conf > 0.7 => IssueSeverity::High,
                    conf if conf > 0.5 => IssueSeverity::Medium,
                    _ => IssueSeverity::Low,
                },
                category: IssueCategory::Structure,
                description: result.description,
                object_id: result.object_id,
                recommendation: "Review and potentially re-clean this artifact".to_string(),
            });
        }
        
        // Check for metadata leakage
        let metadata_issues = self.scan_metadata_leakage(document).await?;
        issues.extend(metadata_issues);
        
        // Check for hidden content
        let hidden_content_issues = self.scan_hidden_content(document).await?;
        issues.extend(hidden_content_issues);
        
        info!("Post-cleaning scan found {} issues", issues.len());
        Ok(issues)
    }

    async fn validate_eof_count(&self, document: &Document) -> Result<usize> {
        info!("Validating EOF count (must be exactly 1)");
        
        let content = &document.content;
        let eof_pattern = b"%%EOF";
        let mut eof_count = 0;
        let mut pos = 0;
        
        while let Some(found_pos) = content[pos..].windows(eof_pattern.len())
            .position(|window| window == eof_pattern) {
            eof_count += 1;
            pos += found_pos + eof_pattern.len();
        }
        
        info!("Found {} EOF markers", eof_count);
        
        if eof_count != 1 {
            warn!("EOF count violation: found {} EOF markers, expected exactly 1", eof_count);
        }
        
        Ok(eof_count)
    }

    async fn verify_object_xref_consistency(&self, document: &Document) -> Result<bool> {
        info!("Verifying object-to-XRef consistency");
        
        let mut consistent = true;
        let mut referenced_objects = HashSet::new();
        
        // Collect all object references from XRef tables
        for xref_table in &document.structure.cross_reference_tables {
            for entry in &xref_table.entries {
                if entry.in_use {
                    referenced_objects.insert(entry.object_number);
                }
            }
        }
        
        // Check if all objects in the document are properly referenced
        for object_id in document.structure.objects.keys() {
            if !referenced_objects.contains(object_id) {
                warn!("Object {} exists but is not referenced in XRef table", object_id);
                consistent = false;
            }
        }
        
        // Check if all XRef entries have corresponding objects
        for object_id in &referenced_objects {
            if !document.structure.objects.contains_key(object_id) {
                warn!("XRef references object {} but object doesn't exist", object_id);
                consistent = false;
            }
        }
        
        info!("Object-XRef consistency: {}", if consistent { "PASS" } else { "FAIL" });
        Ok(consistent)
    }

    async fn validate_stream_page_ratio(&self, document: &Document) -> Result<f64> {
        info!("Validating stream-to-page ratio");
        
        let page_count = document.structure.page_count as f64;
        let stream_count = self.count_content_streams(document).await? as f64;
        
        let ratio = if page_count > 0.0 {
            stream_count / page_count
        } else {
            0.0
        };
        
        info!("Stream-to-page ratio: {:.2} ({} streams, {} pages)", ratio, stream_count, page_count);
        
        // Warn if ratio is suspicious (too many streams per page)
        if ratio > 10.0 {
            warn!("Suspicious stream-to-page ratio: {:.2}", ratio);
        }
        
        Ok(ratio)
    }

    async fn count_content_streams(&self, document: &Document) -> Result<usize> {
        let mut stream_count = 0;
        
        for (_, object) in &document.structure.objects {
            match object {
                Object::Stream(_) => stream_count += 1,
                Object::Dictionary(dict) => {
                    // Check if it's a content stream dictionary
                    if dict.has(b"Length") && (dict.has(b"Filter") || dict.has(b"Type")) {
                        stream_count += 1;
                    }
                }
                _ => {}
            }
        }
        
        Ok(stream_count)
    }

    async fn detect_orphaned_objects(&self, document: &Document) -> Result<(Vec<u32>, Vec<u32>)> {
        info!("Detecting orphaned and unreferenced objects");
        
        let mut referenced_objects = HashSet::new();
        let mut orphaned_objects = Vec::new();
        let mut unreferenced_objects = Vec::new();
        
        // Collect references from trailer
        if let Some(Object::Dictionary(trailer)) = document.structure.trailer.as_ref() {
            self.collect_references_from_object(&Object::Dictionary(trailer.clone()), &mut referenced_objects);
        }
        
        // Collect references from all reachable objects
        let mut to_process: Vec<u32> = referenced_objects.iter().cloned().collect();
        let mut processed = HashSet::new();
        
        while let Some(object_id) = to_process.pop() {
            if processed.contains(&object_id) {
                continue;
            }
            processed.insert(object_id);
            
            if let Some(object) = document.structure.objects.get(&object_id) {
                let mut refs = HashSet::new();
                self.collect_references_from_object(object, &mut refs);
                
                for new_ref in refs {
                    if !processed.contains(&new_ref) {
                        to_process.push(new_ref);
                        referenced_objects.insert(new_ref);
                    }
                }
            }
        }
        
        // Find unreferenced objects
        for object_id in document.structure.objects.keys() {
            if !referenced_objects.contains(object_id) {
                unreferenced_objects.push(*object_id);
            }
        }
        
        // Find orphaned objects (referenced but don't exist)
        for ref_id in &referenced_objects {
            if !document.structure.objects.contains_key(ref_id) {
                orphaned_objects.push(*ref_id);
            }
        }
        
        info!("Found {} orphaned objects, {} unreferenced objects", 
               orphaned_objects.len(), unreferenced_objects.len());
        
        Ok((orphaned_objects, unreferenced_objects))
    }

    fn collect_references_from_object(&self, object: &Object, references: &mut HashSet<u32>) {
        match object {
            Object::Reference((id, _)) => {
                references.insert(*id);
            }
            Object::Dictionary(dict) => {
                for (_, value) in dict.iter() {
                    self.collect_references_from_object(value, references);
                }
            }
            Object::Array(array) => {
                for item in array {
                    self.collect_references_from_object(item, references);
                }
            }
            Object::Stream(stream) => {
                self.collect_references_from_object(&Object::Dictionary(stream.dict.clone()), references);
            }
            _ => {}
        }
    }

    async fn verify_anti_forensic_compliance(&self, document: &Document) -> Result<ComplianceStatus> {
        info!("Verifying anti-forensic compliance");
        
        let eof_compliance = self.check_eof_compliance(document).await?;
        let object_consistency = self.check_object_consistency(document).await?;
        let stream_compliance = self.check_stream_compliance(document).await?;
        let metadata_compliance = self.check_metadata_compliance(document).await?;
        let security_compliance = self.check_security_compliance(document).await?;
        
        let overall_compliant = eof_compliance && 
                               object_consistency && 
                               stream_compliance && 
                               metadata_compliance && 
                               security_compliance;
        
        Ok(ComplianceStatus {
            eof_compliance,
            object_consistency,
            stream_compliance,
            metadata_compliance,
            security_compliance,
            overall_compliant,
        })
    }

    async fn check_eof_compliance(&self, document: &Document) -> Result<bool> {
        let eof_count = self.validate_eof_count(document).await?;
        Ok(eof_count == 1)
    }

    async fn check_object_consistency(&self, document: &Document) -> Result<bool> {
        self.verify_object_xref_consistency(document).await
    }

    async fn check_stream_compliance(&self, document: &Document) -> Result<bool> {
        let ratio = self.validate_stream_page_ratio(document).await?;
        // Accept reasonable stream-to-page ratios
        Ok(ratio <= 10.0 && ratio >= 0.5)
    }

    async fn check_metadata_compliance(&self, document: &Document) -> Result<bool> {
        // Check for any auto-generated metadata
        let has_auto_metadata = self.detect_auto_generated_metadata(document).await?;
        Ok(!has_auto_metadata)
    }

    async fn check_security_compliance(&self, document: &Document) -> Result<bool> {
        // Check for proper security implementation
        self.verify_security_implementation(document).await
    }

    async fn detect_auto_generated_metadata(&self, document: &Document) -> Result<bool> {
        // Check for common auto-generated metadata patterns
        let suspicious_patterns = vec![
            "Producer: Unknown",
            "Creator: Default",
            "ModDate: Auto",
            "CreationDate: Generated",
        ];
        
        for pattern in suspicious_patterns {
            if document.metadata.producer.as_ref().map_or(false, |p| p.contains(pattern)) ||
               document.metadata.creator.as_ref().map_or(false, |c| c.contains(pattern)) {
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    async fn verify_security_implementation(&self, document: &Document) -> Result<bool> {
        // Verify encryption is properly implemented if requested
        if self.config.security.is_some() {
            // Check for encryption dictionary
            if let Some(encrypt_ref) = self.find_encrypt_dictionary(document) {
                if let Some(Object::Dictionary(encrypt_dict)) = document.structure.objects.get(&encrypt_ref) {
                    // Verify required encryption parameters are present
                    return Ok(encrypt_dict.has(b"V") && 
                             encrypt_dict.has(b"R") && 
                             encrypt_dict.has(b"P"));
                }
            }
            return Ok(false); // Encryption requested but not properly implemented
        }
        
        Ok(true) // No encryption requested
    }

    fn find_encrypt_dictionary(&self, document: &Document) -> Option<u32> {
        if let Some(Object::Dictionary(trailer)) = document.structure.trailer.as_ref() {
            if let Ok(Object::Reference((id, _))) = trailer.get(b"Encrypt") {
                return Some(*id);
            }
        }
        None
    }

    async fn scan_metadata_leakage(&self, document: &Document) -> Result<Vec<ForensicIssue>> {
        let mut issues = Vec::new();
        
        // Check for sensitive metadata that might have been missed
        let sensitive_keys = vec![
            "Author", "Creator", "Producer", "Subject", "Title", 
            "Keywords", "ModDate", "CreationDate", "Trapped"
        ];
        
        for (key, value) in &document.metadata.custom_properties {
            if sensitive_keys.iter().any(|&k| key.contains(k)) {
                issues.push(ForensicIssue {
                    severity: IssueSeverity::Medium,
                    category: IssueCategory::Metadata,
                    description: format!("Potential metadata leakage in field: {}", key),
                    object_id: None,
                    recommendation: "Review and sanitize this metadata field".to_string(),
                });
            }
        }
        
        Ok(issues)
    }

    async fn scan_hidden_content(&self, document: &Document) -> Result<Vec<ForensicIssue>> {
        let mut issues = Vec::new();
        
        // Scan for potential hidden content or steganography
        for (object_id, object) in &document.structure.objects {
            if let Object::Stream(stream) = object {
                // Check for suspicious stream content
                if self.is_suspicious_stream(stream) {
                    issues.push(ForensicIssue {
                        severity: IssueSeverity::High,
                        category: IssueCategory::Security,
                        description: "Potentially hidden content detected in stream".to_string(),
                        object_id: Some(*object_id),
                        recommendation: "Examine stream content for hidden data".to_string(),
                    });
                }
            }
        }
        
        Ok(issues)
    }

    fn is_suspicious_stream(&self, stream: &Stream) -> bool {
        // Check for streams with unusual characteristics
        let content = &stream.content;
        
        // Check for high entropy (possible encrypted/compressed hidden data)
        let entropy = self.calculate_entropy(content);
        if entropy > 7.5 {
            return true;
        }
        
        // Check for unusual size patterns
        if content.len() > 1_000_000 && stream.dict.len() < 5 {
            return true;
        }
        
        false
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut freq = [0u32; 256];
        
        for &byte in data {
            freq[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }

    async fn generate_verification_report(&self, 
        eof_count: usize,
        object_consistency: bool,
        stream_ratio: f64,
        orphaned: Vec<u32>,
        unreferenced: Vec<u32>,
        forensic_issues: Vec<ForensicIssue>,
        compliance: ComplianceStatus
    ) -> Result<VerificationReport> {
        
        Ok(VerificationReport {
            eof_count,
            object_consistency,
            stream_page_ratio: stream_ratio,
            orphaned_objects: orphaned,
            unreferenced_objects: unreferenced,
            forensic_issues,
            compliance_status: compliance,
        })
    }

    async fn validate_overall_compliance(&self, report: &VerificationReport) -> Result<()> {
        if !report.compliance_status.overall_compliant {
            let mut errors = Vec::new();
            
            if !report.compliance_status.eof_compliance {
                errors.push(format!("EOF compliance failed: found {} EOF markers", report.eof_count));
            }
            
            if !report.compliance_status.object_consistency {
                errors.push("Object-XRef consistency failed".to_string());
            }
            
            if !report.compliance_status.stream_compliance {
                errors.push(format!("Stream compliance failed: ratio {:.2}", report.stream_page_ratio));
            }
            
            if !report.compliance_status.metadata_compliance {
                errors.push("Metadata compliance failed".to_string());
            }
            
            if !report.compliance_status.security_compliance {
                errors.push("Security compliance failed".to_string());
            }
            
            let critical_issues = report.forensic_issues.iter()
                .filter(|issue| matches!(issue.severity, IssueSeverity::Critical))
                .count();
            
            if critical_issues > 0 {
                errors.push(format!("Found {} critical forensic issues", critical_issues));
            }
            
            return Err(PipelineError::Verification(
                format!("Anti-forensic compliance validation failed: {}", errors.join(", "))
            ));
        }
        
        info!("Overall compliance validation PASSED");
        Ok(())
    }
}
