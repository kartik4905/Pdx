
use crate::types::Document;
use crate::error::Result;
use crate::scanner::signature_scanner::SignatureScanner;
use crate::analyzer::entropy::EntropyAnalyzer;
use crate::verification::forensic_verifier::ForensicVerifier;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage0Result {
    pub document_loaded: bool,
    pub structure_valid: bool,
    pub entropy_verified: bool,
    pub forensic_scan_passed: bool,
    pub issues: Vec<Stage0Issue>,
    pub pdf_version: Option<String>,
    pub object_count: usize,
    pub page_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage0Issue {
    pub severity: IssueSeverity,
    pub description: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueSeverity {
    Low,
    Medium,
    High,
    Critical,
}

pub struct Stage0Processor {
    signature_scanner: SignatureScanner,
    entropy_analyzer: EntropyAnalyzer,
    forensic_verifier: ForensicVerifier,
}

impl Stage0Processor {
    pub fn new() -> Self {
        Self {
            signature_scanner: SignatureScanner::new(),
            entropy_analyzer: EntropyAnalyzer::new(),
            forensic_verifier: ForensicVerifier::new(),
        }
    }

    pub async fn execute(&self, document: &Document) -> Result<Stage0Result> {
        let mut result = Stage0Result {
            document_loaded: false,
            structure_valid: false,
            entropy_verified: false,
            forensic_scan_passed: false,
            issues: Vec::new(),
            pdf_version: None,
            object_count: 0,
            page_count: 0,
        };

        // Load and verify document structure
        if self.verify_document_load(document, &mut result).await? {
            result.document_loaded = true;
        }

        // Validate PDF structure without fallbacks
        if self.validate_structure(document, &mut result).await? {
            result.structure_valid = true;
        }

        // Verify entropy patterns
        if self.verify_entropy(document, &mut result).await? {
            result.entropy_verified = true;
        }

        // Run forensic verification
        if self.run_forensic_scan(document, &mut result).await? {
            result.forensic_scan_passed = true;
        }

        Ok(result)
    }

    async fn verify_document_load(&self, document: &Document, result: &mut Stage0Result) -> Result<bool> {
        if document.content.is_empty() {
            result.issues.push(Stage0Issue {
                severity: IssueSeverity::Critical,
                description: "Document content is empty".to_string(),
                remediation: Some("Provide a valid PDF file".to_string()),
            });
            return Ok(false);
        }

        // Verify PDF signature
        let signature_result = self.signature_scanner.validate_pdf_signature(&document.content)?;
        
        if !signature_result.is_valid_pdf {
            result.issues.push(Stage0Issue {
                severity: IssueSeverity::Critical,
                description: "Invalid PDF signature".to_string(),
                remediation: Some("File must start with %PDF- header".to_string()),
            });
            return Ok(false);
        }

        result.pdf_version = signature_result.pdf_version;
        Ok(true)
    }

    async fn validate_structure(&self, document: &Document, result: &mut Stage0Result) -> Result<bool> {
        let mut valid = true;

        // Check for proper EOF markers
        let eof_count = self.count_eof_markers(&document.content);
        if eof_count == 0 {
            result.issues.push(Stage0Issue {
                severity: IssueSeverity::Critical,
                description: "Missing %%EOF marker".to_string(),
                remediation: Some("PDF must end with %%EOF".to_string()),
            });
            valid = false;
        } else if eof_count > 1 {
            result.issues.push(Stage0Issue {
                severity: IssueSeverity::Medium,
                description: format!("Multiple %%EOF markers found: {}", eof_count),
                remediation: Some("PDF should have exactly one %%EOF marker".to_string()),
            });
        }

        // Validate cross-reference table
        if !self.validate_xref_table(&document.content) {
            result.issues.push(Stage0Issue {
                severity: IssueSeverity::High,
                description: "Invalid cross-reference table".to_string(),
                remediation: Some("Cross-reference table must be properly formatted".to_string()),
            });
            valid = false;
        }

        // Count objects and pages
        result.object_count = self.count_objects(&document.content);
        result.page_count = document.get_page_count();

        Ok(valid)
    }

    async fn verify_entropy(&self, document: &Document, result: &mut Stage0Result) -> Result<bool> {
        let entropy_result = self.entropy_analyzer.analyze(&document.content)?;
        
        // Check for suspicious entropy patterns
        if entropy_result.overall_entropy > 7.5 {
            result.issues.push(Stage0Issue {
                severity: IssueSeverity::Medium,
                description: "High entropy detected - possible encrypted/compressed content".to_string(),
                remediation: Some("Verify if encryption or compression is intentional".to_string()),
            });
        }

        if entropy_result.has_anomalies {
            result.issues.push(Stage0Issue {
                severity: IssueSeverity::High,
                description: "Entropy anomalies detected".to_string(),
                remediation: Some("Review document for hidden data or steganography".to_string()),
            });
        }

        Ok(!entropy_result.has_anomalies)
    }

    async fn run_forensic_scan(&self, document: &Document, result: &mut Stage0Result) -> Result<bool> {
        let forensic_result = self.forensic_verifier.verify(&document.content)?;
        
        if !forensic_result.passed {
            for issue in &forensic_result.issues {
                result.issues.push(Stage0Issue {
                    severity: match issue.severity.as_str() {
                        "critical" => IssueSeverity::Critical,
                        "high" => IssueSeverity::High,
                        "medium" => IssueSeverity::Medium,
                        _ => IssueSeverity::Low,
                    },
                    description: issue.description.clone(),
                    remediation: issue.remediation.clone(),
                });
            }
        }

        Ok(forensic_result.passed)
    }

    fn count_eof_markers(&self, content: &[u8]) -> usize {
        let eof_pattern = b"%%EOF";
        let mut count = 0;
        
        for i in 0..=content.len().saturating_sub(eof_pattern.len()) {
            if &content[i..i + eof_pattern.len()] == eof_pattern {
                count += 1;
            }
        }
        
        count
    }

    fn validate_xref_table(&self, content: &[u8]) -> bool {
        // Look for xref keyword
        let xref_pattern = b"xref";
        let content_str = String::from_utf8_lossy(content);
        
        content_str.contains("xref") && content_str.contains("trailer")
    }

    fn count_objects(&self, content: &[u8]) -> usize {
        let content_str = String::from_utf8_lossy(content);
        let obj_pattern = regex::Regex::new(r"\d+\s+\d+\s+obj").unwrap();
        obj_pattern.find_iter(&content_str).count()
    }
}

impl Default for Stage0Processor {
    fn default() -> Self {
        Self::new()
    }
}
