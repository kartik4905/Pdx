
use crate::error::Result;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicVerificationResult {
    pub passed: bool,
    pub issues: Vec<ForensicIssue>,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicIssue {
    pub severity: String,
    pub description: String,
    pub remediation: Option<String>,
    pub location: Option<usize>,
}

pub struct ForensicVerifier {
    suspicious_patterns: Vec<Vec<u8>>,
    javascript_patterns: Vec<Vec<u8>>,
}

impl ForensicVerifier {
    pub fn new() -> Self {
        Self {
            suspicious_patterns: vec![
                b"/JavaScript".to_vec(),
                b"/JS".to_vec(),
                b"/Launch".to_vec(),
                b"/SubmitForm".to_vec(),
                b"/ImportData".to_vec(),
                b"eval(".to_vec(),
                b"unescape(".to_vec(),
            ],
            javascript_patterns: vec![
                b"app.alert".to_vec(),
                b"this.print".to_vec(),
                b"String.fromCharCode".to_vec(),
                b"document.write".to_vec(),
            ],
        }
    }

    pub fn verify(&self, content: &[u8]) -> Result<ForensicVerificationResult> {
        let start_time = std::time::Instant::now();
        let mut issues = Vec::new();

        // Check for JavaScript
        self.scan_for_javascript(content, &mut issues);
        
        // Check for suspicious actions
        self.scan_for_suspicious_actions(content, &mut issues);
        
        // Check for embedded files
        self.scan_for_embedded_files(content, &mut issues);
        
        // Check for forms
        self.scan_for_forms(content, &mut issues);

        let scan_duration = start_time.elapsed().as_millis() as u64;
        let passed = issues.iter().all(|issue| issue.severity != "critical");

        Ok(ForensicVerificationResult {
            passed,
            issues,
            scan_duration_ms: scan_duration,
        })
    }

    fn scan_for_javascript(&self, content: &[u8], issues: &mut Vec<ForensicIssue>) {
        for pattern in &self.javascript_patterns {
            if let Some(pos) = self.find_pattern(content, pattern) {
                issues.push(ForensicIssue {
                    severity: "critical".to_string(),
                    description: format!("JavaScript detected: {}", String::from_utf8_lossy(pattern)),
                    remediation: Some("Remove all JavaScript code".to_string()),
                    location: Some(pos),
                });
            }
        }
    }

    fn scan_for_suspicious_actions(&self, content: &[u8], issues: &mut Vec<ForensicIssue>) {
        let suspicious_actions = [
            (b"/Launch", "Launch action detected"),
            (b"/SubmitForm", "Form submission action detected"),
            (b"/ImportData", "Data import action detected"),
            (b"/Action", "Generic action detected"),
        ];

        for (pattern, description) in &suspicious_actions {
            if let Some(pos) = self.find_pattern(content, pattern) {
                issues.push(ForensicIssue {
                    severity: "high".to_string(),
                    description: description.to_string(),
                    remediation: Some("Review and remove suspicious actions".to_string()),
                    location: Some(pos),
                });
            }
        }
    }

    fn scan_for_embedded_files(&self, content: &[u8], issues: &mut Vec<ForensicIssue>) {
        if let Some(pos) = self.find_pattern(content, b"/EmbeddedFile") {
            issues.push(ForensicIssue {
                severity: "medium".to_string(),
                description: "Embedded file detected".to_string(),
                remediation: Some("Review embedded files for security risks".to_string()),
                location: Some(pos),
            });
        }
    }

    fn scan_for_forms(&self, content: &[u8], issues: &mut Vec<ForensicIssue>) {
        if let Some(pos) = self.find_pattern(content, b"/AcroForm") {
            issues.push(ForensicIssue {
                severity: "low".to_string(),
                description: "PDF form detected".to_string(),
                remediation: Some("Review form fields for sensitive data".to_string()),
                location: Some(pos),
            });
        }
    }

    fn find_pattern(&self, content: &[u8], pattern: &[u8]) -> Option<usize> {
        for i in 0..=content.len().saturating_sub(pattern.len()) {
            if &content[i..i + pattern.len()] == pattern {
                return Some(i);
            }
        }
        None
    }
}

impl Default for ForensicVerifier {
    fn default() -> Self {
        Self::new()
    }
}
