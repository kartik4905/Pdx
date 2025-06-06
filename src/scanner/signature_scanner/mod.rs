
use crate::error::Result;
use crate::types::Document;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    pub offset: usize,
    pub signature_type: SignatureType,
    pub confidence: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureType {
    PdfHeader,
    PdfTrailer,
    JavaScript,
    EmbeddedFile,
    Form,
    Encryption,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone)]
pub struct SignaturePattern {
    pub pattern: Vec<u8>,
    pub mask: Option<Vec<u8>>,
    pub signature_type: SignatureType,
    pub description: String,
    pub confidence: f64,
}

pub struct SignatureScanner {
    patterns: Vec<SignaturePattern>,
    max_scan_size: usize,
}

impl SignatureScanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            patterns: Vec::new(),
            max_scan_size: 10_000_000, // 10MB default
        };
        scanner.load_default_patterns();
        scanner
    }

    pub fn with_max_scan_size(mut self, size: usize) -> Self {
        self.max_scan_size = size;
        self
    }

    fn load_default_patterns(&mut self) {
        // PDF structure signatures
        self.add_pattern(SignaturePattern {
            pattern: b"%PDF-".to_vec(),
            mask: None,
            signature_type: SignatureType::PdfHeader,
            description: "PDF header signature".to_string(),
            confidence: 1.0,
        });

        self.add_pattern(SignaturePattern {
            pattern: b"%%EOF".to_vec(),
            mask: None,
            signature_type: SignatureType::PdfTrailer,
            description: "PDF end-of-file marker".to_string(),
            confidence: 1.0,
        });

        // JavaScript signatures
        self.add_pattern(SignaturePattern {
            pattern: b"/JavaScript".to_vec(),
            mask: None,
            signature_type: SignatureType::JavaScript,
            description: "JavaScript action".to_string(),
            confidence: 0.9,
        });

        self.add_pattern(SignaturePattern {
            pattern: b"/JS".to_vec(),
            mask: None,
            signature_type: SignatureType::JavaScript,
            description: "JavaScript (short form)".to_string(),
            confidence: 0.8,
        });

        // Embedded file signatures
        self.add_pattern(SignaturePattern {
            pattern: b"/EmbeddedFile".to_vec(),
            mask: None,
            signature_type: SignatureType::EmbeddedFile,
            description: "Embedded file".to_string(),
            confidence: 0.9,
        });

        // Form signatures
        self.add_pattern(SignaturePattern {
            pattern: b"/AcroForm".to_vec(),
            mask: None,
            signature_type: SignatureType::Form,
            description: "PDF form".to_string(),
            confidence: 0.8,
        });

        // Encryption signatures
        self.add_pattern(SignaturePattern {
            pattern: b"/Encrypt".to_vec(),
            mask: None,
            signature_type: SignatureType::Encryption,
            description: "Encryption dictionary".to_string(),
            confidence: 0.9,
        });

        // Suspicious patterns
        self.add_pattern(SignaturePattern {
            pattern: b"eval(".to_vec(),
            mask: None,
            signature_type: SignatureType::Suspicious,
            description: "JavaScript eval() function".to_string(),
            confidence: 0.7,
        });

        self.add_pattern(SignaturePattern {
            pattern: b"unescape(".to_vec(),
            mask: None,
            signature_type: SignatureType::Suspicious,
            description: "JavaScript unescape() function".to_string(),
            confidence: 0.7,
        });

        // Malicious patterns
        self.add_pattern(SignaturePattern {
            pattern: b"String.fromCharCode".to_vec(),
            mask: None,
            signature_type: SignatureType::Malicious,
            description: "Potential obfuscated code".to_string(),
            confidence: 0.6,
        });
    }

    pub fn add_pattern(&mut self, pattern: SignaturePattern) {
        self.patterns.push(pattern);
    }

    pub fn scan_document(&self, document: &Document) -> Result<Vec<SignatureMatch>> {
        let content = std::fs::read(&document.path)?;
        self.scan_bytes(&content)
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<SignatureMatch>> {
        let mut matches = Vec::new();
        let scan_size = std::cmp::min(data.len(), self.max_scan_size);
        let scan_data = &data[..scan_size];

        for pattern in &self.patterns {
            let pattern_matches = self.find_pattern_matches(scan_data, pattern);
            matches.extend(pattern_matches);
        }

        // Sort by offset
        matches.sort_by_key(|m| m.offset);
        
        Ok(matches)
    }

    fn find_pattern_matches(&self, data: &[u8], pattern: &SignaturePattern) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();
        
        if pattern.pattern.is_empty() {
            return matches;
        }

        for i in 0..=data.len().saturating_sub(pattern.pattern.len()) {
            if self.matches_pattern(&data[i..], pattern) {
                matches.push(SignatureMatch {
                    offset: i,
                    signature_type: pattern.signature_type.clone(),
                    confidence: pattern.confidence,
                    description: pattern.description.clone(),
                });
            }
        }

        matches
    }

    fn matches_pattern(&self, data: &[u8], pattern: &SignaturePattern) -> bool {
        if data.len() < pattern.pattern.len() {
            return false;
        }

        for (i, &pattern_byte) in pattern.pattern.iter().enumerate() {
            let data_byte = data[i];
            
            // Apply mask if present
            if let Some(ref mask) = pattern.mask {
                if i < mask.len() {
                    let masked_data = data_byte & mask[i];
                    let masked_pattern = pattern_byte & mask[i];
                    if masked_data != masked_pattern {
                        return false;
                    }
                    continue;
                }
            }
            
            // Direct comparison
            if data_byte != pattern_byte {
                return false;
            }
        }

        true
    }

    pub fn validate_pdf_structure(&self, data: &[u8]) -> Result<StructureValidation> {
        let mut validation = StructureValidation::new();
        
        // Check for PDF header
        if !data.starts_with(b"%PDF-") {
            validation.add_issue("Missing PDF header signature".to_string());
        }

        // Check for EOF marker
        let eof_positions = self.find_eof_markers(data);
        if eof_positions.is_empty() {
            validation.add_issue("Missing %%EOF marker".to_string());
        } else if eof_positions.len() > 1 {
            validation.add_issue(format!("Multiple %%EOF markers found: {}", eof_positions.len()));
        }

        // Check for proper PDF version
        if let Some(version) = self.extract_pdf_version(data) {
            validation.pdf_version = Some(version);
        } else {
            validation.add_issue("Cannot determine PDF version".to_string());
        }

        Ok(validation)
    }

    fn find_eof_markers(&self, data: &[u8]) -> Vec<usize> {
        let mut positions = Vec::new();
        let eof_pattern = b"%%EOF";
        
        for i in 0..=data.len().saturating_sub(eof_pattern.len()) {
            if &data[i..i + eof_pattern.len()] == eof_pattern {
                positions.push(i);
            }
        }
        
        positions
    }

    fn extract_pdf_version(&self, data: &[u8]) -> Option<String> {
        if data.len() < 8 || !data.starts_with(b"%PDF-") {
            return None;
        }

        // Look for version in first 20 bytes
        let header_end = std::cmp::min(data.len(), 20);
        let header = &data[5..header_end];
        
        // Find the version string (e.g., "1.4", "1.7")
        if let Some(newline_pos) = header.iter().position(|&b| b == b'\n' || b == b'\r') {
            let version_bytes = &header[..newline_pos];
            if let Ok(version_str) = std::str::from_utf8(version_bytes) {
                return Some(version_str.to_string());
            }
        }

        None
    }

    pub fn generate_signature_report(&self, matches: &[SignatureMatch]) -> SignatureReport {
        let mut report = SignatureReport::new();
        
        for signature_match in matches {
            report.add_match(signature_match.clone());
        }
        
        report.calculate_statistics();
        report
    }
}

#[derive(Debug, Clone)]
pub struct StructureValidation {
    pub pdf_version: Option<String>,
    pub issues: Vec<String>,
    pub is_valid: bool,
}

impl StructureValidation {
    pub fn new() -> Self {
        Self {
            pdf_version: None,
            issues: Vec::new(),
            is_valid: true,
        }
    }

    pub fn add_issue(&mut self, issue: String) {
        self.issues.push(issue);
        self.is_valid = false;
    }
}

#[derive(Debug, Clone)]
pub struct SignatureReport {
    pub total_matches: usize,
    pub matches_by_type: HashMap<String, usize>,
    pub highest_risk_score: f64,
    pub matches: Vec<SignatureMatch>,
}

impl SignatureReport {
    pub fn new() -> Self {
        Self {
            total_matches: 0,
            matches_by_type: HashMap::new(),
            highest_risk_score: 0.0,
            matches: Vec::new(),
        }
    }

    pub fn add_match(&mut self, signature_match: SignatureMatch) {
        let type_key = format!("{:?}", signature_match.signature_type);
        *self.matches_by_type.entry(type_key).or_insert(0) += 1;
        
        if signature_match.confidence > self.highest_risk_score {
            self.highest_risk_score = signature_match.confidence;
        }
        
        self.matches.push(signature_match);
    }

    pub fn calculate_statistics(&mut self) {
        self.total_matches = self.matches.len();
    }
}

impl Default for SignatureScanner {
    fn default() -> Self {
        Self::new()
    }
}
