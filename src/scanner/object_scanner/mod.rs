
use crate::error::Result;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfObjectInfo {
    pub object_number: u32,
    pub generation: u16,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousObject {
    pub object_number: u32,
    pub generation: u16,
    pub reason: String,
    pub severity: SuspiciousSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuspiciousSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct ObjectScanner {
    suspicious_keywords: Vec<String>,
    max_object_size: usize,
}

impl ObjectScanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            suspicious_keywords: Vec::new(),
            max_object_size: 10_000_000, // 10MB default
        };
        scanner.load_suspicious_keywords();
        scanner
    }

    fn load_suspicious_keywords(&mut self) {
        self.suspicious_keywords = vec![
            "eval(".to_string(),
            "unescape(".to_string(),
            "String.fromCharCode".to_string(),
            "/Launch".to_string(),
            "/SubmitForm".to_string(),
            "/ImportData".to_string(),
            "/GoToR".to_string(),
            "/GoToE".to_string(),
            "/Movie".to_string(),
            "/Sound".to_string(),
            "/RichMedia".to_string(),
            "/3D".to_string(),
            "/Flash".to_string(),
            "ActiveX".to_string(),
            "shellcode".to_string(),
            "exploit".to_string(),
            "payload".to_string(),
            "CVE-".to_string(),
        ];
    }

    pub fn scan_objects(&self, objects: &[PdfObjectInfo]) -> Result<ObjectScanResult> {
        let mut result = ObjectScanResult::new();
        
        for obj in objects {
            // Check object size
            if obj.content.len() > self.max_object_size {
                result.add_suspicious_object(SuspiciousObject {
                    object_number: obj.object_number,
                    generation: obj.generation,
                    reason: format!("Object size exceeds limit: {} bytes", obj.content.len()),
                    severity: SuspiciousSeverity::Medium,
                });
            }
            
            // Analyze object content
            self.analyze_object_content(obj, &mut result);
        }
        
        result.calculate_statistics();
        Ok(result)
    }

    fn analyze_object_content(&self, obj: &PdfObjectInfo, result: &mut ObjectScanResult) {
        let content_str = std::str::from_utf8(&obj.content).unwrap_or("");
        
        // Check for JavaScript
        if content_str.contains("/JavaScript") || content_str.contains("/JS") {
            result.add_suspicious_object(SuspiciousObject {
                object_number: obj.object_number,
                generation: obj.generation,
                reason: "Contains JavaScript".to_string(),
                severity: SuspiciousSeverity::High,
            });
            result.javascript_objects += 1;
        }
        
        // Check for actions
        if content_str.contains("/Action") {
            result.add_suspicious_object(SuspiciousObject {
                object_number: obj.object_number,
                generation: obj.generation,
                reason: "Contains action".to_string(),
                severity: SuspiciousSeverity::Medium,
            });
            result.action_objects += 1;
        }
        
        // Check for forms
        if content_str.contains("/AcroForm") || content_str.contains("/XFA") {
            result.form_objects += 1;
        }
        
        // Check for embedded files
        if content_str.contains("/EmbeddedFile") || content_str.contains("/FileSpec") {
            result.embedded_files += 1;
        }
        
        // Check for suspicious keywords
        for keyword in &self.suspicious_keywords {
            if content_str.contains(keyword) {
                let severity = match keyword.as_str() {
                    s if s.contains("eval") || s.contains("exploit") || s.contains("shellcode") => SuspiciousSeverity::Critical,
                    s if s.contains("CVE-") || s.contains("payload") => SuspiciousSeverity::High,
                    s if s.contains("/Launch") || s.contains("ActiveX") => SuspiciousSeverity::High,
                    _ => SuspiciousSeverity::Medium,
                };
                
                result.add_suspicious_object(SuspiciousObject {
                    object_number: obj.object_number,
                    generation: obj.generation,
                    reason: format!("Contains suspicious keyword: {}", keyword),
                    severity,
                });
            }
        }
        
        // Check for obfuscation patterns
        self.check_obfuscation_patterns(obj, result);
        
        // Check for unusual object types
        self.check_unusual_object_types(obj, result);
        
        // Check for malformed objects
        self.check_malformed_objects(obj, result);
    }

    fn check_obfuscation_patterns(&self, obj: &PdfObjectInfo, result: &mut ObjectScanResult) {
        let content_str = std::str::from_utf8(&obj.content).unwrap_or("");
        
        // Check for hex encoding patterns
        let hex_pattern_count = content_str.matches("<").count();
        if hex_pattern_count > 10 {
            result.add_suspicious_object(SuspiciousObject {
                object_number: obj.object_number,
                generation: obj.generation,
                reason: format!("High number of hex-encoded strings: {}", hex_pattern_count),
                severity: SuspiciousSeverity::Medium,
            });
        }
        
        // Check for long strings that might be obfuscated
        for line in content_str.lines() {
            if line.len() > 1000 && !line.chars().any(|c| c.is_whitespace()) {
                result.add_suspicious_object(SuspiciousObject {
                    object_number: obj.object_number,
                    generation: obj.generation,
                    reason: "Contains very long string without whitespace (possible obfuscation)".to_string(),
                    severity: SuspiciousSeverity::Medium,
                });
                break;
            }
        }
        
        // Check for repeated patterns that might indicate encoding
        if self.has_repeated_patterns(content_str) {
            result.add_suspicious_object(SuspiciousObject {
                object_number: obj.object_number,
                generation: obj.generation,
                reason: "Contains repeated patterns (possible encoding)".to_string(),
                severity: SuspiciousSeverity::Low,
            });
        }
    }

    fn check_unusual_object_types(&self, obj: &PdfObjectInfo, result: &mut ObjectScanResult) {
        let content_str = std::str::from_utf8(&obj.content).unwrap_or("");
        
        // Check for multimedia objects
        let multimedia_types = [
            "/Movie", "/Sound", "/RichMedia", "/3D", "/Flash",
            "/Video", "/Audio", "/Rendition"
        ];
        
        for media_type in &multimedia_types {
            if content_str.contains(media_type) {
                result.add_suspicious_object(SuspiciousObject {
                    object_number: obj.object_number,
                    generation: obj.generation,
                    reason: format!("Contains multimedia object: {}", media_type),
                    severity: SuspiciousSeverity::Medium,
                });
            }
        }
        
        // Check for annotation objects with actions
        if content_str.contains("/Annot") && content_str.contains("/A") {
            result.add_suspicious_object(SuspiciousObject {
                object_number: obj.object_number,
                generation: obj.generation,
                reason: "Annotation with action detected".to_string(),
                severity: SuspiciousSeverity::Medium,
            });
        }
    }

    fn check_malformed_objects(&self, obj: &PdfObjectInfo, result: &mut ObjectScanResult) {
        let content_str = std::str::from_utf8(&obj.content).unwrap_or("");
        
        // Check for missing endobj
        if content_str.contains("obj") && !content_str.contains("endobj") {
            result.add_suspicious_object(SuspiciousObject {
                object_number: obj.object_number,
                generation: obj.generation,
                reason: "Object missing endobj keyword".to_string(),
                severity: SuspiciousSeverity::Medium,
            });
        }
        
        // Check for malformed dictionary brackets
        let open_dict = content_str.matches("<<").count();
        let close_dict = content_str.matches(">>").count();
        if open_dict != close_dict {
            result.add_suspicious_object(SuspiciousObject {
                object_number: obj.object_number,
                generation: obj.generation,
                reason: "Mismatched dictionary brackets".to_string(),
                severity: SuspiciousSeverity::High,
            });
        }
        
        // Check for malformed array brackets
        let open_array = content_str.matches('[').count();
        let close_array = content_str.matches(']').count();
        if open_array != close_array {
            result.add_suspicious_object(SuspiciousObject {
                object_number: obj.object_number,
                generation: obj.generation,
                reason: "Mismatched array brackets".to_string(),
                severity: SuspiciousSeverity::Medium,
            });
        }
    }

    fn has_repeated_patterns(&self, content: &str) -> bool {
        if content.len() < 20 {
            return false;
        }
        
        // Look for repeated substrings
        for i in 0..content.len() - 10 {
            let pattern = &content[i..i + 6];
            let occurrences = content.matches(pattern).count();
            if occurrences > 5 {
                return true;
            }
        }
        
        false
    }

    pub fn find_suspicious_objects(&self, objects: &[PdfObjectInfo]) -> Vec<SuspiciousObject> {
        let mut suspicious = Vec::new();
        
        for obj in objects {
            let content_str = std::str::from_utf8(&obj.content).unwrap_or("");
            
            // Check for JavaScript
            if content_str.contains("/JavaScript") || content_str.contains("/JS") {
                suspicious.push(SuspiciousObject {
                    object_number: obj.object_number,
                    generation: obj.generation,
                    reason: "Contains JavaScript".to_string(),
                    severity: SuspiciousSeverity::High,
                });
            }
            
            // Check for actions
            if content_str.contains("/Action") {
                suspicious.push(SuspiciousObject {
                    object_number: obj.object_number,
                    generation: obj.generation,
                    reason: "Contains action".to_string(),
                    severity: SuspiciousSeverity::Medium,
                });
            }
            
            // Check for suspicious keywords
            let suspicious_keywords = [
                "eval(", "unescape(", "String.fromCharCode",
                "/Launch", "/SubmitForm", "/ImportData"
            ];
            
            for keyword in &suspicious_keywords {
                if content_str.contains(keyword) {
                    suspicious.push(SuspiciousObject {
                        object_number: obj.object_number,
                        generation: obj.generation,
                        reason: format!("Contains suspicious keyword: {}", keyword),
                        severity: SuspiciousSeverity::High,
                    });
                }
            }
        }
        
        suspicious
    }

    pub fn extract_javascript_content(&self, obj: &PdfObjectInfo) -> Option<String> {
        let content_str = std::str::from_utf8(&obj.content).unwrap_or("");
        
        // Look for JavaScript content between parentheses or in streams
        if let Some(start) = content_str.find('(') {
            if let Some(end) = content_str[start..].find(')') {
                let js_content = &content_str[start + 1..start + end];
                if !js_content.is_empty() {
                    return Some(js_content.to_string());
                }
            }
        }
        
        None
    }

    pub fn validate_object_references(&self, objects: &[PdfObjectInfo]) -> Vec<ReferenceIssue> {
        let mut issues = Vec::new();
        
        // Create a map of existing objects
        let mut object_map = std::collections::HashMap::new();
        for obj in objects {
            object_map.insert((obj.object_number, obj.generation), obj);
        }
        
        // Check for dangling references
        for obj in objects {
            let content_str = std::str::from_utf8(&obj.content).unwrap_or("");
            
            // Find object references (simplified pattern matching)
            for word in content_str.split_whitespace() {
                if word.ends_with('R') && word.len() > 3 {
                    if let Some(ref_part) = word.strip_suffix('R') {
                        let parts: Vec<&str> = ref_part.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let (Ok(obj_num), Ok(gen_num)) = (parts[0].parse::<u32>(), parts[1].parse::<u16>()) {
                                if !object_map.contains_key(&(obj_num, gen_num)) {
                                    issues.push(ReferenceIssue {
                                        referencing_object: obj.object_number,
                                        referenced_object: obj_num,
                                        referenced_generation: gen_num,
                                        issue_type: ReferenceIssueType::DanglingReference,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        issues
    }
}

#[derive(Debug, Clone)]
pub struct ObjectScanResult {
    pub total_objects: usize,
    pub suspicious_objects: Vec<SuspiciousObject>,
    pub javascript_objects: usize,
    pub action_objects: usize,
    pub form_objects: usize,
    pub embedded_files: usize,
    pub risk_score: f64,
}

impl ObjectScanResult {
    pub fn new() -> Self {
        Self {
            total_objects: 0,
            suspicious_objects: Vec::new(),
            javascript_objects: 0,
            action_objects: 0,
            form_objects: 0,
            embedded_files: 0,
            risk_score: 0.0,
        }
    }

    pub fn add_suspicious_object(&mut self, obj: SuspiciousObject) {
        self.suspicious_objects.push(obj);
    }

    pub fn calculate_statistics(&mut self) {
        self.total_objects = self.suspicious_objects.len();
        
        // Calculate risk score based on findings
        let mut score = 0.0;
        
        for obj in &self.suspicious_objects {
            match obj.severity {
                SuspiciousSeverity::Critical => score += 25.0,
                SuspiciousSeverity::High => score += 15.0,
                SuspiciousSeverity::Medium => score += 10.0,
                SuspiciousSeverity::Low => score += 5.0,
            }
        }
        
        // Additional scoring for specific object types
        score += self.javascript_objects as f64 * 10.0;
        score += self.action_objects as f64 * 5.0;
        
        self.risk_score = score.min(100.0);
    }
}

#[derive(Debug, Clone)]
pub struct ReferenceIssue {
    pub referencing_object: u32,
    pub referenced_object: u32,
    pub referenced_generation: u16,
    pub issue_type: ReferenceIssueType,
}

#[derive(Debug, Clone)]
pub enum ReferenceIssueType {
    DanglingReference,
    CircularReference,
    InvalidGeneration,
}

impl Default for ObjectScanner {
    fn default() -> Self {
        Self::new()
    }
}
