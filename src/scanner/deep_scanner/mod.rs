
use crate::error::Result;
use crate::types::Document;
use crate::scanner::signature_scanner::{SignatureScanner, SignatureMatch};
use crate::scanner::object_scanner::{ObjectScanner, SuspiciousObject};
use crate::scanner::stream_scanner::{StreamScanner, SuspiciousStream};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DeepScanner {
    pub analysis_options: AnalysisOptions,
    signature_scanner: SignatureScanner,
    object_scanner: ObjectScanner,
    stream_scanner: StreamScanner,
}

#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    pub analyze_structure: bool,
    pub analyze_objects: bool,
    pub analyze_streams: bool,
    pub analyze_metadata: bool,
    pub analyze_signatures: bool,
    pub analyze_entropy: bool,
    pub max_depth: usize,
    pub max_scan_size: usize,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            analyze_structure: true,
            analyze_objects: true,
            analyze_streams: true,
            analyze_metadata: true,
            analyze_signatures: true,
            analyze_entropy: true,
            max_depth: 10,
            max_scan_size: 50_000_000, // 50MB
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanResult {
    pub structure_analysis: Option<StructureAnalysis>,
    pub object_analysis: Option<ObjectAnalysis>,
    pub stream_analysis: Option<StreamAnalysis>,
    pub metadata_analysis: Option<MetadataAnalysis>,
    pub signature_analysis: Option<SignatureAnalysis>,
    pub entropy_analysis: Option<EntropyAnalysis>,
    pub risk_score: f64,
    pub scan_duration_ms: u64,
    pub total_issues: usize,
}

impl DeepScanResult {
    pub fn new() -> Self {
        Self {
            structure_analysis: None,
            object_analysis: None,
            stream_analysis: None,
            metadata_analysis: None,
            signature_analysis: None,
            entropy_analysis: None,
            risk_score: 0.0,
            scan_duration_ms: 0,
            total_issues: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureAnalysis {
    pub pdf_version: Option<String>,
    pub object_count: usize,
    pub stream_count: usize,
    pub page_count: usize,
    pub xref_sections: usize,
    pub trailer_count: usize,
    pub eof_count: usize,
    pub linearized: bool,
    pub encrypted: bool,
    pub issues: Vec<StructureIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureIssue {
    pub severity: IssueSeverity,
    pub description: String,
    pub location: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectAnalysis {
    pub total_objects: usize,
    pub suspicious_objects: Vec<SuspiciousObject>,
    pub javascript_objects: usize,
    pub form_objects: usize,
    pub embedded_files: usize,
    pub action_objects: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamAnalysis {
    pub total_streams: usize,
    pub suspicious_streams: Vec<SuspiciousStream>,
    pub compressed_streams: usize,
    pub encrypted_streams: usize,
    pub filter_usage: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataAnalysis {
    pub info_dict_present: bool,
    pub xmp_metadata_present: bool,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
    pub producer: Option<String>,
    pub creator: Option<String>,
    pub suspicious_metadata: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureAnalysis {
    pub total_matches: usize,
    pub signature_matches: Vec<SignatureMatch>,
    pub malicious_patterns: usize,
    pub suspicious_patterns: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    pub overall_entropy: f64,
    pub high_entropy_regions: Vec<EntropyRegion>,
    pub compressed_ratio: f64,
    pub randomness_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyRegion {
    pub offset: usize,
    pub length: usize,
    pub entropy: f64,
    pub description: String,
}

impl DeepScanner {
    pub fn new() -> Self {
        Self {
            analysis_options: AnalysisOptions::default(),
            signature_scanner: SignatureScanner::new(),
            object_scanner: ObjectScanner::new(),
            stream_scanner: StreamScanner::new(),
        }
    }

    pub fn with_options(mut self, options: AnalysisOptions) -> Self {
        self.analysis_options = options;
        self
    }

    pub async fn perform_deep_scan(&self, document: &Document) -> Result<DeepScanResult> {
        let start_time = std::time::Instant::now();
        let mut result = DeepScanResult::new();
        
        // Read document content
        let content = std::fs::read(&document.path)?;
        
        // Perform structure analysis
        if self.analysis_options.analyze_structure {
            result.structure_analysis = Some(self.analyze_structure(&content)?);
        }
        
        // Perform object analysis
        if self.analysis_options.analyze_objects {
            result.object_analysis = Some(self.analyze_objects(&content)?);
        }
        
        // Perform stream analysis
        if self.analysis_options.analyze_streams {
            result.stream_analysis = Some(self.analyze_streams(&content)?);
        }
        
        // Perform metadata analysis
        if self.analysis_options.analyze_metadata {
            result.metadata_analysis = Some(self.analyze_metadata(&content)?);
        }

        // Perform signature analysis
        if self.analysis_options.analyze_signatures {
            result.signature_analysis = Some(self.analyze_signatures(&content)?);
        }

        // Perform entropy analysis
        if self.analysis_options.analyze_entropy {
            result.entropy_analysis = Some(self.analyze_entropy(&content)?);
        }
        
        // Calculate overall risk score
        result.risk_score = self.calculate_risk_score(&result);
        result.total_issues = self.count_total_issues(&result);
        result.scan_duration_ms = start_time.elapsed().as_millis() as u64;
        
        Ok(result)
    }

    fn analyze_structure(&self, content: &[u8]) -> Result<StructureAnalysis> {
        let mut analysis = StructureAnalysis {
            pdf_version: None,
            object_count: 0,
            stream_count: 0,
            page_count: 0,
            xref_sections: 0,
            trailer_count: 0,
            eof_count: 0,
            linearized: false,
            encrypted: false,
            issues: Vec::new(),
        };

        // Extract PDF version
        analysis.pdf_version = self.extract_pdf_version(content);

        // Count objects
        analysis.object_count = self.count_objects(content);
        
        // Count streams
        analysis.stream_count = self.count_streams(content);
        
        // Count pages
        analysis.page_count = self.count_pages(content);
        
        // Count xref sections
        analysis.xref_sections = self.count_xref_sections(content);
        
        // Count trailers
        analysis.trailer_count = self.count_trailers(content);
        
        // Count EOF markers
        analysis.eof_count = self.count_eof_markers(content);
        
        // Check if linearized
        analysis.linearized = self.is_linearized(content);
        
        // Check if encrypted
        analysis.encrypted = self.is_encrypted(content);
        
        // Validate structure and add issues
        self.validate_structure_integrity(content, &mut analysis);

        Ok(analysis)
    }

    fn analyze_objects(&self, content: &[u8]) -> Result<ObjectAnalysis> {
        let objects = self.extract_pdf_objects(content);
        let suspicious_objects = self.object_scanner.find_suspicious_objects(&objects);
        
        let mut javascript_objects = 0;
        let mut form_objects = 0;
        let mut embedded_files = 0;
        let mut action_objects = 0;

        for obj in &objects {
            let content_str = std::str::from_utf8(&obj.content).unwrap_or("");
            
            if content_str.contains("/JavaScript") || content_str.contains("/JS") {
                javascript_objects += 1;
            }
            if content_str.contains("/AcroForm") {
                form_objects += 1;
            }
            if content_str.contains("/EmbeddedFile") {
                embedded_files += 1;
            }
            if content_str.contains("/Action") {
                action_objects += 1;
            }
        }

        Ok(ObjectAnalysis {
            total_objects: objects.len(),
            suspicious_objects,
            javascript_objects,
            form_objects,
            embedded_files,
            action_objects,
        })
    }

    fn analyze_streams(&self, content: &[u8]) -> Result<StreamAnalysis> {
        let streams = self.extract_pdf_streams(content);
        let suspicious_streams = self.stream_scanner.find_suspicious_streams(&streams);
        
        let mut compressed_streams = 0;
        let mut encrypted_streams = 0;
        let mut filter_usage = HashMap::new();

        for stream in &streams {
            if !stream.filters.is_empty() {
                for filter in &stream.filters {
                    *filter_usage.entry(format!("{:?}", filter)).or_insert(0) += 1;
                    
                    match filter {
                        crate::scanner::stream_scanner::StreamFilter::FlateDecode |
                        crate::scanner::stream_scanner::StreamFilter::LZWDecode |
                        crate::scanner::stream_scanner::StreamFilter::RunLengthDecode => {
                            compressed_streams += 1;
                        }
                        crate::scanner::stream_scanner::StreamFilter::Crypt => {
                            encrypted_streams += 1;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(StreamAnalysis {
            total_streams: streams.len(),
            suspicious_streams,
            compressed_streams,
            encrypted_streams,
            filter_usage,
        })
    }

    fn analyze_metadata(&self, content: &[u8]) -> Result<MetadataAnalysis> {
        let mut analysis = MetadataAnalysis {
            info_dict_present: false,
            xmp_metadata_present: false,
            creation_date: None,
            modification_date: None,
            producer: None,
            creator: None,
            suspicious_metadata: Vec::new(),
        };

        // Check for Info dictionary
        if content.windows(5).any(|w| w == b"/Info") {
            analysis.info_dict_present = true;
        }

        // Check for XMP metadata
        if content.windows(10).any(|w| w == b"xpacket") {
            analysis.xmp_metadata_present = true;
        }

        // Extract metadata fields (simplified extraction)
        let content_str = std::str::from_utf8(content).unwrap_or("");
        
        // Look for creation date
        if let Some(start) = content_str.find("/CreationDate") {
            if let Some(date) = self.extract_metadata_value(&content_str[start..], "/CreationDate") {
                analysis.creation_date = Some(date);
            }
        }

        // Look for modification date
        if let Some(start) = content_str.find("/ModDate") {
            if let Some(date) = self.extract_metadata_value(&content_str[start..], "/ModDate") {
                analysis.modification_date = Some(date);
            }
        }

        // Look for producer
        if let Some(start) = content_str.find("/Producer") {
            if let Some(producer) = self.extract_metadata_value(&content_str[start..], "/Producer") {
                analysis.producer = Some(producer);
            }
        }

        // Look for creator
        if let Some(start) = content_str.find("/Creator") {
            if let Some(creator) = self.extract_metadata_value(&content_str[start..], "/Creator") {
                analysis.creator = Some(creator);
            }
        }

        Ok(analysis)
    }

    fn analyze_signatures(&self, content: &[u8]) -> Result<SignatureAnalysis> {
        let signature_matches = self.signature_scanner.scan_bytes(content)?;
        
        let mut malicious_patterns = 0;
        let mut suspicious_patterns = 0;

        for signature_match in &signature_matches {
            match signature_match.signature_type {
                crate::scanner::signature_scanner::SignatureType::Malicious => malicious_patterns += 1,
                crate::scanner::signature_scanner::SignatureType::Suspicious => suspicious_patterns += 1,
                _ => {}
            }
        }

        Ok(SignatureAnalysis {
            total_matches: signature_matches.len(),
            signature_matches,
            malicious_patterns,
            suspicious_patterns,
        })
    }

    fn analyze_entropy(&self, content: &[u8]) -> Result<EntropyAnalysis> {
        let overall_entropy = self.calculate_shannon_entropy(content);
        let high_entropy_regions = self.find_high_entropy_regions(content);
        let compressed_ratio = self.estimate_compression_ratio(content);
        let randomness_score = self.calculate_randomness_score(content);

        Ok(EntropyAnalysis {
            overall_entropy,
            high_entropy_regions,
            compressed_ratio,
            randomness_score,
        })
    }

    fn calculate_risk_score(&self, result: &DeepScanResult) -> f64 {
        let mut score = 0.0;
        let mut factors = 0;

        // Structure analysis contribution
        if let Some(ref structure) = result.structure_analysis {
            if structure.eof_count != 1 {
                score += 20.0;
            }
            if structure.encrypted {
                score += 10.0;
            }
            score += structure.issues.len() as f64 * 5.0;
            factors += 1;
        }

        // Object analysis contribution
        if let Some(ref objects) = result.object_analysis {
            score += objects.suspicious_objects.len() as f64 * 15.0;
            score += objects.javascript_objects as f64 * 10.0;
            factors += 1;
        }

        // Stream analysis contribution
        if let Some(ref streams) = result.stream_analysis {
            score += streams.suspicious_streams.len() as f64 * 10.0;
            factors += 1;
        }

        // Signature analysis contribution
        if let Some(ref signatures) = result.signature_analysis {
            score += signatures.malicious_patterns as f64 * 25.0;
            score += signatures.suspicious_patterns as f64 * 15.0;
            factors += 1;
        }

        // Entropy analysis contribution
        if let Some(ref entropy) = result.entropy_analysis {
            if entropy.overall_entropy > 7.5 {
                score += 15.0;
            }
            score += entropy.high_entropy_regions.len() as f64 * 5.0;
            factors += 1;
        }

        // Normalize score (0-100)
        if factors > 0 {
            score = (score / factors as f64).min(100.0);
        }

        score
    }

    fn count_total_issues(&self, result: &DeepScanResult) -> usize {
        let mut count = 0;

        if let Some(ref structure) = result.structure_analysis {
            count += structure.issues.len();
        }
        if let Some(ref objects) = result.object_analysis {
            count += objects.suspicious_objects.len();
        }
        if let Some(ref streams) = result.stream_analysis {
            count += streams.suspicious_streams.len();
        }
        if let Some(ref signatures) = result.signature_analysis {
            count += signatures.malicious_patterns + signatures.suspicious_patterns;
        }

        count
    }

    // Helper methods for structure analysis
    fn extract_pdf_version(&self, content: &[u8]) -> Option<String> {
        if content.len() < 8 || !content.starts_with(b"%PDF-") {
            return None;
        }

        let header_end = std::cmp::min(content.len(), 20);
        let header = &content[5..header_end];
        
        if let Some(newline_pos) = header.iter().position(|&b| b == b'\n' || b == b'\r') {
            let version_bytes = &header[..newline_pos];
            if let Ok(version_str) = std::str::from_utf8(version_bytes) {
                return Some(version_str.to_string());
            }
        }

        None
    }

    fn count_objects(&self, content: &[u8]) -> usize {
        let pattern = b" obj";
        content.windows(pattern.len()).filter(|&w| w == pattern).count()
    }

    fn count_streams(&self, content: &[u8]) -> usize {
        let pattern = b"stream\n";
        content.windows(pattern.len()).filter(|&w| w == pattern).count() +
        content.windows(7).filter(|&w| w == b"stream\r").count()
    }

    fn count_pages(&self, content: &[u8]) -> usize {
        let pattern = b"/Type/Page";
        content.windows(pattern.len()).filter(|&w| w == pattern).count()
    }

    fn count_xref_sections(&self, content: &[u8]) -> usize {
        let pattern = b"xref\n";
        content.windows(pattern.len()).filter(|&w| w == pattern).count() +
        content.windows(5).filter(|&w| w == b"xref\r").count()
    }

    fn count_trailers(&self, content: &[u8]) -> usize {
        let pattern = b"trailer";
        content.windows(pattern.len()).filter(|&w| w == pattern).count()
    }

    fn count_eof_markers(&self, content: &[u8]) -> usize {
        let pattern = b"%%EOF";
        content.windows(pattern.len()).filter(|&w| w == pattern).count()
    }

    fn is_linearized(&self, content: &[u8]) -> bool {
        content.windows(11).any(|w| w == b"/Linearized")
    }

    fn is_encrypted(&self, content: &[u8]) -> bool {
        content.windows(8).any(|w| w == b"/Encrypt")
    }

    fn validate_structure_integrity(&self, content: &[u8], analysis: &mut StructureAnalysis) {
        // Check for proper PDF header
        if !content.starts_with(b"%PDF-") {
            analysis.issues.push(StructureIssue {
                severity: IssueSeverity::Critical,
                description: "Missing or invalid PDF header".to_string(),
                location: Some(0),
            });
        }

        // Check EOF count
        if analysis.eof_count == 0 {
            analysis.issues.push(StructureIssue {
                severity: IssueSeverity::Critical,
                description: "Missing %%EOF marker".to_string(),
                location: None,
            });
        } else if analysis.eof_count > 1 {
            analysis.issues.push(StructureIssue {
                severity: IssueSeverity::Medium,
                description: format!("Multiple %%EOF markers found: {}", analysis.eof_count),
                location: None,
            });
        }

        // Check object/stream ratio
        if analysis.stream_count > analysis.object_count {
            analysis.issues.push(StructureIssue {
                severity: IssueSeverity::Medium,
                description: "More streams than objects detected".to_string(),
                location: None,
            });
        }
    }

    fn extract_pdf_objects(&self, content: &[u8]) -> Vec<crate::scanner::object_scanner::PdfObjectInfo> {
        let mut objects = Vec::new();
        let content_str = std::str::from_utf8(content).unwrap_or("");
        
        // Simple object extraction (would need more sophisticated parsing in real implementation)
        let mut object_number = 1;
        for line in content_str.lines() {
            if line.contains(" obj") {
                objects.push(crate::scanner::object_scanner::PdfObjectInfo {
                    object_number,
                    generation: 0,
                    content: line.as_bytes().to_vec(),
                });
                object_number += 1;
            }
        }
        
        objects
    }

    fn extract_pdf_streams(&self, content: &[u8]) -> Vec<crate::scanner::stream_scanner::PdfStream> {
        let mut streams = Vec::new();
        let content_str = std::str::from_utf8(content).unwrap_or("");
        
        // Simple stream extraction
        for (i, line) in content_str.lines().enumerate() {
            if line.contains("stream") {
                streams.push(crate::scanner::stream_scanner::PdfStream {
                    dictionary: crate::scanner::stream_scanner::StreamDictionary {
                        length: Some(line.len()),
                        filters: Vec::new(),
                    },
                    data: line.as_bytes().to_vec(),
                    filters: Vec::new(),
                });
            }
        }
        
        streams
    }

    fn extract_metadata_value(&self, content: &str, key: &str) -> Option<String> {
        if let Some(start) = content.find(key) {
            let after_key = &content[start + key.len()..];
            if let Some(value_start) = after_key.find('(') {
                if let Some(value_end) = after_key[value_start..].find(')') {
                    let value = &after_key[value_start + 1..value_start + value_end];
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    fn calculate_shannon_entropy(&self, data: &[u8]) -> f64 {
        let mut frequency = [0u64; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &freq in &frequency {
            if freq > 0 {
                let p = freq as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    fn find_high_entropy_regions(&self, data: &[u8]) -> Vec<EntropyRegion> {
        let mut regions = Vec::new();
        let window_size = 1024;
        let threshold = 7.0;

        for i in (0..data.len()).step_by(window_size) {
            let end = std::cmp::min(i + window_size, data.len());
            let window = &data[i..end];
            let entropy = self.calculate_shannon_entropy(window);

            if entropy > threshold {
                regions.push(EntropyRegion {
                    offset: i,
                    length: end - i,
                    entropy,
                    description: "High entropy region detected".to_string(),
                });
            }
        }

        regions
    }

    fn estimate_compression_ratio(&self, data: &[u8]) -> f64 {
        // Simple compression ratio estimation
        use std::collections::HashMap;
        let mut byte_counts = HashMap::new();
        
        for &byte in data {
            *byte_counts.entry(byte).or_insert(0) += 1;
        }
        
        let unique_bytes = byte_counts.len() as f64;
        let total_bytes = data.len() as f64;
        
        unique_bytes / total_bytes
    }

    fn calculate_randomness_score(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        // Calculate runs of identical bytes
        let mut runs = 0;
        let mut current_run = 1;
        
        for i in 1..data.len() {
            if data[i] == data[i - 1] {
                current_run += 1;
            } else {
                runs += 1;
                current_run = 1;
            }
        }

        // More runs indicate less randomness
        let run_ratio = runs as f64 / data.len() as f64;
        (1.0 - run_ratio).max(0.0).min(1.0)
    }
}

impl Default for DeepScanner {
    fn default() -> Self {
        Self::new()
    }
}
