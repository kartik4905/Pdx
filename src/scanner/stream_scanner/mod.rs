
use crate::error::Result;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfStream {
    pub dictionary: StreamDictionary,
    pub data: Vec<u8>,
    pub filters: Vec<StreamFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamDictionary {
    pub length: Option<usize>,
    pub filters: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamFilter {
    FlateDecode,
    LZWDecode,
    RunLengthDecode,
    CCITTFaxDecode,
    JBIG2Decode,
    DCTDecode,
    JPXDecode,
    Crypt,
    ASCII85Decode,
    ASCIIHexDecode,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousStream {
    pub stream_index: usize,
    pub reason: String,
    pub severity: SuspiciousSeverity,
    pub filters: Vec<StreamFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuspiciousSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct StreamIntegrityIssue {
    pub stream_index: usize,
    pub issue_type: IntegrityIssueType,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum IntegrityIssueType {
    LengthMismatch,
    EmptyCompressedStream,
    InvalidFilter,
    CorruptedData,
    SuspiciousContent,
}

pub struct StreamScanner {
    max_decompression_size: usize,
    suspicious_patterns: Vec<Vec<u8>>,
}

impl StreamScanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            max_decompression_size: 50_000_000, // 50MB limit
            suspicious_patterns: Vec::new(),
        };
        scanner.load_suspicious_patterns();
        scanner
    }

    fn load_suspicious_patterns(&mut self) {
        self.suspicious_patterns = vec![
            b"eval(".to_vec(),
            b"unescape(".to_vec(),
            b"String.fromCharCode".to_vec(),
            b"document.write".to_vec(),
            b"ActiveXObject".to_vec(),
            b"WScript.Shell".to_vec(),
            b"cmd.exe".to_vec(),
            b"powershell".to_vec(),
            b"<script".to_vec(),
            b"javascript:".to_vec(),
            b"/Launch".to_vec(),
            b"/GoToR".to_vec(),
            b"/SubmitForm".to_vec(),
            b"/ImportData".to_vec(),
            b"exploit".to_vec(),
            b"shellcode".to_vec(),
            b"payload".to_vec(),
        ];
    }

    pub fn scan_streams(&self, streams: &[PdfStream]) -> Result<StreamScanResult> {
        let mut result = StreamScanResult::new();
        
        for (index, stream) in streams.iter().enumerate() {
            // Validate stream integrity
            let integrity_issues = self.validate_stream_integrity(&[stream.clone()]);
            result.integrity_issues.extend(integrity_issues);
            
            // Find suspicious streams
            let suspicious = self.analyze_stream_content(index, stream);
            if let Some(suspicious_stream) = suspicious {
                result.suspicious_streams.push(suspicious_stream);
            }
            
            // Analyze filters
            self.analyze_stream_filters(index, stream, &mut result);
            
            // Count stream types
            result.total_streams += 1;
            if !stream.filters.is_empty() {
                result.compressed_streams += 1;
            }
            
            // Check for encryption
            if stream.filters.iter().any(|f| matches!(f, StreamFilter::Crypt)) {
                result.encrypted_streams += 1;
            }
        }
        
        result.calculate_statistics();
        Ok(result)
    }

    fn validate_stream_integrity(&self, streams: &[PdfStream]) -> Vec<StreamIntegrityIssue> {
        let mut issues = Vec::new();
        
        for (index, stream) in streams.iter().enumerate() {
            // Check length consistency
            if let Some(declared_length) = stream.dictionary.length {
                if declared_length != stream.data.len() {
                    issues.push(StreamIntegrityIssue {
                        stream_index: index,
                        issue_type: IntegrityIssueType::LengthMismatch,
                        description: format!("Declared length {} does not match actual length {}", 
                                           declared_length, stream.data.len()),
                    });
                }
            }
            
            // Check for truncated streams
            if stream.data.is_empty() && !stream.filters.is_empty() {
                issues.push(StreamIntegrityIssue {
                    stream_index: index,
                    issue_type: IntegrityIssueType::EmptyCompressedStream,
                    description: "Compressed stream has no data".to_string(),
                });
            }
            
            // Validate filter chain
            if let Err(filter_issue) = self.validate_filter_chain(&stream.filters) {
                issues.push(StreamIntegrityIssue {
                    stream_index: index,
                    issue_type: IntegrityIssueType::InvalidFilter,
                    description: filter_issue,
                });
            }
        }
        
        issues
    }

    fn analyze_stream_content(&self, index: usize, stream: &PdfStream) -> Option<SuspiciousStream> {
        // Try to decompress and analyze content
        let content = match self.decompress_stream(stream) {
            Ok(data) => data,
            Err(_) => {
                // If decompression fails, analyze raw data
                stream.data.clone()
            }
        };
        
        // Check for JavaScript in streams
        if self.contains_javascript(&content) {
            return Some(SuspiciousStream {
                stream_index: index,
                reason: "Contains JavaScript code".to_string(),
                severity: SuspiciousSeverity::High,
                filters: stream.filters.clone(),
            });
        }
        
        // Check for suspicious filters
        for filter in &stream.filters {
            match filter {
                StreamFilter::Crypt => {
                    return Some(SuspiciousStream {
                        stream_index: index,
                        reason: "Uses Crypt filter".to_string(),
                        severity: SuspiciousSeverity::Medium,
                        filters: stream.filters.clone(),
                    });
                }
                StreamFilter::JBIG2Decode => {
                    return Some(SuspiciousStream {
                        stream_index: index,
                        reason: "Uses JBIG2Decode filter (potential exploit vector)".to_string(),
                        severity: SuspiciousSeverity::High,
                        filters: stream.filters.clone(),
                    });
                }
                _ => {}
            }
        }
        
        // Check for suspicious patterns
        for pattern in &self.suspicious_patterns {
            if content.windows(pattern.len()).any(|w| w == pattern) {
                return Some(SuspiciousStream {
                    stream_index: index,
                    reason: format!("Contains suspicious pattern: {:?}", 
                                  String::from_utf8_lossy(pattern)),
                    severity: SuspiciousSeverity::Medium,
                    filters: stream.filters.clone(),
                });
            }
        }
        
        // Check for high entropy (possible encrypted/compressed data)
        let entropy = self.calculate_entropy(&content);
        if entropy > 7.5 {
            return Some(SuspiciousStream {
                stream_index: index,
                reason: format!("High entropy content: {:.2}", entropy),
                severity: SuspiciousSeverity::Low,
                filters: stream.filters.clone(),
            });
        }
        
        None
    }

    fn analyze_stream_filters(&self, index: usize, stream: &PdfStream, result: &mut StreamScanResult) {
        for filter in &stream.filters {
            let filter_name = match filter {
                StreamFilter::FlateDecode => "FlateDecode",
                StreamFilter::LZWDecode => "LZWDecode",
                StreamFilter::RunLengthDecode => "RunLengthDecode",
                StreamFilter::CCITTFaxDecode => "CCITTFaxDecode",
                StreamFilter::JBIG2Decode => "JBIG2Decode",
                StreamFilter::DCTDecode => "DCTDecode",
                StreamFilter::JPXDecode => "JPXDecode",
                StreamFilter::Crypt => "Crypt",
                StreamFilter::ASCII85Decode => "ASCII85Decode",
                StreamFilter::ASCIIHexDecode => "ASCIIHexDecode",
                StreamFilter::Unknown(name) => name,
            };
            
            *result.filter_usage.entry(filter_name.to_string()).or_insert(0) += 1;
        }
    }

    fn decompress_stream(&self, stream: &PdfStream) -> Result<Vec<u8>> {
        let mut data = stream.data.clone();
        
        // Apply filters in reverse order
        for filter in stream.filters.iter().rev() {
            data = self.apply_filter_decode(&data, filter)?;
            
            // Safety check for decompression bomb
            if data.len() > self.max_decompression_size {
                return Err(crate::error::PdfError::Processing(
                    "Decompressed data exceeds size limit".to_string()
                ).into());
            }
        }
        
        Ok(data)
    }

    fn apply_filter_decode(&self, data: &[u8], filter: &StreamFilter) -> Result<Vec<u8>> {
        match filter {
            StreamFilter::FlateDecode => {
                use flate2::read::ZlibDecoder;
                use std::io::Read;
                
                let mut decoder = ZlibDecoder::new(data);
                let mut result = Vec::new();
                decoder.read_to_end(&mut result)?;
                Ok(result)
            }
            StreamFilter::ASCIIHexDecode => {
                self.decode_ascii_hex(data)
            }
            StreamFilter::ASCII85Decode => {
                self.decode_ascii85(data)
            }
            StreamFilter::RunLengthDecode => {
                self.decode_run_length(data)
            }
            _ => {
                // For unsupported filters, return original data
                Ok(data.to_vec())
            }
        }
    }

    fn decode_ascii_hex(&self, data: &[u8]) -> Result<Vec<u8>> {
        let hex_str = std::str::from_utf8(data)
            .map_err(|_| crate::error::PdfError::Processing("Invalid UTF-8 in hex data".to_string()))?;
        
        let mut result = Vec::new();
        let mut chars = hex_str.chars().filter(|c| c.is_ascii_hexdigit());
        
        while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
            let high_val = high.to_digit(16).unwrap() as u8;
            let low_val = low.to_digit(16).unwrap() as u8;
            result.push((high_val << 4) | low_val);
        }
        
        Ok(result)
    }

    fn decode_ascii85(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Simplified ASCII85 decoder
        let input = std::str::from_utf8(data)
            .map_err(|_| crate::error::PdfError::Processing("Invalid UTF-8 in ASCII85 data".to_string()))?;
        
        let mut result = Vec::new();
        let chars: Vec<char> = input.chars().filter(|c| *c >= '!' && *c <= 'u').collect();
        
        for chunk in chars.chunks(5) {
            if chunk.len() < 5 {
                break;
            }
            
            let mut value = 0u32;
            for (i, &c) in chunk.iter().enumerate() {
                value += ((c as u32) - 33) * 85_u32.pow(4 - i as u32);
            }
            
            result.extend_from_slice(&value.to_be_bytes());
        }
        
        Ok(result)
    }

    fn decode_run_length(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut i = 0;
        
        while i < data.len() {
            let length = data[i] as i8;
            i += 1;
            
            if length == -128 {
                // EOD marker
                break;
            } else if length >= 0 {
                // Copy next length+1 bytes literally
                let count = (length + 1) as usize;
                if i + count > data.len() {
                    break;
                }
                result.extend_from_slice(&data[i..i + count]);
                i += count;
            } else {
                // Repeat next byte -length+1 times
                let count = (-length + 1) as usize;
                if i >= data.len() {
                    break;
                }
                let byte_to_repeat = data[i];
                i += 1;
                result.extend(std::iter::repeat(byte_to_repeat).take(count));
            }
        }
        
        Ok(result)
    }

    fn validate_filter_chain(&self, filters: &[StreamFilter]) -> Result<(), String> {
        // Check for invalid filter combinations
        let has_crypt = filters.iter().any(|f| matches!(f, StreamFilter::Crypt));
        let has_compression = filters.iter().any(|f| matches!(f, 
            StreamFilter::FlateDecode | StreamFilter::LZWDecode | StreamFilter::RunLengthDecode
        ));
        
        if has_crypt && has_compression {
            // Encryption should typically come after compression
            let crypt_pos = filters.iter().position(|f| matches!(f, StreamFilter::Crypt));
            let compression_pos = filters.iter().position(|f| matches!(f, 
                StreamFilter::FlateDecode | StreamFilter::LZWDecode | StreamFilter::RunLengthDecode
            ));
            
            if let (Some(crypt), Some(comp)) = (crypt_pos, compression_pos) {
                if crypt > comp {
                    return Err("Crypt filter should come before compression filters".to_string());
                }
            }
        }
        
        Ok(())
    }

    fn contains_javascript(&self, data: &[u8]) -> bool {
        let js_patterns = [
            b"/JavaScript",
            b"/JS",
            b"eval(",
            b"function",
            b"var ",
            b"document.",
            b"window.",
        ];
        
        for pattern in &js_patterns {
            if data.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut frequency = [0u32; 256];
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

    pub fn find_suspicious_streams(&self, streams: &[PdfStream]) -> Vec<SuspiciousStream> {
        let mut suspicious = Vec::new();
        
        for (index, stream) in streams.iter().enumerate() {
            // Check for JavaScript in streams
            if self.contains_javascript(&stream.data) {
                suspicious.push(SuspiciousStream {
                    stream_index: index,
                    reason: "Contains JavaScript code".to_string(),
                    severity: SuspiciousSeverity::High,
                    filters: stream.filters.clone(),
                });
            }
            
            // Check for suspicious filters
            for filter in &stream.filters {
                match filter {
                    StreamFilter::Crypt => {
                        suspicious.push(SuspiciousStream {
                            stream_index: index,
                            reason: "Uses Crypt filter".to_string(),
                            severity: SuspiciousSeverity::Medium,
                            filters: stream.filters.clone(),
                        });
                    }
                    StreamFilter::JBIG2Decode => {
                        suspicious.push(SuspiciousStream {
                            stream_index: index,
                            reason: "Uses JBIG2Decode filter (potential exploit vector)".to_string(),
                            severity: SuspiciousSeverity::High,
                            filters: stream.filters.clone(),
                        });
                    }
                    _ => {}
                }
            }
        }
        
        suspicious
    }
}

#[derive(Debug, Clone)]
pub struct StreamScanResult {
    pub total_streams: usize,
    pub suspicious_streams: Vec<SuspiciousStream>,
    pub compressed_streams: usize,
    pub encrypted_streams: usize,
    pub filter_usage: std::collections::HashMap<String, usize>,
    pub integrity_issues: Vec<StreamIntegrityIssue>,
    pub risk_score: f64,
}

impl StreamScanResult {
    pub fn new() -> Self {
        Self {
            total_streams: 0,
            suspicious_streams: Vec::new(),
            compressed_streams: 0,
            encrypted_streams: 0,
            filter_usage: std::collections::HashMap::new(),
            integrity_issues: Vec::new(),
            risk_score: 0.0,
        }
    }

    pub fn calculate_statistics(&mut self) {
        // Calculate risk score
        let mut score = 0.0;
        
        for stream in &self.suspicious_streams {
            match stream.severity {
                SuspiciousSeverity::Critical => score += 25.0,
                SuspiciousSeverity::High => score += 15.0,
                SuspiciousSeverity::Medium => score += 10.0,
                SuspiciousSeverity::Low => score += 5.0,
            }
        }
        
        score += self.integrity_issues.len() as f64 * 5.0;
        score += self.encrypted_streams as f64 * 2.0;
        
        self.risk_score = score.min(100.0);
    }
}

impl Default for StreamScanner {
    fn default() -> Self {
        Self::new()
    }
}
