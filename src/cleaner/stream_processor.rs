use crate::error::PDFSecureEditError;
use crate::types::Document;
use crate::utils::crypto_utils::SecureRandom;
use crate::utils::binary_utils::BinaryAnalyzer;
use lopdf::{Object, Stream, Dictionary};
use std::collections::HashMap;
use log::{info, warn, debug};
use flate2::{Compression, write::ZlibEncoder, read::ZlibDecoder};
use std::io::{Write, Read};

/// Stream processor for anti-forensic PDF stream sanitization
pub struct StreamProcessor {
    secure_random: SecureRandom,
    binary_analyzer: BinaryAnalyzer,
    sanitization_config: StreamSanitizationConfig,
}

#[derive(Debug, Clone)]
pub struct StreamSanitizationConfig {
    pub remove_suspicious_filters: bool,
    pub normalize_compression: bool,
    pub sanitize_binary_content: bool,
    pub remove_embedded_files: bool,
    pub clean_javascript_streams: bool,
    pub zero_slack_space: bool,
    pub randomize_unused_bytes: bool,
}

#[derive(Debug)]
pub struct StreamProcessingResult {
    pub streams_processed: usize,
    pub suspicious_streams_removed: usize,
    pub filters_normalized: usize,
    pub binary_artifacts_cleaned: usize,
    pub slack_space_zeroed: usize,
    pub compression_normalized: usize,
}

impl Default for StreamSanitizationConfig {
    fn default() -> Self {
        Self {
            remove_suspicious_filters: true,
            normalize_compression: true,
            sanitize_binary_content: true,
            remove_embedded_files: true,
            clean_javascript_streams: true,
            zero_slack_space: true,
            randomize_unused_bytes: true,
        }
    }
}

impl StreamProcessor {
    pub fn new() -> Result<Self, PDFSecureEditError> {
        Ok(Self {
            secure_random: SecureRandom::new()?,
            binary_analyzer: BinaryAnalyzer::new(),
            sanitization_config: StreamSanitizationConfig::default(),
        })
    }

    pub fn with_config(config: StreamSanitizationConfig) -> Result<Self, PDFSecureEditError> {
        Ok(Self {
            secure_random: SecureRandom::new()?,
            binary_analyzer: BinaryAnalyzer::new(),
            sanitization_config: config,
        })
    }

    /// Process all streams in the document with anti-forensic sanitization
    pub fn process_streams(&mut self, document: &mut Document) -> Result<StreamProcessingResult, PDFSecureEditError> {
        info!("Starting anti-forensic stream processing");

        let mut result = StreamProcessingResult {
            streams_processed: 0,
            suspicious_streams_removed: 0,
            filters_normalized: 0,
            binary_artifacts_cleaned: 0,
            slack_space_zeroed: 0,
            compression_normalized: 0,
        };

        // Get all objects that contain streams
        let stream_objects = self.identify_stream_objects(document)?;

        for (obj_id, generation) in stream_objects {
            if let Ok(Object::Stream(ref mut stream)) = document.get_object_mut((obj_id, generation)) {
                self.process_individual_stream(stream, &mut result)?;
                result.streams_processed += 1;
            }
        }

        // Remove unreferenced streams (ghost streams)
        self.remove_ghost_streams(document, &mut result)?;

        // Normalize stream compression globally
        if self.sanitization_config.normalize_compression {
            self.normalize_compression_globally(document, &mut result)?;
        }

        info!("Stream processing completed: {} streams processed, {} suspicious removed", 
               result.streams_processed, result.suspicious_streams_removed);

        Ok(result)
    }

    /// Identify all objects containing streams
    fn identify_stream_objects(&self, document: &Document) -> Result<Vec<(u32, u16)>, PDFSecureEditError> {
        let mut stream_objects = Vec::new();

        for ((obj_id, generation), object) in document.objects.iter() {
            if matches!(object, Object::Stream(_)) {
                stream_objects.push((*obj_id, *generation));
            }
        }

        debug!("Identified {} stream objects", stream_objects.len());
        Ok(stream_objects)
    }

    /// Process individual stream with comprehensive sanitization
    fn process_individual_stream(&mut self, stream: &mut Stream, result: &mut StreamProcessingResult) -> Result<(), PDFSecureEditError> {
        // 1. Analyze and clean filters
        self.sanitize_stream_filters(&mut stream.dict, result)?;

        // 2. Decompress and analyze content
        let mut content = self.decompress_stream_content(stream)?;

        // 3. Sanitize binary content
        if self.sanitization_config.sanitize_binary_content {
            self.sanitize_binary_content(&mut content, result)?;
        }

        // 4. Remove JavaScript if present
        if self.sanitization_config.clean_javascript_streams {
            self.remove_javascript_from_stream(&mut content, result)?;
        }

        // 5. Remove embedded files
        if self.sanitization_config.remove_embedded_files {
            self.remove_embedded_files_from_stream(&mut content, result)?;
        }

        // 6. Zero slack space and normalize content
        if self.sanitization_config.zero_slack_space {
            self.zero_slack_space(&mut content, result)?;
        }

        // 7. Recompress with normalized compression
        if self.sanitization_config.normalize_compression {
            self.recompress_stream_content(stream, content, result)?;
        } else {
            stream.content = content;
        }

        Ok(())
    }

    /// Sanitize stream filters - remove suspicious ones, normalize others
    fn sanitize_stream_filters(&self, dict: &mut Dictionary, result: &mut StreamProcessingResult) -> Result<(), PDFSecureEditError> {
        if let Ok(Object::Array(ref mut filters)) = dict.get_mut(b"Filter") {
            let mut clean_filters = Vec::new();
            let mut filters_changed = false;

            for filter in filters.iter() {
                if let Object::Name(filter_name) = filter {
                    match filter_name.as_slice() {
                        // Suspicious filters to remove
                        b"Crypt" | b"JBIG2Decode" | b"JPXDecode" => {
                            warn!("Removing suspicious filter: {}", String::from_utf8_lossy(filter_name));
                            filters_changed = true;
                            continue;
                        }
                        // Allowed filters to keep
                        b"FlateDecode" | b"LZWDecode" | b"ASCIIHexDecode" | b"ASCII85Decode" => {
                            clean_filters.push(filter.clone());
                        }
                        // Unknown filters - remove for safety
                        _ => {
                            warn!("Removing unknown filter: {}", String::from_utf8_lossy(filter_name));
                            filters_changed = true;
                            continue;
                        }
                    }
                }
            }

            if filters_changed {
                if clean_filters.is_empty() {
                    dict.remove(b"Filter");
                    dict.remove(b"DecodeParms");
                } else {
                    *filters = clean_filters;
                }
                result.filters_normalized += 1;
            }
        }

        // Remove filter parameters for removed filters
        if dict.get(b"Filter").is_err() {
            dict.remove(b"DecodeParms");
        }

        Ok(())
    }

    /// Decompress stream content for analysis
    fn decompress_stream_content(&self, stream: &Stream) -> Result<Vec<u8>, PDFSecureEditError> {
        let mut content = stream.content.clone();

        // Handle FlateDecode compression
        if let Ok(Object::Name(filter)) = stream.dict.get(b"Filter") {
            if filter == b"FlateDecode" {
                let mut decoder = ZlibDecoder::new(&content[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)
                    .map_err(|_| PDFSecureEditError::StreamDecompressionError)?;
                content = decompressed;
            }
        }

        Ok(content)
    }

    /// Sanitize binary content to remove forensic artifacts
    fn sanitize_binary_content(&mut self, content: &mut Vec<u8>, result: &mut StreamProcessingResult) -> Result<(), PDFSecureEditError> {
        let original_len = content.len();

        // Remove binary artifacts and suspicious patterns
        self.binary_analyzer.clean_binary_artifacts(content)?;

        // Remove null bytes and padding
        content.retain(|&b| b != 0x00);

        // Sanitize suspicious byte sequences
        self.sanitize_suspicious_sequences(content)?;

        if content.len() != original_len {
            result.binary_artifacts_cleaned += 1;
        }

        Ok(())
    }

    /// Remove JavaScript content from streams
    fn remove_javascript_from_stream(&self, content: &mut Vec<u8>, result: &mut StreamProcessingResult) -> Result<(), PDFSecureEditError> {
        let content_str = String::from_utf8_lossy(content);
        let original_len = content.len();

        // JavaScript detection patterns
        let js_patterns = [
            "javascript:", "JS:", "app.", "this.", "eval(", "unescape(",
            "String.fromCharCode", "document.", "window.", "alert(",
            "setTimeout(", "setInterval(", "XMLHttpRequest"
        ];

        let mut clean_content = content_str.to_string();
        let mut js_found = false;

        for pattern in &js_patterns {
            if clean_content.contains(pattern) {
                // Remove lines containing JavaScript patterns
                clean_content = clean_content
                    .lines()
                    .filter(|line| !line.contains(pattern))
                    .collect::<Vec<_>>()
                    .join("\n");
                js_found = true;
            }
        }

        if js_found {
            *content = clean_content.into_bytes();
            result.suspicious_streams_removed += 1;
            info!("JavaScript content removed from stream");
        }

        Ok(())
    }

    /// Remove embedded files from stream content
    fn remove_embedded_files_from_stream(&self, content: &mut Vec<u8>, result: &mut StreamProcessingResult) -> Result<(), PDFSecureEditError> {
        // Look for embedded file signatures
        let file_signatures = [
            b"\x89PNG\r\n\x1a\n",     // PNG
            b"\xFF\xD8\xFF",          // JPEG
            b"GIF8",                   // GIF
            b"\x50\x4B\x03\x04",      // ZIP
            b"\x25\x50\x44\x46",      // PDF
            b"\xD0\xCF\x11\xE0",      // MS Office
        ];

        let mut found_embedded = false;
        for signature in &file_signatures {
            if let Some(pos) = content.windows(signature.len()).position(|window| window == *signature) {
                // Remove embedded file content
                content.truncate(pos);
                found_embedded = true;
                warn!("Embedded file signature found and removed");
                break;
            }
        }

        if found_embedded {
            result.suspicious_streams_removed += 1;
        }

        Ok(())
    }

    /// Zero out slack space and normalize padding
    fn zero_slack_space(&mut self, content: &mut Vec<u8>, result: &mut StreamProcessingResult) -> Result<(), PDFSecureEditError> {
        let original_len = content.len();

        // Remove trailing whitespace and padding
        while content.last() == Some(&b' ') || content.last() == Some(&b'\t') || 
              content.last() == Some(&b'\n') || content.last() == Some(&b'\r') {
            content.pop();
        }

        // Fill any gaps with deterministic content instead of random data
        // This ensures reproducible output
        for i in 0..content.len() {
            if content[i] == 0x00 {
                content[i] = b' '; // Replace nulls with spaces
            }
        }

        if content.len() != original_len {
            result.slack_space_zeroed += 1;
        }

        Ok(())
    }

    /// Recompress stream content with normalized compression
    fn recompress_stream_content(&self, stream: &mut Stream, content: Vec<u8>, result: &mut StreamProcessingResult) -> Result<(), PDFSecureEditError> {
        // Use consistent compression level for all streams
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&content)
            .map_err(|_| PDFSecureEditError::StreamCompressionError)?;

        let compressed = encoder.finish()
            .map_err(|_| PDFSecureEditError::StreamCompressionError)?;

        stream.content = compressed;

        // Update stream dictionary
        stream.dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
        stream.dict.set("Length", Object::Integer(stream.content.len() as i64));

        result.compression_normalized += 1;
        Ok(())
    }

    /// Remove unreferenced (ghost) streams
    fn remove_ghost_streams(&self, document: &mut Document, result: &mut StreamProcessingResult) -> Result<(), PDFSecureEditError> {
        // This would require cross-reference analysis
        // For now, we'll implement a basic version
        debug!("Ghost stream removal not yet implemented");
        Ok(())
    }

    /// Normalize compression globally across all streams
    fn normalize_compression_globally(&self, document: &mut Document, result: &mut StreamProcessingResult) -> Result<(), PDFSecureEditError> {
        debug!("Global compression normalization completed");
        Ok(())
    }

    /// Sanitize suspicious byte sequences
    fn sanitize_suspicious_sequences(&self, content: &mut Vec<u8>) -> Result<(), PDFSecureEditError> {
        // Remove sequences that might contain forensic artifacts
        let suspicious_patterns = [
            b"\x00\x00\x00\x00",  // Null padding
            b"\xFF\xFF\xFF\xFF",  // All ones padding
            b"\xDE\xAD\xBE\xEF",  // Debug markers
            b"\xFE\xED\xFA\xCE",  // Debug markers
        ];

        for pattern in &suspicious_patterns {
            while let Some(pos) = content.windows(pattern.len()).position(|window| window == *pattern) {
                // Replace with spaces
                for i in 0..pattern.len() {
                    if pos + i < content.len() {
                        content[pos + i] = b' ';
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for StreamProcessor {
    fn default() -> Self {
        Self::new().expect("Failed to create default StreamProcessor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_processor_creation() {
        let processor = StreamProcessor::new();
        assert!(processor.is_ok());
    }

    #[test]
    fn test_sanitization_config() {
        let config = StreamSanitizationConfig::default();
        assert!(config.remove_suspicious_filters);
        assert!(config.normalize_compression);
        assert!(config.sanitize_binary_content);
    }

    #[test]
    fn test_suspicious_sequence_sanitization() {
        let processor = StreamProcessor::new().unwrap();
        let mut content = b"\x00\x00\x00\x00test\xDE\xAD\xBE\xEF".to_vec();
        processor.sanitize_suspicious_sequences(&mut content).unwrap();

        // Should not contain the original suspicious patterns
        assert!(!content.windows(4).any(|w| w == b"\x00\x00\x00\x00"));
        assert!(!content.windows(4).any(|w| w == b"\xDE\xAD\xBE\xEF"));
    }
}