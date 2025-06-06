//! Compression handling implementation for PDF anti-forensics
//! Created: 2025-06-03 16:14:13 UTC
//! Author: kartik4091

use std::collections::HashMap;
use flate2::{write::DeflateEncoder, Compression};
use std::io::Write;
use weezl::{encode::Encoder as LzwEncoder, BitOrder};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    error::{Error, Result},
    types::{Document, Object, ObjectId, Stream},
};

/// Handles PDF compression operations
#[derive(Debug)]
pub struct CompressionHandler {
    /// Compression statistics
    stats: CompressionStats,
    
    /// Compression configurations
    configurations: HashMap<String, CompressionConfig>,
    
    /// Processing cache
    processing_cache: HashMap<ObjectId, ProcessingResult>,
}

/// Compression statistics
#[derive(Debug, Default)]
pub struct CompressionStats {
    /// Number of objects compressed
    pub objects_compressed: usize,
    
    /// Number of bytes before compression
    pub bytes_before: usize,
    
    /// Number of bytes after compression
    pub bytes_after: usize,
    
    /// Number of cache hits
    pub cache_hits: usize,
    
    /// Processing duration in milliseconds
    pub duration_ms: u64,
}

/// Compression configuration
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Compression method
    pub method: CompressionMethod,
    
    /// Compression level
    pub level: CompressionLevel,
    
    /// Processing options
    pub options: ProcessingOptions,
    
    /// Filter configuration
    pub filters: FilterConfig,
}

/// Compression methods supported
#[derive(Debug, Clone, PartialEq)]
pub enum CompressionMethod {
    /// No compression
    None,
    
    /// Deflate compression
    Deflate,
    
    /// LZW compression
    LZW,
    
    /// Run Length encoding
    RunLength,
    
    /// Custom compression method
    Custom(String),
}

/// Compression levels
#[derive(Debug, Clone, Copy)]
pub struct CompressionLevel {
    /// Level value (0-9)
    pub value: u32,
    
    /// Level type
    pub level_type: LevelType,
}

/// Level types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LevelType {
    /// No compression
    None,
    
    /// Fast compression
    Fast,
    
    /// Default compression
    Default,
    
    /// Best compression
    Best,
}

/// Processing options
#[derive(Debug, Clone)]
pub struct ProcessingOptions {
    /// Enable parallel processing
    pub parallel: bool,
    
    /// Enable caching
    pub enable_cache: bool,
    
    /// Chunk size in bytes
    pub chunk_size: usize,
    
    /// Memory limit in bytes
    pub memory_limit: usize,
}

/// Filter configuration
#[derive(Debug, Clone)]
pub struct FilterConfig {
    /// Include filters
    pub include: Vec<String>,
    
    /// Exclude filters
    pub exclude: Vec<String>,
    
    /// Filter mode
    pub mode: FilterMode,
}

/// Filter modes
#[derive(Debug, Clone, PartialEq)]
pub enum FilterMode {
    /// Include mode
    Include,
    
    /// Exclude mode
    Exclude,
    
    /// Both modes
    Both,
}

/// Processing result
#[derive(Debug, Clone)]
pub struct ProcessingResult {
    /// Original size
    pub original_size: usize,
    
    /// Compressed size
    pub compressed_size: usize,
    
    /// Compression ratio
    pub ratio: f64,
    
    /// Processing metadata
    pub metadata: ProcessingMetadata,
}

/// Processing metadata
#[derive(Debug, Clone)]
pub struct ProcessingMetadata {
    /// Processing duration
    pub duration: std::time::Duration,
    
    /// Memory usage
    pub memory_usage: usize,
    
    /// Method used
    pub method: CompressionMethod,
    
    /// Additional info
    pub info: HashMap<String, String>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            method: CompressionMethod::Deflate,
            level: CompressionLevel {
                value: 6,
                level_type: LevelType::Default,
            },
            options: ProcessingOptions {
                parallel: true,
                enable_cache: true,
                chunk_size: 65536,
                memory_limit: 1073741824, // 1GB
            },
            filters: FilterConfig {
                include: vec![],
                exclude: vec![],
                mode: FilterMode::Both,
            },
        }
    }
}

impl CompressionHandler {
    /// Create new compression handler instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            stats: CompressionStats::default(),
            configurations: HashMap::new(),
            processing_cache: HashMap::new(),
        })
    }
    
    /// Compress data using configured method
    fn compress_data(&self, data: &[u8], config: &CompressionConfig) -> Result<Vec<u8>> {
        match config.method {
            CompressionMethod::None => Ok(data.to_vec()),
            CompressionMethod::Deflate => self.compress_deflate(data, config.level),
            CompressionMethod::LZW => self.compress_lzw(data),
            CompressionMethod::RunLength => self.compress_rle(data),
            CompressionMethod::Custom(_) => Err(Error::CompressionError("Custom compression not implemented".to_string())),
        }
    }
    
    /// Compress using Deflate
    fn compress_deflate(&self, data: &[u8], level: CompressionLevel) -> Result<Vec<u8>> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(level.value));
        encoder.write_all(data)
            .map_err(|e| Error::CompressionError(format!("Deflate compression failed: {}", e)))?;
        encoder.finish().map_err(|e| Error::CompressionError(format!("Failed to finalize compression: {}", e)))
    }
    
    /// Compress using LZW (Implemented with `weezl`)
    fn compress_lzw(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = LzwEncoder::new(BitOrder::Msb, 8);
        let compressed = encoder.encode(data).collect::<Result<Vec<u8>, _>>()
            .map_err(|e| Error::CompressionError(format!("LZW compression failed: {:?}", e)))?;
        Ok(compressed)
    }
    
    /// Compress using Run Length Encoding
    fn compress_rle(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut compressed = Vec::new();
        let mut count = 1;
        let mut current = data[0];
        
        for &byte in &data[1..] {
            if byte == current && count < 255 {
                count += 1;
            } else {
                compressed.push(count);
                compressed.push(current);
                current = byte;
                count = 1;
            }
        }
        
        compressed.push(count);
        compressed.push(current);
        
        Ok(compressed)
    }
    
    /// Update the compression metadata
    fn update_metadata(&mut self, metadata: &mut ProcessingMetadata, method: CompressionMethod, duration: std::time::Duration) {
        metadata.method = method;
        metadata.duration = duration;
    }
    
    /// Compress individual object
    fn compress_object(&mut self, id: ObjectId, object: &mut Object, config: &CompressionConfig) -> Result<()> {
        // Check cache if enabled
        if config.options.enable_cache {
            if let Some(cached) = self.check_cache(id)? {
                self.stats.cache_hits += 1;
                return Ok(());
            }
        }
        
        match object {
            Object::Stream(stream) => {
                let original_size = stream.data.len();
                self.stats.bytes_before += original_size;
                
                // Start timer for processing metadata
                let start_time = std::time::Instant::now();
                
                // Compress stream data
                let compressed_data = self.compress_data(&stream.data, config)?;
                
                // Update stream
                stream.data = compressed_data;
                
                // Update filters
                self.update_filters(&mut stream.dict, &config.method)?;
                
                // Update metadata
                let duration = start_time.elapsed();
                let mut metadata = ProcessingMetadata {
                    duration,
                    memory_usage: original_size + stream.data.len(), // Estimate memory usage
                    method: config.method.clone(),
                    info: HashMap::new(),
                };
                self.update_metadata(&mut metadata, config.method.clone(), duration);
                
                let compressed_size = stream.data.len();
                self.stats.bytes_after += compressed_size;
                
                // Update cache if enabled
                if config.options.enable_cache {
                    self.update_cache(id, original_size, compressed_size, config.method.clone())?;
                }
                
                self.stats.objects_compressed += 1;
            }
            _ => {}
        }
        
        Ok(())
    }
    
    /// Update stream filters
    fn update_filters(&self, dict: &mut HashMap<Vec<u8>, Object>, method: &CompressionMethod) -> Result<()> {
        let filter_name = match method {
            CompressionMethod::Deflate => b"FlateDecode".to_vec(),
            CompressionMethod::LZW => b"LZWDecode".to_vec(),
            CompressionMethod::RunLength => b"RunLengthDecode".to_vec(),
            _ => return Ok(()),
        };
        
        dict.insert(b"Filter".to_vec(), Object::Name(filter_name));
        Ok(())
    }
    
    /// Check processing cache
    fn check_cache(&self, id: ObjectId) -> Result<Option<ProcessingResult>> {
        Ok(self.processing_cache.get(&id).cloned())
    }
    
    /// Update processing cache
    fn update_cache(&mut self, id: ObjectId, original_size: usize, compressed_size: usize, method: CompressionMethod) -> Result<()> {
        let result = ProcessingResult {
            original_size,
            compressed_size,
            ratio: compressed_size as f64 / original_size as f64,
            metadata: ProcessingMetadata {
                duration: std::time::Duration::from_secs(0),
                memory_usage: original_size + compressed_size, // Estimate memory usage
                method,
                info: HashMap::new(),
            },
        };
        
        self.processing_cache.insert(id, result);
        Ok(())
    }
    
    /// Expose chaining compression for multi-stage compression pipelines
    pub fn chain_compressions(&self, data: &[u8], methods: &[CompressionMethod]) -> Result<Vec<u8>> {
        let mut intermediate_data = data.to_vec();
        for method in methods {
            let config = CompressionConfig {
                method: method.clone(),
                ..CompressionConfig::default()
            };
            intermediate_data = self.compress_data(&intermediate_data, &config)?;
        }
        Ok(intermediate_data)
    }

    /// Get compression statistics
    pub fn statistics(&self) -> &CompressionStats {
        &self.stats
    }
    
    /// Reset handler state
    pub fn reset(&mut self) {
        self.stats = CompressionStats::default();
        self.processing_cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn setup_test_handler() -> CompressionHandler {
        CompressionHandler::new().unwrap()
    }
    
    fn create_test_stream() -> Stream {
        Stream {
            dict: HashMap::new(),
            data: vec![1, 2, 3, 4, 5],
        }
    }
    
    #[test]
    fn test_handler_initialization() {
        let handler = setup_test_handler();
        assert!(handler.processing_cache.is_empty());
    }
    
    #[test]
    fn test_deflate_compression() {
        let handler = setup_test_handler();
        let data = vec![1, 2, 3, 4, 5];
        let config = CompressionConfig::default();
        
        let compressed = handler.compress_deflate(&data, config.level).unwrap();
        assert!(!compressed.is_empty());
    }
    
    #[test]
    fn test_lzw_compression() {
        let handler = setup_test_handler();
        let data = vec![1, 2, 3, 1, 1, 2, 3, 3, 3];
        
        let compressed = handler.compress_lzw(&data).unwrap();
        assert!(!compressed.is_empty());
        
        let encoder = LzwEncoder::new(BitOrder::Msb, 8);
        let roundtrip = encoder.decode(&compressed).collect::<Result<Vec<u8>, _>>().unwrap();
        assert_eq!(data, roundtrip);
    }
    
    #[test]
    fn test_rle_compression() {
        let handler = setup_test_handler();
        let data = vec![1, 1, 1, 2, 2, 3];
        
        let compressed = handler.compress_rle(&data).unwrap();
        assert!(!compressed.is_empty());
    }
    
    #[test]
    fn test_filter_matching() {
        let handler = setup_test_handler();
        let mut dict = HashMap::new();
        dict.insert(b"Filter".to_vec(), Object::Name(b"FlateDecode".to_vec()));
        
        assert!(handler.matches_filters(&dict, &vec!["FlateDecode".to_string()]));
    }
    
    #[test]
    fn test_cache_operations() {
        let mut handler = setup_test_handler();
        let id = ObjectId { number: 1, generation: 0 };
        
        handler.update_cache(id, 100, 50, CompressionMethod::Deflate).unwrap();
        assert!(handler.check_cache(id).unwrap().is_some());
    }
    
    #[test]
    fn test_handler_reset() {
        let mut handler = setup_test_handler();
        let id = ObjectId { number: 1, generation: 0 };
        
        handler.stats.objects_compressed = 1;
        handler.update_cache(id, 100, 50, CompressionMethod::Deflate).unwrap();
        
        handler.reset();
        
        assert_eq!(handler.stats.objects_compressed, 0);
        assert!(handler.processing_cache.is_empty());
    }
    
    #[test]
    fn test_chain_compressions() {
        let handler = setup_test_handler();
        let data = vec![1, 2, 3, 4, 5];
        let methods = vec![CompressionMethod::Deflate, CompressionMethod::RunLength];
        
        let compressed = handler.chain_compressions(&data, &methods).unwrap();
        assert!(!compressed.is_empty());
    }
}
