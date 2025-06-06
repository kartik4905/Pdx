//! Output module for PDF anti-forensics
//! Created: 2025-06-03 16:18:02 UTC
//! Author: kartik4091

use std::collections::HashMap;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    error::{Error, Result},
    types::{Document, Object, ObjectId},
};

// Public module exports
pub mod output_generator;
pub mod pdf_rebuilder;
pub mod compression_handler;
pub mod hash_generator;

// Re-exports for convenient access
pub use output_generator::{OutputGenerator, GenerationStats as OutputStats, OutputConfig};
pub use pdf_rebuilder::{PdfRebuilder, RebuildingStats, RebuildingConfig};
pub use compression_handler::{CompressionHandler, CompressionStats, CompressionConfig};
pub use hash_generator::{HashGenerator, HashingStats, HashConfig};

/// Comprehensive output processing statistics
#[derive(Debug, Default)]
pub struct OutputProcessingStats {
    /// Output generation statistics
    pub output_stats: OutputStats,
    
    /// PDF rebuilding statistics
    pub rebuilding_stats: RebuildingStats,
    
    /// Compression statistics
    pub compression_stats: CompressionStats,
    
    /// Hashing statistics
    pub hashing_stats: HashingStats,
    
    /// Total processing duration in milliseconds
    pub total_duration_ms: u64,
}

/// Complete output processing configuration
#[derive(Debug, Clone)]
pub struct OutputProcessingConfig {
    /// Output generation configuration
    pub output: Option<OutputConfig>,
    
    /// PDF rebuilding configuration
    pub rebuilding: Option<RebuildingConfig>,
    
    /// Compression configuration
    pub compression: Option<CompressionConfig>,
    
    /// Hashing configuration
    pub hashing: Option<HashConfig>,
    
    /// Processing order
    pub processing_order: ProcessingOrder,
}

/// Processing order configuration
#[derive(Debug, Clone)]
pub struct ProcessingOrder {
    /// Processing steps
    pub steps: Vec<ProcessingStep>,
    
    /// Parallel processing where possible
    pub enable_parallel: bool,
}

/// Processing step types
#[derive(Debug, Clone, PartialEq)]
pub enum ProcessingStep {
    /// Output generation
    Output,
    
    /// PDF rebuilding
    Rebuilding,
    
    /// Compression
    Compression,
    
    /// Hashing
    Hashing,
}

impl Default for ProcessingOrder {
    fn default() -> Self {
        Self {
            steps: vec![
                ProcessingStep::Compression,
                ProcessingStep::Rebuilding,
                ProcessingStep::Hashing,
                ProcessingStep::Output,
            ],
            enable_parallel: false,
        }
    }
}

impl Default for OutputProcessingConfig {
    fn default() -> Self {
        Self {
            output: Some(OutputConfig::default()),
            rebuilding: Some(RebuildingConfig::default()),
            compression: Some(CompressionConfig::default()),
            hashing: Some(HashConfig::default()),
            processing_order: ProcessingOrder::default(),
        }
    }
}

/// Main output manager handling all output processing operations
#[derive(Debug)]
pub struct OutputManager {
    /// Output generator
    output_generator: OutputGenerator,
    
    /// PDF rebuilder
    pdf_rebuilder: PdfRebuilder,
    
    /// Compression handler
    compression_handler: CompressionHandler,
    
    /// Hash generator
    hash_generator: HashGenerator,
    
    /// Processing statistics
    stats: OutputProcessingStats,
}

impl OutputManager {
    /// Create new output manager instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            output_generator: OutputGenerator::new()?,
            pdf_rebuilder: PdfRebuilder::new()?,
            compression_handler: CompressionHandler::new()?,
            hash_generator: HashGenerator::new()?,
            stats: OutputProcessingStats::default(),
        })
    }
    
    /// Process document output
    #[instrument(skip(self, document, config))]
    pub async fn process_output(&mut self, document: &mut Document, config: &OutputProcessingConfig) -> Result<Vec<u8>> {
        let start_time = std::time::Instant::now();
        info!("Starting output processing");
        
        let output = if config.processing_order.enable_parallel {
            self.process_output_parallel(document, config).await?
        } else {
            self.process_output_sequential(document, config).await?
        };
        
        // Update total statistics
        self.update_statistics();
        
        self.stats.total_duration_ms = start_time.elapsed().as_millis() as u64;
        info!("Output processing completed successfully");
        
        Ok(output)
    }
    
    /// Process output sequentially
    async fn process_output_sequential(&mut self, document: &mut Document, config: &OutputProcessingConfig) -> Result<Vec<u8>> {
        let mut processed_document = document.clone();
        
        for step in &config.processing_order.steps {
            match step {
                ProcessingStep::Compression => {
                    if let Some(compression_config) = &config.compression {
                        debug!("Applying compression");
                        self.compression_handler.compress_document(&mut processed_document, compression_config)?;
                    }
                }
                ProcessingStep::Rebuilding => {
                    if let Some(rebuilding_config) = &config.rebuilding {
                        debug!("Rebuilding PDF");
                        self.pdf_rebuilder.rebuild_document(&mut processed_document, rebuilding_config)?;
                    }
                }
                ProcessingStep::Hashing => {
                    if let Some(hashing_config) = &config.hashing {
                        debug!("Generating hashes");
                        let _hash = self.hash_generator.generate_hash(&processed_document, hashing_config)?;
                    }
                }
                ProcessingStep::Output => {
                    if let Some(output_config) = &config.output {
                        debug!("Generating output");
                        return self.output_generator.generate_output(&processed_document, output_config);
                    }
                }
            }
        }
        
        Err(Error::OutputError("No output configuration provided".to_string()))
    }
    
    /// Process output in parallel
    async fn process_output_parallel(&mut self, document: &mut Document, config: &OutputProcessingConfig) -> Result<Vec<u8>> {
        use tokio::task;
        use std::sync::Arc;
        use parking_lot::RwLock;
        
        let document = Arc::new(RwLock::new(document.clone()));
        let mut handles = Vec::new();
        
        for step in &config.processing_order.steps {
            match step {
                ProcessingStep::Compression => {
                    if let Some(compression_config) = &config.compression {
                        let doc = Arc::clone(&document);
                        let config = compression_config.clone();
                        handles.push(task::spawn(async move {
                            let mut handler = CompressionHandler::new()?;
                            let mut doc = doc.write();
                            handler.compress_document(&mut doc, &config)
                        }));
                    }
                }
                ProcessingStep::Rebuilding => {
                    if let Some(rebuilding_config) = &config.rebuilding {
                        let doc = Arc::clone(&document);
                        let config = rebuilding_config.clone();
                        handles.push(task::spawn(async move {
                            let mut rebuilder = PdfRebuilder::new()?;
                            let mut doc = doc.write();
                            rebuilder.rebuild_document(&mut doc, &config)
                        }));
                    }
                }
                ProcessingStep::Hashing => {
                    if let Some(hashing_config) = &config.hashing {
                        let doc = Arc::clone(&document);
                        let config = hashing_config.clone();
                        handles.push(task::spawn(async move {
                            let mut generator = HashGenerator::new()?;
                            let doc = doc.read();
                            generator.generate_hash(&doc, &config)
                        }));
                    }
                }
                ProcessingStep::Output => {
                    if let Some(output_config) = &config.output {
                        let doc = Arc::clone(&document);
                        let config = output_config.clone();
                        let output_result = task::spawn(async move {
                            let mut generator = OutputGenerator::new()?;
                            let doc = doc.read();
                            generator.generate_output(&doc, &config)
                        });
                        handles.push(output_result);
                    }
                }
            }
        }
        
        // Wait for all tasks to complete
        for handle in handles {
            handle.await??;
        }
        
        // Generate final output
        if let Some(output_config) = &config.output {
            let doc = document.read();
            self.output_generator.generate_output(&doc, output_config)
        } else {
            Err(Error::OutputError("No output configuration provided".to_string()))
        }
    }
    
    /// Update total statistics
    fn update_statistics(&mut self) {
        self.stats.output_stats = *self.output_generator.statistics();
        self.stats.rebuilding_stats = *self.pdf_rebuilder.statistics();
        self.stats.compression_stats = *self.compression_handler.statistics();
        self.stats.hashing_stats = *self.hash_generator.statistics();
    }
    
    /// Get processing statistics
    pub fn statistics(&self) -> &OutputProcessingStats {
        &self.stats
    }
    
    /// Get output generator
    pub fn output_generator(&self) -> &OutputGenerator {
        &self.output_generator
    }
    
    /// Get PDF rebuilder
    pub fn pdf_rebuilder(&self) -> &PdfRebuilder {
        &self.pdf_rebuilder
    }
    
    /// Get compression handler
    pub fn compression_handler(&self) -> &CompressionHandler {
        &self.compression_handler
    }
    
    /// Get hash generator
    pub fn hash_generator(&self) -> &HashGenerator {
        &self.hash_generator
    }
    
    /// Reset manager state
    pub fn reset(&mut self) -> Result<()> {
        self.output_generator.reset();
        self.pdf_rebuilder.reset();
        self.compression_handler.reset();
        self.hash_generator.reset();
        self.stats = OutputProcessingStats::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn setup_test_manager() -> OutputManager {
        OutputManager::new().unwrap()
    }
    
    fn create_test_document() -> Document {
        Document::default()
    }
    
    #[tokio::test]
    async fn test_manager_initialization() {
        let manager = setup_test_manager();
        assert_eq!(manager.stats.total_duration_ms, 0);
    }
    
    #[tokio::test]
    async fn test_sequential_processing() {
        let mut manager = setup_test_manager();
        let mut document = create_test_document();
        
        let config = OutputProcessingConfig {
            processing_order: ProcessingOrder {
                enable_parallel: false,
                ..Default::default()
            },
            ..Default::default()
        };
        
        let result = manager.process_output(&mut document, &config).await;
        assert!(result.is_err()); // Expects error due to empty document
    }
    
    #[tokio::test]
    async fn test_parallel_processing() {
        let mut manager = setup_test_manager();
        let mut document = create_test_document();
        
        let config = OutputProcessingConfig {
            processing_order: ProcessingOrder {
                enable_parallel: true,
                ..Default::default()
            },
            ..Default::default()
        };
        
        let result = manager.process_output(&mut document, &config).await;
        assert!(result.is_err()); // Expects error due to empty document
    }
    
    #[test]
    fn test_statistics_update() {
        let mut manager = setup_test_manager();
        
        manager.output_generator.stats.bytes_written = 100;
        manager.pdf_rebuilder.stats.objects_rebuilt = 10;
        manager.compression_handler.stats.objects_compressed = 5;
        manager.hash_generator.stats.objects_hashed = 15;
        
        manager.update_statistics();
        
        assert_eq!(manager.stats.output_stats.bytes_written, 100);
        assert_eq!(manager.stats.rebuilding_stats.objects_rebuilt, 10);
        assert_eq!(manager.stats.compression_stats.objects_compressed, 5);
        assert_eq!(manager.stats.hashing_stats.objects_hashed, 15);
    }
    
    #[test]
    fn test_manager_reset() {
        let mut manager = setup_test_manager();
        
        manager.stats.total_duration_ms = 1000;
        assert!(manager.reset().is_ok());
        assert_eq!(manager.stats.total_duration_ms, 0);
    }
    
    #[test]
    fn test_processing_order() {
        let order = ProcessingOrder::default();
        assert_eq!(order.steps.len(), 4);
        assert!(!order.enable_parallel);
        
        // Verify correct order
        assert!(matches!(order.steps[0], ProcessingStep::Compression));
        assert!(matches!(order.steps[1], ProcessingStep::Rebuilding));
        assert!(matches!(order.steps[2], ProcessingStep::Hashing));
        assert!(matches!(order.steps[3], ProcessingStep::Output));
    }
}
