//! Content processing module for PDF anti-forensics
//! Created: 2025-06-03 15:29:09 UTC
//! Author: kartik4091

use std::collections::HashMap;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    error::{Error, Result},
    types::{Document, Object, ObjectId},
};

// Public module exports
pub mod content_processor;
pub mod font_processor;
pub mod image_processor;
pub mod resource_cleaner;

// Re-exports for convenient access
pub use content_processor::{ContentProcessor, ProcessingStats as ContentStats, ProcessingConfig as ContentConfig};
pub use font_processor::{FontProcessor, ProcessingStats as FontStats, ProcessingConfig as FontConfig};
pub use image_processor::{ImageProcessor, ProcessingStats as ImageStats, ProcessingConfig as ImageConfig};
pub use resource_cleaner::{ResourceCleaner, CleaningStats as ResourceStats, CleaningConfig as ResourceConfig};

/// Comprehensive content processing statistics
#[derive(Debug, Default)]
pub struct ContentProcessingStats {
    /// Content stream processing statistics
    pub content_stats: ContentStats,
    
    /// Font processing statistics
    pub font_stats: FontStats,
    
    /// Image processing statistics
    pub image_stats: ImageStats,
    
    /// Resource cleaning statistics
    pub resource_stats: ResourceStats,
    
    /// Total processing duration in milliseconds
    pub total_duration_ms: u64,
    
    /// Total bytes saved
    pub total_bytes_saved: u64,
}

/// Complete content processing configuration
#[derive(Debug, Clone)]
pub struct ContentProcessingConfig {
    /// Content stream processing configuration
    pub content: Option<ContentConfig>,
    
    /// Font processing configuration
    pub font: Option<FontConfig>,
    
    /// Image processing configuration
    pub image: Option<ImageConfig>,
    
    /// Resource cleaning configuration
    pub resource: Option<ResourceConfig>,
    
    /// Processing order
    pub processing_order: ProcessingOrder,
}

/// Processing order configuration
#[derive(Debug, Clone)]
pub struct ProcessingOrder {
    /// Order of operations
    pub steps: Vec<ProcessingStep>,
    
    /// Parallel processing where possible
    pub enable_parallel: bool,
}

/// Processing step types
#[derive(Debug, Clone, PartialEq)]
pub enum ProcessingStep {
    /// Content stream processing
    Content,
    
    /// Font processing
    Font,
    
    /// Image processing
    Image,
    
    /// Resource cleaning
    Resource,
}

/// Main content processor handling all content-related operations
#[derive(Debug)]
pub struct ContentManager {
    /// Content stream processor
    content_processor: ContentProcessor,
    
    /// Font processor
    font_processor: FontProcessor,
    
    /// Image processor
    image_processor: ImageProcessor,
    
    /// Resource cleaner
    resource_cleaner: ResourceCleaner,
    
    /// Processing statistics
    stats: ContentProcessingStats,
}

impl Default for ProcessingOrder {
    fn default() -> Self {
        Self {
            steps: vec![
                ProcessingStep::Content,
                ProcessingStep::Font,
                ProcessingStep::Image,
                ProcessingStep::Resource,
            ],
            enable_parallel: false,
        }
    }
}

impl Default for ContentProcessingConfig {
    fn default() -> Self {
        Self {
            content: Some(ContentConfig::default()),
            font: Some(FontConfig::default()),
            image: Some(ImageConfig::default()),
            resource: Some(ResourceConfig::default()),
            processing_order: ProcessingOrder::default(),
        }
    }
}

impl ContentManager {
    /// Create new content manager instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            content_processor: ContentProcessor::new()?,
            font_processor: FontProcessor::new()?,
            image_processor: ImageProcessor::new()?,
            resource_cleaner: ResourceCleaner::new()?,
            stats: ContentProcessingStats::default(),
        })
    }
    
    /// Process all content-related aspects
    #[instrument(skip(self, document, config))]
    pub async fn process_content(&mut self, document: &mut Document, config: &ContentProcessingConfig) -> Result<()> {
        let start_time = std::time::Instant::now();
        info!("Starting comprehensive content processing");
        
        if config.processing_order.enable_parallel {
            self.process_content_parallel(document, config).await?;
        } else {
            self.process_content_sequential(document, config).await?;
        }
        
        // Update total statistics
        self.update_statistics();
        
        self.stats.total_duration_ms = start_time.elapsed().as_millis() as u64;
        info!("Content processing completed successfully");
        Ok(())
    }
    
    /// Process content sequentially
    async fn process_content_sequential(&mut self, document: &mut Document, config: &ContentProcessingConfig) -> Result<()> {
        for step in &config.processing_order.steps {
            match step {
                ProcessingStep::Content => {
                    if let Some(content_config) = &config.content {
                        debug!("Processing content streams");
                        self.content_processor.process_content(document, content_config)?;
                    }
                }
                ProcessingStep::Font => {
                    if let Some(font_config) = &config.font {
                        debug!("Processing fonts");
                        self.font_processor.process_fonts(document, font_config)?;
                    }
                }
                ProcessingStep::Image => {
                    if let Some(image_config) = &config.image {
                        debug!("Processing images");
                        self.image_processor.process_images(document, image_config)?;
                    }
                }
                ProcessingStep::Resource => {
                    if let Some(resource_config) = &config.resource {
                        debug!("Cleaning resources");
                        self.resource_cleaner.clean_resources(document, resource_config)?;
                    }
                }
            }
        }
        Ok(())
    }
    
    /// Process content in parallel where possible
    async fn process_content_parallel(&mut self, document: &mut Document, config: &ContentProcessingConfig) -> Result<()> {
        use tokio::task;
        use std::sync::Arc;
        use parking_lot::RwLock;
        
        let document = Arc::new(RwLock::new(document));
        let mut handles = Vec::new();
        
        for step in &config.processing_order.steps {
            match step {
                ProcessingStep::Content => {
                    if let Some(content_config) = &config.content {
                        let doc = Arc::clone(&document);
                        let config = content_config.clone();
                        handles.push(task::spawn(async move {
                            let mut processor = ContentProcessor::new()?;
                            let mut doc = doc.write();
                            processor.process_content(&mut doc, &config)
                        }));
                    }
                }
                ProcessingStep::Font => {
                    if let Some(font_config) = &config.font {
                        let doc = Arc::clone(&document);
                        let config = font_config.clone();
                        handles.push(task::spawn(async move {
                            let mut processor = FontProcessor::new()?;
                            let mut doc = doc.write();
                            processor.process_fonts(&mut doc, &config)
                        }));
                    }
                }
                ProcessingStep::Image => {
                    if let Some(image_config) = &config.image {
                        let doc = Arc::clone(&document);
                        let config = image_config.clone();
                        handles.push(task::spawn(async move {
                            let mut processor = ImageProcessor::new()?;
                            let mut doc = doc.write();
                            processor.process_images(&mut doc, &config)
                        }));
                    }
                }
                ProcessingStep::Resource => {
                    if let Some(resource_config) = &config.resource {
                        let doc = Arc::clone(&document);
                        let config = resource_config.clone();
                        handles.push(task::spawn(async move {
                            let mut cleaner = ResourceCleaner::new()?;
                            let mut doc = doc.write();
                            cleaner.clean_resources(&mut doc, &config)
                        }));
                    }
                }
            }
        }
        
        // Wait for all tasks to complete
        for handle in handles {
            handle.await??;
        }
        
        Ok(())
    }
    
    /// Update total statistics
    fn update_statistics(&mut self) {
        self.stats.content_stats = *self.content_processor.statistics();
        self.stats.font_stats = *self.font_processor.statistics();
        self.stats.image_stats = *self.image_processor.statistics();
        self.stats.resource_stats = *self.resource_cleaner.statistics();
        
        // Calculate total bytes saved
        self.stats.total_bytes_saved = 
            self.stats.content_stats.bytes_saved +
            self.stats.font_stats.bytes_saved +
            self.stats.image_stats.bytes_saved +
            self.stats.resource_stats.bytes_saved;
    }
    
    /// Get processing statistics
    pub fn statistics(&self) -> &ContentProcessingStats {
        &self.stats
    }
    
    /// Reset manager state
    pub fn reset(&mut self) -> Result<()> {
        self.content_processor.reset();
        self.font_processor.reset();
        self.image_processor.reset();
        self.resource_cleaner.reset();
        self.stats = ContentProcessingStats::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn setup_test_manager() -> ContentManager {
        ContentManager::new().unwrap()
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
        
        let config = ContentProcessingConfig {
            processing_order: ProcessingOrder {
                enable_parallel: false,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(manager.process_content(&mut document, &config).await.is_ok());
    }
    
    #[tokio::test]
    async fn test_parallel_processing() {
        let mut manager = setup_test_manager();
        let mut document = create_test_document();
        
        let config = ContentProcessingConfig {
            processing_order: ProcessingOrder {
                enable_parallel: true,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(manager.process_content(&mut document, &config).await.is_ok());
    }
    
    #[test]
    fn test_statistics_update() {
        let mut manager = setup_test_manager();
        
        // Add some test statistics
        manager.content_processor.stats.bytes_saved = 100;
        manager.font_processor.stats.bytes_saved = 200;
        manager.image_processor.stats.bytes_saved = 300;
        manager.resource_cleaner.stats.bytes_saved = 400;
        
        manager.update_statistics();
        
        assert_eq!(manager.stats.total_bytes_saved, 1000);
    }
    
    #[test]
    fn test_manager_reset() {
        let mut manager = setup_test_manager();
        
        // Add some test data
        manager.stats.total_bytes_saved = 1000;
        manager.stats.total_duration_ms = 500;
        
        assert!(manager.reset().is_ok());
        
        assert_eq!(manager.stats.total_bytes_saved, 0);
        assert_eq!(manager.stats.total_duration_ms, 0);
    }
    
    #[test]
    fn test_processing_order() {
        let order = ProcessingOrder::default();
        assert_eq!(order.steps.len(), 4);
        assert!(!order.enable_parallel);
    }
}
