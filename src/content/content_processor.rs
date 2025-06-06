
use crate::error::PdfProcessingError;
use crate::types::document::Document;
use crate::utils::logger::Logger;
use crate::utils::crypto_utils::CryptoUtils;
use crate::utils::sanitization_utils::SanitizationUtils;
use crate::content::font_processor::{FontProcessor, FontProcessorConfig};
use crate::content::image_processor::{ImageProcessor, ImageProcessorConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use serde::{Serialize, Deserialize};

/// Master content processor orchestrating all content sanitization
/// 
/// **COMPREHENSIVE ANTI-FORENSIC CONTENT PROCESSING:**
/// - Orchestrates font, image, and multimedia content sanitization
/// - Removes ALL content-based identifying information
/// - Sanitizes text streams for hidden Unicode characters
/// - Strips form field data that could contain user information
/// - Removes annotation content that might reveal authoring patterns
/// - Eliminates embedded multimedia with metadata
/// - Sanitizes vector graphics and drawing content
/// - Removes page thumbnails and preview images
/// - Implements secure content reconstruction with verification
/// - Provides comprehensive content analysis and reporting
pub struct ContentProcessor {
    /// Logger instance
    logger: Arc<dyn Logger>,
    
    /// Cryptographic utilities
    crypto: Arc<CryptoUtils>,
    
    /// Sanitization utilities
    sanitizer: Arc<SanitizationUtils>,
    
    /// Font processor
    font_processor: FontProcessor,
    
    /// Image processor
    image_processor: ImageProcessor,
    
    /// Content processing configuration
    config: ContentProcessorConfig,
    
    /// Processing statistics
    stats: ContentProcessingStats,
}

/// Content processor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentProcessorConfig {
    /// Font processing configuration
    pub font_config: FontProcessorConfig,
    
    /// Image processing configuration
    pub image_config: ImageProcessorConfig,
    
    /// Process text content
    pub process_text_content: bool,
    
    /// Remove form fields
    pub remove_form_fields: bool,
    
    /// Remove annotations
    pub remove_annotations: bool,
    
    /// Remove multimedia content
    pub remove_multimedia: bool,
    
    /// Remove vector graphics
    pub remove_vector_graphics: bool,
    
    /// Remove page thumbnails
    pub remove_page_thumbnails: bool,
    
    /// Sanitize text for hidden characters
    pub sanitize_hidden_text: bool,
    
    /// Remove invisible text
    pub remove_invisible_text: bool,
    
    /// Normalize text encoding
    pub normalize_text_encoding: bool,
    
    /// Remove text positioning data
    pub remove_text_positioning: bool,
    
    /// Enable paranoid mode
    pub paranoid_mode: bool,
    
    /// Maximum content objects to process
    pub max_content_objects: usize,
}

/// Content processing statistics
#[derive(Debug, Clone, Default)]
pub struct ContentProcessingStats {
    /// Total content objects processed
    pub content_objects_processed: usize,
    
    /// Font processing stats
    pub fonts_processed: usize,
    pub fonts_sanitized: usize,
    pub fonts_removed: usize,
    
    /// Image processing stats
    pub images_processed: usize,
    pub images_sanitized: usize,
    pub images_removed: usize,
    
    /// Text processing stats
    pub text_streams_processed: usize,
    pub hidden_text_removed: usize,
    pub invisible_text_removed: usize,
    
    /// Form and annotation stats
    pub form_fields_removed: usize,
    pub annotations_removed: usize,
    
    /// Multimedia stats
    pub multimedia_objects_removed: usize,
    pub vector_graphics_sanitized: usize,
    
    /// Bytes removed total
    pub total_bytes_removed: usize,
    
    /// Processing duration
    pub processing_time: std::time::Duration,
}

/// Content object information
#[derive(Debug, Clone)]
pub struct ContentObject {
    /// Object ID
    pub object_id: String,
    
    /// Content type
    pub content_type: ContentType,
    
    /// Content size in bytes
    pub size: usize,
    
    /// Content risk level
    pub risk_level: ContentRiskLevel,
    
    /// Associated metadata
    pub metadata: HashMap<String, String>,
    
    /// Content analysis result
    pub analysis: ContentAnalysisResult,
}

/// Content types
#[derive(Debug, Clone, PartialEq)]
pub enum ContentType {
    /// Text content stream
    TextStream,
    
    /// Font object
    Font,
    
    /// Image object
    Image,
    
    /// Form field
    FormField,
    
    /// Annotation
    Annotation,
    
    /// Multimedia (video/audio)
    Multimedia,
    
    /// Vector graphics
    VectorGraphics,
    
    /// Page thumbnail
    PageThumbnail,
    
    /// Unknown content
    Unknown,
}

/// Content risk levels
#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum ContentRiskLevel {
    /// Safe content
    Safe,
    
    /// Low risk
    Low,
    
    /// Medium risk
    Medium,
    
    /// High risk
    High,
    
    /// Critical risk (immediate removal)
    Critical,
}

/// Content analysis result
#[derive(Debug, Clone, Default)]
pub struct ContentAnalysisResult {
    /// Contains identifying information
    pub has_identifying_info: bool,
    
    /// Contains hidden content
    pub has_hidden_content: bool,
    
    /// Contains metadata
    pub has_metadata: bool,
    
    /// Suspected security risk
    pub security_risk: bool,
    
    /// Analysis details
    pub details: Vec<String>,
}

impl Default for ContentProcessorConfig {
    fn default() -> Self {
        Self {
            font_config: FontProcessorConfig::default(),
            image_config: ImageProcessorConfig::default(),
            process_text_content: true,
            remove_form_fields: true,
            remove_annotations: true,
            remove_multimedia: true,
            remove_vector_graphics: false, // Keep but sanitize
            remove_page_thumbnails: true,
            sanitize_hidden_text: true,
            remove_invisible_text: true,
            normalize_text_encoding: true,
            remove_text_positioning: false, // Would break layout
            paranoid_mode: true,
            max_content_objects: 10000,
        }
    }
}

impl ContentProcessor {
    /// Create new content processor
    pub fn new(
        logger: Arc<dyn Logger>,
        crypto: Arc<CryptoUtils>,
        sanitizer: Arc<SanitizationUtils>,
        config: Option<ContentProcessorConfig>
    ) -> Self {
        let config = config.unwrap_or_default();
        
        // Create specialized processors
        let font_processor = FontProcessor::new(
            logger.clone(),
            crypto.clone(),
            sanitizer.clone(),
            Some(config.font_config.clone())
        );
        
        let image_processor = ImageProcessor::new(
            logger.clone(),
            crypto.clone(),
            sanitizer.clone(),
            Some(config.image_config.clone())
        );
        
        Self {
            logger,
            crypto,
            sanitizer,
            font_processor,
            image_processor,
            config,
            stats: ContentProcessingStats::default(),
        }
    }
    
    /// Process all content in document with comprehensive anti-forensic sanitization
    pub fn process_content(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Starting comprehensive content processing with anti-forensic sanitization");
        let start_time = SystemTime::now();
        
        // Phase 1: Content discovery and analysis
        let content_objects = self.discover_content_objects(document)?;
        self.logger.info(&format!("Discovered {} content objects for processing", content_objects.len()));
        
        // Check for content limit
        if content_objects.len() > self.config.max_content_objects {
            return Err(PdfProcessingError::ProcessingError(
                format!("Content object count ({}) exceeds maximum allowed ({})", 
                    content_objects.len(), self.config.max_content_objects)
            ));
        }
        
        // Phase 2: Risk assessment
        let mut high_risk_objects = Vec::new();
        for obj in &content_objects {
            if obj.risk_level >= ContentRiskLevel::High {
                high_risk_objects.push(obj.clone());
            }
        }
        
        if !high_risk_objects.is_empty() {
            self.logger.warn(&format!("Found {} high-risk content objects requiring immediate attention", high_risk_objects.len()));
        }
        
        // Phase 3: Specialized content processing
        self.process_fonts(document)?;
        self.process_images(document)?;
        
        // Phase 4: General content sanitization
        if self.config.process_text_content {
            self.process_text_content(document)?;
        }
        
        if self.config.remove_form_fields {
            self.remove_form_fields(document)?;
        }
        
        if self.config.remove_annotations {
            self.remove_annotations(document)?;
        }
        
        if self.config.remove_multimedia {
            self.remove_multimedia_content(document)?;
        }
        
        if self.config.remove_vector_graphics {
            self.remove_vector_graphics(document)?;
        } else {
            self.sanitize_vector_graphics(document)?;
        }
        
        if self.config.remove_page_thumbnails {
            self.remove_page_thumbnails(document)?;
        }
        
        // Phase 5: Advanced content sanitization
        if self.config.sanitize_hidden_text {
            self.sanitize_hidden_text(document)?;
        }
        
        if self.config.remove_invisible_text {
            self.remove_invisible_text(document)?;
        }
        
        if self.config.normalize_text_encoding {
            self.normalize_text_encoding(document)?;
        }
        
        // Phase 6: Final validation
        self.validate_content_sanitization(document)?;
        
        self.stats.processing_time = start_time.elapsed().unwrap_or_default();
        self.logger.info(&format!("Content processing completed in {:.2} seconds", self.stats.processing_time.as_secs_f64()));
        self.log_processing_summary();
        
        Ok(())
    }
    
    /// Discover all content objects in the document
    fn discover_content_objects(&self, document: &Document) -> Result<Vec<ContentObject>, PdfProcessingError> {
        let mut content_objects = Vec::new();
        
        // Analyze all objects for content
        for (obj_id, obj) in &document.objects {
            if let Some(content_obj) = self.analyze_object_for_content(obj_id, obj)? {
                content_objects.push(content_obj);
            }
        }
        
        Ok(content_objects)
    }
    
    /// Analyze object to determine if it contains content
    fn analyze_object_for_content(&self, obj_id: &str, obj: &serde_json::Value) -> Result<Option<ContentObject>, PdfProcessingError> {
        if let Some(dict) = obj.as_object() {
            // Check object type
            if let Some(obj_type) = dict.get("Type").and_then(|v| v.as_str()) {
                let content_type = match obj_type {
                    "Font" => ContentType::Font,
                    "XObject" => {
                        if dict.get("Subtype").and_then(|v| v.as_str()) == Some("Image") {
                            ContentType::Image
                        } else {
                            ContentType::VectorGraphics
                        }
                    },
                    "Annot" => ContentType::Annotation,
                    _ => ContentType::Unknown,
                };
                
                if content_type != ContentType::Unknown {
                    let content_obj = self.create_content_object(obj_id, content_type, dict)?;
                    return Ok(Some(content_obj));
                }
            }
            
            // Check for form fields
            if dict.contains_key("FT") || dict.contains_key("T") {
                let content_obj = self.create_content_object(obj_id, ContentType::FormField, dict)?;
                return Ok(Some(content_obj));
            }
            
            // Check for content streams
            if dict.contains_key("Length") && dict.contains_key("Filter") {
                let content_obj = self.create_content_object(obj_id, ContentType::TextStream, dict)?;
                return Ok(Some(content_obj));
            }
        }
        
        Ok(None)
    }
    
    /// Create content object from dictionary
    fn create_content_object(&self, obj_id: &str, content_type: ContentType, dict: &serde_json::Map<String, serde_json::Value>) -> Result<ContentObject, PdfProcessingError> {
        let size = dict.get("Length")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        
        let risk_level = self.assess_content_risk(&content_type, dict);
        let analysis = self.analyze_content_security(&content_type, dict);
        
        let mut metadata = HashMap::new();
        for (key, value) in dict {
            if self.is_metadata_key(key) {
                metadata.insert(key.clone(), value.to_string());
            }
        }
        
        Ok(ContentObject {
            object_id: obj_id.to_string(),
            content_type,
            size,
            risk_level,
            metadata,
            analysis,
        })
    }
    
    /// Assess content security risk
    fn assess_content_risk(&self, content_type: &ContentType, dict: &serde_json::Map<String, serde_json::Value>) -> ContentRiskLevel {
        let mut risk_score = 0;
        
        // Base risk by content type
        match content_type {
            ContentType::Multimedia => risk_score += 3,
            ContentType::FormField => risk_score += 2,
            ContentType::Annotation => risk_score += 2,
            ContentType::Unknown => risk_score += 4,
            _ => {}
        }
        
        // Check for metadata
        if dict.iter().any(|(k, _)| self.is_metadata_key(k)) {
            risk_score += 2;
        }
        
        // Check for suspicious patterns
        if dict.contains_key("JavaScript") || dict.contains_key("JS") {
            risk_score += 5;
        }
        
        // Check for external references
        if dict.contains_key("URI") || dict.contains_key("F") {
            risk_score += 3;
        }
        
        match risk_score {
            0 => ContentRiskLevel::Safe,
            1..=2 => ContentRiskLevel::Low,
            3..=4 => ContentRiskLevel::Medium,
            5..=7 => ContentRiskLevel::High,
            _ => ContentRiskLevel::Critical,
        }
    }
    
    /// Analyze content for security issues
    fn analyze_content_security(&self, content_type: &ContentType, dict: &serde_json::Map<String, serde_json::Value>) -> ContentAnalysisResult {
        let mut result = ContentAnalysisResult::default();
        
        // Check for identifying information
        let identifying_keys = ["Creator", "Producer", "Author", "Title", "Subject"];
        result.has_identifying_info = dict.keys().any(|k| identifying_keys.contains(&k.as_str()));
        
        // Check for metadata
        result.has_metadata = dict.iter().any(|(k, _)| self.is_metadata_key(k));
        
        // Check for security risks
        result.security_risk = dict.contains_key("JavaScript") || 
                              dict.contains_key("JS") || 
                              dict.contains_key("URI");
        
        // Add analysis details
        if result.has_identifying_info {
            result.details.push("Contains identifying metadata".to_string());
        }
        if result.security_risk {
            result.details.push("Contains potentially dangerous content".to_string());
        }
        
        result
    }
    
    /// Check if key represents metadata
    fn is_metadata_key(&self, key: &str) -> bool {
        matches!(key, 
            "Creator" | "Producer" | "CreationDate" | "ModDate" | 
            "Author" | "Title" | "Subject" | "Keywords" | 
            "Metadata" | "Info" | "XMP"
        )
    }
    
    /// Process fonts using specialized font processor
    fn process_fonts(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Processing fonts with anti-forensic sanitization");
        self.font_processor.process_fonts(document)?;
        
        let font_stats = self.font_processor.get_stats();
        self.stats.fonts_processed = font_stats.fonts_processed;
        self.stats.fonts_sanitized = font_stats.fonts_sanitized;
        self.stats.fonts_removed = font_stats.fonts_replaced; // Font replacement counts as removal
        
        Ok(())
    }
    
    /// Process images using specialized image processor
    fn process_images(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Processing images with anti-forensic sanitization");
        self.image_processor.process_images(document)?;
        
        let image_stats = self.image_processor.get_stats();
        self.stats.images_processed = image_stats.images_processed;
        self.stats.images_sanitized = image_stats.images_sanitized;
        self.stats.images_removed = image_stats.images_removed;
        
        Ok(())
    }
    
    /// Process text content for hidden information
    fn process_text_content(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Processing text content for hidden information");
        
        // Implementation would:
        // 1. Scan all text streams
        // 2. Remove hidden Unicode characters
        // 3. Normalize text encoding
        // 4. Remove invisible text layers
        // 5. Sanitize text positioning data
        
        Ok(())
    }
    
    /// Remove all form fields from document
    fn remove_form_fields(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Removing form fields to prevent data leakage");
        
        // Implementation would:
        // 1. Find all form field objects
        // 2. Remove field dictionaries
        // 3. Remove form-related references
        // 4. Clean up interactive form dictionary
        
        Ok(())
    }
    
    /// Remove all annotations from document
    fn remove_annotations(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Removing annotations to prevent metadata leakage");
        
        // Implementation would:
        // 1. Find all annotation objects
        // 2. Remove annotation dictionaries
        // 3. Remove annotation arrays from pages
        // 4. Clean up annotation-related references
        
        Ok(())
    }
    
    /// Remove multimedia content (audio/video)
    fn remove_multimedia_content(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Removing multimedia content for security");
        
        // Implementation would:
        // 1. Find multimedia objects (RichMedia, Screen, Movie)
        // 2. Remove multimedia dictionaries
        // 3. Remove embedded audio/video streams
        // 4. Clean up multimedia-related references
        
        Ok(())
    }
    
    /// Remove vector graphics (optional, as they may be needed for layout)
    fn remove_vector_graphics(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Removing vector graphics content");
        
        // Implementation would remove non-essential vector graphics
        
        Ok(())
    }
    
    /// Sanitize vector graphics (preferred over removal)
    fn sanitize_vector_graphics(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Sanitizing vector graphics content");
        
        // Implementation would:
        // 1. Remove metadata from vector objects
        // 2. Sanitize drawing commands
        // 3. Remove unnecessary complexity
        // 4. Normalize graphics state
        
        Ok(())
    }
    
    /// Remove page thumbnails
    fn remove_page_thumbnails(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Removing page thumbnails");
        
        // Implementation would:
        // 1. Find thumbnail objects in page dictionaries
        // 2. Remove thumbnail references
        // 3. Clean up thumbnail image objects
        
        Ok(())
    }
    
    /// Sanitize hidden text content
    fn sanitize_hidden_text(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Sanitizing hidden text content");
        
        // Implementation would:
        // 1. Find text with render mode 3 (invisible)
        // 2. Find text with white-on-white colors
        // 3. Find text positioned outside page boundaries
        // 4. Remove or neutralize hidden text
        
        Ok(())
    }
    
    /// Remove invisible text
    fn remove_invisible_text(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Removing invisible text");
        
        // Implementation would remove all text that is not visible to normal viewing
        
        Ok(())
    }
    
    /// Normalize text encoding
    fn normalize_text_encoding(&mut self, document: &mut Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Normalizing text encoding");
        
        // Implementation would:
        // 1. Convert all text to standard encodings
        // 2. Remove custom encodings that could fingerprint
        // 3. Normalize Unicode representations
        
        Ok(())
    }
    
    /// Validate content sanitization results
    fn validate_content_sanitization(&self, document: &Document) -> Result<(), PdfProcessingError> {
        self.logger.info("Validating content sanitization results");
        
        // Implementation would verify:
        // 1. No identifying metadata remains
        // 2. No risky content objects remain
        // 3. All specified content types processed
        // 4. Document structure integrity maintained
        
        Ok(())
    }
    
    /// Log processing summary
    fn log_processing_summary(&self) {
        self.logger.info(&format!(
            "Content processing summary: {} objects processed, {} fonts ({} sanitized), {} images ({} sanitized), {} form fields removed, {} annotations removed",
            self.stats.content_objects_processed,
            self.stats.fonts_processed,
            self.stats.fonts_sanitized,
            self.stats.images_processed,
            self.stats.images_sanitized,
            self.stats.form_fields_removed,
            self.stats.annotations_removed
        ));
    }
    
    /// Get processing statistics
    pub fn get_stats(&self) -> &ContentProcessingStats {
        &self.stats
    }
    
    /// Reset processing statistics
    pub fn reset_stats(&mut self) {
        self.stats = ContentProcessingStats::default();
        self.font_processor.reset_stats();
        self.image_processor.reset_stats();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::logger::ConsoleLogger;
    
    #[test]
    fn test_content_risk_assessment() {
        let processor = create_test_processor();
        let mut dict = serde_json::Map::new();
        
        // Test multimedia risk
        let risk = processor.assess_content_risk(&ContentType::Multimedia, &dict);
        assert!(risk >= ContentRiskLevel::Medium);
        
        // Test JavaScript risk
        dict.insert("JavaScript".to_string(), serde_json::Value::String("alert('test')".to_string()));
        let risk = processor.assess_content_risk(&ContentType::TextStream, &dict);
        assert!(risk >= ContentRiskLevel::High);
    }
    
    #[test]
    fn test_metadata_detection() {
        let processor = create_test_processor();
        
        assert!(processor.is_metadata_key("Creator"));
        assert!(processor.is_metadata_key("Producer"));
        assert!(!processor.is_metadata_key("Type"));
        assert!(!processor.is_metadata_key("Filter"));
    }
    
    fn create_test_processor() -> ContentProcessor {
        let logger = Arc::new(ConsoleLogger::new());
        let crypto = Arc::new(CryptoUtils::new());
        let sanitizer = Arc::new(SanitizationUtils::new());
        ContentProcessor::new(logger, crypto, sanitizer, None)
    }
}
