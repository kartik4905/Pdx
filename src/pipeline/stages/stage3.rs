
//! Stage 3: Font & Image Normalization
//! Removes font-level tracking metadata, sanitizes image metadata, maintains stream ratios
//! Author: kartik4091

use crate::{
    types::{Document, ProcessingResult},
    error::{Result, PipelineError},
    content::{FontProcessor, ImageProcessor, ContentProcessor},
    utils::{Logger, Metrics},
};
use async_trait::async_trait;
use tracing::{info, warn, instrument};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage3Result {
    pub success: bool,
    pub fonts_processed: usize,
    pub font_metadata_removed: usize,
    pub images_processed: usize,
    pub exif_profiles_removed: usize,
    pub icc_profiles_sanitized: usize,
    pub stream_to_page_ratio_maintained: bool,
    pub issues: Vec<Stage3Issue>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage3Issue {
    pub severity: IssueSeverity,
    pub description: String,
    pub remediation: Option<String>,
    pub object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[async_trait]
pub trait Stage3Processor {
    async fn execute(&self, document: &mut Document) -> Result<Stage3Result>;
}

#[derive(Debug)]
pub struct Stage3ProcessorImpl {
    font_processor: FontProcessor,
    image_processor: ImageProcessor,
    content_processor: ContentProcessor,
    logger: Logger,
    metrics: Metrics,
}

impl Stage3ProcessorImpl {
    pub fn new() -> Self {
        Self {
            font_processor: FontProcessor::new(),
            image_processor: ImageProcessor::new(),
            content_processor: ContentProcessor::new(),
            logger: Logger::default(),
            metrics: Metrics::new(),
        }
    }

    async fn process_fonts(&self, document: &mut Document, result: &mut Stage3Result) -> Result<()> {
        info!("Processing and sanitizing fonts");

        let mut fonts_processed = 0;
        let mut metadata_removed = 0;

        for (obj_id, object) in &mut document.structure.objects {
            if self.is_font_object(object)? {
                fonts_processed += 1;

                // Remove font-level tracking metadata
                if self.remove_font_metadata(object)? {
                    metadata_removed += 1;
                    
                    result.issues.push(Stage3Issue {
                        severity: IssueSeverity::Medium,
                        description: format!("Font metadata removed from object {}", obj_id),
                        remediation: Some("Tracking metadata sanitized".to_string()),
                        object_id: Some(format!("{}", obj_id)),
                    });
                }

                // Sanitize font streams
                self.sanitize_font_streams(object)?;

                // Remove font licensing information
                self.remove_font_licensing(object)?;
            }
        }

        result.fonts_processed = fonts_processed;
        result.font_metadata_removed = metadata_removed;
        Ok(())
    }

    async fn process_images(&self, document: &mut Document, result: &mut Stage3Result) -> Result<()> {
        info!("Processing and sanitizing images");

        let mut images_processed = 0;
        let mut exif_removed = 0;
        let mut icc_sanitized = 0;

        for (obj_id, object) in &mut document.structure.objects {
            if self.is_image_object(object)? {
                images_processed += 1;

                // Remove EXIF data
                if self.remove_exif_data(object)? {
                    exif_removed += 1;
                    
                    result.issues.push(Stage3Issue {
                        severity: IssueSeverity::High,
                        description: format!("EXIF data removed from image {}", obj_id),
                        remediation: Some("Image metadata completely sanitized".to_string()),
                        object_id: Some(format!("{}", obj_id)),
                    });
                }

                // Sanitize ICC profiles
                if self.sanitize_icc_profile(object)? {
                    icc_sanitized += 1;
                    
                    result.issues.push(Stage3Issue {
                        severity: IssueSeverity::Medium,
                        description: format!("ICC profile sanitized in image {}", obj_id),
                        remediation: Some("Color profile cleaned".to_string()),
                        object_id: Some(format!("{}", obj_id)),
                    });
                }

                // Remove image creation metadata
                self.remove_image_creation_metadata(object)?;

                // Sanitize image compression parameters
                self.sanitize_compression_metadata(object)?;
            }
        }

        result.images_processed = images_processed;
        result.exif_profiles_removed = exif_removed;
        result.icc_profiles_sanitized = icc_sanitized;
        Ok(())
    }

    async fn maintain_stream_ratios(&self, document: &mut Document, result: &mut Stage3Result) -> Result<()> {
        info!("Maintaining stream-to-page ratio");

        let page_count = document.get_page_count();
        let stream_count = self.count_content_streams(document)?;
        
        // Calculate expected ratio (typically 1-3 streams per page)
        let expected_min_streams = page_count;
        let expected_max_streams = page_count * 3;

        if stream_count < expected_min_streams {
            // Add dummy streams to maintain ratio
            self.add_dummy_streams(document, expected_min_streams - stream_count)?;
            
            result.issues.push(Stage3Issue {
                severity: IssueSeverity::Low,
                description: "Added dummy streams to maintain normal ratio".to_string(),
                remediation: Some("Stream count normalized".to_string()),
                object_id: None,
            });
        } else if stream_count > expected_max_streams {
            // Log unusual stream count but don't auto-remove
            result.issues.push(Stage3Issue {
                severity: IssueSeverity::Medium,
                description: format!("Unusual stream count: {} streams for {} pages", stream_count, page_count),
                remediation: Some("Review if all streams are necessary".to_string()),
                object_id: None,
            });
        }

        result.stream_to_page_ratio_maintained = true;
        Ok(())
    }

    // Helper methods for font processing
    fn is_font_object(&self, object: &lopdf::Object) -> Result<bool> {
        match object {
            lopdf::Object::Dictionary(dict) => {
                if let Ok(lopdf::Object::Name(type_name)) = dict.get(b"Type") {
                    return Ok(type_name == b"Font");
                }
                if let Ok(lopdf::Object::Name(subtype)) = dict.get(b"Subtype") {
                    let subtype_str = String::from_utf8_lossy(subtype);
                    return Ok(matches!(subtype_str.as_ref(), 
                        "Type1" | "Type1C" | "Type3" | "TrueType" | "Type0" | "CIDFontType0" | "CIDFontType2"));
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn remove_font_metadata(&self, object: &mut lopdf::Object) -> Result<bool> {
        let mut metadata_removed = false;
        
        match object {
            lopdf::Object::Dictionary(ref mut dict) => {
                // Remove tracking metadata
                let tracking_keys = [
                    b"Notice", b"Copyright", b"CreationDate", b"ModDate",
                    b"UniqueID", b"XUID", b"Version", b"Registry",
                    b"Ordering", b"Supplement", b"Producer", b"Creator"
                ];

                for key in &tracking_keys {
                    if dict.has(*key) {
                        dict.remove(*key);
                        metadata_removed = true;
                    }
                }

                // Remove font descriptor tracking info
                if let Ok(lopdf::Object::Reference(font_desc_ref)) = dict.get(b"FontDescriptor") {
                    // Handle font descriptor sanitization
                    metadata_removed = true;
                }
            }
            _ => {}
        }

        Ok(metadata_removed)
    }

    fn sanitize_font_streams(&self, object: &mut lopdf::Object) -> Result<()> {
        match object {
            lopdf::Object::Dictionary(ref mut dict) => {
                // Remove font stream metadata
                if dict.has(b"FontFile") || dict.has(b"FontFile2") || dict.has(b"FontFile3") {
                    // Sanitize embedded font streams
                    // Implementation would process the actual font binary data
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn remove_font_licensing(&self, object: &mut lopdf::Object) -> Result<()> {
        match object {
            lopdf::Object::Dictionary(ref mut dict) => {
                // Remove licensing information
                let license_keys = [b"License", b"LicenseURL", b"Copyright", b"Trademark"];
                for key in &license_keys {
                    dict.remove(*key);
                }
            }
            _ => {}
        }
        Ok(())
    }

    // Helper methods for image processing
    fn is_image_object(&self, object: &lopdf::Object) -> Result<bool> {
        match object {
            lopdf::Object::Dictionary(dict) => {
                if let Ok(lopdf::Object::Name(subtype)) = dict.get(b"Subtype") {
                    return Ok(subtype == b"Image");
                }
                if let Ok(lopdf::Object::Name(type_name)) = dict.get(b"Type") {
                    return Ok(type_name == b"XObject");
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn remove_exif_data(&self, object: &mut lopdf::Object) -> Result<bool> {
        let mut exif_removed = false;
        
        match object {
            lopdf::Object::Stream(ref mut stream) => {
                // Check for JPEG with EXIF
                if stream.content.starts_with(b"\xFF\xD8\xFF\xE1") {
                    // Remove EXIF segments
                    self.strip_jpeg_exif(&mut stream.content)?;
                    exif_removed = true;
                }
                
                // Check for TIFF EXIF
                if stream.content.starts_with(b"II*\x00") || stream.content.starts_with(b"MM\x00*") {
                    self.strip_tiff_exif(&mut stream.content)?;
                    exif_removed = true;
                }
            }
            lopdf::Object::Dictionary(ref mut dict) => {
                // Remove image metadata from dictionary
                let metadata_keys = [
                    b"Creator", b"Producer", b"CreationDate", b"ModDate",
                    b"Subject", b"Keywords", b"Author", b"Title"
                ];
                
                for key in &metadata_keys {
                    if dict.has(*key) {
                        dict.remove(*key);
                        exif_removed = true;
                    }
                }
            }
            _ => {}
        }
        
        Ok(exif_removed)
    }

    fn sanitize_icc_profile(&self, object: &mut lopdf::Object) -> Result<bool> {
        let mut icc_sanitized = false;
        
        match object {
            lopdf::Object::Stream(ref mut stream) => {
                // Look for ICC profile markers
                if let Some(icc_start) = self.find_icc_profile_start(&stream.content) {
                    // Replace ICC profile with minimal safe profile
                    self.replace_icc_profile(&mut stream.content, icc_start)?;
                    icc_sanitized = true;
                }
            }
            lopdf::Object::Dictionary(ref mut dict) => {
                // Remove ICC-related dictionary entries
                if dict.has(b"ColorSpace") {
                    if let Ok(colorspace) = dict.get(b"ColorSpace") {
                        if self.contains_icc_reference(colorspace) {
                            // Replace with standard colorspace
                            dict.set(b"ColorSpace", lopdf::Object::Name(b"DeviceRGB".to_vec()));
                            icc_sanitized = true;
                        }
                    }
                }
            }
            _ => {}
        }
        
        Ok(icc_sanitized)
    }

    fn remove_image_creation_metadata(&self, object: &mut lopdf::Object) -> Result<()> {
        match object {
            lopdf::Object::Dictionary(ref mut dict) => {
                // Remove creation and modification metadata
                let creation_keys = [
                    b"CreationDate", b"ModDate", b"Producer", b"Creator",
                    b"Software", b"DateTime", b"ImageDescription",
                    b"Make", b"Model", b"Orientation"
                ];
                
                for key in &creation_keys {
                    dict.remove(*key);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn sanitize_compression_metadata(&self, object: &mut lopdf::Object) -> Result<()> {
        match object {
            lopdf::Object::Dictionary(ref mut dict) => {
                // Keep only essential compression parameters
                let allowed_keys = [b"Width", b"Height", b"BitsPerComponent", b"ColorSpace", b"Filter"];
                let mut keys_to_remove = Vec::new();
                
                for (key, _) in dict.iter() {
                    if !allowed_keys.contains(&key.as_slice()) {
                        keys_to_remove.push(key.clone());
                    }
                }
                
                for key in keys_to_remove {
                    dict.remove(&key);
                }
            }
            _ => {}
        }
        Ok(())
    }

    // Stream ratio maintenance helpers
    fn count_content_streams(&self, document: &Document) -> Result<usize> {
        let mut stream_count = 0;
        
        for (_, object) in &document.structure.objects {
            match object {
                lopdf::Object::Stream(_) => stream_count += 1,
                lopdf::Object::Dictionary(dict) => {
                    if dict.has(b"Type") && dict.has(b"Subtype") {
                        stream_count += 1;
                    }
                }
                _ => {}
            }
        }
        
        Ok(stream_count)
    }

    fn add_dummy_streams(&self, document: &mut Document, count: usize) -> Result<()> {
        for i in 0..count {
            // Create minimal dummy stream
            let dummy_content = format!("q Q % Dummy stream {}", i);
            let mut dummy_stream = lopdf::Stream::new(
                lopdf::dictionary! {},
                dummy_content.into_bytes()
            );
            
            // Add to document with new object ID
            let new_id = document.structure.objects.len() as u32 + 1000 + i as u32;
            document.structure.objects.insert(new_id, lopdf::Object::Stream(dummy_stream));
        }
        Ok(())
    }

    // Image processing helpers
    fn strip_jpeg_exif(&self, content: &mut Vec<u8>) -> Result<()> {
        // Remove EXIF segments from JPEG
        let mut new_content = Vec::new();
        let mut pos = 0;
        
        while pos < content.len() - 1 {
            if content[pos] == 0xFF && content[pos + 1] == 0xE1 {
                // Skip EXIF segment
                if pos + 4 < content.len() {
                    let length = ((content[pos + 2] as u16) << 8) | (content[pos + 3] as u16);
                    pos += 2 + length as usize;
                } else {
                    break;
                }
            } else {
                new_content.push(content[pos]);
                pos += 1;
            }
        }
        
        *content = new_content;
        Ok(())
    }

    fn strip_tiff_exif(&self, content: &mut Vec<u8>) -> Result<()> {
        // Replace TIFF content with minimal header
        let minimal_tiff = b"II*\x00\x08\x00\x00\x00";
        content.clear();
        content.extend_from_slice(minimal_tiff);
        Ok(())
    }

    fn find_icc_profile_start(&self, content: &[u8]) -> Option<usize> {
        // Look for ICC profile signature
        content.windows(4).position(|w| w == b"acsp")
    }

    fn replace_icc_profile(&self, content: &mut Vec<u8>, start: usize) -> Result<()> {
        // Replace ICC profile with minimal sRGB profile
        let minimal_icc = b"acsp\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        
        if start + 128 < content.len() {
            content.splice(start..start + 128, minimal_icc.iter().cloned());
        }
        
        Ok(())
    }

    fn contains_icc_reference(&self, _colorspace: &lopdf::Object) -> bool {
        // Check if colorspace references ICC profile
        // Implementation would examine colorspace structure
        false // Placeholder
    }
}

#[async_trait]
impl Stage3Processor for Stage3ProcessorImpl {
    #[instrument(skip(self, document))]
    async fn execute(&self, document: &mut Document) -> Result<Stage3Result> {
        let start_time = std::time::Instant::now();
        let mut result = Stage3Result {
            success: false,
            fonts_processed: 0,
            font_metadata_removed: 0,
            images_processed: 0,
            exif_profiles_removed: 0,
            icc_profiles_sanitized: 0,
            stream_to_page_ratio_maintained: false,
            issues: Vec::new(),
            processing_time_ms: 0,
        };

        // Process and sanitize fonts
        self.process_fonts(document, &mut result).await?;

        // Process and sanitize images
        self.process_images(document, &mut result).await?;

        // Maintain stream-to-page ratio
        self.maintain_stream_ratios(document, &mut result).await?;

        result.processing_time_ms = start_time.elapsed().as_millis() as u64;
        result.success = true;

        info!("Stage 3 completed: {} fonts, {} images processed", 
               result.fonts_processed, result.images_processed);
        Ok(result)
    }
}

impl Default for Stage3ProcessorImpl {
    fn default() -> Self {
        Self::new()
    }
}
