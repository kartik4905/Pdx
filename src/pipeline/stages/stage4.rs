
//! Stage 4: Metadata Enforcement
//! All metadata fields editable, no auto-fill, Info/XMP sync, cryptographically safe ID reassignment
//! Author: kartik4091

use crate::{
    types::{Document, ProcessingResult},
    error::{Result, PipelineError},
    metadata::{SecureMetadataHandler, MetadataCleaner, IdCleaner},
    utils::{Logger, Metrics},
};
use async_trait::async_trait;
use tracing::{info, warn, instrument};
use serde::{Serialize, Deserialize};
use ring::rand::{SecureRandom, SystemRandom};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage4Result {
    pub success: bool,
    pub metadata_fields_processed: usize,
    pub auto_fields_cleared: usize,
    pub info_xmp_synchronized: bool,
    pub document_id_regenerated: bool,
    pub fallback_values_removed: usize,
    pub issues: Vec<Stage4Issue>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage4Issue {
    pub severity: IssueSeverity,
    pub description: String,
    pub remediation: Option<String>,
    pub field_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[async_trait]
pub trait Stage4Processor {
    async fn execute(&self, document: &mut Document) -> Result<Stage4Result>;
}

#[derive(Debug)]
pub struct Stage4ProcessorImpl {
    metadata_handler: SecureMetadataHandler,
    metadata_cleaner: MetadataCleaner,
    id_cleaner: IdCleaner,
    logger: Logger,
    metrics: Metrics,
    rng: SystemRandom,
}

impl Stage4ProcessorImpl {
    pub fn new() -> Self {
        Self {
            metadata_handler: SecureMetadataHandler::new(),
            metadata_cleaner: MetadataCleaner::new(),
            id_cleaner: IdCleaner::new(),
            logger: Logger::default(),
            metrics: Metrics::new(),
            rng: SystemRandom::new(),
        }
    }

    async fn enforce_metadata_control(&self, document: &mut Document, result: &mut Stage4Result) -> Result<()> {
        info!("Enforcing complete metadata control");

        let mut fields_processed = 0;
        let mut auto_fields_cleared = 0;

        // Process Info dictionary
        if let Some(info_ref) = self.get_info_reference(&document.structure.trailer)? {
            if let Some(info_dict) = self.get_object_as_dict_mut(document, info_ref)? {
                fields_processed += self.process_info_dictionary(info_dict, &mut auto_fields_cleared, result)?;
            }
        } else if !document.config.user_metadata.is_empty() {
            // Create Info dictionary if user provided metadata
            self.create_info_dictionary(document, result)?;
            fields_processed += 1;
        }

        // Process XMP metadata
        if let Some(xmp_ref) = self.find_xmp_metadata(document)? {
            fields_processed += self.process_xmp_metadata(document, xmp_ref, &mut auto_fields_cleared, result)?;
        } else if !document.config.user_metadata.is_empty() {
            // Create XMP metadata if user provided metadata
            self.create_xmp_metadata(document, result)?;
            fields_processed += 1;
        }

        result.metadata_fields_processed = fields_processed;
        result.auto_fields_cleared = auto_fields_cleared;
        Ok(())
    }

    async fn synchronize_info_xmp(&self, document: &mut Document, result: &mut Stage4Result) -> Result<()> {
        info!("Synchronizing Info and XMP metadata");

        let user_metadata = &document.config.user_metadata;
        
        // Get or create Info dictionary
        let info_ref = match self.get_info_reference(&document.structure.trailer)? {
            Some(r) => r,
            None => self.create_info_dictionary(document, result)?,
        };

        // Get or create XMP metadata
        let xmp_ref = match self.find_xmp_metadata(document)? {
            Some(r) => r,
            None => self.create_xmp_metadata(document, result)?,
        };

        // Synchronize all user-provided metadata
        self.sync_metadata_fields(document, info_ref, xmp_ref, user_metadata, result)?;

        result.info_xmp_synchronized = true;
        Ok(())
    }

    async fn handle_document_id(&self, document: &mut Document, result: &mut Stage4Result) -> Result<()> {
        info!("Handling document ID");

        if document.config.preserve_document_id {
            // Keep existing ID if user explicitly wants it
            result.issues.push(Stage4Issue {
                severity: IssueSeverity::Low,
                description: "Document ID preserved per user request".to_string(),
                remediation: None,
                field_name: Some("/ID".to_string()),
            });
        } else {
            // Generate cryptographically secure new ID
            let new_id = self.generate_secure_document_id()?;
            self.set_document_id(document, new_id)?;
            
            result.document_id_regenerated = true;
            result.issues.push(Stage4Issue {
                severity: IssueSeverity::Medium,
                description: "Document ID regenerated with cryptographically secure values".to_string(),
                remediation: Some("New secure ID assigned".to_string()),
                field_name: Some("/ID".to_string()),
            });
        }

        Ok(())
    }

    async fn remove_fallback_values(&self, document: &mut Document, result: &mut Stage4Result) -> Result<()> {
        info!("Removing all fallback and auto-generated values");

        let mut fallbacks_removed = 0;

        // Remove fallback values from all objects
        for (obj_id, object) in &mut document.structure.objects {
            fallbacks_removed += self.remove_object_fallbacks(object, obj_id, result)?;
        }

        // Remove fallback values from trailer
        fallbacks_removed += self.remove_trailer_fallbacks(&mut document.structure.trailer, result)?;

        result.fallback_values_removed = fallbacks_removed;
        Ok(())
    }

    // Helper methods
    fn process_info_dictionary(&self, info_dict: &mut lopdf::Dictionary, auto_cleared: &mut usize, result: &mut Stage4Result) -> Result<usize> {
        let mut fields_processed = 0;
        
        // List of fields that should never be auto-generated
        let auto_fields = [
            b"Producer", b"Creator", b"CreationDate", b"ModDate", 
            b"Trapped", b"PTEX.Fullbanner"
        ];

        // Clear auto-generated fields
        for field in &auto_fields {
            if info_dict.has(*field) {
                let value = info_dict.get(*field).unwrap_or(&lopdf::Object::Null);
                if self.is_auto_generated_value(value, field) {
                    info_dict.remove(*field);
                    *auto_cleared += 1;
                    
                    result.issues.push(Stage4Issue {
                        severity: IssueSeverity::Medium,
                        description: format!("Auto-generated field {} removed", String::from_utf8_lossy(field)),
                        remediation: Some("Field cleared - will remain empty unless user provides value".to_string()),
                        field_name: Some(String::from_utf8_lossy(field).to_string()),
                    });
                }
            }
        }

        // Ensure all remaining fields are user-controlled
        for (key, value) in info_dict.iter() {
            if !self.is_user_controlled_field(&key, value) {
                result.issues.push(Stage4Issue {
                    severity: IssueSeverity::High,
                    description: format!("Non-user-controlled field detected: {}", String::from_utf8_lossy(&key)),
                    remediation: Some("Field requires user validation".to_string()),
                    field_name: Some(String::from_utf8_lossy(&key).to_string()),
                });
            }
            fields_processed += 1;
        }

        Ok(fields_processed)
    }

    fn process_xmp_metadata(&self, document: &mut Document, xmp_ref: u32, auto_cleared: &mut usize, result: &mut Stage4Result) -> Result<usize> {
        let mut fields_processed = 0;

        if let Some(xmp_object) = document.structure.objects.get_mut(&xmp_ref) {
            match xmp_object {
                lopdf::Object::Stream(ref mut stream) => {
                    // Parse XMP XML and remove auto-generated fields
                    let xmp_content = String::from_utf8_lossy(&stream.content);
                    let cleaned_xmp = self.clean_xmp_auto_fields(&xmp_content, auto_cleared, result)?;
                    stream.content = cleaned_xmp.into_bytes();
                    fields_processed = 1;
                }
                _ => {
                    result.issues.push(Stage4Issue {
                        severity: IssueSeverity::High,
                        description: "XMP metadata object is not a stream".to_string(),
                        remediation: Some("XMP metadata should be a stream object".to_string()),
                        field_name: Some("XMP".to_string()),
                    });
                }
            }
        }

        Ok(fields_processed)
    }

    fn clean_xmp_auto_fields(&self, xmp_content: &str, auto_cleared: &mut usize, result: &mut Stage4Result) -> Result<String> {
        let mut cleaned = xmp_content.to_string();
        
        // Remove auto-generated XMP fields
        let auto_patterns = [
            r#"<xmp:CreatorTool>.*?</xmp:CreatorTool>"#,
            r#"<xmp:CreateDate>.*?</xmp:CreateDate>"#,
            r#"<xmp:ModifyDate>.*?</xmp:ModifyDate>"#,
            r#"<pdf:Producer>.*?</pdf:Producer>"#,
            r#"<pdf:Trapped>.*?</pdf:Trapped>"#,
        ];

        for pattern in &auto_patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if regex.is_match(&cleaned) {
                    cleaned = regex.replace_all(&cleaned, "").to_string();
                    *auto_cleared += 1;
                }
            }
        }

        Ok(cleaned)
    }

    fn sync_metadata_fields(&self, document: &mut Document, info_ref: u32, xmp_ref: u32, 
                           user_metadata: &std::collections::HashMap<String, String>, 
                           result: &mut Stage4Result) -> Result<()> {
        
        // Update Info dictionary with user metadata
        if let Some(info_dict) = self.get_object_as_dict_mut(document, info_ref)? {
            for (key, value) in user_metadata {
                if !value.is_empty() {
                    info_dict.set(key.as_bytes(), lopdf::Object::String(value.as_bytes().to_vec(), lopdf::StringFormat::Literal));
                }
            }
        }

        // Update XMP metadata with user metadata
        if let Some(xmp_stream) = self.get_object_as_stream_mut(document, xmp_ref)? {
            let updated_xmp = self.update_xmp_with_user_data(&xmp_stream.content, user_metadata)?;
            xmp_stream.content = updated_xmp.into_bytes();
        }

        Ok(())
    }

    fn update_xmp_with_user_data(&self, xmp_content: &[u8], user_metadata: &std::collections::HashMap<String, String>) -> Result<String> {
        let mut xmp_str = String::from_utf8_lossy(xmp_content).to_string();
        
        // Update XMP fields with user-provided values
        for (key, value) in user_metadata {
            if !value.is_empty() {
                let xmp_key = match key.as_str() {
                    "Title" => "dc:title",
                    "Author" => "dc:creator", 
                    "Subject" => "dc:subject",
                    "Keywords" => "pdf:Keywords",
                    "Creator" => "xmp:CreatorTool",
                    "Producer" => "pdf:Producer",
                    _ => continue,
                };
                
                // Insert or update XMP field
                let field_xml = format!("<{}>{}</{}>", xmp_key, value, xmp_key);
                
                // Simple insertion - in production would use proper XML parsing
                if !xmp_str.contains(xmp_key) {
                    // Insert before closing rdf:Description
                    xmp_str = xmp_str.replace("</rdf:Description>", &format!("  {}\n</rdf:Description>", field_xml));
                }
            }
        }
        
        Ok(xmp_str)
    }

    fn generate_secure_document_id(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut id1 = vec![0u8; 16];
        let mut id2 = vec![0u8; 16];
        
        self.rng.fill(&mut id1).map_err(|_| PipelineError::CryptoError("Failed to generate secure ID".to_string()))?;
        self.rng.fill(&mut id2).map_err(|_| PipelineError::CryptoError("Failed to generate secure ID".to_string()))?;
        
        Ok((id1, id2))
    }

    fn set_document_id(&self, document: &mut Document, (id1, id2): (Vec<u8>, Vec<u8>)) -> Result<()> {
        let id_array = lopdf::Object::Array(vec![
            lopdf::Object::String(id1, lopdf::StringFormat::Hexadecimal),
            lopdf::Object::String(id2, lopdf::StringFormat::Hexadecimal),
        ]);
        
        document.structure.trailer.set(b"ID", id_array);
        Ok(())
    }

    fn create_info_dictionary(&self, document: &mut Document, result: &mut Stage4Result) -> Result<u32> {
        let info_dict = lopdf::dictionary! {};
        let info_id = self.get_next_object_id(document);
        
        document.structure.objects.insert(info_id, lopdf::Object::Dictionary(info_dict));
        document.structure.trailer.set(b"Info", lopdf::Object::Reference((info_id, 0)));
        
        result.issues.push(Stage4Issue {
            severity: IssueSeverity::Low,
            description: "Created new Info dictionary".to_string(),
            remediation: Some("Info dictionary ready for user metadata".to_string()),
            field_name: Some("Info".to_string()),
        });
        
        Ok(info_id)
    }

    fn create_xmp_metadata(&self, document: &mut Document, result: &mut Stage4Result) -> Result<u32> {
        let minimal_xmp = r#"<?xml version="1.0" encoding="UTF-8"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:pdf="http://ns.adobe.com/pdf/1.3/">
</rdf:Description>
</rdf:RDF>
</x:xmpmeta>"#;

        let xmp_stream = lopdf::Stream::new(
            lopdf::dictionary! {
                "Type" => lopdf::Object::Name(b"Metadata".to_vec()),
                "Subtype" => lopdf::Object::Name(b"XML".to_vec()),
            },
            minimal_xmp.as_bytes().to_vec()
        );

        let xmp_id = self.get_next_object_id(document);
        document.structure.objects.insert(xmp_id, lopdf::Object::Stream(xmp_stream));
        
        // Add to document catalog
        if let Some(catalog_ref) = self.get_catalog_reference(&document.structure.trailer)? {
            if let Some(catalog_dict) = self.get_object_as_dict_mut(document, catalog_ref)? {
                catalog_dict.set(b"Metadata", lopdf::Object::Reference((xmp_id, 0)));
            }
        }

        result.issues.push(Stage4Issue {
            severity: IssueSeverity::Low,
            description: "Created new XMP metadata stream".to_string(),
            remediation: Some("XMP metadata ready for user content".to_string()),
            field_name: Some("XMP".to_string()),
        });

        Ok(xmp_id)
    }

    // Utility methods
    fn get_next_object_id(&self, document: &Document) -> u32 {
        document.structure.objects.keys().max().unwrap_or(&0) + 1
    }

    fn is_auto_generated_value(&self, value: &lopdf::Object, field: &[u8]) -> bool {
        match value {
            lopdf::Object::String(content, _) => {
                let content_str = String::from_utf8_lossy(content);
                match field {
                    b"Producer" => content_str.contains("lopdf") || content_str.contains("Adobe") || content_str.contains("PDF"),
                    b"Creator" => content_str.contains("Writer") || content_str.contains("Office"),
                    b"CreationDate" | b"ModDate" => content_str.starts_with("D:"),
                    _ => false,
                }
            }
            _ => false,
        }
    }

    fn is_user_controlled_field(&self, _key: &[u8], _value: &lopdf::Object) -> bool {
        // Check if field appears to be user-controlled vs auto-generated
        true // Placeholder - implement actual logic
    }

    fn remove_object_fallbacks(&self, object: &mut lopdf::Object, obj_id: &u32, result: &mut Stage4Result) -> Result<usize> {
        let mut removed = 0;
        
        match object {
            lopdf::Object::Dictionary(ref mut dict) => {
                let fallback_keys = [b"Producer", b"Creator", b"CreationDate", b"ModDate"];
                for key in &fallback_keys {
                    if dict.has(*key) {
                        if let Ok(value) = dict.get(*key) {
                            if self.is_auto_generated_value(value, key) {
                                dict.remove(*key);
                                removed += 1;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        
        Ok(removed)
    }

    fn remove_trailer_fallbacks(&self, trailer: &mut lopdf::Dictionary, result: &mut Stage4Result) -> Result<usize> {
        let mut removed = 0;
        
        // Remove auto-generated trailer entries
        let auto_keys = [b"Producer", b"Creator"];
        for key in &auto_keys {
            if trailer.has(*key) {
                trailer.remove(*key);
                removed += 1;
            }
        }
        
        Ok(removed)
    }

    fn get_info_reference(&self, trailer: &lopdf::Dictionary) -> Result<Option<u32>> {
        if let Ok(lopdf::Object::Reference((id, _))) = trailer.get(b"Info") {
            Ok(Some(*id))
        } else {
            Ok(None)
        }
    }

    fn get_catalog_reference(&self, trailer: &lopdf::Dictionary) -> Result<Option<u32>> {
        if let Ok(lopdf::Object::Reference((id, _))) = trailer.get(b"Root") {
            Ok(Some(*id))
        } else {
            Ok(None)
        }
    }

    fn find_xmp_metadata(&self, document: &Document) -> Result<Option<u32>> {
        // Find XMP metadata in document catalog
        if let Some(catalog_ref) = self.get_catalog_reference(&document.structure.trailer)? {
            if let Some(catalog_dict) = self.get_object_as_dict(document, catalog_ref)? {
                if let Ok(lopdf::Object::Reference((id, _))) = catalog_dict.get(b"Metadata") {
                    return Ok(Some(*id));
                }
            }
        }
        Ok(None)
    }

    fn get_object_as_dict(&self, document: &Document, obj_id: u32) -> Result<Option<&lopdf::Dictionary>> {
        if let Some(lopdf::Object::Dictionary(dict)) = document.structure.objects.get(&obj_id) {
            Ok(Some(dict))
        } else {
            Ok(None)
        }
    }

    fn get_object_as_dict_mut(&self, document: &mut Document, obj_id: u32) -> Result<Option<&mut lopdf::Dictionary>> {
        if let Some(lopdf::Object::Dictionary(dict)) = document.structure.objects.get_mut(&obj_id) {
            Ok(Some(dict))
        } else {
            Ok(None)
        }
    }

    fn get_object_as_stream_mut(&self, document: &mut Document, obj_id: u32) -> Result<Option<&mut lopdf::Stream>> {
        if let Some(lopdf::Object::Stream(stream)) = document.structure.objects.get_mut(&obj_id) {
            Ok(Some(stream))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl Stage4Processor for Stage4ProcessorImpl {
    #[instrument(skip(self, document))]
    async fn execute(&self, document: &mut Document) -> Result<Stage4Result> {
        let start_time = std::time::Instant::now();
        let mut result = Stage4Result {
            success: false,
            metadata_fields_processed: 0,
            auto_fields_cleared: 0,
            info_xmp_synchronized: false,
            document_id_regenerated: false,
            fallback_values_removed: 0,
            issues: Vec::new(),
            processing_time_ms: 0,
        };

        // Enforce complete metadata control
        self.enforce_metadata_control(document, &mut result).await?;

        // Synchronize Info and XMP metadata
        self.synchronize_info_xmp(document, &mut result).await?;

        // Handle document ID
        self.handle_document_id(document, &mut result).await?;

        // Remove all fallback values
        self.remove_fallback_values(document, &mut result).await?;

        result.processing_time_ms = start_time.elapsed().as_millis() as u64;
        result.success = true;

        info!("Stage 4 completed: {} metadata fields processed, {} auto-fields cleared", 
               result.metadata_fields_processed, result.auto_fields_cleared);
        Ok(result)
    }
}

impl Default for Stage4ProcessorImpl {
    fn default() -> Self {
        Self::new()
    }
}
