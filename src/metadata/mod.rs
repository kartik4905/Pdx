//! Metadata handling and cleaning module for PDF anti-forensics
//! Created: 2025-06-03 15:05:27 UTC
//! Author: kartik4091

use std::collections::HashMap;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    error::{Error, Result},
    types::{Document, Object, ObjectId},
};

// Public module exports
pub mod secure_metadata_handler;
pub mod info_cleaner;
pub mod xmp_cleaner;
pub mod id_cleaner;
pub mod redactor;

// Re-exports for convenient access
pub use secure_metadata_handler::{SecureMetadataHandler, SecurityStats, EncryptionSettings, SignatureSettings};
pub use info_cleaner::{InfoCleaner, CleaningStats as InfoCleaningStats, CleaningConfig as InfoConfig};
pub use xmp_cleaner::{XMPCleaner, CleaningStats as XMPCleaningStats, XMPConfig};
pub use id_cleaner::{IDCleaner, CleaningStats as IDCleaningStats, IDConfig};

/// Comprehensive metadata processing statistics
#[derive(Debug, Default)]
pub struct MetadataStats {
    /// Security-related statistics
    pub security_stats: SecurityStats,

    /// Info dictionary cleaning statistics
    pub info_stats: InfoCleaningStats,

    /// XMP metadata cleaning statistics
    pub xmp_stats: XMPCleaningStats,

    /// Document ID cleaning statistics
    pub id_stats: IDCleaningStats,

    /// Total processing duration in milliseconds
    pub total_duration_ms: u64,
}

/// Complete metadata processing configuration
#[derive(Debug, Clone)]
pub struct MetadataConfig {
    /// Security configuration
    pub security: Option<SecurityConfig>,

    /// Info dictionary cleaning configuration
    pub info: Option<InfoConfig>,

    /// XMP metadata cleaning configuration
    pub xmp: Option<XMPConfig>,

    /// Document ID cleaning configuration
    pub id: Option<IDConfig>,
}

/// Security configuration wrapper
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Encryption settings
    pub encryption: Option<EncryptionSettings>,

    /// Signature settings
    pub signature: Option<SignatureSettings>,
}

/// Main metadata processor handling all aspects of metadata cleaning
#[derive(Debug)]
pub struct MetadataProcessor {
    /// Security handler
    secure_handler: SecureMetadataHandler,

    /// Info dictionary cleaner
    info_cleaner: InfoCleaner,

    /// XMP metadata cleaner
    xmp_cleaner: XMPCleaner,

    /// Document ID cleaner
    id_cleaner: IDCleaner,

    /// Processing statistics
    stats: MetadataStats,
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            security: None,
            info: Some(InfoConfig::default()),
            xmp: Some(XMPConfig::default()),
            id: Some(IDConfig::default()),
        }
    }
}

impl MetadataProcessor {
    /// Create a new metadata processor instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            secure_handler: SecureMetadataHandler::new()?,
            info_cleaner: InfoCleaner::new()?,
            xmp_cleaner: XMPCleaner::new()?,
            id_cleaner: IDCleaner::new()?,
            stats: MetadataStats::default(),
        })
    }

    /// Configure the processor with comprehensive settings
    #[instrument(skip(self, config))]
    pub fn configure(&mut self, config: &MetadataConfig) -> Result<()> {
        info!("Configuring metadata processor");
        
        // Configure security if specified
        if let Some(security) = &config.security {
            if let Some(encryption) = &security.encryption {
                self.secure_handler.configure_encryption(encryption.clone())?;
            }
            if let Some(signature) = &security.signature {
                self.secure_handler.configure_signature(signature.clone())?;
            }
        }
        
        // Configure cleaners if specified
        if let Some(info_config) = &config.info {
            self.info_cleaner.configure(info_config)?;
        }
        
        if let Some(xmp_config) = &config.xmp {
            self.xmp_cleaner.configure(xmp_config)?;
        }
        
        if let Some(id_config) = &config.id {
            self.id_cleaner.configure_id_cleaning(id_config)?;
        }
        
        debug!("Metadata processor configured successfully");
        Ok(())
    }

    /// Process all metadata in document
    #[instrument(skip(self, document, config))]
    pub async fn process_metadata(&mut self, document: &mut Document, config: &MetadataConfig) -> Result<()> {
        let start_time = std::time::Instant::now();
        info!("Starting comprehensive metadata processing");
        
        // Security processing
        if config.security.is_some() {
            match self.secure_handler.process_metadata(document).await {
                Ok(_) => {
                    self.stats.security_stats = *self.secure_handler.statistics();
                    debug!("Security processing completed successfully");
                }
                Err(e) => {
                    error!("Security processing failed: {:?}", e);
                    return Err(e);
                }
            }
        }
        
        // Info dictionary cleaning
        if let Some(info_config) = &config.info {
            match self.info_cleaner.clean_info_dictionary(document, info_config) {
                Ok(_) => {
                    self.stats.info_stats = *self.info_cleaner.statistics();
                    debug!("Info dictionary cleaning completed successfully");
                }
                Err(e) => {
                    error!("Info dictionary cleaning failed: {:?}", e);
                    return Err(e);
                }
            }
        }
        
        // XMP metadata cleaning
        if let Some(xmp_config) = &config.xmp {
            match self.xmp_cleaner.clean_xmp(document, xmp_config) {
                Ok(_) => {
                    self.stats.xmp_stats = *self.xmp_cleaner.statistics();
                    debug!("XMP metadata cleaning completed successfully");
                }
                Err(e) => {
                    error!("XMP metadata cleaning failed: {:?}", e);
                    return Err(e);
                }
            }
        }
        
        // Document ID cleaning
        if let Some(id_config) = &config.id {
            match self.id_cleaner.clean_document_ids(document, id_config) {
                Ok(_) => {
                    self.stats.id_stats = *self.id_cleaner.statistics();
                    debug!("Document ID cleaning completed successfully");
                }
                Err(e) => {
                    error!("Document ID cleaning failed: {:?}", e);
                    return Err(e);
                }
            }
        }
        
        self.stats.total_duration_ms = start_time.elapsed().as_millis() as u64;
        info!("Comprehensive metadata processing completed successfully");
        Ok(())
    }

    /// Get processing statistics
    pub fn statistics(&self) -> &MetadataStats {
        &self.stats
    }

    /// Reset all processors
    pub fn reset(&mut self) -> Result<()> {
        self.secure_handler = SecureMetadataHandler::new()?;
        self.info_cleaner = InfoCleaner::new()?;
        self.xmp_cleaner = XMPCleaner::new()?;
        self.id_cleaner = IDCleaner::new()?;
        self.stats = MetadataStats::default();
        Ok(())
    }
        }
