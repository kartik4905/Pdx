//! Security module for PDF anti-forensics
//! Created: 2025-06-03 15:41:54 UTC
//! Author: kartik4091

use std::collections::HashMap;
use tracing::{debug, error, info, instrument, warn};

use crate::security::encryption::Encryptor;
use crate::{
    error::{Error, Result},
    types::{Document, Object, ObjectId},
};

// Public module exports
pub mod security_handler;
pub mod encryption;
pub mod permissions;
pub mod signature_cleaner;

// Re-exports for convenient access
pub use security_handler::{SecurityHandler, SecurityStats, SecurityConfig};
pub use encryption::{Encryptor, EncryptionStats, EncryptionConfig, EncryptionMethod};
pub use permissions::{PermissionHandler, PermissionStats, PermissionConfig, Permissions};
pub use signature_cleaner::{SignatureCleaner, CleaningStats as SignatureStats, CleaningConfig as SignatureConfig};

/// Comprehensive security processing statistics
#[derive(Debug, Default)]
pub struct SecurityProcessingStats {
    /// Security handler statistics
    pub handler_stats: SecurityStats,
    
    /// Encryption statistics
    pub encryption_stats: EncryptionStats,
    
    /// Permission statistics
    pub permission_stats: PermissionStats,
    
    /// Signature cleaning statistics
    pub signature_stats: SignatureStats,
    
    /// Total processing duration in milliseconds
    pub total_duration_ms: u64,
}

/// Complete security processing configuration
#[derive(Debug, Clone)]
pub struct SecurityProcessingConfig {
    /// Security handler configuration
    pub handler: Option<SecurityConfig>,
    
    /// Encryption configuration
    pub encryption: Option<EncryptionConfig>,
    
    /// Permission configuration
    pub permissions: Option<PermissionConfig>,
    
    /// Signature cleaning configuration
    pub signatures: Option<SignatureConfig>,
    
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
    /// Security handler processing
    Handler,
    
    /// Encryption processing
    Encryption,
    
    /// Permission processing
    Permissions,
    
    /// Signature cleaning
    Signatures,
}

impl Default for ProcessingOrder {
    fn default() -> Self {
        Self {
            steps: vec![
                ProcessingStep::Handler,
                ProcessingStep::Encryption,
                ProcessingStep::Permissions,
                ProcessingStep::Signatures,
            ],
            enable_parallel: false,
        }
    }
}

impl Default for SecurityProcessingConfig {
    fn default() -> Self {
        Self {
            handler: Some(SecurityConfig::default()),
            encryption: Some(EncryptionConfig::default()),
            permissions: Some(PermissionConfig::default()),
            signatures: Some(SignatureConfig::default()),
            processing_order: ProcessingOrder::default(),
        }
    }
}

/// Main security manager handling all security-related operations
#[derive(Debug)]
pub struct SecurityManager {
    /// Security handler
    handler: SecurityHandler,
    
    /// Encryptor
    encryptor: Encryptor,
    
    /// Permission handler
    permission_handler: PermissionHandler,
    
    /// Signature cleaner
    signature_cleaner: SignatureCleaner,
    
    /// Processing statistics
    stats: SecurityProcessingStats,
}

impl SecurityManager {
    /// Create new security manager instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            handler: SecurityHandler::new()?,
            encryptor: Encryptor::new()?,
            permission_handler: PermissionHandler::new()?,
            signature_cleaner: SignatureCleaner::new()?,
            stats: SecurityProcessingStats::default(),
        })
    }
    
    /// Process document security
    #[instrument(skip(self, document, config))]
    pub async fn process_security(&mut self, document: &mut Document, config: &SecurityProcessingConfig) -> Result<()> {
        let start_time = std::time::Instant::now();
        info!("Starting comprehensive security processing");
        
        if config.processing_order.enable_parallel {
            self.process_security_parallel(document, config).await?;
        } else {
            self.process_security_sequential(document, config).await?;
        }
        
        // Update total statistics
        self.update_statistics();
        
        self.stats.total_duration_ms = start_time.elapsed().as_millis() as u64;
        info!("Security processing completed successfully");
        Ok(())
    }
    
    /// Process security sequentially
    async fn process_security_sequential(&mut self, document: &mut Document, config: &SecurityProcessingConfig) -> Result<()> {
        for step in &config.processing_order.steps {
            match step {
                ProcessingStep::Handler => {
                    if let Some(handler_config) = &config.handler {
                        debug!("Processing security handler");
                        self.handler.process_security(document, handler_config)?;
                    }
                }
                ProcessingStep::Encryption => {
                    if let Some(encryption_config) = &config.encryption {
                        debug!("Processing encryption");
                        self.encryptor.encrypt_document(document, encryption_config)?;
                    }
                }
                ProcessingStep::Permissions => {
                    if let Some(permission_config) = &config.permissions {
                        debug!("Processing permissions");
                        self.permission_handler.process_permissions(document, permission_config)?;
                    }
                }
                ProcessingStep::Signatures => {
                    if let Some(signature_config) = &config.signatures {
                        debug!("Processing signatures");
                        self.signature_cleaner.clean_signatures(document, signature_config)?;
                    }
                }
            }
        }
        Ok(())
    }
    
    /// Process security in parallel where possible
    async fn process_security_parallel(&mut self, document: &mut Document, config: &SecurityProcessingConfig) -> Result<()> {
        use tokio::task;
        use std::sync::Arc;
        use parking_lot::RwLock;
        
        let document = Arc::new(RwLock::new(document));
        let mut handles = Vec::new();
        
        for step in &config.processing_order.steps {
            match step {
                ProcessingStep::Handler => {
                    if let Some(handler_config) = &config.handler {
                        let doc = Arc::clone(&document);
                        let config = handler_config.clone();
                        handles.push(task::spawn(async move {
                            let mut handler = SecurityHandler::new()?;
                            let mut doc = doc.write();
                            handler.process_security(&mut doc, &config)
                        }));
                    }
                }
                ProcessingStep::Encryption => {
                    if let Some(encryption_config) = &config.encryption {
                        let doc = Arc::clone(&document);
                        let config = encryption_config.clone();
                        handles.push(task::spawn(async move {
                            let mut encryptor = Encryptor::new()?;
                            let mut doc = doc.write();
                            encryptor.encrypt_document(&mut doc, &config)
                        }));
                    }
                }
                ProcessingStep::Permissions => {
                    if let Some(permission_config) = &config.permissions {
                        let doc = Arc::clone(&document);
                        let config = permission_config.clone();
                        handles.push(task::spawn(async move {
                            let mut handler = PermissionHandler::new()?;
                            let mut doc = doc.write();
                            handler.process_permissions(&mut doc, &config)
                        }));
                    }
                }
                ProcessingStep::Signatures => {
                    if let Some(signature_config) = &config.signatures {
                        let doc = Arc::clone(&document);
                        let config = signature_config.clone();
                        handles.push(task::spawn(async move {
                            let mut cleaner = SignatureCleaner::new()?;
                            let mut doc = doc.write();
                            cleaner.clean_signatures(&mut doc, &config)
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
        self.stats.handler_stats = *self.handler.statistics();
        self.stats.encryption_stats = *self.encryptor.statistics();
        self.stats.permission_stats = *self.permission_handler.statistics();
        self.stats.signature_stats = *self.signature_cleaner.statistics();
    }
    
    /// Get processing statistics
    pub fn statistics(&self) -> &SecurityProcessingStats {
        &self.stats
    }
    
    /// Reset manager state
    pub fn reset(&mut self) -> Result<()> {
        self.handler.reset();
        self.encryptor.reset();
        self.permission_handler.reset();
        self.signature_cleaner.reset();
        self.stats = SecurityProcessingStats::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn setup_test_manager() -> SecurityManager {
        SecurityManager::new().unwrap()
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
        
        let config = SecurityProcessingConfig {
            processing_order: ProcessingOrder {
                enable_parallel: false,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(manager.process_security(&mut document, &config).await.is_ok());
    }
    
    #[tokio::test]
    async fn test_parallel_processing() {
        let mut manager = setup_test_manager();
        let mut document = create_test_document();
        
        let config = SecurityProcessingConfig {
            processing_order: ProcessingOrder {
                enable_parallel: true,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(manager.process_security(&mut document, &config).await.is_ok());
    }
    
    #[test]
    fn test_statistics_update() {
        let mut manager = setup_test_manager();
        
        // Add some test statistics
        manager.handler.stats.objects_encrypted = 1;
        manager.encryptor.stats.objects_encrypted = 2;
        manager.permission_handler.stats.permissions_updated = 3;
        manager.signature_cleaner.stats.signatures_removed = 4;
        
        manager.update_statistics();
        
        assert_eq!(manager.stats.handler_stats.objects_encrypted, 1);
        assert_eq!(manager.stats.encryption_stats.objects_encrypted, 2);
        assert_eq!(manager.stats.permission_stats.permissions_updated, 3);
        assert_eq!(manager.stats.signature_stats.signatures_removed, 4);
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
    }
}
