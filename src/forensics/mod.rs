//! Forensics module for PDF anti-forensics
//! Created: 2025-06-03 16:06:58 UTC
//! Author: kartik4091

use std::collections::HashMap;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    error::{Error, Result},
    types::{Document, Object, ObjectId},
};

// Public module exports
pub mod forensic_scanner;
pub mod stego_detector;
pub mod hidden_data_scanner;
pub mod trace_detector;

// Re-exports for convenient access
pub use forensic_scanner::{ForensicScanner, ScanningStats as ForensicStats, ScanningConfig as ForensicConfig};
pub use stego_detector::{StegoDetector, DetectionStats as StegoStats, DetectionConfig as StegoConfig};
pub use hidden_data_scanner::{HiddenDataScanner, ScanningStats as HiddenDataStats, ScanningConfig as HiddenDataConfig};
pub use trace_detector::{TraceDetector, DetectionStats as TraceStats, DetectionConfig as TraceConfig};

/// Comprehensive forensic analysis statistics
#[derive(Debug, Default)]
pub struct ForensicAnalysisStats {
    /// Forensic scanning statistics
    pub forensic_stats: ForensicStats,
    
    /// Steganography detection statistics
    pub stego_stats: StegoStats,
    
    /// Hidden data scanning statistics
    pub hidden_data_stats: HiddenDataStats,
    
    /// Trace detection statistics
    pub trace_stats: TraceStats,
    
    /// Total processing duration in milliseconds
    pub total_duration_ms: u64,
}

/// Complete forensic analysis configuration
#[derive(Debug, Clone)]
pub struct ForensicAnalysisConfig {
    /// Forensic scanning configuration
    pub forensic: Option<ForensicConfig>,
    
    /// Steganography detection configuration
    pub stego: Option<StegoConfig>,
    
    /// Hidden data scanning configuration
    pub hidden_data: Option<HiddenDataConfig>,
    
    /// Trace detection configuration
    pub trace: Option<TraceConfig>,
    
    /// Analysis order
    pub analysis_order: AnalysisOrder,
}

/// Analysis order configuration
#[derive(Debug, Clone)]
pub struct AnalysisOrder {
    /// Analysis steps
    pub steps: Vec<AnalysisStep>,
    
    /// Parallel analysis where possible
    pub enable_parallel: bool,
}

/// Analysis step types
#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisStep {
    /// Forensic scanning
    Forensic,
    
    /// Steganography detection
    Stego,
    
    /// Hidden data scanning
    HiddenData,
    
    /// Trace detection
    Trace,
}

impl Default for AnalysisOrder {
    fn default() -> Self {
        Self {
            steps: vec![
                AnalysisStep::Forensic,
                AnalysisStep::Stego,
                AnalysisStep::HiddenData,
                AnalysisStep::Trace,
            ],
            enable_parallel: false,
        }
    }
}

impl Default for ForensicAnalysisConfig {
    fn default() -> Self {
        Self {
            forensic: Some(ForensicConfig::default()),
            stego: Some(StegoConfig::default()),
            hidden_data: Some(HiddenDataConfig::default()),
            trace: Some(TraceConfig::default()),
            analysis_order: AnalysisOrder::default(),
        }
    }
}

/// Main forensics manager handling all forensic analysis operations
#[derive(Debug)]
pub struct ForensicsManager {
    /// Forensic scanner
    forensic_scanner: ForensicScanner,
    
    /// Steganography detector
    stego_detector: StegoDetector,
    
    /// Hidden data scanner
    hidden_data_scanner: HiddenDataScanner,
    
    /// Trace detector
    trace_detector: TraceDetector,
    
    /// Analysis statistics
    stats: ForensicAnalysisStats,
}

impl ForensicsManager {
    /// Create new forensics manager instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            forensic_scanner: ForensicScanner::new()?,
            stego_detector: StegoDetector::new()?,
            hidden_data_scanner: HiddenDataScanner::new()?,
            trace_detector: TraceDetector::new()?,
            stats: ForensicAnalysisStats::default(),
        })
    }
    
    /// Perform forensic analysis
    #[instrument(skip(self, document, config))]
    pub async fn analyze_document(&mut self, document: &Document, config: &ForensicAnalysisConfig) -> Result<()> {
        let start_time = std::time::Instant::now();
        info!("Starting comprehensive forensic analysis");
        
        if config.analysis_order.enable_parallel {
            self.analyze_document_parallel(document, config).await?;
        } else {
            self.analyze_document_sequential(document, config).await?;
        }
        
        // Update total statistics
        self.update_statistics();
        
        self.stats.total_duration_ms = start_time.elapsed().as_millis() as u64;
        info!("Forensic analysis completed successfully");
        Ok(())
    }
    
    /// Perform sequential analysis
    async fn analyze_document_sequential(&mut self, document: &Document, config: &ForensicAnalysisConfig) -> Result<()> {
        for step in &config.analysis_order.steps {
            match step {
                AnalysisStep::Forensic => {
                    if let Some(forensic_config) = &config.forensic {
                        debug!("Performing forensic scanning");
                        self.forensic_scanner.scan_document(document, forensic_config)?;
                    }
                }
                AnalysisStep::Stego => {
                    if let Some(stego_config) = &config.stego {
                        debug!("Performing steganography detection");
                        self.stego_detector.analyze_document(document, stego_config)?;
                    }
                }
                AnalysisStep::HiddenData => {
                    if let Some(hidden_data_config) = &config.hidden_data {
                        debug!("Performing hidden data scanning");
                        self.hidden_data_scanner.scan_document(document, hidden_data_config)?;
                    }
                }
                AnalysisStep::Trace => {
                    if let Some(trace_config) = &config.trace {
                        debug!("Performing trace detection");
                        self.trace_detector.detect_traces(document, trace_config)?;
                    }
                }
            }
        }
        Ok(())
    }
    
    /// Perform parallel analysis
    async fn analyze_document_parallel(&mut self, document: &Document, config: &ForensicAnalysisConfig) -> Result<()> {
        use tokio::task;
        use std::sync::Arc;
        
        let document = Arc::new(document);
        let mut handles = Vec::new();
        
        for step in &config.analysis_order.steps {
            match step {
                AnalysisStep::Forensic => {
                    if let Some(forensic_config) = &config.forensic {
                        let doc = Arc::clone(&document);
                        let config = forensic_config.clone();
                        handles.push(task::spawn(async move {
                            let mut scanner = ForensicScanner::new()?;
                            scanner.scan_document(&doc, &config)
                        }));
                    }
                }
                AnalysisStep::Stego => {
                    if let Some(stego_config) = &config.stego {
                        let doc = Arc::clone(&document);
                        let config = stego_config.clone();
                        handles.push(task::spawn(async move {
                            let mut detector = StegoDetector::new()?;
                            detector.analyze_document(&doc, &config)
                        }));
                    }
                }
                AnalysisStep::HiddenData => {
                    if let Some(hidden_data_config) = &config.hidden_data {
                        let doc = Arc::clone(&document);
                        let config = hidden_data_config.clone();
                        handles.push(task::spawn(async move {
                            let mut scanner = HiddenDataScanner::new()?;
                            scanner.scan_document(&doc, &config)
                        }));
                    }
                }
                AnalysisStep::Trace => {
                    if let Some(trace_config) = &config.trace {
                        let doc = Arc::clone(&document);
                        let config = trace_config.clone();
                        handles.push(task::spawn(async move {
                            let mut detector = TraceDetector::new()?;
                            detector.detect_traces(&doc, &config)
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
        self.stats.forensic_stats = *self.forensic_scanner.statistics();
        self.stats.stego_stats = *self.stego_detector.statistics();
        self.stats.hidden_data_stats = *self.hidden_data_scanner.statistics();
        self.stats.trace_stats = *self.trace_detector.statistics();
    }
    
    /// Get analysis statistics
    pub fn statistics(&self) -> &ForensicAnalysisStats {
        &self.stats
    }
    
    /// Get forensic scanner
    pub fn forensic_scanner(&self) -> &ForensicScanner {
        &self.forensic_scanner
    }
    
    /// Get steganography detector
    pub fn stego_detector(&self) -> &StegoDetector {
        &self.stego_detector
    }
    
    /// Get hidden data scanner
    pub fn hidden_data_scanner(&self) -> &HiddenDataScanner {
        &self.hidden_data_scanner
    }
    
    /// Get trace detector
    pub fn trace_detector(&self) -> &TraceDetector {
        &self.trace_detector
    }
    
    /// Reset manager state
    pub fn reset(&mut self) -> Result<()> {
        self.forensic_scanner.reset();
        self.stego_detector.reset();
        self.hidden_data_scanner.reset();
        self.trace_detector.reset();
        self.stats = ForensicAnalysisStats::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn setup_test_manager() -> ForensicsManager {
        ForensicsManager::new().unwrap()
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
    async fn test_sequential_analysis() {
        let mut manager = setup_test_manager();
        let document = create_test_document();
        
        let config = ForensicAnalysisConfig {
            analysis_order: AnalysisOrder {
                enable_parallel: false,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(manager.analyze_document(&document, &config).await.is_ok());
    }
    
    #[tokio::test]
    async fn test_parallel_analysis() {
        let mut manager = setup_test_manager();
        let document = create_test_document();
        
        let config = ForensicAnalysisConfig {
            analysis_order: AnalysisOrder {
                enable_parallel: true,
                ..Default::default()
            },
            ..Default::default()
        };
        
        assert!(manager.analyze_document(&document, &config).await.is_ok());
    }
    
    #[test]
    fn test_statistics_update() {
        let mut manager = setup_test_manager();
        
        // Add some test statistics
        manager.forensic_scanner.stats.objects_scanned = 1;
        manager.stego_detector.stats.potential_detections = 2;
        manager.hidden_data_scanner.stats.instances_found = 3;
        manager.trace_detector.stats.traces_detected = 4;
        
        manager.update_statistics();
        
        assert_eq!(manager.stats.forensic_stats.objects_scanned, 1);
        assert_eq!(manager.stats.stego_stats.potential_detections, 2);
        assert_eq!(manager.stats.hidden_data_stats.instances_found, 3);
        assert_eq!(manager.stats.trace_stats.traces_detected, 4);
    }
    
    #[test]
    fn test_manager_reset() {
        let mut manager = setup_test_manager();
        
        manager.stats.total_duration_ms = 1000;
        assert!(manager.reset().is_ok());
        assert_eq!(manager.stats.total_duration_ms, 0);
    }
    
    #[test]
    fn test_analysis_order() {
        let order = AnalysisOrder::default();
        assert_eq!(order.steps.len(), 4);
        assert!(!order.enable_parallel);
    }
}
