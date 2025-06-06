//! Report generation module for PDF anti-forensics pipeline
//! Author: kartik4091
//! Created: 2025-06-05

use crate::error::Result;
use crate::pipeline::Pipeline;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use thiserror::Error;

pub mod generator;
pub mod formatter;
pub mod templates;

pub use generator::ReportGenerator;
pub use formatter::ReportFormatter;
pub use templates::TemplateEngine;

/// Report configuration
#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub output_path: PathBuf,
    pub format: ReportFormat,
}

/// Report output formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    PlainText,
    Json,
    Html,
    Markdown,
}

/// Report severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Individual report entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEntry {
    pub timestamp: String,
    pub severity: ReportSeverity,
    pub category: String,
    pub message: String,
    pub details: Option<String>,
}

/// Complete report data structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportData {
    pub entries: Vec<ReportEntry>,
    pub metadata: ReportMetadata,
}

/// Report metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub generation_time: Option<String>,
    pub pipeline_version: String,
    pub total_entries: usize,
    pub summary: ReportSummary,
}

/// Report summary statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    pub info_count: usize,
    pub warning_count: usize,
    pub error_count: usize,
    pub critical_count: usize,
}

/// Report generation errors
#[derive(Error, Debug)]
pub enum ReportError {
    #[error("Template error: {0}")]
    TemplateError(String),
    
    #[error("Format error: {0}")]
    FormatError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl ReportData {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            metadata: ReportMetadata {
                pipeline_version: "0.1.0".to_string(),
                ..Default::default()
            },
        }
    }

    pub fn add_entry(&mut self, entry: ReportEntry) {
        self.entries.push(entry);
        self.update_summary();
    }

    pub fn add_info(&mut self, category: &str, message: &str) {
        self.add_entry(ReportEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity: ReportSeverity::Info,
            category: category.to_string(),
            message: message.to_string(),
            details: None,
        });
    }

    pub fn add_warning(&mut self, category: &str, message: &str) {
        self.add_entry(ReportEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity: ReportSeverity::Warning,
            category: category.to_string(),
            message: message.to_string(),
            details: None,
        });
    }

    pub fn add_error(&mut self, category: &str, message: &str) {
        self.add_entry(ReportEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            severity: ReportSeverity::Error,
            category: category.to_string(),
            message: message.to_string(),
            details: None,
        });
    }

    fn update_summary(&mut self) {
        let mut summary = ReportSummary::default();
        for entry in &self.entries {
            match entry.severity {
                ReportSeverity::Info => summary.info_count += 1,
                ReportSeverity::Warning => summary.warning_count += 1,
                ReportSeverity::Error => summary.error_count += 1,
                ReportSeverity::Critical => summary.critical_count += 1,
            }
        }
        self.metadata.total_entries = self.entries.len();
        self.metadata.summary = summary;
    }
}