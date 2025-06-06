//! Metadata Scanner Implementation
//! Author: kartik4905
//! Created: 2025-06-03 09:16:08 UTC

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use regex::Regex;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    error::{Error, Result},
    types::{Document, Object, ObjectId},
};

/// Metadata scanner implementation
pub struct MetadataScanner {
    /// Scanner state
    state: RwLock<MetadataScannerState>,
}

/// Metadata scanner state
#[derive(Debug, Default)]
pub struct MetadataScannerState {
    /// Detected metadata patterns
    patterns: HashMap<String, Regex>,
}

/// Scan finding
#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub severity: Severity,
    pub category: Category,
    pub description: String,
    pub location: String,
    pub recommendation: String,
    pub timestamp: Option<DateTime<Utc>>, // Made optional to avoid fallback
}

/// Scan result severity levels
#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Low,
    Medium,
    High,
}

/// Scan result categories
#[derive(Debug, Clone, Copy)]
pub enum Category {
    Security,
    Privacy,
    Compliance,
}

impl MetadataScanner {
    /// New instance
    pub fn new() -> Self {
        Self {
            state: RwLock::new(MetadataScannerState::default()),
        }
    }

    /// Scans metadata for patterns
    #[instrument(skip(self, metadata))]
    pub async fn scan_metadata(&self, metadata: &HashMap<String, String>) -> Result<Vec<ScanFinding>> {
        let mut findings = Vec::new();
        let state = self.state.read().await;

        for (field, value) in metadata {
            // Check custom patterns
            for (pattern_name, pattern) in &state.patterns {
                if pattern.is_match(value) {
                    findings.push(ScanFinding {
                        severity: Severity::High,
                        category: Category::Security,
                        description: format!("Sensitive information found: {}", pattern_name),
                        location: format!("Metadata field: {}", field),
                        recommendation: "Remove or redact sensitive information".into(),
                        timestamp: None, // No fallback timestamp added
                    });
                }
            }

            // Check common patterns
            for (pattern_name, pattern_str) in COMMON_PATTERNS.iter() {
                if Regex::new(pattern_str).unwrap().is_match(value) {
                    findings.push(ScanFinding {
                        severity: Severity::High,
                        category: Category::Security,
                        description: format!("Common sensitive pattern found: {}", pattern_name),
                        location: format!("Metadata field: {}", field),
                        recommendation: "Review and remove sensitive information".into(),
                        timestamp: None, // No fallback timestamp added
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Adds a custom pattern
    #[instrument(skip(self))]
    pub async fn add_pattern(&self, name: &str, pattern: &str) -> Result<()> {
        let mut state = self.state.write().await;
        state.patterns.insert(name.to_string(), Regex::new(pattern)?);
        Ok(())
    }
}

/// Common patterns for metadata scanning
pub const COMMON_PATTERNS: &[(&str, &str)] = &[
    ("Email Address", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    ("Phone Number", r"\+?\d[\d -]{8,}\d"),
    ("Credit Card", r"\b(?:\d[ -]*?){13,16}\b"),
];
