//! Configuration types and validation for the pipeline
//! Author: kartik4091
//! Created: 2025-06-03

use serde::{Serialize, Deserialize};
use crate::utils::{UtilityConfig, UtilError, Result};

/// Configuration for structure or content analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub check_xref: bool,
    pub check_scripts: bool,
    pub entropy_threshold: f64,
    pub detect_recursion: bool,
}

/// Configuration for secure metadata processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataConfig {
    pub clean_info: bool,
    pub remove_xmp: bool,
    pub check_entropy: bool,
    pub preserve_keys: Vec<String>,
}

/// Configuration for cleaner base settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanerConfig {
    pub verify: bool,
    pub passes: usize,
    pub max_concurrent_ops: usize,
    pub buffer_size: usize,
    pub throttle_ms: Option<u64>,
}

/// Global pipeline execution config
#[derive(Debug, Clone)]
pub struct ProcessingConfig {
    pub user_metadata: Option<UserMetadata>,
    pub security: Option<SecurityOptions>,
    pub verification_level: VerificationLevel,
}

/// User-supplied metadata to inject into Info/XMP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMetadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
}

/// Encryption, password protection and permission restriction
#[derive(Debug, Clone)]
pub struct SecurityOptions {
    pub user_password: Option<String>,
    pub owner_password: Option<String>,
    pub restrictions: Option<PermissionRestrictions>,
}

/// Document permission restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRestrictions {
    pub allow_printing: bool,
    pub allow_copy: bool,
    pub allow_annotate: bool,
    pub allow_form_fill: bool,
    pub allow_extract: bool,
    pub allow_accessibility: bool,
    pub allow_assembly: bool,
}

/// Verification depth configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationLevel {
    Paranoid,
    Normal,
    Lite,
}

// Defaults
impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            check_xref: true,
            check_scripts: true,
            entropy_threshold: 7.5,
            detect_recursion: true,
        }
    }
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            clean_info: true,
            remove_xmp: true,
            check_entropy: true,
            preserve_keys: vec!["Title".into(), "Author".into()],
        }
    }
}

impl Default for CleanerConfig {
    fn default() -> Self {
        Self {
            verify: false,
            passes: 0,
            max_concurrent_ops: 4,
            buffer_size: 8192,
            throttle_ms: None,
        }
    }
}

impl Default for ProcessingConfig {
    fn default() -> Self {
        Self {
            user_metadata: None,
            security: None,
            verification_level: VerificationLevel::Normal,
        }
    }
}

impl Default for PermissionRestrictions {
    fn default() -> Self {
        Self {
            allow_printing: true,
            allow_copy: true,
            allow_annotate: true,
            allow_form_fill: true,
            allow_extract: true,
            allow_accessibility: true,
            allow_assembly: true,
        }
    }
}

// CleanerConfig validation implementation
impl UtilityConfig for CleanerConfig {
    fn validate(&self) -> Result<()> {
        if self.passes > 10 {
            return Err(UtilError::Validation("Too many overwrite passes".into()));
        }
        if self.buffer_size < 512 {
            return Err(UtilError::Validation("Buffer size too small".into()));
        }
        if self.max_concurrent_ops == 0 {
            return Err(UtilError::Validation("Concurrency must be at least 1".into()));
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Option<String> {
        match key {
            "verify" => Some(self.verify.to_string()),
            "passes" => Some(self.passes.to_string()),
            "max_concurrent_ops" => Some(self.max_concurrent_ops.to_string()),
            "buffer_size" => Some(self.buffer_size.to_string()),
            "throttle_ms" => self.throttle_ms.map(|v| v.to_string()),
            _ => None,
        }
    }

    fn set(&mut self, key: &str, value: String) -> Result<()> {
        match key {
            "verify" => self.verify = value.parse().map_err(|_| UtilError::Validation("Invalid bool".into()))?,
            "passes" => self.passes = value.parse().map_err(|_| UtilError::Validation("Invalid usize".into()))?,
            "max_concurrent_ops" => self.max_concurrent_ops = value.parse().map_err(|_| UtilError::Validation("Invalid usize".into()))?,
            "buffer_size" => self.buffer_size = value.parse().map_err(|_| UtilError::Validation("Invalid usize".into()))?,
            "throttle_ms" => self.throttle_ms = Some(value.parse().map_err(|_| UtilError::Validation("Invalid u64".into()))?),
            _ => return Err(UtilError::Validation(format!("Unknown key: {}", key))),
        }
        Ok(())
    }
        }
