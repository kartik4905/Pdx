//! Verification module for PDF anti-forensics
//! Created: 2025-06-03 13:59:42 UTC
//! Author: kartik4091

mod verification_handler;
mod initial_scan;

pub use self::{
    verification_handler::VerificationHandler,
    initial_scan::InitialScanner,
};

use crate::{
    error::Result,
    types::Document,
};

/// Verification result for a document
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Document hash values
    pub hashes: DocumentHashes,
    
    /// Encryption status
    pub encryption_info: Option<EncryptionInfo>,
    
    /// Signature information
    pub signatures: Vec<SignatureInfo>,
    
    /// Hidden content detection results
    pub hidden_content: Vec<HiddenContent>,
    
    /// Steganography scan results
    pub steganography: Vec<StegoDetection>,
    
    /// Verification statistics
    pub statistics: VerificationStats,
}

/// Document hash values
#[derive(Debug, Clone)]
pub struct DocumentHashes {
    /// MD5 hash
    pub md5: String,
    
    /// SHA1 hash
    pub sha1: String,
    
    /// SHA256 hash
    pub sha256: String,
}

/// Encryption information
#[derive(Debug, Clone)]
pub struct EncryptionInfo {
    /// Encryption method
    pub method: String,
    
    /// Key length
    pub key_length: u32,
    
    /// Encryption version
    pub version: String,
    
    /// Permission flags
    pub permissions: u32,
}

/// Digital signature information
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    /// Signature type
    pub sig_type: String,
    
    /// Signer name/identifier
    pub signer: String,
    
    /// Signing time
    pub time: String,
    
    /// Signature location in document
    pub location: String,
    
    /// Verification status
    pub status: SignatureStatus,
}

/// Signature verification status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Signature is valid
    Valid,
    
    /// Signature is invalid
    Invalid(String),
    
    /// Signature verification failed
    Error(String),
}

/// Hidden content detection
#[derive(Debug, Clone)]
pub struct HiddenContent {
    /// Content type
    pub content_type: HiddenContentType,
    
    /// Location in document
    pub location: String,
    
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f64,
    
    /// Additional details
    pub details: String,
}

/// Types of hidden content
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HiddenContentType {
    /// Hidden text
    Text,
    
    /// Hidden image
    Image,
    
    /// Hidden attachment
    Attachment,
    
    /// JavaScript
    JavaScript,
    
    /// Form field
    FormField,
    
    /// Other hidden content
    Other(String),
}

/// Steganography detection
#[derive(Debug, Clone)]
pub struct StegoDetection {
    /// Detection method
    pub method: String,
    
    /// Location in document
    pub location: String,
    
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f64,
    
    /// Additional details
    pub details: String,
}

/// Verification statistics
#[derive(Debug, Clone, Default)]
pub struct VerificationStats {
    /// Number of objects verified
    pub objects_verified: usize,
    
    /// Number of streams analyzed
    pub streams_analyzed: usize,
    
    /// Number of hidden elements found
    pub hidden_elements: usize,
    
    /// Number of signatures found
    pub signatures_found: usize,
    
    /// Verification duration in milliseconds
    pub duration_ms: u64,
}

/// Configuration for verification
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Enable hash computation
    pub compute_hashes: bool,
    
    /// Enable encryption detection
    pub check_encryption: bool,
    
    /// Enable signature verification
    pub verify_signatures: bool,
    
    /// Enable hidden content detection
    pub detect_hidden: bool,
    
    /// Enable steganography detection
    pub detect_stego: bool,
    
    /// Custom verification options
    pub custom_options: HashMap<String, String>,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            compute_hashes: true,
            check_encryption: true,
            verify_signatures: true,
            detect_hidden: true,
            detect_stego: true,
            custom_options: HashMap::new(),
        }
    }
}

use std::collections::HashMap;
