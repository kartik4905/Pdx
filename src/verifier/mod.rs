//! PDF Verifier Module
//! Author: kartik4091
//! Created: 2025-06-04 10:24:00 UTC
//!
//! This module implements layered verification logic for forensic assurance,
//! compliance enforcement, and integrity checks on PDF documents.

use std::collections::HashMap;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

// Submodule declarations
pub mod chain_verifier;
pub mod forensic_verifier;
pub mod security_verifier;

// Re-exports for unified access
pub use self::{
    chain_verifier::ChainVerifier,
    forensic_verifier::{ForensicVerifier, ForensicVerificationResult},
    security_verifier::{SecurityVerifier, SecurityVerificationResult},
};

/// Result type used across all verifiers
pub type Result<T> = std::result::Result<T, VerifierError>;

/// Main error type for all verification logic
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("Chain of trust failed: {0}")]
    ChainFailure(String),

    #[error("Security verification error: {0}")]
    SecurityError(String),

    #[error("Forensic mismatch: {0}")]
    ForensicError(String),

    #[error("IO failure: {0}")]
    Io(#[from] std::io::Error),

    #[error("Generic verification failure: {0}")]
    General(String),
}

/// Output structure from each verification step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub passed: bool,
    pub issues: Vec<VerificationIssue>,
    pub metadata: HashMap<String, String>,
    pub verified_at: DateTime<Utc>,
    pub duration: Duration,
}

/// Individual issue or finding from a verifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationIssue {
    pub category: IssueCategory,
    pub severity: IssueSeverity,
    pub description: String,
    pub hint: Option<String>,
    pub offset: Option<u64>,
}

/// Category of a verification issue
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IssueCategory {
    Cryptographic,
    Structural,
    Metadata,
    Timestamp,
    Redaction,
    Signature,
}

/// Severity levels for issues
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IssueSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Standard interface all verifier modules must implement
#[async_trait]
pub trait Verifier: Send + Sync {
    /// Perform verification on the provided PDF byte buffer
    async fn verify(&self, data: &[u8]) -> Result<VerificationReport>;

    /// Indicates whether this verifier is optional or required
    fn is_mandatory(&self) -> bool;
}
