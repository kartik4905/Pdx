//! Error types and handling for the PDF Forensics library
//! Created: 2025-06-03 11:31:05 UTC
//! Author: kartik4905

use std::{
    error::Error as StdError,
    fmt::{Display, Formatter, Result as FmtResult},
    io,
    result::Result as StdResult,
    sync::PoisonError,
};

use thiserror::Error;
use tokio::sync::TryLockError;
use tracing::error;

/// Custom result type for antiforensics operations
pub type Result<T> = StdResult<T, Error>;

/// Core error type for antiforensics operations
#[derive(Error, Debug)]
#[non_exhaustive]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[error("Initialization error: {0}")]
    InitializationError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("PDF structure error: {0}")]
    StructureError(#[from] StructureError),

    #[error("Analysis error: {0}")]
    AnalysisError(#[from] AnalysisError),

    #[error("Cleaner error: {0}")]
    CleanerError(#[from] CleanerError),

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] EncryptionError),

    #[error("Hash error: {0}")]
    HashError(#[from] HashError),

    #[error("Scanner error: {0}")]
    ScannerError(#[from] ScannerError),

    #[error("Stego error: {0}")]
    StegoError(#[from] StegoError),

    #[error("Verification error: {0}")]
    VerificationError(#[from] VerificationError),

    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Concurrency error: {0}")]
    ConcurrencyError(String),

    #[error("Lock error: {0}")]
    LockError(String),

    #[error("Resource error: {0}")]
    ResourceError(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Internal error: {0}")]
    InternalError(#[source] Box<dyn StdError + Send + Sync>),
}

impl Error {
    /// Helper for creating an `InternalError` with a boxed source
    pub fn internal<E: StdError + Send + Sync + 'static>(e: E) -> Self {
        Error::InternalError(Box::new(e))
    }
}

// Implement conversions
impl<T> From<PoisonError<T>> for Error {
    fn from(err: PoisonError<T>) -> Self {
        Error::ConcurrencyError(err.to_string())
    }
}

impl From<TryLockError> for Error {
    fn from(err: TryLockError) -> Self {
        Error::LockError(format!("{:?}", err))
    }
}

// -------------------- Sub-Error Categories --------------------

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum StructureError {
    #[error("Invalid PDF header: {0}")]
    InvalidHeader(String),

    #[error("Invalid xref table: {0}")]
    InvalidXref(String),

    #[error("Invalid trailer: {0}")]
    InvalidTrailer(String),

    #[error("Invalid object stream: {0}")]
    InvalidObjectStream(String),

    #[error("Missing required object: {0}")]
    MissingObject(String),

    #[error("Corrupted structure: {0}")]
    Corrupted(String),
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AnalysisError {
    #[error("Pattern analysis failed: {0}")]
    PatternError(String),

    #[error("Content analysis failed: {0}")]
    ContentError(String),

    #[error("Metadata analysis failed: {0}")]
    MetadataError(String),

    #[error("Version analysis failed: {0}")]
    VersionError(String),
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CleanerError {
    #[error("Metadata cleaning failed: {0}")]
    MetadataError(String),

    #[error("Content cleaning failed: {0}")]
    ContentError(String),

    #[error("Structure cleaning failed: {0}")]
    StructureError(String),

    #[error("Stream cleaning failed: {0}")]
    StreamError(String),
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum EncryptionError {
    #[error("Encryption algorithm not supported: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    #[error("Encryption process failed: {0}")]
    ProcessError(String),
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("Verification failed: {0}")]
    General(String),

    #[error("Checksum mismatch for file: {0}")]
    ChecksumMismatch(String),

    #[error("Signature validation failed: {0}")]
    SignatureError(String),
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ScannerError {
    #[error("Scanner initialization failed: {0}")]
    InitializationError(String),

    #[error("Pattern matching failed: {0}")]
    PatternMatchError(String),

    #[error("File signature mismatch: {0}")]
    SignatureMismatch(String),
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum StegoError {
    #[error("Steganographic content not found: {0}")]
    NotFound(String),

    #[error("Steganographic extraction failed: {0}")]
    ExtractionError(String),

    #[error("Steganographic embedding failed: {0}")]
    EmbeddingError(String),
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum HashError {
    #[error("Hash algorithm unsupported: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Hash computation failed: {0}")]
    ComputationError(String),
                                 }
