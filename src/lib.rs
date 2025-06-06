//! Main Library File for PDF Forensics and Sanitization
//! Provides a modular, pipeline-based architecture for analyzing,
//! cleaning, processing, and securing PDF documents.

// Configuration and Core Pipeline
pub mod config;
pub mod pipeline;
pub mod types;
pub mod pdf_document;
pub mod error;
pub mod hash_utils;

// Stage 0: Initial Document Loading & Verification
pub mod verification {
    pub mod verification_handler;
}

// Stage 1: Deep Structure Analysis
pub mod structure;

pub use structure::{
    analysis::{StructureAnalysis, StructureIssue, IssueSeverity, IssueLocation, AnalysisConfig},
    relationships::ObjectRelationships,
    metrics::DocumentMetrics,
    statistics::AnalysisStatistics,
    progress::{ProgressCallback, ProgressUpdate, AnalysisStage},
    structure_handler::StructureHandler,
    parser::PdfParser,
    cross_ref::CrossRefHandler,
    linearization::LinearizationHandler,
};

// Stage 2: Deep Cleaning Phase
pub mod cleaner {
    pub mod binary_sanitizer;
    pub mod content_cleaner;
    pub mod deep_cleaner;
    pub mod file_cleaner;
    pub mod javascript_cleaner;
    pub mod pdf_cleaner;
    pub mod secure_delete;
    pub mod stream_processor;
    pub mod structure_cleaner;
}

// Stage 3: Font & Image Processing
pub mod content {
    pub mod content_processor;
    pub mod font_processor;
    pub mod image_processor;
    pub mod resource_cleaner;
}

// Top-level module declaration
pub mod hash_injector;
pub mod hash;

// Stage 4: Metadata Handling
pub mod metadata {
    pub mod metadata_cleaner;
    pub mod secure_metadata_handler;
    pub mod id_cleaner;
}

// Stage 5: Security Implementation
pub mod security {
    pub mod security_handler;
    pub mod encryption;
}

// Stage 6: Forensic Verification
pub mod forensics {
    pub mod forensic_scanner;
    pub mod verification_engine;
}

// Stage 7: Clean Output Generation
pub mod output {
    pub mod output_generator;
}

// Stage 8: Verifier Modules
pub mod verifier;

pub use verifier::{
    chain_verifier::ChainVerifier,
    forensic_verifier::ForensicVerifier,
    security_verifier::SecurityVerifier,
};

// Stage 9: Report Generation
pub mod report;

pub use report::{
    ReportData,
    ReportEntry,
    ReportSeverity,
    ReportGenerator,
    ReportConfig,
    ReportFormat,
    ReportError,
    ReportFormatter,
    TemplateEngine,
};

// Shared Utilities
pub mod utils;

// Re-exports for crate consumers
pub use cleaner::deep_cleaner::DeepCleaner;
pub use forensics::{forensic_scanner::ForensicScanner, verification_engine::VerificationEngine};
pub use metadata::{metadata_cleaner::MetadataCleaner, secure_metadata_handler::SecureMetadataHandler};
pub use output::output_generator::OutputGenerator;
pub use content::{content_processor::ContentProcessor, font_processor::FontProcessor, image_processor::ImageProcessor};
pub use security::security_handler::SecurityHandler;
pub use utils::{Logger, Metrics};
pub use types::{Document, Metadata, ModificationType};
