//! Core Pipeline Orchestration for PDF Forensics & Sanitization
//! Author: kartik4091
//! Fully antiforensic pipeline with verification, cleaning, encryption, metadata handling, and secure output

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, debug, warn};

use crate::config::{ProcessingConfig, VerificationLevel, SecurityOptions, UserMetadata, MetadataConfig};
use crate::types::{Document, ModificationType, Object, ObjectId};
use crate::error::{Error, Result};
use crate::utils::{Logger, Metrics};
use crate::verification::{VerificationEngine, VerificationReport};
use crate::structure::StructureHandler;
use crate::cleaner::{
    file_cleaner::FileCleaner,
    pdf_cleaner::PdfCleaner,
    structure_cleaner::StructureCleaner,
    javascript_cleaner::JavaScriptCleaner,
    secure_delete::SecureDelete
};
use crate::content::{font_processor::FontProcessor, image_processor::ImageProcessor};
use crate::metadata::secure_metadata_handler::SecureMetadataHandler;
use crate::security::security_handler::SecurityHandler;
use crate::output::output_generator::OutputGenerator;
use crate::hash_utils::HashInjector;

pub struct Pipeline {
    config: ProcessingConfig,
    logger: Arc<Logger>,
    state: Arc<RwLock<PipelineState>>,
}

#[derive(Debug, Default)]
pub struct PipelineState {
    pub verification_report: Option<VerificationReport>,
    pub document: Option<Document>,
    pub completed_stages: Vec<String>,
}

impl Pipeline {
    pub fn new(config: ProcessingConfig) -> Self {
        let logger = Arc::new(Logger::default());
        Self {
            config,
            logger,
            state: Arc::new(RwLock::new(PipelineState::default())),
        }
    }

    pub async fn execute(&self, input_path: &str, output_path: &str) -> Result<()> {
        let document = self.load(input_path).await?;
        self.state.write().await.document = Some(document);

        self.verify().await?;
        self.analyze_structure().await?;
        self.clean().await?;
        self.handle_metadata().await?;
        self.process_fonts_images().await?;
        self.apply_security().await?;
        self.inject_hashes().await?;
        self.cleanup_and_output(output_path).await?;

        Ok(())
    }

    async fn load(&self, path: &str) -> Result<Document> {
        info!("Loading document from path: {}", path);
        let doc = Document::load(Path::new(path))?;
        self.state.write().await.completed_stages.push("load".into());
        Ok(doc)
    }

    async fn verify(&self) -> Result<()> {
        info!("Running forensic verification");
        let doc = self.state.read().await.document.as_ref().unwrap();
        let engine = VerificationEngine::new(self.config.verification_level.clone());
        let report = engine.run(doc).await?;

        if !report.passed {
            warn!("Verification issues detected: {}", report.issues.len());
        }

        self.state.write().await.verification_report = Some(report);
        self.state.write().await.completed_stages.push("verification".into());
        Ok(())
    }

    async fn analyze_structure(&self) -> Result<()> {
        info!("Analyzing PDF structure");
        let doc = self.state.read().await.document.as_ref().unwrap().clone();
        let handler = StructureHandler::new(
            HashMap::new(),
            self.state.clone(),
            None,
        );
        handler.analyze_document(&doc).await?;
        self.state.write().await.completed_stages.push("structure_analysis".into());
        Ok(())
    }

    async fn clean(&self) -> Result<()> {
        info!("Starting deep cleaning");
        let mut doc = self.state.write().await.document.take().unwrap();

        FileCleaner::new().clean(&mut doc).await?;
        JavaScriptCleaner::new().clean(&mut doc).await?;
        StructureCleaner::new().clean(&mut doc).await?;
        PdfCleaner::new().clean(&mut doc).await?;

        self.state.write().await.document = Some(doc);
        self.state.write().await.completed_stages.push("cleaning".into());
        Ok(())
    }

    async fn handle_metadata(&self) -> Result<()> {
        info!("Processing secure metadata");
        let meta_config = MetadataConfig::default();
        let logger = self.logger.clone();
        let metrics = Metrics::default();
        let mut handler = SecureMetadataHandler::new(meta_config, logger, metrics);
        let mut doc = self.state.write().await.document.take().unwrap();

        if let Some(meta) = &self.config.user_metadata {
            doc.apply_user_metadata(meta.clone());
        }

        handler.process_metadata(&mut doc).await?;
        self.state.write().await.document = Some(doc);
        self.state.write().await.completed_stages.push("metadata".into());
        Ok(())
    }

    async fn process_fonts_images(&self) -> Result<()> {
        info!("Processing fonts and embedded images");
        let mut doc = self.state.write().await.document.take().unwrap();
        FontProcessor::new().process(&mut doc).await?;
        ImageProcessor::new().process(&mut doc).await?;
        self.state.write().await.document = Some(doc);
        self.state.write().await.completed_stages.push("font_image".into());
        Ok(())
    }

    async fn apply_security(&self) -> Result<()> {
        info!("Applying encryption and permissions");
        if let Some(security) = &self.config.security {
            let mut doc = self.state.write().await.document.take().unwrap();
            let mut handler = SecurityHandler::new();
            handler.encrypt(&mut doc, security)?;
            self.state.write().await.document = Some(doc);
            self.state.write().await.completed_stages.push("encryption".into());
        }
        Ok(())
    }

    async fn inject_hashes(&self) -> Result<()> {
        info!("Injecting SHA, MD5, and SHA1 hashes into metadata");
        let mut doc = self.state.write().await.document.take().unwrap();
        let mut injector = HashInjector::new();
        injector.inject_all(&mut doc)?;
        self.state.write().await.document = Some(doc);
        self.state.write().await.completed_stages.push("hash_injection".into());
        Ok(())
    }

    async fn cleanup_and_output(&self, output_path: &str) -> Result<()> {
        info!("Final cleanup and output generation");
        let mut doc = self.state.write().await.document.take().unwrap();

        self.remove_multiple_eofs(&mut doc)?;

        OutputGenerator::new().generate(&doc, output_path).await?;
        self.state.write().await.completed_stages.push("output".into());
        Ok(())
    }

    fn remove_multiple_eofs(&self, doc: &mut Document) -> Result<()> {
        doc.strip_eofs();
        doc.append_final_eof();
        Ok(())
    }
}
