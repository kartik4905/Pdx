//! Chained Verifier Implementation for Multi-stage Verification Pipeline
//! Author: kartik4091

use crate::{
    error::{Error, Result},
    types::{Document, ProcessingState},
    verification::verification_handler::VerificationHandler,
    structure::structure_handler::StructureHandler,
    metadata::secure_metadata_handler::SecureMetadataHandler,
    utils::{Logger, Metrics},
    utils::logger::LogLevel,
};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Execution result per stage
#[derive(Debug, Clone)]
pub struct StageResult {
    pub stage: String,
    pub success: bool,
    pub duration_ms: u128,
    pub message: Option<String>,
}

/// ChainVerifier coordinates all verification phases
pub struct ChainVerifier {
    logger: Arc<Logger>,
    metrics: Arc<Metrics>,
    pub results: Arc<RwLock<Vec<StageResult>>>,
}

impl ChainVerifier {
    pub fn new(logger: Arc<Logger>, metrics: Arc<Metrics>) -> Self {
        Self {
            logger,
            metrics,
            results: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn run_all(&self, path: &str) -> Result<()> {
        self.run_verification_handler(path).await?;
        self.run_structure_analysis(path).await?;
        self.run_metadata_handler(path).await?;
        Ok(())
    }

    async fn run_verification_handler(&self, path: &str) -> Result<()> {
        let stage = "VerificationHandler";
        let start = std::time::Instant::now();

        let verifier = VerificationHandler::new(self.logger.clone(), self.metrics.clone());
        match verifier.verify(path).await {
            Ok(_) => {
                self.log_result(stage, true, start.elapsed().as_millis(), None).await;
                Ok(())
            }
            Err(e) => {
                let msg = format!("{:?}", e);
                self.log_result(stage, false, start.elapsed().as_millis(), Some(msg.clone())).await;
                Err(e)
            }
        }
    }

    async fn run_structure_analysis(&self, path: &str) -> Result<()> {
        let stage = "StructureHandler";
        let start = std::time::Instant::now();

        let handler = StructureHandler::new(HashMap::new(), Arc::new(RwLock::new(ProcessingState::Loaded)), None);
        match handler.analyze(path).await {
            Ok(_) => {
                self.log_result(stage, true, start.elapsed().as_millis(), None).await;
                Ok(())
            }
            Err(e) => {
                let msg = format!("{:?}", e);
                self.log_result(stage, false, start.elapsed().as_millis(), Some(msg.clone())).await;
                Err(e)
            }
        }
    }

    async fn run_metadata_handler(&self, path: &str) -> Result<()> {
        let stage = "SecureMetadataHandler";
        let start = std::time::Instant::now();

        let document = Document::load(std::path::Path::new(path))?;
        let handler = SecureMetadataHandler::new(self.logger.clone(), self.metrics.clone());

        match handler.validate(&document).await {
            Ok(_) => {
                self.log_result(stage, true, start.elapsed().as_millis(), None).await;
                Ok(())
            }
            Err(e) => {
                let msg = format!("{:?}", e);
                self.log_result(stage, false, start.elapsed().as_millis(), Some(msg.clone())).await;
                Err(e)
            }
        }
    }

    async fn log_result(
        &self,
        stage: &str,
        success: bool,
        duration_ms: u128,
        message: Option<String>,
    ) {
        self.logger
            .log(
                if success { LogLevel::Info } else { LogLevel::Error },
                &format!(
                    "{} {} in {}ms",
                    stage,
                    if success { "completed" } else { "failed" },
                    duration_ms
                ),
                module_path!(),
                file!(),
                line!(),
            )
            .await
            .ok();

        let result = StageResult {
            stage: stage.to_string(),
            success,
            duration_ms,
            message,
        };

        self.results.write().await.push(result);
    }

    pub async fn get_results(&self) -> Vec<StageResult> {
        self.results.read().await.clone()
    }
}
