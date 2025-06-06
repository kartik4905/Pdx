//! Logger implementation for PDF processing pipeline
//! Author: kartik4091
//! Created: 2025-06-05

use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};
use tracing::{info, warn, error, debug};

/// Logger for the PDF processing pipeline
pub struct Logger {
    level: String,
    initialized: bool,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            level: "info".to_string(),
            initialized: false,
        }
    }

    pub fn with_level(level: &str) -> Self {
        Self {
            level: level.to_string(),
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        if !self.initialized {
            let filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&self.level));
            
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .init();
            
            self.initialized = true;
            info!("Logger initialized with level: {}", self.level);
        }
    }

    pub fn log_info(&self, message: &str) {
        info!("{}", message);
    }

    pub fn log_warn(&self, message: &str) {
        warn!("{}", message);
    }

    pub fn log_error(&self, message: &str) {
        error!("{}", message);
    }

    pub fn log_debug(&self, message: &str) {
        debug!("{}", message);
    }
}

impl Default for Logger {
    fn default() -> Self {
        let mut logger = Self::new();
        logger.init();
        logger
    }
}