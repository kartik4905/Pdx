//! Utility Module Implementation
//! Author: kartik4091
//! Created: 2025-06-03 09:14:13 UTC
//!
//! Aggregates internal utility helpers like logging, metrics,
//! configuration, validation, entropy analysis, and more.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{RwLock, Semaphore},
};
use tracing::{debug, error, info, instrument, warn};

// Submodules
pub mod binary_utils;
pub mod cache;
pub mod config;
pub mod crypto_utils;
pub mod entropy;
pub mod io;
pub mod logger;
pub mod logging;
pub mod memory;
pub mod metadata_utils;
pub mod metrics;
pub mod pattern_utils;
pub mod sanitization_utils;
pub mod template_utils;
pub mod validation;
pub mod validator;

// Re-exports for unified access
pub use self::{
    binary_utils::*,
    cache::*,
    config::*,
    crypto_utils::*,
    entropy::calculate_entropy,
    io::*,
    logger::*,
    logging::*,
    memory::*,
    metadata_utils::*,
    metrics::*,
    pattern_utils::*,
    sanitization_utils::*,
    validation::*,
    validator::*,
};

// General-purpose utility error type
#[derive(Debug, thiserror::Error)]
pub enum UtilError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("Metric error: {0}")]
    Metric(String),

    #[error("Logging error: {0}")]
    Logging(String),
}

// Result alias for utility operations
pub type Result<T> = std::result::Result<T, UtilError>;

// General trait for configurable utility components
#[async_trait]
pub trait UtilityConfig: Send + Sync {
    fn validate(&self) -> Result<()>;
    fn get(&self, key: &str) -> Option<String>;
    fn set(&mut self, key: &str, value: String) -> Result<()>;
}
