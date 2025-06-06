//! Logging Utilities for PDF Forensics and Sanitization
//! Author: kartik4091

use chrono::Utc;
use std::fmt;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::error::{Error, Result};

/// Severity levels for structured log entries
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level_str = match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        };
        write!(f, "{}", level_str)
    }
}

/// Log entry structure
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
    pub file: &'static str,
    pub line: u32,
    pub module_path: &'static str,
    pub timestamp: String,
}

/// Thread-safe logger for use in all pipeline stages
#[derive(Debug, Default)]
pub struct Logger {
    entries: RwLock<Vec<LogEntry>>,
}

impl Logger {
    /// Create a new logger instance
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    /// Log a structured entry
    #[instrument(skip(self))]
    pub async fn log(
        &self,
        level: LogLevel,
        message: &str,
        module_path: &'static str,
        file: &'static str,
        line: u32,
    ) -> Result<()> {
        let entry = LogEntry {
            level,
            message: message.to_string(),
            file,
            line,
            module_path,
            timestamp: Utc::now().to_rfc3339(),
        };

        {
            let mut entries = self.entries.write().await;
            entries.push(entry.clone());
        }

        // Also emit to tracing system
        match level {
            LogLevel::Trace => trace!("{} [{}:{}] {}", module_path, file, line, message),
            LogLevel::Debug => debug!("{} [{}:{}] {}", module_path, file, line, message),
            LogLevel::Info => info!("{} [{}:{}] {}", module_path, file, line, message),
            LogLevel::Warn => warn!("{} [{}:{}] {}", module_path, file, line, message),
            LogLevel::Error => error!("{} [{}:{}] {}", module_path, file, line, message),
        }

        Ok(())
    }
                                      }
