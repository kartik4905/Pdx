//! Forensic Scanner
//! Performs detailed PDF forensic scans for anomalies, suspicious patterns, and hidden data.
//! Author: kartik4091

use crate::{
    types::{Document, Object},
    utils::{calculate_entropy, logging::LogLevel, Logger, Metrics},
    error::{Error, Result},
};
use std::collections::{HashMap, HashSet};
use async_trait::async_trait;
use tracing::{debug, error, info, warn, instrument};
use lopdf::{Dictionary as LopdfDict};

#[derive(Debug, Default)]
pub struct ForensicReport {
    pub suspicious_objects: Vec<String>,
    pub high_entropy_streams: Vec<String>,
    pub hidden_metadata: HashMap<String, String>,
    pub encrypted_sections: usize,
    pub embedded_files: usize,
    pub javascript_found: usize,
    pub suspicious_keys: usize,
    pub total_issues: usize,
}

#[async_trait]
pub trait ForensicScan {
    async fn scan(&self, document: &Document) -> Result<ForensicReport>;
}

#[derive(Debug)]
pub struct ForensicScanner {
    logger: Logger,
    metrics: Metrics,
    suspicious_keywords: HashSet<String>,
}

impl ForensicScanner {
    pub fn new(logger: Logger) -> Self {
        let suspicious_keywords = vec![
            "JavaScript", "Names", "EmbeddedFile", "Launch", "OpenAction", "AA", "JS", "Encrypt"
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            logger,
            metrics: Metrics::new(),
            suspicious_keywords,
        }
    }

    fn is_suspicious_key(&self, key: &[u8]) -> bool {
        self.suspicious_keywords.contains(&String::from_utf8_lossy(key).to_string())
    }

    fn check_stream_entropy(&self, object_id: &str, stream_data: &[u8], report: &mut ForensicReport) {
        let entropy = calculate_entropy(stream_data);
        if entropy > 7.5 {
            report.high_entropy_streams.push(format!("{} (entropy = {:.2})", object_id, entropy));
            report.total_issues += 1;
        }
    }

    fn check_for_keywords(&self, id: &str, dict: &LopdfDict, report: &mut ForensicReport) {
        for key in dict.iter().map(|(k, _)| k) {
            if self.is_suspicious_key(key.as_bytes()) {
                report.suspicious_keys += 1;
                report.suspicious_objects.push(format!("{}: suspicious key '{}'", id, key));
                report.total_issues += 1;
            }
        }
    }

    fn extract_hidden_metadata(&self, dict: &LopdfDict, report: &mut ForensicReport) {
        for (k, v) in dict.iter() {
            let key = k.as_str();
            match v {
                Object::String(s, _) | Object::Name(s) => {
                    report.hidden_metadata.insert(key.to_string(), String::from_utf8_lossy(s).to_string());
                }
                _ => {}
            }
        }
    }

    fn detect_embedded_files(&self, dict: &LopdfDict, report: &mut ForensicReport) {
        if dict.get(b"EmbeddedFile").is_ok() {
            report.embedded_files += 1;
            report.total_issues += 1;
        }
    }

    fn detect_javascript(&self, dict: &LopdfDict, report: &mut ForensicReport) {
        if dict.get(b"JavaScript").is_ok() || dict.get(b"JS").is_ok() {
            report.javascript_found += 1;
            report.total_issues += 1;
        }
    }

    fn detect_encryption(&self, dict: &LopdfDict, report: &mut ForensicReport) {
        if dict.get(b"Encrypt").is_ok() {
            report.encrypted_sections += 1;
            report.total_issues += 1;
        }
    }
}

#[async_trait]
impl ForensicScan for ForensicScanner {
    #[instrument(skip(self, document))]
    async fn scan(&self, document: &Document) -> Result<ForensicReport> {
        self.logger
            .log(LogLevel::Info, "Starting forensic scan", module_path!(), file!(), line!())
            .await?;

        let mut report = ForensicReport::default();

        for (id, object) in &document.structure.objects {
            let id_str = format!("{}", id);

            match object {
                Object::Stream(stream) => {
                    self.check_stream_entropy(&id_str, &stream.content, &mut report);
                    self.check_for_keywords(&id_str, &stream.dict, &mut report);
                    self.extract_hidden_metadata(&stream.dict, &mut report);
                    self.detect_embedded_files(&stream.dict, &mut report);
                    self.detect_javascript(&stream.dict, &mut report);
                    self.detect_encryption(&stream.dict, &mut report);
                }

                Object::Dictionary(dict) => {
                    self.check_for_keywords(&id_str, dict, &mut report);
                    self.extract_hidden_metadata(dict, &mut report);
                    self.detect_embedded_files(dict, &mut report);
                    self.detect_javascript(dict, &mut report);
                    self.detect_encryption(dict, &mut report);
                }

                _ => {}
            }
        }

        self.logger
            .log(LogLevel::Info, "Forensic scan completed", module_path!(), file!(), line!())
            .await?;

        Ok(report)
    }
}
