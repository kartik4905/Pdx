
//! Stage 2: Deep Cleaning
//! Scrubs binary artifacts, removes JavaScript, normalizes streams, secure delete
//! Author: kartik4091

use crate::{
    types::{Document, ProcessingResult},
    error::{Result, PipelineError},
    cleaner::{
        StructureCleaner, JavaScriptCleaner, StreamProcessor, 
        FileCleaner, SecureDelete
    },
    utils::{Logger, Metrics},
};
use async_trait::async_trait;
use tracing::{info, warn, instrument};
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage2Result {
    pub success: bool,
    pub binary_artifacts_removed: usize,
    pub javascript_instances_removed: usize,
    pub suspicious_keywords_replaced: usize,
    pub streams_normalized: usize,
    pub filters_processed: usize,
    pub slack_space_wiped: bool,
    pub names_entries_removed: usize,
    pub actions_removed: usize,
    pub issues: Vec<Stage2Issue>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage2Issue {
    pub severity: IssueSeverity,
    pub description: String,
    pub remediation: Option<String>,
    pub object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[async_trait]
pub trait Stage2Processor {
    async fn execute(&self, document: &mut Document) -> Result<Stage2Result>;
}

#[derive(Debug)]
pub struct Stage2ProcessorImpl {
    structure_cleaner: StructureCleaner,
    javascript_cleaner: JavaScriptCleaner,
    stream_processor: StreamProcessor,
    file_cleaner: FileCleaner,
    secure_delete: SecureDelete,
    logger: Logger,
    metrics: Metrics,
    suspicious_keywords: HashSet<String>,
}

impl Stage2ProcessorImpl {
    pub fn new() -> Self {
        let suspicious_keywords = vec![
            "eval", "unescape", "String.fromCharCode", "document.write",
            "ActiveX", "WScript", "Shell", "CreateObject", "exploit",
            "payload", "shellcode", "CVE-", "vulnerability"
        ].into_iter().map(|s| s.to_string()).collect();

        Self {
            structure_cleaner: StructureCleaner::new(),
            javascript_cleaner: JavaScriptCleaner::new(),
            stream_processor: StreamProcessor::new(),
            file_cleaner: FileCleaner::new(),
            secure_delete: SecureDelete::new(),
            logger: Logger::default(),
            metrics: Metrics::new(),
            suspicious_keywords,
        }
    }

    async fn scrub_binary_artifacts(&self, document: &mut Document, result: &mut Stage2Result) -> Result<()> {
        info!("Scrubbing binary artifacts");
        
        let mut artifacts_removed = 0;
        
        // Remove binary metadata in objects
        for (obj_id, object) in &mut document.structure.objects {
            match object {
                lopdf::Object::Stream(ref mut stream) => {
                    // Check for embedded binary signatures
                    if self.contains_binary_signatures(&stream.content) {
                        self.sanitize_binary_content(&mut stream.content)?;
                        artifacts_removed += 1;
                        
                        result.issues.push(Stage2Issue {
                            severity: IssueSeverity::Medium,
                            description: format!("Binary artifacts removed from stream {}", obj_id),
                            remediation: Some("Stream content sanitized".to_string()),
                            object_id: Some(format!("{}", obj_id)),
                        });
                    }
                }
                _ => {}
            }
        }
        
        result.binary_artifacts_removed = artifacts_removed;
        Ok(())
    }

    async fn remove_javascript(&self, document: &mut Document, result: &mut Stage2Result) -> Result<()> {
        info!("Removing all JavaScript code");
        
        let js_result = self.javascript_cleaner.remove_all_javascript(document).await?;
        result.javascript_instances_removed = js_result.instances_removed;
        
        for instance in js_result.removed_instances {
            result.issues.push(Stage2Issue {
                severity: IssueSeverity::Critical,
                description: format!("JavaScript removed: {}", instance.description),
                remediation: Some("JavaScript code completely removed".to_string()),
                object_id: instance.object_id,
            });
        }
        
        Ok(())
    }

    async fn replace_suspicious_keywords(&self, document: &mut Document, result: &mut Stage2Result) -> Result<()> {
        info!("Replacing suspicious keywords");
        
        let mut keywords_replaced = 0;
        
        for (obj_id, object) in &mut document.structure.objects {
            match object {
                lopdf::Object::Stream(ref mut stream) => {
                    let original_content = stream.content.clone();
                    self.sanitize_keywords(&mut stream.content)?;
                    
                    if stream.content != original_content {
                        keywords_replaced += 1;
                        result.issues.push(Stage2Issue {
                            severity: IssueSeverity::High,
                            description: format!("Suspicious keywords replaced in object {}", obj_id),
                            remediation: Some("Keywords replaced with safe alternatives".to_string()),
                            object_id: Some(format!("{}", obj_id)),
                        });
                    }
                }
                lopdf::Object::String(ref mut content, _) => {
                    let original_content = content.clone();
                    let content_str = String::from_utf8_lossy(content);
                    let sanitized = self.sanitize_string_keywords(&content_str);
                    *content = sanitized.into_bytes();
                    
                    if *content != original_content {
                        keywords_replaced += 1;
                    }
                }
                _ => {}
            }
        }
        
        result.suspicious_keywords_replaced = keywords_replaced;
        Ok(())
    }

    async fn remove_suspicious_names_and_actions(&self, document: &mut Document, result: &mut Stage2Result) -> Result<()> {
        info!("Removing suspicious /Names and /Action entries");
        
        let mut names_removed = 0;
        let mut actions_removed = 0;
        
        for (obj_id, object) in &mut document.structure.objects {
            match object {
                lopdf::Object::Dictionary(ref mut dict) => {
                    // Remove suspicious /Names entries
                    if dict.has(b"Names") {
                        if self.is_suspicious_names_entry(dict.get(b"Names").unwrap())? {
                            dict.remove(b"Names");
                            names_removed += 1;
                            
                            result.issues.push(Stage2Issue {
                                severity: IssueSeverity::High,
                                description: format!("Suspicious /Names entry removed from object {}", obj_id),
                                remediation: Some("/Names dictionary removed".to_string()),
                                object_id: Some(format!("{}", obj_id)),
                            });
                        }
                    }
                    
                    // Remove suspicious /Action entries
                    if dict.has(b"Action") || dict.has(b"A") {
                        let action_key = if dict.has(b"Action") { b"Action" } else { b"A" };
                        
                        if self.is_suspicious_action(dict.get(action_key).unwrap())? {
                            dict.remove(action_key);
                            actions_removed += 1;
                            
                            result.issues.push(Stage2Issue {
                                severity: IssueSeverity::Critical,
                                description: format!("Suspicious action removed from object {}", obj_id),
                                remediation: Some("Action completely removed".to_string()),
                                object_id: Some(format!("{}", obj_id)),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        
        result.names_entries_removed = names_removed;
        result.actions_removed = actions_removed;
        Ok(())
    }

    async fn normalize_streams(&self, document: &mut Document, result: &mut Stage2Result) -> Result<()> {
        info!("Normalizing stream filters");
        
        let normalize_result = self.stream_processor.normalize_streams(document).await?;
        result.streams_normalized = normalize_result.streams_processed;
        result.filters_processed = normalize_result.filters_normalized;
        
        for warning in normalize_result.warnings {
            result.issues.push(Stage2Issue {
                severity: IssueSeverity::Medium,
                description: warning.description,
                remediation: warning.remediation,
                object_id: warning.object_id,
            });
        }
        
        Ok(())
    }

    async fn secure_wipe_slack_space(&self, document: &mut Document, result: &mut Stage2Result) -> Result<()> {
        info!("Securely wiping slack space");
        
        let wipe_result = self.secure_delete.wipe_slack_space(document).await?;
        result.slack_space_wiped = wipe_result.success;
        
        if !wipe_result.success {
            result.issues.push(Stage2Issue {
                severity: IssueSeverity::Medium,
                description: "Slack space wiping incomplete".to_string(),
                remediation: Some("Some slack space may remain".to_string()),
                object_id: None,
            });
        }
        
        Ok(())
    }

    // Helper methods
    fn contains_binary_signatures(&self, content: &[u8]) -> bool {
        // Check for known binary signatures
        let signatures = [
            b"\x89PNG",     // PNG
            b"\xFF\xD8\xFF", // JPEG
            b"GIF8",        // GIF
            b"\x50\x4B",   // ZIP/Office
            b"\xD0\xCF",   // OLE
            b"MZ",          // PE executable
            b"\x7FELF",     // ELF executable
        ];
        
        for signature in &signatures {
            if content.windows(signature.len()).any(|w| w == *signature) {
                return true;
            }
        }
        false
    }

    fn sanitize_binary_content(&self, content: &mut Vec<u8>) -> Result<()> {
        // Replace binary signatures with safe alternatives
        let replacements = [
            (b"\x89PNG".to_vec(), b"SAFE".to_vec()),
            (b"\xFF\xD8\xFF".to_vec(), b"SAFE".to_vec()),
            (b"GIF8".to_vec(), b"SAFE".to_vec()),
        ];
        
        for (from, to) in &replacements {
            let content_str = content.clone();
            *content = content_str.replace(from, to);
        }
        
        Ok(())
    }

    fn sanitize_keywords(&self, content: &mut Vec<u8>) -> Result<()> {
        let mut content_str = String::from_utf8_lossy(content).to_string();
        
        for keyword in &self.suspicious_keywords {
            if content_str.contains(keyword) {
                // Replace with safe alternative of same length
                let replacement = "X".repeat(keyword.len());
                content_str = content_str.replace(keyword, &replacement);
            }
        }
        
        *content = content_str.into_bytes();
        Ok(())
    }

    fn sanitize_string_keywords(&self, content: &str) -> String {
        let mut result = content.to_string();
        
        for keyword in &self.suspicious_keywords {
            if result.contains(keyword) {
                let replacement = "X".repeat(keyword.len());
                result = result.replace(keyword, &replacement);
            }
        }
        
        result
    }

    fn is_suspicious_names_entry(&self, _names_obj: &lopdf::Object) -> Result<bool> {
        // Check if Names entry contains suspicious JavaScript or actions
        // Implementation would examine the Names tree structure
        Ok(true) // Conservative approach - remove all Names entries
    }

    fn is_suspicious_action(&self, action_obj: &lopdf::Object) -> Result<bool> {
        match action_obj {
            lopdf::Object::Dictionary(dict) => {
                // Check for suspicious action types
                if let Ok(lopdf::Object::Name(action_type)) = dict.get(b"S") {
                    let action_str = String::from_utf8_lossy(action_type);
                    match action_str.as_ref() {
                        "JavaScript" | "JS" | "Launch" | "SubmitForm" | "ImportData" => return Ok(true),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        Ok(false)
    }
}

#[async_trait]
impl Stage2Processor for Stage2ProcessorImpl {
    #[instrument(skip(self, document))]
    async fn execute(&self, document: &mut Document) -> Result<Stage2Result> {
        let start_time = std::time::Instant::now();
        let mut result = Stage2Result {
            success: false,
            binary_artifacts_removed: 0,
            javascript_instances_removed: 0,
            suspicious_keywords_replaced: 0,
            streams_normalized: 0,
            filters_processed: 0,
            slack_space_wiped: false,
            names_entries_removed: 0,
            actions_removed: 0,
            issues: Vec::new(),
            processing_time_ms: 0,
        };

        // Scrub binary artifacts
        self.scrub_binary_artifacts(document, &mut result).await?;

        // Remove all JavaScript
        self.remove_javascript(document, &mut result).await?;

        // Replace suspicious keywords
        self.replace_suspicious_keywords(document, &mut result).await?;

        // Remove suspicious Names and Actions
        self.remove_suspicious_names_and_actions(document, &mut result).await?;

        // Normalize streams and filters
        self.normalize_streams(document, &mut result).await?;

        // Secure wipe slack space
        self.secure_wipe_slack_space(document, &mut result).await?;

        result.processing_time_ms = start_time.elapsed().as_millis() as u64;
        result.success = true;

        info!("Stage 2 completed: {} issues resolved", result.issues.len());
        Ok(result)
    }
}

impl Default for Stage2ProcessorImpl {
    fn default() -> Self {
        Self::new()
    }
}
