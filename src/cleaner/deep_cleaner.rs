//! Deep cleaning implementation for PDF anti-forensics

use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument};

use crate::{
    error::{Error, Result},
    types::{Document, Object, ObjectId, ProcessingState},
    cleaner::{
        stream_processor::StreamProcessor,
        binary_sanitizer::BinarySanitizer,
        content_cleaner::ContentCleaner,
        structure_cleaner::StructureCleaner,
    },
};

/// Deep cleaner for PDF documents
pub struct DeepCleaner {
    stream_processor: StreamProcessor,
    binary_sanitizer: BinarySanitizer,
    content_cleaner: ContentCleaner,
    structure_cleaner: StructureCleaner,
    state: Arc<RwLock<ProcessingState>>,
    stats: CleaningStatistics,
}

/// Cleaning configuration
#[derive(Debug, Clone)]
pub struct CleaningConfig {
    pub clean_streams: bool,
    pub clean_binary: bool,
    pub clean_content: bool,
    pub clean_structure: bool,
    pub preserve_functionality: bool,
    pub remove_metadata: bool,
    pub remove_hidden: bool,
    pub custom_options: HashMap<String, String>,
}

impl Default for CleaningConfig {
    fn default() -> Self {
        Self {
            clean_streams: true,
            clean_binary: true,
            clean_content: true,
            clean_structure: true,
            preserve_functionality: true,
            remove_metadata: true,
            remove_hidden: true,
            custom_options: HashMap::new(),
        }
    }
}

/// Cleaning statistics
#[derive(Debug, Default, Clone)]
pub struct CleaningStatistics {
    pub streams_cleaned: usize,
    pub binary_objects_cleaned: usize,
    pub content_objects_cleaned: usize,
    pub structural_changes: usize,
    pub data_removed: u64,
    pub duration_ms: u64,
}

/// Cleaning result
#[derive(Debug)]
pub struct CleaningResult {
    pub document: Document,
    pub statistics: CleaningStatistics,
    pub issues: Vec<CleaningIssue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug)]
pub struct CleaningIssue {
    pub severity: IssueSeverity,
    pub description: String,
    pub object_id: Option<ObjectId>,
    pub context: String,
}

impl DeepCleaner {
    pub fn new(state: Arc<RwLock<ProcessingState>>) -> Self {
        Self {
            stream_processor: StreamProcessor::new(),
            binary_sanitizer: BinarySanitizer::new(),
            content_cleaner: ContentCleaner::new(),
            structure_cleaner: StructureCleaner::new(),
            state,
            stats: CleaningStatistics::default(),
        }
    }

    #[instrument(skip(self, document, config))]
    pub async fn clean(&mut self, mut document: Document, config: CleaningConfig) -> Result<CleaningResult> {
        info!("Starting deep cleaning process");
        let start_time = std::time::Instant::now();
        let mut issues = Vec::new();

        if config.clean_streams {
            debug!("Cleaning streams");
            self.clean_streams(&mut document, &mut issues).await?;
        }

        if config.clean_binary {
            debug!("Cleaning binary");
            self.clean_binary_data(&mut document, &mut issues).await?;
        }

        if config.clean_content {
            debug!("Cleaning content");
            self.clean_content(&mut document, &mut issues).await?;
        }

        if config.clean_structure {
            debug!("Cleaning structure");
            self.clean_structure(&mut document, &mut issues).await?;
        }

        if config.remove_metadata {
            debug!("Removing metadata");
            self.remove_metadata(&mut document, &mut issues).await?;
        }

        if config.remove_hidden {
            debug!("Removing hidden content");
            self.remove_hidden_content(&mut document, &mut issues).await?;
        }

        self.stats.duration_ms = start_time.elapsed().as_millis() as u64;

        Ok(CleaningResult {
            document,
            statistics: self.stats.clone(),
            issues,
        })
    }

    async fn clean_streams(&mut self, document: &mut Document, issues: &mut Vec<CleaningIssue>) -> Result<()> {
        for (id, obj) in &mut document.content {
            if let Object::Stream(stream) = obj {
                match self.stream_processor.clean_stream(&stream.dict, &stream.data).await {
                    Ok(cleaned) => {
                        self.stats.streams_cleaned += 1;
                        self.stats.data_removed += (stream.data.len() - cleaned.len()) as u64;
                        stream.data = cleaned;
                    }
                    Err(e) => issues.push(CleaningIssue {
                        severity: IssueSeverity::Warning,
                        description: e.to_string(),
                        object_id: Some(*id),
                        context: "Stream processing".into(),
                    }),
                }
            }
        }
        Ok(())
    }

    async fn clean_binary_data(&mut self, document: &mut Document, issues: &mut Vec<CleaningIssue>) -> Result<()> {
        for (id, obj) in &mut document.content {
            match obj {
                Object::Stream(stream) if self.is_binary_stream(&stream.dict) => {
                    match self.binary_sanitizer.clean_binary(&stream.data).await {
                        Ok(cleaned) => {
                            self.stats.binary_objects_cleaned += 1;
                            self.stats.data_removed += (stream.data.len() - cleaned.len()) as u64;
                            stream.data = cleaned;
                        }
                        Err(e) => issues.push(CleaningIssue {
                            severity: IssueSeverity::Warning,
                            description: e.to_string(),
                            object_id: Some(*id),
                            context: "Binary stream".into(),
                        }),
                    }
                }
                Object::String(data) if self.is_binary_string(data) => {
                    match self.binary_sanitizer.clean_binary(data).await {
                        Ok(cleaned) => {
                            self.stats.binary_objects_cleaned += 1;
                            self.stats.data_removed += (data.len() - cleaned.len()) as u64;
                            *data = cleaned;
                        }
                        Err(e) => issues.push(CleaningIssue {
                            severity: IssueSeverity::Warning,
                            description: e.to_string(),
                            object_id: Some(*id),
                            context: "Binary string".into(),
                        }),
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn clean_content(&mut self, document: &mut Document, issues: &mut Vec<CleaningIssue>) -> Result<()> {
        for (id, obj) in &mut document.content {
            match self.content_cleaner.clean_object(obj).await {
                Ok(cleaned) => {
                    if &cleaned != obj {
                        *obj = cleaned;
                        self.stats.content_objects_cleaned += 1;
                    }
                }
                Err(e) => issues.push(CleaningIssue {
                    severity: IssueSeverity::Warning,
                    description: e.to_string(),
                    object_id: Some(*id),
                    context: "Content cleaner".into(),
                }),
            }
        }
        Ok(())
    }

    async fn clean_structure(&mut self, document: &mut Document, issues: &mut Vec<CleaningIssue>) -> Result<()> {
        match self.structure_cleaner.clean_structure(document).await {
            Ok(()) => {
                self.stats.structural_changes += 1;
                Ok(())
            }
            Err(e) => {
                issues.push(CleaningIssue {
                    severity: IssueSeverity::Error,
                    description: e.to_string(),
                    object_id: None,
                    context: "Structure cleaning failed".into(),
                });
                Err(e)
            }
        }
    }

    async fn remove_metadata(&mut self, document: &mut Document, _issues: &mut Vec<CleaningIssue>) -> Result<()> {
        document.metadata.clear();
        for obj in document.content.values_mut() {
            if let Object::Dictionary(dict) = obj {
                dict.remove(b"Metadata");
                dict.remove(b"Info");
                dict.remove(b"PieceInfo");
            }
        }
        Ok(())
    }

    async fn remove_hidden_content(&mut self, _document: &mut Document, _issues: &mut Vec<CleaningIssue>) -> Result<()> {
        // Stub: Future hidden content logic
        Ok(())
    }

    fn is_binary_stream(&self, dict: &HashMap<Vec<u8>, Object>) -> bool {
        matches!(
            dict.get(b"Subtype"),
            Some(Object::Name(name)) if matches!(name.as_slice(), b"Image" | b"Form" | b"JPXDecode" | b"ICCProfile")
        )
    }

    fn is_binary_string(&self, data: &[u8]) -> bool {
        data.iter().any(|&b| b < 32 && !b.is_ascii_whitespace())
    }
}
