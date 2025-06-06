
use crate::error::{Result, AntiForensicsError};
use crate::types::Document;
use crate::cleaner::secure_delete::SecureDelete;
use crate::utils::crypto_utils::CryptoUtils;
use crate::utils::binary_utils::BinaryUtils;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use log::{info, warn, debug};
use lopdf::{Object, ObjectId};
use std::fs;
use std::io::{Write, Read};
use tempfile::TempDir;
use sha2::{Sha256, Digest};

pub struct FileCleaner {
    secure_delete: SecureDelete,
    temp_dir: Option<TempDir>,
    extracted_files: HashMap<String, PathBuf>,
    crypto_utils: CryptoUtils,
    binary_utils: BinaryUtils,
    zero_tolerance: bool,
}

#[derive(Debug, Clone)]
pub struct EmbeddedFile {
    pub id: ObjectId,
    pub name: String,
    pub size: u64,
    pub hash: String,
    pub file_type: String,
    pub content: Vec<u8>,
    pub is_suspicious: bool,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct FileCleaningResult {
    pub files_found: usize,
    pub files_removed: usize,
    pub files_quarantined: usize,
    pub bytes_cleaned: u64,
    pub suspicious_patterns: Vec<String>,
    pub risk_assessment: HashMap<String, RiskLevel>,
    pub secure_wipe_passes: u32,
}

impl FileCleaner {
    pub fn new() -> Self {
        Self {
            secure_delete: SecureDelete::new(),
            temp_dir: None,
            extracted_files: HashMap::new(),
            crypto_utils: CryptoUtils::new(),
            binary_utils: BinaryUtils::new(),
            zero_tolerance: true,
        }
    }

    pub fn with_zero_tolerance(mut self, enabled: bool) -> Self {
        self.zero_tolerance = enabled;
        self
    }

    /// Extract and analyze all embedded files with zero-tolerance scanning
    pub async fn clean_embedded_files(&mut self, document: &mut Document) -> Result<FileCleaningResult> {
        info!("Starting embedded file cleaning with zero-tolerance mode");
        
        let mut result = FileCleaningResult {
            files_found: 0,
            files_removed: 0,
            files_quarantined: 0,
            bytes_cleaned: 0,
            suspicious_patterns: Vec::new(),
            risk_assessment: HashMap::new(),
            secure_wipe_passes: 7, // DoD 5220.22-M standard
        };

        // Initialize temporary directory for extraction
        self.temp_dir = Some(TempDir::new().map_err(|e| {
            AntiForensicsError::FileOperation(format!("Failed to create temp directory: {}", e))
        })?);

        // Extract all embedded files
        let embedded_files = self.extract_all_files(document).await?;
        result.files_found = embedded_files.len();

        info!("Found {} embedded files for analysis", embedded_files.len());

        // Analyze each file with comprehensive anti-forensic scanning
        for file in embedded_files {
            let risk_level = self.assess_file_risk(&file).await?;
            result.risk_assessment.insert(file.name.clone(), risk_level.clone());

            match risk_level {
                RiskLevel::Safe => {
                    debug!("File {} assessed as safe, keeping", file.name);
                }
                RiskLevel::Low | RiskLevel::Medium => {
                    if self.zero_tolerance {
                        self.remove_file_from_document(document, &file).await?;
                        result.files_removed += 1;
                        result.bytes_cleaned += file.size;
                        warn!("Zero-tolerance: Removed {} (risk: {:?})", file.name, risk_level);
                    } else {
                        self.quarantine_file(&file).await?;
                        result.files_quarantined += 1;
                        warn!("Quarantined {} (risk: {:?})", file.name, risk_level);
                    }
                }
                RiskLevel::High | RiskLevel::Critical => {
                    self.remove_file_from_document(document, &file).await?;
                    self.secure_wipe_file(&file).await?;
                    result.files_removed += 1;
                    result.bytes_cleaned += file.size;
                    warn!("Removed high-risk file: {} (risk: {:?})", file.name, risk_level);
                }
            }
        }

        // Clean up temporary files with secure deletion
        self.cleanup_temp_files().await?;

        info!("File cleaning completed: {} removed, {} quarantined", 
              result.files_removed, result.files_quarantined);

        Ok(result)
    }

    /// Extract all embedded files from PDF document
    async fn extract_all_files(&mut self, document: &Document) -> Result<Vec<EmbeddedFile>> {
        let mut embedded_files = Vec::new();

        for (id, object) in &document.objects {
            if let Ok(dict) = object.as_dict() {
                // Check for file specifications
                if dict.get(b"Type").and_then(|o| o.as_name_str()).ok() == Some("Filespec") {
                    let file = self.extract_filespec(id, dict).await?;
                    embedded_files.push(file);
                }

                // Check for embedded streams that could contain files
                if dict.has(b"Filter") && dict.has(b"Length") {
                    if let Ok(stream) = object.as_stream() {
                        if let Some(file) = self.analyze_stream_for_files(id, stream).await? {
                            embedded_files.push(file);
                        }
                    }
                }

                // Check for attachment annotations
                if dict.get(b"Subtype").and_then(|o| o.as_name_str()).ok() == Some("FileAttachment") {
                    if let Some(file) = self.extract_attachment(id, dict).await? {
                        embedded_files.push(file);
                    }
                }
            }
        }

        Ok(embedded_files)
    }

    /// Extract file from filespec object
    async fn extract_filespec(&self, id: &ObjectId, dict: &lopdf::Dictionary) -> Result<EmbeddedFile> {
        let name = dict.get(b"F")
            .and_then(|o| o.as_str().ok())
            .unwrap_or("unknown_file")
            .to_string();

        let ef_dict = dict.get(b"EF")
            .and_then(|o| o.as_dict().ok())
            .ok_or_else(|| AntiForensicsError::InvalidStructure("Missing EF dictionary".into()))?;

        let stream_ref = ef_dict.get(b"F")
            .ok_or_else(|| AntiForensicsError::InvalidStructure("Missing file stream reference".into()))?;

        // Extract file content (simplified - would need full PDF parsing)
        let content = self.extract_stream_content(stream_ref).await?;
        let hash = self.calculate_file_hash(&content);
        let file_type = self.detect_file_type(&content, &name);

        Ok(EmbeddedFile {
            id: *id,
            name,
            size: content.len() as u64,
            hash,
            file_type,
            content,
            is_suspicious: false, // Will be determined by risk assessment
            risk_level: RiskLevel::Safe, // Will be updated by risk assessment
        })
    }

    /// Analyze stream for embedded files
    async fn analyze_stream_for_files(&self, id: &ObjectId, stream: &lopdf::Stream) -> Result<Option<EmbeddedFile>> {
        let content = &stream.content;
        
        // Look for file signatures in stream content
        if let Some(file_type) = self.detect_embedded_file_signature(content) {
            let name = format!("embedded_{}_{}", id.0, id.1);
            let hash = self.calculate_file_hash(content);

            return Ok(Some(EmbeddedFile {
                id: *id,
                name,
                size: content.len() as u64,
                hash,
                file_type,
                content: content.clone(),
                is_suspicious: true, // Embedded in stream is suspicious
                risk_level: RiskLevel::Medium,
            }));
        }

        Ok(None)
    }

    /// Extract attachment from annotation
    async fn extract_attachment(&self, id: &ObjectId, dict: &lopdf::Dictionary) -> Result<Option<EmbeddedFile>> {
        let fs = dict.get(b"FS")
            .and_then(|o| o.as_dict().ok());

        if let Some(fs_dict) = fs {
            let name = fs_dict.get(b"F")
                .and_then(|o| o.as_str().ok())
                .unwrap_or("attachment")
                .to_string();

            // Extract content (simplified)
            let content = vec![]; // Would extract from actual stream
            let hash = self.calculate_file_hash(&content);
            let file_type = self.detect_file_type(&content, &name);

            return Ok(Some(EmbeddedFile {
                id: *id,
                name,
                size: content.len() as u64,
                hash,
                file_type,
                content,
                is_suspicious: false,
                risk_level: RiskLevel::Low,
            }));
        }

        Ok(None)
    }

    /// Comprehensive risk assessment for embedded files
    async fn assess_file_risk(&self, file: &EmbeddedFile) -> Result<RiskLevel> {
        let mut risk_score = 0;

        // File type risk assessment
        risk_score += match file.file_type.to_lowercase().as_str() {
            "exe" | "scr" | "bat" | "cmd" | "com" | "pif" => 50,
            "js" | "vbs" | "ps1" | "jar" | "class" => 40,
            "dll" | "sys" | "drv" => 45,
            "zip" | "rar" | "7z" | "tar" | "gz" => 20,
            "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" => 15,
            "pdf" | "rtf" => 25, // Nested PDFs are suspicious
            _ => 5,
        };

        // Size-based risk
        if file.size > 10_000_000 { // > 10MB
            risk_score += 15;
        } else if file.size > 1_000_000 { // > 1MB
            risk_score += 10;
        }

        // Content analysis
        risk_score += self.analyze_file_content(&file.content).await?;

        // Filename analysis
        risk_score += self.analyze_filename(&file.name);

        // Hash-based reputation check (simplified)
        risk_score += self.check_hash_reputation(&file.hash).await?;

        // Convert score to risk level
        match risk_score {
            0..=10 => Ok(RiskLevel::Safe),
            11..=25 => Ok(RiskLevel::Low),
            26..=50 => Ok(RiskLevel::Medium),
            51..=75 => Ok(RiskLevel::High),
            _ => Ok(RiskLevel::Critical),
        }
    }

    /// Analyze file content for suspicious patterns
    async fn analyze_file_content(&self, content: &[u8]) -> Result<i32> {
        let mut risk_score = 0;

        // Look for executable signatures
        if content.starts_with(b"MZ") || content.starts_with(b"\x7fELF") {
            risk_score += 30;
        }

        // Look for script patterns
        let content_str = String::from_utf8_lossy(content);
        if content_str.contains("eval(") || 
           content_str.contains("exec(") ||
           content_str.contains("powershell") ||
           content_str.contains("cmd.exe") {
            risk_score += 25;
        }

        // Look for suspicious URLs
        if content_str.contains("http://") && !content_str.contains("https://") {
            risk_score += 15;
        }

        // Look for encoding obfuscation
        if content_str.contains("base64") || content_str.contains("fromCharCode") {
            risk_score += 20;
        }

        // Entropy analysis for packed/encrypted content
        let entropy = self.calculate_entropy(content);
        if entropy > 7.5 {
            risk_score += 20;
        }

        Ok(risk_score)
    }

    /// Analyze filename for suspicious patterns
    fn analyze_filename(&self, filename: &str) -> i32 {
        let mut risk_score = 0;

        // Double extensions
        if filename.matches('.').count() > 1 {
            risk_score += 15;
        }

        // Suspicious names
        let suspicious_names = [
            "setup", "install", "update", "patch", "crack", "keygen",
            "loader", "activator", "temp", "tmp", "cache"
        ];

        for name in &suspicious_names {
            if filename.to_lowercase().contains(name) {
                risk_score += 10;
                break;
            }
        }

        // Unicode/special characters
        if !filename.is_ascii() {
            risk_score += 10;
        }

        risk_score
    }

    /// Check hash reputation (simplified implementation)
    async fn check_hash_reputation(&self, hash: &str) -> Result<i32> {
        // In a real implementation, this would check against threat intelligence feeds
        // For now, return 0 (unknown)
        Ok(0)
    }

    /// Remove file from PDF document structure
    async fn remove_file_from_document(&mut self, document: &mut Document, file: &EmbeddedFile) -> Result<()> {
        info!("Removing file {} from document", file.name);

        // Remove the object and all references
        document.objects.remove(&file.id);

        // Remove references from parent objects
        self.remove_file_references(document, &file.id).await?;

        // Update cross-reference table
        self.update_xref_table(document, &file.id).await?;

        Ok(())
    }

    /// Remove all references to a file object
    async fn remove_file_references(&self, document: &mut Document, file_id: &ObjectId) -> Result<()> {
        let mut objects_to_update = Vec::new();

        for (id, object) in &document.objects {
            if let Ok(dict) = object.as_dict() {
                // Check if this object references the file
                if self.contains_reference(dict, file_id) {
                    objects_to_update.push(*id);
                }
            }
        }

        // Update objects to remove references
        for id in objects_to_update {
            if let Some(object) = document.objects.get_mut(&id) {
                self.remove_reference_from_object(object, file_id)?;
            }
        }

        Ok(())
    }

    /// Check if dictionary contains reference to file
    fn contains_reference(&self, dict: &lopdf::Dictionary, file_id: &ObjectId) -> bool {
        for (_, value) in dict {
            match value {
                Object::Reference(id) if id == file_id => return true,
                Object::Array(arr) => {
                    for item in arr {
                        if let Object::Reference(id) = item {
                            if id == file_id {
                                return true;
                            }
                        }
                    }
                }
                Object::Dictionary(dict) => {
                    if self.contains_reference(dict, file_id) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Remove reference from object
    fn remove_reference_from_object(&self, object: &mut Object, file_id: &ObjectId) -> Result<()> {
        match object {
            Object::Dictionary(dict) => {
                dict.retain(|_, value| {
                    !matches!(value, Object::Reference(id) if id == file_id)
                });
            }
            Object::Array(arr) => {
                arr.retain(|item| {
                    !matches!(item, Object::Reference(id) if id == file_id)
                });
            }
            _ => {}
        }
        Ok(())
    }

    /// Update cross-reference table
    async fn update_xref_table(&self, document: &mut Document, file_id: &ObjectId) -> Result<()> {
        // Mark object as deleted in xref table
        if let Some(entry) = document.reference_table.get_mut(file_id) {
            *entry = (0, 65535, false); // Standard deletion marker
        }
        Ok(())
    }

    /// Quarantine suspicious file
    async fn quarantine_file(&mut self, file: &EmbeddedFile) -> Result<()> {
        if let Some(temp_dir) = &self.temp_dir {
            let quarantine_path = temp_dir.path().join(format!("quarantine_{}", file.name));
            
            let mut quarantine_file = fs::File::create(&quarantine_path)
                .map_err(|e| AntiForensicsError::FileOperation(format!("Failed to create quarantine file: {}", e)))?;
            
            quarantine_file.write_all(&file.content)
                .map_err(|e| AntiForensicsError::FileOperation(format!("Failed to write quarantine file: {}", e)))?;
            
            self.extracted_files.insert(file.name.clone(), quarantine_path);
        }
        Ok(())
    }

    /// Secure wipe of file content
    async fn secure_wipe_file(&mut self, file: &EmbeddedFile) -> Result<()> {
        info!("Performing secure wipe of file: {}", file.name);
        
        // Use DoD 5220.22-M standard (7 passes)
        self.secure_delete.wipe_memory(&file.content).await?;
        
        Ok(())
    }

    /// Clean up temporary files with secure deletion
    async fn cleanup_temp_files(&mut self) -> Result<()> {
        if let Some(temp_dir) = self.temp_dir.take() {
            // Secure wipe all extracted files
            for (name, path) in &self.extracted_files {
                info!("Secure wiping extracted file: {}", name);
                self.secure_delete.wipe_file(path).await?;
            }
            
            // Let temp_dir drop naturally (will clean up directory)
            self.extracted_files.clear();
        }
        Ok(())
    }

    /// Helper functions
    async fn extract_stream_content(&self, stream_ref: &Object) -> Result<Vec<u8>> {
        // Simplified - would need full PDF stream extraction
        Ok(vec![])
    }

    fn calculate_file_hash(&self, content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }

    fn detect_file_type(&self, content: &[u8], filename: &str) -> String {
        // File signature detection
        if content.starts_with(b"PK\x03\x04") || content.starts_with(b"PK\x05\x06") {
            return "zip".to_string();
        }
        if content.starts_with(b"\x89PNG\r\n\x1a\n") {
            return "png".to_string();
        }
        if content.starts_with(b"\xff\xd8\xff") {
            return "jpg".to_string();
        }
        if content.starts_with(b"MZ") {
            return "exe".to_string();
        }
        if content.starts_with(b"%PDF-") {
            return "pdf".to_string();
        }

        // Fallback to extension
        if let Some(ext) = filename.split('.').last() {
            ext.to_lowercase()
        } else {
            "unknown".to_string()
        }
    }

    fn detect_embedded_file_signature(&self, content: &[u8]) -> Option<String> {
        if content.len() < 4 {
            return None;
        }

        // Check for known file signatures
        if content.starts_with(b"PK\x03\x04") {
            Some("zip".to_string())
        } else if content.starts_with(b"\x89PNG") {
            Some("png".to_string())
        } else if content.starts_with(b"\xff\xd8\xff") {
            Some("jpg".to_string())
        } else if content.starts_with(b"MZ") {
            Some("exe".to_string())
        } else {
            None
        }
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut frequency = [0u32; 256];
        
        for &byte in data {
            frequency[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &freq in &frequency {
            if freq > 0 {
                let p = freq as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
}

impl Default for FileCleaner {
    fn default() -> Self {
        Self::new()
    }
}
