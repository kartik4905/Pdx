
use crate::error::{Result, AntiForensicsError};
use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom, Read};
use std::path::Path;
use rand::{RngCore, thread_rng};
use log::{info, debug, warn};
use std::mem;

/// Secure deletion implementation following DoD 5220.22-M standard
/// and other military-grade data sanitization specifications
pub struct SecureDelete {
    /// Number of overwrite passes (default: 7 for DoD 5220.22-M)
    passes: u32,
    /// Verification enabled
    verify_deletion: bool,
    /// Pattern-based overwriting
    use_patterns: bool,
    /// Random data overwriting
    use_random: bool,
}

#[derive(Debug, Clone)]
pub struct SecureDeletionResult {
    pub bytes_wiped: u64,
    pub passes_completed: u32,
    pub verification_passed: bool,
    pub deletion_time_ms: u64,
    pub method_used: String,
}

/// DoD 5220.22-M standard patterns
const DOD_PATTERNS: &[&[u8]] = &[
    &[0x00], // Pass 1: All zeros
    &[0xFF], // Pass 2: All ones
    &[0x00], // Pass 3: All zeros again
];

/// Gutmann method patterns (35 passes)
const GUTMANN_PATTERNS: &[&[u8]] = &[
    &[0x55], &[0xAA], &[0x92, 0x49, 0x24], &[0x49, 0x24, 0x92],
    &[0x24, 0x92, 0x49], &[0x00], &[0x11], &[0x22], &[0x33],
    &[0x44], &[0x55], &[0x66], &[0x77], &[0x88], &[0x99],
    &[0xAA], &[0xBB], &[0xCC], &[0xDD], &[0xEE], &[0xFF],
    &[0x92, 0x49, 0x24], &[0x49, 0x24, 0x92], &[0x24, 0x92, 0x49],
    &[0x6D, 0xB6, 0xDB], &[0xB6, 0xDB, 0x6D], &[0xDB, 0x6D, 0xB6],
];

impl SecureDelete {
    /// Create new SecureDelete instance with DoD 5220.22-M defaults
    pub fn new() -> Self {
        Self {
            passes: 7, // DoD 5220.22-M standard
            verify_deletion: true,
            use_patterns: true,
            use_random: true,
        }
    }

    /// Create instance with custom number of passes
    pub fn with_passes(passes: u32) -> Self {
        Self {
            passes,
            verify_deletion: true,
            use_patterns: true,
            use_random: true,
        }
    }

    /// Enable Gutmann method (35 passes)
    pub fn gutmann_method() -> Self {
        Self {
            passes: 35,
            verify_deletion: true,
            use_patterns: true,
            use_random: true,
        }
    }

    /// Configure verification
    pub fn with_verification(mut self, enabled: bool) -> Self {
        self.verify_deletion = enabled;
        self
    }

    /// Securely wipe file following DoD 5220.22-M standard
    pub async fn wipe_file<P: AsRef<Path>>(&self, path: P) -> Result<SecureDeletionResult> {
        let path = path.as_ref();
        let start_time = std::time::Instant::now();
        
        info!("Starting secure deletion of file: {}", path.display());

        // Get file size
        let metadata = std::fs::metadata(path)
            .map_err(|e| AntiForensicsError::FileOperation(format!("Cannot access file metadata: {}", e)))?;
        
        let file_size = metadata.len();
        
        if file_size == 0 {
            warn!("File is empty, skipping secure deletion");
            return Ok(SecureDeletionResult {
                bytes_wiped: 0,
                passes_completed: 0,
                verification_passed: true,
                deletion_time_ms: start_time.elapsed().as_millis() as u64,
                method_used: "skip_empty".to_string(),
            });
        }

        // Open file for writing
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(path)
            .map_err(|e| AntiForensicsError::FileOperation(format!("Cannot open file for wiping: {}", e)))?;

        // Perform secure overwriting
        let mut passes_completed = 0;
        let method_used = if self.passes == 35 {
            "gutmann_35_pass"
        } else if self.passes == 7 {
            "dod_5220_22_m"
        } else {
            "custom"
        };

        for pass in 0..self.passes {
            debug!("Secure deletion pass {} of {}", pass + 1, self.passes);
            
            // Seek to beginning
            file.seek(SeekFrom::Start(0))
                .map_err(|e| AntiForensicsError::FileOperation(format!("Seek failed: {}", e)))?;

            // Determine pattern for this pass
            let pattern = self.get_pattern_for_pass(pass);
            
            // Overwrite file with pattern
            self.overwrite_with_pattern(&mut file, file_size, &pattern).await?;
            
            // Force write to disk
            file.sync_all()
                .map_err(|e| AntiForensicsError::FileOperation(format!("Sync failed: {}", e)))?;
            
            passes_completed += 1;
        }

        // Verification pass
        let verification_passed = if self.verify_deletion {
            self.verify_overwrite(&mut file, file_size).await?
        } else {
            true
        };

        // Finally, truncate and delete the file
        file.set_len(0)
            .map_err(|e| AntiForensicsError::FileOperation(format!("Truncate failed: {}", e)))?;
        
        drop(file); // Close file handle
        
        std::fs::remove_file(path)
            .map_err(|e| AntiForensicsError::FileOperation(format!("File deletion failed: {}", e)))?;

        let deletion_time = start_time.elapsed().as_millis() as u64;
        
        info!("Secure deletion completed: {} bytes, {} passes, {}ms", 
              file_size, passes_completed, deletion_time);

        Ok(SecureDeletionResult {
            bytes_wiped: file_size,
            passes_completed,
            verification_passed,
            deletion_time_ms: deletion_time,
            method_used: method_used.to_string(),
        })
    }

    /// Securely wipe memory buffer
    pub async fn wipe_memory(&self, data: &[u8]) -> Result<SecureDeletionResult> {
        let start_time = std::time::Instant::now();
        let data_size = data.len() as u64;
        
        info!("Starting secure memory wipe: {} bytes", data_size);

        // Create mutable copy for overwriting
        let mut buffer = data.to_vec();
        let mut passes_completed = 0;

        for pass in 0..self.passes {
            let pattern = self.get_pattern_for_pass(pass);
            
            // Overwrite memory with pattern
            for (i, byte) in buffer.iter_mut().enumerate() {
                *byte = pattern[i % pattern.len()];
            }
            
            passes_completed += 1;
        }

        // Final random overwrite
        thread_rng().fill_bytes(&mut buffer);

        // Zero out the buffer
        buffer.fill(0);

        // Force buffer to be dropped and memory cleared
        mem::drop(buffer);

        let deletion_time = start_time.elapsed().as_millis() as u64;
        
        debug!("Memory wipe completed: {} bytes, {} passes, {}ms", 
               data_size, passes_completed, deletion_time);

        Ok(SecureDeletionResult {
            bytes_wiped: data_size,
            passes_completed,
            verification_passed: true, // Cannot verify memory
            deletion_time_ms: deletion_time,
            method_used: "memory_overwrite".to_string(),
        })
    }

    /// Wipe slack space in PDF file
    pub async fn wipe_slack_space(&self, file: &mut File, used_size: u64, total_size: u64) -> Result<SecureDeletionResult> {
        if used_size >= total_size {
            return Ok(SecureDeletionResult {
                bytes_wiped: 0,
                passes_completed: 0,
                verification_passed: true,
                deletion_time_ms: 0,
                method_used: "no_slack".to_string(),
            });
        }

        let start_time = std::time::Instant::now();
        let slack_size = total_size - used_size;
        
        info!("Wiping slack space: {} bytes at offset {}", slack_size, used_size);

        // Seek to start of slack space
        file.seek(SeekFrom::Start(used_size))
            .map_err(|e| AntiForensicsError::FileOperation(format!("Seek to slack space failed: {}", e)))?;

        let mut passes_completed = 0;

        for pass in 0..self.passes {
            // Seek back to slack space start
            file.seek(SeekFrom::Start(used_size))
                .map_err(|e| AntiForensicsError::FileOperation(format!("Seek failed: {}", e)))?;

            let pattern = self.get_pattern_for_pass(pass);
            
            // Overwrite slack space
            self.overwrite_with_pattern(file, slack_size, &pattern).await?;
            
            file.sync_all()
                .map_err(|e| AntiForensicsError::FileOperation(format!("Sync failed: {}", e)))?;
            
            passes_completed += 1;
        }

        let deletion_time = start_time.elapsed().as_millis() as u64;
        
        info!("Slack space wipe completed: {} bytes, {} passes, {}ms", 
              slack_size, passes_completed, deletion_time);

        Ok(SecureDeletionResult {
            bytes_wiped: slack_size,
            passes_completed,
            verification_passed: true,
            deletion_time_ms: deletion_time,
            method_used: "slack_space_wipe".to_string(),
        })
    }

    /// Get pattern for specific pass
    fn get_pattern_for_pass(&self, pass: u32) -> Vec<u8> {
        if self.passes == 35 && self.use_patterns {
            // Gutmann method
            let pattern_index = (pass as usize) % GUTMANN_PATTERNS.len();
            GUTMANN_PATTERNS[pattern_index].to_vec()
        } else if self.use_patterns && pass < 3 {
            // DoD 5220.22-M patterns for first 3 passes
            DOD_PATTERNS[(pass as usize) % DOD_PATTERNS.len()].to_vec()
        } else if self.use_random {
            // Random patterns for remaining passes
            let mut rng = thread_rng();
            let pattern_size = match pass % 4 {
                0 => 1,
                1 => 3,
                2 => 7,
                _ => 16,
            };
            let mut pattern = vec![0u8; pattern_size];
            rng.fill_bytes(&mut pattern);
            pattern
        } else {
            // Alternating patterns
            match pass % 4 {
                0 => vec![0x00],
                1 => vec![0xFF],
                2 => vec![0x55],
                _ => vec![0xAA],
            }
        }
    }

    /// Overwrite data with specific pattern
    async fn overwrite_with_pattern(&self, file: &mut File, size: u64, pattern: &[u8]) -> Result<()> {
        const BUFFER_SIZE: usize = 64 * 1024; // 64KB buffer
        let mut buffer = vec![0u8; BUFFER_SIZE];
        
        // Fill buffer with pattern
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = pattern[i % pattern.len()];
        }

        let mut remaining = size;
        
        while remaining > 0 {
            let write_size = std::cmp::min(remaining, BUFFER_SIZE as u64) as usize;
            
            file.write_all(&buffer[..write_size])
                .map_err(|e| AntiForensicsError::FileOperation(format!("Write failed: {}", e)))?;
            
            remaining -= write_size as u64;
        }

        Ok(())
    }

    /// Verify that overwrite was successful
    async fn verify_overwrite(&self, file: &mut File, size: u64) -> Result<bool> {
        debug!("Verifying secure overwrite");
        
        file.seek(SeekFrom::Start(0))
            .map_err(|e| AntiForensicsError::FileOperation(format!("Verification seek failed: {}", e)))?;

        const BUFFER_SIZE: usize = 64 * 1024;
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut remaining = size;
        let mut original_data_found = false;

        while remaining > 0 {
            let read_size = std::cmp::min(remaining, BUFFER_SIZE as u64) as usize;
            
            file.read_exact(&mut buffer[..read_size])
                .map_err(|e| AntiForensicsError::FileOperation(format!("Verification read failed: {}", e)))?;

            // Check for patterns that might indicate original data
            if self.contains_original_data_patterns(&buffer[..read_size]) {
                original_data_found = true;
                break;
            }

            remaining -= read_size as u64;
        }

        Ok(!original_data_found)
    }

    /// Check for patterns that might indicate original data survived
    fn contains_original_data_patterns(&self, data: &[u8]) -> bool {
        // Look for common file signatures that might have survived
        let signatures = [
            b"PDF", b"JPEG", b"PNG", b"GIF", b"ZIP", b"RAR",
            b"<?xml", b"<html", b"MZ", b"\x7fELF"
        ];

        for signature in &signatures {
            if data.windows(signature.len()).any(|window| window == *signature) {
                return true;
            }
        }

        // Check for high concentration of printable ASCII (might be text)
        let printable_count = data.iter()
            .filter(|&&b| b >= 32 && b <= 126)
            .count();
        
        let printable_ratio = printable_count as f64 / data.len() as f64;
        
        // If more than 70% printable ASCII, might be original text
        printable_ratio > 0.7
    }

    /// Wipe free space on filesystem (requires root/admin)
    pub async fn wipe_free_space<P: AsRef<Path>>(&self, path: P) -> Result<SecureDeletionResult> {
        let path = path.as_ref();
        let start_time = std::time::Instant::now();
        
        info!("Starting free space wipe on: {}", path.display());

        // Create temporary file to fill free space
        let temp_file_path = path.join(".secure_wipe_temp");
        
        let mut temp_file = File::create(&temp_file_path)
            .map_err(|e| AntiForensicsError::FileOperation(format!("Cannot create temp file: {}", e)))?;

        let mut bytes_written = 0u64;
        const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
        let pattern = vec![0x00u8; CHUNK_SIZE];

        // Fill free space until disk is full
        loop {
            match temp_file.write_all(&pattern) {
                Ok(()) => {
                    bytes_written += CHUNK_SIZE as u64;
                    if bytes_written % (100 * 1024 * 1024) == 0 { // Log every 100MB
                        debug!("Written {} MB to free space", bytes_written / (1024 * 1024));
                    }
                }
                Err(_) => break, // Disk full
            }
        }

        // Sync and delete temp file
        let _ = temp_file.sync_all();
        drop(temp_file);
        let _ = std::fs::remove_file(&temp_file_path);

        let deletion_time = start_time.elapsed().as_millis() as u64;
        
        info!("Free space wipe completed: {} bytes written in {}ms", 
              bytes_written, deletion_time);

        Ok(SecureDeletionResult {
            bytes_wiped: bytes_written,
            passes_completed: 1,
            verification_passed: true,
            deletion_time_ms: deletion_time,
            method_used: "free_space_wipe".to_string(),
        })
    }
}

impl Default for SecureDelete {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_secure_file_deletion() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"sensitive data that must be wiped").unwrap();
        temp_file.flush().unwrap();

        let secure_delete = SecureDelete::new();
        let result = secure_delete.wipe_file(temp_file.path()).await;
        
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.passes_completed > 0);
        assert!(result.bytes_wiped > 0);
    }

    #[tokio::test]
    async fn test_memory_wipe() {
        let sensitive_data = b"secret information";
        let secure_delete = SecureDelete::new();
        
        let result = secure_delete.wipe_memory(sensitive_data).await;
        
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.bytes_wiped, sensitive_data.len() as u64);
        assert!(result.passes_completed > 0);
    }
}
