//! File Encryption Implementation
//! Author: kartik4091
//! Created: 2025-06-03 09:07:59 UTC

use super::*;
use crate::utils::metrics::Metrics;
use std::{
    sync::Arc,
    path::PathBuf,
    time::{Duration, Instant},
    collections::{HashMap, HashSet},
    io::{self, SeekFrom},
};
use tokio::{
    sync::{RwLock, Semaphore, broadcast},
    fs::{self, File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt},
};
use tracing::{info, warn, error, debug, instrument};
use ring::aead::{self, Aad, AES_256_GCM};

/// File encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEncryptionConfig {
    /// Base encryption configuration
    pub base: EncryptionConfig,
    /// Preserve original file
    pub preserve_original: bool,
    /// File extension for encrypted files
    pub encrypted_extension: String,
    /// Chunk size for streaming
    pub chunk_size: usize,
    /// Compression enabled
    pub use_compression: bool,
}

/// File encryption state
#[derive(Debug)]
struct FileEncryptionState {
    /// Active encryptions
    active_encryptions: HashSet<PathBuf>,
    /// Statistics
    stats: FileEncryptionStats,
}

/// File encryption statistics
#[derive(Debug, Default)]
struct FileEncryptionStats {
    files_encrypted: u64,
    files_decrypted: u64,
    bytes_processed: u64,
    avg_encryption_time: Duration,
}

pub struct FileEncryption {
    /// Base encryption
    base: Arc<BaseEncryption>,
    /// File encryption configuration
    config: Arc<FileEncryptionConfig>,
    /// Encryption state
    state: Arc<RwLock<FileEncryptionState>>,
    /// Performance metrics
    metrics: Arc<Metrics>,
}

impl FileEncryption {
    /// Creates a new file encryption instance
    pub fn new(config: FileEncryptionConfig) -> Self {
        Self {
            base: Arc::new(BaseEncryption::new(config.base.clone())),
            config: Arc::new(config),
            state: Arc::new(RwLock::new(FileEncryptionState {
                active_encryptions: HashSet::new(),
                stats: FileEncryptionStats::default(),
            })),
            metrics: Arc::new(Metrics::new()),
        }
    }

    /// Gets output path for encrypted file
    fn get_encrypted_path(&self, path: &PathBuf) -> PathBuf {
        path.with_extension(format!(
            "{}.{}",
            path.extension().unwrap_or_default().to_string_lossy(),
            self.config.encrypted_extension
        ))
    }

    /// Gets output path for decrypted file
    fn get_decrypted_path(&self, path: &PathBuf) -> PathBuf {
        let stem = path.file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        path.with_file_name(stem)
    }

    /// Encrypts data chunk
    #[instrument(skip(self, key, data))]
    async fn encrypt_chunk(&self, key: &EncryptionKey, data: &[u8]) -> Result<Vec<u8>> {
        let start = Instant::now();

        // Generate nonce
        let nonce = self.base.generate_nonce()?;
        let mut output = nonce.as_ref().to_vec();

        // Create encryption key
        let aead_key = self.base.create_key(&key.data)?;

        // Encrypt data
        let mut buffer = vec![0u8; data.len() + AES_256_GCM.tag_len()];
        aead_key.seal_in_place_append_tag(
            nonce,
            Aad::empty(),
            &mut buffer[..data.len()].copy_from_slice(data),
        ).map_err(|_| EncryptionError::Encryption("Failed to encrypt data".into()))?;

        output.extend_from_slice(&buffer);
        self.metrics.record_operation("chunk_encryption", start.elapsed()).await;
        Ok(output)
    }

    /// Decrypts data chunk
    #[instrument(skip(self, key, data))]
    async fn decrypt_chunk(&self, key: &EncryptionKey, data: &[u8]) -> Result<Vec<u8>> {
        let start = Instant::now();

        if data.len() < 12 {
            return Err(EncryptionError::Decryption("Invalid data length".into()));
        }

        // Extract nonce
        let nonce = Nonce::try_assume_unique_for_key(&data[..12])
            .map_err(|_| EncryptionError::Decryption("Invalid nonce".into()))?;

        // Create decryption key
        let aead_key = self.base.create_key(&key.data)?;

        // Decrypt data
        let mut buffer = data[12..].to_vec();
        let decrypted_data = aead_key.open_in_place(
            nonce,
            Aad::empty(),
            &mut buffer,
        ).map_err(|_| EncryptionError::Decryption("Failed to decrypt data".into()))?;

        self.metrics.record_operation("chunk_decryption", start.elapsed()).await;
        Ok(decrypted_data.to_vec())
    }

    /// Compresses data if enabled
    #[instrument(skip(self, data))]
    async fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.config.use_compression {
            return Ok(data.to_vec());
        }

        let start = Instant::now();
        let mut encoder = snap::Encoder::new();
        let compressed = encoder.compress_vec(data)
            .map_err(|e| EncryptionError::Encryption(
                format!("Compression failed: {}", e)
            ))?;

        self.metrics.record_operation("compression", start.elapsed()).await;
        Ok(compressed)
    }

    /// Decompresses data if enabled
    #[instrument(skip(self, data))]
    async fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !self.config.use_compression {
            return Ok(data.to_vec());
        }

        let start = Instant::now();
        let mut decoder = snap::Decoder::new();
        let decompressed = decoder.decompress_vec(data)
            .map_err(|e| EncryptionError::Decryption(
                format!("Decompression failed: {}", e)
            ))?;

        self.metrics.record_operation("decompression", start.elapsed()).await;
        Ok(decompressed)
    }
}

#[async_trait]
impl Encryption for FileEncryption {
    #[instrument(skip(self, key))]
    async fn encrypt_file(&self, path: &PathBuf, key: &EncryptionKey) -> Result<EncryptionResult> {
        let start = Instant::now();

        // Get rate limiting permit
        let _permit = self.base.semaphore.acquire().await
            .map_err(|e| EncryptionError::Encryption(e.to_string()))?;

        // Validate input
        self.validate(path).await?;

        // Open input file
        let mut input_file = File::open(path).await?;
        let file_size = input_file.metadata().await?.len();

        // Create output file
        let output_path = self.get_encrypted_path(path);
        let mut output_file = File::create(&output_path).await?;

        let mut buffer = vec![0u8; self.config.chunk_size];
        let mut total_written = 0u64;

        // Process file in chunks
        loop {
            let n = input_file.read(&mut buffer).await?;
            if n == 0 { break; }

            let chunk = &buffer[..n];
            
            // Compress chunk if enabled
            let compressed = self.compress_data(chunk).await?;
            
            // Encrypt chunk
            let encrypted = self.encrypt_chunk(key, &compressed).await?;
            
            // Write encrypted chunk
            output_file.write_all(&encrypted).await?;
            total_written += encrypted.len() as u64;
        }

        // Delete original file if not preserving
        if !self.config.preserve_original {
            fs::remove_file(path).await?;
        }

        // Update statistics
        let duration = start.elapsed();
        self.base.update_metrics(duration, true, total_written).await;

        let mut state = self.state.write().await;
        state.stats.files_encrypted += 1;
        state.stats.bytes_processed += total_written;
        state.stats.avg_encryption_time = (state.stats.avg_encryption_time + duration) / 2;

        let result = EncryptionResult {
            path: output_path,
            original_size: file_size,
            encrypted_size: total_written,
            duration,
            metrics: EncryptionMetrics {
                duration,
                memory_usage: self.config.chunk_size,
                encryption_ops: (file_size / self.config.chunk_size as u64) + 1,
                bytes_processed: total_written,
            },
        };

        // Record history and notify subscribers
        self.base.record_history(path.clone(), duration, true).await;
        let _ = self.base.alert_tx.send(result.clone());

        Ok(result)
    }

    #[instrument(skip(self, key))]
    async fn decrypt_file(&self, path: &PathBuf, key: &EncryptionKey) -> Result<EncryptionResult> {
        let start = Instant::now();

        // Get rate limiting permit
        let _permit = self.base.semaphore.acquire().await
            .map_err(|e| EncryptionError::Decryption(e.to_string()))?;

        // Validate input
        self.validate(path).await?;

        // Open input file
        let mut input_file = File::open(path).await?;
        let file_size = input_file.metadata().await?.len();

        // Create output file
        let output_path = self.get_decrypted_path(path);
        let mut output_file = File::create(&output_path).await?;

        let mut buffer = vec![0u8; self.config.chunk_size + AES_256_GCM.tag_len() + 12];
        let mut total_written = 0u64;

        // Process file in chunks
        loop {
            let n = input_file.read(&mut buffer).await?;
            if n == 0 { break; }

            let chunk = &buffer[..n];
            
            // Decrypt chunk
            let decrypted = self.decrypt_chunk(key, chunk).await?;
            
            // Decompress chunk if enabled
            let decompressed = self.decompress_data(&decrypted).await?;
            
            // Write decrypted chunk
            output_file.write_all(&decompressed).await?;
            total_written += decompressed.len() as u64;
        }

        // Delete encrypted file if not preserving
        if !self.config.preserve_original {
            fs::remove_file(path).await?;
        }

        // Update statistics
        let duration = start.elapsed();
        self.base.update_metrics(duration, true, total_written).await;

        let mut state = self.state.write().await;
        state.stats.files_decrypted += 1;
        state.stats.bytes_processed += total_written;
        state.stats.avg_encryption_time = (state.stats.avg_encryption_time + duration) / 2;

        let result = EncryptionResult {
            path: output_path,
            original_size: file_size,
            encrypted_size: total_written,
            duration,
            metrics: EncryptionMetrics {
                duration,
                memory_usage: self.config.chunk_size,
                encryption_ops: (file_size / self.config.chunk_size as u64) + 1,
                bytes_processed: total_written,
            },
        };

        // Record history and notify subscribers
        self.base.record_history(path.clone(), duration, true).await;
        let _ = self.base.alert_tx.send(result.clone());

        Ok(result)
    }

    #[instrument(skip(self))]
    async fn validate(&self, path: &PathBuf) -> Result<()> {
        // Check if file exists
        if !path.exists() {
            return Err(EncryptionError::InvalidInput(
                format!("File not found: {}", path.display())
            ));
        }

        // Check if it's a file
        if !path.is_file() {
            return Err(EncryptionError::InvalidInput(
                format!("Not a file: {}", path.display())
            ));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn cleanup(&self) -> Result<()> {
        let mut state = self.state.write().await;
        state.active_encryptions.clear();
        state.stats = FileEncryptionStats::default();
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_stats(&self) -> Result<EncryptionStats> {
        let state = self.state.read().await;
        Ok(EncryptionStats {
            total_ops: state.stats.files_encrypted + state.stats.files_decrypted,
            successful_ops: state.stats.files_encrypted + state.stats.files_decrypted,
            failed_ops: 0,
            total_bytes: state.stats.bytes_processed,
            avg_op_time: state.stats.avg_encryption_time,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_config() -> FileEncryptionConfig {
        FileEncryptionConfig {
            base: EncryptionConfig::default(),
            preserve_original: false,
            encrypted_extension: "enc".into(),
            chunk_size: 1024,
            use_compression: true,
        }
    }

    fn create_test_key() -> EncryptionKey {
        EncryptionKey {
            data: vec![0u8; 32],
            id: "test-key".into(),
            created: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_file_encryption() {
        let encryption = FileEncryption::new(create_test_config());
        let file = NamedTempFile::new().unwrap();
        let path = PathBuf::from(file.path());
        
        // Write test data
        tokio::fs::write(&path, b"test data").await.unwrap();
        
        let key = create_test_key();
        let result = encryption.encrypt_file(&path, &key).await.unwrap();
        assert!(result.encrypted_size > 0);
    }

    #[tokio::test]
    async fn test_file_decryption() {
        let encryption = FileEncryption::new(create_test_config());
        let file = NamedTempFile::new().unwrap();
        let path = PathBuf::from(file.path());
        
        // Write test data and encrypt
        tokio::fs::write(&path, b"test data").await.unwrap();
        let key = create_test_key();
        let encrypted = encryption.encrypt_file(&path, &key).await.unwrap();
        
        // Decrypt and verify
        let decrypted = encryption.decrypt_file(&encrypted.path, &key).await.unwrap();
        assert_eq!(decrypted.original_size, encrypted.encrypted_size);
    }

    #[tokio::test]
    async fn test_compression() {
        let encryption = FileEncryption::new(FileEncryptionConfig {
            use_compression: true,
            ..create_test_config()
        });
        
        let data = vec![0u8; 1000];
        let compressed = encryption.compress_data(&data).await.unwrap();
        assert!(compressed.len() < data.len());
    }

    #[tokio::test]
    async fn test_concurrent_encryption() {
        let encryption = FileEncryption::new(FileEncryptionConfig {
            base: EncryptionConfig {
                max_concurrent_ops: 2,
                ..EncryptionConfig::default()
            },
            ..create_test_config()
        });

        let files: Vec<_> = (0..4).map(|_| NamedTempFile::new().unwrap()).collect();
        let key = create_test_key();

        let handles: Vec<_> = files.iter().map(|file| {
            let encryption = encryption.clone();
            let key = key.clone();
            let path = PathBuf::from(file.path());
            tokio::spawn(async move {
                encryption.encrypt_file(&path, &key).await
            })
        }).collect();

        let results = futures::future::join_all(handles).await;
        for result in results {
            assert!(result.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn test_chunk_encryption() {
        let encryption = FileEncryption::new(create_test_config());
        let key = create_test_key();
        let data = b"test data";
        
        let encrypted = encryption.encrypt_chunk(&key, data).await.unwrap();
        assert!(encrypted.len() > data.len());
    }
  }
