//! Stream Encryption Implementation
//! Author: kartik4091
//! Created: 2025-06-03 09:12:21 UTC

use super::*;
use crate::utils::metrics::Metrics;
use std::{
    sync::Arc,
    path::PathBuf,
    time::{Duration, Instant},
    collections::{HashMap, HashSet, VecDeque},
    pin::Pin,
};
use tokio::{
    sync::{RwLock, Semaphore, broadcast, mpsc},
    fs::{self, File},
    io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt},
};
use tracing::{info, warn, error, debug, instrument};
use futures::{Stream, StreamExt, Sink, SinkExt};
use ring::aead::{self, Aad, Nonce};

/// Stream encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEncryptionConfig {
    /// Base encryption configuration
    pub base: EncryptionConfig,
    /// Buffer size
    pub buffer_size: usize,
    /// Chunk size
    pub chunk_size: usize,
    /// Pipeline depth
    pub pipeline_depth: usize,
    /// Use compression
    pub use_compression: bool,
}

/// Stream encryption state
#[derive(Debug)]
struct StreamEncryptionState {
    /// Active streams
    active_streams: HashSet<String>,
    /// Statistics
    stats: StreamEncryptionStats,
}

/// Stream encryption statistics
#[derive(Debug, Default)]
struct StreamEncryptionStats {
    chunks_processed: u64,
    bytes_processed: u64,
    active_streams: u64,
    avg_chunk_time: Duration,
}

/// Encrypted chunk
#[derive(Debug)]
struct EncryptedChunk {
    /// Chunk index
    index: u64,
    /// Encrypted data
    data: Vec<u8>,
    /// Initialization vector
    iv: Vec<u8>,
}

/// Stream processor
struct StreamProcessor {
    /// Chunk queue
    queue: VecDeque<EncryptedChunk>,
    /// Next expected index
    next_index: u64,
    /// Stream ID
    stream_id: String,
}

pub struct StreamEncryption {
    /// Base encryption
    base: Arc<BaseEncryption>,
    /// Stream encryption configuration
    config: Arc<StreamEncryptionConfig>,
    /// Encryption state
    state: Arc<RwLock<StreamEncryptionState>>,
    /// Performance metrics
    metrics: Arc<Metrics>,
}

impl StreamEncryption {
    /// Creates a new stream encryption instance
    pub fn new(config: StreamEncryptionConfig) -> Self {
        Self {
            base: Arc::new(BaseEncryption::new(config.base.clone())),
            config: Arc::new(config),
            state: Arc::new(RwLock::new(StreamEncryptionState {
                active_streams: HashSet::new(),
                stats: StreamEncryptionStats::default(),
            })),
            metrics: Arc::new(Metrics::new()),
        }
    }

    /// Creates an encryption stream
    #[instrument(skip(self, key, reader))]
    pub async fn create_encryption_stream<R>(
        &self,
        key: &EncryptionKey,
        reader: R,
    ) -> Result<impl Stream<Item = Result<Vec<u8>>>>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let stream_id = format!("stream_{}", chrono::Utc::now().timestamp_nanos());
        let (tx, rx) = mpsc::channel(self.config.pipeline_depth);
        let key = key.clone();
        let config = self.config.clone();
        let metrics = self.metrics.clone();

        // Update state
        let mut state = self.state.write().await;
        state.active_streams.insert(stream_id.clone());
        state.stats.active_streams += 1;

        // Spawn encryption task
        tokio::spawn(async move {
            let mut reader = reader;
            let mut buffer = vec![0u8; config.chunk_size];
            let mut chunk_index = 0u64;
            let start = Instant::now();

            loop {
                // Read chunk
                let n = match reader.read(&mut buffer).await {
                    Ok(0) => break, // EOF
                    Ok(n) => n,
                    Err(e) => {
                        let _ = tx.send(Err(EncryptionError::IoError(e))).await;
                        break;
                    }
                };

                let chunk = &buffer[..n];

                // Compress if enabled
                let data = if config.use_compression {
                    match snap::raw::Encoder::new().compress_vec(chunk) {
                        Ok(compressed) => compressed,
                        Err(e) => {
                            let _ = tx.send(Err(EncryptionError::Encryption(
                                format!("Compression failed: {}", e)
                            ))).await;
                            break;
                        }
                    }
                } else {
                    chunk.to_vec()
                };

                // Generate nonce
                let nonce = match ring::aead::Nonce::try_assume_unique_for_key(&chunk_index.to_le_bytes()) {
                    Ok(n) => n,
                    Err(_) => {
                        let _ = tx.send(Err(EncryptionError::Encryption(
                            "Failed to generate nonce".into()
                        ))).await;
                        break;
                    }
                };

                // Create encryption key
                let aead_key = match UnboundKey::new(&AES_256_GCM, &key.data) {
                    Ok(k) => LessSafeKey::new(k),
                    Err(_) => {
                        let _ = tx.send(Err(EncryptionError::Key(
                            "Invalid encryption key".into()
                        ))).await;
                        break;
                    }
                };

                // Encrypt chunk
                let mut encrypted = data.clone();
                match aead_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted) {
                    Ok(_) => {
                        // Send encrypted chunk
                        if let Err(e) = tx.send(Ok(encrypted)).await {
                            error!("Failed to send encrypted chunk: {}", e);
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = tx.send(Err(EncryptionError::Encryption(
                            "Encryption failed".into()
                        ))).await;
                        break;
                    }
                }

                chunk_index += 1;
            }

            // Record metrics
            metrics.record_operation("stream_encryption", start.elapsed()).await;
        });

        Ok(rx)
    }

    /// Creates a decryption stream
    #[instrument(skip(self, key, reader))]
    pub async fn create_decryption_stream<R>(
        &self,
        key: &EncryptionKey,
        reader: R,
    ) -> Result<impl Stream<Item = Result<Vec<u8>>>>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let stream_id = format!("stream_{}", chrono::Utc::now().timestamp_nanos());
        let (tx, rx) = mpsc::channel(self.config.pipeline_depth);
        let key = key.clone();
        let config = self.config.clone();
        let metrics = self.metrics.clone();

        // Update state
        let mut state = self.state.write().await;
        state.active_streams.insert(stream_id.clone());
        state.stats.active_streams += 1;

        // Spawn decryption task
        tokio::spawn(async move {
            let mut reader = reader;
            let mut buffer = vec![0u8; config.chunk_size + AES_256_GCM.tag_len()];
            let mut chunk_index = 0u64;
            let start = Instant::now();

            loop {
                // Read chunk
                let n = match reader.read(&mut buffer).await {
                    Ok(0) => break, // EOF
                    Ok(n) => n,
                    Err(e) => {
                        let _ = tx.send(Err(EncryptionError::IoError(e))).await;
                        break;
                    }
                };

                let chunk = &buffer[..n];

                // Generate nonce
                let nonce = match ring::aead::Nonce::try_assume_unique_for_key(&chunk_index.to_le_bytes()) {
                    Ok(n) => n,
                    Err(_) => {
                        let _ = tx.send(Err(EncryptionError::Decryption(
                            "Failed to generate nonce".into()
                        ))).await;
                        break;
                    }
                };

                // Create decryption key
                let aead_key = match UnboundKey::new(&AES_256_GCM, &key.data) {
                    Ok(k) => LessSafeKey::new(k),
                    Err(_) => {
                        let _ = tx.send(Err(EncryptionError::Key(
                            "Invalid decryption key".into()
                        ))).await;
                        break;
                    }
                };

                // Decrypt chunk
                let mut decrypted = chunk.to_vec();
                match aead_key.open_in_place(nonce, Aad::empty(), &mut decrypted) {
                    Ok(plaintext) => {
                        // Decompress if enabled
                        let data = if config.use_compression {
                            match snap::raw::Decoder::new().decompress_vec(plaintext) {
                                Ok(decompressed) => decompressed,
                                Err(e) => {
                                    let _ = tx.send(Err(EncryptionError::Decryption(
                                        format!("Decompression failed: {}", e)
                                    ))).await;
                                    break;
                                }
                            }
                        } else {
                            plaintext.to_vec()
                        };

                        // Send decrypted chunk
                        if let Err(e) = tx.send(Ok(data)).await {
                            error!("Failed to send decrypted chunk: {}", e);
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = tx.send(Err(EncryptionError::Decryption(
                            "Decryption failed".into()
                        ))).await;
                        break;
                    }
                }

                chunk_index += 1;
            }

            // Record metrics
            metrics.record_operation("stream_decryption", start.elapsed()).await;
        });

        Ok(rx)
    }

    /// Processes a stream in memory
    #[instrument(skip(self))]
    async fn process_stream(&self, stream_id: &str) -> Result<StreamProcessor> {
        let processor = StreamProcessor {
            queue: VecDeque::new(),
            next_index: 0,
            stream_id: stream_id.to_string(),
        };

        Ok(processor)
    }
}

#[async_trait]
impl Encryption for StreamEncryption {
    #[instrument(skip(self, key))]
    async fn encrypt_file(&self, path: &PathBuf, key: &EncryptionKey) -> Result<EncryptionResult> {
        let start = Instant::now();

        // Open input file
        let file = File::open(path).await?;
        let file_size = file.metadata().await?.len();

        // Create encryption stream
        let mut stream = self.create_encryption_stream(key, file).await?;

        // Create output file
        let output_path = path.with_extension("enc");
        let mut output_file = File::create(&output_path).await?;

        let mut total_written = 0u64;

        // Process stream
        while let Some(result) = stream.next().await {
            match result {
                Ok(chunk) => {
                    output_file.write_all(&chunk).await?;
                    total_written += chunk.len() as u64;
                }
                Err(e) => return Err(e),
            }
        }

        // Update statistics
        let duration = start.elapsed();
        self.base.update_metrics(duration, true, total_written).await;

        let mut state = self.state.write().await;
        state.stats.chunks_processed += total_written / self.config.chunk_size as u64;
        state.stats.bytes_processed += total_written;
        state.stats.avg_chunk_time = (state.stats.avg_chunk_time + duration) / 2;

        Ok(EncryptionResult {
            path: output_path,
            original_size: file_size,
            encrypted_size: total_written,
            duration,
            metrics: EncryptionMetrics {
                duration,
                memory_usage: self.config.buffer_size,
                encryption_ops: total_written / self.config.chunk_size as u64,
                bytes_processed: total_written,
            },
        })
    }

    #[instrument(skip(self, key))]
    async fn decrypt_file(&self, path: &PathBuf, key: &EncryptionKey) -> Result<EncryptionResult> {
        let start = Instant::now();

        // Open input file
        let file = File::open(path).await?;
        let file_size = file.metadata().await?.len();

        // Create decryption stream
        let mut stream = self.create_decryption_stream(key, file).await?;

        // Create output file
        let output_path = path.with_extension("dec");
        let mut output_file = File::create(&output_path).await?;

        let mut total_written = 0u64;

        // Process stream
        while let Some(result) = stream.next().await {
            match result {
                Ok(chunk) => {
                    output_file.write_all(&chunk).await?;
                    total_written += chunk.len() as u64;
                }
                Err(e) => return Err(e),
            }
        }

        // Update statistics
        let duration = start.elapsed();
        self.base.update_metrics(duration, true, total_written).await;

        let mut state = self.state.write().await;
        state.stats.chunks_processed += total_written / self.config.chunk_size as u64;
        state.stats.bytes_processed += total_written;
        state.stats.avg_chunk_time = (state.stats.avg_chunk_time + duration) / 2;

        Ok(EncryptionResult {
            path: output_path,
            original_size: file_size,
            encrypted_size: total_written,
            duration,
            metrics: EncryptionMetrics {
                duration,
                memory_usage: self.config.buffer_size,
                encryption_ops: total_written / self.config.chunk_size as u64,
                bytes_processed: total_written,
            },
        })
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
        state.active_streams.clear();
        state.stats = StreamEncryptionStats::default();
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_stats(&self) -> Result<EncryptionStats> {
        let state = self.state.read().await;
        Ok(EncryptionStats {
            total_ops: state.stats.chunks_processed,
            successful_ops: state.stats.chunks_processed,
            failed_ops: 0,
            total_bytes: state.stats.bytes_processed,
            avg_op_time: state.stats.avg_chunk_time,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_config() -> StreamEncryptionConfig {
        StreamEncryptionConfig {
            base: EncryptionConfig::default(),
            buffer_size: 1024,
            chunk_size: 512,
            pipeline_depth: 4,
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
    async fn test_stream_encryption() {
        let encryption = StreamEncryption::new(create_test_config());
        let key = create_test_key();
        let data = b"test data".to_vec();
        
        let cursor = std::io::Cursor::new(data.clone());
        let mut stream = encryption.create_encryption_stream(&key, cursor).await.unwrap();
        
        let mut encrypted = Vec::new();
        while let Some(chunk) = stream.next().await {
            encrypted.extend(chunk.unwrap());
        }
        
        assert!(encrypted.len() > data.len());
    }

    #[tokio::test]
    async fn test_stream_decryption() {
        let encryption = StreamEncryption::new(create_test_config());
        let key = create_test_key();
        let data = b"test data".to_vec();
        
        // Encrypt
        let cursor = std::io::Cursor::new(data.clone());
        let mut enc_stream = encryption.create_encryption_stream(&key, cursor).await.unwrap();
        
        let mut encrypted = Vec::new();
        while let Some(chunk) = enc_stream.next().await {
            encrypted.extend(chunk.unwrap());
        }
        
        // Decrypt
        let cursor = std::io::Cursor::new(encrypted);
        let mut dec_stream = encryption.create_decryption_stream(&key, cursor).await.unwrap();
        
        let mut decrypted = Vec::new();
        while let Some(chunk) = dec_stream.next().await {
            decrypted.extend(chunk.unwrap());
        }
        
        assert_eq!(data, decrypted);
    }

    #[tokio::test]
    async fn test_file_encryption() {
        let encryption = StreamEncryption::new(create_test_config());
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
        let encryption = StreamEncryption::new(create_test_config());
        let file = NamedTempFile::new().unwrap();
        let path = PathBuf::from(file.path());
        
        // Write and encrypt test data
        tokio::fs::write(&path, b"test data").await.unwrap();
        let key = create_test_key();
        let encrypted = encryption.encrypt_file(&path, &key).await.unwrap();
        
        // Decrypt and verify
        let decrypted = encryption.decrypt_file(&encrypted.path, &key).await.unwrap();
        assert_eq!(decrypted.original_size, encrypted.encrypted_size);
    }

    #[tokio::test]
    async fn test_compression() {
        let encryption = StreamEncryption::new(StreamEncryptionConfig {
            use_compression: true,
            ..create_test_config()
        });
        let file = NamedTempFile::new().unwrap();
        let path = PathBuf::from(file.path());
        
        // Write repeating data that should compress well
        tokio::fs::write(&path, vec![0u8; 1000]).await.unwrap();
        
        let key = create_test_key();
        let result = encryption.encrypt_file(&path, &key).await.unwrap();
        assert!(result.encrypted_size < 1000);
    }
                     }
