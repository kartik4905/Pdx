//! Combined HashHandler + HashInjector
//! Author: kartik4091
//! Fully production-grade

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    fs::File,
    io::AsyncReadExt,
    sync::{RwLock, Semaphore},
};
use sha2::{Sha256, Sha512, Digest as ShaDigest};
use sha1::Sha1;
use md5::Md5;
use blake3::Hasher as Blake3;
use chrono::Utc;
use tracing::{debug, error, info, instrument};
use serde::{Serialize, Deserialize};
use hex;

use crate::{
    error::{Error, ForensicError, Result},
    metrics::MetricsCollector,
    types::{Document, Object},
};

// ========================== Document Hashing =============================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentHashes {
    pub document_id: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub blake3: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
struct HashState {
    active: usize,
    cache: HashMap<String, DocumentHashes>,
    history: Vec<HashRecord>,
    total_bytes: u64,
}

#[derive(Debug)]
struct HashRecord {
    doc_id: String,
    started: Instant,
    duration: Duration,
    bytes: u64,
    success: bool,
}

#[derive(Debug, Clone)]
pub struct HashConfig {
    pub buffer_size: usize,
    pub max_concurrent: usize,
    pub timeout: Duration,
    pub enable_cache: bool,
}

impl Default for HashConfig {
    fn default() -> Self {
        Self {
            buffer_size: 1024 * 1024,
            max_concurrent: num_cpus::get(),
            timeout: Duration::from_secs(300),
            enable_cache: true,
        }
    }
}

pub struct HashHandler {
    state: Arc<RwLock<HashState>>,
    limiter: Arc<Semaphore>,
    metrics: Arc<MetricsCollector>,
    config: Arc<HashConfig>,
}

impl HashHandler {
    pub fn new(config: HashConfig, metrics: Arc<MetricsCollector>) -> Self {
        Self {
            state: Arc::new(RwLock::new(HashState {
                active: 0,
                cache: HashMap::new(),
                history: Vec::new(),
                total_bytes: 0,
            })),
            limiter: Arc::new(Semaphore::new(config.max_concurrent)),
            metrics,
            config: Arc::new(config),
        }
    }

    #[instrument(skip(self, doc))]
    pub async fn compute(&self, doc: &Document) -> Result<DocumentHashes> {
        let _permit = self.limiter.acquire().await.unwrap();
        let id = doc.id();
        let start = Instant::now();

        if self.config.enable_cache {
            if let Some(cached) = self.state.read().await.cache.get(&id).cloned() {
                return Ok(cached);
            }
        }

        let mut file = doc.open_async().await?;
        let mut buf = vec![0u8; self.config.buffer_size];
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        let mut sha512 = Sha512::new();
        let mut blake3 = Blake3::new();

        let mut total = 0u64;

        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 { break; }
            let chunk = &buf[..n];
            md5.update(chunk);
            sha1.update(chunk);
            sha256.update(chunk);
            sha512.update(chunk);
            blake3.update(chunk);
            total += n as u64;
        }

        let result = DocumentHashes {
            document_id: id.clone(),
            md5: format!("{:x}", md5.finalize()),
            sha1: format!("{:x}", sha1.finalize()),
            sha256: format!("{:x}", sha256.finalize()),
            sha512: format!("{:x}", sha512.finalize()),
            blake3: format!("{:x}", blake3.finalize()),
            timestamp: Utc::now(),
        };

        self.state.write().await.cache.insert(id.clone(), result.clone());
        self.metrics.increment_counter("hashes_computed").await;

        Ok(result)
    }
}

// ========================== Hash Injector =============================

#[derive(Debug)]
pub struct HashInjector;

impl HashInjector {
    pub fn new() -> Self { Self }

    pub fn inject_all(&mut self, doc: &mut Document) -> Result<()> {
        let content = doc.raw_bytes().ok_or(Error::Hashing("Missing raw bytes".into()))?;
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();

        md5.update(&content);
        sha1.update(&content);
        sha256.update(&content);

        let info = doc.info_dict_mut().ok_or(Error::Metadata("Missing /Info dictionary".into()))?;
        info.insert(b"MD5Digest".to_vec(), Object::String(hex::encode(md5.finalize()).into_bytes()));
        info.insert(b"SHA1Digest".to_vec(), Object::String(hex::encode(sha1.finalize()).into_bytes()));
        info.insert(b"SHA256Digest".to_vec(), Object::String(hex::encode(sha256.finalize()).into_bytes()));

        Ok(())
    }
          }
  
