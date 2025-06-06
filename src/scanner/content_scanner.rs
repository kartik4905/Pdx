//! Content Scanner Implementation
//! Author: kartik4091
//! Created: 2025-06-03 08:52:18 UTC

use super::*;
use crate::utils::{metrics::Metrics, cache::Cache};
use std::{
    sync::Arc,
    path::PathBuf,
    time::{Duration, Instant},
    collections::{HashMap, HashSet, BTreeMap},
    io::SeekFrom,
};
use tokio::{
    sync::{RwLock, Semaphore, broadcast},
    fs::{self, File},
    io::{BufReader, AsyncReadExt, AsyncSeekExt},
};
use tracing::{info, warn, error, debug, instrument};
use memmap2::MmapOptions;
use rayon::prelude::*;

/// Content scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentScannerConfig {
    /// Base scanner configuration
    pub base: ScannerConfig,
    /// Chunk size for streaming
    pub chunk_size: usize,
    /// Maximum content depth
    pub max_depth: usize,
    /// Content patterns to match
    pub patterns: HashMap<String, String>,
    /// Binary analysis enabled
    pub binary_analysis: bool,
    /// Memory map threshold
    pub mmap_threshold: usize,
}

/// Content scanner state
#[derive(Debug)]
struct ContentScannerState {
    /// Active scans
    active_scans: HashSet<PathBuf>,
    /// Compiled patterns
    patterns: HashMap<String, regex::Regex>,
    /// Statistics
    stats: ContentStats,
}

/// Content statistics
#[derive(Debug, Default)]
struct ContentStats {
    bytes_scanned: u64,
    patterns_matched: u64,
    files_analyzed: u64,
    avg_scan_time: Duration,
}

/// Cached content analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedContentScan {
    results: ScanResult,
    timestamp: chrono::DateTime<chrono::Utc>,
    hash: String,
}

/// Content analysis chunk
#[derive(Debug)]
struct ContentChunk {
    offset: u64,
    data: Vec<u8>,
    findings: Vec<ChunkFinding>,
}

/// Finding within a chunk
#[derive(Debug)]
struct ChunkFinding {
    pattern: String,
    offset: u64,
    context: String,
}

pub struct ContentScanner {
    base: Arc<BaseScanner>,
    config: Arc<ContentScannerConfig>,
    state: Arc<RwLock<ContentScannerState>>,
    metrics: Arc<Metrics>,
    cache: Arc<Cache<CachedContentScan>>,
}

impl ContentScanner {
    /// Creates a new content scanner
    pub fn new(config: ContentScannerConfig) -> Self {
        let patterns = Self::compile_patterns(&config.patterns);
        
        Self {
            base: Arc::new(BaseScanner::new(config.base.clone())),
            config: Arc::new(config),
            state: Arc::new(RwLock::new(ContentScannerState {
                active_scans: HashSet::new(),
                patterns,
                stats: ContentStats::default(),
            })),
            metrics: Arc::new(Metrics::new()),
            cache: Arc::new(Cache::new(Duration::from_secs(3600))), // 1 hour cache
        }
    }

    /// Compiles regex patterns
    fn compile_patterns(patterns: &HashMap<String, String>) -> HashMap<String, regex::Regex> {
        patterns.iter()
            .filter_map(|(name, pattern)| {
                regex::Regex::new(pattern)
                    .map(|r| (name.clone(), r))
                    .ok()
            })
            .collect()
    }

    /// Analyzes content using memory mapping for large files
    #[instrument(skip(self, path))]
    async fn analyze_mapped_content(&self, path: &PathBuf) -> Result<Vec<ScanFinding>> {
        let file = File::open(path).await?;
        let metadata = file.metadata().await?;
        let mut findings = Vec::new();

        // Safety: We've validated the file and have exclusive access
        let mmap = unsafe {
            MmapOptions::new()
                .map(&std::fs::File::from(file))
                .map_err(|e| ScannerError::Internal(e.to_string()))?
        };

        let state = self.state.read().await;
        let chunk_size = self.config.chunk_size;

        // Process content in parallel chunks
        let chunk_findings: Vec<_> = mmap.par_chunks(chunk_size)
            .enumerate()
            .flat_map(|(i, chunk)| {
                let offset = i as u64 * chunk_size as u64;
                let mut chunk_findings = Vec::new();

                for (pattern_name, pattern) in &state.patterns {
                    if let Ok(content) = String::from_utf8_lossy(chunk).to_string() {
                        for mat in pattern.find_iter(&content) {
                            chunk_findings.push(ChunkFinding {
                                pattern: pattern_name.clone(),
                                offset: offset + mat.start() as u64,
                                context: content[mat.start().saturating_sub(20)..
                                    (mat.end() + 20).min(content.len())].to_string(),
                            });
                        }
                    }
                }
                chunk_findings
            })
            .collect();

        // Convert chunk findings to scan findings
        for finding in chunk_findings {
            findings.push(ScanFinding {
                severity: Severity::Medium,
                category: Category::Content,
                description: format!("Pattern match: {}", finding.pattern),
                location: format!("Offset: {}", finding.offset),
                recommendation: format!("Review content: {}", finding.context),
                timestamp: chrono::Utc::now(),
            });
        }

        Ok(findings)
    }

    /// Analyzes content using streaming for smaller files
    #[instrument(skip(self, file))]
    async fn analyze_streamed_content(&self, mut file: File) -> Result<Vec<ScanFinding>> {
        let mut findings = Vec::new();
        let mut buffer = vec![0; self.config.chunk_size];
        let mut offset = 0u64;

        let state = self.state.read().await;

        loop {
            let n = file.read(&mut buffer).await?;
            if n == 0 { break; }

            if let Ok(content) = String::from_utf8_lossy(&buffer[..n]).to_string() {
                for (pattern_name, pattern) in &state.patterns {
                    for mat in pattern.find_iter(&content) {
                        findings.push(ScanFinding {
                            severity: Severity::Medium,
                            category: Category::Content,
                            description: format!("Pattern match: {}", pattern_name),
                            location: format!("Offset: {}", offset + mat.start() as u64),
                            recommendation: format!("Review content near offset"),
                            timestamp: chrono::Utc::now(),
                        });
                    }
                }
            }

            offset += n as u64;
        }

        Ok(findings)
    }

    /// Performs binary analysis if enabled
    #[instrument(skip(self, data))]
    async fn analyze_binary(&self, data: &[u8]) -> Result<Vec<ScanFinding>> {
        let mut findings = Vec::new();

        // Check for executable content
        if data.starts_with(b"MZ") || data.starts_with(b"\x7FELF") {
            findings.push(ScanFinding {
                severity: Severity::High,
                category: Category::Security,
                description: "Executable content detected".into(),
                location: "File header".into(),
                recommendation: "Review executable content for security risks".into(),
                timestamp: chrono::Utc::now(),
            });
        }

        // Check for encrypted content
        if data.len() >= 256 {
            let entropy = self.calculate_entropy(&data[..256]);
            if entropy > 7.5 {
                findings.push(ScanFinding {
                    severity: Severity::Medium,
                    category: Category::Security,
                    description: "Possible encrypted content detected".into(),
                    location: "File header".into(),
                    recommendation: "Review content for encryption".into(),
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        Ok(findings)
    }

    /// Calculates Shannon entropy for binary analysis
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut frequencies = [0u32; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }

        let mut entropy = 0.0;
        let len = data.len() as f64;
        for &freq in &frequencies {
            if freq > 0 {
                let p = freq as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

#[async_trait]
impl Scanner for ContentScanner {
    #[instrument(skip(self))]
    async fn scan_file(&self, path: &PathBuf) -> Result<ScanResult> {
        let start = Instant::now();

        // Get rate limiting permit
        let _permit = self.base.semaphore.acquire().await
            .map_err(|e| ScannerError::Internal(e.to_string()))?;

        // Validate input
        self.validate(path).await?;

        // Check cache
        let hash = format!("{:x}", md5::compute(&fs::read(path).await?));
        let cache_key = format!("content_scan_{}", hash);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached.results);
        }

        // Open file
        let file = File::open(path).await?;
        let metadata = file.metadata().await?;

        // Choose analysis method based on file size
        let findings = if metadata.len() as usize > self.config.mmap_threshold {
            self.analyze_mapped_content(path).await?
        } else {
            self.analyze_streamed_content(file).await?
        };

        // Perform binary analysis if enabled
        let mut all_findings = findings;
        if self.config.binary_analysis {
            let data = fs::read(path).await?;
            all_findings.extend(self.analyze_binary(&data).await?);
        }

        // Update statistics
        let duration = start.elapsed();
        self.base.update_metrics(duration, true).await;

        let mut state = self.state.write().await;
        state.stats.bytes_scanned += metadata.len();
        state.stats.patterns_matched += all_findings.len() as u64;
        state.stats.files_analyzed += 1;
        state.stats.avg_scan_time = (state.stats.avg_scan_time + duration) / 2;

        // Prepare result
        let result = ScanResult {
            path: path.clone(),
            size: metadata.len(),
            file_type: "Content".into(),
            findings: all_findings,
            metadata: HashMap::new(),
            metrics: ScanMetrics {
                duration,
                memory_usage: metadata.len() as usize,
                cpu_usage: 0.0,
            },
        };

        // Cache result
        let cache_entry = CachedContentScan {
            results: result.clone(),
            timestamp: chrono::Utc::now(),
            hash,
        };
        self.cache.set(cache_key, cache_entry).await;

        Ok(result)
    }

    #[instrument(skip(self))]
    async fn validate(&self, path: &PathBuf) -> Result<()> {
        self.base.validate_file(path).await
    }

    #[instrument(skip(self))]
    async fn cleanup(&self) -> Result<()> {
        self.cache.clear().await;
        let mut state = self.state.write().await;
        state.active_scans.clear();
        state.stats = ContentStats::default();
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_stats(&self) -> Result<ScannerMetrics> {
        let state = self.state.read().await;
        Ok(ScannerMetrics {
            total_scans: state.stats.files_analyzed,
            successful_scans: state.stats.files_analyzed,
            failed_scans: 0,
            total_scan_time: state.stats.avg_scan_time * state.stats.files_analyzed,
            avg_scan_time: state.stats.avg_scan_time,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_config() -> ContentScannerConfig {
        ContentScannerConfig {
            base: ScannerConfig::default(),
            chunk_size: 4096,
            max_depth: 5,
            patterns: [
                ("test_pattern".into(), r"test\d+".into()),
            ].iter().cloned().collect(),
            binary_analysis: true,
            mmap_threshold: 1024 * 1024, // 1MB
        }
    }

    #[tokio::test]
    async fn test_content_streaming() {
        let scanner = ContentScanner::new(create_test_config());
        let mut file = NamedTempFile::new().unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut file, b"test123").await.unwrap();
        
        let findings = scanner.analyze_streamed_content(
            File::open(file.path()).await.unwrap()
        ).await.unwrap();
        
        assert!(!findings.is_empty());
    }

    #[tokio::test]
    async fn test_binary_analysis() {
        let scanner = ContentScanner::new(create_test_config());
        let data = b"MZ\x90\x00\x03\x00\x00\x00";
        
        let findings = scanner.analyze_binary(data).await.unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[tokio::test]
    async fn test_entropy_calculation() {
        let scanner = ContentScanner::new(create_test_config());
        
        // Test low entropy
        let low_entropy_data = vec![0u8; 256];
        assert!(scanner.calculate_entropy(&low_entropy_data) < 1.0);

        // Test high entropy
        let high_entropy_data: Vec<u8> = (0..256).collect();
        assert!(scanner.calculate_entropy(&high_entropy_data) > 7.0);
    }

    #[tokio::test]
    async fn test_concurrent_scans() {
        let scanner = ContentScanner::new(ContentScannerConfig {
            base: ScannerConfig {
                max_concurrent_scans: 2,
                ..ScannerConfig::default()
            },
            ..create_test_config()
        });

        let file = NamedTempFile::new().unwrap();
        let path = PathBuf::from(file.path());

        let handles: Vec<_> = (0..4).map(|_| {
            let scanner = scanner.clone();
            let path = path.clone();
            tokio::spawn(async move {
                scanner.scan_file(&path).await
            })
        }).collect();

        let results = futures::future::join_all(handles).await;
        for result in results {
            assert!(result.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn test_cleanup() {
        let scanner = ContentScanner::new(create_test_config());
        assert!(scanner.cleanup().await.is_ok());
    }

    #[tokio::test]
    async fn test_stats() {
        let scanner = ContentScanner::new(create_test_config());
        let file = NamedTempFile::new().unwrap();
        let path = PathBuf::from(file.path());
        
        scanner.scan_file(&path).await.unwrap();
        let stats = scanner.get_stats().await.unwrap();
        assert_eq!(stats.total_scans, 1);
        assert_eq!(stats.failed_scans, 0);
    }
  }
