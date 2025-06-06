//! Shannon entropy calculation implementation
//! Created: 2025-06-03 12:30:19 UTC
//! Author: kartik4091

use std::{
    io::{self, Read},
    sync::Arc,
};

use parking_lot::RwLock;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, instrument};

use crate::{
    error::{Error, Result},
    types::Document,
};

/// Shannon entropy calculator for data analysis
pub struct ShannonEntropy {
    /// Window size for sliding analysis
    window_size: usize,
    /// Overlap between windows
    window_overlap: usize,
    /// Processing limiter
    limiter: Arc<Semaphore>,
    /// Processing statistics
    stats: Arc<RwLock<EntropyStats>>,
}

/// Entropy calculation statistics
#[derive(Debug, Default)]
struct EntropyStats {
    /// Number of blocks processed
    blocks_processed: u64,
    /// Total bytes analyzed
    bytes_analyzed: u64,
    /// Average entropy
    average_entropy: f64,
    /// Maximum entropy found
    max_entropy: f64,
    /// Minimum entropy found
    min_entropy: f64,
}

/// Entropy calculation result
#[derive(Debug, Clone)]
pub struct EntropyResult {
    /// Overall entropy value
    pub entropy: f64,
    /// Block-wise entropy values
    pub block_entropy: Vec<f64>,
    /// Analysis timestamp
    pub timestamp: std::time::Instant,
    /// Processing duration
    pub duration: std::time::Duration,
}

impl ShannonEntropy {
    /// Creates new Shannon entropy calculator
    pub fn new(window_size: usize, window_overlap: usize) -> Self {
        assert!(window_overlap < window_size, "Overlap must be less than window size");
        
        Self {
            window_size,
            window_overlap,
            limiter: Arc::new(Semaphore::new(num_cpus::get())),
            stats: Arc::new(RwLock::new(EntropyStats::default())),
        }
    }

    /// Calculates entropy for document
    #[instrument(skip(self, document))]
    pub async fn analyze(&self, document: &Document) -> Result<EntropyResult> {
        let start = std::time::Instant::now();
        
        // Acquire processing permit
        let _permit = self.limiter.acquire().await?;
        
        let content = tokio::fs::read(&document.path).await?;
        
        // Calculate overall entropy
        let entropy = self.calculate_entropy(&content);
        
        // Calculate block entropy
        let block_entropy = self.calculate_block_entropy(&content)?;
        
        // Update statistics
        self.update_stats(entropy, &block_entropy);
        
        Ok(EntropyResult {
            entropy,
            block_entropy,
            timestamp: std::time::Instant::now(),
            duration: start.elapsed(),
        })
    }

    /// Calculates Shannon entropy for data block
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut frequencies = [0u64; 256];
        let len = data.len() as f64;
        
        // Calculate byte frequencies
        for &byte in data {
            frequencies[byte as usize] += 1;
        }
        
        // Calculate entropy
        let mut entropy = 0.0;
        for &freq in &frequencies {
            if freq > 0 {
                let p = freq as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }

    /// Calculates entropy for sliding windows
    fn calculate_block_entropy(&self, data: &[u8]) -> Result<Vec<f64>> {
        let mut block_entropy = Vec::new();
        let step_size = self.window_size - self.window_overlap;
        
        for window in data.windows(self.window_size).step_by(step_size) {
            let entropy = self.calculate_entropy(window);
            block_entropy.push(entropy);
        }
        
        Ok(block_entropy)
    }

    /// Updates entropy statistics
    fn update_stats(&self, entropy: f64, block_entropy: &[f64]) {
        let mut stats = self.stats.write();
        
        stats.blocks_processed += block_entropy.len() as u64;
        stats.bytes_analyzed += block_entropy.len() * self.window_size as u64;
        
        // Update running average
        let n = stats.blocks_processed as f64;
        stats.average_entropy = (stats.average_entropy * (n - 1.0) + entropy) / n;
        
        // Update min/max
        stats.max_entropy = stats.max_entropy.max(entropy);
        stats.min_entropy = if stats.min_entropy == 0.0 {
            entropy
        } else {
            stats.min_entropy.min(entropy)
        };
    }

    /// Gets current statistics
    pub fn get_stats(&self) -> EntropyStats {
        self.stats.read().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_entropy_calculation() {
        let data = b"Hello, World!";
        let file = NamedTempFile::new().unwrap();
        tokio::fs::write(&file, data).await.unwrap();
        
        let doc = Document::new(file.path().to_path_buf(), data.len() as u64);
        let analyzer = ShannonEntropy::new(8, 4);
        
        let result = analyzer.analyze(&doc).await.unwrap();
        assert!(result.entropy > 0.0);
        assert!(!result.block_entropy.is_empty());
    }

    #[tokio::test]
    async fn test_entropy_stats() {
        let analyzer = ShannonEntropy::new(8, 4);
        let data = vec![0u8; 1024];
        
        let entropy = analyzer.calculate_entropy(&data);
        let block_entropy = analyzer.calculate_block_entropy(&data).unwrap();
        
        analyzer.update_stats(entropy, &block_entropy);
        let stats = analyzer.get_stats();
        
        assert!(stats.blocks_processed > 0);
        assert!(stats.bytes_analyzed > 0);
    }

    #[test]
    fn test_window_validation() {
        assert!(std::panic::catch_unwind(|| {
            ShannonEntropy::new(4, 8) // overlap > window_size
        }).is_err());
    }
  }
