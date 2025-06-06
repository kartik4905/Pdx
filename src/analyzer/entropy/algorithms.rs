//! Additional entropy analysis algorithms
//! Created: 2025-06-03 12:30:19 UTC
//! Author: kartik4091

use std::{
    collections::HashMap,
    io::Read,
    sync::Arc,
};

use parking_lot::RwLock;
use tracing::{debug, error, info, instrument};

use crate::{
    error::{Error, Result},
    types::Document,
};

/// Collection of entropy analysis algorithms
pub struct EntropyAlgorithms {
    /// Compression dictionary size
    dict_size: usize,
    /// Processing statistics
    stats: Arc<RwLock<AlgorithmStats>>,
}

/// Algorithm processing statistics
#[derive(Debug, Default)]
struct AlgorithmStats {
    /// Files processed
    files_processed: u64,
    /// Total bytes analyzed
    bytes_analyzed: u64,
    /// Average compression ratio
    average_compression: f64,
}

/// Analysis results from multiple algorithms
#[derive(Debug, Clone)]
pub struct AlgorithmResults {
    /// Compression ratio
    pub compression_ratio: f64,
    /// Chi-square test result
    pub chi_square: f64,
    /// Monte Carlo π estimation
    pub monte_carlo_pi: f64,
    /// Serial correlation coefficient
    pub serial_correlation: f64,
    /// Analysis duration
    pub duration: std::time::Duration,
}

impl EntropyAlgorithms {
    /// Creates new entropy algorithm collection
    pub fn new(dict_size: usize) -> Self {
        Self {
            dict_size,
            stats: Arc::new(RwLock::new(AlgorithmStats::default())),
        }
    }

    /// Analyzes document using multiple algorithms
    #[instrument(skip(self, document))]
    pub async fn analyze(&self, document: &Document) -> Result<AlgorithmResults> {
        let start = std::time::Instant::now();
        
        let content = tokio::fs::read(&document.path).await?;
        
        // Run various analyses
        let compression_ratio = self.calculate_compression_ratio(&content)?;
        let chi_square = self.calculate_chi_square(&content);
        let monte_carlo_pi = self.estimate_pi(&content);
        let serial_correlation = self.calculate_serial_correlation(&content);
        
        // Update statistics
        self.update_stats(compression_ratio, content.len());
        
        Ok(AlgorithmResults {
            compression_ratio,
            chi_square,
            monte_carlo_pi,
            serial_correlation,
            duration: start.elapsed(),
        })
    }

    /// Calculates compression ratio using LZ77
    fn calculate_compression_ratio(&self, data: &[u8]) -> Result<f64> {
        let mut dictionary = Vec::with_capacity(self.dict_size);
        let mut compressed = Vec::new();
        
        let mut pos = 0;
        while pos < data.len() {
            let (offset, length) = self.find_longest_match(data, pos, &dictionary);
            
            if length > 0 {
                // Add match reference
                compressed.extend_from_slice(&[1, offset as u8, length as u8]);
                pos += length;
            } else {
                // Add literal byte
                compressed.push(0);
                compressed.push(data[pos]);
                pos += 1;
            }
            
            // Update dictionary
            if dictionary.len() >= self.dict_size {
                dictionary.remove(0);
            }
            dictionary.extend_from_slice(&data[pos.saturating_sub(length)..pos]);
        }
        
        Ok(data.len() as f64 / compressed.len() as f64)
    }

    /// Finds longest matching sequence in dictionary
    fn find_longest_match(&self, data: &[u8], pos: usize, dict: &[u8]) -> (usize, usize) {
        let mut best_offset = 0;
        let mut best_length = 0;
        
        let look_ahead = data.len() - pos;
        if look_ahead == 0 {
            return (0, 0);
        }
        
        for (offset, window) in dict.windows(look_ahead).enumerate() {
            let mut length = 0;
            while length < window.len() && length < look_ahead && 
                  window[length] == data[pos + length] {
                length += 1;
            }
            
            if length > best_length {
                best_length = length;
                best_offset = offset;
            }
        }
        
        (best_offset, best_length)
    }

    /// Calculates chi-square statistic
    fn calculate_chi_square(&self, data: &[u8]) -> f64 {
        let mut frequencies = [0u64; 256];
        let expected = data.len() as f64 / 256.0;
        
        // Calculate frequencies
        for &byte in data {
            frequencies[byte as usize] += 1;
        }
        
        // Calculate chi-square
        let mut chi_square = 0.0;
        for &freq in &frequencies {
            let diff = freq as f64 - expected;
            chi_square += diff * diff / expected;
        }
        
        chi_square
    }

    /// Estimates π using Monte Carlo method
    fn estimate_pi(&self, data: &[u8]) -> f64 {
        let mut inside = 0u64;
        let mut total = 0u64;
        
        for chunk in data.chunks(2) {
            if chunk.len() < 2 {
                break;
            }
            
            let x = chunk[0] as f64 / 255.0;
            let y = chunk[1] as f64 / 255.0;
            
            if x * x + y * y <= 1.0 {
                inside += 1;
            }
            total += 1;
        }
        
        4.0 * inside as f64 / total as f64
    }

    /// Calculates serial correlation coefficient
    fn calculate_serial_correlation(&self, data: &[u8]) -> f64 {
        if data.len() < 2 {
            return 0.0;
        }
        
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;
        let mut sum_y2 = 0.0;
        
        for i in 0..data.len()-1 {
            let x = data[i] as f64;
            let y = data[i + 1] as f64;
            
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
            sum_y2 += y * y;
        }
        
        let n = (data.len() - 1) as f64;
        let numerator = n * sum_xy - sum_x * sum_y;
        let denominator = ((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y)).sqrt();
        
        if denominator == 0.0 {
            0.0
        } else {
            numerator / denominator
        }
    }

    /// Updates algorithm statistics
    fn update_stats(&self, compression_ratio: f64, bytes: usize) {
        let mut stats = self.stats.write();
        
        stats.files_processed += 1;
        stats.bytes_analyzed += bytes as u64;
        
        // Update running average
        let n = stats.files_processed as f64;
        stats.average_compression = 
            (stats.average_compression * (n - 1.0) + compression_ratio) / n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_compression_ratio() {
        let data = vec![0u8; 1024];
        let file = NamedTempFile::new().unwrap();
        tokio::fs::write(&file, &data).await.unwrap();
        
        let doc = Document::new(file.path().to_path_buf(), data.len() as u64);
        let analyzer = EntropyAlgorithms::new(256);
        
        let result = analyzer.analyze(&doc).await.unwrap();
        assert!(result.compression_ratio > 0.0);
    }

    #[tokio::test]
    async fn test_statistics() {
        let analyzer = EntropyAlgorithms::new(256);
        let data = vec![0u8; 1024];
        
        analyzer.update_stats(2.0, data.len());
        let stats = analyzer.stats.read();
        
        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.bytes_analyzed, 1024);
        assert!(stats.average_compression > 0.0);
    }

    #[test]
    fn test_monte_carlo_pi() {
        let analyzer = EntropyAlgorithms::new(256);
        let data = vec![0u8; 1024];
        
        let pi = analyzer.estimate_pi(&data);
        assert!(pi >= 0.0 && pi <= 4.0);
    }
  }
