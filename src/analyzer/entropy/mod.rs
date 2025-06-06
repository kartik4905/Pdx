//! Entropy analysis for PDF forensics
//! Author: kartik4091
//! Created: 2025-06-05

use crate::error::Result;
use crate::types::Document;
use std::collections::HashMap;

/// Entropy calculator for PDF content analysis
pub struct EntropyAnalyzer {
    threshold: f64,
    block_size: usize,
}

impl EntropyAnalyzer {
    pub fn new() -> Self {
        Self {
            threshold: 7.5,
            block_size: 1024,
        }
    }

    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            threshold,
            block_size: 1024,
        }
    }

    pub async fn analyze_document(&self, document: &Document) -> Result<EntropyReport> {
        let mut report = EntropyReport::new();
        
        // Analyze entropy of document content
        for (object_id, object) in &document.content {
            let entropy = self.calculate_object_entropy(object)?;
            report.add_measurement(object_id.clone(), entropy);
        }
        
        Ok(report)
    }

    pub fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequencies = HashMap::new();
        for &byte in data {
            *frequencies.entry(byte).or_insert(0) += 1;
        }

        let data_len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in frequencies.values() {
            let probability = count as f64 / data_len;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    fn calculate_object_entropy(&self, object: &lopdf::Object) -> Result<f64> {
        // Extract bytes from PDF object and calculate entropy
        let bytes = self.extract_object_bytes(object);
        Ok(self.calculate_entropy(&bytes))
    }

    fn extract_object_bytes(&self, object: &lopdf::Object) -> Vec<u8> {
        // Implementation to extract bytes from PDF object
        match object {
            lopdf::Object::String(bytes, _) => bytes.clone(),
            lopdf::Object::Stream(stream) => stream.content.clone(),
            _ => Vec::new(),
        }
    }

    pub fn is_suspicious_entropy(&self, entropy: f64) -> bool {
        entropy > self.threshold
    }
}

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct EntropyReport {
    pub measurements: Vec<EntropyMeasurement>,
    pub average_entropy: f64,
    pub max_entropy: f64,
    pub suspicious_objects: Vec<lopdf::ObjectId>,
}

impl EntropyReport {
    pub fn new() -> Self {
        Self {
            measurements: Vec::new(),
            average_entropy: 0.0,
            max_entropy: 0.0,
            suspicious_objects: Vec::new(),
        }
    }

    pub fn add_measurement(&mut self, object_id: lopdf::ObjectId, entropy: f64) {
        self.measurements.push(EntropyMeasurement {
            object_id: object_id.clone(),
            entropy,
        });

        if entropy > self.max_entropy {
            self.max_entropy = entropy;
        }

        if entropy > 7.5 {
            self.suspicious_objects.push(object_id);
        }

        self.recalculate_average();
    }

    fn recalculate_average(&mut self) {
        if self.measurements.is_empty() {
            self.average_entropy = 0.0;
        } else {
            let sum: f64 = self.measurements.iter().map(|m| m.entropy).sum();
            self.average_entropy = sum / self.measurements.len() as f64;
        }
    }
}

#[derive(Debug, Clone)]
pub struct EntropyMeasurement {
    pub object_id: lopdf::ObjectId,
    pub entropy: f64,
}