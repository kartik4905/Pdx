//! Binary Sanitization Module
//! Performs low-level binary sanitization on raw PDF buffers.
//! Author: kartik4091
//! Created: 2025-06-03 09:11:32 UTC

use std::ops::Range;
use regex::bytes::Regex;
use crate::error::{CleanerError, Result};

#[derive(Debug, Clone)]
pub struct BinarySanitizer {
    /// Patterns to remove
    pub patterns: Vec<SanitizationPattern>,
    /// EOF removal enforcement
    pub remove_extra_eof: bool,
}

#[derive(Debug, Clone)]
pub struct SanitizationPattern {
    /// Regex pattern to match binary regions
    pub regex: Regex,
    /// Optional replacement value
    pub replacement: Option<Vec<u8>>,
}

impl BinarySanitizer {
    pub fn new(remove_extra_eof: bool) -> Self {
        Self {
            patterns: vec![
                SanitizationPattern {
                    regex: Regex::new(r"(?i)%PDF-[0-9]\.[0-9].*?")
                        .expect("Invalid regex for header removal"),
                    replacement: Some(b"%PDF-cleaned\n".to_vec()),
                },
                SanitizationPattern {
                    regex: Regex::new(r"(?s)%%EOF(?!.*%%EOF)").unwrap(),
                    replacement: None, // Keep final EOF only
                },
                SanitizationPattern {
                    regex: Regex::new(r"(?i)Creator.*?\n").unwrap(),
                    replacement: Some(b"".to_vec()),
                },
            ],
            remove_extra_eof,
        }
    }

    /// Performs binary sanitization in-place
    pub fn sanitize(&self, buffer: &mut Vec<u8>) -> Result<()> {
        let mut sanitized = buffer.clone();

        for pattern in &self.patterns {
            sanitized = self.apply_pattern(&sanitized, pattern)?;
        }

        if self.remove_extra_eof {
            sanitized = self.enforce_single_eof(&sanitized)?;
        }

        *buffer = sanitized;
        Ok(())
    }

    /// Applies a single sanitization pattern
    fn apply_pattern(&self, data: &[u8], pattern: &SanitizationPattern) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(data.len());
        let mut last_end = 0;

        for m in pattern.regex.find_iter(data) {
            result.extend_from_slice(&data[last_end..m.start()]);
            if let Some(repl) = &pattern.replacement {
                result.extend_from_slice(repl);
            }
            last_end = m.end();
        }

        result.extend_from_slice(&data[last_end..]);
        Ok(result)
    }

    /// Ensures only one EOF marker exists
    fn enforce_single_eof(&self, data: &[u8]) -> Result<Vec<u8>> {
        let re = Regex::new(r"(?i)%%EOF").unwrap();
        let matches: Vec<Range<usize>> = re.find_iter(data).map(|m| m.range()).collect();

        if matches.len() <= 1 {
            return Ok(data.to_vec());
        }

        let mut cleaned = Vec::with_capacity(data.len());
        cleaned.extend_from_slice(&data[..matches[0].start]);
        cleaned.extend_from_slice(b"%%EOF\n");
        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_sanitization() {
        let mut buffer = b"%PDF-1.7\nCreator: Adobe\nRandom%%EOF%%EOF".to_vec();
        let sanitizer = BinarySanitizer::new(true);
        sanitizer.sanitize(&mut buffer).unwrap();
        assert!(buffer.ends_with(b"%%EOF\n"));
        assert!(!buffer.contains(&b"Adobe"[..]));
    }
}
