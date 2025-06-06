//! Pattern matching implementation for PDF anti-forensics
//! Created: 2025-06-03 16:34:34 UTC
//! Author: kartik4091

use std::collections::HashMap;
use regex::Regex;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    error::{Error, Result},
    types::{Document, Object, ObjectId},
};

use super::{
    PatternType,
    PatternMatch,
    PatternMetadata,
    MatchLocation,
    MatchContext,
    ContextConfig,
    ValidationResult,
    CompilationResult,
};

/// Handles pattern matching operations
#[derive(Debug)]
pub struct PatternMatcher {
    /// Matching statistics
    pub stats: MatchStats,
    
    /// Pattern cache
    pattern_cache: HashMap<String, CompiledPattern>,
    
    /// Match cache
    match_cache: HashMap<ObjectId, Vec<PatternMatch>>,
    
    /// Active patterns
    active_patterns: Vec<PatternDefinition>,
}

/// Pattern matching statistics
#[derive(Debug, Clone, Default)]
pub struct MatchStats {
    /// Number of patterns matched
    pub patterns_matched: usize,
    
    /// Number of objects processed
    pub objects_processed: usize,
    
    /// Number of bytes scanned
    pub bytes_scanned: usize,
    
    /// Number of cache hits
    pub cache_hits: usize,
    
    /// Processing duration in milliseconds
    pub duration_ms: u64,
}

/// Pattern matcher configuration
#[derive(Debug, Clone)]
pub struct MatcherConfig {
    /// Match options
    pub options: MatchOptions,
    
    /// Context configuration
    pub context: ContextConfig,
    
    /// Processing settings
    pub processing: ProcessingSettings,
}

/// Match options
#[derive(Debug, Clone)]
pub struct MatchOptions {
    /// Case sensitive matching
    pub case_sensitive: bool,
    
    /// Multi-line matching
    pub multi_line: bool,
    
    /// Dot matches newline
    pub dot_matches_newline: bool,
    
    /// Match overlapping patterns
    pub match_overlapping: bool,
    
    /// Maximum matches per pattern
    pub max_matches: Option<usize>,
}

/// Processing settings
#[derive(Debug, Clone)]
pub struct ProcessingSettings {
    /// Enable parallel processing
    pub parallel: bool,
    
    /// Enable caching
    pub enable_cache: bool,
    
    /// Chunk size in bytes
    pub chunk_size: usize,
    
    /// Memory limit in bytes
    pub memory_limit: usize,
}

/// Pattern definition
#[derive(Debug, Clone)]
pub struct PatternDefinition {
    /// Pattern type
    pub pattern_type: PatternType,
    
    /// Pattern metadata
    pub metadata: PatternMetadata,
    
    /// Pattern options
    pub options: MatchOptions,
}

/// Compiled pattern
#[derive(Debug)]
pub struct CompiledPattern {
    /// Pattern definition
    pub definition: PatternDefinition,
    
    /// Compiled regex
    pub regex: Option<Regex>,
    
    /// Compiled binary
    pub binary: Option<Vec<u8>>,
    
    /// Compilation result
    pub compilation: CompilationResult,
}

impl Default for MatcherConfig {
    fn default() -> Self {
        Self {
            options: MatchOptions {
                case_sensitive: true,
                multi_line: false,
                dot_matches_newline: false,
                match_overlapping: false,
                max_matches: None,
            },
            context: ContextConfig::default(),
            processing: ProcessingSettings {
                parallel: true,
                enable_cache: true,
                chunk_size: 65536,
                memory_limit: 1073741824, // 1GB
            },
        }
    }
}

impl PatternMatcher {
    /// Create new pattern matcher instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            stats: MatchStats::default(),
            pattern_cache: HashMap::new(),
            match_cache: HashMap::new(),
            active_patterns: Vec::new(),
        })
    }
    
    /// Match patterns in document
    #[instrument(skip(self, document, config))]
    pub fn match_patterns(&mut self, document: &Document, config: &MatcherConfig) -> Result<HashMap<ObjectId, Vec<PatternMatch>>> {
        let start_time = std::time::Instant::now();
        info!("Starting pattern matching");
        
        let mut matches = HashMap::new();
        
        // Process each object
        for (id, object) in &document.structure.objects {
            if let Some(object_matches) = self.match_object(*id, object, config)? {
                matches.insert(*id, object_matches);
            }
        }
        
        // Update statistics
        self.stats.duration_ms = start_time.elapsed().as_millis() as u64;
        
        info!("Pattern matching completed");
        Ok(matches)
    }
    
    /// Match patterns in object
    fn match_object(&mut self, id: ObjectId, object: &Object, config: &MatcherConfig) -> Result<Option<Vec<PatternMatch>>> {
        // Check cache if enabled
        if config.processing.enable_cache {
            if let Some(cached) = self.check_cache(id)? {
                self.stats.cache_hits += 1;
                return Ok(Some(cached));
            }
        }
        
        let data = object.to_bytes()?;
        if data.is_empty() {
            return Ok(None);
        }
        
        self.stats.objects_processed += 1;
        self.stats.bytes_scanned += data.len();
        
        let mut matches = Vec::new();
        
        // Match each active pattern
        for pattern in &self.active_patterns {
            let pattern_matches = self.match_pattern(&data, pattern, config)?;
            matches.extend(pattern_matches);
            self.stats.patterns_matched += pattern_matches.len();
        }
        
        // Update cache if enabled
        if config.processing.enable_cache {
            self.update_cache(id, &matches)?;
        }
        
        Ok(Some(matches))
    }
    
    /// Match individual pattern
    fn match_pattern(&self, data: &[u8], pattern: &PatternDefinition, config: &MatcherConfig) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();
        
        match &pattern.pattern_type {
            PatternType::Regex(regex) => {
                matches.extend(self.match_regex(data, regex, pattern, config)?);
            }
            PatternType::Binary(binary) => {
                matches.extend(self.match_binary(data, binary, pattern, config)?);
            }
            PatternType::Hex(hex) => {
                matches.extend(self.match_hex(data, hex, pattern, config)?);
            }
            PatternType::ByteSequence(seq) => {
                matches.extend(self.match_byte_sequence(data, seq, pattern, config)?);
            }
            PatternType::Custom(_) => {}
        }
        
        Ok(matches)
    }
    
    /// Match regex pattern
    fn match_regex(&self, data: &[u8], regex: &str, pattern: &PatternDefinition, config: &MatcherConfig) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();
        
        if let Ok(text) = String::from_utf8(data.to_vec()) {
            let regex = Regex::new(regex)
                .map_err(|e| Error::PatternError(format!("Invalid regex pattern: {}", e)))?;
            
            for cap in regex.captures_iter(&text) {
                if let Some(m) = cap.get(0) {
                    matches.push(PatternMatch {
                        pattern_type: pattern.pattern_type.clone(),
                        metadata: pattern.metadata.clone(),
                        location: MatchLocation {
                            object_id: ObjectId { number: 0, generation: 0 },
                            start: m.start(),
                            end: m.end(),
                            context: String::new(),
                        },
                        confidence: 1.0,
                        context: self.extract_context(data, m.start(), m.end(), &config.context)?,
                    });
                    
                    if let Some(max) = pattern.options.max_matches {
                        if matches.len() >= max {
                            break;
                        }
                    }
                }
            }
        }
        
        Ok(matches)
    }
    
    /// Match binary pattern
    fn match_binary(&self, data: &[u8], binary: &[u8], pattern: &PatternDefinition, config: &MatcherConfig) -> Result<Vec<PatternMatch>> {
        let mut matches = Vec::new();
        let mut start = 0;
        
        while let Some(pos) = data[start..].windows(binary.len()).position(|window| window == binary) {
            let match_start = start + pos;
            let match_end = match_start + binary.len();
            
            matches.push(PatternMatch {
                pattern_type: pattern.pattern_type.clone(),
                metadata: pattern.metadata.clone(),
                location: MatchLocation {
                    object_id: ObjectId { number: 0, generation: 0 },
                    start: match_start,
                    end: match_end,
                    context: String::new(),
                },
                confidence: 1.0,
                context: self.extract_context(data, match_start, match_end, &config.context)?,
            });
            
            if let Some(max) = pattern.options.max_matches {
                if matches.len() >= max {
                    break;
                }
            }
            
            start = if pattern.options.match_overlapping {
                match_start + 1
            } else {
                match_end
            };
        }
        
        Ok(matches)
    }
    
    /// Match hex pattern
    fn match_hex(&self, data: &[u8], hex: &str, pattern: &PatternDefinition, config: &MatcherConfig) -> Result<Vec<PatternMatch>> {
        let binary = hex::decode(hex)
            .map_err(|e| Error::PatternError(format!("Invalid hex pattern: {}", e)))?;
        self.match_binary(data, &binary, pattern, config)
    }
    
    /// Match byte sequence pattern
    fn match_byte_sequence(&self, data: &[u8], seq: &[u8], pattern: &PatternDefinition, config: &MatcherConfig) -> Result<Vec<PatternMatch>> {
        self.match_binary(data, seq, pattern, config)
    }
    
    /// Extract match context
    fn extract_context(&self, data: &[u8], start: usize, end: usize, config: &ContextConfig) -> Result<MatchContext> {
        let before_start = if start >= config.before_size {
            start - config.before_size
        } else {
            0
        };
        
        let after_end = std::cmp::min(end + config.after_size, data.len());
        
        Ok(MatchContext {
            before: data[before_start..start].to_vec(),
            content: data[start..end].to_vec(),
            after: data[end..after_end].to_vec(),
            metadata: if config.include_metadata {
                let mut metadata = HashMap::new();
                metadata.insert("before_size".to_string(), (start - before_start).to_string());
                metadata.insert("after_size".to_string(), (after_end - end).to_string());
                metadata
            } else {
                HashMap::new()
            },
        })
    }
    
    /// Add pattern
    pub fn add_pattern(&mut self, pattern: PatternDefinition) -> Result<()> {
        self.active_patterns.push(pattern);
        Ok(())
    }
    
    /// Remove pattern
    pub fn remove_pattern(&mut self, pattern_id: &str) -> Result<()> {
        self.active_patterns.retain(|p| p.metadata.id != pattern_id);
        Ok(())
    }
    
    /// Check match cache
    fn check_cache(&self, id: ObjectId) -> Result<Option<Vec<PatternMatch>>> {
        Ok(self.match_cache.get(&id).cloned())
    }
    
    /// Update match cache
    fn update_cache(&mut self, id: ObjectId, matches: &[PatternMatch]) -> Result<()> {
        self.match_cache.insert(id, matches.to_vec());
        Ok(())
    }
    
    /// Reset matcher state
    pub fn reset(&mut self) {
        self.stats = MatchStats::default();
        self.pattern_cache.clear();
        self.match_cache.clear();
        self.active_patterns.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn setup_test_matcher() -> PatternMatcher {
        PatternMatcher::new().unwrap()
    }
    
    #[test]
    fn test_matcher_initialization() {
        let matcher = setup_test_matcher();
        assert!(matcher.active_patterns.is_empty());
    }
    
    #[test]
    fn test_regex_matching() {
        let mut matcher = setup_test_matcher();
        let config = MatcherConfig::default();
        
        let pattern = PatternDefinition {
            pattern_type: PatternType::Regex(r"\d+".to_string()),
            metadata: PatternMetadata {
                id: "test".to_string(),
                name: "Test Pattern".to_string(),
                description: "Test Pattern".to_string(),
                category: "Test".to_string(),
                severity: super::super::Severity::Low,
                tags: vec![],
                additional: HashMap::new(),
            },
            options: MatchOptions {
                case_sensitive: true,
                multi_line: false,
                dot_matches_newline: false,
                match_overlapping: false,
                max_matches: None,
            },
        };
        
        matcher.add_pattern(pattern).unwrap();
        
        let data = b"123 abc 456";
        let matches = matcher.match_pattern(data, &matcher.active_patterns[0], &config).unwrap();
        
        assert_eq!(matches.len(), 2);
    }
    
    #[test]
    fn test_binary_matching() {
        let mut matcher = setup_test_matcher();
        let config = MatcherConfig::default();
        
        let pattern = PatternDefinition {
            pattern_type: PatternType::Binary(vec![1, 2, 3]),
            metadata: PatternMetadata {
                id: "test".to_string(),
                name: "Test Pattern".to_string(),
                description: "Test Pattern".to_string(),
                category: "Test".to_string(),
                severity: super::super::Severity::Low,
                tags: vec![],
                additional: HashMap::new(),
            },
            options: MatchOptions {
                case_sensitive: true,
                multi_line: false,
                dot_matches_newline: false,
                match_overlapping: false,
                max_matches: None,
            },
        };
        
        matcher.add_pattern(pattern).unwrap();
        
        let data = vec![0, 1, 2, 3, 4, 1, 2, 3, 5];
        let matches = matcher.match_pattern(&data, &matcher.active_patterns[0], &config).unwrap();
        
        assert_eq!(matches.len(), 2);
    }
    
    #[test]
    fn test_context_extraction() {
        let matcher = setup_test_matcher();
        let config = ContextConfig {
            before_size: 2,
            after_size: 2,
            include_metadata: true,
        };
        
        let data = b"12345";
        let context = matcher.extract_context(data, 2, 3, &config).unwrap();
        
        assert_eq!(context.before, b"12");
        assert_eq!(context.content, b"3");
        assert_eq!(context.after, b"45");
    }
    
    #[test]
    fn test_pattern_management() {
        let mut matcher = setup_test_matcher();
        
        let pattern = PatternDefinition {
            pattern_type: PatternType::Regex(r"\d+".to_string()),
            metadata: PatternMetadata {
                id: "test".to_string(),
                name: "Test Pattern".to_string(),
                description: "Test Pattern".to_string(),
                category: "Test".to_string(),
                severity: super::super::Severity::Low,
                tags: vec![],
                additional: HashMap::new(),
            },
            options: MatchOptions {
                case_sensitive: true,
                multi_line: false,
                dot_matches_newline: false,
                match_overlapping: false,
                max_matches: None,
            },
        };
        
        matcher.add_pattern(pattern).unwrap();
        assert_eq!(matcher.active_patterns.len(), 1);
        
        matcher.remove_pattern("test").unwrap();
        assert!(matcher.active_patterns.is_empty());
    }
    
    #[test]
    fn test_matcher_reset() {
        let mut matcher = setup_test_matcher();
        
        matcher.stats.patterns_matched = 1;
        matcher.match_cache.insert(ObjectId { number: 1, generation: 0 }, Vec::new());
        
        matcher.reset();
        
        assert_eq!(matcher.stats.patterns_matched, 0);
        assert!(matcher.match_cache.is_empty());
    }
}
