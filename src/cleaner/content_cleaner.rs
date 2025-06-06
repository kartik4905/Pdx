//! Content Cleaner Implementation
//! Author: kartik4091
//! Created: 2025-06-03 09:06:55 UTC

use crate::types::{Document, Object, ObjectId, Stream};
use crate::error::{Result, CleanerError};
use crate::utils::entropy::calculate_entropy;
use tracing::{debug, warn, info, instrument};

/// Cleans content streams and objects containing embedded scripts, high entropy,
/// or known obfuscation techniques.
pub struct ContentCleaner;

impl ContentCleaner {
    /// Creates a new instance
    pub fn new() -> Self {
        Self
    }

    /// Performs content-level stream sanitization
    #[instrument(skip(self, document))]
    pub async fn clean(&self, document: &mut Document) -> Result<usize> {
        let mut cleaned = 0;

        for (id, obj) in &mut document.structure.objects {
            match obj {
                Object::Stream(ref mut stream) => {
                    if self.should_clean_stream(stream) {
                        debug!("Cleaning stream object {:?} (entropy or suspicious content)", id);
                        stream.data.clear();
                        cleaned += 1;
                    }
                }
                Object::Dictionary(ref mut dict) => {
                    if self.is_malicious_dict(dict) {
                        debug!("Resetting malicious dictionary fields in {:?}", id);
                        dict.remove(b"JavaScript");
                        dict.remove(b"JS");
                        dict.remove(b"Launch");
                        cleaned += 1;
                    }
                }
                _ => {}
            }
        }

        // Additional pass: clean suspicious /Contents from pages
        for (id, obj) in &mut document.structure.objects {
            if let Object::Dictionary(dict) = obj {
                if dict.get(b"Type").map_or(false, |v| matches!(v, Object::Name(name) if name == b"Page")) {
                    if dict.contains_key(b"Contents") {
                        debug!("Removing /Contents from page object {:?}", id);
                        dict.remove(b"Contents");
                        cleaned += 1;
                    }
                }
            }
        }

        info!("ContentCleaner: Total cleaned objects: {}", cleaned);
        Ok(cleaned)
    }

    /// Determines if a stream is suspicious based on entropy or obfuscation
    fn should_clean_stream(&self, stream: &Stream) -> bool {
        let entropy = calculate_entropy(&stream.data);
        if entropy > 7.9 {
            warn!("High entropy stream detected: {:.2}", entropy);
            return true;
        }

        let suspicious_keywords = [
            b"/JavaScript", b"/JS", b"/Launch", b"app.alert", b"this.exportDataObject",
            b"submitForm", b"this.saveAs", b"getAnnots", b"xfa.datasets",
        ];

        for keyword in &suspicious_keywords {
            if stream.data.windows(keyword.len()).any(|w| w == *keyword) {
                warn!("Suspicious keyword in stream: {:?}", String::from_utf8_lossy(keyword));
                return true;
            }
        }

        // Optional: Check suspicious filter chains (e.g., double encoding)
        if let Some(Object::Array(filters)) = stream.dict.get(b"Filter") {
            let count = filters.iter().filter(|f| matches!(f, Object::Name(_))).count();
            if count > 1 {
                warn!("Multi-layered filters detected in stream");
                return true;
            }
        }

        false
    }

    /// Detects embedded JS or scripting in dictionaries
    fn is_malicious_dict(&self, dict: &mut std::collections::HashMap<Vec<u8>, Object>) -> bool {
        dict.contains_key(b"JavaScript") || dict.contains_key(b"JS") || dict.contains_key(b"Launch")
    }
}
