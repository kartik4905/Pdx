//! Security Verifier
//! Verifies encryption status, crypt filters, permissions, and signatures
//! Author: kartik4091

use crate::{
    types::{Document, Object},
    error::{Error, Result},
    utils::{Logger, Metrics},
    utils::logger::LogLevel,
};

use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Represents the outcome of a security verification pass
#[derive(Debug, Clone)]
pub struct SecurityVerificationResult {
    pub encrypted: bool,
    pub key_length: Option<u32>,
    pub algorithm: Option<String>,
    pub permissions: Option<HashMap<String, bool>>,
    pub has_signature: bool,
    pub anomalies: Vec<String>,
}

/// PDF encryption verifier
pub struct SecurityVerifier {
    logger: Arc<Logger>,
    metrics: Arc<Metrics>,
}

impl SecurityVerifier {
    pub fn new(logger: Arc<Logger>, metrics: Arc<Metrics>) -> Self {
        Self { logger, metrics }
    }

    pub async fn verify(&self, document: &Document) -> Result<SecurityVerificationResult> {
        let mut anomalies = Vec::new();
        let start = std::time::Instant::now();

        let trailer = &document.structure.trailer;
        let mut result = SecurityVerificationResult {
            encrypted: false,
            key_length: None,
            algorithm: None,
            permissions: None,
            has_signature: false,
            anomalies: Vec::new(),
        };

        // Detect encryption entry
        if let Some(Object::Reference(enc_ref)) = trailer.get(b"Encrypt") {
            result.encrypted = true;
            debug!("Encrypt reference found: {:?}", enc_ref);

            if let Some(Object::Dictionary(dict)) = document.structure.objects.get(enc_ref) {
                if let Some(Object::Integer(len)) = dict.get(b"Length") {
                    result.key_length = Some(*len as u32);
                }

                if let Some(Object::Name(filter)) = dict.get(b"Filter") {
                    result.algorithm = Some(String::from_utf8_lossy(filter).to_string());
                }

                // Check optional crypt filter
                if let Some(Object::Dictionary(cf)) = dict.get(b"CF") {
                    for (k, v) in cf {
                        if let Object::Dictionary(cf_dict) = v {
                            if let Some(Object::Name(cfm)) = cf_dict.get(b"CFM") {
                                let cfm_str = String::from_utf8_lossy(cfm);
                                debug!("Crypt Filter {} uses {}", String::from_utf8_lossy(k), cfm_str);
                            }
                        }
                    }
                }

                if let Some(Object::Integer(perm_bits)) = dict.get(b"P") {
                    result.permissions = Some(Self::parse_permission_bits(*perm_bits));
                }
            } else {
                anomalies.push("Invalid Encrypt reference or missing dictionary".into());
                warn!("Encrypt reference points to invalid or missing dictionary");
            }
        }

        // Look for signature objects
        for (id, obj) in &document.structure.objects {
            if let Object::Dictionary(dict) = obj {
                if let Some(Object::Name(subtype)) = dict.get(b"Type") {
                    if subtype == b"Sig" || subtype == b"DocTimeStamp" {
                        result.has_signature = true;
                        debug!("Found signature object: {:?}", id);
                    }
                }
            }
        }

        result.anomalies = anomalies;

        self.logger
            .log(
                LogLevel::Info,
                "Security verification completed",
                module_path!(),
                file!(),
                line!(),
            )
            .await?;

        self.metrics
            .record_operation("security_verification", start.elapsed())
            .await;

        Ok(result)
    }

    fn parse_permission_bits(bits: i32) -> HashMap<String, bool> {
        let mut perms = HashMap::new();
        perms.insert("print".to_string(), bits & 0b0000_0100 != 0);
        perms.insert("modify".to_string(), bits & 0b0000_1000 != 0);
        perms.insert("extract".to_string(), bits & 0b0001_0000 != 0);
        perms.insert("annotate".to_string(), bits & 0b0010_0000 != 0);
        perms.insert("form_fill".to_string(), bits & 0b0000_1000_0000 != 0);
        perms
    }
}
