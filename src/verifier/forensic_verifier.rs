//! Forensic Verifier
//! Performs trace-based signature checks, metadata comparison, and anomaly correlation
//! Author: kartik4091

use crate::{
    error::{Error, Result},
    types::{Document, Object, ModificationType},
    utils::{Logger, Metrics},
    utils::logger::LogLevel,
};

use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, warn};

/// Result of forensic verification
#[derive(Debug, Clone)]
pub struct ForensicVerificationResult {
    pub has_signature: bool,
    pub embedded_signers: HashSet<String>,
    pub modification_mismatch: bool,
    pub metadata_integrity_ok: bool,
    pub anomalies: Vec<String>,
}

/// Performs trace and signature-based forensics
pub struct ForensicVerifier {
    logger: Arc<Logger>,
    metrics: Arc<Metrics>,
}

impl ForensicVerifier {
    pub fn new(logger: Arc<Logger>, metrics: Arc<Metrics>) -> Self {
        Self { logger, metrics }
    }

    pub async fn verify(&self, document: &Document) -> Result<ForensicVerificationResult> {
        let mut anomalies = Vec::new();
        let mut embedded_signers = HashSet::new();
        let mut has_signature = false;
        let start = std::time::Instant::now();

        for (id, obj) in &document.structure.objects {
            if let Object::Dictionary(dict) = obj {
                if let Some(Object::Name(subtype)) = dict.get(b"Type") {
                    if subtype == b"Sig" || subtype == b"DocTimeStamp" {
                        has_signature = true;

                        if let Some(Object::String(name)) = dict.get(b"Name") {
                            let signer = String::from_utf8_lossy(name);
                            embedded_signers.insert(signer.to_string());
                        }

                        if let Some(Object::Array(byte_range)) = dict.get(b"ByteRange") {
                            if byte_range.len() == 4 {
                                if let (Some(Object::Integer(start)), Some(Object::Integer(length))) =
                                    (byte_range.get(0), byte_range.get(1))
                                {
                                    if *start > 0 || *length == 0 {
                                        anomalies.push(format!(
                                            "ByteRange mismatch in signature {:?}",
                                            id
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut metadata_integrity_ok = true;
        let xmp_present = document
            .structure
            .objects
            .values()
            .any(|obj| matches!(obj, Object::Stream(stream)
                if stream.dict.get(b"Subtype") == Some(&Object::Name(b"XML".to_vec())))
            );

        if xmp_present && !has_signature {
            metadata_integrity_ok = false;
            anomalies.push("XMP metadata exists but no digital signature found".into());
        }

        let modification_mismatch = document
            .modifications
            .iter()
            .any(|m| matches!(m, ModificationType::Inserted | ModificationType::Removed));

        if has_signature && modification_mismatch {
            anomalies.push("Signed document has unexpected insert/remove modifications".into());
        }

        let result = ForensicVerificationResult {
            has_signature,
            embedded_signers,
            modification_mismatch,
            metadata_integrity_ok,
            anomalies,
        };

        self.logger
            .log(
                LogLevel::Info,
                "Forensic verification completed",
                module_path!(),
                file!(),
                line!(),
            )
            .await?;

        self.metrics
            .record_operation("forensic_verification", start.elapsed())
            .await;

        Ok(result)
    }
}
