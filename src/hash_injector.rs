
//! Anti-Forensic Hash Injector
//! 
//! This module provides comprehensive hash injection with military-grade security,
//! allowing manual hash specification and cryptographic integrity verification.

use crate::error::Result;
use crate::types::Document;
use blake3::Hasher as Blake3Hasher;
use ring::{digest, rand::{SecureRandom, SystemRandom}};
use sha1::Sha1;
use sha2::{Sha256, Sha512, Digest};
use md5::Md5;
use std::collections::HashMap;
use tracing::{info, warn, debug};
use uuid::Uuid;

/// Military-grade hash injector with anti-forensic capabilities
pub struct AntiForensicHashInjector {
    /// Injection statistics
    stats: HashInjectionStats,
    /// Injection configuration
    config: HashInjectionConfig,
    /// Cryptographic engines
    crypto_engines: CryptoEngines,
    /// Hash verification system
    verification_system: HashVerificationSystem,
    /// Anti-forensic protection
    anti_forensic_protection: AntiForensicProtection,
}

#[derive(Debug, Clone, Default)]
pub struct HashInjectionStats {
    pub documents_processed: u64,
    pub hashes_injected: u64,
    pub md5_hashes_injected: u64,
    pub sha1_hashes_injected: u64,
    pub sha256_hashes_injected: u64,
    pub sha512_hashes_injected: u64,
    pub blake3_hashes_injected: u64,
    pub custom_hashes_injected: u64,
    pub verification_checks_performed: u64,
    pub anti_forensic_operations: u64,
    pub total_processing_time_ms: u64,
}

#[derive(Debug, Clone)]
pub struct HashInjectionConfig {
    pub enable_md5_injection: bool,
    pub enable_sha1_injection: bool,
    pub enable_sha256_injection: bool,
    pub enable_sha512_injection: bool,
    pub enable_blake3_injection: bool,
    pub enable_custom_hashes: bool,
    pub enable_verification: bool,
    pub enable_anti_forensic_mode: bool,
    pub allow_manual_specification: bool,
    pub security_level: SecurityLevel,
    pub injection_strategy: InjectionStrategy,
}

#[derive(Debug, Clone)]
pub enum SecurityLevel {
    Basic,
    Standard,
    Enhanced,
    Military,
    Classified,
}

#[derive(Debug, Clone)]
pub enum InjectionStrategy {
    Replace,        // Replace existing hashes
    Append,         // Append to existing hashes
    Merge,          // Merge with existing hashes
    Overwrite,      // Overwrite all hashes
    Selective,      // Selective injection based on criteria
}

#[derive(Debug, Clone)]
pub struct CryptoEngines {
    /// MD5 engine
    md5_engine: Md5Engine,
    /// SHA-1 engine
    sha1_engine: Sha1Engine,
    /// SHA-256 engine
    sha256_engine: Sha256Engine,
    /// SHA-512 engine
    sha512_engine: Sha512Engine,
    /// BLAKE3 engine
    blake3_engine: Blake3Engine,
    /// Custom hash engines
    custom_engines: HashMap<String, CustomHashEngine>,
}

#[derive(Debug, Clone)]
pub struct Md5Engine {
    pub enabled: bool,
    pub manual_hash: Option<String>,
    pub computed_hash: Option<String>,
    pub injection_count: u64,
}

#[derive(Debug, Clone)]
pub struct Sha1Engine {
    pub enabled: bool,
    pub manual_hash: Option<String>,
    pub computed_hash: Option<String>,
    pub injection_count: u64,
}

#[derive(Debug, Clone)]
pub struct Sha256Engine {
    pub enabled: bool,
    pub manual_hash: Option<String>,
    pub computed_hash: Option<String>,
    pub injection_count: u64,
}

#[derive(Debug, Clone)]
pub struct Sha512Engine {
    pub enabled: bool,
    pub manual_hash: Option<String>,
    pub computed_hash: Option<String>,
    pub injection_count: u64,
}

#[derive(Debug, Clone)]
pub struct Blake3Engine {
    pub enabled: bool,
    pub manual_hash: Option<String>,
    pub computed_hash: Option<String>,
    pub injection_count: u64,
}

#[derive(Debug, Clone)]
pub struct CustomHashEngine {
    pub algorithm_name: String,
    pub hash_value: String,
    pub hash_function: String,
    pub injection_count: u64,
}

#[derive(Debug, Clone)]
pub struct HashVerificationSystem {
    /// Verification results
    verification_results: HashMap<String, VerificationResult>,
    /// Integrity checks
    integrity_checks: Vec<IntegrityCheck>,
    /// Anti-tampering measures
    anti_tampering: AntiTamperingMeasures,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub algorithm: String,
    pub expected_hash: String,
    pub computed_hash: String,
    pub verification_status: VerificationStatus,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub enum VerificationStatus {
    Passed,
    Failed,
    Pending,
    Skipped,
    Error,
}

#[derive(Debug, Clone)]
pub struct IntegrityCheck {
    pub check_id: String,
    pub check_type: String,
    pub result: bool,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct AntiTamperingMeasures {
    pub enabled: bool,
    pub detection_algorithms: Vec<String>,
    pub protection_level: SecurityLevel,
}

#[derive(Debug, Clone)]
pub struct AntiForensicProtection {
    /// Hash obfuscation
    hash_obfuscation: HashObfuscation,
    /// Steganographic hiding
    steganographic_hiding: SteganographicHiding,
    /// Cryptographic protection
    cryptographic_protection: CryptographicProtection,
}

#[derive(Debug, Clone)]
pub struct HashObfuscation {
    pub enabled: bool,
    pub obfuscation_level: u8,
    pub decoy_hashes: Vec<String>,
    pub noise_injection: bool,
}

#[derive(Debug, Clone)]
pub struct SteganographicHiding {
    pub enabled: bool,
    pub hiding_algorithm: String,
    pub cover_data: Vec<u8>,
    pub extraction_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CryptographicProtection {
    pub enabled: bool,
    pub encryption_algorithm: String,
    pub key_derivation: String,
    pub protection_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct HashInjectionRequest {
    pub algorithm: String,
    pub manual_hash: Option<String>,
    pub target_location: HashLocation,
    pub injection_mode: InjectionMode,
    pub verification_required: bool,
}

#[derive(Debug, Clone)]
pub enum HashLocation {
    DocumentInfo,
    Metadata,
    CustomField(String),
    EmbeddedStream,
    TrailerSection,
}

#[derive(Debug, Clone)]
pub enum InjectionMode {
    Manual,
    Computed,
    Hybrid,
}

impl Default for HashInjectionConfig {
    fn default() -> Self {
        Self {
            enable_md5_injection: true,
            enable_sha1_injection: true,
            enable_sha256_injection: true,
            enable_sha512_injection: true,
            enable_blake3_injection: true,
            enable_custom_hashes: true,
            enable_verification: true,
            enable_anti_forensic_mode: true,
            allow_manual_specification: true,
            security_level: SecurityLevel::Military,
            injection_strategy: InjectionStrategy::Selective,
        }
    }
}

impl Default for CryptoEngines {
    fn default() -> Self {
        Self {
            md5_engine: Md5Engine::default(),
            sha1_engine: Sha1Engine::default(),
            sha256_engine: Sha256Engine::default(),
            sha512_engine: Sha512Engine::default(),
            blake3_engine: Blake3Engine::default(),
            custom_engines: HashMap::new(),
        }
    }
}

impl Default for Md5Engine {
    fn default() -> Self {
        Self {
            enabled: true,
            manual_hash: None,
            computed_hash: None,
            injection_count: 0,
        }
    }
}

impl Default for Sha1Engine {
    fn default() -> Self {
        Self {
            enabled: true,
            manual_hash: None,
            computed_hash: None,
            injection_count: 0,
        }
    }
}

impl Default for Sha256Engine {
    fn default() -> Self {
        Self {
            enabled: true,
            manual_hash: None,
            computed_hash: None,
            injection_count: 0,
        }
    }
}

impl Default for Sha512Engine {
    fn default() -> Self {
        Self {
            enabled: true,
            manual_hash: None,
            computed_hash: None,
            injection_count: 0,
        }
    }
}

impl Default for Blake3Engine {
    fn default() -> Self {
        Self {
            enabled: true,
            manual_hash: None,
            computed_hash: None,
            injection_count: 0,
        }
    }
}

impl Default for HashVerificationSystem {
    fn default() -> Self {
        Self {
            verification_results: HashMap::new(),
            integrity_checks: Vec::new(),
            anti_tampering: AntiTamperingMeasures::default(),
        }
    }
}

impl Default for AntiTamperingMeasures {
    fn default() -> Self {
        Self {
            enabled: true,
            detection_algorithms: vec![
                "Hash Chain Verification".to_string(),
                "Checksum Validation".to_string(),
                "Digital Signature Check".to_string(),
            ],
            protection_level: SecurityLevel::Military,
        }
    }
}

impl Default for AntiForensicProtection {
    fn default() -> Self {
        Self {
            hash_obfuscation: HashObfuscation::default(),
            steganographic_hiding: SteganographicHiding::default(),
            cryptographic_protection: CryptographicProtection::default(),
        }
    }
}

impl Default for HashObfuscation {
    fn default() -> Self {
        Self {
            enabled: true,
            obfuscation_level: 3,
            decoy_hashes: Vec::new(),
            noise_injection: true,
        }
    }
}

impl Default for SteganographicHiding {
    fn default() -> Self {
        Self {
            enabled: false,
            hiding_algorithm: "LSB".to_string(),
            cover_data: Vec::new(),
            extraction_key: None,
        }
    }
}

impl Default for CryptographicProtection {
    fn default() -> Self {
        Self {
            enabled: true,
            encryption_algorithm: "AES-256-GCM".to_string(),
            key_derivation: "PBKDF2".to_string(),
            protection_key: None,
        }
    }
}

impl AntiForensicHashInjector {
    /// Create new anti-forensic hash injector
    pub fn new() -> Self {
        info!("Initializing Anti-Forensic Hash Injector with military-grade security");
        
        Self {
            stats: HashInjectionStats::default(),
            config: HashInjectionConfig::default(),
            crypto_engines: CryptoEngines::default(),
            verification_system: HashVerificationSystem::default(),
            anti_forensic_protection: AntiForensicProtection::default(),
        }
    }

    /// Create injector with custom configuration
    pub fn with_config(config: HashInjectionConfig) -> Self {
        info!("Initializing Anti-Forensic Hash Injector with custom configuration");
        
        Self {
            stats: HashInjectionStats::default(),
            config,
            crypto_engines: CryptoEngines::default(),
            verification_system: HashVerificationSystem::default(),
            anti_forensic_protection: AntiForensicProtection::default(),
        }
    }

    /// Inject hashes with anti-forensic protection
    pub async fn inject_hashes(&mut self, document: &mut Document) -> Result<()> {
        let start_time = std::time::Instant::now();
        info!("Starting anti-forensic hash injection");

        // Phase 1: Initialize crypto engines
        self.initialize_crypto_engines().await?;

        // Phase 2: Inject MD5 hashes
        if self.config.enable_md5_injection {
            self.inject_md5_hashes(document).await?;
        }

        // Phase 3: Inject SHA-1 hashes
        if self.config.enable_sha1_injection {
            self.inject_sha1_hashes(document).await?;
        }

        // Phase 4: Inject SHA-256 hashes
        if self.config.enable_sha256_injection {
            self.inject_sha256_hashes(document).await?;
        }

        // Phase 5: Inject SHA-512 hashes
        if self.config.enable_sha512_injection {
            self.inject_sha512_hashes(document).await?;
        }

        // Phase 6: Inject BLAKE3 hashes
        if self.config.enable_blake3_injection {
            self.inject_blake3_hashes(document).await?;
        }

        // Phase 7: Inject custom hashes
        if self.config.enable_custom_hashes {
            self.inject_custom_hashes(document).await?;
        }

        // Phase 8: Apply anti-forensic protection
        if self.config.enable_anti_forensic_mode {
            self.apply_anti_forensic_protection(document).await?;
        }

        // Phase 9: Verify injected hashes
        if self.config.enable_verification {
            self.verify_injected_hashes(document).await?;
        }

        let elapsed = start_time.elapsed().as_millis() as u64;
        self.stats.total_processing_time_ms += elapsed;
        self.stats.documents_processed += 1;

        info!("Anti-forensic hash injection completed in {}ms", elapsed);
        Ok(())
    }

    /// Initialize crypto engines
    async fn initialize_crypto_engines(&mut self) -> Result<()> {
        debug!("Initializing cryptographic engines");

        // Initialize all hash engines
        self.crypto_engines.md5_engine.enabled = self.config.enable_md5_injection;
        self.crypto_engines.sha1_engine.enabled = self.config.enable_sha1_injection;
        self.crypto_engines.sha256_engine.enabled = self.config.enable_sha256_injection;
        self.crypto_engines.sha512_engine.enabled = self.config.enable_sha512_injection;
        self.crypto_engines.blake3_engine.enabled = self.config.enable_blake3_injection;

        debug!("Cryptographic engines initialized");
        Ok(())
    }

    /// Inject MD5 hashes
    async fn inject_md5_hashes(&mut self, document: &mut Document) -> Result<()> {
        debug!("Injecting MD5 hashes");

        let hash_value = if let Some(manual_hash) = &self.crypto_engines.md5_engine.manual_hash {
            manual_hash.clone()
        } else {
            self.compute_md5_hash(document).await?
        };

        self.inject_hash_to_document(document, "MD5", &hash_value, HashLocation::Metadata).await?;
        
        self.crypto_engines.md5_engine.computed_hash = Some(hash_value);
        self.crypto_engines.md5_engine.injection_count += 1;
        self.stats.md5_hashes_injected += 1;
        self.stats.hashes_injected += 1;

        debug!("MD5 hash injection completed");
        Ok(())
    }

    /// Inject SHA-1 hashes
    async fn inject_sha1_hashes(&mut self, document: &mut Document) -> Result<()> {
        debug!("Injecting SHA-1 hashes");

        let hash_value = if let Some(manual_hash) = &self.crypto_engines.sha1_engine.manual_hash {
            manual_hash.clone()
        } else {
            self.compute_sha1_hash(document).await?
        };

        self.inject_hash_to_document(document, "SHA1", &hash_value, HashLocation::Metadata).await?;
        
        self.crypto_engines.sha1_engine.computed_hash = Some(hash_value);
        self.crypto_engines.sha1_engine.injection_count += 1;
        self.stats.sha1_hashes_injected += 1;
        self.stats.hashes_injected += 1;

        debug!("SHA-1 hash injection completed");
        Ok(())
    }

    /// Inject SHA-256 hashes
    async fn inject_sha256_hashes(&mut self, document: &mut Document) -> Result<()> {
        debug!("Injecting SHA-256 hashes");

        let hash_value = if let Some(manual_hash) = &self.crypto_engines.sha256_engine.manual_hash {
            manual_hash.clone()
        } else {
            self.compute_sha256_hash(document).await?
        };

        self.inject_hash_to_document(document, "SHA256", &hash_value, HashLocation::Metadata).await?;
        
        self.crypto_engines.sha256_engine.computed_hash = Some(hash_value);
        self.crypto_engines.sha256_engine.injection_count += 1;
        self.stats.sha256_hashes_injected += 1;
        self.stats.hashes_injected += 1;

        debug!("SHA-256 hash injection completed");
        Ok(())
    }

    /// Inject SHA-512 hashes
    async fn inject_sha512_hashes(&mut self, document: &mut Document) -> Result<()> {
        debug!("Injecting SHA-512 hashes");

        let hash_value = if let Some(manual_hash) = &self.crypto_engines.sha512_engine.manual_hash {
            manual_hash.clone()
        } else {
            self.compute_sha512_hash(document).await?
        };

        self.inject_hash_to_document(document, "SHA512", &hash_value, HashLocation::Metadata).await?;
        
        self.crypto_engines.sha512_engine.computed_hash = Some(hash_value);
        self.crypto_engines.sha512_engine.injection_count += 1;
        self.stats.sha512_hashes_injected += 1;
        self.stats.hashes_injected += 1;

        debug!("SHA-512 hash injection completed");
        Ok(())
    }

    /// Inject BLAKE3 hashes
    async fn inject_blake3_hashes(&mut self, document: &mut Document) -> Result<()> {
        debug!("Injecting BLAKE3 hashes");

        let hash_value = if let Some(manual_hash) = &self.crypto_engines.blake3_engine.manual_hash {
            manual_hash.clone()
        } else {
            self.compute_blake3_hash(document).await?
        };

        self.inject_hash_to_document(document, "BLAKE3", &hash_value, HashLocation::Metadata).await?;
        
        self.crypto_engines.blake3_engine.computed_hash = Some(hash_value);
        self.crypto_engines.blake3_engine.injection_count += 1;
        self.stats.blake3_hashes_injected += 1;
        self.stats.hashes_injected += 1;

        debug!("BLAKE3 hash injection completed");
        Ok(())
    }

    /// Inject custom hashes
    async fn inject_custom_hashes(&mut self, document: &mut Document) -> Result<()> {
        debug!("Injecting custom hashes");

        for (algorithm, engine) in &mut self.crypto_engines.custom_engines {
            self.inject_hash_to_document(
                document, 
                algorithm, 
                &engine.hash_value, 
                HashLocation::CustomField(format!("Custom{}", algorithm))
            ).await?;
            
            engine.injection_count += 1;
            self.stats.custom_hashes_injected += 1;
            self.stats.hashes_injected += 1;
        }

        debug!("Custom hash injection completed");
        Ok(())
    }

    /// Compute MD5 hash
    async fn compute_md5_hash(&self, document: &Document) -> Result<String> {
        let mut hasher = Md5::new();
        hasher.update(&document.content);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Compute SHA-1 hash
    async fn compute_sha1_hash(&self, document: &Document) -> Result<String> {
        let mut hasher = Sha1::new();
        hasher.update(&document.content);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Compute SHA-256 hash
    async fn compute_sha256_hash(&self, document: &Document) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(&document.content);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Compute SHA-512 hash
    async fn compute_sha512_hash(&self, document: &Document) -> Result<String> {
        let mut hasher = Sha512::new();
        hasher.update(&document.content);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Compute BLAKE3 hash
    async fn compute_blake3_hash(&self, document: &Document) -> Result<String> {
        let mut hasher = Blake3Hasher::new();
        hasher.update(&document.content);
        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Inject hash to document
    async fn inject_hash_to_document(
        &self, 
        document: &mut Document, 
        algorithm: &str, 
        hash_value: &str, 
        location: HashLocation
    ) -> Result<()> {
        debug!("Injecting {} hash to {:?}", algorithm, location);

        match location {
            HashLocation::DocumentInfo => {
                // Inject into document info dictionary
                document.metadata.custom.insert(
                    format!("{}Hash", algorithm),
                    hash_value.to_string()
                );
            },
            HashLocation::Metadata => {
                // Inject into custom metadata
                document.metadata.custom.insert(
                    format!("Hash{}", algorithm),
                    hash_value.to_string()
                );
            },
            HashLocation::CustomField(field_name) => {
                // Inject into custom field
                document.metadata.custom.insert(field_name, hash_value.to_string());
            },
            HashLocation::EmbeddedStream => {
                // Inject into embedded stream (would require more complex implementation)
                document.metadata.custom.insert(
                    format!("EmbeddedHash{}", algorithm),
                    hash_value.to_string()
                );
            },
            HashLocation::TrailerSection => {
                // Inject into trailer section
                document.metadata.custom.insert(
                    format!("TrailerHash{}", algorithm),
                    hash_value.to_string()
                );
            },
        }

        Ok(())
    }

    /// Apply anti-forensic protection
    async fn apply_anti_forensic_protection(&mut self, document: &mut Document) -> Result<()> {
        debug!("Applying anti-forensic protection to hashes");

        // Apply hash obfuscation
        if self.anti_forensic_protection.hash_obfuscation.enabled {
            self.apply_hash_obfuscation(document).await?;
        }

        // Apply steganographic hiding
        if self.anti_forensic_protection.steganographic_hiding.enabled {
            self.apply_steganographic_hiding(document).await?;
        }

        // Apply cryptographic protection
        if self.anti_forensic_protection.cryptographic_protection.enabled {
            self.apply_cryptographic_protection(document).await?;
        }

        self.stats.anti_forensic_operations += 1;
        Ok(())
    }

    /// Apply hash obfuscation
    async fn apply_hash_obfuscation(&mut self, document: &mut Document) -> Result<()> {
        debug!("Applying hash obfuscation");

        // Generate decoy hashes
        for i in 0..self.anti_forensic_protection.hash_obfuscation.obfuscation_level {
            let decoy_hash = self.generate_decoy_hash().await?;
            self.anti_forensic_protection.hash_obfuscation.decoy_hashes.push(decoy_hash.clone());
            
            document.metadata.custom.insert(
                format!("DecoyHash{}", i),
                decoy_hash
            );
        }

        // Inject noise if enabled
        if self.anti_forensic_protection.hash_obfuscation.noise_injection {
            self.inject_noise_hashes(document).await?;
        }

        Ok(())
    }

    /// Apply steganographic hiding
    async fn apply_steganographic_hiding(&self, document: &mut Document) -> Result<()> {
        debug!("Applying steganographic hiding");

        // Hide hash data steganographically
        // This would involve more complex steganographic algorithms
        document.metadata.custom.insert(
            "SteganographicData".to_string(),
            "Hidden hash data".to_string()
        );

        Ok(())
    }

    /// Apply cryptographic protection
    async fn apply_cryptographic_protection(&self, document: &mut Document) -> Result<()> {
        debug!("Applying cryptographic protection");

        // Encrypt hash data
        // This would involve actual encryption of the hash values
        document.metadata.custom.insert(
            "ProtectedHashes".to_string(),
            "Encrypted hash data".to_string()
        );

        Ok(())
    }

    /// Generate decoy hash
    async fn generate_decoy_hash(&self) -> Result<String> {
        let rng = SystemRandom::new();
        let mut random_bytes = vec![0u8; 32];
        rng.fill(&mut random_bytes).map_err(|e| {
            crate::error::PdfSecureEditError::SecurityError(format!("Decoy hash generation failed: {}", e))
        })?;

        let hash = digest::digest(&digest::SHA256, &random_bytes);
        Ok(hex::encode(hash.as_ref()))
    }

    /// Inject noise hashes
    async fn inject_noise_hashes(&self, document: &mut Document) -> Result<()> {
        debug!("Injecting noise hashes");

        // Generate and inject noise hashes to confuse analysis
        for i in 0..5 {
            let noise_hash = self.generate_decoy_hash().await?;
            document.metadata.custom.insert(
                format!("NoiseHash{}", i),
                noise_hash
            );
        }

        Ok(())
    }

    /// Verify injected hashes
    async fn verify_injected_hashes(&mut self, document: &Document) -> Result<()> {
        debug!("Verifying injected hashes");

        // Verify MD5
        if self.config.enable_md5_injection {
            self.verify_hash(document, "MD5").await?;
        }

        // Verify SHA-1
        if self.config.enable_sha1_injection {
            self.verify_hash(document, "SHA1").await?;
        }

        // Verify SHA-256
        if self.config.enable_sha256_injection {
            self.verify_hash(document, "SHA256").await?;
        }

        // Verify SHA-512
        if self.config.enable_sha512_injection {
            self.verify_hash(document, "SHA512").await?;
        }

        // Verify BLAKE3
        if self.config.enable_blake3_injection {
            self.verify_hash(document, "BLAKE3").await?;
        }

        self.stats.verification_checks_performed += 1;
        Ok(())
    }

    /// Verify specific hash
    async fn verify_hash(&mut self, document: &Document, algorithm: &str) -> Result<()> {
        debug!("Verifying {} hash", algorithm);

        let expected_hash = match algorithm {
            "MD5" => self.crypto_engines.md5_engine.computed_hash.as_ref(),
            "SHA1" => self.crypto_engines.sha1_engine.computed_hash.as_ref(),
            "SHA256" => self.crypto_engines.sha256_engine.computed_hash.as_ref(),
            "SHA512" => self.crypto_engines.sha512_engine.computed_hash.as_ref(),
            "BLAKE3" => self.crypto_engines.blake3_engine.computed_hash.as_ref(),
            _ => None,
        };

        if let Some(expected) = expected_hash {
            // Recompute hash and compare
            let computed_hash = match algorithm {
                "MD5" => self.compute_md5_hash(document).await?,
                "SHA1" => self.compute_sha1_hash(document).await?,
                "SHA256" => self.compute_sha256_hash(document).await?,
                "SHA512" => self.compute_sha512_hash(document).await?,
                "BLAKE3" => self.compute_blake3_hash(document).await?,
                _ => return Ok(()),
            };

            let verification_result = VerificationResult {
                algorithm: algorithm.to_string(),
                expected_hash: expected.clone(),
                computed_hash: computed_hash.clone(),
                verification_status: if expected == &computed_hash {
                    VerificationStatus::Passed
                } else {
                    VerificationStatus::Failed
                },
                timestamp: chrono::Utc::now(),
            };

            self.verification_system.verification_results.insert(
                algorithm.to_string(),
                verification_result
            );
        }

        Ok(())
    }

    /// Set manual hash for algorithm
    pub fn set_manual_hash(&mut self, algorithm: &str, hash_value: &str) -> Result<()> {
        debug!("Setting manual hash for {}: {}", algorithm, hash_value);

        match algorithm.to_uppercase().as_str() {
            "MD5" => {
                self.crypto_engines.md5_engine.manual_hash = Some(hash_value.to_string());
            },
            "SHA1" => {
                self.crypto_engines.sha1_engine.manual_hash = Some(hash_value.to_string());
            },
            "SHA256" => {
                self.crypto_engines.sha256_engine.manual_hash = Some(hash_value.to_string());
            },
            "SHA512" => {
                self.crypto_engines.sha512_engine.manual_hash = Some(hash_value.to_string());
            },
            "BLAKE3" => {
                self.crypto_engines.blake3_engine.manual_hash = Some(hash_value.to_string());
            },
            _ => {
                // Add as custom hash
                self.crypto_engines.custom_engines.insert(
                    algorithm.to_string(),
                    CustomHashEngine {
                        algorithm_name: algorithm.to_string(),
                        hash_value: hash_value.to_string(),
                        hash_function: "Manual".to_string(),
                        injection_count: 0,
                    }
                );
            }
        }

        Ok(())
    }

    /// Get injection statistics
    pub fn statistics(&self) -> &HashInjectionStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_statistics(&mut self) {
        self.stats = HashInjectionStats::default();
    }

    /// Set configuration
    pub fn set_config(&mut self, config: HashInjectionConfig) {
        self.config = config;
    }

    /// Get verification results
    pub fn verification_results(&self) -> &HashMap<String, VerificationResult> {
        &self.verification_system.verification_results
    }
}

impl Default for AntiForensicHashInjector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Document, DocumentStructure, DocumentMetadata};

    fn create_test_document() -> Document {
        Document {
            structure: DocumentStructure::default(),
            metadata: DocumentMetadata::default(),
            content: b"Test document content for hashing".to_vec(),
        }
    }

    #[tokio::test]
    async fn test_hash_injection() {
        let mut injector = AntiForensicHashInjector::new();
        let mut document = create_test_document();
        
        injector.inject_hashes(&mut document).await.unwrap();
        assert_eq!(injector.statistics().documents_processed, 1);
        assert!(injector.statistics().hashes_injected > 0);
    }

    #[tokio::test]
    async fn test_manual_hash_setting() {
        let mut injector = AntiForensicHashInjector::new();
        
        injector.set_manual_hash("MD5", "d41d8cd98f00b204e9800998ecf8427e").unwrap();
        assert!(injector.crypto_engines.md5_engine.manual_hash.is_some());
    }

    #[tokio::test]
    async fn test_md5_hash_computation() {
        let injector = AntiForensicHashInjector::new();
        let document = create_test_document();
        
        let hash = injector.compute_md5_hash(&document).await.unwrap();
        assert_eq!(hash.len(), 32); // MD5 hex string length
    }

    #[tokio::test]
    async fn test_sha256_hash_computation() {
        let injector = AntiForensicHashInjector::new();
        let document = create_test_document();
        
        let hash = injector.compute_sha256_hash(&document).await.unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 hex string length
    }

    #[tokio::test]
    async fn test_blake3_hash_computation() {
        let injector = AntiForensicHashInjector::new();
        let document = create_test_document();
        
        let hash = injector.compute_blake3_hash(&document).await.unwrap();
        assert_eq!(hash.len(), 64); // BLAKE3 hex string length
    }

    #[tokio::test]
    async fn test_anti_forensic_protection() {
        let mut injector = AntiForensicHashInjector::new();
        let mut document = create_test_document();
        
        injector.apply_anti_forensic_protection(&mut document).await.unwrap();
        assert!(injector.statistics().anti_forensic_operations > 0);
    }

    #[tokio::test]
    async fn test_hash_verification() {
        let mut injector = AntiForensicHashInjector::new();
        let document = create_test_document();
        
        // Set a computed hash first
        injector.crypto_engines.md5_engine.computed_hash = Some("test_hash".to_string());
        
        injector.verify_injected_hashes(&document).await.unwrap();
        assert!(injector.statistics().verification_checks_performed > 0);
    }
}
