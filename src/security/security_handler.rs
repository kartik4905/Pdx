
use crate::error::{Result, AntiForensicsError};
use crate::types::Document;
use crate::config::SecurityConfig;
use crate::utils::crypto_utils::CryptoUtils;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::rand::rand_bytes;
use openssl::hash::{hash, MessageDigest};
use std::collections::HashMap;
use log::{info, warn, debug};
use lopdf::{Object, ObjectId, Dictionary};

/// PDF Security Handler with zero-fallback cryptographic operations
pub struct SecurityHandler {
    crypto_utils: CryptoUtils,
    encryption_enabled: bool,
    key_length: u32,
    algorithm: EncryptionAlgorithm,
    permissions: PdfPermissions,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EncryptionAlgorithm {
    RC4_40,
    RC4_128,
    AES_128,
    AES_256,
}

#[derive(Debug, Clone)]
pub struct PdfPermissions {
    pub print: bool,
    pub copy: bool,
    pub modify: bool,
    pub annotate: bool,
    pub fill_forms: bool,
    pub extract_for_accessibility: bool,
    pub assemble: bool,
    pub high_quality_print: bool,
}

#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub algorithm_used: String,
    pub key_length: u32,
    pub objects_encrypted: usize,
    pub streams_encrypted: usize,
    pub encryption_time_ms: u64,
    pub permissions_set: PdfPermissions,
}

#[derive(Debug, Clone)]
pub struct UserPasswords {
    pub user_password: Option<String>,
    pub owner_password: Option<String>,
}

impl SecurityHandler {
    pub fn new() -> Self {
        Self {
            crypto_utils: CryptoUtils::new(),
            encryption_enabled: false,
            key_length: 256,
            algorithm: EncryptionAlgorithm::AES_256,
            permissions: PdfPermissions::default(),
        }
    }

    pub fn with_algorithm(mut self, algorithm: EncryptionAlgorithm) -> Self {
        self.algorithm = algorithm;
        self.key_length = match algorithm {
            EncryptionAlgorithm::RC4_40 => 40,
            EncryptionAlgorithm::RC4_128 => 128,
            EncryptionAlgorithm::AES_128 => 128,
            EncryptionAlgorithm::AES_256 => 256,
        };
        self
    }

    pub fn with_permissions(mut self, permissions: PdfPermissions) -> Self {
        self.permissions = permissions;
        self
    }

    /// Encrypt PDF document with user-specified security settings (NO DEFAULTS)
    pub async fn encrypt(&mut self, document: &mut Document, config: &SecurityConfig) -> Result<EncryptionResult> {
        let start_time = std::time::Instant::now();
        
        info!("Starting PDF encryption with algorithm: {:?}", self.algorithm);

        // Validate that user has explicitly set passwords - NO DEFAULTS ALLOWED
        if config.user_password.is_none() && config.owner_password.is_none() {
            return Err(AntiForensicsError::Security(
                "No passwords provided - explicit user/owner passwords required".into()
            ));
        }

        // Generate encryption dictionary
        let encrypt_dict = self.create_encryption_dictionary(config).await?;
        
        // Generate file encryption key
        let file_key = self.generate_file_encryption_key(config).await?;
        
        // Encrypt all streams and strings in the document
        let (objects_encrypted, streams_encrypted) = self.encrypt_document_content(document, &file_key).await?;
        
        // Add encryption dictionary to document
        document.objects.insert(
            self.get_next_object_id(document),
            Object::Dictionary(encrypt_dict)
        );

        // Update document trailer
        self.update_trailer_with_encryption(document).await?;

        let encryption_time = start_time.elapsed().as_millis() as u64;
        
        info!("Encryption completed: {} objects, {} streams, {}ms", 
              objects_encrypted, streams_encrypted, encryption_time);

        Ok(EncryptionResult {
            algorithm_used: format!("{:?}", self.algorithm),
            key_length: self.key_length,
            objects_encrypted,
            streams_encrypted,
            encryption_time_ms: encryption_time,
            permissions_set: self.permissions.clone(),
        })
    }

    /// Create PDF encryption dictionary with explicit user settings
    async fn create_encryption_dictionary(&self, config: &SecurityConfig) -> Result<Dictionary> {
        let mut encrypt_dict = Dictionary::new();
        
        // Filter (encryption method) - NO DEFAULTS
        match self.algorithm {
            EncryptionAlgorithm::RC4_40 | EncryptionAlgorithm::RC4_128 => {
                encrypt_dict.set("Filter", Object::Name(b"Standard".to_vec()));
                encrypt_dict.set("V", Object::Integer(1));
            }
            EncryptionAlgorithm::AES_128 => {
                encrypt_dict.set("Filter", Object::Name(b"Standard".to_vec()));
                encrypt_dict.set("V", Object::Integer(4));
                encrypt_dict.set("CF", self.create_crypt_filters_aes128()?);
                encrypt_dict.set("StmF", Object::Name(b"StdCF".to_vec()));
                encrypt_dict.set("StrF", Object::Name(b"StdCF".to_vec()));
            }
            EncryptionAlgorithm::AES_256 => {
                encrypt_dict.set("Filter", Object::Name(b"Standard".to_vec()));
                encrypt_dict.set("V", Object::Integer(5));
                encrypt_dict.set("CF", self.create_crypt_filters_aes256()?);
                encrypt_dict.set("StmF", Object::Name(b"StdCF".to_vec()));
                encrypt_dict.set("StrF", Object::Name(b"StdCF".to_vec()));
            }
        }

        // Key length
        encrypt_dict.set("Length", Object::Integer(self.key_length as i64));

        // Revision number
        let revision = match self.algorithm {
            EncryptionAlgorithm::RC4_40 => 2,
            EncryptionAlgorithm::RC4_128 => 3,
            EncryptionAlgorithm::AES_128 => 4,
            EncryptionAlgorithm::AES_256 => 6,
        };
        encrypt_dict.set("R", Object::Integer(revision));

        // User password computation
        if let Some(user_pass) = &config.user_password {
            let u_value = self.compute_u_value(user_pass, config).await?;
            encrypt_dict.set("U", Object::String(u_value, lopdf::StringFormat::Literal));
        } else {
            return Err(AntiForensicsError::Security("User password required".into()));
        }

        // Owner password computation
        if let Some(owner_pass) = &config.owner_password {
            let o_value = self.compute_o_value(owner_pass, config).await?;
            encrypt_dict.set("O", Object::String(o_value, lopdf::StringFormat::Literal));
        } else {
            return Err(AntiForensicsError::Security("Owner password required".into()));
        }

        // Permissions (explicit user control)
        let permissions_value = self.compute_permissions_value();
        encrypt_dict.set("P", Object::Integer(permissions_value));

        // Metadata encryption (user controlled)
        encrypt_dict.set("EncryptMetadata", Object::Boolean(config.encrypt_metadata.unwrap_or(true)));

        Ok(encrypt_dict)
    }

    /// Create AES-128 crypt filters
    fn create_crypt_filters_aes128(&self) -> Result<Object> {
        let mut cf_dict = Dictionary::new();
        let mut stdcf_dict = Dictionary::new();
        
        stdcf_dict.set("CFM", Object::Name(b"AESV2".to_vec()));
        stdcf_dict.set("Length", Object::Integer(16)); // 128 bits = 16 bytes
        stdcf_dict.set("AuthEvent", Object::Name(b"DocOpen".to_vec()));
        
        cf_dict.set("StdCF", Object::Dictionary(stdcf_dict));
        
        Ok(Object::Dictionary(cf_dict))
    }

    /// Create AES-256 crypt filters
    fn create_crypt_filters_aes256(&self) -> Result<Object> {
        let mut cf_dict = Dictionary::new();
        let mut stdcf_dict = Dictionary::new();
        
        stdcf_dict.set("CFM", Object::Name(b"AESV3".to_vec()));
        stdcf_dict.set("Length", Object::Integer(32)); // 256 bits = 32 bytes
        stdcf_dict.set("AuthEvent", Object::Name(b"DocOpen".to_vec()));
        
        cf_dict.set("StdCF", Object::Dictionary(stdcf_dict));
        
        Ok(Object::Dictionary(cf_dict))
    }

    /// Generate file encryption key from passwords
    async fn generate_file_encryption_key(&self, config: &SecurityConfig) -> Result<Vec<u8>> {
        let key_length_bytes = self.key_length / 8;
        
        match self.algorithm {
            EncryptionAlgorithm::AES_256 => {
                // For AES-256, use PBKDF2 key derivation
                self.generate_aes256_key(config, key_length_bytes as usize).await
            }
            EncryptionAlgorithm::AES_128 => {
                self.generate_aes128_key(config, key_length_bytes as usize).await
            }
            EncryptionAlgorithm::RC4_128 | EncryptionAlgorithm::RC4_40 => {
                self.generate_rc4_key(config, key_length_bytes as usize).await
            }
        }
    }

    /// Generate AES-256 encryption key using PBKDF2
    async fn generate_aes256_key(&self, config: &SecurityConfig, key_length: usize) -> Result<Vec<u8>> {
        let password = config.user_password.as_ref()
            .or(config.owner_password.as_ref())
            .ok_or_else(|| AntiForensicsError::Security("No password provided".into()))?;

        // Generate random salt
        let mut salt = vec![0u8; 16];
        rand_bytes(&mut salt)
            .map_err(|e| AntiForensicsError::Cryptographic(format!("Salt generation failed: {}", e)))?;

        // Use PBKDF2 with SHA-256
        let key = self.crypto_utils.pbkdf2_sha256(
            password.as_bytes(),
            &salt,
            10000, // 10,000 iterations (good security vs performance balance)
            key_length
        )?;

        Ok(key)
    }

    /// Generate AES-128 encryption key
    async fn generate_aes128_key(&self, config: &SecurityConfig, key_length: usize) -> Result<Vec<u8>> {
        let password = config.user_password.as_ref()
            .or(config.owner_password.as_ref())
            .ok_or_else(|| AntiForensicsError::Security("No password provided".into()))?;

        let mut salt = vec![0u8; 8];
        rand_bytes(&mut salt)
            .map_err(|e| AntiForensicsError::Cryptographic(format!("Salt generation failed: {}", e)))?;

        let key = self.crypto_utils.pbkdf2_sha256(
            password.as_bytes(),
            &salt,
            5000, // 5,000 iterations for AES-128
            key_length
        )?;

        Ok(key)
    }

    /// Generate RC4 encryption key
    async fn generate_rc4_key(&self, config: &SecurityConfig, key_length: usize) -> Result<Vec<u8>> {
        let password = config.user_password.as_ref()
            .or(config.owner_password.as_ref())
            .ok_or_else(|| AntiForensicsError::Security("No password provided".into()))?;

        // For RC4, use MD5 hash derivation (legacy but required for PDF compatibility)
        let mut hasher_input = password.as_bytes().to_vec();
        
        // Add some salt
        let mut salt = vec![0u8; 8];
        rand_bytes(&mut salt)
            .map_err(|e| AntiForensicsError::Cryptographic(format!("Salt generation failed: {}", e)))?;
        hasher_input.extend_from_slice(&salt);

        let hash_result = hash(MessageDigest::md5(), &hasher_input)
            .map_err(|e| AntiForensicsError::Cryptographic(format!("MD5 hash failed: {}", e)))?;

        // Truncate to required key length
        let mut key = hash_result.to_vec();
        key.truncate(key_length);
        
        // If key is too short, repeat the hash
        while key.len() < key_length {
            let additional_hash = hash(MessageDigest::md5(), &key)
                .map_err(|e| AntiForensicsError::Cryptographic(format!("MD5 hash failed: {}", e)))?;
            key.extend_from_slice(&additional_hash);
        }
        key.truncate(key_length);

        Ok(key)
    }

    /// Encrypt document content (streams and strings)
    async fn encrypt_document_content(&self, document: &mut Document, file_key: &[u8]) -> Result<(usize, usize)> {
        let mut objects_encrypted = 0;
        let mut streams_encrypted = 0;

        // Clone object IDs to avoid borrow issues
        let object_ids: Vec<ObjectId> = document.objects.keys().cloned().collect();

        for object_id in object_ids {
            if let Some(object) = document.objects.get_mut(&object_id) {
                let (obj_encrypted, stream_encrypted) = self.encrypt_object(object, &object_id, file_key).await?;
                if obj_encrypted {
                    objects_encrypted += 1;
                }
                if stream_encrypted {
                    streams_encrypted += 1;
                }
            }
        }

        Ok((objects_encrypted, streams_encrypted))
    }

    /// Encrypt individual object
    async fn encrypt_object(&self, object: &mut Object, object_id: &ObjectId, file_key: &[u8]) -> Result<(bool, bool)> {
        let mut object_encrypted = false;
        let mut stream_encrypted = false;

        match object {
            Object::String(ref mut content, _) => {
                // Encrypt string content
                let object_key = self.derive_object_key(file_key, object_id)?;
                let encrypted_content = self.encrypt_data(content, &object_key).await?;
                *content = encrypted_content;
                object_encrypted = true;
            }
            Object::Stream(ref mut stream) => {
                // Encrypt stream content
                let object_key = self.derive_object_key(file_key, object_id)?;
                let encrypted_content = self.encrypt_data(&stream.content, &object_key).await?;
                stream.content = encrypted_content;
                
                // Update stream dictionary to indicate encryption
                stream.dict.set("Filter", Object::Name(b"Crypt".to_vec()));
                
                stream_encrypted = true;
                object_encrypted = true;
            }
            Object::Dictionary(ref mut dict) => {
                // Recursively encrypt strings in dictionary
                for (_, value) in dict.iter_mut() {
                    if let Object::String(ref mut content, _) = value {
                        let object_key = self.derive_object_key(file_key, object_id)?;
                        let encrypted_content = self.encrypt_data(content, &object_key).await?;
                        *content = encrypted_content;
                        object_encrypted = true;
                    }
                }
            }
            Object::Array(ref mut array) => {
                // Recursively encrypt strings in array
                for item in array.iter_mut() {
                    if let Object::String(ref mut content, _) = item {
                        let object_key = self.derive_object_key(file_key, object_id)?;
                        let encrypted_content = self.encrypt_data(content, &object_key).await?;
                        *content = encrypted_content;
                        object_encrypted = true;
                    }
                }
            }
            _ => {
                // Other object types don't need encryption
            }
        }

        Ok((object_encrypted, stream_encrypted))
    }

    /// Derive object-specific encryption key
    fn derive_object_key(&self, file_key: &[u8], object_id: &ObjectId) -> Result<Vec<u8>> {
        let mut key_data = file_key.to_vec();
        
        // Add object number and generation (little-endian)
        key_data.extend_from_slice(&(object_id.0 as u32).to_le_bytes()[..3]);
        key_data.extend_from_slice(&(object_id.1 as u16).to_le_bytes());

        // For AES, add salt
        if matches!(self.algorithm, EncryptionAlgorithm::AES_128 | EncryptionAlgorithm::AES_256) {
            key_data.extend_from_slice(b"sAlT"); // PDF standard salt for AES
        }

        // Hash to get final key
        let hash_result = hash(MessageDigest::md5(), &key_data)
            .map_err(|e| AntiForensicsError::Cryptographic(format!("Key derivation failed: {}", e)))?;

        Ok(hash_result.to_vec())
    }

    /// Encrypt data using the specified algorithm
    async fn encrypt_data(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            EncryptionAlgorithm::AES_128 | EncryptionAlgorithm::AES_256 => {
                self.encrypt_aes(data, key).await
            }
            EncryptionAlgorithm::RC4_40 | EncryptionAlgorithm::RC4_128 => {
                self.encrypt_rc4(data, key).await
            }
        }
    }

    /// AES encryption
    async fn encrypt_aes(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let cipher = match self.algorithm {
            EncryptionAlgorithm::AES_128 => Cipher::aes_128_cbc(),
            EncryptionAlgorithm::AES_256 => Cipher::aes_256_cbc(),
            _ => return Err(AntiForensicsError::Cryptographic("Invalid AES algorithm".into())),
        };

        // Generate random IV
        let mut iv = vec![0u8; cipher.iv_len().unwrap_or(16)];
        rand_bytes(&mut iv)
            .map_err(|e| AntiForensicsError::Cryptographic(format!("IV generation failed: {}", e)))?;

        // Encrypt data
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv))
            .map_err(|e| AntiForensicsError::Cryptographic(format!("Crypter creation failed: {}", e)))?;

        let mut encrypted = vec![0u8; data.len() + cipher.block_size()];
        let mut len = crypter.update(data, &mut encrypted)
            .map_err(|e| AntiForensicsError::Cryptographic(format!("Encryption failed: {}", e)))?;
        
        len += crypter.finalize(&mut encrypted[len..])
            .map_err(|e| AntiForensicsError::Cryptographic(format!("Encryption finalization failed: {}", e)))?;

        encrypted.truncate(len);

        // Prepend IV to encrypted data
        let mut result = iv;
        result.extend_from_slice(&encrypted);
        
        Ok(result)
    }

    /// RC4 encryption (legacy support)
    async fn encrypt_rc4(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        // RC4 implementation (simplified - use a proper crypto library in production)
        let mut s: [u8; 256] = [0; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        let mut encrypted = Vec::with_capacity(data.len());
        let mut i = 0u8;
        let mut j = 0u8;

        for &byte in data {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            encrypted.push(byte ^ k);
        }

        Ok(encrypted)
    }

    /// Compute U value for user password
    async fn compute_u_value(&self, user_password: &str, config: &SecurityConfig) -> Result<Vec<u8>> {
        // Simplified U value computation - full implementation would follow PDF spec
        let mut input = user_password.as_bytes().to_vec();
        input.extend_from_slice(b"PDF_STANDARD_U_VALUE"); // Padding
        
        let hash_result = hash(MessageDigest::md5(), &input)
            .map_err(|e| AntiForensicsError::Cryptographic(format!("U value computation failed: {}", e)))?;
        
        Ok(hash_result.to_vec())
    }

    /// Compute O value for owner password
    async fn compute_o_value(&self, owner_password: &str, config: &SecurityConfig) -> Result<Vec<u8>> {
        // Simplified O value computation - full implementation would follow PDF spec
        let mut input = owner_password.as_bytes().to_vec();
        input.extend_from_slice(b"PDF_STANDARD_O_VALUE"); // Padding
        
        let hash_result = hash(MessageDigest::md5(), &input)
            .map_err(|e| AntiForensicsError::Cryptographic(format!("O value computation failed: {}", e)))?;
        
        Ok(hash_result.to_vec())
    }

    /// Compute permissions value from permission flags
    fn compute_permissions_value(&self) -> i64 {
        let mut permissions: i32 = -4; // Base value with required bits

        if self.permissions.print {
            permissions |= 1 << 2;
        }
        if self.permissions.modify {
            permissions |= 1 << 3;
        }
        if self.permissions.copy {
            permissions |= 1 << 4;
        }
        if self.permissions.annotate {
            permissions |= 1 << 5;
        }
        if self.permissions.fill_forms {
            permissions |= 1 << 8;
        }
        if self.permissions.extract_for_accessibility {
            permissions |= 1 << 9;
        }
        if self.permissions.assemble {
            permissions |= 1 << 10;
        }
        if self.permissions.high_quality_print {
            permissions |= 1 << 11;
        }

        permissions as i64
    }

    /// Update document trailer with encryption reference
    async fn update_trailer_with_encryption(&self, document: &mut Document) -> Result<()> {
        // Find encryption dictionary object ID
        let encrypt_id = document.objects.iter()
            .find(|(_, obj)| {
                if let Object::Dictionary(dict) = obj {
                    dict.get(b"Filter").and_then(|o| o.as_name_str()).ok() == Some("Standard")
                } else {
                    false
                }
            })
            .map(|(id, _)| *id);

        if let Some(encrypt_id) = encrypt_id {
            // Add /Encrypt reference to trailer
            document.trailer.set("Encrypt", Object::Reference(encrypt_id));
        }

        Ok(())
    }

    /// Get next available object ID
    fn get_next_object_id(&self, document: &Document) -> ObjectId {
        let max_id = document.objects.keys()
            .map(|id| id.0)
            .max()
            .unwrap_or(0);
        
        (max_id + 1, 0) // Generation 0 for new objects
    }

    /// Set explicit permissions (no defaults)
    pub fn set_permissions(&mut self, permissions: PdfPermissions) {
        self.permissions = permissions;
    }

    /// Enable/disable encryption
    pub fn set_encryption_enabled(&mut self, enabled: bool) {
        self.encryption_enabled = enabled;
    }
}

impl PdfPermissions {
    pub fn new() -> Self {
        Self {
            print: false,
            copy: false,
            modify: false,
            annotate: false,
            fill_forms: false,
            extract_for_accessibility: false,
            assemble: false,
            high_quality_print: false,
        }
    }

    pub fn allow_all() -> Self {
        Self {
            print: true,
            copy: true,
            modify: true,
            annotate: true,
            fill_forms: true,
            extract_for_accessibility: true,
            assemble: true,
            high_quality_print: true,
        }
    }

    pub fn read_only() -> Self {
        Self {
            print: true,
            copy: false,
            modify: false,
            annotate: false,
            fill_forms: false,
            extract_for_accessibility: true,
            assemble: false,
            high_quality_print: true,
        }
    }
}

impl Default for PdfPermissions {
    fn default() -> Self {
        Self::new() // Default to no permissions (most restrictive)
    }
}

impl Default for SecurityHandler {
    fn default() -> Self {
        Self::new()
    }
}
