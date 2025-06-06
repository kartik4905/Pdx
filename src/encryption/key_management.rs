//! Key Management Implementation
//! Author: kartik4091
//! Created: 2025-06-03 09:10:14 UTC

use super::*;
use crate::utils::metrics::Metrics;
use std::{
    sync::Arc,
    path::PathBuf,
    time::{Duration, Instant},
    collections::{HashMap, HashSet, BTreeMap},
};
use tokio::{
    sync::{RwLock, Semaphore, broadcast},
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
};
use tracing::{info, warn, error, debug, instrument};
use ring::{
    aead::{self, AES_256_GCM},
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// Key management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagementConfig {
    /// Base encryption configuration
    pub base: EncryptionConfig,
    /// Key store path
    pub key_store_path: PathBuf,
    /// Master key derivation salt
    pub master_key_salt: Vec<u8>,
    /// Key rotation interval
    pub rotation_interval: Duration,
    /// Backup enabled
    pub enable_backup: bool,
    /// Backup location
    pub backup_path: Option<PathBuf>,
}

/// Key store entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyStoreEntry {
    /// Key ID
    id: String,
    /// Encrypted key data
    encrypted_data: Vec<u8>,
    /// Creation timestamp
    created: chrono::DateTime<chrono::Utc>,
    /// Last rotation timestamp
    last_rotated: chrono::DateTime<chrono::Utc>,
    /// Key metadata
    metadata: HashMap<String, String>,
}

/// Key management state
#[derive(Debug)]
struct KeyManagementState {
    /// Active keys
    active_keys: HashMap<String, EncryptionKey>,
    /// Key store
    key_store: BTreeMap<String, KeyStoreEntry>,
    /// Statistics
    stats: KeyManagementStats,
}

/// Key management statistics
#[derive(Debug, Default)]
struct KeyManagementStats {
    keys_generated: u64,
    keys_rotated: u64,
    keys_deleted: u64,
    avg_operation_time: Duration,
}

pub struct KeyManagement {
    /// Base encryption
    base: Arc<BaseEncryption>,
    /// Key management configuration
    config: Arc<KeyManagementConfig>,
    /// Management state
    state: Arc<RwLock<KeyManagementState>>,
    /// Performance metrics
    metrics: Arc<Metrics>,
    /// Random number generator
    rng: SystemRandom,
}

impl KeyManagement {
    /// Creates a new key management instance
    pub fn new(config: KeyManagementConfig) -> Self {
        Self {
            base: Arc::new(BaseEncryption::new(config.base.clone())),
            config: Arc::new(config),
            state: Arc::new(RwLock::new(KeyManagementState {
                active_keys: HashMap::new(),
                key_store: BTreeMap::new(),
                stats: KeyManagementStats::default(),
            })),
            metrics: Arc::new(Metrics::new()),
            rng: SystemRandom::new(),
        }
    }

    /// Initializes key store
    #[instrument(skip(self, master_password))]
    pub async fn initialize(&self, master_password: &str) -> Result<()> {
        let start = Instant::now();

        // Create key store directory if it doesn't exist
        if !self.config.key_store_path.exists() {
            fs::create_dir_all(&self.config.key_store_path).await?;
        }

        // Initialize master key
        self.derive_master_key(master_password).await?;

        // Load existing keys
        self.load_key_store().await?;

        self.metrics.record_operation("initialization", start.elapsed()).await;
        Ok(())
    }

    /// Derives master key from password
    #[instrument(skip(self, password))]
    async fn derive_master_key(&self, password: &str) -> Result<Vec<u8>> {
        let start = Instant::now();
        let mut key = vec![0u8; 32];

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(self.config.base.key_derivation.iterations).unwrap(),
            &self.config.master_key_salt,
            password.as_bytes(),
            &mut key,
        );

        self.metrics.record_operation("key_derivation", start.elapsed()).await;
        Ok(key)
    }

    /// Generates a new encryption key
    #[instrument(skip(self, master_key))]
    pub async fn generate_key(&self, master_key: &[u8]) -> Result<EncryptionKey> {
        let start = Instant::now();

        // Generate random key data
        let mut key_data = vec![0u8; 32];
        self.rng.fill(&mut key_data)
            .map_err(|_| EncryptionError::Key("Failed to generate key".into()))?;

        // Create key ID
        let key_id = format!("key_{}", chrono::Utc::now().timestamp());

        // Create key entry
        let key = EncryptionKey {
            data: key_data.clone(),
            id: key_id.clone(),
            created: chrono::Utc::now(),
        };

        // Encrypt key data
        let encrypted_data = self.encrypt_key_data(master_key, &key_data).await?;

        // Store key
        let mut state = self.state.write().await;
        state.active_keys.insert(key_id.clone(), key.clone());
        state.key_store.insert(key_id.clone(), KeyStoreEntry {
            id: key_id,
            encrypted_data,
            created: key.created,
            last_rotated: key.created,
            metadata: HashMap::new(),
        });
        state.stats.keys_generated += 1;

        // Save key store
        self.save_key_store().await?;

        self.metrics.record_operation("key_generation", start.elapsed()).await;
        Ok(key)
    }

    /// Rotates an existing key
    #[instrument(skip(self, master_key))]
    pub async fn rotate_key(&self, key_id: &str, master_key: &[u8]) -> Result<EncryptionKey> {
        let start = Instant::now();

        // Generate new key data
        let mut new_key_data = vec![0u8; 32];
        self.rng.fill(&mut new_key_data)
            .map_err(|_| EncryptionError::Key("Failed to generate key".into()))?;

        // Update key store
        let mut state = self.state.write().await;
        
        if let Some(entry) = state.key_store.get_mut(key_id) {
            // Encrypt new key data
            let encrypted_data = self.encrypt_key_data(master_key, &new_key_data).await?;

            // Update entry
            entry.encrypted_data = encrypted_data;
            entry.last_rotated = chrono::Utc::now();

            // Update active key
            if let Some(key) = state.active_keys.get_mut(key_id) {
                key.data = new_key_data.clone();
            }

            state.stats.keys_rotated += 1;

            // Save key store
            drop(state);
            self.save_key_store().await?;

            self.metrics.record_operation("key_rotation", start.elapsed()).await;
            Ok(EncryptionKey {
                data: new_key_data,
                id: key_id.to_string(),
                created: chrono::Utc::now(),
            })
        } else {
            Err(EncryptionError::Key(format!("Key not found: {}", key_id)))
        }
    }

    /// Encrypts key data with master key
    #[instrument(skip(self, master_key, key_data))]
    async fn encrypt_key_data(&self, master_key: &[u8], key_data: &[u8]) -> Result<Vec<u8>> {
        let start = Instant::now();

        // Create encryption key
        let aead_key = self.base.create_key(master_key)?;

        // Generate nonce
        let nonce = self.base.generate_nonce()?;
        let mut output = nonce.as_ref().to_vec();

        // Encrypt data
        let mut buffer = vec![0u8; key_data.len() + AES_256_GCM.tag_len()];
        buffer[..key_data.len()].copy_from_slice(key_data);

        aead_key.seal_in_place_append_tag(
            nonce,
            Aad::empty(),
            &mut buffer,
        ).map_err(|_| EncryptionError::Encryption("Failed to encrypt key data".into()))?;

        output.extend_from_slice(&buffer);
        self.metrics.record_operation("key_encryption", start.elapsed()).await;
        Ok(output)
    }

    /// Decrypts key data with master key
    #[instrument(skip(self, master_key, encrypted_data))]
    async fn decrypt_key_data(&self, master_key: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let start = Instant::now();

        if encrypted_data.len() < 12 {
            return Err(EncryptionError::Decryption("Invalid data length".into()));
        }

        // Extract nonce
        let nonce = Nonce::try_assume_unique_for_key(&encrypted_data[..12])
            .map_err(|_| EncryptionError::Decryption("Invalid nonce".into()))?;

        // Create decryption key
        let aead_key = self.base.create_key(master_key)?;

        // Decrypt data
        let mut buffer = encrypted_data[12..].to_vec();
        let decrypted_data = aead_key.open_in_place(
            nonce,
            Aad::empty(),
            &mut buffer,
        ).map_err(|_| EncryptionError::Decryption("Failed to decrypt key data".into()))?;

        self.metrics.record_operation("key_decryption", start.elapsed()).await;
        Ok(decrypted_data.to_vec())
    }

    /// Saves key store to disk
    #[instrument(skip(self))]
    async fn save_key_store(&self) -> Result<()> {
        let start = Instant::now();
        let state = self.state.read().await;

        // Serialize key store
        let data = serde_json::to_string(&*state.key_store)
            .map_err(|e| EncryptionError::Key(format!("Failed to serialize key store: {}", e)))?;

        // Write to file
        let store_path = self.config.key_store_path.join("keystore.json");
        fs::write(&store_path, data).await?;

        // Create backup if enabled
        if self.config.enable_backup {
            if let Some(backup_path) = &self.config.backup_path {
                if !backup_path.exists() {
                    fs::create_dir_all(backup_path).await?;
                }
                let backup_file = backup_path.join(format!(
                    "keystore_backup_{}.json",
                    chrono::Utc::now().format("%Y%m%d_%H%M%S")
                ));
                fs::copy(&store_path, backup_file).await?;
            }
        }

        self.metrics.record_operation("key_store_save", start.elapsed()).await;
        Ok(())
    }

    /// Loads key store from disk
    #[instrument(skip(self))]
    async fn load_key_store(&self) -> Result<()> {
        let start = Instant::now();

        let store_path = self.config.key_store_path.join("keystore.json");
        if store_path.exists() {
            // Read file
            let data = fs::read_to_string(&store_path).await?;

            // Deserialize key store
            let key_store: BTreeMap<String, KeyStoreEntry> = serde_json::from_str(&data)
                .map_err(|e| EncryptionError::Key(format!("Failed to deserialize key store: {}", e)))?;

            // Update state
            let mut state = self.state.write().await;
            state.key_store = key_store;
        }

        self.metrics.record_operation("key_store_load", start.elapsed()).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_config() -> KeyManagementConfig {
        let temp_dir = TempDir::new().unwrap();
        KeyManagementConfig {
            base: EncryptionConfig::default(),
            key_store_path: temp_dir.path().to_path_buf(),
            master_key_salt: vec![0u8; 32],
            rotation_interval: Duration::from_secs(86400),
            enable_backup: false,
            backup_path: None,
        }
    }

    #[tokio::test]
    async fn test_key_generation() {
        let key_management = KeyManagement::new(create_test_config());
        let master_key = key_management.derive_master_key("password123").await.unwrap();
        
        let key = key_management.generate_key(&master_key).await.unwrap();
        assert_eq!(key.data.len(), 32);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let key_management = KeyManagement::new(create_test_config());
        let master_key = key_management.derive_master_key("password123").await.unwrap();
        
        let key = key_management.generate_key(&master_key).await.unwrap();
        let rotated_key = key_management.rotate_key(&key.id, &master_key).await.unwrap();
        
        assert_ne!(key.data, rotated_key.data);
    }

    #[tokio::test]
    async fn test_key_store_persistence() {
        let config = create_test_config();
        let key_management = KeyManagement::new(config.clone());
        let master_key = key_management.derive_master_key("password123").await.unwrap();
        
        // Generate and save key
        let key = key_management.generate_key(&master_key).await.unwrap();
        
        // Create new instance and load key store
        let new_key_management = KeyManagement::new(config);
        new_key_management.load_key_store().await.unwrap();
        
        let state = new_key_management.state.read().await;
        assert!(state.key_store.contains_key(&key.id));
    }

    #[tokio::test]
    async fn test_key_encryption() {
        let key_management = KeyManagement::new(create_test_config());
        let master_key = key_management.derive_master_key("password123").await.unwrap();
        let key_data = vec![0u8; 32];
        
        let encrypted = key_management.encrypt_key_data(&master_key, &key_data).await.unwrap();
        let decrypted = key_management.decrypt_key_data(&master_key, &encrypted).await.unwrap();
        
        assert_eq!(key_data, decrypted);
    }

    #[tokio::test]
    async fn test_backup_functionality() {
        let temp_dir = TempDir::new().unwrap();
        let backup_dir = TempDir::new().unwrap();
        
        let config = KeyManagementConfig {
            enable_backup: true,
            backup_path: Some(backup_dir.path().to_path_buf()),
            key_store_path: temp_dir.path().to_path_buf(),
            ..create_test_config()
        };
        
        let key_management = KeyManagement::new(config);
        let master_key = key_management.derive_master_key("password123").await.unwrap();
        
        key_management.generate_key(&master_key).await.unwrap();
        key_management.save_key_store().await.unwrap();
        
        // Verify backup was created
        let backup_files = fs::read_dir(backup_dir.path()).await.unwrap();
        assert!(backup_files.count_files().await.unwrap() > 0);
    }
                                                }
