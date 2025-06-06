//! Cryptographic Utilities for Secure Operations
//! Author: kartik4091

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha256, Sha512, Digest};

use std::io::{self, Read, Write};
use std::path::Path;
use std::fs::File;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type HmacSha256 = Hmac<Sha256>;

const PBKDF2_ITERATIONS: u32 = 100_000;
const AES_BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const IV_SIZE: usize = 16;

/// Generates a cryptographically secure random IV
pub fn generate_iv() -> [u8; IV_SIZE] {
    let mut iv = [0u8; IV_SIZE];
    OsRng.fill_bytes(&mut iv);
    iv
}

/// Derives a 256-bit key from a password using PBKDF2
pub fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    pbkdf2::<HmacSha256>(password, salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypts data using AES-256-CBC
pub fn encrypt_aes_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Cbc::new_from_slices(key, iv)?;
    Ok(cipher.encrypt_vec(data))
}

/// Decrypts data using AES-256-CBC
pub fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Cbc::new_from_slices(key, iv)?;
    cipher.decrypt_vec(ciphertext).map_err(|_| Error::DecryptionFailed)
}

/// Calculates SHA-256 hash
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calculates SHA-512 hash
pub fn sha512_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Performs constant-time comparison to prevent timing attacks
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).unwrap_u8() == 1
}

/// Encrypts a file using AES-256-CBC and writes to output path
pub fn encrypt_file(input: &Path, output: &Path, key: &[u8], iv: &[u8]) -> Result<()> {
    let mut infile = File::open(input)?;
    let mut outfile = File::create(output)?;
    let mut buffer = Vec::new();

    infile.read_to_end(&mut buffer)?;
    let encrypted = encrypt_aes_cbc(&buffer, key, iv)?;
    outfile.write_all(&encrypted)?;
    Ok(())
}

/// Decrypts a file using AES-256-CBC and writes to output path
pub fn decrypt_file(input: &Path, output: &Path, key: &[u8], iv: &[u8]) -> Result<()> {
    let mut infile = File::open(input)?;
    let mut outfile = File::create(output)?;
    let mut buffer = Vec::new();

    infile.read_to_end(&mut buffer)?;
    let decrypted = decrypt_aes_cbc(&buffer, key, iv)?;
    outfile.write_all(&decrypted)?;
    Ok(())
}

/// Tests encryption-decryption round trip
pub fn test_encryption_cycle(data: &[u8], password: &[u8], salt: &[u8]) -> Result<bool> {
    let key = derive_key(password, salt);
    let iv = generate_iv();

    let encrypted = encrypt_aes_cbc(data, &key, &iv)?;
    let decrypted = decrypt_aes_cbc(&encrypted, &key, &iv)?;
    Ok(secure_compare(data, &decrypted))
}
