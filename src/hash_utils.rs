//! Hash Utilities for PDF Forensics
//! Provides secure content hashing for verification, fingerprints, or integrity
//! Author: kartik4091
//! Created: 2025-06-04

use std::io::{Read, Cursor};
use std::fs::File;
use std::path::Path;
use std::fmt;

use sha2::{Sha256, Sha512, Digest as ShaDigest};
use blake2::{Blake2b512, Blake2s256};
use ripemd160::Ripemd160;
use hex;

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    SHA256,
    SHA512,
    BLAKE2b,
    BLAKE2s,
    RIPEMD160,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HashAlgorithm::SHA256 => "SHA256",
            HashAlgorithm::SHA512 => "SHA512",
            HashAlgorithm::BLAKE2b => "BLAKE2b",
            HashAlgorithm::BLAKE2s => "BLAKE2s",
            HashAlgorithm::RIPEMD160 => "RIPEMD160",
        };
        write!(f, "{}", name)
    }
}

/// Hash result (digest + algorithm)
#[derive(Debug, Clone)]
pub struct HashResult {
    pub algorithm: HashAlgorithm,
    pub digest: String,
}

/// Hashes a byte slice
pub fn hash_bytes(data: &[u8], algo: HashAlgorithm) -> HashResult {
    let digest = match algo {
        HashAlgorithm::SHA256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::SHA512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::BLAKE2b => {
            let mut hasher = Blake2b512::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::BLAKE2s => {
            let mut hasher = Blake2s256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::RIPEMD160 => {
            let mut hasher = Ripemd160::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
    };

    HashResult { algorithm: algo, digest }
}

/// Hashes file content at given path
pub fn hash_file(path: &Path, algo: HashAlgorithm) -> Result<HashResult, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(hash_bytes(&buffer, algo))
}

/// Hashes using the default algorithm (SHA256)
pub fn hash_default(data: &[u8]) -> HashResult {
    hash_bytes(data, HashAlgorithm::SHA256)
}

/// Verifies content hash matches the expected value
pub fn verify_hash(data: &[u8], expected: &str, algo: HashAlgorithm) -> bool {
    hash_bytes(data, algo).digest.eq_ignore_ascii_case(expected)
}

/// Verifies file hash
pub fn verify_file_hash(path: &Path, expected: &str, algo: HashAlgorithm) -> Result<bool, std::io::Error> {
    Ok(hash_file(path, algo)?.digest.eq_ignore_ascii_case(expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hashing() {
        let input = b"forensic test";
        let result = hash_bytes(input, HashAlgorithm::SHA256);
        assert_eq!(result.algorithm, HashAlgorithm::SHA256);
        assert_eq!(result.digest.len(), 64);
    }

    #[test]
    fn test_ripemd160_hashing() {
        let input = b"forensic test";
        let result = hash_bytes(input, HashAlgorithm::RIPEMD160);
        assert_eq!(result.algorithm, HashAlgorithm::RIPEMD160);
        assert_eq!(result.digest.len(), 40);
    }

    #[test]
    fn test_verify_correct_hash() {
        let input = b"integrity";
        let hash = hash_bytes(input, HashAlgorithm::SHA256);
        assert!(verify_hash(input, &hash.digest, HashAlgorithm::SHA256));
    }

    #[test]
    fn test_verify_incorrect_hash() {
        let input = b"tampered";
        let wrong = "abcdef123456";
        assert!(!verify_hash(input, wrong, HashAlgorithm::SHA256));
    }
}
