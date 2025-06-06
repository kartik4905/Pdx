//! Hashing subsystem for PDF anti-forensics
//! Provides secure document fingerprinting, verification, and injection
//! Author: kartik4091
//! Created: 2025-06-03

pub mod handler;

pub use handler::{
    HashHandler,
    HashConfig,
    HashType,
    DocumentHashes,
};
