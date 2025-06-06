//! IO Utilities for File and Stream Operations
//! Author: kartik4091

use std::{
    fs::{self, File},
    io::{self, Read, Write, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use tracing::{debug, error, info, instrument, warn};
use crate::error::{Error, Result};

/// Reads the entire contents of a file into a byte vector.
#[instrument]
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Writes a byte slice to a file, creating or overwriting it.
#[instrument]
pub fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
}

/// Appends data to the end of a file.
#[instrument]
pub fn append_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(data)?;
    Ok(())
}

/// Copies content from a reader to a writer using a fixed buffer size.
pub fn copy_stream<R: Read, W: Write>(mut reader: R, mut writer: W) -> Result<u64> {
    let mut buffer = [0u8; 8192];
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 { break; }
        writer.write_all(&buffer[..n])?;
        total += n as u64;
    }

    Ok(total)
}

/// Securely zeroes out a file (overwrite then truncate).
#[instrument]
pub fn secure_erase(path: &Path) -> Result<()> {
    if !path.exists() {
        warn!("File not found for secure erase: {}", path.display());
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    let len = metadata.len();

    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(path)?;

    let zeros = vec![0u8; 8192];
    let mut remaining = len;

    file.seek(SeekFrom::Start(0))?;
    while remaining > 0 {
        let write_len = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..write_len])?;
        remaining -= write_len as u64;
    }

    file.flush()?;
    fs::remove_file(path)?;

    info!("Securely erased file: {}", path.display());
    Ok(())
}

/// Checks if a path is a regular readable file.
pub fn is_readable_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|meta| meta.is_file())
        .unwrap_or(false)
}

/// Ensures parent directory exists for a file path.
pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Renames a file safely (overwriting target if necessary).
pub fn safe_rename(from: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        fs::remove_file(to)?;
    }
    fs::rename(from, to)?;
    Ok(())
}

/// Returns true if path has one of the allowed extensions.
pub fn has_allowed_extension(path: &Path, allowed: &[&str]) -> bool {
    match path.extension() {
        Some(ext) => allowed.iter().any(|e| ext.eq_ignore_ascii_case(*e)),
        None => false,
    }
}
