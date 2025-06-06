//! Binary Utilities for PDF Forensics and Sanitization
//! Author: kartik4091

use std::fs::File;
use std::io::{self, Read};

/// Read entire file into a byte buffer
pub fn read_file_bytes(path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Check if buffer contains likely binary (non-printable) data
pub fn is_binary_data(buf: &[u8]) -> bool {
    buf.iter().any(|&b| b == 0 || (b < 9 || (b > 13 && b < 32)))
}
