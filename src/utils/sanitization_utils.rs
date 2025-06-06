//! Generic sanitization functions for content filtering

/// Remove null bytes from input data
pub fn strip_null_bytes(data: &[u8]) -> Vec<u8> {
    data.iter().cloned().filter(|&b| b != 0).collect()
}
