//! Pattern searching utility for low-level byte pattern detection

/// Find all positions of a pattern in a byte buffer
pub fn find_pattern_positions(buf: &[u8], pattern: &[u8]) -> Vec<usize> {
    buf.windows(pattern.len())
        .enumerate()
        .filter_map(|(i, window)| if window == pattern { Some(i) } else { None })
        .collect()
}
