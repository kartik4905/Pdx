// src/utils/entropy.rs

/// Calculates the Shannon entropy of a byte slice.
/// Useful for detecting randomness in streams or encrypted sections.
pub fn calculate_entropy(data: &[u8]) -> f64 {
    let mut frequencies = [0usize; 256];
    for byte in data {
        frequencies[*byte as usize] += 1;
    }

    let len = data.len() as f64;
    frequencies
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}
