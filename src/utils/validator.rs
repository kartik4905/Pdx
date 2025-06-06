//! Validators for input files and document structure

use std::path::Path;

/// Check if a given path points to a valid `.pdf` file
pub fn is_valid_pdf(path: &str) -> bool {
    Path::new(path)
        .extension()
        .map(|ext| ext.eq_ignore_ascii_case("pdf"))
        .unwrap_or(false)
}
