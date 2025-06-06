
pub mod integration;
pub mod unit;
pub mod fixtures;

use std::path::PathBuf;

pub fn get_test_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("data")
}

pub fn get_test_pdf_path(filename: &str) -> PathBuf {
    get_test_data_dir().join(filename)
}
