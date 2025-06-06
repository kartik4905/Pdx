//! Progress reporting for structural analysis

use std::sync::{Arc, Mutex};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisStage {
    Setup,
    Objects,
    Streams,
    References,
    Validation,
    Complete,
}

impl fmt::Display for AnalysisStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalysisStage::Setup => write!(f, "Setup"),
            AnalysisStage::Objects => write!(f, "Object Analysis"),
            AnalysisStage::Streams => write!(f, "Stream Analysis"),
            AnalysisStage::References => write!(f, "Reference Validation"),
            AnalysisStage::Validation => write!(f, "Final Validation"),
            AnalysisStage::Complete => write!(f, "Complete"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    pub stage: AnalysisStage,
    pub completed: usize,
    pub total: usize,
}

pub type ProgressCallback = Arc<Mutex<Box<dyn FnMut(ProgressUpdate) + Send>>>;
