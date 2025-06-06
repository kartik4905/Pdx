//! Metrics collection for PDF processing pipeline
//! Author: kartik4091
//! Created: 2025-06-05

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;

/// Metrics collector for pipeline operations
pub struct Metrics {
    counters: Arc<RwLock<HashMap<String, u64>>>,
    timers: Arc<RwLock<HashMap<String, Duration>>>,
    gauges: Arc<RwLock<HashMap<String, f64>>>,
    start_times: Arc<RwLock<HashMap<String, Instant>>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            timers: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            start_times: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn increment_counter(&self, name: &str) {
        let mut counters = self.counters.write();
        *counters.entry(name.to_string()).or_insert(0) += 1;
    }

    pub fn set_gauge(&self, name: &str, value: f64) {
        let mut gauges = self.gauges.write();
        gauges.insert(name.to_string(), value);
    }

    pub fn start_timer(&self, name: &str) {
        let mut start_times = self.start_times.write();
        start_times.insert(name.to_string(), Instant::now());
    }

    pub fn end_timer(&self, name: &str) {
        if let Some(start_time) = self.start_times.write().remove(name) {
            let duration = start_time.elapsed();
            let mut timers = self.timers.write();
            timers.insert(name.to_string(), duration);
        }
    }

    pub fn get_counter(&self, name: &str) -> u64 {
        self.counters.read().get(name).copied().unwrap_or(0)
    }

    pub fn get_gauge(&self, name: &str) -> f64 {
        self.gauges.read().get(name).copied().unwrap_or(0.0)
    }

    pub fn get_timer(&self, name: &str) -> Option<Duration> {
        self.timers.read().get(name).copied()
    }

    pub fn reset(&self) {
        self.counters.write().clear();
        self.timers.write().clear();
        self.gauges.write().clear();
        self.start_times.write().clear();
    }

    pub fn get_all_metrics(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            counters: self.counters.read().clone(),
            timers: self.timers.read().clone(),
            gauges: self.gauges.read().clone(),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub counters: HashMap<String, u64>,
    pub timers: HashMap<String, Duration>,
    pub gauges: HashMap<String, f64>,
}