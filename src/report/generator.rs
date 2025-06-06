//! Report generator implementation
//! Author: kartik4091
//! Created: 2025-06-05

use crate::error::Result;
use crate::pipeline::Pipeline;
use super::{ReportConfig, ReportData, ReportError, ReportFormat};
use std::fs;
use tokio::fs as async_fs;

/// Generates reports from pipeline execution data
pub struct ReportGenerator;

impl ReportGenerator {
    pub async fn generate_from_pipeline(pipeline: &Pipeline, config: &ReportConfig) -> Result<(), ReportError> {
        let report_data = pipeline.get_report_data();
        Self::generate(report_data, config).await
    }

    pub async fn generate(data: &ReportData, config: &ReportConfig) -> Result<(), ReportError> {
        let content = match config.format {
            ReportFormat::PlainText => Self::format_as_text(data)?,
            ReportFormat::Json => Self::format_as_json(data)?,
            ReportFormat::Html => Self::format_as_html(data)?,
            ReportFormat::Markdown => Self::format_as_markdown(data)?,
        };

        async_fs::write(&config.output_path, content).await?;
        Ok(())
    }

    fn format_as_text(data: &ReportData) -> Result<String, ReportError> {
        let mut content = String::new();
        content.push_str("PDF Anti-Forensics Pipeline Report\n");
        content.push_str("===================================\n\n");
        
        content.push_str(&format!("Generated: {}\n", 
            data.metadata.generation_time.as_deref().unwrap_or("Unknown")));
        content.push_str(&format!("Pipeline Version: {}\n", data.metadata.pipeline_version));
        content.push_str(&format!("Total Entries: {}\n\n", data.metadata.total_entries));
        
        content.push_str("Summary:\n");
        content.push_str(&format!("- Info: {}\n", data.metadata.summary.info_count));
        content.push_str(&format!("- Warnings: {}\n", data.metadata.summary.warning_count));
        content.push_str(&format!("- Errors: {}\n", data.metadata.summary.error_count));
        content.push_str(&format!("- Critical: {}\n\n", data.metadata.summary.critical_count));
        
        content.push_str("Entries:\n");
        content.push_str("--------\n");
        for entry in &data.entries {
            content.push_str(&format!("[{}] {} - {}: {}\n", 
                entry.timestamp, 
                format!("{:?}", entry.severity),
                entry.category,
                entry.message
            ));
        }
        
        Ok(content)
    }

    fn format_as_json(data: &ReportData) -> Result<String, ReportError> {
        serde_json::to_string_pretty(data)
            .map_err(|e| ReportError::SerializationError(e.to_string()))
    }

    fn format_as_html(data: &ReportData) -> Result<String, ReportError> {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html><head><title>PDF Anti-Forensics Report</title></head><body>\n");
        html.push_str("<h1>PDF Anti-Forensics Pipeline Report</h1>\n");
        html.push_str("<table border='1'>\n");
        html.push_str("<tr><th>Timestamp</th><th>Severity</th><th>Category</th><th>Message</th></tr>\n");
        
        for entry in &data.entries {
            html.push_str(&format!("<tr><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td></tr>\n",
                entry.timestamp, entry.severity, entry.category, entry.message));
        }
        
        html.push_str("</table>\n</body></html>");
        Ok(html)
    }

    fn format_as_markdown(data: &ReportData) -> Result<String, ReportError> {
        let mut md = String::new();
        md.push_str("# PDF Anti-Forensics Pipeline Report\n\n");
        md.push_str("## Summary\n\n");
        md.push_str(&format!("- **Total Entries**: {}\n", data.metadata.total_entries));
        md.push_str(&format!("- **Info**: {}\n", data.metadata.summary.info_count));
        md.push_str(&format!("- **Warnings**: {}\n", data.metadata.summary.warning_count));
        md.push_str(&format!("- **Errors**: {}\n", data.metadata.summary.error_count));
        md.push_str(&format!("- **Critical**: {}\n\n", data.metadata.summary.critical_count));
        
        md.push_str("## Entries\n\n");
        md.push_str("| Timestamp | Severity | Category | Message |\n");
        md.push_str("|-----------|----------|----------|----------|\n");
        
        for entry in &data.entries {
            md.push_str(&format!("| {} | {:?} | {} | {} |\n",
                entry.timestamp, entry.severity, entry.category, entry.message));
        }
        
        Ok(md)
    }
}