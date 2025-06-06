//! Report formatter implementation
//! Author: kartik4091
//! Created: 2025-06-05

use super::{ReportData, ReportError, ReportFormat};

/// Formats report data into various output formats
pub struct ReportFormatter;

impl ReportFormatter {
    pub fn format(data: &ReportData, format: ReportFormat) -> Result<String, ReportError> {
        match format {
            ReportFormat::PlainText => Self::to_text(data),
            ReportFormat::Json => Self::to_json(data),
            ReportFormat::Html => Self::to_html(data),
            ReportFormat::Markdown => Self::to_markdown(data),
        }
    }

    fn to_text(data: &ReportData) -> Result<String, ReportError> {
        let mut output = String::new();
        output.push_str("PDF Anti-Forensics Report\n");
        output.push_str("========================\n\n");
        
        for entry in &data.entries {
            output.push_str(&format!("{}: {} - {}\n", 
                entry.timestamp, entry.category, entry.message));
        }
        
        Ok(output)
    }

    fn to_json(data: &ReportData) -> Result<String, ReportError> {
        serde_json::to_string_pretty(data)
            .map_err(|e| ReportError::SerializationError(e.to_string()))
    }

    fn to_html(data: &ReportData) -> Result<String, ReportError> {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html><html><body>");
        html.push_str("<h1>PDF Anti-Forensics Report</h1>");
        
        for entry in &data.entries {
            html.push_str(&format!("<p>{}: {}</p>", entry.category, entry.message));
        }
        
        html.push_str("</body></html>");
        Ok(html)
    }

    fn to_markdown(data: &ReportData) -> Result<String, ReportError> {
        let mut md = String::new();
        md.push_str("# PDF Anti-Forensics Report\n\n");
        
        for entry in &data.entries {
            md.push_str(&format!("- **{}**: {}\n", entry.category, entry.message));
        }
        
        Ok(md)
    }
}