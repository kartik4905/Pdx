
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateContext {
    pub variables: HashMap<String, TemplateValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Array(Vec<TemplateValue>),
    Object(HashMap<String, TemplateValue>),
}

pub struct TemplateEngine {
    templates: HashMap<String, String>,
}

impl TemplateEngine {
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }

    pub fn register_template(&mut self, name: String, template: String) {
        self.templates.insert(name, template);
    }

    pub fn render(&self, template_name: &str, context: &TemplateContext) -> Result<String> {
        let template = self.templates.get(template_name)
            .ok_or_else(|| crate::error::PipelineError::Configuration(
                format!("Template '{}' not found", template_name)
            ))?;

        let mut result = template.clone();
        
        for (key, value) in &context.variables {
            let placeholder = format!("{{{{{}}}}}", key);
            let replacement = self.format_value(value);
            result = result.replace(&placeholder, &replacement);
        }

        Ok(result)
    }

    fn format_value(&self, value: &TemplateValue) -> String {
        match value {
            TemplateValue::String(s) => s.clone(),
            TemplateValue::Number(n) => n.to_string(),
            TemplateValue::Boolean(b) => b.to_string(),
            TemplateValue::Array(arr) => {
                let items: Vec<String> = arr.iter()
                    .map(|v| self.format_value(v))
                    .collect();
                format!("[{}]", items.join(", "))
            }
            TemplateValue::Object(obj) => {
                let items: Vec<String> = obj.iter()
                    .map(|(k, v)| format!("{}: {}", k, self.format_value(v)))
                    .collect();
                format!("{{{}}}", items.join(", "))
            }
        }
    }

    pub fn get_default_templates() -> HashMap<String, String> {
        let mut templates = HashMap::new();
        
        templates.insert("scan_report".to_string(), 
            "PDF Anti-Forensics Scan Report\n\
             ================================\n\
             Document: {{document_name}}\n\
             Scan Date: {{scan_date}}\n\
             Risk Score: {{risk_score}}\n\
             \n\
             Issues Found: {{total_issues}}\n\
             {{#issues}}\n\
             - {{severity}}: {{description}}\n\
             {{/issues}}\n".to_string());

        templates.insert("cleaning_report".to_string(),
            "PDF Cleaning Report\n\
             ===================\n\
             Original File: {{original_file}}\n\
             Cleaned File: {{cleaned_file}}\n\
             Processing Time: {{processing_time}}ms\n\
             \n\
             Actions Performed:\n\
             {{#actions}}\n\
             - {{action}}\n\
             {{/actions}}\n".to_string());

        templates
    }
}

impl Default for TemplateEngine {
    fn default() -> Self {
        let mut engine = Self::new();
        let default_templates = Self::get_default_templates();
        
        for (name, template) in default_templates {
            engine.register_template(name, template);
        }
        
        engine
    }
}

impl TemplateContext {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: String, value: TemplateValue) {
        self.variables.insert(key, value);
    }

    pub fn insert_string(&mut self, key: String, value: String) {
        self.variables.insert(key, TemplateValue::String(value));
    }

    pub fn insert_number(&mut self, key: String, value: f64) {
        self.variables.insert(key, TemplateValue::Number(value));
    }

    pub fn insert_boolean(&mut self, key: String, value: bool) {
        self.variables.insert(key, TemplateValue::Boolean(value));
    }
}
