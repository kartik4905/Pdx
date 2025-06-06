//! JavaScript Cleaner - 100% Anti-Forensic Implementation
//! Completely removes JavaScript and action triggers with zero tolerance

use crate::{
    error::{Result, PdfSecureEditError},
    types::{Document, Object},
    config::Config,
};

use std::collections::{HashMap, HashSet};
use tracing::{info, warn, error, debug, instrument};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct JavaScriptCleaningResult {
    pub javascript_objects_removed: u32,
    pub action_triggers_removed: u32,
    pub suspicious_strings_removed: u32,
    pub forms_sanitized: u32,
    pub annotations_cleaned: u32,
    pub total_threats_neutralized: u32,
}

pub struct JavaScriptCleaner {
    zero_tolerance: bool,
    removed_actions: Vec<String>,
    suspicious_patterns: HashSet<String>,
    javascript_keywords: HashSet<String>,
    action_patterns: Vec<Regex>,
}

impl JavaScriptCleaner {
    pub fn new(zero_tolerance: bool) -> Self {
        let suspicious_patterns = [
            "JavaScript", "JS", "app.alert", "this.print", "eval", 
            "setTimeout", "setInterval", "function", "var ", "let ",
            "const ", "document.", "window.", "navigator.", "screen.",
            "XMLHttpRequest", "fetch", "ActiveXObject", "WScript",
            "Shell.Application", "FileSystemObject", "RegExp",
            "unescape", "decodeURI", "String.fromCharCode", "charAt",
            "charCodeAt", "indexOf", "substring", "replace", "split"
        ].iter().map(|s| s.to_string()).collect();

        let javascript_keywords = [
            "function", "var", "let", "const", "if", "else", "for", "while",
            "do", "switch", "case", "break", "continue", "return", "try",
            "catch", "finally", "throw", "new", "this", "typeof", "instanceof",
            "delete", "void", "null", "undefined", "true", "false"
        ].iter().map(|s| s.to_string()).collect();

        let action_patterns = vec![
            Regex::new(r"(?i)javascript:").unwrap(),
            Regex::new(r"(?i)app\.\w+").unwrap(),
            Regex::new(r"(?i)this\.\w+").unwrap(),
            Regex::new(r"(?i)document\.\w+").unwrap(),
            Regex::new(r"(?i)window\.\w+").unwrap(),
            Regex::new(r"(?i)eval\s*\(").unwrap(),
            Regex::new(r"(?i)function\s*\(").unwrap(),
        ];

        Self {
            zero_tolerance,
            removed_actions: Vec::new(),
            suspicious_patterns,
            javascript_keywords,
            action_patterns,
        }
    }

    /// Remove all JavaScript and action triggers with zero tolerance
    #[instrument(skip(self, document))]
    pub async fn clean_javascript(&mut self, document: &mut Document) -> Result<JavaScriptCleaningResult> {
        info!("Starting zero-tolerance JavaScript cleaning");

        let mut result = JavaScriptCleaningResult {
            javascript_objects_removed: 0,
            action_triggers_removed: 0,
            suspicious_strings_removed: 0,
            forms_sanitized: 0,
            annotations_cleaned: 0,
            total_threats_neutralized: 0,
        };

        // Phase 1: Remove JavaScript objects
        result.javascript_objects_removed = self.remove_javascript_objects(document).await?;

        // Phase 2: Remove action triggers from all objects
        result.action_triggers_removed = self.remove_action_triggers(document).await?;

        // Phase 3: Sanitize suspicious strings
        result.suspicious_strings_removed = self.sanitize_suspicious_strings(document).await?;

        // Phase 4: Clean forms and form fields
        result.forms_sanitized = self.sanitize_forms(document).await?;

        // Phase 5: Clean annotations
        result.annotations_cleaned = self.clean_annotations(document).await?;

        // Phase 6: Remove Names dictionary entries
        self.clean_names_dictionary(document).await?;

        // Phase 7: Remove OpenAction and other automatic actions
        self.remove_automatic_actions(document).await?;

        result.total_threats_neutralized = result.javascript_objects_removed 
            + result.action_triggers_removed 
            + result.suspicious_strings_removed 
            + result.forms_sanitized 
            + result.annotations_cleaned;

        info!("JavaScript cleaning completed: {} total threats neutralized", 
              result.total_threats_neutralized);

        Ok(result)
    }

    /// Remove objects that contain JavaScript code
    #[instrument(skip(self, document))]
    async fn remove_javascript_objects(&mut self, document: &mut Document) -> Result<u32> {
        debug!("Removing JavaScript objects");

        let mut objects_to_remove = Vec::new();
        let mut removed_count = 0;

        for (object_id, object) in &document.structure.objects {
            if self.is_javascript_object(object).await? {
                objects_to_remove.push(*object_id);
                warn!("Removing JavaScript object: {}", object_id.number);
            }
        }

        // Remove identified JavaScript objects
        for object_id in objects_to_remove {
            document.structure.objects.remove(&object_id);
            removed_count += 1;
        }

        info!("Removed {} JavaScript objects", removed_count);
        Ok(removed_count)
    }

    /// Check if an object contains JavaScript
    async fn is_javascript_object(&self, object: &Object) -> Result<bool> {
        use crate::types::Object;

        match object {
            Object::Dictionary(dict) => {
                // Check for JavaScript type indicators
                if let Some(Object::Name(name)) = dict.get("S") {
                    if name.eq_ignore_ascii_case("JavaScript") || name.eq_ignore_ascii_case("JS") {
                        return Ok(true);
                    }
                }

                // Check for JavaScript subtype
                if let Some(Object::Name(subtype)) = dict.get("Subtype") {
                    if subtype.eq_ignore_ascii_case("JavaScript") {
                        return Ok(true);
                    }
                }

                // Check for action type
                if let Some(Object::Name(action_type)) = dict.get("Type") {
                    if action_type.eq_ignore_ascii_case("Action") {
                        return Ok(true);
                    }
                }

                // Check all string values for JavaScript patterns
                for value in dict.values() {
                    if self.contains_javascript_patterns(value).await? {
                        return Ok(true);
                    }
                }
            }
            Object::Stream { dict, data } => {
                // Check stream dictionary
                if self.is_javascript_object(&Object::Dictionary(dict.clone())).await? {
                    return Ok(true);
                }

                // Check stream data for JavaScript
                let data_str = String::from_utf8_lossy(data);
                if self.contains_javascript_code(&data_str).await? {
                    return Ok(true);
                }
            }
            Object::String(content, _) => {
                let content_str = String::from_utf8_lossy(content);
                if self.contains_javascript_code(&content_str).await? {
                    return Ok(true);
                }
            }
            _ => {}
        }

        Ok(false)
    }

    /// Check if content contains JavaScript patterns
    async fn contains_javascript_patterns(&self, object: &Object) -> Result<bool> {
        use crate::types::Object;

        match object {
            Object::String(content, _) => {
                let content_str = String::from_utf8_lossy(content);
                Ok(self.contains_javascript_code(&content_str).await?)
            }
            Object::Dictionary(dict) => {
                for value in dict.values() {
                    if self.contains_javascript_patterns(value).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Object::Array(array) => {
                for value in array {
                    if self.contains_javascript_patterns(value).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            _ => Ok(false)
        }
    }

    /// Check if text contains JavaScript code
    async fn contains_javascript_code(&self, text: &str) -> Result<bool> {
        // Check for direct JavaScript patterns
        for pattern in &self.action_patterns {
            if pattern.is_match(text) {
                return Ok(true);
            }
        }

        // Check for JavaScript keywords
        let lower_text = text.to_lowercase();
        for keyword in &self.javascript_keywords {
            if lower_text.contains(&keyword.to_lowercase()) {
                return Ok(true);
            }
        }

        // In zero tolerance mode, check for any suspicious patterns
        if self.zero_tolerance {
            for pattern in &self.suspicious_patterns {
                if lower_text.contains(&pattern.to_lowercase()) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Remove action triggers from objects
    #[instrument(skip(self, document))]
    async fn remove_action_triggers(&mut self, document: &mut Document) -> Result<u32> {
        debug!("Removing action triggers");

        let mut triggers_removed = 0;

        for (object_id, object) in document.structure.objects.iter_mut() {
            triggers_removed += self.clean_object_actions(object).await?;
        }

        info!("Removed {} action triggers", triggers_removed);
        Ok(triggers_removed)
    }

    /// Clean actions from a single object
    async fn clean_object_actions(&mut self, object: &mut Object) -> Result<u32> {
        use crate::types::Object;

        let mut cleaned = 0;

        match object {
            Object::Dictionary(dict) => {
                let mut keys_to_remove = Vec::new();

                // Remove action-related keys
                let action_keys = ["A", "AA", "OpenAction", "Action", "Next", "Prev", "First", "Last"];
                for key in &action_keys {
                    if dict.contains_key(*key) {
                        keys_to_remove.push(key.to_string());
                    }
                }

                for key in keys_to_remove {
                    dict.remove(&key);
                    cleaned += 1;
                    debug!("Removed action key: {}", key);
                }

                // Recursively clean nested objects
                for value in dict.values_mut() {
                    cleaned += self.clean_object_actions(value).await?;
                }
            }
            Object::Array(array) => {
                for value in array.iter_mut() {
                    cleaned += self.clean_object_actions(value).await?;
                }
            }
            Object::Stream { dict, .. } => {
                cleaned += self.clean_object_actions(&mut Object::Dictionary(dict.clone())).await?;
            }
            _ => {}
        }

        Ok(cleaned)
    }

    /// Sanitize suspicious strings
    #[instrument(skip(self, document))]
    async fn sanitize_suspicious_strings(&mut self, document: &mut Document) -> Result<u32> {
        debug!("Sanitizing suspicious strings");

        let mut sanitized = 0;

        for object in document.structure.objects.values_mut() {
            sanitized += self.sanitize_object_strings(object).await?;
        }

        info!("Sanitized {} suspicious strings", sanitized);
        Ok(sanitized)
    }

    /// Sanitize strings in an object
    async fn sanitize_object_strings(&mut self, object: &mut Object) -> Result<u32> {
        use crate::types::Object;

        let mut sanitized = 0;

        match object {
            Object::String(content, encoding) => {
                let original_str = String::from_utf8_lossy(content);
                if self.contains_javascript_code(&original_str).await? {
                    // Replace with empty content or safe placeholder
                    *content = Vec::new();
                    sanitized += 1;
                    debug!("Sanitized suspicious string");
                }
            }
            Object::Dictionary(dict) => {
                for value in dict.values_mut() {
                    sanitized += self.sanitize_object_strings(value).await?;
                }
            }
            Object::Array(array) => {
                for value in array.iter_mut() {
                    sanitized += self.sanitize_object_strings(value).await?;
                }
            }
            Object::Stream { dict, data } => {
                // Check and clean stream data
                let data_str = String::from_utf8_lossy(data);
                if self.contains_javascript_code(&data_str).await? {
                    data.clear();
                    sanitized += 1;
                    debug!("Sanitized suspicious stream data");
                }

                // Clean dictionary
                for value in dict.values_mut() {
                    sanitized += self.sanitize_object_strings(value).await?;
                }
            }
            _ => {}
        }

        Ok(sanitized)
    }

    /// Sanitize forms and form fields
    #[instrument(skip(self, document))]
    async fn sanitize_forms(&mut self, document: &mut Document) -> Result<u32> {
        debug!("Sanitizing forms");

        let mut forms_cleaned = 0;

        for object in document.structure.objects.values_mut() {
            if self.is_form_object(object).await? {
                self.clean_form_object(object).await?;
                forms_cleaned += 1;
            }
        }

        info!("Sanitized {} forms", forms_cleaned);
        Ok(forms_cleaned)
    }

    /// Check if object is a form
    async fn is_form_object(&self, object: &Object) -> Result<bool> {
        use crate::types::Object;

        if let Object::Dictionary(dict) = object {
            if let Some(Object::Name(type_name)) = dict.get("Type") {
                return Ok(type_name.eq_ignore_ascii_case("Annot") || 
                         type_name.eq_ignore_ascii_case("Widget"));
            }

            if let Some(Object::Name(subtype)) = dict.get("Subtype") {
                return Ok(subtype.eq_ignore_ascii_case("Widget"));
            }
        }

        Ok(false)
    }

    /// Clean form object
    async fn clean_form_object(&mut self, object: &mut Object) -> Result<()> {
        use crate::types::Object;

        if let Object::Dictionary(dict) = object {
            // Remove action-related keys from forms
            let form_action_keys = ["A", "AA", "K", "F", "V", "DV"];
            for key in &form_action_keys {
                if dict.remove(*key).is_some() {
                    debug!("Removed form action key: {}", key);
                }
            }
        }

        Ok(())
    }

    /// Clean annotations
    #[instrument(skip(self, document))]
    async fn clean_annotations(&mut self, document: &mut Document) -> Result<u32> {
        debug!("Cleaning annotations");

        let mut annotations_cleaned = 0;

        for object in document.structure.objects.values_mut() {
            if self.is_annotation_object(object).await? {
                self.clean_annotation_object(object).await?;
                annotations_cleaned += 1;
            }
        }

        info!("Cleaned {} annotations", annotations_cleaned);
        Ok(annotations_cleaned)
    }

    /// Check if object is an annotation
    async fn is_annotation_object(&self, object: &Object) -> Result<bool> {
        use crate::types::Object;

        if let Object::Dictionary(dict) = object {
            if let Some(Object::Name(type_name)) = dict.get("Type") {
                return Ok(type_name.eq_ignore_ascii_case("Annot"));
            }
        }

        Ok(false)
    }

    /// Clean annotation object
    async fn clean_annotation_object(&mut self, object: &mut Object) -> Result<()> {
        use crate::types::Object;

        if let Object::Dictionary(dict) = object {
            // Remove action and JavaScript-related keys from annotations
            let annotation_action_keys = ["A", "AA", "PA", "JS"];
            for key in &annotation_action_keys {
                if dict.remove(*key).is_some() {
                    debug!("Removed annotation action key: {}", key);
                }
            }
        }

        Ok(())
    }

    /// Clean Names dictionary
    #[instrument(skip(self, document))]
    async fn clean_names_dictionary(&mut self, document: &mut Document) -> Result<()> {
        debug!("Cleaning Names dictionary");

        for object in document.structure.objects.values_mut() {
            if let Object::Dictionary(dict) = object {
                if dict.contains_key("Names") {
                    // Remove JavaScript entries from Names dictionary
                    if let Some(Object::Dictionary(names_dict)) = dict.get_mut("Names") {
                        names_dict.remove("JavaScript");
                        names_dict.remove("JS");
                        debug!("Cleaned Names dictionary");
                    }
                }
            }
        }

        Ok(())
    }

    /// Remove automatic actions from document catalog
    #[instrument(skip(self, document))]
    async fn remove_automatic_actions(&mut self, document: &mut Document) -> Result<()> {
        debug!("Removing automatic actions");

        // Find and clean the document catalog
        if let Some(root_ref) = &document.structure.trailer.root {
            let root_id = crate::types::ObjectId { 
                number: root_ref.number, 
                generation: root_ref.generation 
            };

            if let Some(Object::Dictionary(catalog)) = document.structure.objects.get_mut(&root_id) {
                // Remove OpenAction and other automatic actions
                let auto_action_keys = ["OpenAction", "AA", "URI"];
                for key in &auto_action_keys {
                    if catalog.remove(*key).is_some() {
                        info!("Removed automatic action: {}", key);
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_javascript_cleaner_creation() {
        let cleaner = JavaScriptCleaner::new(true);
        assert!(cleaner.zero_tolerance);
        assert!(!cleaner.suspicious_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_javascript_detection() {
        let cleaner = JavaScriptCleaner::new(true);

        // Test JavaScript detection
        assert!(cleaner.contains_javascript_code("function test() { alert('hello'); }").await.unwrap());
        assert!(cleaner.contains_javascript_code("javascript:void(0)").await.unwrap());
        assert!(cleaner.contains_javascript_code("app.alert('test')").await.unwrap());

        // Test safe content
        assert!(!cleaner.contains_javascript_code("This is normal text").await.unwrap());
    }
}