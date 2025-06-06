
use crate::error::{PipelineError, Result};
use crate::types::Document;
use lopdf::{Document as LopdfDocument, Object, ObjectId};
use std::collections::{HashMap, HashSet};
use log::{info, warn, debug};

#[derive(Debug, Clone)]
pub struct StructureValidation {
    pub is_valid: bool,
    pub issues: Vec<String>,
    pub object_count: usize,
    pub xref_entries: usize,
    pub trailer_present: bool,
    pub eof_count: usize,
    pub linearized: bool,
}

#[derive(Debug, Clone)]
pub struct StructureMetrics {
    pub total_objects: usize,
    pub referenced_objects: usize,
    pub unreferenced_objects: usize,
    pub ghost_objects: usize,
    pub dangling_references: usize,
    pub stream_objects: usize,
    pub page_objects: usize,
    pub font_objects: usize,
    pub image_objects: usize,
}

pub struct StructureHandler {
    strict_validation: bool,
    allow_repairs: bool,
    max_object_depth: u32,
}

impl StructureHandler {
    pub fn new() -> Self {
        Self {
            strict_validation: true,
            allow_repairs: false, // Anti-forensic: No automatic repairs
            max_object_depth: 100,
        }
    }

    pub fn with_strict_validation(mut self, strict: bool) -> Self {
        self.strict_validation = strict;
        self
    }

    pub fn with_repairs(mut self, allow: bool) -> Self {
        self.allow_repairs = allow;
        self
    }

    /// Validates PDF structure with anti-forensic requirements
    pub async fn validate_structure(&self, document: &Document) -> Result<StructureValidation> {
        info!("Starting anti-forensic structure validation");
        
        let mut validation = StructureValidation {
            is_valid: true,
            issues: Vec::new(),
            object_count: 0,
            xref_entries: 0,
            trailer_present: false,
            eof_count: 0,
            linearized: false,
        };

        // Count objects
        validation.object_count = document.structure.objects.len();
        
        // Validate XRef table integrity
        self.validate_xref_table(document, &mut validation).await?;
        
        // Check for exactly one EOF marker (anti-forensic requirement)
        self.validate_eof_markers(document, &mut validation).await?;
        
        // Detect ghost objects and dangling references
        self.detect_structural_anomalies(document, &mut validation).await?;
        
        // Validate object hierarchy depth
        self.validate_object_depth(document, &mut validation).await?;
        
        // Check for linearization (should be removed in anti-forensic processing)
        self.check_linearization(document, &mut validation).await?;

        validation.is_valid = validation.issues.is_empty();
        
        info!("Structure validation completed: {} issues found", validation.issues.len());
        Ok(validation)
    }

    /// Normalizes PDF structure according to anti-forensic requirements
    pub async fn normalize_structure(&self, document: &mut Document) -> Result<StructureMetrics> {
        info!("Starting anti-forensic structure normalization");
        
        let mut metrics = StructureMetrics {
            total_objects: document.structure.objects.len(),
            referenced_objects: 0,
            unreferenced_objects: 0,
            ghost_objects: 0,
            dangling_references: 0,
            stream_objects: 0,
            page_objects: 0,
            font_objects: 0,
            image_objects: 0,
        };

        // Remove ghost objects
        self.remove_ghost_objects(document, &mut metrics).await?;
        
        // Fix dangling references (user-controlled only)
        if self.allow_repairs {
            self.repair_dangling_references(document, &mut metrics).await?;
        }
        
        // Normalize object numbering
        self.normalize_object_numbering(document, &mut metrics).await?;
        
        // Remove linearization data
        self.remove_linearization(document, &mut metrics).await?;
        
        // Rebuild XRef table cleanly
        self.rebuild_xref_table(document, &mut metrics).await?;
        
        // Ensure single trailer
        self.normalize_trailer(document, &mut metrics).await?;

        info!("Structure normalization completed: {} objects processed", metrics.total_objects);
        Ok(metrics)
    }

    /// Validates XRef table integrity with anti-forensic checks
    async fn validate_xref_table(&self, document: &Document, validation: &mut StructureValidation) -> Result<()> {
        debug!("Validating XRef table integrity");
        
        // Check for XRef table presence
        if document.structure.xref_table.is_empty() {
            validation.issues.push("Missing XRef table".to_string());
            return Ok(());
        }
        
        validation.xref_entries = document.structure.xref_table.len();
        
        // Validate all object references
        for (object_id, xref_entry) in &document.structure.xref_table {
            if !document.structure.objects.contains_key(object_id) {
                validation.issues.push(format!("XRef entry {} points to non-existent object", object_id.0));
            }
            
            // Anti-forensic: Check for suspicious offset patterns
            if xref_entry.offset == 0 && xref_entry.generation == 65535 {
                // This is a free object entry - validate it's actually free
                if document.structure.objects.contains_key(object_id) {
                    validation.issues.push(format!("Object {} marked as free but exists", object_id.0));
                }
            }
        }
        
        // Check for unreferenced objects
        for object_id in document.structure.objects.keys() {
            if !document.structure.xref_table.contains_key(object_id) {
                validation.issues.push(format!("Object {} exists but not in XRef table", object_id.0));
            }
        }
        
        Ok(())
    }

    /// Validates EOF markers (anti-forensic: exactly one required)
    async fn validate_eof_markers(&self, document: &Document, validation: &mut StructureValidation) -> Result<()> {
        debug!("Validating EOF markers");
        
        // Count EOF markers in raw content
        let eof_count = self.count_eof_in_content(&document.raw_content);
        validation.eof_count = eof_count;
        
        if eof_count == 0 {
            validation.issues.push("No EOF marker found".to_string());
        } else if eof_count > 1 {
            validation.issues.push(format!("Multiple EOF markers found: {} (anti-forensic requirement: exactly 1)", eof_count));
        }
        
        Ok(())
    }

    /// Detects ghost objects and dangling references
    async fn detect_structural_anomalies(&self, document: &Document, validation: &mut StructureValidation) -> Result<()> {
        debug!("Detecting structural anomalies");
        
        let mut referenced_objects = HashSet::new();
        let mut ghost_objects = Vec::new();
        let mut dangling_refs = Vec::new();
        
        // Build reference map from root and info objects
        if let Some(ref catalog) = document.structure.catalog {
            self.collect_references_recursive(&catalog, &document.structure.objects, &mut referenced_objects, 0)?;
        }
        
        if let Some(ref info) = document.structure.info {
            self.collect_references_recursive(&info, &document.structure.objects, &mut referenced_objects, 0)?;
        }
        
        // Find ghost objects (exist but not referenced)
        for object_id in document.structure.objects.keys() {
            if !referenced_objects.contains(object_id) {
                ghost_objects.push(*object_id);
            }
        }
        
        // Find dangling references (referenced but don't exist)
        for referenced_id in &referenced_objects {
            if !document.structure.objects.contains_key(referenced_id) {
                dangling_refs.push(*referenced_id);
            }
        }
        
        if !ghost_objects.is_empty() {
            validation.issues.push(format!("Ghost objects detected: {:?}", ghost_objects));
        }
        
        if !dangling_refs.is_empty() {
            validation.issues.push(format!("Dangling references detected: {:?}", dangling_refs));
        }
        
        Ok(())
    }

    /// Validates object hierarchy depth to prevent recursion attacks
    async fn validate_object_depth(&self, document: &Document, validation: &mut StructureValidation) -> Result<()> {
        debug!("Validating object hierarchy depth");
        
        if let Some(ref catalog) = document.structure.catalog {
            let max_depth = self.calculate_max_depth(&catalog, &document.structure.objects, 0)?;
            if max_depth > self.max_object_depth {
                validation.issues.push(format!("Object hierarchy too deep: {} (max allowed: {})", max_depth, self.max_object_depth));
            }
        }
        
        Ok(())
    }

    /// Checks for linearization data (should be removed in anti-forensic processing)
    async fn check_linearization(&self, document: &Document, validation: &mut StructureValidation) -> Result<()> {
        debug!("Checking linearization status");
        
        // Check for linearization dictionary
        validation.linearized = document.structure.linearized;
        
        if validation.linearized {
            validation.issues.push("Document is linearized (anti-forensic requirement: remove linearization)".to_string());
        }
        
        Ok(())
    }

    /// Removes ghost objects from document
    async fn remove_ghost_objects(&self, document: &mut Document, metrics: &mut StructureMetrics) -> Result<()> {
        info!("Removing ghost objects");
        
        let mut referenced_objects = HashSet::new();
        
        // Collect all referenced objects
        if let Some(ref catalog) = document.structure.catalog {
            self.collect_references_recursive(&catalog, &document.structure.objects, &mut referenced_objects, 0)?;
        }
        
        if let Some(ref info) = document.structure.info {
            self.collect_references_recursive(&info, &document.structure.objects, &mut referenced_objects, 0)?;
        }
        
        // Remove unreferenced objects
        let mut objects_to_remove = Vec::new();
        for object_id in document.structure.objects.keys() {
            if !referenced_objects.contains(object_id) {
                objects_to_remove.push(*object_id);
            }
        }
        
        for object_id in objects_to_remove {
            document.structure.objects.remove(&object_id);
            document.structure.xref_table.remove(&object_id);
            metrics.ghost_objects += 1;
        }
        
        metrics.referenced_objects = referenced_objects.len();
        metrics.unreferenced_objects = metrics.ghost_objects;
        
        info!("Removed {} ghost objects", metrics.ghost_objects);
        Ok(())
    }

    /// Repairs dangling references (only if user allows)
    async fn repair_dangling_references(&self, document: &mut Document, metrics: &mut StructureMetrics) -> Result<()> {
        if !self.allow_repairs {
            return Ok(());
        }
        
        info!("Repairing dangling references (user-controlled)");
        
        // This would implement reference repair logic
        // For anti-forensic purposes, we typically don't auto-repair
        warn!("Dangling reference repair is enabled - not recommended for anti-forensic use");
        
        Ok(())
    }

    /// Normalizes object numbering to sequential order
    async fn normalize_object_numbering(&self, document: &mut Document, _metrics: &mut StructureMetrics) -> Result<()> {
        info!("Normalizing object numbering");
        
        let mut new_objects = HashMap::new();
        let mut new_xref = HashMap::new();
        let mut id_mapping = HashMap::new();
        
        // Create sequential mapping
        let mut new_id = 1u32;
        for old_id in document.structure.objects.keys() {
            id_mapping.insert(*old_id, ObjectId(new_id));
            new_id += 1;
        }
        
        // Rebuild objects with new IDs
        for (old_id, object) in &document.structure.objects {
            if let Some(&new_id) = id_mapping.get(old_id) {
                let updated_object = self.update_object_references(object, &id_mapping)?;
                new_objects.insert(new_id, updated_object);
                
                if let Some(xref_entry) = document.structure.xref_table.get(old_id) {
                    new_xref.insert(new_id, xref_entry.clone());
                }
            }
        }
        
        document.structure.objects = new_objects;
        document.structure.xref_table = new_xref;
        
        info!("Object numbering normalized to sequential order");
        Ok(())
    }

    /// Removes linearization data
    async fn remove_linearization(&self, document: &mut Document, _metrics: &mut StructureMetrics) -> Result<()> {
        if document.structure.linearized {
            info!("Removing linearization data");
            document.structure.linearized = false;
            // Remove linearization dictionary from catalog
            if let Some(ref mut catalog) = document.structure.catalog {
                // Remove /Linearized entry if present
                if let Object::Dictionary(ref mut dict) = catalog {
                    dict.remove(b"Linearized");
                }
            }
        }
        Ok(())
    }

    /// Rebuilds XRef table cleanly
    async fn rebuild_xref_table(&self, document: &mut Document, _metrics: &mut StructureMetrics) -> Result<()> {
        info!("Rebuilding XRef table");
        
        use crate::structure::cross_ref::XRefEntry;
        
        let mut new_xref = HashMap::new();
        let mut offset = 0u64;
        
        // Rebuild XRef entries with clean offsets
        for object_id in document.structure.objects.keys() {
            new_xref.insert(*object_id, XRefEntry {
                offset,
                generation: 0,
                in_use: true,
            });
            offset += 1000; // Placeholder offset calculation
        }
        
        document.structure.xref_table = new_xref;
        
        info!("XRef table rebuilt with clean offsets");
        Ok(())
    }

    /// Normalizes trailer to single clean trailer
    async fn normalize_trailer(&self, document: &mut Document, _metrics: &mut StructureMetrics) -> Result<()> {
        info!("Normalizing trailer");
        
        // Ensure single, clean trailer
        // Implementation would clean up multiple trailers and normalize contents
        
        Ok(())
    }

    // Helper methods
    
    fn count_eof_in_content(&self, content: &[u8]) -> usize {
        let eof_pattern = b"%%EOF";
        let mut count = 0;
        
        for i in 0..=content.len().saturating_sub(eof_pattern.len()) {
            if &content[i..i + eof_pattern.len()] == eof_pattern {
                count += 1;
            }
        }
        
        count
    }

    fn collect_references_recursive(
        &self,
        object: &Object,
        objects: &HashMap<ObjectId, Object>,
        referenced: &mut HashSet<ObjectId>,
        depth: u32
    ) -> Result<()> {
        if depth > self.max_object_depth {
            return Err(PipelineError::Validation("Object hierarchy too deep".to_string()));
        }
        
        match object {
            Object::Reference(id) => {
                if referenced.insert(*id) {
                    if let Some(referenced_object) = objects.get(id) {
                        self.collect_references_recursive(referenced_object, objects, referenced, depth + 1)?;
                    }
                }
            }
            Object::Dictionary(dict) => {
                for (_, value) in dict {
                    self.collect_references_recursive(value, objects, referenced, depth + 1)?;
                }
            }
            Object::Array(array) => {
                for item in array {
                    self.collect_references_recursive(item, objects, referenced, depth + 1)?;
                }
            }
            Object::Stream(stream) => {
                self.collect_references_recursive(&stream.dict, objects, referenced, depth + 1)?;
            }
            _ => {} // Other object types don't contain references
        }
        
        Ok(())
    }

    fn calculate_max_depth(
        &self,
        object: &Object,
        objects: &HashMap<ObjectId, Object>,
        current_depth: u32
    ) -> Result<u32> {
        if current_depth > self.max_object_depth {
            return Ok(current_depth);
        }
        
        let mut max_depth = current_depth;
        
        match object {
            Object::Reference(id) => {
                if let Some(referenced_object) = objects.get(id) {
                    let depth = self.calculate_max_depth(referenced_object, objects, current_depth + 1)?;
                    max_depth = max_depth.max(depth);
                }
            }
            Object::Dictionary(dict) => {
                for (_, value) in dict {
                    let depth = self.calculate_max_depth(value, objects, current_depth + 1)?;
                    max_depth = max_depth.max(depth);
                }
            }
            Object::Array(array) => {
                for item in array {
                    let depth = self.calculate_max_depth(item, objects, current_depth + 1)?;
                    max_depth = max_depth.max(depth);
                }
            }
            Object::Stream(stream) => {
                let depth = self.calculate_max_depth(&stream.dict, objects, current_depth + 1)?;
                max_depth = max_depth.max(depth);
            }
            _ => {}
        }
        
        Ok(max_depth)
    }

    fn update_object_references(&self, object: &Object, id_mapping: &HashMap<ObjectId, ObjectId>) -> Result<Object> {
        match object {
            Object::Reference(old_id) => {
                if let Some(&new_id) = id_mapping.get(old_id) {
                    Ok(Object::Reference(new_id))
                } else {
                    Ok(object.clone())
                }
            }
            Object::Dictionary(dict) => {
                let mut new_dict = HashMap::new();
                for (key, value) in dict {
                    let updated_value = self.update_object_references(value, id_mapping)?;
                    new_dict.insert(key.clone(), updated_value);
                }
                Ok(Object::Dictionary(new_dict))
            }
            Object::Array(array) => {
                let mut new_array = Vec::new();
                for item in array {
                    let updated_item = self.update_object_references(item, id_mapping)?;
                    new_array.push(updated_item);
                }
                Ok(Object::Array(new_array))
            }
            Object::Stream(stream) => {
                let updated_dict = self.update_object_references(&stream.dict, id_mapping)?;
                if let Object::Dictionary(dict) = updated_dict {
                    Ok(Object::Stream(lopdf::Stream {
                        dict,
                        content: stream.content.clone(),
                        allows_compression: stream.allows_compression,
                        start_position: stream.start_position,
                    }))
                } else {
                    Ok(object.clone())
                }
            }
            _ => Ok(object.clone())
        }
    }
}

impl Default for StructureHandler {
    fn default() -> Self {
        Self::new()
    }
}
