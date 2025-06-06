
use crate::error::{PipelineError, Result};
use crate::types::Document;
use lopdf::{Object, ObjectId};
use std::collections::HashMap;
use log::{info, debug, warn};

#[derive(Debug, Clone)]
pub struct LinearizationInfo {
    pub is_linearized: bool,
    pub linearization_dict: Option<ObjectId>,
    pub hint_tables: Vec<ObjectId>,
    pub page_offsets: Vec<u64>,
    pub shared_objects: Vec<ObjectId>,
}

#[derive(Debug, Clone)]
pub struct LinearizationMetrics {
    pub objects_removed: usize,
    pub hint_tables_removed: usize,
    pub page_offsets_cleared: usize,
    pub shared_objects_relocated: usize,
    pub bytes_saved: usize,
}

pub struct LinearizationHandler {
    strict_removal: bool,
    preserve_structure: bool,
}

impl LinearizationHandler {
    pub fn new() -> Self {
        Self {
            strict_removal: true,  // Anti-forensic: Remove all linearization
            preserve_structure: true,
        }
    }

    pub fn with_strict_removal(mut self, strict: bool) -> Self {
        self.strict_removal = strict;
        self
    }

    pub fn with_structure_preservation(mut self, preserve: bool) -> Self {
        self.preserve_structure = preserve;
        self
    }

    /// Detects linearization in PDF document
    pub async fn detect_linearization(&self, document: &Document) -> Result<LinearizationInfo> {
        info!("Detecting PDF linearization");
        
        let mut info = LinearizationInfo {
            is_linearized: false,
            linearization_dict: None,
            hint_tables: Vec::new(),
            page_offsets: Vec::new(),
            shared_objects: Vec::new(),
        };

        // Check for linearization dictionary (usually object 1)
        if let Some(linearization_dict) = self.find_linearization_dictionary(document).await? {
            info.is_linearized = true;
            info.linearization_dict = Some(linearization_dict);
            
            // Extract linearization parameters
            self.extract_linearization_params(document, linearization_dict, &mut info).await?;
        }

        // Check for hint tables
        info.hint_tables = self.find_hint_tables(document).await?;
        
        // Detect page offset tables
        info.page_offsets = self.detect_page_offsets(document).await?;
        
        // Find shared objects (typically used in linearized PDFs)
        info.shared_objects = self.find_shared_objects(document).await?;

        if info.is_linearized {
            warn!("Document is linearized - this creates forensic artifacts and should be removed");
        }

        Ok(info)
    }

    /// Removes linearization from PDF (anti-forensic requirement)
    pub async fn remove_linearization(&self, document: &mut Document) -> Result<LinearizationMetrics> {
        info!("Removing PDF linearization for anti-forensic compliance");
        
        let mut metrics = LinearizationMetrics {
            objects_removed: 0,
            hint_tables_removed: 0,
            page_offsets_cleared: 0,
            shared_objects_relocated: 0,
            bytes_saved: 0,
        };

        // First detect what needs to be removed
        let linearization_info = self.detect_linearization(document).await?;
        
        if !linearization_info.is_linearized {
            info!("Document is not linearized - no changes needed");
            return Ok(metrics);
        }

        // Remove linearization dictionary
        if let Some(lin_dict_id) = linearization_info.linearization_dict {
            self.remove_linearization_dictionary(document, lin_dict_id, &mut metrics).await?;
        }

        // Remove hint tables
        for hint_table_id in &linearization_info.hint_tables {
            self.remove_hint_table(document, *hint_table_id, &mut metrics).await?;
        }

        // Clear page offset optimization
        self.clear_page_offsets(document, &linearization_info.page_offsets, &mut metrics).await?;

        // Relocate shared objects to normal positions
        self.relocate_shared_objects(document, &linearization_info.shared_objects, &mut metrics).await?;

        // Remove linearization flags from catalog
        self.clean_catalog_linearization(document, &mut metrics).await?;

        // Update document structure flag
        document.structure.linearized = false;

        info!("Linearization removal completed: {} objects removed, {} bytes saved", 
              metrics.objects_removed, metrics.bytes_saved);
        
        Ok(metrics)
    }

    /// Validates that linearization has been completely removed
    pub async fn validate_linearization_removal(&self, document: &Document) -> Result<bool> {
        debug!("Validating complete linearization removal");
        
        // Check for any remaining linearization artifacts
        let info = self.detect_linearization(document).await?;
        
        if info.is_linearized {
            warn!("Linearization artifacts still detected after removal");
            return Ok(false);
        }

        if !info.hint_tables.is_empty() {
            warn!("Hint tables still present after linearization removal");
            return Ok(false);
        }

        if !info.page_offsets.is_empty() {
            warn!("Page offset tables still present");
            return Ok(false);
        }

        // Check catalog for linearization flags
        if let Some(ref catalog) = document.structure.catalog {
            if let Object::Dictionary(dict) = catalog {
                if dict.contains_key(b"Linearized") {
                    warn!("Linearization flag still present in catalog");
                    return Ok(false);
                }
            }
        }

        info!("Linearization removal validation passed");
        Ok(true)
    }

    // Private implementation methods

    async fn find_linearization_dictionary(&self, document: &Document) -> Result<Option<ObjectId>> {
        debug!("Searching for linearization dictionary");
        
        // Linearization dictionary is typically object 1
        if let Some(object) = document.structure.objects.get(&ObjectId(1)) {
            if let Object::Dictionary(dict) = object {
                if dict.contains_key(b"Linearized") {
                    debug!("Found linearization dictionary at object 1");
                    return Ok(Some(ObjectId(1)));
                }
            }
        }

        // Search other objects if not found at object 1
        for (object_id, object) in &document.structure.objects {
            if let Object::Dictionary(dict) = object {
                if dict.contains_key(b"Linearized") {
                    debug!("Found linearization dictionary at object {}", object_id.0);
                    return Ok(Some(*object_id));
                }
            }
        }

        Ok(None)
    }

    async fn extract_linearization_params(
        &self, 
        document: &Document, 
        dict_id: ObjectId, 
        info: &mut LinearizationInfo
    ) -> Result<()> {
        debug!("Extracting linearization parameters");
        
        if let Some(Object::Dictionary(dict)) = document.structure.objects.get(&dict_id) {
            // Extract linearization parameters
            if let Some(Object::Integer(length)) = dict.get(b"L") {
                debug!("Linearization file length: {}", length);
            }
            
            if let Some(Object::Array(hint_array)) = dict.get(b"H") {
                debug!("Found hint stream parameters");
                // Extract hint table information
            }
            
            if let Some(Object::Integer(obj_count)) = dict.get(b"N") {
                debug!("Linearization object count: {}", obj_count);
            }
            
            if let Some(Object::Integer(endtable)) = dict.get(b"E") {
                debug!("End of first page offset: {}", endtable);
            }
        }

        Ok(())
    }

    async fn find_hint_tables(&self, document: &Document) -> Result<Vec<ObjectId>> {
        debug!("Finding hint tables");
        
        let mut hint_tables = Vec::new();
        
        for (object_id, object) in &document.structure.objects {
            if let Object::Stream(stream) = object {
                if let Object::Dictionary(dict) = &stream.dict {
                    // Check for hint stream type
                    if let Some(Object::Name(type_name)) = dict.get(b"Type") {
                        if type_name == b"Hint" {
                            hint_tables.push(*object_id);
                        }
                    }
                    
                    // Check for linearization hint markers
                    if dict.contains_key(b"S") && dict.contains_key(b"Length") {
                        // This might be a hint stream
                        hint_tables.push(*object_id);
                    }
                }
            }
        }
        
        debug!("Found {} hint tables", hint_tables.len());
        Ok(hint_tables)
    }

    async fn detect_page_offsets(&self, document: &Document) -> Result<Vec<u64>> {
        debug!("Detecting page offset optimizations");
        
        let mut page_offsets = Vec::new();
        
        // Look for page offset tables in the document structure
        // These are typically stored as arrays in linearization context
        
        for (_, object) in &document.structure.objects {
            if let Object::Array(array) = object {
                // Check if this looks like a page offset array
                if self.looks_like_page_offset_array(array) {
                    // Extract offsets
                    for item in array {
                        if let Object::Integer(offset) = item {
                            page_offsets.push(*offset as u64);
                        }
                    }
                }
            }
        }
        
        Ok(page_offsets)
    }

    async fn find_shared_objects(&self, document: &Document) -> Result<Vec<ObjectId>> {
        debug!("Finding shared objects used in linearization");
        
        let mut shared_objects = Vec::new();
        
        // In linearized PDFs, certain objects are shared across pages
        // These need to be reorganized for anti-forensic compliance
        
        for (object_id, object) in &document.structure.objects {
            if self.is_shared_object(object) {
                shared_objects.push(*object_id);
            }
        }
        
        debug!("Found {} shared objects", shared_objects.len());
        Ok(shared_objects)
    }

    async fn remove_linearization_dictionary(
        &self, 
        document: &mut Document, 
        dict_id: ObjectId, 
        metrics: &mut LinearizationMetrics
    ) -> Result<()> {
        info!("Removing linearization dictionary");
        
        if let Some(object) = document.structure.objects.remove(&dict_id) {
            // Calculate bytes saved
            let object_size = self.estimate_object_size(&object);
            metrics.bytes_saved += object_size;
            metrics.objects_removed += 1;
            
            // Also remove from XRef table
            document.structure.xref_table.remove(&dict_id);
            
            info!("Removed linearization dictionary object {}", dict_id.0);
        }
        
        Ok(())
    }

    async fn remove_hint_table(
        &self, 
        document: &mut Document, 
        hint_id: ObjectId, 
        metrics: &mut LinearizationMetrics
    ) -> Result<()> {
        debug!("Removing hint table {}", hint_id.0);
        
        if let Some(object) = document.structure.objects.remove(&hint_id) {
            let object_size = self.estimate_object_size(&object);
            metrics.bytes_saved += object_size;
            metrics.hint_tables_removed += 1;
            
            document.structure.xref_table.remove(&hint_id);
            
            debug!("Removed hint table object {}", hint_id.0);
        }
        
        Ok(())
    }

    async fn clear_page_offsets(
        &self, 
        _document: &mut Document, 
        page_offsets: &[u64], 
        metrics: &mut LinearizationMetrics
    ) -> Result<()> {
        debug!("Clearing page offset optimizations");
        
        metrics.page_offsets_cleared = page_offsets.len();
        
        // Page offsets are cleared by removing the arrays/objects that contain them
        // This is handled by the general object removal process
        
        Ok(())
    }

    async fn relocate_shared_objects(
        &self, 
        _document: &mut Document, 
        shared_objects: &[ObjectId], 
        metrics: &mut LinearizationMetrics
    ) -> Result<()> {
        debug!("Relocating shared objects to normal positions");
        
        metrics.shared_objects_relocated = shared_objects.len();
        
        // Shared objects don't need special relocation in our anti-forensic approach
        // They will be handled by the normal object reorganization process
        
        Ok(())
    }

    async fn clean_catalog_linearization(
        &self, 
        document: &mut Document, 
        _metrics: &mut LinearizationMetrics
    ) -> Result<()> {
        debug!("Cleaning linearization flags from catalog");
        
        if let Some(ref mut catalog) = document.structure.catalog {
            if let Object::Dictionary(ref mut dict) = catalog {
                // Remove linearization-related entries
                dict.remove(b"Linearized");
                dict.remove(b"L");
                dict.remove(b"H");
                dict.remove(b"O");
                dict.remove(b"E");
                dict.remove(b"N");
                dict.remove(b"T");
                
                debug!("Removed linearization flags from catalog");
            }
        }
        
        Ok(())
    }

    // Helper methods

    fn looks_like_page_offset_array(&self, array: &[Object]) -> bool {
        // Check if array contains mostly integers that could be offsets
        if array.len() < 2 {
            return false;
        }
        
        let mut integer_count = 0;
        for item in array {
            if matches!(item, Object::Integer(_)) {
                integer_count += 1;
            }
        }
        
        // If more than 80% are integers, it might be an offset array
        (integer_count as f64 / array.len() as f64) > 0.8
    }

    fn is_shared_object(&self, object: &Object) -> bool {
        // Determine if an object is likely a shared object in linearization
        match object {
            Object::Dictionary(dict) => {
                // Font objects, form XObjects, and image XObjects are often shared
                if let Some(Object::Name(type_name)) = dict.get(b"Type") {
                    matches!(type_name.as_slice(), b"Font" | b"XObject" | b"ExtGState")
                } else {
                    false
                }
            }
            _ => false
        }
    }

    fn estimate_object_size(&self, object: &Object) -> usize {
        match object {
            Object::Stream(stream) => {
                stream.content.len() + 200 // Content + dictionary overhead
            }
            Object::Dictionary(dict) => {
                dict.len() * 50 + 100 // Rough estimate
            }
            Object::Array(array) => {
                array.len() * 20 + 50
            }
            Object::String(s, _) => {
                s.len() + 20
            }
            _ => 50
        }
    }
}

impl Default for LinearizationHandler {
    fn default() -> Self {
        Self::new()
    }
}
