//! PDF Document abstraction
//! Created: 2025-06-03
//! Author: kartik4905

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use crate::types::{Object, ObjectId};
use crate::error::Result;

/// Structural information about the PDF
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PdfStructure {
    /// Mapping of object IDs to objects
    pub objects: BTreeMap<ObjectId, Object>,
    /// Root object reference
    pub root: Option<ObjectId>,
    /// Trailer dictionary
    pub trailer: Option<Object>,
    /// Cross-reference table (if available)
    pub xref_table: Option<Object>,
    /// Version (header) string
    pub version: Option<String>,
}

impl PdfStructure {
    /// Inserts or replaces an object in the PDF structure
    pub fn insert_object(&mut self, id: ObjectId, obj: Object) {
        self.objects.insert(id, obj);
    }

    /// Gets a reference to an object
    pub fn get_object(&self, id: &ObjectId) -> Option<&Object> {
        self.objects.get(id)
    }

    /// Gets a mutable reference to an object
    pub fn get_object_mut(&mut self, id: &ObjectId) -> Option<&mut Object> {
        self.objects.get_mut(id)
    }

    /// Removes an object by ID
    pub fn remove_object(&mut self, id: &ObjectId) -> Option<Object> {
        self.objects.remove(id)
    }

    /// Returns a list of all object IDs
    pub fn all_object_ids(&self) -> Vec<ObjectId> {
        self.objects.keys().cloned().collect()
    }
}

/// PDF metadata representation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PdfMetadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<String>,
    pub mod_date: Option<String>,
}

impl PdfMetadata {
    /// Converts metadata into a PDF dictionary-like format
    pub fn to_map(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        if let Some(ref v) = self.title { map.insert("Title".into(), v.clone()); }
        if let Some(ref v) = self.author { map.insert("Author".into(), v.clone()); }
        if let Some(ref v) = self.subject { map.insert("Subject".into(), v.clone()); }
        if let Some(ref v) = self.keywords { map.insert("Keywords".into(), v.clone()); }
        if let Some(ref v) = self.creator { map.insert("Creator".into(), v.clone()); }
        if let Some(ref v) = self.producer { map.insert("Producer".into(), v.clone()); }
        if let Some(ref v) = self.creation_date { map.insert("CreationDate".into(), v.clone()); }
        if let Some(ref v) = self.mod_date { map.insert("ModDate".into(), v.clone()); }
        map
    }

    /// Creates metadata from a dictionary map
    pub fn from_map(map: &BTreeMap<String, String>) -> Self {
        Self {
            title: map.get("Title").cloned(),
            author: map.get("Author").cloned(),
            subject: map.get("Subject").cloned(),
            keywords: map.get("Keywords").cloned(),
            creator: map.get("Creator").cloned(),
            producer: map.get("Producer").cloned(),
            creation_date: map.get("CreationDate").cloned(),
            mod_date: map.get("ModDate").cloned(),
        }
    }
}

/// PDF Document wrapper for loading and processing
#[derive(Debug, Clone)]
pub struct PdfDocument {
    pub document: Document,
    pub file_path: String,
}

impl PdfDocument {
    /// Load a PDF document from file path
    pub async fn load(path: &str) -> Result<Self> {
        use std::fs;
        use std::collections::HashMap;
        use lopdf::Dictionary;
        
        // Read the file to get basic information
        let metadata = fs::metadata(path).map_err(crate::error::Error::IoError)?;
        let file_size = metadata.len();
        
        // Create a basic document structure
        let document = Document {
            path: path.into(),
            size: file_size,
            version: "1.4".to_string(), // Default PDF version
            metadata: Dictionary::new(),
            content: HashMap::new(),
            modifications: Vec::new(),
        };
        
        Ok(PdfDocument {
            document,
            file_path: path.to_string(),
        })
    }
}

impl From<PdfDocument> for Document {
    fn from(pdf_doc: PdfDocument) -> Self {
        pdf_doc.document
    }
}
