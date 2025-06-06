
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub content: Vec<u8>,
    pub metadata: DocumentMetadata,
    pub structure: DocumentStructure,
    pub security: SecurityInfo,
    pub pages: Vec<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
    pub custom_properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentStructure {
    pub version: String,
    pub object_count: usize,
    pub page_count: usize,
    pub has_xref_stream: bool,
    pub linearized: bool,
    pub encrypted: bool,
    pub cross_reference_tables: Vec<CrossReferenceTable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossReferenceTable {
    pub starting_object_number: u32,
    pub entries: Vec<CrossReferenceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossReferenceEntry {
    pub object_number: u32,
    pub generation_number: u16,
    pub offset: u64,
    pub in_use: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityInfo {
    pub encrypted: bool,
    pub permissions: DocumentPermissions,
    pub security_handler: Option<String>,
    pub encryption_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentPermissions {
    pub print: bool,
    pub modify: bool,
    pub copy: bool,
    pub annotate: bool,
    pub fill_forms: bool,
    pub extract_for_accessibility: bool,
    pub assemble: bool,
    pub print_high_quality: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    pub page_number: usize,
    pub media_box: Rectangle,
    pub crop_box: Option<Rectangle>,
    pub resources: PageResources,
    pub content_streams: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rectangle {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageResources {
    pub fonts: HashMap<String, FontInfo>,
    pub images: HashMap<String, ImageInfo>,
    pub color_spaces: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontInfo {
    pub name: String,
    pub subtype: String,
    pub base_font: Option<String>,
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    pub width: u32,
    pub height: u32,
    pub bits_per_component: u8,
    pub color_space: String,
    pub filter: Option<String>,
}

impl Document {
    pub fn new() -> Self {
        Self {
            content: Vec::new(),
            metadata: DocumentMetadata::default(),
            structure: DocumentStructure::default(),
            security: SecurityInfo::default(),
            pages: Vec::new(),
        }
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        let mut document = Self::new();
        document.content = data;
        Ok(document)
    }

    pub fn get_page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn is_encrypted(&self) -> bool {
        self.security.encrypted
    }

    pub fn get_version(&self) -> &str {
        &self.structure.version
    }
}

impl Default for DocumentMetadata {
    fn default() -> Self {
        Self {
            title: None,
            author: None,
            subject: None,
            keywords: None,
            creator: None,
            producer: None,
            creation_date: None,
            modification_date: None,
            custom_properties: HashMap::new(),
        }
    }
}

impl Default for DocumentStructure {
    fn default() -> Self {
        Self {
            version: "1.4".to_string(),
            object_count: 0,
            page_count: 0,
            has_xref_stream: false,
            linearized: false,
            encrypted: false,
            cross_reference_tables: Vec::new(),
        }
    }
}

impl Default for SecurityInfo {
    fn default() -> Self {
        Self {
            encrypted: false,
            permissions: DocumentPermissions::default(),
            security_handler: None,
            encryption_method: None,
        }
    }
}

impl Default for DocumentPermissions {
    fn default() -> Self {
        Self {
            print: true,
            modify: true,
            copy: true,
            annotate: true,
            fill_forms: true,
            extract_for_accessibility: true,
            assemble: true,
            print_high_quality: true,
        }
    }
}
