//! Structural analysis for PDF anti-forensics

use lopdf::{Object, Dictionary, Stream};
use crate::types::Document;

pub struct StructureAnalysis;

impl StructureAnalysis {
    pub fn analyze_structure(&self, document: &Document) {
        for (id, object) in &document.content {
            match object {
                Object::Dictionary(dict) => {
                    if !dict.has(b"Type") {
                        println!("Object {:?} is missing Type entry", id);
                    }
                }
                Object::Stream(stream) => {
                    if stream.dict.is_empty() {
                        println!("Object {:?} has empty stream dictionary", id);
                    }
                }
                _ => {}
            }
        }
    }
}
