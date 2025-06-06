//! Cross-reference table handler implementation for PDF anti-forensics
//! Author: kartik4091

use std::collections::HashMap;
use lopdf::{ObjectId};
use tracing::{debug, info, instrument};

use crate::{
    error::{Error, Result},
    types::{Document, XRefTable, XRefEntry, XRefEntryType},
    structure::analysis::{StructureIssue, IssueSeverity, IssueLocation},
};

pub struct CrossRefHandler {
    entries: HashMap<ObjectId, XRefEntry>,
    stats: XRefStatistics,
}

#[derive(Debug, Default)]
pub struct XRefStatistics {
    pub tables_processed: usize,
    pub entries_processed: usize,
    pub free_objects: usize,
    pub in_use_objects: usize,
    pub compressed_objects: usize,
}

impl CrossRefHandler {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            stats: XRefStatistics::default(),
        }
    }

    pub fn validate_table(&mut self, table: &XRefTable, issues: &mut Vec<StructureIssue>) -> Result<()> {
        debug!("Validating cross-reference table at offset {}", table.offset);

        let mut seen = HashMap::new();
        for entry in &table.entries {
            if let Some(_) = seen.insert(entry.object_id, entry) {
                issues.push(StructureIssue {
                    message: format!("Duplicate cross-reference entry for object {:?}", entry.object_id),
                    severity: IssueSeverity::Warning,
                    location: IssueLocation {
                        object_id: entry.object_id,
                        description: format!("Duplicate entry at xref offset {}", table.offset),
                    },
                });
            }
        }

        let mut prev = 0;
        for entry in &table.entries {
            if entry.object_id.number < prev {
                issues.push(StructureIssue {
                    message: format!("Object number {} follows {} out of order", entry.object_id.number, prev),
                    severity: IssueSeverity::Info,
                    location: IssueLocation {
                        object_id: entry.object_id,
                        description: format!("Out-of-order object at xref offset {}", table.offset),
                    },
                });
            }
            prev = entry.object_id.number;
        }

        Ok(())
    }

    pub fn process_table(&mut self, table: &XRefTable) -> Result<()> {
        for entry in &table.entries {
            self.entries.insert(entry.object_id, entry.clone());
            self.stats.entries_processed += 1;
            match entry.entry_type {
                XRefEntryType::Free => self.stats.free_objects += 1,
                XRefEntryType::InUse => self.stats.in_use_objects += 1,
                XRefEntryType::Compressed => self.stats.compressed_objects += 1,
            }
        }
        self.stats.tables_processed += 1;
        Ok(())
    }

    pub fn lookup(&self, object_id: &ObjectId) -> Option<&XRefEntry> {
        self.entries.get(object_id)
    }

    pub fn statistics(&self) -> &XRefStatistics {
        &self.stats
    }
}
