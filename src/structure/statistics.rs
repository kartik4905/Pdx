//! Statistical aggregation of structure analysis

use crate::structure::analysis::{StructureIssue, IssueSeverity};

#[derive(Debug, Default, Clone)]
pub struct AnalysisStatistics {
    pub total_issues: usize,
    pub critical_issues: usize,
    pub warnings: usize,
    pub infos: usize,
}

impl AnalysisStatistics {
    pub fn from_counts(critical: usize, warnings: usize, infos: usize) -> Self {
        Self {
            total_issues: critical + warnings + infos,
            critical_issues: critical,
            warnings,
            infos,
        }
    }

    /// Builds statistics from a list of structure issues
    pub fn from_issues(issues: &[StructureIssue]) -> Self {
        let mut stats = Self::default();

        for issue in issues {
            match issue.severity {
                IssueSeverity::Critical => stats.critical_issues += 1,
                IssueSeverity::Warning => stats.warnings += 1,
                IssueSeverity::Info => stats.infos += 1,
            }
        }

        stats.total_issues = stats.critical_issues + stats.warnings + stats.infos;
        stats
    }

    pub fn merge(&mut self, other: &AnalysisStatistics) {
        self.total_issues += other.total_issues;
        self.critical_issues += other.critical_issues;
        self.warnings += other.warnings;
        self.infos += other.infos;
    }
}
