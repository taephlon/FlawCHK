use serde::{Deserialize, Serialize};
use crate::finding::Finding;
use crate::severity::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_pretty_name: String,
    pub kernel_version: String,
    pub init_system: String,
    pub package_manager: String,
    pub mac_system: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentSummary {
    pub total: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub na_count: usize,
    pub error_count: usize,
    pub status_text: String,
}

impl AssessmentSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut total = 0;
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;
        let mut pass_count = 0;
        let mut fail_count = 0;
        let mut na_count = 0;
        let mut error_count = 0;

        for f in findings {
            total += 1;
            match f.status {
                crate::finding::Status::Pass => pass_count += 1,
                crate::finding::Status::Fail => {
                    fail_count += 1;
                    match f.severity {
                        Severity::Critical => critical_count += 1,
                        Severity::High => high_count += 1,
                        Severity::Medium => medium_count += 1,
                        Severity::Low => low_count += 1,
                        Severity::Info => info_count += 1,
                    }
                }
                crate::finding::Status::NotApplicable => na_count += 1,
                crate::finding::Status::Error => error_count += 1,
            }
        }

        let status_text = if critical_count > 0 || high_count > 0 {
            "NEEDS ATTENTION".to_string()
        } else if fail_count > 0 {
            "MINOR ISSUES FOUND".to_string()
        } else {
            "HARDENED".to_string()
        };

        Self {
            total,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            pass_count,
            fail_count,
            na_count,
            error_count,
            status_text,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentResult {
    pub system_info: SystemInfo,
    pub profile_name: String,
    pub timestamp: String,
    pub summary: AssessmentSummary,
    pub findings: Vec<Finding>,
}
