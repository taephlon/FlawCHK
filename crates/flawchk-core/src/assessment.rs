use serde::{Deserialize, Serialize};
use crate::finding::{Finding, FindingKind};
use crate::severity::Severity;
use crate::exposure::ExposureLevel;

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

    pub hardening_fails: usize,
    pub vulnerability_fails: usize,
    pub exposure_fails: usize,

    pub exposure_critical: usize,
    pub exposure_high: usize,
    pub exposure_medium: usize,
    pub exposure_low: usize,

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

        let mut hardening_fails = 0;
        let mut vulnerability_fails = 0;
        let mut exposure_fails = 0;

        let mut exposure_critical = 0;
        let mut exposure_high = 0;
        let mut exposure_medium = 0;
        let mut exposure_low = 0;

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

                    match f.kind {
                        FindingKind::Hardening => hardening_fails += 1,
                        FindingKind::Vulnerability => vulnerability_fails += 1,
                        FindingKind::Exposure => exposure_fails += 1,
                    }

                    if let Some(ref exp) = f.exposure_analysis {
                        match exp.level {
                            ExposureLevel::Critical => exposure_critical += 1,
                            ExposureLevel::High => exposure_high += 1,
                            ExposureLevel::Medium => exposure_medium += 1,
                            ExposureLevel::Low | ExposureLevel::Reduced => exposure_low += 1,
                            ExposureLevel::None => {}
                        }
                    }

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

        let status_text = if critical_count > 0 || high_count > 0 || exposure_critical > 0 || exposure_high > 0 {
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
            hardening_fails,
            vulnerability_fails,
            exposure_fails,
            exposure_critical,
            exposure_high,
            exposure_medium,
            exposure_low,
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
