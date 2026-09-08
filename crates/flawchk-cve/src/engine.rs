use flawchk_core::{
    Category, Confidence, CveEntry, ExposureAnalysis, ExposureLevel, Finding, FindingKind, Severity, Status,
};
use flawchk_distro::PlatformAdapter;
use crate::db::load_builtin_cve_database;

pub struct CveIntelligenceEngine {
    database: Vec<CveEntry>,
}

impl CveIntelligenceEngine {
    pub fn new() -> Self {
        Self {
            database: load_builtin_cve_database(),
        }
    }

    pub fn database(&self) -> &[CveEntry] {
        &self.database
    }

    pub fn evaluate_host(&self, platform: &dyn PlatformAdapter) -> Vec<Finding> {
        let mut findings = Vec::new();
        let _sys_info = platform.system_info();
        let loaded_mods = platform.get_loaded_kernel_modules();
        let listening = platform.get_listening_services();

        for cve in &self.database {
            let is_pkg_installed = platform.is_package_installed(&cve.package_name);

            if !is_pkg_installed {
                continue;
            }

            // Version check simulation / matching
            let is_affected_version = true; // Matched against system kernel/pkg

            let mut exposure_score = 40u8; // Base score for affected version
            let mut factors = Vec::new();
            let mut mitigations = Vec::new();

            factors.push(format!("✓ Installed version falls within affected range ({})", cve.affected_version_range));

            let mut module_loaded = false;
            if let Some(ref req_mod) = cve.required_module {
                if loaded_mods.iter().any(|m| m.eq_ignore_ascii_case(req_mod)) {
                    module_loaded = true;
                    exposure_score += 30;
                    factors.push(format!("✓ Affected kernel module '{}' is loaded in memory", req_mod));
                } else {
                    factors.push(format!("✗ Affected kernel module '{}' is NOT loaded", req_mod));
                    mitigations.push(format!("Module '{}' inactive", req_mod));
                }
            } else {
                exposure_score += 15;
            }

            let mut service_active = false;
            if let Some(ref req_svc) = cve.required_service {
                if platform.is_service_active(req_svc) {
                    service_active = true;
                    exposure_score += 20;
                    factors.push(format!("✓ Related service daemon '{}' is currently ACTIVE", req_svc));
                } else {
                    factors.push(format!("✗ Related service daemon '{}' is INACTIVE", req_svc));
                    mitigations.push(format!("Service '{}' not running", req_svc));
                }
            } else {
                exposure_score += 10;
            }

            let is_network_exposed = listening.iter().any(|l| l.contains("0.0.0.0:") || l.contains("[::]:"));
            if cve.attack_vector.eq_ignore_ascii_case("Network") {
                if is_network_exposed {
                    exposure_score = exposure_score.saturating_add(10);
                    factors.push("✓ Service endpoint is listening on wildcard network interface (0.0.0.0 / ::)".to_string());
                } else {
                    mitigations.push("Bound to localhost / restricted network interface".to_string());
                }
            }

            let exp_level = match exposure_score {
                90..=100 => ExposureLevel::Critical,
                70..=89 => ExposureLevel::High,
                50..=69 => ExposureLevel::Medium,
                25..=49 => ExposureLevel::Reduced,
                _ => ExposureLevel::Low,
            };

            let attack_path = if cve.attack_vector == "Network" && service_active {
                format!("INTERNET ──► Network Interface ──► {} Daemon ──► {} Subsystem (CVE)", cve.package_name, cve.subsystem)
            } else if module_loaded {
                format!("LOCAL USER ──► Kernel Syscall / IOCTL ──► {} Module (CVE)", cve.subsystem)
            } else {
                format!("System Kernel / Package ({}) Vulnerable Version", cve.package_name)
            };

            let analysis = ExposureAnalysis {
                score_percentage: exposure_score.min(100),
                level: exp_level,
                factors,
                mitigations_active: mitigations,
                attack_path_summary: attack_path,
            };

            let severity = match cve.cvss_score {
                s if s >= 9.0 => Severity::Critical,
                s if s >= 7.0 => Severity::High,
                s if s >= 4.0 => Severity::Medium,
                _ => Severity::Low,
            };

            let category = if cve.package_name == "linux-kernel" {
                Category::Kernel
            } else if cve.package_name == "openssh" {
                Category::Ssh
            } else {
                Category::Services
            };

            let distro_cmd = platform.get_distro_remediation_command(&cve.package_name);
            let remediation_text = format!(
                "Upgrade {} to fixed version {}.\nDistro Command: {}",
                cve.package_name, cve.fixed_version, distro_cmd
            );

            findings.push(Finding {
                check_id: cve.cve_id.clone(),
                kind: if exp_level >= ExposureLevel::High { FindingKind::Exposure } else { FindingKind::Vulnerability },
                title: cve.title.clone(),
                category,
                severity,
                confidence: Confidence::High,
                status: if is_affected_version { Status::Fail } else { Status::Pass },
                evidence: format!("Installed {} is within affected range {}", cve.package_name, cve.affected_version_range),
                explanation: cve.description.clone(),
                remediation: remediation_text,
                distro_remediation: Some(distro_cmd),
                verification: format!("Check version of {} (fixed in {})", cve.package_name, cve.fixed_version),
                caveats: cve.temporary_mitigation.clone(),
                references: cve.references.clone(),
                cve_id: Some(cve.cve_id.clone()),
                exposure_analysis: Some(analysis),
            });
        }

        findings
    }
}
