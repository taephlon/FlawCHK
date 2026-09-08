use flawchk_core::{Category, CheckMetadata, Confidence, Finding, Severity, Status};
use flawchk_distro::PlatformAdapter;
use crate::registry::{Rule, RuleRegistry};

pub fn register_logging_rules(registry: &mut RuleRegistry) {
    registry.register(Box::new(AuditdLoggingRule));
}

// --- FLAW-LOG-001 ---
pub struct AuditdLoggingRule;

impl Rule for AuditdLoggingRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-LOG-001".to_string(),
            title: "System audit daemon (auditd) or logging service inactive".to_string(),
            category: Category::Logging,
            severity: Severity::Medium,
            confidence: Confidence::High,
            description: "The auditd service collects security audit events from the Linux kernel, including system calls, file access, and authentication attempts.".to_string(),
            impact: "Without active audit logging, security incidents cannot be accurately investigated or backtracked during post-incident analysis.".to_string(),
            remediation: "Enable and start the auditd daemon: systemctl enable --now auditd OR rc-update add auditd default && rc-service auditd start".to_string(),
            verification: "Run: auditctl -s\nExpected: enabled 1".to_string(),
            references: vec![
                "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/securing_networks/assembly_audit-log-events_securing-networks".to_string(),
                "https://wiki.gentoo.org/wiki/Auditd".to_string(),
            ],
            caveats: None,
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();

        let is_auditd_active = platform.is_service_active("auditd");
        let is_journald_active = platform.is_service_active("systemd-journald");
        let is_syslog_active = platform.is_service_active("rsyslog") || platform.is_service_active("syslog-ng");

        if is_auditd_active {
            Finding {
                check_id: meta.id,
                title: meta.title,
                category: meta.category,
                severity: meta.severity,
                confidence: meta.confidence,
                status: Status::Pass,
                evidence: "Kernel audit daemon (auditd) is active and running".to_string(),
                explanation: "System event audit daemon is collecting security telemetry.".to_string(),
                remediation: meta.remediation,
                verification: meta.verification,
                caveats: meta.caveats,
                references: meta.references,
            }
        } else if is_journald_active || is_syslog_active {
            Finding {
                check_id: meta.id,
                title: meta.title,
                category: meta.category,
                severity: meta.severity,
                confidence: meta.confidence,
                status: Status::Fail,
                evidence: "System logging (journald/syslog) is active, but auditd kernel event auditing is inactive".to_string(),
                explanation: meta.impact,
                remediation: meta.remediation,
                verification: meta.verification,
                caveats: meta.caveats,
                references: meta.references,
            }
        } else {
            Finding {
                check_id: meta.id,
                title: meta.title,
                category: meta.category,
                severity: meta.severity,
                confidence: meta.confidence,
                status: Status::Fail,
                evidence: "No active system audit daemon (auditd, journald, or syslog) detected".to_string(),
                explanation: meta.impact,
                remediation: meta.remediation,
                verification: meta.verification,
                caveats: meta.caveats,
                references: meta.references,
            }
        }
    }
}
