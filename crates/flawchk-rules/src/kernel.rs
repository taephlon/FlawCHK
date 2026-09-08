use flawchk_core::{Category, CheckMetadata, Confidence, Finding, Severity, Status};
use flawchk_distro::PlatformAdapter;
use crate::registry::{Rule, RuleRegistry};

pub fn register_kernel_rules(registry: &mut RuleRegistry) {
    registry.register(Box::new(KernelIpForwardRule));
    registry.register(Box::new(KernelIcmpRedirectRule));
    registry.register(Box::new(KernelAslrRule));
}

// --- FLAW-KERN-001 ---
pub struct KernelIpForwardRule;

impl Rule for KernelIpForwardRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-KERN-001".to_string(),
            title: "IPv4 packet forwarding enabled".to_string(),
            category: Category::Kernel,
            severity: Severity::Medium,
            confidence: Confidence::High,
            description: "IPv4 forwarding allows the system to act as a router and route packets between different networks.".to_string(),
            impact: "Unless the system is a dedicated network router or container host, packet forwarding can allow unauthorized traffic routing through the node.".to_string(),
            remediation: "Set net.ipv4.ip_forward = 0 in /etc/sysctl.d/99-security.conf or /etc/sysctl.conf and run: sysctl -p".to_string(),
            verification: "Run: sysctl net.ipv4.ip_forward\nExpected: net.ipv4.ip_forward = 0".to_string(),
            references: vec!["https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt".to_string()],
            caveats: Some("Container hosts (Docker/Podman/K8s) or VPN gateways require packet forwarding.".to_string()),
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        match platform.read_sysctl("net.ipv4.ip_forward") {
            Ok(val) => {
                if val == "1" {
                    Finding {
                        check_id: meta.id,
                        title: meta.title,
                        category: meta.category,
                        severity: meta.severity,
                        confidence: meta.confidence,
                        status: Status::Fail,
                        evidence: "net.ipv4.ip_forward is set to 1".to_string(),
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
                        status: Status::Pass,
                        evidence: format!("net.ipv4.ip_forward is set to {}", val),
                        explanation: "IPv4 packet forwarding is disabled.".to_string(),
                        remediation: meta.remediation,
                        verification: meta.verification,
                        caveats: meta.caveats,
                        references: meta.references,
                    }
                }
            }
            Err(e) => Finding {
                check_id: meta.id,
                title: meta.title,
                category: meta.category,
                severity: meta.severity,
                confidence: meta.confidence,
                status: Status::Error,
                evidence: format!("Failed to read sysctl net.ipv4.ip_forward: {}", e),
                explanation: "Unable to query kernel parameter.".to_string(),
                remediation: meta.remediation,
                verification: meta.verification,
                caveats: meta.caveats,
                references: meta.references,
            },
        }
    }
}

// --- FLAW-KERN-002 ---
pub struct KernelIcmpRedirectRule;

impl Rule for KernelIcmpRedirectRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-KERN-002".to_string(),
            title: "ICMP redirect acceptance enabled".to_string(),
            category: Category::Kernel,
            severity: Severity::Low,
            confidence: Confidence::High,
            description: "ICMP redirects allow remote routers to modify routing tables on host systems.".to_string(),
            impact: "An attacker could send forged ICMP redirect packets to alter routing tables and perform Man-in-the-Middle attacks.".to_string(),
            remediation: "Set net.ipv4.conf.all.accept_redirects = 0 and net.ipv4.conf.default.accept_redirects = 0 in /etc/sysctl.d/99-security.conf".to_string(),
            verification: "Run: sysctl net.ipv4.conf.all.accept_redirects\nExpected: net.ipv4.conf.all.accept_redirects = 0".to_string(),
            references: vec!["https://www.cisecurity.org/benchmarks".to_string()],
            caveats: None,
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        match platform.read_sysctl("net.ipv4.conf.all.accept_redirects") {
            Ok(val) => {
                if val != "0" {
                    Finding {
                        check_id: meta.id,
                        title: meta.title,
                        category: meta.category,
                        severity: meta.severity,
                        confidence: meta.confidence,
                        status: Status::Fail,
                        evidence: format!("net.ipv4.conf.all.accept_redirects is set to {}", val),
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
                        status: Status::Pass,
                        evidence: "net.ipv4.conf.all.accept_redirects is 0".to_string(),
                        explanation: "ICMP redirect packets are ignored by the kernel.".to_string(),
                        remediation: meta.remediation,
                        verification: meta.verification,
                        caveats: meta.caveats,
                        references: meta.references,
                    }
                }
            }
            Err(e) => Finding {
                check_id: meta.id,
                title: meta.title,
                category: meta.category,
                severity: meta.severity,
                confidence: meta.confidence,
                status: Status::Error,
                evidence: format!("Failed to read sysctl: {}", e),
                explanation: "Unable to query kernel parameter.".to_string(),
                remediation: meta.remediation,
                verification: meta.verification,
                caveats: meta.caveats,
                references: meta.references,
            },
        }
    }
}

// --- FLAW-KERN-003 ---
pub struct KernelAslrRule;

impl Rule for KernelAslrRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-KERN-003".to_string(),
            title: "Address Space Layout Randomization (ASLR) disabled or partial".to_string(),
            category: Category::Kernel,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "ASLR randomizes memory addresses used by programs, making buffer overflow exploitation much more difficult.".to_string(),
            impact: "Disabling ASLR makes memory corruption exploits significantly easier and more deterministic.".to_string(),
            remediation: "Set kernel.randomize_va_space = 2 in /etc/sysctl.d/99-security.conf".to_string(),
            verification: "Run: sysctl kernel.randomize_va_space\nExpected: kernel.randomize_va_space = 2".to_string(),
            references: vec!["https://en.wikipedia.org/wiki/Address_space_layout_randomization".to_string()],
            caveats: None,
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        match platform.read_sysctl("kernel.randomize_va_space") {
            Ok(val) => {
                if val != "2" {
                    Finding {
                        check_id: meta.id,
                        title: meta.title,
                        category: meta.category,
                        severity: meta.severity,
                        confidence: meta.confidence,
                        status: Status::Fail,
                        evidence: format!("kernel.randomize_va_space is set to '{}' (expected 2)", val),
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
                        status: Status::Pass,
                        evidence: "kernel.randomize_va_space is set to 2 (Full ASLR)".to_string(),
                        explanation: "Address space layout randomization is fully enabled.".to_string(),
                        remediation: meta.remediation,
                        verification: meta.verification,
                        caveats: meta.caveats,
                        references: meta.references,
                    }
                }
            }
            Err(e) => Finding {
                check_id: meta.id,
                title: meta.title,
                category: meta.category,
                severity: meta.severity,
                confidence: meta.confidence,
                status: Status::Error,
                evidence: format!("Failed to read ASLR parameter: {}", e),
                explanation: "Could not inspect kernel parameter.".to_string(),
                remediation: meta.remediation,
                verification: meta.verification,
                caveats: meta.caveats,
                references: meta.references,
            },
        }
    }
}
