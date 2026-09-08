use flawchk_core::{Category, CheckMetadata, Confidence, Finding, Severity, Status};
use flawchk_distro::PlatformAdapter;
use crate::registry::{Rule, RuleRegistry};

pub fn register_network_rules(registry: &mut RuleRegistry) {
    registry.register(Box::new(FirewallStatusRule));
    registry.register(Box::new(UnrestrictedListeningServicesRule));
}

// --- FLAW-NET-001 ---
pub struct FirewallStatusRule;

impl Rule for FirewallStatusRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-NET-001".to_string(),
            title: "No active host firewall daemon detected".to_string(),
            category: Category::Network,
            severity: Severity::High,
            confidence: Confidence::Medium,
            description: "Host-based firewalls enforce ingress and egress filtering rules directly on the Linux node.".to_string(),
            impact: "Absence of host firewall rules leaves listening services exposed directly to untrusted networks or local network neighbors.".to_string(),
            remediation: "Enable and configure nftables, iptables, ufw, or firewalld on the node.".to_string(),
            verification: "Run: nft list ruleset || iptables -L -n || ufw status || firewall-cmd --state\nExpected: Active firewall rules loaded.".to_string(),
            references: vec![
                "https://wiki.gentoo.org/wiki/Nftables".to_string(),
                "https://help.ubuntu.com/community/UFW".to_string(),
            ],
            caveats: Some("If the host sits behind an upstream hardware security gateway or cloud Security Group, host firewalling might be handled at the network edge.".to_string()),
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();

        let firewall_services = ["nftables", "iptables", "ufw", "firewalld"];
        let mut active_fw = Vec::new();

        for fw in &firewall_services {
            if platform.is_service_active(fw) {
                active_fw.push(*fw);
            }
        }

        if active_fw.is_empty() {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Fail,
                "No active host firewall service (nftables, iptables, ufw, firewalld) was detected".to_string(),
                meta.impact,
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        } else {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Pass,
                format!("Active host firewall service detected: {}", active_fw.join(", ")),
                "Host-based firewall daemon is active.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        }
    }
}

// --- FLAW-NET-002 ---
pub struct UnrestrictedListeningServicesRule;

impl Rule for UnrestrictedListeningServicesRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-NET-002".to_string(),
            title: "Services listening on all network interfaces (0.0.0.0 / ::)".to_string(),
            category: Category::Network,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            description: "Services bound to 0.0.0.0 or :: listen on every available network interface, including public or external interfaces.".to_string(),
            impact: "Exposing internal management daemons or database ports globally increases the external attack surface.".to_string(),
            remediation: "Bind sensitive daemons (e.g. Redis, MySQL, internal APIs) specifically to localhost (127.0.0.1 / ::1) or private IP interfaces.".to_string(),
            verification: "Run: ss -tuln\nExpected: Unneeded internal services bound to 127.0.0.1 rather than 0.0.0.0".to_string(),
            references: vec!["https://www.man7.org/linux/man-pages/man8/ss.8.html".to_string()],
            caveats: Some("Public web servers (HTTP/HTTPS) or SSH daemons intentionally listen on all interfaces.".to_string()),
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        let listening = platform.get_listening_services();

        let mut wildcard_listeners = Vec::new();
        for line in listening {
            if line.contains("0.0.0.0:") || line.contains("[::]:") || line.contains("*:*") {
                wildcard_listeners.push(line.trim().to_string());
            }
        }

        if wildcard_listeners.len() > 3 {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Fail,
                format!("Detected {} services listening on wildcard 0.0.0.0 / :: interfaces", wildcard_listeners.len()),
                meta.impact,
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        } else {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Pass,
                format!("Controlled number of wildcard listening sockets ({} detected)", wildcard_listeners.len()),
                "Network listening sockets are appropriately restricted.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        }
    }
}
