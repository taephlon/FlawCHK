use flawchk_core::{Category, CheckMetadata, Confidence, Finding, Severity, Status};
use flawchk_distro::PlatformAdapter;
use crate::registry::{Rule, RuleRegistry};

pub fn register_ssh_rules(registry: &mut RuleRegistry) {
    registry.register(Box::new(SshRootLoginRule));
    registry.register(Box::new(SshPasswordAuthRule));
    registry.register(Box::new(SshEmptyPasswordsRule));
}

fn parse_sshd_directive(content: &str, directive: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 && parts[0].eq_ignore_ascii_case(directive) {
            return Some(parts[1].to_lowercase());
        }
    }
    None
}

// --- FLAW-SSH-001 ---
pub struct SshRootLoginRule;

impl Rule for SshRootLoginRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-SSH-001".to_string(),
            title: "SSH permits direct root login".to_string(),
            category: Category::Ssh,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "Direct root login over SSH permits attackers to attempt authentication directly against the privileged root account.".to_string(),
            impact: "Direct root authentication increases the impact of credential compromise and hinders audit accountability.".to_string(),
            remediation: "Set PermitRootLogin to 'no' in /etc/ssh/sshd_config and reload the SSH service.".to_string(),
            verification: "Run: sshd -T | grep permitrootlogin\nExpected: permitrootlogin no".to_string(),
            references: vec![
                "https://www.cisecurity.org/benchmark/ubuntu_linux".to_string(),
                "https://wiki.gentoo.org/wiki/SSH".to_string(),
            ],
            caveats: Some("Ensure an alternative administrative user with sudo or su access exists before disabling root SSH login.".to_string()),
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        let sshd_path = platform.resolve_config_path("sshd_config");

        if !platform.path_exists(&sshd_path) {
            return Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::NotApplicable,
                format!("SSH configuration file not found at {}", sshd_path.display()),
                "SSH daemon does not appear to be installed or configured on this node.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            );
        }

        let content = match platform.read_file(&sshd_path) {
            Ok(c) => c,
            Err(e) => {
                return Finding::hardening(
                    meta.id,
                    meta.title,
                    meta.category,
                    meta.severity,
                    meta.confidence,
                    Status::Error,
                    format!("Failed to read {}: {}", sshd_path.display(), e),
                    "Unable to inspect SSH configuration due to permission or file I/O error.".to_string(),
                    meta.remediation,
                    meta.verification,
                    meta.caveats,
                    meta.references,
                );
            }
        };

        let val = parse_sshd_directive(&content, "PermitRootLogin");
        let is_root_permitted = match val.as_deref() {
            Some("no") => false,
            Some("prohibit-password") | Some("without-password") => false,
            Some("yes") | None => true,
            _ => true,
        };

        if is_root_permitted {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Fail,
                format!(
                    "PermitRootLogin is currently set to '{}' in {}",
                    val.unwrap_or_else(|| "unset (defaulting to enabled/yes)".to_string()),
                    sshd_path.display()
                ),
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
                format!("PermitRootLogin is securely set to '{}'", val.unwrap_or_default()),
                "Direct root SSH authentication is properly restricted.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        }
    }
}

// --- FLAW-SSH-002 ---
pub struct SshPasswordAuthRule;

impl Rule for SshPasswordAuthRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-SSH-002".to_string(),
            title: "SSH password authentication enabled".to_string(),
            category: Category::Ssh,
            severity: Severity::Medium,
            confidence: Confidence::High,
            description: "Password authentication for SSH allows brute-force attacks against user accounts.".to_string(),
            impact: "Permitting password authentication exposes system SSH endpoints to automated dictionary attacks.".to_string(),
            remediation: "Set PasswordAuthentication to 'no' in /etc/ssh/sshd_config and use SSH key-based authentication.".to_string(),
            verification: "Run: sshd -T | grep passwordauthentication\nExpected: passwordauthentication no".to_string(),
            references: vec!["https://www.ssh.com/academy/ssh/sshd_config".to_string()],
            caveats: Some("Verify SSH public keys are configured for all legitimate users prior to disabling password authentication.".to_string()),
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        let sshd_path = platform.resolve_config_path("sshd_config");

        if !platform.path_exists(&sshd_path) {
            return Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::NotApplicable,
                "SSH configuration not found".to_string(),
                "SSH daemon is not installed.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            );
        }

        let content = match platform.read_file(&sshd_path) {
            Ok(c) => c,
            Err(e) => {
                return Finding::hardening(
                    meta.id,
                    meta.title,
                    meta.category,
                    meta.severity,
                    meta.confidence,
                    Status::Error,
                    format!("Could not read {}: {}", sshd_path.display(), e),
                    "Error reading SSH configuration.".to_string(),
                    meta.remediation,
                    meta.verification,
                    meta.caveats,
                    meta.references,
                );
            }
        };

        let val = parse_sshd_directive(&content, "PasswordAuthentication");
        let is_pass_auth_enabled = match val.as_deref() {
            Some("no") => false,
            Some("yes") | None => true,
            _ => true,
        };

        if is_pass_auth_enabled {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Fail,
                format!("PasswordAuthentication is set to '{}'", val.unwrap_or_else(|| "unset (default yes)".to_string())),
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
                "PasswordAuthentication is set to 'no'".to_string(),
                "Password-based SSH authentication is disabled.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        }
    }
}

// --- FLAW-SSH-003 ---
pub struct SshEmptyPasswordsRule;

impl Rule for SshEmptyPasswordsRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-SSH-003".to_string(),
            title: "SSH permits empty passwords".to_string(),
            category: Category::Ssh,
            severity: Severity::Critical,
            confidence: Confidence::High,
            description: "Permitting empty passwords allows authentication without credentials if a system account has an empty password field.".to_string(),
            impact: "Accounts with blank passwords can be compromised without any authentication effort.".to_string(),
            remediation: "Set PermitEmptyPasswords to 'no' in /etc/ssh/sshd_config.".to_string(),
            verification: "Run: sshd -T | grep permitemptypasswords\nExpected: permitemptypasswords no".to_string(),
            references: vec!["https://man.openbsd.org/sshd_config".to_string()],
            caveats: None,
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        let sshd_path = platform.resolve_config_path("sshd_config");

        if !platform.path_exists(&sshd_path) {
            return Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::NotApplicable,
                "SSH configuration not found".to_string(),
                "SSH daemon is not installed.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            );
        }

        let content = match platform.read_file(&sshd_path) {
            Ok(c) => c,
            Err(e) => {
                return Finding::hardening(
                    meta.id,
                    meta.title,
                    meta.category,
                    meta.severity,
                    meta.confidence,
                    Status::Error,
                    format!("Could not read {}: {}", sshd_path.display(), e),
                    "Error reading SSH configuration.".to_string(),
                    meta.remediation,
                    meta.verification,
                    meta.caveats,
                    meta.references,
                );
            }
        };

        let val = parse_sshd_directive(&content, "PermitEmptyPasswords");
        let allows_empty = match val.as_deref() {
            Some("yes") => true,
            _ => false,
        };

        if allows_empty {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Fail,
                "PermitEmptyPasswords is set to 'yes'".to_string(),
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
                format!("PermitEmptyPasswords is set to '{}'", val.unwrap_or_else(|| "no (default)".to_string())),
                "Empty SSH passwords are forbidden.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        }
    }
}
