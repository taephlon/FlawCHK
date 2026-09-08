use flawchk_core::{Category, CheckMetadata, Confidence, Finding, Severity, Status};
use flawchk_distro::PlatformAdapter;
use crate::registry::{Rule, RuleRegistry};

pub fn register_user_rules(registry: &mut RuleRegistry) {
    registry.register(Box::new(UidZeroRule));
    registry.register(Box::new(EmptyPasswordShadowRule));
    registry.register(Box::new(PasswordMaxDaysRule));
}

// --- FLAW-USER-001 ---
pub struct UidZeroRule;

impl Rule for UidZeroRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-USER-001".to_string(),
            title: "Non-root account with UID 0 detected".to_string(),
            category: Category::Users,
            severity: Severity::Critical,
            confidence: Confidence::High,
            description: "Root is the only account that should possess User Identifier (UID) 0.".to_string(),
            impact: "Any user with UID 0 has full root privileges on the Linux system, bypassing standard user separation.".to_string(),
            remediation: "Edit /etc/passwd to assign non-zero unique UIDs to non-root user accounts or remove malicious backdoors.".to_string(),
            verification: "Run: awk -F: '($3 == 0) { print $1 }' /etc/passwd\nExpected: root".to_string(),
            references: vec!["https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html".to_string()],
            caveats: None,
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        let passwd_path = platform.resolve_config_path("passwd");

        if !platform.path_exists(&passwd_path) {
            return Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Error,
                "/etc/passwd file not found".to_string(),
                "Cannot evaluate user accounts without /etc/passwd.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            );
        }

        let content = match platform.read_file(&passwd_path) {
            Ok(c) => c,
            Err(e) => {
                return Finding::hardening(
                    meta.id,
                    meta.title,
                    meta.category,
                    meta.severity,
                    meta.confidence,
                    Status::Error,
                    format!("Error reading /etc/passwd: {}", e),
                    "Unable to parse user registry.".to_string(),
                    meta.remediation,
                    meta.verification,
                    meta.caveats,
                    meta.references,
                );
            }
        };

        let mut uid0_users = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                let username = fields[0];
                let uid = fields[2];
                if uid == "0" && username != "root" {
                    uid0_users.push(username.to_string());
                }
            }
        }

        if !uid0_users.is_empty() {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Fail,
                format!("Non-root accounts with UID 0 found: {}", uid0_users.join(", ")),
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
                "Only 'root' has UID 0 in /etc/passwd".to_string(),
                "No unauthorized UID 0 accounts were found.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        }
    }
}

// --- FLAW-USER-002 ---
pub struct EmptyPasswordShadowRule;

impl Rule for EmptyPasswordShadowRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-USER-002".to_string(),
            title: "User account with empty password in shadow file".to_string(),
            category: Category::Users,
            severity: Severity::Critical,
            confidence: Confidence::High,
            description: "Accounts with blank password fields in /etc/shadow allow login without any credentials.".to_string(),
            impact: "Attacker can gain interactive shell or console access without knowing or providing a password.".to_string(),
            remediation: "Lock blank accounts using: passwd -l <username> or set a strong password.".to_string(),
            verification: "Run: awk -F: '($2 == \"\") { print $1 }' /etc/shadow\nExpected: (empty output)".to_string(),
            references: vec!["https://linux.die.net/man/5/shadow".to_string()],
            caveats: Some("Scanning /etc/shadow requires administrative (root) privileges.".to_string()),
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        let shadow_path = platform.resolve_config_path("shadow");

        if !platform.path_exists(&shadow_path) {
            return Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::NotApplicable,
                "Shadow file not found".to_string(),
                "System does not use standard shadow file authentication.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            );
        }

        let content = match platform.read_file(&shadow_path) {
            Ok(c) => c,
            Err(e) => {
                return Finding::hardening(
                    meta.id,
                    meta.title,
                    meta.category,
                    meta.severity,
                    meta.confidence,
                    Status::Error,
                    format!("Unable to read /etc/shadow: {}", e),
                    "Root privileges are required to inspect /etc/shadow.".to_string(),
                    meta.remediation,
                    meta.verification,
                    meta.caveats,
                    meta.references,
                );
            }
        };

        let mut empty_pass_users = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 2 {
                let username = fields[0];
                let pwd_hash = fields[1];
                if pwd_hash.is_empty() {
                    empty_pass_users.push(username.to_string());
                }
            }
        }

        if !empty_pass_users.is_empty() {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Fail,
                format!("Accounts with empty passwords found in /etc/shadow: {}", empty_pass_users.join(", ")),
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
                "No accounts with blank passwords detected in /etc/shadow".to_string(),
                "All configured user accounts have encrypted password hashes or locked fields.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        }
    }
}

// --- FLAW-USER-003 ---
pub struct PasswordMaxDaysRule;

impl Rule for PasswordMaxDaysRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-USER-003".to_string(),
            title: "Unbounded password maximum age".to_string(),
            category: Category::Users,
            severity: Severity::Medium,
            confidence: Confidence::High,
            description: "PASS_MAX_DAYS in /etc/login.defs specifies the maximum number of days a password may be used.".to_string(),
            impact: "Unbounded password age (e.g. 99999 days) means compromised user credentials remain valid indefinitely.".to_string(),
            remediation: "Set PASS_MAX_DAYS 90 (or <= 365) in /etc/login.defs".to_string(),
            verification: "Run: grep '^PASS_MAX_DAYS' /etc/login.defs\nExpected: PASS_MAX_DAYS 90".to_string(),
            references: vec!["https://www.cisecurity.org/benchmarks".to_string()],
            caveats: None,
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        let login_defs = platform.resolve_config_path("login.defs");

        if !platform.path_exists(&login_defs) {
            return Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::NotApplicable,
                "/etc/login.defs not found".to_string(),
                "System login.defs configuration not present.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            );
        }

        let content = match platform.read_file(&login_defs) {
            Ok(c) => c,
            Err(e) => {
                return Finding::hardening(
                    meta.id,
                    meta.title,
                    meta.category,
                    meta.severity,
                    meta.confidence,
                    Status::Error,
                    format!("Error reading /etc/login.defs: {}", e),
                    "Could not inspect login parameters.".to_string(),
                    meta.remediation,
                    meta.verification,
                    meta.caveats,
                    meta.references,
                );
            }
        };

        let mut max_days = None;
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[0] == "PASS_MAX_DAYS" {
                if let Ok(num) = parts[1].parse::<u32>() {
                    max_days = Some(num);
                }
            }
        }

        match max_days {
            Some(days) if days > 365 => Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Fail,
                format!("PASS_MAX_DAYS is set to {} days (recommended <= 365)", days),
                meta.impact,
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            ),
            Some(days) => Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Pass,
                format!("PASS_MAX_DAYS is configured to {} days", days),
                "Password maximum lifetime is bounded.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            ),
            None => Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Fail,
                "PASS_MAX_DAYS parameter is unset or unparseable in /etc/login.defs".to_string(),
                meta.impact,
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            ),
        }
    }
}
