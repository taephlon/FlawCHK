use std::fs;
use std::os::unix::fs::PermissionsExt;
use flawchk_core::{Category, CheckMetadata, Confidence, Finding, Severity, Status};
use flawchk_distro::PlatformAdapter;
use crate::registry::{Rule, RuleRegistry};

pub fn register_filesystem_rules(registry: &mut RuleRegistry) {
    registry.register(Box::new(WorldWritableSensitiveFilesRule));
    registry.register(Box::new(TmpMountOptionsRule));
    registry.register(Box::new(SuidSgidBinariesRule));
}

// --- FLAW-FS-001 ---
pub struct WorldWritableSensitiveFilesRule;

impl Rule for WorldWritableSensitiveFilesRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-FS-001".to_string(),
            title: "World-writable sensitive system file detected".to_string(),
            category: Category::Filesystem,
            severity: Severity::Critical,
            confidence: Confidence::High,
            description: "World-writable permissions on system configuration files like /etc/passwd, /etc/shadow, or /etc/sudoers allow unprivileged users to modify system authorization.".to_string(),
            impact: "Unprivileged users or compromised low-privilege services can rewrite configuration files to instantly gain root access.".to_string(),
            remediation: "Remove world-write permissions using: chmod o-w /etc/passwd /etc/shadow /etc/sudoers".to_string(),
            verification: "Run: stat -c '%A %n' /etc/shadow /etc/passwd /etc/sudoers\nExpected: no 'w' in world permissions (e.g. -rw-r-----)".to_string(),
            references: vec!["https://www.cisecurity.org/benchmarks".to_string()],
            caveats: None,
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        let sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config"];

        let mut world_writable = Vec::new();

        for file in &sensitive_files {
            let path = platform.resolve_config_path(file.trim_start_matches("/etc/"));
            if platform.path_exists(&path) {
                if let Ok(metadata) = fs::metadata(&path) {
                    let mode = metadata.permissions().mode();
                    // World write bit is 0o002
                    if (mode & 0o002) != 0 {
                        world_writable.push(format!("{} (mode: {:o})", path.display(), mode & 0o777));
                    }
                }
            }
        }

        if !world_writable.is_empty() {
            Finding {
                check_id: meta.id,
                title: meta.title,
                category: meta.category,
                severity: meta.severity,
                confidence: meta.confidence,
                status: Status::Fail,
                evidence: format!("World-writable sensitive system files found: {}", world_writable.join(", ")),
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
                evidence: "No checked sensitive system files (/etc/passwd, shadow, sudoers, sshd_config) are world-writable".to_string(),
                explanation: "Permissions on sensitive configuration files are appropriately restrictive.".to_string(),
                remediation: meta.remediation,
                verification: meta.verification,
                caveats: meta.caveats,
                references: meta.references,
            }
        }
    }
}

// --- FLAW-FS-002 ---
pub struct TmpMountOptionsRule;

impl Rule for TmpMountOptionsRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-FS-002".to_string(),
            title: "Insecure /tmp mount options missing noexec, nosuid, or nodev".to_string(),
            category: Category::Filesystem,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            description: "/tmp is a world-writable directory. Mounting /tmp with nodev, nosuid, and noexec limits binary exploitation.".to_string(),
            impact: "Allowing execution and SUID binaries in /tmp facilitates malicious script and payload execution by low-privilege users.".to_string(),
            remediation: "Ensure /etc/fstab mounts /tmp with nodev,nosuid,noexec options or configure systemd tmp.mount.".to_string(),
            verification: "Run: mount | grep ' /tmp '\nExpected: options include nodev, nosuid, noexec".to_string(),
            references: vec!["https://www.cisecurity.org/benchmarks".to_string()],
            caveats: Some("Some legacy build scripts or package compilers (e.g. Portage / gentoo build dirs) may require executable /tmp if TMPDIR is not set elsewhere.".to_string()),
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        let fstab_path = platform.resolve_config_path("fstab");

        let mut found_tmp_mount = false;
        let mut missing_opts = Vec::new();

        if platform.path_exists(&fstab_path) {
            if let Ok(content) = platform.read_file(&fstab_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with('#') || line.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 && parts[1] == "/tmp" {
                        found_tmp_mount = true;
                        let opts: Vec<&str> = parts[3].split(',').collect();
                        if !opts.contains(&"noexec") {
                            missing_opts.push("noexec");
                        }
                        if !opts.contains(&"nosuid") {
                            missing_opts.push("nosuid");
                        }
                        if !opts.contains(&"nodev") {
                            missing_opts.push("nodev");
                        }
                    }
                }
            }
        }

        if !found_tmp_mount {
            // Check /proc/mounts if fstab didn't specify /tmp explicitly
            let mounts_path = std::path::Path::new("/proc/mounts");
            if platform.path_exists(mounts_path) {
                if let Ok(content) = platform.read_file(mounts_path) {
                    for line in content.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 && parts[1] == "/tmp" {
                            found_tmp_mount = true;
                            let opts: Vec<&str> = parts[3].split(',').collect();
                            if !opts.contains(&"noexec") {
                                missing_opts.push("noexec");
                            }
                            if !opts.contains(&"nosuid") {
                                missing_opts.push("nosuid");
                            }
                            if !opts.contains(&"nodev") {
                                missing_opts.push("nodev");
                            }
                        }
                    }
                }
            }
        }

        if !found_tmp_mount {
            Finding {
                check_id: meta.id,
                title: meta.title,
                category: meta.category,
                severity: meta.severity,
                confidence: meta.confidence,
                status: Status::Fail,
                evidence: "/tmp is not mounted on a separate partition or tmpfs with secure flags".to_string(),
                explanation: meta.impact,
                remediation: meta.remediation,
                verification: meta.verification,
                caveats: meta.caveats,
                references: meta.references,
            }
        } else if !missing_opts.is_empty() {
            Finding {
                check_id: meta.id,
                title: meta.title,
                category: meta.category,
                severity: meta.severity,
                confidence: meta.confidence,
                status: Status::Fail,
                evidence: format!("/tmp mount is missing recommended security options: {}", missing_opts.join(", ")),
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
                evidence: "/tmp partition is securely mounted with nodev, nosuid, and noexec".to_string(),
                explanation: "Hardening mount flags are active on /tmp.".to_string(),
                remediation: meta.remediation,
                verification: meta.verification,
                caveats: meta.caveats,
                references: meta.references,
            }
        }
    }
}

// --- FLAW-FS-003 ---
pub struct SuidSgidBinariesRule;

impl Rule for SuidSgidBinariesRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-FS-003".to_string(),
            title: "Uncommon or rogue SUID/SGID executable binaries present".to_string(),
            category: Category::Filesystem,
            severity: Severity::High,
            confidence: Confidence::Medium,
            description: "SUID/SGID executables run with the privileges of the file owner (often root), creating privilege escalation vectors if vulnerable or malicious.".to_string(),
            impact: "Rogue or unexpected SUID binaries allow local unprivileged users to execute commands as root.".to_string(),
            remediation: "Audit SUID binaries and remove the SUID bit from non-essential utilities: chmod u-s <binary>".to_string(),
            verification: "Run: find /bin /sbin /usr/bin /usr/sbin -perm /6000 -type f\nExpected: Only standard tools like sudo, passwd, su, etc.".to_string(),
            references: vec!["https://gtfobins.github.io/".to_string()],
            caveats: Some("Some SUID binaries like sudo, passwd, and pkexec are legitimate system requirements.".to_string()),
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();
        let target_dirs = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"];

        let standard_suid = [
            "sudo", "passwd", "su", "chsh", "chfn", "gpasswd", "newgrp", "pkexec",
            "mount", "umount", "ping", "ssh-keysign", "crontab", "at",
        ];

        let mut suspicious_suid = Vec::new();

        for dir_str in &target_dirs {
            let dir_path = platform.resolve_config_path(dir_str.trim_start_matches('/'));
            if platform.path_exists(&dir_path) {
                if let Ok(entries) = fs::read_dir(&dir_path) {
                    for entry in entries.flatten() {
                        if let Ok(file_meta) = entry.metadata() {
                            if file_meta.is_file() {
                                let mode = file_meta.permissions().mode();
                                let is_suid = (mode & 0o4000) != 0;
                                let is_sgid = (mode & 0o2000) != 0;
                                if is_suid || is_sgid {
                                    let filename = entry.file_name().to_string_lossy().to_string();
                                    if !standard_suid.contains(&filename.as_str()) {
                                        suspicious_suid.push(format!("{} (mode: {:o})", entry.path().display(), mode & 0o7777));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if !suspicious_suid.is_empty() {
            Finding {
                check_id: meta.id,
                title: meta.title,
                category: meta.category,
                severity: meta.severity,
                confidence: meta.confidence,
                status: Status::Fail,
                evidence: format!("Non-standard SUID/SGID binaries found: {}", suspicious_suid.join(", ")),
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
                evidence: "No non-standard SUID/SGID executable binaries were detected in system binary paths".to_string(),
                explanation: "SUID/SGID executables belong exclusively to standard privilege utilities.".to_string(),
                remediation: meta.remediation,
                verification: meta.verification,
                caveats: meta.caveats,
                references: meta.references,
            }
        }
    }
}
