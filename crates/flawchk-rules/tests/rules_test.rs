use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use flawchk_core::{Profile, Severity, Status, SystemInfo};
use flawchk_distro::PlatformAdapter;
use flawchk_rules::RuleRegistry;

pub struct MockPlatform {
    pub files: RwLock<HashMap<PathBuf, String>>,
    pub sysctls: RwLock<HashMap<String, String>>,
    pub active_services: RwLock<Vec<String>>,
    pub listening_services: RwLock<Vec<String>>,
}

impl MockPlatform {
    pub fn new() -> Self {
        Self {
            files: RwLock::new(HashMap::new()),
            sysctls: RwLock::new(HashMap::new()),
            active_services: RwLock::new(Vec::new()),
            listening_services: RwLock::new(Vec::new()),
        }
    }

    pub fn set_file(&self, path: &str, content: &str) {
        self.files.write().unwrap().insert(PathBuf::from(path), content.to_string());
    }

    pub fn set_sysctl(&self, key: &str, value: &str) {
        self.sysctls.write().unwrap().insert(key.to_string(), value.to_string());
    }
}

impl PlatformAdapter for MockPlatform {
    fn system_info(&self) -> SystemInfo {
        SystemInfo {
            os_name: "gentoo".to_string(),
            os_pretty_name: "Gentoo Linux".to_string(),
            kernel_version: "6.6.21-gentoo".to_string(),
            init_system: "OpenRC".to_string(),
            package_manager: "Portage (emerge)".to_string(),
            mac_system: "None / Standard DAC".to_string(),
        }
    }

    fn is_service_active(&self, service_name: &str) -> bool {
        self.active_services.read().unwrap().contains(&service_name.to_string())
    }

    fn read_sysctl(&self, key: &str) -> Result<String, String> {
        self.sysctls
            .read()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| format!("Sysctl {} not set", key))
    }

    fn resolve_config_path(&self, logical_name: &str) -> PathBuf {
        PathBuf::from(format!("/etc/{}", logical_name))
    }

    fn read_file(&self, path: &Path) -> Result<String, std::io::Error> {
        if let Some(c) = self.files.read().unwrap().get(path) {
            Ok(c.clone())
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Mock file not found"))
        }
    }

    fn is_package_installed(&self, _package_name: &str) -> bool {
        true
    }

    fn get_listening_services(&self) -> Vec<String> {
        self.listening_services.read().unwrap().clone()
    }

    fn path_exists(&self, path: &Path) -> bool {
        self.files.read().unwrap().contains_key(path)
    }
}

#[test]
fn test_ssh_root_login_vulnerable_fixture() {
    let mock = MockPlatform::new();
    mock.set_file("/etc/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\n");

    let mut registry = RuleRegistry::new();
    registry.register_all_builtin();

    let rule = registry.get_rule("FLAW-SSH-001").expect("Rule missing");
    let finding = rule.evaluate(&mock);

    assert_eq!(finding.status, Status::Fail);
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.evidence.contains("PermitRootLogin is currently set to 'yes'"));
}

#[test]
fn test_ssh_root_login_secure_fixture() {
    let mock = MockPlatform::new();
    mock.set_file("/etc/sshd_config", "PermitRootLogin no\nPasswordAuthentication no\n");

    let mut registry = RuleRegistry::new();
    registry.register_all_builtin();

    let rule = registry.get_rule("FLAW-SSH-001").expect("Rule missing");
    let finding = rule.evaluate(&mock);

    assert_eq!(finding.status, Status::Pass);
}

#[test]
fn test_kernel_sysctl_evaluation() {
    let mock = MockPlatform::new();
    mock.set_sysctl("net.ipv4.ip_forward", "1");
    mock.set_sysctl("kernel.randomize_va_space", "2");

    let mut registry = RuleRegistry::new();
    registry.register_all_builtin();

    let rule_fwd = registry.get_rule("FLAW-KERN-001").unwrap();
    let finding_fwd = rule_fwd.evaluate(&mock);
    assert_eq!(finding_fwd.status, Status::Fail);

    let rule_aslr = registry.get_rule("FLAW-KERN-003").unwrap();
    let finding_aslr = rule_aslr.evaluate(&mock);
    assert_eq!(finding_aslr.status, Status::Pass);
}

#[test]
fn test_profile_evaluation() {
    let mock = MockPlatform::new();
    mock.set_file("/etc/sshd_config", "PermitRootLogin no\n");
    mock.set_sysctl("net.ipv4.ip_forward", "0");
    mock.set_sysctl("net.ipv4.conf.all.accept_redirects", "0");
    mock.set_sysctl("kernel.randomize_va_space", "2");

    let mut registry = RuleRegistry::new();
    registry.register_all_builtin();

    let profile = Profile::default_baseline();
    let findings = registry.evaluate_profile(&profile, &mock);

    assert!(!findings.is_empty());
}
