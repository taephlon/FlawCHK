use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use flawchk_core::{AttackSurface, SystemInfo};

pub trait PlatformAdapter: Send + Sync {
    fn system_info(&self) -> SystemInfo;
    fn is_service_active(&self, service_name: &str) -> bool;
    fn read_sysctl(&self, key: &str) -> Result<String, String>;
    fn resolve_config_path(&self, logical_name: &str) -> PathBuf;
    fn read_file(&self, path: &Path) -> Result<String, std::io::Error>;
    fn is_package_installed(&self, package_name: &str) -> bool;
    fn get_listening_services(&self) -> Vec<String>;
    fn path_exists(&self, path: &Path) -> bool;
    fn get_loaded_kernel_modules(&self) -> Vec<String>;
    fn get_attack_surface(&self) -> AttackSurface;
    fn get_distro_remediation_command(&self, package_name: &str) -> String;
}

#[derive(Debug, Clone)]
pub struct HostPlatform {
    pub os_id: String,
    pub os_name: String,
    pub kernel: String,
    pub init: String,
    pub pkg: String,
    pub mac: String,
    pub custom_root: Option<PathBuf>,
}

impl HostPlatform {
    pub fn detect() -> Self {
        Self::detect_with_root(None)
    }

    pub fn detect_with_root(root: Option<PathBuf>) -> Self {
        let root_dir = root.as_deref().unwrap_or_else(|| Path::new("/"));

        let os_release_path = root_dir.join("etc/os-release");
        let mut os_id = "linux".to_string();
        let mut os_name = "Linux Generic".to_string();

        if os_release_path.exists() {
            if let Ok(content) = fs::read_to_string(&os_release_path) {
                for line in content.lines() {
                    if line.starts_with("ID=") {
                        os_id = line.trim_start_matches("ID=").trim_matches('"').to_lowercase();
                    } else if line.starts_with("PRETTY_NAME=") {
                        os_name = line.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string();
                    }
                }
            }
        } else if root_dir.join("etc/gentoo-release").exists() {
            os_id = "gentoo".to_string();
            os_name = "Gentoo Linux".to_string();
        } else if root_dir.join("etc/redhat-release").exists() {
            os_id = "rhel".to_string();
            os_name = "Red Hat Enterprise Linux".to_string();
        } else if root_dir.join("etc/debian_version").exists() {
            os_id = "debian".to_string();
            os_name = "Debian GNU/Linux".to_string();
        }

        let kernel = if root.is_none() {
            Command::new("uname")
                .arg("-r")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        } else {
            "6.x (Target Root)".to_string()
        };

        let init = if root_dir.join("run/systemd/system").exists() || root_dir.join("etc/systemd").exists() {
            "systemd".to_string()
        } else if root_dir.join("run/openrc").exists() || root_dir.join("etc/init.d").exists() {
            "OpenRC".to_string()
        } else if root_dir.join("run/runit").exists() {
            "runit".to_string()
        } else {
            "sysvinit/other".to_string()
        };

        let pkg = match os_id.as_str() {
            "gentoo" => "Portage (emerge)".to_string(),
            "ubuntu" | "debian" => "apt/dpkg".to_string(),
            "fedora" | "rhel" | "centos" | "rocky" | "alma" => "dnf/rpm".to_string(),
            "arch" | "manjaro" => "pacman".to_string(),
            "alpine" => "apk".to_string(),
            "void" => "xbps".to_string(),
            _ => "generic".to_string(),
        };

        let selinux_path = root_dir.join("sys/fs/selinux");
        let apparmor_path = root_dir.join("sys/kernel/security/apparmor");

        let mac = if selinux_path.exists() {
            "SELinux".to_string()
        } else if apparmor_path.exists() {
            "AppArmor".to_string()
        } else {
            "None / Standard DAC".to_string()
        };

        Self {
            os_id,
            os_name,
            kernel,
            init,
            pkg,
            mac,
            custom_root: root,
        }
    }

    fn resolve_path(&self, relative_or_abs: &str) -> PathBuf {
        let p = Path::new(relative_or_abs);
        if let Some(ref root) = self.custom_root {
            if p.is_absolute() {
                let stripped = p.strip_prefix("/").unwrap_or(p);
                root.join(stripped)
            } else {
                root.join(p)
            }
        } else {
            p.to_path_buf()
        }
    }
}

impl PlatformAdapter for HostPlatform {
    fn system_info(&self) -> SystemInfo {
        SystemInfo {
            os_name: self.os_id.clone(),
            os_pretty_name: self.os_name.clone(),
            kernel_version: self.kernel.clone(),
            init_system: self.init.clone(),
            package_manager: self.pkg.clone(),
            mac_system: self.mac.clone(),
        }
    }

    fn is_service_active(&self, service_name: &str) -> bool {
        if self.custom_root.is_some() {
            return false;
        }

        if self.init == "systemd" {
            let output = Command::new("systemctl")
                .args(["is-active", service_name])
                .output();
            if let Ok(out) = output {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                return text == "active";
            }
        } else if self.init == "OpenRC" {
            let output = Command::new("rc-service")
                .args([service_name, "status"])
                .output();
            if let Ok(out) = output {
                let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
                return text.contains("started") || text.contains("running");
            }
        }

        if let Ok(out) = Command::new("pgrep").arg(service_name).output() {
            return !out.stdout.is_empty();
        }

        false
    }

    fn read_sysctl(&self, key: &str) -> Result<String, String> {
        let proc_path = format!("/proc/sys/{}", key.replace('.', "/"));
        let resolved = self.resolve_path(&proc_path);
        if resolved.exists() {
            fs::read_to_string(&resolved)
                .map(|s| s.trim().to_string())
                .map_err(|e| e.to_string())
        } else if self.custom_root.is_none() {
            let output = Command::new("sysctl")
                .args(["-n", key])
                .output()
                .map_err(|e| e.to_string())?;
            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                Err(format!("sysctl {} returned non-zero exit code", key))
            }
        } else {
            Err(format!("sysctl parameter {} not found in target root", key))
        }
    }

    fn resolve_config_path(&self, logical_name: &str) -> PathBuf {
        let rel_path = match logical_name {
            "sshd_config" => "/etc/ssh/sshd_config",
            "shadow" => "/etc/shadow",
            "passwd" => "/etc/passwd",
            "sudoers" => "/etc/sudoers",
            "fstab" => "/etc/fstab",
            "login.defs" => "/etc/login.defs",
            "auditd.conf" => "/etc/audit/auditd.conf",
            _ => logical_name,
        };
        self.resolve_path(rel_path)
    }

    fn read_file(&self, path: &Path) -> Result<String, std::io::Error> {
        let resolved = if path.is_absolute() && self.custom_root.is_some() {
            let relative = path.strip_prefix("/").unwrap_or(path);
            self.custom_root.as_ref().unwrap().join(relative)
        } else {
            path.to_path_buf()
        };
        fs::read_to_string(resolved)
    }

    fn is_package_installed(&self, package_name: &str) -> bool {
        if package_name.eq_ignore_ascii_case("linux-kernel") || package_name.eq_ignore_ascii_case("kernel") {
            return true;
        }

        if self.custom_root.is_some() {
            return false;
        }

        match self.os_id.as_str() {
            "gentoo" => {
                Command::new("qlist")
                    .args(["-I", package_name])
                    .output()
                    .map(|o| !o.stdout.is_empty())
                    .unwrap_or(false)
            }
            "ubuntu" | "debian" => {
                Command::new("dpkg")
                    .args(["-s", package_name])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            }
            "fedora" | "rhel" | "centos" => {
                Command::new("rpm")
                    .args(["-q", package_name])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    fn get_listening_services(&self) -> Vec<String> {
        if self.custom_root.is_some() {
            return Vec::new();
        }

        let mut services = Vec::new();
        if let Ok(output) = Command::new("ss").args(["-tuln"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("LISTEN") {
                    services.push(line.to_string());
                }
            }
        }
        services
    }

    fn path_exists(&self, path: &Path) -> bool {
        let resolved = if path.is_absolute() && self.custom_root.is_some() {
            let relative = path.strip_prefix("/").unwrap_or(path);
            self.custom_root.as_ref().unwrap().join(relative)
        } else {
            path.to_path_buf()
        };
        resolved.exists()
    }

    fn get_loaded_kernel_modules(&self) -> Vec<String> {
        let proc_modules = self.resolve_path("/proc/modules");
        if proc_modules.exists() {
            if let Ok(content) = fs::read_to_string(&proc_modules) {
                return content
                    .lines()
                    .filter_map(|l| l.split_whitespace().next().map(|s| s.to_string()))
                    .collect();
            }
        }

        if let Ok(out) = Command::new("lsmod").output() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            return stdout
                .lines()
                .skip(1)
                .filter_map(|l| l.split_whitespace().next().map(|s| s.to_string()))
                .collect();
        }

        Vec::new()
    }

    fn get_attack_surface(&self) -> AttackSurface {
        let listening = self.get_listening_services();
        let loaded_mods = self.get_loaded_kernel_modules();
        let mut active_services = Vec::new();

        let common_daemons = [
            "sshd", "cupsd", "cups", "ksmbd", "smbd", "nfsd", "nginx", "httpd",
            "apache2", "dockerd", "containerd", "systemd-resolved", "auditd", "named",
        ];

        for d in &common_daemons {
            if self.is_service_active(d) {
                active_services.push(d.to_string());
            }
        }

        let mut mac_mods = Vec::new();
        if self.mac != "None / Standard DAC" {
            mac_mods.push(self.mac.clone());
        }

        AttackSurface {
            listening_ports: listening,
            active_services,
            loaded_kernel_modules: loaded_mods,
            security_modules: mac_mods,
        }
    }

    fn get_distro_remediation_command(&self, package_name: &str) -> String {
        match self.os_id.as_str() {
            "gentoo" => format!("emerge --sync && emerge -avuDN sys-kernel/gentoo-sources {}", package_name),
            "ubuntu" | "debian" => format!("sudo apt update && sudo apt install --only-upgrade {}", package_name),
            "fedora" | "rhel" | "centos" | "rocky" | "alma" => format!("sudo dnf upgrade {}", package_name),
            "arch" | "manjaro" => format!("sudo pacman -Syu {}", package_name),
            "alpine" => format!("apk update && apk upgrade {}", package_name),
            "void" => format!("xbps-install -Su {}", package_name),
            _ => format!("Upgrade package '{}' using system package manager", package_name),
        }
    }
}
