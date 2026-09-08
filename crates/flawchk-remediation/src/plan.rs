use crate::dry_run::RemediationStep;
use flawchk_distro::PlatformAdapter;

pub fn get_remediation_plan(rule_id: &str, platform: &dyn PlatformAdapter) -> Vec<RemediationStep> {
    let mut steps = Vec::new();

    match rule_id.to_uppercase().as_str() {
        "FLAW-SSH-001" => {
            let path = platform.resolve_config_path("sshd_config");
            steps.push(RemediationStep {
                target_file: path.display().to_string(),
                current_state: "PermitRootLogin yes".to_string(),
                proposed_state: "PermitRootLogin no".to_string(),
                action_description: "Set PermitRootLogin to 'no' in OpenSSH daemon configuration and reload sshd".to_string(),
            });
        }
        "FLAW-SSH-002" => {
            let path = platform.resolve_config_path("sshd_config");
            steps.push(RemediationStep {
                target_file: path.display().to_string(),
                current_state: "PasswordAuthentication yes".to_string(),
                proposed_state: "PasswordAuthentication no".to_string(),
                action_description: "Disable SSH password authentication in favor of SSH public keys".to_string(),
            });
        }
        "FLAW-KERN-001" => {
            let path = platform.resolve_config_path("/etc/sysctl.d/99-security.conf");
            steps.push(RemediationStep {
                target_file: path.display().to_string(),
                current_state: "net.ipv4.ip_forward = 1".to_string(),
                proposed_state: "net.ipv4.ip_forward = 0".to_string(),
                action_description: "Disable kernel IPv4 packet forwarding".to_string(),
            });
        }
        "FLAW-KERN-003" => {
            let path = platform.resolve_config_path("/etc/sysctl.d/99-security.conf");
            steps.push(RemediationStep {
                target_file: path.display().to_string(),
                current_state: "kernel.randomize_va_space = 0".to_string(),
                proposed_state: "kernel.randomize_va_space = 2".to_string(),
                action_description: "Enable full Address Space Layout Randomization (ASLR)".to_string(),
            });
        }
        _ => {
            steps.push(RemediationStep {
                target_file: "/etc/system/configuration".to_string(),
                current_state: "Non-compliant setting".to_string(),
                proposed_state: "Hardened security configuration".to_string(),
                action_description: format!("Apply automated security remediation for rule {}", rule_id),
            });
        }
    }

    steps
}
