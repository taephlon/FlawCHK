use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub cve_id: String,
    pub title: String,
    pub package_name: String,
    pub affected_version_range: String,
    pub fixed_version: String,
    pub cvss_score: f32,
    pub attack_vector: String, // Network, Local, Adjacent
    pub privileges_required: String, // None, Low, High
    pub subsystem: String, // e.g. DRBD, SUNRPC, Bluetooth, OpenSSH, ksmbd
    pub required_module: Option<String>,
    pub required_service: Option<String>,
    pub description: String,
    pub temporary_mitigation: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    pub listening_ports: Vec<String>,
    pub active_services: Vec<String>,
    pub loaded_kernel_modules: Vec<String>,
    pub security_modules: Vec<String>,
}
