use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub categories: Vec<String>,
    pub min_severity: Option<String>,
    pub included_rules: Option<Vec<String>>,
    pub excluded_rules: Option<Vec<String>>,
}

impl Profile {
    pub fn default_baseline() -> Self {
        Self {
            name: "baseline".to_string(),
            description: "Default baseline hardening profile for any Linux distribution".to_string(),
            categories: vec![
                "ssh".to_string(),
                "kernel".to_string(),
                "users".to_string(),
                "filesystem".to_string(),
                "network".to_string(),
                "logging".to_string(),
            ],
            min_severity: None,
            included_rules: None,
            excluded_rules: None,
        }
    }

    pub fn default_server() -> Self {
        Self {
            name: "server".to_string(),
            description: "Strict hardening profile tailored for production servers".to_string(),
            categories: vec![
                "ssh".to_string(),
                "kernel".to_string(),
                "users".to_string(),
                "filesystem".to_string(),
                "network".to_string(),
                "services".to_string(),
                "logging".to_string(),
                "mac".to_string(),
            ],
            min_severity: Some("LOW".to_string()),
            included_rules: None,
            excluded_rules: None,
        }
    }

    pub fn default_workstation() -> Self {
        Self {
            name: "workstation".to_string(),
            description: "Hardening profile suitable for Linux desktop/workstation nodes".to_string(),
            categories: vec![
                "kernel".to_string(),
                "users".to_string(),
                "filesystem".to_string(),
                "network".to_string(),
            ],
            min_severity: None,
            included_rules: None,
            excluded_rules: None,
        }
    }

    pub fn default_minimal() -> Self {
        Self {
            name: "minimal".to_string(),
            description: "High and Critical severity security checks only".to_string(),
            categories: vec![],
            min_severity: Some("HIGH".to_string()),
            included_rules: None,
            excluded_rules: None,
        }
    }
}
