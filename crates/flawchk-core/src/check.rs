use std::fmt;
use serde::{Deserialize, Serialize};
use crate::severity::{Confidence, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Ssh,
    Kernel,
    Users,
    Filesystem,
    Network,
    Services,
    Logging,
    Mac,
    Containers,
    Crypto,
}

impl Category {
    pub fn display_name(&self) -> &'static str {
        match self {
            Category::Ssh => "SSH Hardening",
            Category::Kernel => "Kernel Security",
            Category::Users => "User & Access Controls",
            Category::Filesystem => "Filesystem Permissions",
            Category::Network => "Network Hardening",
            Category::Services => "Service Configuration",
            Category::Logging => "Logging & Audit",
            Category::Mac => "Mandatory Access Control",
            Category::Containers => "Container Security",
            Category::Crypto => "Cryptography Policy",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckMetadata {
    pub id: String,
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub verification: String,
    pub references: Vec<String>,
    pub caveats: Option<String>,
}
