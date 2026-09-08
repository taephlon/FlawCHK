use std::fmt;
use serde::{Deserialize, Serialize};
use colored::*;

use crate::check::Category;
use crate::severity::{Confidence, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Pass,
    Fail,
    NotApplicable,
    Error,
}

impl Status {
    pub fn badge(&self) -> String {
        match self {
            Status::Pass => "PASS".green().bold().to_string(),
            Status::Fail => "FAIL".red().bold().to_string(),
            Status::NotApplicable => "N/A".cyan().to_string(),
            Status::Error => "ERROR".magenta().bold().to_string(),
        }
    }

    pub fn plain_str(&self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::NotApplicable => "N/A",
            Status::Error => "ERROR",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.plain_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check_id: String,
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: Status,
    pub evidence: String,
    pub explanation: String,
    pub remediation: String,
    pub verification: String,
    pub caveats: Option<String>,
    pub references: Vec<String>,
}

impl Finding {
    pub fn is_failed(&self) -> bool {
        matches!(self.status, Status::Fail)
    }
}
