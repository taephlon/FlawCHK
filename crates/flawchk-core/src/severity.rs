use std::fmt;
use serde::{Deserialize, Serialize};
use colored::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn badge(&self) -> String {
        match self {
            Severity::Critical => "CRITICAL".bright_red().bold().to_string(),
            Severity::High => "HIGH".red().bold().to_string(),
            Severity::Medium => "MEDIUM".yellow().bold().to_string(),
            Severity::Low => "LOW".blue().to_string(),
            Severity::Info => "INFO".cyan().to_string(),
        }
    }

    pub fn plain_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.plain_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "CRITICAL" => Ok(Severity::Critical),
            "HIGH" => Ok(Severity::High),
            "MEDIUM" => Ok(Severity::Medium),
            "LOW" => Ok(Severity::Low),
            "INFO" => Ok(Severity::Info),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::Low => write!(f, "LOW"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::High => write!(f, "HIGH"),
        }
    }
}
