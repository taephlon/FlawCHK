use std::fmt;
use serde::{Deserialize, Serialize};
use colored::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ExposureLevel {
    None = 0,
    Reduced = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl ExposureLevel {
    pub fn badge(&self) -> String {
        match self {
            ExposureLevel::Critical => "CRITICAL EXPOSURE".bright_red().bold().to_string(),
            ExposureLevel::High => "HIGH EXPOSURE".red().bold().to_string(),
            ExposureLevel::Medium => "MEDIUM EXPOSURE".yellow().bold().to_string(),
            ExposureLevel::Low => "LOW EXPOSURE".blue().to_string(),
            ExposureLevel::Reduced => "REDUCED EXPOSURE".cyan().to_string(),
            ExposureLevel::None => "NOT EXPOSED".green().to_string(),
        }
    }

    pub fn plain_str(&self) -> &'static str {
        match self {
            ExposureLevel::Critical => "CRITICAL EXPOSURE",
            ExposureLevel::High => "HIGH EXPOSURE",
            ExposureLevel::Medium => "MEDIUM EXPOSURE",
            ExposureLevel::Low => "LOW EXPOSURE",
            ExposureLevel::Reduced => "REDUCED EXPOSURE",
            ExposureLevel::None => "NOT EXPOSED",
        }
    }
}

impl fmt::Display for ExposureLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.plain_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureAnalysis {
    pub score_percentage: u8, // 0 to 100
    pub level: ExposureLevel,
    pub factors: Vec<String>,
    pub mitigations_active: Vec<String>,
    pub attack_path_summary: String,
}
