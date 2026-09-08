use flawchk_core::{AssessmentResult, Finding};
use colored::*;

pub fn render_assess_dashboard(assessment: &AssessmentResult, colorize: bool) -> String {
    let mut out = String::new();

    let title_box = "╔════════════════════════════════════════════════════╗\n\
                     ║                 FLAWCHK ASSESSMENT                 ║\n\
                     ╚════════════════════════════════════════════════════╝";

    if colorize {
        out.push_str(&format!("{}\n\n", title_box.cyan().bold()));
    } else {
        out.push_str(&format!("{}\n\n", title_box));
    }

    out.push_str(&format!("Host:       {}\n", assessment.system_info.os_pretty_name));
    out.push_str(&format!("Kernel:     {}\n", assessment.system_info.kernel_version));
    out.push_str(&format!("Init:       {}\n", assessment.system_info.init_system));
    out.push_str(&format!("Profile:    {}\n\n", assessment.profile_name));

    out.push_str("HARDENING\n");
    out.push_str(&format!("  Critical   {}\n", assessment.summary.critical_count));
    out.push_str(&format!("  High       {}\n", assessment.summary.high_count));
    out.push_str(&format!("  Medium     {}\n", assessment.summary.medium_count));
    out.push_str(&format!("  Low        {}\n\n", assessment.summary.low_count));

    out.push_str("VULNERABILITIES & EXPOSURE\n");
    out.push_str(&format!("  🔴 High Exposure      {}\n", assessment.summary.exposure_high + assessment.summary.exposure_critical));
    out.push_str(&format!("  🟠 Medium Exposure    {}\n", assessment.summary.exposure_medium));
    out.push_str(&format!("  🟢 Reduced / Low      {}\n\n", assessment.summary.exposure_low));

    out.push_str("TOP PRIORITIES\n");
    out.push_str("──────────────────────────────────────────────────────\n\n");

    let failed_findings: Vec<&Finding> = assessment.findings.iter().filter(|f| f.is_failed()).collect();

    if failed_findings.is_empty() {
        out.push_str("  ✓ No high priority security flaws or vulnerabilities detected!\n\n");
    } else {
        for (idx, f) in failed_findings.iter().take(5).enumerate() {
            let indicator = if f.severity >= flawchk_core::Severity::High {
                "🔴".to_string()
            } else {
                "🟠".to_string()
            };

            let title_line = format!("{}. {} {} — {}", idx + 1, indicator, f.check_id, f.title);
            if colorize {
                out.push_str(&format!("{}\n", title_line.bold()));
            } else {
                out.push_str(&format!("{}\n", title_line));
            }

            if let Some(ref exp) = f.exposure_analysis {
                out.push_str(&format!("   Exposure: {}\n", exp.attack_path_summary));
            } else {
                out.push_str(&format!("   Category: {}\n", f.category.display_name()));
            }
            out.push_str(&format!("   Action:   {}\n\n", f.remediation.lines().next().unwrap_or("")));
        }
    }

    out.push_str("──────────────────────────────────────────────────────\n");
    out.push_str("Run: flawchk show <ID> to view evidence, impact, and verification steps.\n\n");

    out
}
