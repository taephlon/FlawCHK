use flawchk_core::{AssessmentResult, Finding};
use colored::*;

pub fn render_explain_report(assessment: &AssessmentResult) -> String {
    let mut out = String::new();

    out.push_str(&format!("{}\n", "FlawCHK Hardening Assessment Explanation".bold().underline()));
    out.push_str(&format!("System: {} ({})\n", assessment.system_info.os_pretty_name, assessment.system_info.init_system));
    out.push_str(&format!("Profile: {}\n", assessment.profile_name));
    out.push_str("─────────────────────────────────────────────────────\n\n");

    let failed_findings: Vec<&Finding> = assessment.findings.iter().filter(|f| f.is_failed()).collect();

    if failed_findings.is_empty() {
        out.push_str(&format!("{}\n", "✓ All evaluated hardening checks PASSED cleanly!".green().bold()));
        return out;
    }

    out.push_str(&format!("Found {} failed hardening rule(s):\n\n", failed_findings.len()));

    for (idx, finding) in failed_findings.iter().enumerate() {
        out.push_str(&format!("{}. {} [{}] - {}\n", idx + 1, finding.check_id.bold(), finding.severity.badge(), finding.title));
        out.push_str(&format!("   Category:     {}\n", finding.category.display_name()));
        out.push_str(&format!("   Evidence:     {}\n", finding.evidence));
        out.push_str(&format!("   Impact:       {}\n", finding.explanation));
        out.push_str(&format!("   Remediation:  {}\n", finding.remediation));
        out.push_str(&format!("   Verification: {}\n", finding.verification.replace('\n', "\n                 ")));
        if let Some(ref cav) = finding.caveats {
            out.push_str(&format!("   Caveats:      {}\n", cav.yellow()));
        }
        out.push_str("\n");
    }

    out
}
