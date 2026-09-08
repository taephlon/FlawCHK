use colored::*;

#[derive(Debug, Clone)]
pub struct RemediationStep {
    pub target_file: String,
    pub current_state: String,
    pub proposed_state: String,
    pub action_description: String,
}

pub fn render_dry_run(rule_id: &str, steps: &[RemediationStep], colorize: bool) -> String {
    let mut out = String::new();

    if colorize {
        out.push_str(&format!("{}\n\n", "DRY RUN".yellow().bold()));
    } else {
        out.push_str("DRY RUN\n\n");
    }

    out.push_str(&format!("Simulating remediation for rule {}\n", rule_id));
    out.push_str("─────────────────────────────────────────────────────\n");

    for step in steps {
        out.push_str(&format!("Would modify:\n  {}\n\n", step.target_file));
        out.push_str(&format!("Action:\n  {}\n\n", step.action_description));
        out.push_str(&format!("Current:\n  {}\n\n", step.current_state));
        out.push_str(&format!("New:\n  {}\n\n", step.proposed_state));
    }

    if colorize {
        out.push_str(&format!("{}\n", "No changes were made.".green().bold()));
    } else {
        out.push_str("No changes were made.\n");
    }

    out
}
