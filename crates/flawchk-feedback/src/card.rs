use flawchk_core::Finding;
use colored::*;

pub fn render_finding_card(finding: &Finding, colorize: bool) -> String {
    let width = 60;

    let id_str = &finding.check_id;
    let sev_str = finding.severity.plain_str();
    let title_str = &finding.title;
    let status_str = finding.status.plain_str();
    let cat_str = finding.category.display_name();

    let mut out = String::new();

    // Top border
    out.push_str("┌");
    out.push_str(&"─".repeat(width - 2));
    out.push_str("┐\n");

    // Header line: ID & Severity
    let right_spacing = if width > id_str.len() + sev_str.len() + 4 {
        width - id_str.len() - sev_str.len() - 4
    } else {
        2
    };

    let header_line = if colorize {
        format!("│ {}{} {} │\n", id_str.bold(), " ".repeat(right_spacing), finding.severity.badge())
    } else {
        format!("│ {}{}{} │\n", id_str, " ".repeat(right_spacing), sev_str)
    };
    out.push_str(&header_line);

    // Title line
    let title_truncated = if title_str.len() > width - 4 {
        format!("{}...", &title_str[..width - 7])
    } else {
        title_str.to_string()
    };
    let title_padding = width - 4 - title_truncated.len();
    out.push_str(&format!("│ {}{} │\n", title_truncated, " ".repeat(title_padding)));

    // Separator line
    out.push_str("├");
    out.push_str(&"─".repeat(width - 2));
    out.push_str("┤\n");

    // Metadata lines
    let status_colored = if colorize {
        finding.status.badge()
    } else {
        status_str.to_string()
    };
    out.push_str(&format!("│ Status:        {:<width_pad$} │\n", status_colored, width_pad = width - 19));
    out.push_str(&format!("│ Category:      {:<width_pad$} │\n", cat_str, width_pad = width - 19));
    out.push_str(&format!("│ {:<width_pad$} │\n", "", width_pad = width - 4));

    // Section helper
    let format_section = |title: &str, content: &str| -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!("│ {:<width_pad$} │", if colorize { title.bold().to_string() } else { title.to_string() }, width_pad = width - 4));

        for raw_line in content.lines() {
            let words = raw_line.split_whitespace();
            let mut current_line = String::new();

            for word in words {
                if current_line.is_empty() {
                    current_line.push_str(word);
                } else if current_line.len() + 1 + word.len() <= width - 4 {
                    current_line.push(' ');
                    current_line.push_str(word);
                } else {
                    lines.push(format!("│ {:<width_pad$} │", current_line, width_pad = width - 4));
                    current_line = word.to_string();
                }
            }
            if !current_line.is_empty() {
                lines.push(format!("│ {:<width_pad$} │", current_line, width_pad = width - 4));
            }
        }
        lines.push(format!("│ {:<width_pad$} │", "", width_pad = width - 4));
        lines
    };

    // What was found
    for l in format_section("What was found", &finding.evidence) {
        out.push_str(&l);
        out.push('\n');
    }

    // Why it matters
    for l in format_section("Why it matters", &finding.explanation) {
        out.push_str(&l);
        out.push('\n');
    }

    // Recommended fix
    for l in format_section("Recommended fix", &finding.remediation) {
        out.push_str(&l);
        out.push('\n');
    }

    // Verify
    for l in format_section("Verify", &finding.verification) {
        out.push_str(&l);
        out.push('\n');
    }

    // Caveats if any
    if let Some(ref cav) = finding.caveats {
        for l in format_section("⚠️ Caveats", cav) {
            out.push_str(&l);
            out.push('\n');
        }
    }

    // Bottom border
    out.push_str("└");
    out.push_str(&"─".repeat(width - 2));
    out.push_str("┘\n");

    out
}
