use flawchk_core::AssessmentResult;
use colored::*;

pub fn render_text_summary(result: &AssessmentResult, colorize: bool) -> String {
    let mut out = String::new();

    out.push_str("\nFlawCHK Linux Hardening Assessment\n");
    out.push_str("──────────────────────────────────────\n\n");

    out.push_str("System\n");
    out.push_str(&format!("  OS:       {}\n", result.system_info.os_pretty_name));
    out.push_str(&format!("  Kernel:   {}\n", result.system_info.kernel_version));
    out.push_str(&format!("  Init:     {}\n\n", result.system_info.init_system));

    out.push_str("Results\n\n");

    let print_row = |label: &str, count: usize, color_fn: fn(&str) -> ColoredString| -> String {
        if colorize {
            format!("  {:<10} {}\n", color_fn(label).bold(), count)
        } else {
            format!("  {:<10} {}\n", label, count)
        }
    };

    out.push_str(&print_row("CRITICAL", result.summary.critical_count, |s| s.bright_red()));
    out.push_str(&print_row("HIGH", result.summary.high_count, |s| s.red()));
    out.push_str(&print_row("MEDIUM", result.summary.medium_count, |s| s.yellow()));
    out.push_str(&print_row("LOW", result.summary.low_count, |s| s.blue()));
    out.push_str(&print_row("PASS", result.summary.pass_count, |s| s.green()));

    out.push_str("\nOverall: ");
    if colorize {
        if result.summary.status_text == "NEEDS ATTENTION" {
            out.push_str(&result.summary.status_text.red().bold().to_string());
        } else if result.summary.status_text == "MINOR ISSUES FOUND" {
            out.push_str(&result.summary.status_text.yellow().bold().to_string());
        } else {
            out.push_str(&result.summary.status_text.green().bold().to_string());
        }
    } else {
        out.push_str(&result.summary.status_text);
    }
    out.push_str("\n\n");

    out
}
