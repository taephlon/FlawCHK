use std::path::PathBuf;
use std::process;
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;

use flawchk_core::{AssessmentResult, Profile, Severity};
use flawchk_distro::{HostPlatform, PlatformAdapter};
use flawchk_feedback::{render_explain_report, render_finding_card};
use flawchk_report::{render_html, render_json, render_sarif, render_text_summary};
use flawchk_remediation::{get_remediation_plan, render_dry_run};
use flawchk_rules::RuleRegistry;

#[derive(Parser)]
#[command(
    name = "flawchk",
    author = "FlawCHK Contributors",
    version = "0.1.0",
    about = "🛡️ FlawCHK — Cross-distribution Linux hardening assessment & remediation guidance",
    long_about = "Cross-distribution Linux hardening assessment tool designed with actionable feedback, explainability, severity scoring, and distro abstraction."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Target root directory for assessment (chroot or mounted system root)
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    /// Disable colored terminal output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform a hardening scan on the system
    Scan {
        /// Security profile (baseline, server, workstation, minimal)
        #[arg(short, long, default_value = "baseline")]
        profile: String,

        /// Output format (text, json, sarif, html)
        #[arg(short, long, value_enum, default_value_t = Format::Text)]
        format: Format,

        /// Exit with non-zero code if findings equal or exceed severity (critical, high, medium, low)
        #[arg(long)]
        fail_on: Option<String>,
    },

    /// Show detailed feedback card for a specific check ID
    Show {
        /// Rule ID (e.g., FLAW-SSH-001)
        rule_id: String,
    },

    /// Explain detected security findings or a specific rule in human-readable terms
    Explain {
        /// Rule ID to explain (if omitted, explains all failed findings from a scan)
        rule_id: Option<String>,

        /// Only explain failed findings
        #[arg(long)]
        failed: bool,

        /// Security profile to use when scanning for explanation
        #[arg(short, long, default_value = "baseline")]
        profile: String,
    },

    /// Simulate or apply remediation for a specific check ID
    Fix {
        /// Rule ID to remediate (e.g. FLAW-SSH-001)
        rule_id: String,

        /// Perform a dry-run simulation without making changes
        #[arg(long, default_value_t = true)]
        dry_run: bool,
    },

    /// List all registered hardening rules
    Rules,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
    Html,
}

fn main() {
    let cli = Cli::parse();

    if cli.no_color {
        colored::control::set_override(false);
    }

    let command = cli.command.unwrap_or(Commands::Scan {
        profile: "baseline".to_string(),
        format: Format::Text,
        fail_on: None,
    });

    let platform = HostPlatform::detect_with_root(cli.root);
    let mut registry = RuleRegistry::new();
    registry.register_all_builtin();

    match command {
        Commands::Scan {
            profile: profile_name,
            format,
            fail_on,
        } => {
            let profile = match profile_name.to_lowercase().as_str() {
                "baseline" => Profile::default_baseline(),
                "server" => Profile::default_server(),
                "workstation" => Profile::default_workstation(),
                "minimal" => Profile::default_minimal(),
                _ => {
                    eprintln!("Unknown profile: {}. Defaulting to baseline.", profile_name);
                    Profile::default_baseline()
                }
            };

            let findings = registry.evaluate_profile(&profile, &platform);
            let summary = flawchk_core::AssessmentSummary::from_findings(&findings);

            let result = AssessmentResult {
                system_info: platform.system_info(),
                profile_name: profile.name,
                timestamp: chrono::Utc::now().to_rfc3339(),
                summary,
                findings,
            };

            match format {
                Format::Text => {
                    let text = render_text_summary(&result, !cli.no_color);
                    print!("{}", text);
                }
                Format::Json => {
                    if let Ok(json_str) = render_json(&result) {
                        println!("{}", json_str);
                    }
                }
                Format::Sarif => {
                    println!("{}", render_sarif(&result));
                }
                Format::Html => {
                    println!("{}", render_html(&result));
                }
            }

            if let Some(fail_sev_str) = fail_on {
                if let Ok(threshold) = fail_sev_str.parse::<Severity>() {
                    let has_exceeding = result.findings.iter().any(|f| f.is_failed() && f.severity >= threshold);
                    if has_exceeding {
                        eprintln!(
                            "{}",
                            format!("Build failed: Findings meeting or exceeding severity threshold '{}' were detected.", threshold)
                                .red()
                                .bold()
                        );
                        process::exit(1);
                    }
                }
            }
        }

        Commands::Show { rule_id } => {
            if let Some(rule) = registry.get_rule(&rule_id) {
                let finding = rule.evaluate(&platform);
                let card = render_finding_card(&finding, !cli.no_color);
                print!("{}", card);
            } else {
                eprintln!("Rule '{}' not found in registry.", rule_id);
                process::exit(1);
            }
        }

        Commands::Explain {
            rule_id,
            failed: _,
            profile: profile_name,
        } => {
            if let Some(id) = rule_id {
                if let Some(rule) = registry.get_rule(&id) {
                    let finding = rule.evaluate(&platform);
                    let card = render_finding_card(&finding, !cli.no_color);
                    print!("{}", card);
                } else {
                    eprintln!("Rule '{}' not found in registry.", id);
                    process::exit(1);
                }
            } else {
                let profile = match profile_name.to_lowercase().as_str() {
                    "baseline" => Profile::default_baseline(),
                    "server" => Profile::default_server(),
                    "workstation" => Profile::default_workstation(),
                    "minimal" => Profile::default_minimal(),
                    _ => Profile::default_baseline(),
                };

                let findings = registry.evaluate_profile(&profile, &platform);
                let summary = flawchk_core::AssessmentSummary::from_findings(&findings);
                let result = AssessmentResult {
                    system_info: platform.system_info(),
                    profile_name: profile.name,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    summary,
                    findings,
                };
                let report = render_explain_report(&result);
                print!("{}", report);
            }
        }

        Commands::Fix { rule_id, dry_run: _ } => {
            let steps = get_remediation_plan(&rule_id, &platform);
            let dry_output = render_dry_run(&rule_id, &steps, !cli.no_color);
            print!("{}", dry_output);
        }

        Commands::Rules => {
            println!("FlawCHK Registered Hardening Rules (Milestone 0.1)\n");
            println!("{:<16} {:<12} {:<24} Title", "Rule ID", "Severity", "Category");
            println!("{}", "─".repeat(75));

            for rule in registry.rules() {
                let meta = rule.metadata();
                println!(
                    "{:<16} {:<12} {:<24} {}",
                    meta.id,
                    meta.severity.plain_str(),
                    meta.category.display_name(),
                    meta.title
                );
            }
            println!();
        }
    }
}
