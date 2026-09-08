use serde_json::{json, Value};
use flawchk_core::{AssessmentResult, Severity, Status};

pub fn render_sarif(result: &AssessmentResult) -> String {
    let mut rules = Vec::new();
    let mut sarif_results = Vec::new();

    for finding in &result.findings {
        let level = match finding.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        };

        rules.push(json!({
            "id": finding.check_id,
            "shortDescription": {
                "text": finding.title
            },
            "fullDescription": {
                "text": finding.explanation
            },
            "help": {
                "text": format!("Remediation:\n{}\n\nVerification:\n{}", finding.remediation, finding.verification)
            },
            "properties": {
                "category": finding.category.display_name(),
                "severity": finding.severity.plain_str()
            }
        }));

        if finding.status == Status::Fail {
            sarif_results.push(json!({
                "ruleId": finding.check_id,
                "level": level,
                "message": {
                    "text": format!("{}: {}", finding.title, finding.evidence)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "system/configuration"
                        }
                    }
                }]
            }));
        }
    }

    let sarif_doc: Value = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "FlawCHK",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/flawchk/flawchk",
                    "rules": rules
                }
            },
            "results": sarif_results
        }]
    });

    serde_json::to_string_pretty(&sarif_doc).unwrap_or_default()
}
