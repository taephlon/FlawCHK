use flawchk_core::AssessmentResult;

pub fn render_html(result: &AssessmentResult) -> String {
    let mut rows = String::new();

    for f in &result.findings {
        let sev_color = match f.severity {
            flawchk_core::Severity::Critical => "#dc2626",
            flawchk_core::Severity::High => "#ea580c",
            flawchk_core::Severity::Medium => "#d97706",
            flawchk_core::Severity::Low => "#2563eb",
            flawchk_core::Severity::Info => "#0891b2",
        };

        let status_badge = match f.status {
            flawchk_core::Status::Pass => "<span style='background:#10b981;color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;'>PASS</span>",
            flawchk_core::Status::Fail => "<span style='background:#ef4444;color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;'>FAIL</span>",
            flawchk_core::Status::NotApplicable => "<span style='background:#6b7280;color:#fff;padding:2px 8px;border-radius:4px;'>N/A</span>",
            flawchk_core::Status::Error => "<span style='background:#8b5cf6;color:#fff;padding:2px 8px;border-radius:4px;'>ERROR</span>",
        };

        rows.push_str(&format!(
            r#"
            <tr style="border-bottom: 1px solid #e5e7eb;">
                <td style="padding: 12px; font-weight: bold; font-family: monospace;">{}</td>
                <td style="padding: 12px;">{}</td>
                <td style="padding: 12px;">{}</td>
                <td style="padding: 12px;"><span style="color: {}; font-weight: bold;">{}</span></td>
                <td style="padding: 12px;">{}</td>
                <td style="padding: 12px; font-size: 0.9em; color: #374151;">{}</td>
            </tr>
            "#,
            f.check_id,
            f.title,
            f.category.display_name(),
            sev_color,
            f.severity.plain_str(),
            status_badge,
            f.evidence
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FlawCHK Hardening Assessment Report</title>
    <style>
        body {{ font-family: system-ui, -apple-system, sans-serif; background-color: #f9fafb; color: #111827; margin: 0; padding: 40px; }}
        .header {{ background: #1e293b; color: #white; padding: 24px; border-radius: 8px; margin-bottom: 24px; color: #f8fafc; }}
        .summary-cards {{ display: flex; gap: 16px; margin-bottom: 24px; }}
        .card {{ background: white; padding: 16px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); flex: 1; text-align: center; }}
        .card .num {{ font-size: 24px; font-weight: bold; margin-top: 8px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th {{ background: #f1f5f9; text-align: left; padding: 12px; font-weight: 600; font-size: 0.9em; color: #475569; }}
    </style>
</head>
<body>
    <div class="header">
        <h1 style="margin: 0 0 8px 0;">🛡️ FlawCHK Hardening Assessment Report</h1>
        <p style="margin: 0; opacity: 0.8;">OS: {} | Kernel: {} | Init: {} | Profile: {}</p>
    </div>

    <div class="summary-cards">
        <div class="card"><div style="color: #dc2626;">CRITICAL</div><div class="num">{}</div></div>
        <div class="card"><div style="color: #ea580c;">HIGH</div><div class="num">{}</div></div>
        <div class="card"><div style="color: #d97706;">MEDIUM</div><div class="num">{}</div></div>
        <div class="card"><div style="color: #2563eb;">LOW</div><div class="num">{}</div></div>
        <div class="card"><div style="color: #10b981;">PASS</div><div class="num">{}</div></div>
    </div>

    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Evidence</th>
            </tr>
        </thead>
        <tbody>
            {}
        </tbody>
    </table>
</body>
</html>
"#,
        result.system_info.os_pretty_name,
        result.system_info.kernel_version,
        result.system_info.init_system,
        result.profile_name,
        result.summary.critical_count,
        result.summary.high_count,
        result.summary.medium_count,
        result.summary.low_count,
        result.summary.pass_count,
        rows
    )
}
