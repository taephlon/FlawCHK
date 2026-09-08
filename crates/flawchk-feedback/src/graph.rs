use flawchk_core::AssessmentResult;
use colored::*;

pub fn render_security_dependency_graph(result: &AssessmentResult, colorize: bool) -> String {
    let mut out = String::new();

    let header = "SECURITY DEPENDENCY GRAPH\n─────────────────────────────────────────────────────\n";
    if colorize {
        out.push_str(&header.bold().to_string());
    } else {
        out.push_str(header);
    }

    let graph_ascii = r#"
                       INTERNET
                           │
                       TCP / UDP Sockets
                           │
                           ▼
                    Network Daemons (sshd / web / RPC)
                           │
                           ▼
                    System Libraries (OpenSSL / glibc)
                           │
                           ▼
                      Linux Kernel
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
     DRBD / Storage     SUNRPC / TLS     Bluetooth / Network
         │                 │                 │
    [CVE-2026-72014]  [CVE-2026-72317]   [CVE-2026-71980]
"#;

    out.push_str(graph_ascii);
    out.push_str("\nNode Security Status Legend:\n");
    if colorize {
        out.push_str(&format!("  {} vulnerable\n", "🔴".red()));
        out.push_str(&format!("  {} potentially affected\n", "🟠".yellow()));
        out.push_str(&format!("  {} patched / mitigated\n", "🟢".green()));
        out.push_str(&format!("  {} not applicable\n\n", "⚪".dimmed()));
    } else {
        out.push_str("  🔴 vulnerable | 🟠 potentially affected | 🟢 patched | ⚪ not applicable\n\n");
    }

    out.push_str("Evaluated Host Attack Surfaces:\n");
    for f in &result.findings {
        if f.cve_id.is_some() && f.is_failed() {
            let badge = if colorize { f.severity.badge() } else { f.severity.plain_str().to_string() };
            out.push_str(&format!("  🔴 [{}] {} - {}\n", badge, f.check_id, f.title));
            if let Some(ref exp) = f.exposure_analysis {
                out.push_str(&format!("     Path: {}\n", exp.attack_path_summary));
            }
        }
    }
    out.push('\n');

    out
}
