use flawchk_core::AttackSurface;
use colored::*;

pub fn render_attack_surface_inventory(surface: &AttackSurface, colorize: bool) -> String {
    let mut out = String::new();

    let header = "ATTACK SURFACE INVENTORY\n────────────────────────────────────\n";
    if colorize {
        out.push_str(&header.bold().to_string());
    } else {
        out.push_str(header);
    }

    out.push_str("\nNetwork Listeners:\n");
    if surface.listening_ports.is_empty() {
        out.push_str("  (No active listening network sockets detected)\n");
    } else {
        for port in &surface.listening_ports {
            out.push_str(&format!("  {}\n", port));
        }
    }

    out.push_str("\nActive Services & Daemons:\n");
    if surface.active_services.is_empty() {
        out.push_str("  (No active common network services detected)\n");
    } else {
        for svc in &surface.active_services {
            out.push_str(&format!("  {:<20} active\n", svc));
        }
    }

    out.push_str("\nLoaded Kernel Subsystems / Modules:\n");
    if surface.loaded_kernel_modules.is_empty() {
        out.push_str("  (No non-builtin loaded kernel modules queryable)\n");
    } else {
        for m in surface.loaded_kernel_modules.iter().take(15) {
            out.push_str(&format!("  {}\n", m));
        }
        if surface.loaded_kernel_modules.len() > 15 {
            out.push_str(&format!("  ... and {} more loaded modules\n", surface.loaded_kernel_modules.len() - 15));
        }
    }

    out.push_str("\nSecurity Frameworks:\n");
    for mac in &surface.security_modules {
        out.push_str(&format!("  {}\n", mac));
    }
    out.push('\n');

    out
}
