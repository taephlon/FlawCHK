# 🤝 Contributing to FlawCHK

Thank you for your interest in contributing to **FlawCHK**! FlawCHK is built on the philosophy that Linux security checkers should provide **actionable feedback, deep explainability, distribution-aware abstraction, and runtime exposure intelligence**.

Whether you are adding a new hardening rule, enriching CVE vulnerability intelligence, implementing a distribution adapter, or fixing documentation, your contributions are welcome!

---

## 🎯 Ways to Contribute

You can contribute to FlawCHK in several key areas:

1. 🛡️ **Hardening Rules** (`crates/flawchk-rules`): Add checks for Linux security baselines (Kernel, SSH, Users, Filesystem, Network, Logging, Containers, MAC).
2. 🧬 **CVE Vulnerability Intelligence** (`crates/flawchk-cve`): Add advisories, kernel subsystem CVE entries, CVSS metadata, and exposure correlation rules.
3. 🐧 **Distribution Adapters** (`crates/flawchk-distro`): Expand support for Linux distributions (Gentoo, Ubuntu, Debian, Fedora, Arch, Alpine, RHEL, openSUSE, Void, NixOS).
4. 📊 **Report Exporters** (`crates/flawchk-report`): Add new report formats (Markdown, CSV, OpenSCAP, PDF).
5. 🎨 **User Experience & Feedback UI** (`crates/flawchk-feedback`): Improve card boxes, dashboards, dependency graphs, or terminal formatting.
6. 📚 **Documentation & Playbooks** (`README.md`, `docs/`): Write security write-ups, vulnerability explanations, or sysadmin playbooks.

---

## 🚀 Development Quickstart

### Prerequisites
- **Rust Toolchain**: 1.75.0 or newer (with `cargo`, `rustc`, `rustfmt`, `clippy`).
- **Operating System**: Linux (any distribution, e.g., Gentoo, Ubuntu, Fedora, Arch, Debian, Alpine).

### Clone & Build
```bash
# Clone repository
git clone https://github.com/flawchk/flawchk.git
cd flawchk

# Build debug workspace
cargo build

# Run test suite
cargo test --workspace

# Run CLI locally
cargo run --bin flawchk -- assess
```

---

## 🛡️ Step-by-Step: Adding a New Hardening Rule

FlawCHK rules are modular structs that implement the `Rule` trait in `crates/flawchk-rules`.

### Step 1: Define the Rule Struct
Open or create a module in `crates/flawchk-rules/src/` (e.g. `ssh.rs`, `kernel.rs`, `users.rs`, `filesystem.rs`, `network.rs`, `logging.rs`, or a new category).

```rust
use flawchk_core::{Category, CheckMetadata, Confidence, Finding, Severity, Status};
use flawchk_distro::PlatformAdapter;
use crate::registry::Rule;

pub struct MyNewHardeningRule;

impl Rule for MyNewHardeningRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-CAT-001".to_string(),
            title: "Short, descriptive title of check".to_string(),
            category: Category::Kernel, // Choose Category enum variant
            severity: Severity::High,  // Critical, High, Medium, Low, Info
            confidence: Confidence::High,
            description: "Clear explanation of what is being inspected.".to_string(),
            impact: "Explanation of why this flaw increases system risk.".to_string(),
            remediation: "Actionable command/step to fix the flaw.".to_string(),
            verification: "Command to verify the fix and expected output.".to_string(),
            references: vec!["https://example.com/reference-doc".to_string()],
            caveats: Some("Operational caveats or service interruption risks.".to_string()),
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        let meta = self.metadata();

        // 1. Use distro-agnostic platform methods
        let config_path = platform.resolve_config_path("my_config.conf");

        if !platform.path_exists(&config_path) {
            return Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::NotApplicable,
                "Configuration file not found".to_string(),
                "Target daemon is not installed.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            );
        }

        // 2. Evaluate condition
        let is_vulnerable = true;

        if is_vulnerable {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Fail,
                "Evidence showing vulnerable state".to_string(),
                meta.impact,
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        } else {
            Finding::hardening(
                meta.id,
                meta.title,
                meta.category,
                meta.severity,
                meta.confidence,
                Status::Pass,
                "Evidence showing hardened state".to_string(),
                "Configuration is secure.".to_string(),
                meta.remediation,
                meta.verification,
                meta.caveats,
                meta.references,
            )
        }
    }
}
```

### Step 2: Register in RuleRegistry
Add your new rule registration in `register_all_builtin()` inside `crates/flawchk-rules/src/registry.rs`:

```rust
pub fn register_all_builtin(&mut self) {
    // ...
    self.register(Box::new(MyNewHardeningRule));
}
```

### Step 3: Write Fixture Tests
Add unit or fixture tests using `MockPlatform` in `crates/flawchk-rules/tests/rules_test.rs`:

```rust
#[test]
fn test_my_new_hardening_rule() {
    let mock = MockPlatform::new();
    mock.set_file("/etc/my_config.conf", "InsecureSetting = true\n");

    let mut registry = RuleRegistry::new();
    registry.register_all_builtin();

    let rule = registry.get_rule("FLAW-CAT-001").expect("Rule registered");
    let finding = rule.evaluate(&mock);

    assert_eq!(finding.status, Status::Fail);
}
```

### Step 4: Add Write-up to README.md
Include rule details in the `Rule Write-ups` catalog in `README.md`.

---

## 🧬 Step-by-Step: Adding CVE Intelligence Entries

CVE entries live in `crates/flawchk-cve/src/db.rs`.

Add a new `CveEntry` to `load_builtin_cve_database()`:

```rust
CveEntry {
    cve_id: "CVE-2026-XXXXX".to_string(),
    title: "Linux Kernel Subsystem Memory Corruption".to_string(),
    package_name: "linux-kernel".to_string(),
    affected_version_range: ">= 6.1, < 6.12.20".to_string(),
    fixed_version: "6.12.20".to_string(),
    cvss_score: 8.8,
    attack_vector: "Network".to_string(), // Network, Local, Adjacent
    privileges_required: "None".to_string(), // None, Low, High
    subsystem: "Kernel Subsystem / Module".to_string(),
    required_module: Some("vulnerable_module".to_string()),
    required_service: Some("daemon_name".to_string()),
    description: "Technical root cause explanation of the vulnerability.".to_string(),
    temporary_mitigation: Some("Modprobe blacklist or sysctl mitigation when patch is unavailable.".to_string()),
    references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX".to_string()],
}
```

FlawCHK's `CveIntelligenceEngine` will automatically perform runtime exposure correlation against active host modules, network listeners, and package managers!

---

## 🐧 Step-by-Step: Enhancing Distribution Support

Distribution intelligence lives in `crates/flawchk-distro/src/platform.rs`.

To support a new Linux distribution:

1. **OS Identification**: Extend `HostPlatform::detect_with_root()` to check `/etc/os-release` or release files (e.g. `nixos-release`, `alpine-release`).
2. **Package Manager Integration**: Add package checking logic to `is_package_installed()` (`dpkg`, `rpm`, `qlist`, `pacman`, `apk`, `xbps`, `nix`).
3. **Init System Integration**: Add service status checking in `is_service_active()` (systemd `systemctl`, OpenRC `rc-service`, runit `sv`, s6).
4. **Remediation Generator**: Update `get_distro_remediation_command()` to output native upgrade commands (`emerge`, `apt`, `dnf`, `pacman`, `apk`, `xbps`, `nix-env`).

---

## 🧪 Code Style & Testing Workflow

Before submitting a Pull Request, verify your changes pass formatting, linting, and tests:

```bash
# Format code according to Rust standards
cargo fmt --all

# Run Clippy lints
cargo clippy --workspace --all-targets -- -D warnings

# Execute all workspace tests
cargo test --workspace

# Verify CLI builds and executes
cargo run --bin flawchk -- assess
```

---

## 📝 Commit Convention & Pull Request Guidelines

We follow Conventional Commits for clear Git logs:

- `feat: add FLAW-FS-004 check for permissions on /etc/shadow`
- `fix: correct sysctl path resolution in Gentoo OpenRC adapter`
- `docs: update hardening playbook in README.md`
- `test: add mock test fixture for kernel ASLR check`

### Pull Request Checklist
- [ ] Code builds without warnings (`cargo check --workspace`).
- [ ] All tests pass (`cargo test --workspace`).
- [ ] Code formatted with `cargo fmt`.
- [ ] New rules or CVE entries documented in `README.md`.
- [ ] Descriptive commit messages used.

---

## 💬 Getting Help & Questions

If you have questions about architecture, rule design, or distro integration, feel free to open a Discussion or Issue on our repository.

Thank you for helping make Linux systems safer, more transparent, and easier to harden! 🛡️
