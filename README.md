# 🛡️ FlawCHK — Cross-Distribution Linux Hardening Assessment & Remediation Guidance

> **Distribution-aware, not distribution-dependent security assessment.**

FlawCHK is a high-performance Linux security hardening assessment tool written in Rust. Unlike legacy CIS checkers that output opaque `[FAIL]` lines, FlawCHK delivers **actionable feedback**, **deep vulnerability explanations**, **distro-aware remediation instructions**, and **verification steps** for every detected security flaw.

---

## 🎯 Core Philosophy & Project Identity

Every flaw detected by FlawCHK produces structured, human-readable guidance:

```
┌──────────────────────────────────────────────────────────┐
│ FLAW-SSH-001                                         HIGH│
│ SSH permits direct root login                            │
├──────────────────────────────────────────────────────────┤
│ Status:        FAIL                                      │
│ Category:      SSH Hardening                             │
│                                                          │
│ What was found                                           │
│ PermitRootLogin is currently enabled in sshd_config.     │
│                                                          │
│ Why it matters                                           │
│ Direct root authentication increases the impact of       │
│ credential compromise and hinders audit accountability.  │
│                                                          │
│ Recommended fix                                          │
│ Set PermitRootLogin to 'no' in /etc/ssh/sshd_config and  │
│ reload the SSH service.                                  │
│                                                          │
│ Verify                                                   │
│ Run: sshd -T | grep permitrootlogin                      │
│ Expected: permitrootlogin no                             │
│                                                          │
│ ⚠️ Caveats                                               │
│ Ensure an alternative administrative user with sudo or   │
│ su access exists before disabling root SSH login.        │
└──────────────────────────────────────────────────────────┘
```

---

## 🏗️ Architecture

FlawCHK is engineered as a modular Rust virtual workspace:

```
                         FlawCHK CLI
                            │
                    ┌───────▼───────┐
                    │  flawchk-cli  │
                    └───────┬───────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
 flawchk-rules      flawchk-feedback     flawchk-report
(Security Checks)    (Card Box & Text)   (JSON/SARIF/HTML)
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
                     flawchk-core
               (Check, Finding, Severity)
                            │
                    ┌───────▼───────┐
                    │ flawchk-distro│
                    └───────┬───────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   Gentoo Linux        Ubuntu / Debian      Fedora / RHEL
   (OpenRC, Portage)   (systemd, apt)       (systemd, dnf)
```

### Modular Crates Breakdown
- **`flawchk-core`**: Defines baseline domain entities (`CheckMetadata`, `Finding`, `Severity`, `Status`, `Category`, `Profile`).
- **`flawchk-distro`**: Distribution abstraction layer providing a unified `PlatformAdapter` interface for OS detection, init system inspection (OpenRC, systemd, runit), package management, sysctl querying, and config path resolution.
- **`flawchk-rules`**: Hardening check registry and modular rules.
- **`flawchk-feedback`**: Terminal card box UI renderer and humane security report layout engine.
- **`flawchk-report`**: Exporters generating Text summary tables, JSON, standard **SARIF v2.1.0** (GitHub Security Scanning), and standalone HTML reports.
- **`flawchk-remediation`**: Remediation planning and dry-run safety simulation engine.
- **`flawchk-cli`**: Command-line interface binary.

---

## 🌍 Distribution Abstraction Layer

FlawCHK treats **Gentoo, Ubuntu, Debian, Fedora, Arch, Alpine, RHEL, openSUSE, and Void Linux** as equal implementations of a unified platform specification:

```
            SECURITY RULE
                  │
                  ▼
          ┌───────────────┐
          │ Platform API  │
          └───────┬───────┘
                  │
       ┌──────────┼──────────┐
       ▼          ▼          ▼
    Gentoo      Ubuntu     Fedora
       │          │          │
    OpenRC      systemd    systemd
    Portage     dpkg/apt   rpm/dnf
       │          │          │
       └──────────┼──────────┘
                  ▼
          UNIFIED FINDING & USER UX
```

---

## 📖 Rule Write-ups & Write-up Directory (Milestone 0.1)

Below is the security reference catalog of built-in hardening rules in FlawCHK 0.1.

### 🔑 SSH Hardening

#### `FLAW-SSH-001` — Root SSH Login Permitted
- **Severity**: `HIGH` | **Category**: `SSH Hardening`
- **Description**: SSH daemon permits direct root account authentication over network connections.
- **Impact**: Direct root logins increase exposure to brute-force attacks and make it impossible to attribute actions to individual system administrators in audit logs.
- **Remediation**: Set `PermitRootLogin no` in `/etc/ssh/sshd_config` and reload the SSH service.
- **Verification**: `sshd -T | grep permitrootlogin` $\rightarrow$ `permitrootlogin no`

#### `FLAW-SSH-002` — Password Authentication Enabled
- **Severity**: `MEDIUM` | **Category**: `SSH Hardening`
- **Description**: SSH permits password-based login attempts over network endpoints.
- **Impact**: Passwords are susceptible to dictionary, credential stuffing, and brute-force attacks. Public key or certificate authentication should be mandated.
- **Remediation**: Set `PasswordAuthentication no` in `/etc/ssh/sshd_config`.
- **Verification**: `sshd -T | grep passwordauthentication` $\rightarrow$ `passwordauthentication no`

#### `FLAW-SSH-003` — Empty Passwords Allowed
- **Severity**: `CRITICAL` | **Category**: `SSH Hardening`
- **Description**: SSH permits login for user accounts configured with blank/empty passwords.
- **Impact**: Anyone can authenticate to blank accounts without providing any credentials.
- **Remediation**: Set `PermitEmptyPasswords no` in `/etc/ssh/sshd_config`.
- **Verification**: `sshd -T | grep permitemptypasswords` $\rightarrow$ `permitemptypasswords no`

---

### 🧠 Kernel Security

#### `FLAW-KERN-001` — IPv4 Packet Forwarding Enabled
- **Severity**: `MEDIUM` | **Category**: `Kernel Security`
- **Description**: Kernel sysctl `net.ipv4.ip_forward` is set to `1`.
- **Impact**: Allows the node to route network packets between network interfaces. Unless operating as a dedicated router, gateway, or container host, this introduces unauthorized traffic routing risks.
- **Remediation**: Add `net.ipv4.ip_forward = 0` to `/etc/sysctl.d/99-security.conf` and run `sysctl -p`.
- **Verification**: `sysctl net.ipv4.ip_forward` $\rightarrow$ `net.ipv4.ip_forward = 0`

#### `FLAW-KERN-002` — ICMP Redirect Acceptance Enabled
- **Severity**: `LOW` | **Category**: `Kernel Security`
- **Description**: Kernel accepts ICMP redirect packets (`net.ipv4.conf.all.accept_redirects = 1`).
- **Impact**: Malicious actors on the local network segment can send forged ICMP redirect messages to alter host routing tables and execute Man-in-the-Middle (MitM) attacks.
- **Remediation**: Set `net.ipv4.conf.all.accept_redirects = 0` in `/etc/sysctl.d/99-security.conf`.
- **Verification**: `sysctl net.ipv4.conf.all.accept_redirects` $\rightarrow$ `0`

#### `FLAW-KERN-003` — ASLR Disabled or Partial
- **Severity**: `HIGH` | **Category**: `Kernel Security`
- **Description**: Address Space Layout Randomization (`kernel.randomize_va_space`) is not set to `2`.
- **Impact**: Disabling or reducing ASLR allows attackers to predict memory addresses for stack, heap, and library locations, significantly simplifying buffer overflow exploitation.
- **Remediation**: Set `kernel.randomize_va_space = 2` in `/etc/sysctl.d/99-security.conf`.
- **Verification**: `sysctl kernel.randomize_va_space` $\rightarrow$ `2`

---

### 👤 User & Access Controls

#### `FLAW-USER-001` — Non-root Account with UID 0
- **Severity**: `CRITICAL` | **Category**: `User & Access Controls`
- **Description**: User accounts other than `root` possess UID `0` in `/etc/passwd`.
- **Impact**: Any account with UID 0 has full, unrestricted superuser privileges, bypassing standard DAC checks.
- **Remediation**: Edit `/etc/passwd` to assign unique non-zero UIDs to non-root users or remove rogue accounts.
- **Verification**: `awk -F: '($3 == 0) { print $1 }' /etc/passwd` $\rightarrow$ `root`

#### `FLAW-USER-002` — User Account with Empty Password
- **Severity**: `CRITICAL` | **Category**: `User & Access Controls`
- **Description**: User account entry in `/etc/shadow` has an empty password field.
- **Impact**: Enables unauthenticated interactive shell logins or console privilege escalation.
- **Remediation**: Lock the account with `passwd -l <username>` or assign a strong password hash.
- **Verification**: `awk -F: '($2 == "") { print $1 }' /etc/shadow` $\rightarrow$ `(empty)`

#### `FLAW-USER-003` — Unbounded Password Maximum Lifetime
- **Severity**: `MEDIUM` | **Category**: `User & Access Controls`
- **Description**: `PASS_MAX_DAYS` in `/etc/login.defs` exceeds 365 days (or is set to 99999).
- **Impact**: Stale or compromised credentials remain valid indefinitely.
- **Remediation**: Set `PASS_MAX_DAYS 90` in `/etc/login.defs`.
- **Verification**: `grep '^PASS_MAX_DAYS' /etc/login.defs` $\rightarrow$ `PASS_MAX_DAYS 90`

---

### 📁 Filesystem Permissions

#### `FLAW-FS-001` — World-Writable Sensitive System Files
- **Severity**: `CRITICAL` | **Category**: `Filesystem Permissions`
- **Description**: Critical files such as `/etc/passwd`, `/etc/shadow`, or `/etc/sudoers` have world-writable bit set (`o+w`).
- **Impact**: Any low-privilege account or compromised daemon process can rewrite system configuration files to instantly grant itself root privileges.
- **Remediation**: Execute `chmod o-w /etc/passwd /etc/shadow /etc/sudoers`.
- **Verification**: `stat -c '%A %n' /etc/shadow /etc/passwd` $\rightarrow$ No `w` in world triad.

#### `FLAW-FS-002` — Insecure `/tmp` Mount Flags
- **Severity**: `LOW` | **Category**: `Filesystem Permissions`
- **Description**: `/tmp` directory mount is missing `noexec`, `nosuid`, or `nodev` security options.
- **Impact**: Malicious users or processes can execute binary payloads or place SUID binaries inside `/tmp`.
- **Remediation**: Configure `/etc/fstab` or systemd `tmp.mount` with `defaults,noexec,nosuid,nodev`.
- **Verification**: `mount | grep ' /tmp '` $\rightarrow$ contains `nodev,nosuid,noexec`

#### `FLAW-FS-003` — Uncommon / Rogue SUID/SGID Binaries
- **Severity**: `HIGH` | **Category**: `Filesystem Permissions`
- **Description**: Non-standard SUID/SGID executable binaries found in system binary paths.
- **Impact**: SUID binaries run with file owner permissions (root). Vulnerable or rogue SUID executables serve as privilege escalation vectors.
- **Remediation**: Audit SUID executables and remove SUID bits: `chmod u-s <binary>`.
- **Verification**: `find /bin /usr/bin -perm /6000 -type f` $\rightarrow$ Only standard utilities (`sudo`, `passwd`, `su`).

---

### 🌐 Network & Logging Hardening

#### `FLAW-NET-001` — No Active Host Firewall Daemon
- **Severity**: `HIGH` | **Category**: `Network Hardening`
- **Description**: No active host firewall daemon (`nftables`, `iptables`, `ufw`, `firewalld`) detected.
- **Impact**: Network interfaces directly expose listening sockets to internal or external network segments without packet filtering.
- **Remediation**: Enable and configure `nftables` or `ufw`.
- **Verification**: `nft list ruleset` or `ufw status`

#### `FLAW-NET-002` — Wildcard Listening Sockets (`0.0.0.0` / `::`)
- **Severity**: `MEDIUM` | **Category**: `Network Hardening`
- **Description**: Multiple internal management services bound to all interfaces.
- **Impact**: Unintended exposure of internal services to remote attackers.
- **Remediation**: Bind non-public services to `127.0.0.1` or specific internal IP addresses.
- **Verification**: `ss -tuln`

#### `FLAW-LOG-001` — System Audit Daemon (`auditd`) Inactive
- **Severity**: `MEDIUM` | **Category**: `Logging & Audit`
- **Description**: Kernel audit daemon (`auditd`) is not active.
- **Impact**: Security-relevant events (file access, privilege changes, syscalls) are not recorded for incident investigation.
- **Remediation**: Enable and start `auditd` (`systemctl enable --now auditd` or `rc-update add auditd default`).
- **Verification**: `auditctl -s` $\rightarrow$ `enabled 1`

---

## 🛠️ Usage & CLI Reference

### 1. Hardening Scan (`flawchk scan`)
Perform a full assessment against a specified security profile:

```bash
# Baseline scan with terminal summary
flawchk scan

# Server profile assessment with JSON output
flawchk scan --profile server --format json

# Export assessment report in SARIF v2.1.0 for GitHub Security
flawchk scan --format sarif > flawchk-results.sarif

# Export responsive HTML report
flawchk scan --format html > report.html

# Fail CI/CD build if HIGH or CRITICAL issues exist
flawchk scan --fail-on high
```

### 2. Inspect Finding Details (`flawchk show`)
Display formatted finding card box for a specific rule ID:

```bash
flawchk show FLAW-SSH-001
```

### 3. Human Security Report (`flawchk explain`)
Generate human-friendly security report for failed rules:

```bash
flawchk explain
```

### 4. Dry-Run Remediation Simulation (`flawchk fix`)
Safely preview proposed configuration changes before applying:

```bash
flawchk fix FLAW-SSH-001 --dry-run
```

### 5. Rule Directory (`flawchk rules`)
List all registered hardening rules:

```bash
flawchk rules
```

---

## 📘 Administrator Hardening Playbook

Follow this 5-phase operational playbook to assess and harden Linux systems using FlawCHK:

```
┌─────────────────────────────────────────────────────────┐
│ PHASE 1: ASSESSMENT & BASELINE INVENTORY                │
│ Run: flawchk scan --profile baseline                     │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 2: TRIAGE & RISK EVALUATION                       │
│ Run: flawchk explain --failed                           │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 3: DRY-RUN SIMULATION & PLANNING                  │
│ Run: flawchk fix <RULE-ID> --dry-run                    │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 4: SAFE CONFIGURATION REMEDIATION                 │
│ Apply config changes, test SSH/access, reload services  │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 5: VERIFICATION & CI COMPLIANCE                   │
│ Run: flawchk scan --fail-on high                        │
└─────────────────────────────────────────────────────────┘
```

### Phase 1: Baseline Assessment
Execute an initial assessment to produce a system security snapshot:
```bash
flawchk scan --profile baseline
```

### Phase 2: Vulnerability Triage
Filter and inspect failed security findings:
```bash
flawchk explain --failed
flawchk show FLAW-SSH-001
```

### Phase 3: Dry-Run Simulation
Preview planned configuration modifications:
```bash
flawchk fix FLAW-SSH-001 --dry-run
```

### Phase 4: Apply Hardening Steps

1. **SSH Hardening**:
   ```bash
   # Edit /etc/ssh/sshd_config
   PermitRootLogin no
   PasswordAuthentication no
   PermitEmptyPasswords no

   # Validate & Reload
   sshd -t && (systemctl reload sshd || rc-service sshd reload)
   ```

2. **Kernel Hardening**:
   ```bash
   cat <<'EOF' > /etc/sysctl.d/99-flawchk-hardening.conf
   net.ipv4.ip_forward = 0
   net.ipv4.conf.all.accept_redirects = 0
   net.ipv4.conf.default.accept_redirects = 0
   kernel.randomize_va_space = 2
   EOF

   sysctl -p /etc/sysctl.d/99-flawchk-hardening.conf
   ```

3. **User & Password Policy**:
   ```bash
   # Lock blank shadow password accounts
   passwd -l <username>

   # Enforce max password lifetime in /etc/login.defs
   sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
   ```

### Phase 5: Verification & Continuous Compliance
Run FlawCHK in CI/CD or cron pipelines with exit-code thresholds:
```bash
flawchk scan --profile server --fail-on high
```

---

## 👩‍💻 Developer & Contributor Guide

### Building from Source
Ensure Rust 1.75+ is installed:

```bash
git clone https://github.com/flawchk/flawchk.git
cd flawchk
cargo build --release
```

### Running Test Suite
Execute integration and unit tests:

```bash
cargo test --workspace
```

### Adding a New Hardening Rule

1. Create a rule struct implementing the `Rule` trait in `crates/flawchk-rules/src/<category>.rs`:

```rust
use flawchk_core::{Category, CheckMetadata, Confidence, Finding, Severity, Status};
use flawchk_distro::PlatformAdapter;
use crate::registry::Rule;

pub struct MyNewRule;

impl Rule for MyNewRule {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "FLAW-CAT-001".to_string(),
            title: "Short description of flaw".to_string(),
            category: Category::Kernel,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "Detailed description of check.".to_string(),
            impact: "Security impact of vulnerability.".to_string(),
            remediation: "Step-by-step fix instruction.".to_string(),
            verification: "Verification command and expected output.".to_string(),
            references: vec!["https://example.com/ref".to_string()],
            caveats: None,
        }
    }

    fn evaluate(&self, platform: &dyn PlatformAdapter) -> Finding {
        // Use platform adapter methods
        let meta = self.metadata();
        // ... evaluate state ...
        Finding {
            check_id: meta.id,
            title: meta.title,
            category: meta.category,
            severity: meta.severity,
            confidence: meta.confidence,
            status: Status::Pass,
            evidence: "Evidence string".to_string(),
            explanation: meta.impact,
            remediation: meta.remediation,
            verification: meta.verification,
            caveats: meta.caveats,
            references: meta.references,
        }
    }
}
```

2. Register your rule in `register_all_builtin()` inside `crates/flawchk-rules/src/registry.rs`.
3. Add fixture test cases in `crates/flawchk-rules/tests/rules_test.rs`.

---

## 📄 License

FlawCHK is licensed under **MIT OR Apache-2.0**.
