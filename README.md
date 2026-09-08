# 🛡️ FlawCHK — Cross-Distribution Linux Hardening & Security Intelligence

> **Distribution-aware Linux hardening assessment, CVE intelligence, and exposure correlation engine.**

FlawCHK is a high-performance Linux security intelligence advisor written in Rust. It bridges the gap between static CIS configuration auditing, CVE vulnerability intelligence, and active runtime exposure analysis.

Instead of outputting raw CVE dumps or opaque `[FAIL]` lines, FlawCHK answers five critical questions for system administrators:

1. **What is wrong or vulnerable?** (`HARDENING`, `VULNERABILITY`, or `EXPOSURE`)
2. **How serious is it?** (CVSS Severity + **Exposure Score percentage**)
3. **Why does it matter?** (Deep root cause & risk explanation)
4. **How do I fix or mitigate it?** (Distro-specific upgrade commands & temporary mitigations)
5. **Did I actually fix it?** (`flawchk show` & verification checks)

---

## 🚀 Flagship Command (`flawchk assess`)

Run a single command for a unified Linux security assessment dashboard:

```
╔════════════════════════════════════════════════════╗
║                 FLAWCHK ASSESSMENT                 ║
╚════════════════════════════════════════════════════╝

Host:       Gentoo Linux
Kernel:     6.18.x
Init:       OpenRC
Profile:    server

HARDENING
  Critical   0
  High       3
  Medium     7
  Low        2

VULNERABILITIES & EXPOSURE
  🔴 High Exposure      1
  🟠 Medium Exposure    3
  🟢 Reduced / Low      2

TOP PRIORITIES
──────────────────────────────────────────────────────

1. 🔴 CVE-2026-72105 — Kernel ksmbd SMB3 Server Remote Code Execution
   Exposure: INTERNET ──► Network Interface ──► ksmbd Daemon ──► ksmbd Subsystem (CVE)
   Action:   Upgrade linux-kernel to fixed version 6.12.14.

2. 🔴 FLAW-SSH-001 — Direct Root SSH Login Enabled
   Category: SSH Hardening
   Action:   Set PermitRootLogin to 'no' in /etc/ssh/sshd_config and reload sshd.

3. 🟠 CVE-2026-72014 — Linux Kernel DRBD Out-of-Bounds Memory Write
   Exposure: Kernel version affected, DRBD module NOT loaded
   Action:   Unload DRBD module or upgrade kernel to 6.12.18.

──────────────────────────────────────────────────────
Run: flawchk show <ID> to view evidence, impact, and verification steps.
```

---

## 🎯 Three Dimensions of Security Findings

FlawCHK classifies security findings into three precise categories:

1. **`HARDENING`**: System configuration vulnerabilities (e.g. `PermitRootLogin yes`, unhardened `/tmp`, disabled ASLR).
2. **`VULNERABILITY`**: Component matched against vulnerability intelligence databases (Kernel, OpenSSH, sudo, OpenSSL, systemd, glibc).
3. **`EXPOSURE`**: Active attack surface correlation determining whether the vulnerable component is installed, loaded in memory, running as a service, listening on network interfaces, or blocked by firewalls.

```
┌──────────────────────────────────────────────────────────┐
│ CVE-2026-72014                                       HIGH│
│ Linux Kernel DRBD Payload Size Out-of-Bounds Memory C... │
├──────────────────────────────────────────────────────────┤
│ Status:        FAIL                                      │
│ Category:      Kernel Security                           │
│ Kind:          VULNERABILITY                             │
│ Exposure:      MEDIUM EXPOSURE                           │
│ Score:         ██████░░░░ 60%                            │
│                                                          │
│ What was found                                           │
│ Installed linux-kernel is within affected range >= 6.0,  │
│ < 6.12.18                                                │
│                                                          │
│ Exposure Analysis                                        │
│ ✓ Installed version falls within affected range (>=      │
│ 6.0, < 6.12.18)                                          │
│ ✗ Affected kernel module 'drbd' is NOT loaded            │
│ ✓ Service endpoint is listening on wildcard network      │
│ interface (0.0.0.0 / ::)                                 │
│                                                          │
│ Attack Path                                              │
│ System Kernel / Package (linux-kernel) Vulnerable        │
│ Version                                                  │
│                                                          │
│ Why it matters                                           │
│ A vulnerability in the Linux kernel DRBD subsystem       │
│ allows remote authenticated peers to trigger an          │
│ out-of-bounds memory write via forged payload sizes.     │
│                                                          │
│ Recommended fix                                          │
│ Upgrade linux-kernel to fixed version 6.12.18.           │
│ Distro Command: emerge -avuDN sys-kernel/gentoo-sources  │
│                                                          │
│ Verify                                                   │
│ Check version of linux-kernel (fixed in 6.12.18)         │
│                                                          │
│ ⚠️ Temporary Mitigation / Caveats                        │
│ Unload the DRBD kernel module (`modprobe -r drbd`) or    │
│ block DRBD TCP port 7788 in iptables/nftables if DRBD is │
│ not actively required.                                   │
└──────────────────────────────────────────────────────────┘
```

---

## 🏗️ System Architecture & Vulnerability Correlation

```
                           FlawCHK
                              │
       ┌──────────────────────┼──────────────────────┐
       │                      │                      │
       ▼                      ▼                      ▼
   Hardening              Vulnerability          Exposure
    Engine                  Engine                Engine
       │                      │                      │
       └──────────────────────┼──────────────────────┘
                              ▼
                       Correlation Engine
                              │
                       ┌──────┴──────┐
                       ▼             ▼
                    Risk Engine   Feedback
                       │             │
                       └──────┬──────┘
                              ▼
                         Remediation
                              │
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
             Gentoo         Ubuntu         Fedora
```

### Virtual Workspace Crates
- **`flawchk-core`**: Baseline domain entities (`FindingKind`, `ExposureLevel`, `ExposureAnalysis`, `CveEntry`, `AttackSurface`).
- **`flawchk-distro`**: Distro abstraction layer querying OS details, OpenRC/systemd daemons, Portage/apt/dnf package status, loaded kernel modules (`/proc/modules`), and distro-specific upgrade commands.
- **`flawchk-rules`**: Built-in system hardening checks.
- **`flawchk-cve`**: CVE intelligence engine correlation database (DRBD `CVE-2026-72014`, SUNRPC TLS `CVE-2026-72317`, Bluetooth HCI `CVE-2026-71980`, ksmbd `CVE-2026-72105`, OpenSSH regreSSHion `CVE-2024-6387`, etc.).
- **`flawchk-feedback`**: Card box UI renderer, `flawchk assess` dashboard, `flawchk inventory`, and `flawchk graph` ASCII renderer.
- **`flawchk-report`**: Exporters (`Text`, `JSON`, `SARIF v2.1.0`, `HTML`).
- **`flawchk-remediation`**: Dry-run simulation and remediation planning engine.
- **`flawchk-cli`**: Command line interface.

---

## 🗺️ Security Dependency Graph (`flawchk graph`)

Visualize the node's attack surface dependencies in ASCII:

```bash
$ flawchk graph

SECURITY DEPENDENCY GRAPH
─────────────────────────────────────────────────────

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

Node Security Status Legend:
  🔴 vulnerable | 🟠 potentially affected | 🟢 patched | ⚪ not applicable
```

---

## 🔍 Attack Surface Inventory (`flawchk inventory`)

Inspect active network sockets, running daemons, and loaded kernel modules:

```bash
$ flawchk inventory

ATTACK SURFACE INVENTORY
────────────────────────────────────

Network Listeners:
  tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* (sshd)

Active Services & Daemons:
  sshd                 active
  auditd               active

Loaded Kernel Subsystems / Modules:
  drbd
  sunrpc
  bluetooth
  ksmbd
  ... and 160 more loaded modules
```

---

## 🛠️ Complete CLI Command Reference

| Command | Description |
| :--- | :--- |
| `flawchk assess` | **Flagship Dashboard** combining Hardening, Vulnerabilities, Exposure, and Top Priorities |
| `flawchk scan [--profile <p>] [--format json\|sarif\|html]` | Perform full hardening & security scan with report exporter |
| `flawchk show <RULE-ID\|CVE-ID>` | Display formatted finding card box with Exposure Score & progress bar |
| `flawchk explain [--failed] [<ID>]` | Generate human-friendly security explanation report |
| `flawchk cve` | Browse CVE intelligence database and host exposure status |
| `flawchk recent` | List recent Linux kernel and system vulnerability exposures |
| `flawchk inventory` | Discover network listeners, active daemons, and loaded kernel modules |
| `flawchk graph` | Render ASCII security dependency graph and attack paths |
| `flawchk update` | Update vulnerability database from Linux kernel & distro security advisory feeds |
| `flawchk fix <ID> --dry-run` | Preview safe dry-run remediation plan |
| `flawchk rules` | List all registered hardening rules |

---

## 📘 Administrator Hardening Playbook

```
┌─────────────────────────────────────────────────────────┐
│ PHASE 1: UNIFIED SECURITY ASSESSMENT                    │
│ Run: flawchk assess                                     │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 2: ATTACK SURFACE & DEPENDENCY ANALYSIS           │
│ Run: flawchk inventory && flawchk graph                 │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 3: CVE EXPOSURE DEEP-DIVE & TEMPORARY MITIGATION  │
│ Run: flawchk show CVE-2026-72014                        │
│ Apply temporary modprobe / sysctl mitigations if needed │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 4: DISTRO-AWARE PATCH REMEDIATION                 │
│ Execute distro upgrade command (e.g. emerge / apt)     │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ PHASE 5: CONTINUOUS COMPLIANCE & VERIFICATION           │
│ Run: flawchk scan --fail-on high                        │
└────────────────────────────┴────────────────────────────┘
```

### Temporary Mitigation vs Patching

FlawCHK distinguishes between:
- **`PATCHED`**: Package/kernel upgraded to fixed release.
- **`MITIGATED`**: Vulnerable kernel module unloaded (`modprobe -r drbd`), service disabled, or firewall rule applied.
- **`EXPOSED`**: Vulnerable version running with active subsystem or reachable network interface.

---

## 🤝 Contributing

Contributions to FlawCHK are warmly welcomed! You can contribute by adding new hardening rules, expanding Linux kernel CVE intelligence entries, adding distribution adapters, or enhancing reporting output formats.

Please read our step-by-step **[Contributor Guide (CONTRIBUTING.md)](CONTRIBUTING.md)** for detailed instructions on:
- Writing custom rules with the `Rule` trait
- Adding CVE entries with runtime exposure matching
- Enhancing distribution adapters (Portage, apt, dnf, pacman, apk, etc.)
- Development, testing, and PR conventions

---

## 📄 License

FlawCHK is licensed under **MIT OR Apache-2.0**.
