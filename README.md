<div align="center">

# Windows 11 Build Audit

**Comprehensive security auditing for Windows 10/11 endpoints**

Validate builds against CIS Benchmarks, Cyber Essentials, and Microsoft Entra ID security controls — all from a single PowerShell script.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6.svg)](https://www.microsoft.com/windows)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Vulnerability Database](#vulnerability-database)
- [Report Output](#report-output)
- [Audit Categories](#audit-categories)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

## Overview

**win-11-build-audit** is a standalone PowerShell auditing tool that performs **734+ security checks** across **80 audit categories**. It evaluates Windows 10/11 endpoints against multiple industry-standard frameworks simultaneously:

| Framework | Description |
|-----------|-------------|
| **CIS Benchmark L1** | CIS Microsoft Windows 11 Enterprise v5.0.1 — Level 1 |
| **CIS Benchmark L2** | CIS Microsoft Windows 11 Enterprise v5.0.1 — Level 2 |
| **Cyber Essentials** | UK NCSC Cyber Essentials baseline controls |
| **Cyber Essentials Plus** | CE+ additional technical verification controls |
| **Entra ID / M365** | Microsoft Entra ID, Intune, WHfB, MDE, and Conditional Access |
| **NCSC** | NCSC-aligned security recommendations |

Results are displayed with colour-coded console output and saved to a plain-text report, CSV export, structured JSON, and an interactive HTML report.

## Key Features

- **Multi-framework auditing** — Assess endpoints against CIS L1, CIS L2, Cyber Essentials, CE+, Entra ID, and NCSC in a single pass
- **Entra ID-aware** — Cloud-managed controls (password policy, lockout, account lifecycle) are contextually adjusted to avoid false FAILs on Entra-joined devices
- **Zero dependencies** — No Microsoft Graph, Azure AD module, or internet connection required; uses `dsregcmd`, registry, WMI/CIM, and local tooling only
- **Vulnerability scanning** — Detects outdated desktop applications with known critical/high CVEs via the [NVD](https://nvd.nist.gov/) and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) databases
- **Interactive HTML report** — Self-contained HTML file with SVG charts, collapsible sections, sortable/filterable results tables, and print-to-PDF support
- **JSON export** — Structured JSON with metadata, framework scores, section scorecard, compliance verdicts, and full results for SIEM/GRC integration
- **Delta / trend comparison** — Compare against a previous JSON export to show resolved failures, regressions, new failures, and score changes
- **Remediation guidance** — Failed controls include severity tags and one-line remediation actions from the companion `remediation.json`
- **Severity-weighted scoring** — Critical checks weighted x3, High x2, Medium x1 alongside the standard unweighted score
- **Compliance attestation** — Per-framework pass/fail verdicts against configurable thresholds (e.g. 100% for CE, 90% for CIS)
- **Executive-ready reports** — Risk ratings, Top 5 Risks, Quick Wins, framework score dashboards with progress bars, and section-level scorecards
- **CSV export** — Machine-readable output for SIEM, GRC platforms, and spreadsheet analysis
- **Flexible scope** — Audit all frameworks at once or focus on a single framework with the `-Audit` parameter

## Requirements

| Requirement | Detail |
|-------------|--------|
| **Operating System** | Windows 10 or 11 (tested on 22H2+) |
| **Join Type** | Entra ID joined, Hybrid joined, or standalone |
| **PowerShell** | Windows PowerShell 5.1 or later |
| **Privileges** | Administrator (enforced via `#Requires -RunAsAdministrator`) |
| **Dependencies** | None — fully self-contained |

## Quick Start

```powershell
# 1. Clone or download the repository
git clone https://github.com/pbassill/win-11-build-audit.git
cd win-11-build-audit

# 2. Run the audit in an elevated PowerShell session
.\audit.ps1
```

The script produces a colour-coded console summary and writes four output files to the user profile directory: `.txt` report, `.csv` export, `.json` structured data, and `.html` interactive report.

## Usage

```powershell
# Full audit across all frameworks (default)
.\audit.ps1
.\audit.ps1 -Audit all

# Single-framework audits
.\audit.ps1 -Audit ce       # Cyber Essentials / CE+ checks only
.\audit.ps1 -Audit cis1     # CIS Level 1 checks only
.\audit.ps1 -Audit cis2     # CIS Level 2 checks only
.\audit.ps1 -Audit ncsc     # NCSC alignment checks only
.\audit.ps1 -Audit entra    # Entra ID / M365 checks only

# Delta / trend comparison against a previous audit
.\audit.ps1 -PreviousReport "C:\audits\DESKTOP-ABC_Audit_2025-01-01.json"
```

### Audit Scope Options

| Option  | Scope |
|---------|-------|
| `all`   | Full audit across all frameworks *(default)* |
| `ce`    | Cyber Essentials / CE+ checks only |
| `cis1`  | CIS Level 1 checks only |
| `cis2`  | CIS Level 2 checks only |
| `ncsc`  | NCSC alignment checks only |
| `entra` | Entra ID / M365 checks only |

> **Tip:** Running without the `-Audit` parameter is equivalent to `-Audit all`.

## Vulnerability Database

Section 80 (**Application Patch Currency**) checks installed desktop applications against a companion `known-vulnerabilities.json` file containing known critical and high-severity CVEs. The database is maintained via `Update-KnownVulnerabilities.ps1`, which queries:

- **[NIST NVD API v2.0](https://nvd.nist.gov/)** — CVE severity, affected versions, and minimum safe versions
- **[CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — Actively exploited vulnerabilities with remediation deadlines

### Updating the Database

```powershell
# Basic usage (public rate limit: 5 requests / 30 seconds)
.\Update-KnownVulnerabilities.ps1

# With an NVD API key (50 requests / 30 seconds)
.\Update-KnownVulnerabilities.ps1 -NvdApiKey "your-api-key"

# Custom output path
.\Update-KnownVulnerabilities.ps1 -OutputPath "C:\audit\known-vulnerabilities.json"

# Skip KEV catalog lookup (offline environments)
.\Update-KnownVulnerabilities.ps1 -SkipKev
```

> A free NVD API key can be requested at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

**Merge behaviour:** Existing entries are preserved unless the NVD provides a higher minimum safe version. KEV-flagged vulnerabilities include the CISA remediation due date and ransomware association metadata. During the audit, these are highlighted as **ACTIVELY EXPLOITED** for priority remediation.

## Report Output

### Output Formats

| Format | Filename | Purpose |
|--------|----------|---------|
| **Console** | — | Colour-coded live results (Green/Red/Yellow/Cyan) |
| **Text report** | `<hostname>_Audit_<timestamp>.txt` | Full audit report with compliance summary |
| **CSV export** | `<hostname>_Audit_<timestamp>.csv` | Machine-readable export for SIEM / GRC / spreadsheet |
| **JSON export** | `<hostname>_Audit_<timestamp>.json` | Structured data with metadata, scores, results, and remediation guidance |
| **HTML report** | `<hostname>_Audit_<timestamp>.html` | Interactive report with charts, filtering, sorting, and print-to-PDF |

### Report Sections

1. **Compliance Attestation** — Per-framework pass/fail verdicts against configurable thresholds
2. **Executive Summary** — Overall risk rating, unweighted and severity-weighted compliance scores, Top 5 Risks, Quick Wins
3. **Framework Score Dashboard** — Side-by-side framework scores with SVG doughnut charts and ASCII progress bars
4. **Section Scorecard** — Pass/fail/warn rates for each of the 80 audit sections
5. **Device Context** — Hostname, OS edition, join type, tenant, MDM, TPM, Secure Boot, BIOS/UEFI, IP addresses
6. **Delta Comparison** — Score changes, resolved failures, regressions, and new failures vs. a previous audit (requires `-PreviousReport`)
7. **Priority Remediation** — Failed controls grouped by framework with severity tags and one-line remediation guidance
8. **Warnings Summary** — Warnings grouped by framework for manual review
9. **Per-Framework Detail** — Full PASS / FAIL / WARN listing for each framework
10. **Sections Audited** — All 80 sections grouped into logical categories

### Delta / Trend Comparison

Pass a previous JSON export to see what changed between audits:

```powershell
.\audit.ps1 -PreviousReport "C:\audits\previous.json"
```

The report will include:
- **Overall score delta** with directional arrows
- **Per-framework score changes**
- **Resolved** items (previously failed, now passing)
- **Regressions** (previously passing/warn, now failing)
- **New failures** (checks not present in the previous report)

### Remediation Guidance

The companion `remediation.json` file provides severity ratings and one-line fix instructions for common failures. When a failed check matches an entry in the file, the text report, HTML report, and JSON export all include:
- **Severity** — Critical, High, or Medium
- **Remediation** — GPO path, registry key, or PowerShell command to resolve the failure

Severity ratings also drive the **weighted score** (Critical ×3, High ×2, Medium ×1) shown alongside the standard unweighted score.

## Audit Categories

<details>
<summary><strong>View all 80 audit categories</strong></summary>

| # | Category | Frameworks |
|---|----------|------------|
| 1 | Password Policy | CIS 1.1, CE2 |
| 2 | Account Lockout Policy | CIS 1.2, CE2 |
| 3 | Remote Desktop (RDP) | CIS, CE1, CE+ |
| 4 | Local Accounts | CIS, CE3, CE+ |
| 5 | Windows Firewall | CIS, CE1, CE+ |
| 6 | Patch Management | CIS, CE5, CE+ |
| 7 | SMBv1 Protocol | CIS, CE2 |
| 8 | AutoRun / AutoPlay | CIS |
| 9 | Insecure Services | CIS, CE2 |
| 10 | Admin Shares | CIS |
| 11 | User Account Control | CIS, CE3 |
| 12 | Security Protocols | CIS, CE2 |
| 13 | Audit Policy | CIS 17.x |
| 14 | Malware Protection (Defender) | CIS, CE4, CE+ |
| 15 | BitLocker / Drive Encryption | CIS, CE2 |
| 16 | Secure Boot & UEFI | CIS, CE+ |
| 17 | PowerShell Security | CIS, CE+ |
| 18 | Application Control | CIS, CE2, CE+ |
| 19 | Event Log Configuration | CIS 18.x |
| 20 | Credential Protection | CIS, CE+ |
| 21 | Screen Lock / Session Security | CIS, CE2 |
| 22 | Unnecessary Windows Features | CE2, CE+ |
| 23 | Network Security | CIS, CE1, CE2 |
| 24 | Memory & Exploit Protection | CIS |
| 25 | Cyber Essentials Secure Configuration | CE2, CE+ |
| 26 | Cyber Essentials Plus Checks | CE+ |
| 27 | Entra ID Device Identity | EntraID, CE+ |
| 28 | Intune / MDM Enrolment | EntraID, CE+ |
| 29 | Windows Hello for Business | EntraID, CE+ |
| 30 | Microsoft Defender for Endpoint | EntraID, CE+ |
| 31 | Microsoft 365 / Office Security | EntraID, CE+ |
| 32 | Conditional Access & Device Compliance | EntraID, CE+ |
| 33 | CIS L2 — User Rights Assignment | CIS L2 |
| 34 | CIS L2 — Additional Security Options | CIS L2 |
| 35 | CIS L2 — Advanced Audit Policy | CIS L2 17.x |
| 36 | TLS/SSL & Cipher Suite Hardening | CIS L2, CE+ |
| 37 | Microsoft Edge Security | CIS L2, CE+ |
| 38 | Peripheral & Device Control | CIS L2, CE+ |
| 39 | Windows Components & Privacy Hardening | CIS L2 |
| 40 | Remote Assistance & Remote Tools | CIS L2 |
| 41 | DNS Client & Name Resolution Security | CIS L2 |
| 42 | Scheduled Tasks Security Audit | CIS L2 |
| 43 | MSS (Legacy) Security Settings | CIS L2 |
| 44 | CIS L2 — Network Protocol Hardening | CIS L2 |
| 45 | Attack Surface Reduction — Specific Rules | CIS L1/L2 |
| 46 | System Exploit Protection (ASLR/CFG) | CIS L2 |
| 47 | Kernel DMA Protection | CIS L2, CE+ |
| 48 | LAPS — Local Admin Password Solution | CIS L1, CE3 |
| 49 | Network List Manager | CIS L2 |
| 50 | Delivery Optimisation | CIS L2 |
| 51 | Time Provider / NTP Security | CIS L2 |
| 52 | Windows Defender Application Guard (WDAG) | CIS L2 |
| 53 | RPC & DCOM Security | CIS L2 |
| 54 | Group Policy Infrastructure | CIS L2 |
| 55 | Print Security | CIS L1/L2 |
| 56 | Windows Copilot / AI Features | CIS L2 |
| 57 | Sensitive File & Registry Permissions | CIS L2 |
| 58 | Internet Explorer / Legacy Browser | CIS L1 |
| 59 | Windows Event Forwarding | CIS L2 |
| 60 | Additional Windows Defender Settings | CIS L1/L2 |
| 61 | CIS L1 — User Rights Assignment | CIS L1 2.2 |
| 62 | CIS L1 — Security Options (Missing) | CIS L1 2.3/18.3 |
| 63 | CIS L1 — Administrative Templates (System) | CIS L1 18.1/18.8 |
| 64 | CIS L1 — Administrative Templates (Windows Components) | CIS L1 18.5/18.9 |
| 65 | CIS L1 — System Services (Missing) | CIS L1 5.x |
| 66 | CIS L1 — Administrative Templates (User) | CIS L1 19.x |
| 67 | CIS L1 — Data Collection / Telemetry | CIS L1 18.9.17 |
| 68 | CIS L1 — Device Guard / VBS | CIS L1 18.8.5 |
| 69 | CIS L1 — Logon & Credential UI | CIS L1 18.8.28/18.9.15 |
| 70 | CIS L1 — Additional Admin Templates | CIS L1 18.x |
| 71 | CIS L1 — Account Lockout, User Rights & Security Options | CIS L1 1.2/2.2/2.3 |
| 72 | CIS L1 — Windows Firewall Policy Logging | CIS L1 9.x |
| 73 | CIS L1 — Audit Policy Additional | CIS L1 17.x |
| 74 | CIS L1 — Personalization & Speech | CIS L1 18.1 |
| 75 | CIS L1 — MSS / Network / SMB Hardening | CIS L1 18.5/18.6 |
| 76 | CIS L1 — Printer Security | CIS L1 18.7 |
| 77 | CIS L1 — System Admin Templates | CIS L1 18.9 |
| 78 | CIS L1 — Windows Components | CIS L1 18.10 |
| 79 | CIS L1 — WiFi & User Templates | CIS L1 18.11/19.7 |
| 80 | Application Patch Currency | CE+, CE5 |

</details>

## Changelog

### v6.0.0 — Enhanced Reporting Suite

- **Interactive HTML report** — Self-contained `.html` file with inline CSS/JS, SVG doughnut charts per framework, collapsible/expandable sections, sortable and filterable results table, and browser print-to-PDF support
- **Structured JSON export** — Full `.json` export with metadata, framework scores, compliance verdicts, section-level scorecard, and all results with optional remediation guidance; designed for SIEM, GRC, and dashboard ingestion
- **Delta / trend comparison** — New `-PreviousReport` parameter accepts a prior JSON export; generates a "Changes Since Last Audit" section showing resolved failures, regressions, new failures, and per-framework score deltas
- **Remediation guidance** — New companion `remediation.json` with severity ratings and one-line fix instructions for common failures; integrated into text report, HTML report, and JSON export
- **Severity-weighted scoring** — Critical checks weighted ×3, High ×2, Medium ×1; shown alongside the standard unweighted score in the executive summary
- **Compliance attestation** — Per-framework pass/fail verdicts against configurable thresholds (100% CE, 90% CIS/Entra, 85% NCSC)
- **Section scorecard** — Category-level pass/fail/warn rates for all 80 audit sections; highlights priority areas below 50%
- **Enhanced device context** — OS edition and build, last reboot time, TPM version/status, Secure Boot state, BIOS/UEFI vendor, PowerShell/.NET versions, domain/workgroup, IP addresses
- **Executive summary enhancements** — Top 5 Risks (sorted by severity weight), Quick Wins (easy registry/GPO fixes with remediation instructions), framework compliance threshold status
- **Four output formats** — Text (.txt), CSV (.csv), JSON (.json), and HTML (.html) generated on every audit run

### v5.2.0 — Audit Scope Selection

- **`-Audit` parameter** — Select which framework to audit: `all` (default), `ce`, `cis1`, `cis2`, `ncsc`, or `entra`
- Checks outside the selected scope are silently skipped, producing a focused report
- Banner, executive summary, and report header display the selected scope
- Fully backwards compatible — running without `-Audit` performs the full audit

### v5.1.0 — Enhanced Reporting & CSV Export

- **Executive Summary** with risk rating and visual compliance score bar
- **Framework Score Dashboard** with ASCII progress bars and per-framework PASS/FAIL/WARN breakdowns
- **Priority Remediation** section with numbered items grouped by framework
- **Warnings Summary** grouped by framework for manual review
- **CSV export** alongside the text report for SIEM and spreadsheet integration
- **Audit duration** tracked and displayed in the report footer
- Report helper functions (`Write-ReportLine`, `Write-Divider`, `Get-ProgressBar`, `Get-RiskRating`)

### v5.0.0 — CIS v5.0.1 L1 Full Coverage

- **134 new CIS L1 checks** across 9 new sections (71-79), mapped from the CIS Microsoft Windows 11 Enterprise v5.0.1 Level 1 benchmark
- Total checks increased from 587 to **721** across **79 audit categories**
- All checks mapped to specific CIS benchmark control IDs

<details>
<summary><strong>Previous changes</strong></summary>

- **Section 15 (BitLocker):** Key escrow check now returns PASS on Entra-joined devices with BitLocker enabled
- **Section 22 (Unnecessary Features):** Null/empty feature state correctly treated as PASS
- **Section 26A (Account Separation):** Fixed `CommandNotFoundException` in `Where-Object` sub-expression
- **Section 26A (Entra Admins):** Entra admin accounts in local Administrators group report as INFO

</details>

## Contributing

Contributions are welcome! If you would like to improve this tool:

1. **Fork** the repository
2. **Create a feature branch** (`git checkout -b feature/my-improvement`)
3. **Commit your changes** (`git commit -m "Add my improvement"`)
4. **Push to your branch** (`git push origin feature/my-improvement`)
5. **Open a Pull Request**

Please ensure PowerShell scripts use **ASCII-only characters** (no em dashes, smart quotes, or other multi-byte characters) for compatibility with Windows PowerShell 5.1.

## Author

**Peter Bassill** — [OTY Heavy Industries](https://github.com/pbassill)

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
