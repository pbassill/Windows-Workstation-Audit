# win-11-build-audit

A PowerShell script to audit Windows 10/11 builds against CIS Level 1 & 2, Cyber Essentials (CE), Cyber Essentials Plus (CE+), and Microsoft Entra ID / M365 security controls.

## Overview

This tool performs **721 individual security checks** across **79 audit categories**, covering:

- **CIS Microsoft Windows Benchmark Level 1** controls
- **CIS Microsoft Windows Benchmark Level 2** controls
- **Cyber Essentials (CE)** baseline controls
- **Cyber Essentials Plus (CE+)** additional controls
- **Microsoft Entra ID** (Azure AD) join and device health
- **Microsoft Intune / MDM** enrolment and compliance
- **Windows Hello for Business** (WHfB)
- **Microsoft Defender for Endpoint** (MDE)
- **Microsoft 365 / Office** security configuration
- **Entra ID Conditional Access** compliance

Results are displayed with colour-coded console output and saved to a plain-text report on the Desktop.

### Entra ID Awareness

The script is Entra ID-aware. When a device is detected as Entra joined, checks that are natively managed by Entra ID / Intune (e.g. password policy, lockout, account lifecycle) are contextually adjusted so that cloud-managed controls do not generate false FAILs against local policy baselines.

No Microsoft Graph or Azure AD module is required — the script uses `dsregcmd`, registry, WMI/CIM, and local tooling only, so it works offline and without extra modules.

## Requirements

- Windows 10/11 (tested on 22H2+, Entra ID joined and Hybrid joined)
- PowerShell
- **Administrator privileges** (the script enforces this via `#Requires -RunAsAdministrator`)

## Usage

Run the script in an elevated PowerShell session:

```powershell
# Run the full audit (all frameworks)
.\audit.ps1
.\audit.ps1 -Audit all

# Run only Cyber Essentials / CE+ checks
.\audit.ps1 -Audit ce

# Run only CIS Level 1 checks
.\audit.ps1 -Audit cis1

# Run only CIS Level 2 checks
.\audit.ps1 -Audit cis2

# Run only NCSC alignment checks
.\audit.ps1 -Audit ncsc

# Run only Entra ID / M365 checks
.\audit.ps1 -Audit entra
```

### Audit Scope Options

| Option | Description |
|--------|-------------|
| `all` | Full audit across all frameworks (default) |
| `ce` | Cyber Essentials / CE+ checks only |
| `cis1` | CIS Level 1 checks only |
| `cis2` | CIS Level 2 checks only |
| `ncsc` | NCSC alignment checks only |
| `entra` | Entra ID / M365 checks only |

> **Note:** The `--audit` syntax (e.g. `.\audit.ps1 --audit ce`) is also supported by PowerShell and is equivalent to `-Audit ce`.

## Output

- **Console** — colour-coded results: **Green** (PASS), **Red** (FAIL), **Yellow** (WARN), **Cyan** (INFO / Cloud-Managed)
- **Text report** — `OTY_Heavy_Industries_Audit_<timestamp>.txt` saved to the user profile directory, containing all results plus a compliance summary with pass/fail/warn counts, per-framework scores with visual progress bars, and an overall risk rating
- **CSV export** — `OTY_Heavy_Industries_Audit_<timestamp>.csv` saved alongside the text report for import into spreadsheets, SIEM tools, or other analysis platforms

### Report Structure

The report is organised into clear, logical sections:

1. **Executive Summary** — overall risk rating (Critical / High / Moderate / Low), compliance score with progress bar, and key metrics at a glance
2. **Framework Score Dashboard** — side-by-side comparison of all framework scores (CIS L1, CIS L2, CE/CE+, Entra ID, NCSC) with ASCII progress bars and pass/fail/warn breakdowns
3. **Device Context** — hostname, join type, tenant, MDM enrolment, and PRT status
4. **Priority Remediation** — all failed controls grouped by framework, numbered and sorted for actionable prioritisation
5. **Warnings Summary** — all warnings grouped by framework for manual review
6. **Per-Framework Detailed Reports** — full PASS/FAIL/WARN listing for each framework (CIS L1, CIS L2, CE/CE+, Entra ID/M365, NCSC)
7. **Sections Audited** — all 79 sections grouped into logical categories (Core Security, Entra/Cloud, CIS L2, CIS L1 Extended)

## Audit Categories

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

## Changelog

### v5.2.0 — Audit Scope Selection

- **`-Audit` parameter** added to select which framework to audit: `all` (default), `ce`, `cis1`, `cis2`, `ncsc`, or `entra`
- Checks outside the selected scope are silently skipped, producing a focused report for the chosen framework
- Banner, executive summary, and report header display the selected audit scope
- Fully backwards compatible — running without `-Audit` performs the full audit as before

### v5.1.0 — Enhanced Reporting & CSV Export

- **Executive Summary** with risk rating (Critical/High/Moderate/Low) and visual compliance score bar
- **Framework Score Dashboard** with ASCII progress bars and per-framework PASS/FAIL/WARN breakdowns for all five frameworks (CIS L1, CIS L2, CE/CE+, Entra ID/M365, NCSC)
- **Priority Remediation** section groups all failures by framework with numbered items for actionable triage
- **Warnings Summary** groups all warnings by framework for efficient manual review
- **Entra ID / M365** now included in per-framework detailed reports (previously missing)
- **CSV export** generated alongside the text report for integration with spreadsheets, SIEM, or analysis tools
- **Audit duration** tracked and displayed in the report footer
- **Sections Audited** listing reorganised into logical categories (Core Security, Entra/Cloud, CIS L2, CIS L1 Extended)
- Passed items in per-framework reports now show check name only (detail omitted for readability)
- Report helper functions added (`Write-ReportLine`, `Write-Divider`, `Get-ProgressBar`, `Get-RiskRating`) for consistent formatting

### v5.0.0 — CIS v5.0.1 L1 Full Coverage

- **134 new CIS L1 checks** across 9 new sections (71–79), mapped directly from the CIS Microsoft Windows 11 Enterprise v5.0.1 Level 1 benchmark audit file
- Total checks increased from 587 to **721** across **79 audit categories**
- New sections cover: Account Lockout (1.2.3), additional User Rights (2.2.x), Security Options (2.3.x), Windows Firewall Policy logging (9.x), Audit Policy subcategories (17.x), Personalization (18.1.x), MSS/Network/SMB hardening (18.5–18.6), Printer security (18.7.x), System templates (18.9.x), Windows Components (18.10.x), WiFi (18.11.x), and User templates (19.7.x)
- All checks mapped to specific CIS benchmark control IDs (e.g. `CIS 18.10.42.4.1`, `CIS 2.3.17.1`)

### Previous Changes

- **Section 15 (BitLocker)**: BitLocker Key Backed Up to Entra/AD check now always returns PASS on Entra-joined devices with BitLocker enabled, since key escrow is managed by Entra ID.
- **Section 22 (Unnecessary Windows Features)**: Features that return an empty or null state (i.e. not present / removed) are now correctly treated as PASS instead of WARN.
- **Section 26A (Account Separation)**: Fixed a PowerShell compatibility error where `try` was used as a sub-expression inside `Where-Object`, causing a `CommandNotFoundException` on some systems.
- **Section 26A (Entra Admins)**: Entra/AAD admin accounts found in the local Administrators group now report as INFO instead of WARN, since their presence is expected on Entra-joined devices.

## Author

**Peter Bassill** — OTY Heavy Industries

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
