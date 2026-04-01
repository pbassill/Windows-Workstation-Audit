# win-11-build-audit

A PowerShell script to audit Windows 10/11 builds against CIS Level 1 & 2, Cyber Essentials (CE), Cyber Essentials Plus (CE+), and Microsoft Entra ID / M365 security controls.

## Overview

This tool performs **416 individual security checks** across **60 audit categories**, covering:

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
.\audit.ps1
```

## Output

- **Console** — colour-coded results: **Green** (PASS), **Red** (FAIL), **Yellow** (WARN), **Cyan** (INFO / Cloud-Managed)
- **Report file** — `OTY_Heavy_Industries_Audit_<timestamp>.txt` saved to the Desktop, containing all results plus a compliance summary with pass/fail/warn counts and an overall score

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

## Author

**Peter Bassill** — OTY Heavy Industries

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
