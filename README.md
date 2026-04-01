# win-11-build-audit

A PowerShell script to audit Windows 10/11 builds against CIS Level 1, Cyber Essentials (CE), and Cyber Essentials Plus (CE+) security controls.

## Overview

This tool performs **139 individual security checks** across **26 audit categories**, covering:

- **CIS Microsoft Windows Benchmark Level 1** (~90 controls)
- **Cyber Essentials (CE)** baseline controls
- **Cyber Essentials Plus (CE+)** additional controls

Results are displayed with colour-coded console output and saved to a plain-text report on the Desktop.

## Requirements

- Windows 10/11 (tested on 22H2+)
- PowerShell
- **Administrator privileges** (the script enforces this via `#Requires -RunAsAdministrator`)

## Usage

Run the script in an elevated PowerShell session:

```powershell
.\audit.ps1
```

## Output

- **Console** — colour-coded results: **Green** (PASS), **Red** (FAIL), **Yellow** (WARN)
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

## Author

**Peter Bassill** — OTY Heavy Industries

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
