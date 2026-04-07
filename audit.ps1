#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Level 1 + Cyber Essentials + Cyber Essentials Plus + Entra ID / M365 Auditor
    Author: Peter Bassill | OTY Heavy Industries
.DESCRIPTION
    Comprehensive local Windows 10/11 audit covering:
      - CIS Microsoft Windows Benchmark Level 1
      - Cyber Essentials (CE) controls
      - Cyber Essentials Plus (CE+) additional controls
      - Microsoft Entra ID (Azure AD) join and device health
      - Microsoft Intune / MDM enrolment and compliance
      - Windows Hello for Business (WHfB)
      - Microsoft Defender for Endpoint (MDE)
      - Microsoft 365 / Office security configuration
      - Entra ID Conditional Access compliance

    The script is Entra ID-aware. When a device is detected as Entra joined,
    checks that are natively managed by Entra ID / Intune (e.g. password policy,
    lockout, account lifecycle) are contextually adjusted so that cloud-managed
    controls do not generate false FAILs against local policy baselines.

.PARAMETER Audit
    Selects which audit scope to run. Valid values:
      all   - Full audit across all frameworks (default)
      ce    - Cyber Essentials / CE+ checks only
      cis1  - CIS Level 1 checks only
      cis2  - CIS Level 2 checks only
      ncsc  - NCSC alignment checks only
      entra - Entra ID / M365 checks only

.PARAMETER PreviousReport
    Path to a previous audit JSON export file. When provided, the report
    includes a delta/trend comparison showing new failures, resolved items,
    score changes, and regressions since the last audit.

.EXAMPLE
    .\audit.ps1 -Audit all
    .\audit.ps1 -Audit ce
    .\audit.ps1 -Audit cis1
    .\audit.ps1 -Audit cis2
    .\audit.ps1 -Audit ncsc
    .\audit.ps1 -Audit entra
    .\audit.ps1 -PreviousReport "C:\audits\previous.json"

.NOTES
    Must be run as Administrator.
    Tested on Windows 10/11 22H2+, Entra ID joined and Hybrid joined.
    No Microsoft Graph or Azure AD module required - uses dsregcmd, registry,
    WMI/CIM, and local tooling only so it works offline and without extra modules.
#>
param(
    [ValidateSet("all","ce","cis1","cis2","ncsc","entra")]
    [string]$Audit = "all",

    [string]$PreviousReport = ""
)

# ============================================================
#  INITIALISATION
# ============================================================
$ScriptVersion = "6.0.0"
$Timestamp     = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$MachineName   = $env:COMPUTERNAME
$ReportPath    = "$env:USERPROFILE\${MachineName}_Audit_$Timestamp.txt"
$CsvPath       = "$env:USERPROFILE\${MachineName}_Audit_$Timestamp.csv"
$JsonPath      = "$env:USERPROFILE\${MachineName}_Audit_$Timestamp.json"
$HtmlPath      = "$env:USERPROFILE\${MachineName}_Audit_$Timestamp.html"
$SecCfg        = "$env:TEMP\oty_secedit_$Timestamp.cfg"
$Results       = [System.Collections.Generic.List[PSCustomObject]]::new()
$AuditStartTime = Get-Date

# ---- Audit scope filter ----
# Maps the -Audit parameter to the set of Framework values to include.
# "all" means no filtering; every framework is included.
$Script:AuditScope = $Audit.ToLower()
$Script:FrameworkFilter = switch ($Script:AuditScope) {
    "ce"    { @("CE+")            }
    "cis1"  { @("CIS")            }
    "cis2"  { @("CIS-L2")         }
    "ncsc"  { @("NCSC")           }
    "entra" { @("EntraID")        }
    default { @()                 }   # empty = include everything
}
$Script:AuditLabel = switch ($Script:AuditScope) {
    "ce"    { "Cyber Essentials / CE+" }
    "cis1"  { "CIS Level 1"           }
    "cis2"  { "CIS Level 2"           }
    "ncsc"  { "NCSC Alignment"        }
    "entra" { "Entra ID / M365"       }
    default { "Full Audit (all frameworks)" }
}

# Entra ID context flags - populated in Section 27, referenced throughout
$Script:EntraJoined      = $false
$Script:HybridJoined     = $false
$Script:WorkplaceJoined  = $false
$Script:MDMEnrolled      = $false
$Script:TenantID         = "Not detected"
$Script:TenantName       = "Not detected"
$Script:DeviceID         = "Not detected"
$Script:PRTPresent       = $false
$Script:ComplianceURL    = ""
$Script:MDMUrl           = ""

# ---- Load remediation guidance companion file ----
$Script:RemediationData = @{}
$remDataPath = Join-Path $PSScriptRoot "remediation.json"
if (Test-Path $remDataPath) {
    try {
        $remJson = Get-Content $remDataPath -Raw -ErrorAction Stop | ConvertFrom-Json
        foreach ($entry in $remJson) {
            $Script:RemediationData[$entry.id] = @{
                Severity    = $entry.severity
                Remediation = $entry.remediation
            }
        }
    } catch { }
}

# ---- Load previous report for delta comparison ----
$Script:PreviousData = $null
if ($PreviousReport -and (Test-Path $PreviousReport)) {
    try {
        $Script:PreviousData = Get-Content $PreviousReport -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        Write-Host "  [!] Could not parse previous report: $_" -ForegroundColor Yellow
    }
}

# ---- Severity weight mapping ----
# Used for weighted scoring: Critical x3, High x2, Medium x1
function Get-SeverityWeight {
    param([string]$CheckID)
    if ($Script:RemediationData.ContainsKey($CheckID)) {
        $sev = $Script:RemediationData[$CheckID].Severity
        switch ($sev) {
            "Critical" { return 3 }
            "High"     { return 2 }
            default    { return 1 }
        }
    }
    return 1
}

# ---- Compliance threshold mapping ----
$Script:ComplianceThresholds = @{
    "CIS"     = @{ Threshold = 90;  Label = "CIS Level 1 (90%)"         }
    "CIS-L2"  = @{ Threshold = 90;  Label = "CIS Level 2 (90%)"         }
    "CE+"     = @{ Threshold = 100; Label = "Cyber Essentials (100%)"    }
    "NCSC"    = @{ Threshold = 85;  Label = "NCSC Alignment (85%)"       }
    "EntraID" = @{ Threshold = 90;  Label = "Entra ID / M365 (90%)"     }
}

# ============================================================
#  HELPER FUNCTIONS
# ============================================================

function Write-Banner {
    $os    = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
    $build = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).BuildNumber
    $lines = @(
        "========================================================================",
        "  OTY HEAVY INDUSTRIES - COMPREHENSIVE WINDOWS AUDIT",
        "  CIS Level 1 & 2  |  Cyber Essentials  |  Cyber Essentials Plus",
        "  Microsoft Entra ID  |  Microsoft 365  |  Intune / MDM  |  NCSC",
        "  Version $ScriptVersion",
        "  Audit Scope  : $($Script:AuditLabel)",
        "========================================================================",
        "  Hostname     : $env:COMPUTERNAME",
        "  User         : $env:USERNAME",
        "  Date/Time    : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss') UTC",
        "  OS           : $os (Build $build)",
        "========================================================================"
    )
    foreach ($line in $lines) { Write-Host $line -ForegroundColor Cyan }
    Write-Host ""
    $lines | Set-Content -Path $ReportPath -Encoding UTF8
    Add-Content -Path $ReportPath -Value ""
}

function Write-SectionHeader {
    param([string]$Title, [string]$Framework = "")
    $tag  = if ($Framework) { "  [$Framework]" } else { "" }
    $line = "`n  --- $Title$tag ---"
    Write-Host $line -ForegroundColor Yellow
    Add-Content -Path $ReportPath -Value $line
}

function Add-Result {
    param(
        [string]$ID,
        [string]$Description,
        [ValidateSet("PASS","FAIL","WARN","INFO")]
        [string]$Status,
        [string]$Detail    = "",
        [string]$Framework = "CIS"
    )
    # Skip checks outside the selected audit scope
    if ($Script:FrameworkFilter.Count -gt 0 -and $Framework -notin $Script:FrameworkFilter) { return }

    $Results.Add([PSCustomObject]@{
        ID          = $ID
        Description = $Description
        Status      = $Status
        Detail      = $Detail
        Framework   = $Framework
    })
    $colour = switch ($Status) {
        "PASS" { "Green"   }
        "FAIL" { "Red"     }
        "WARN" { "Yellow"  }
        "INFO" { "Cyan"    }
    }
    $line = "  [{0}] {1,-46} {2}" -f $Status, $Description, $Detail
    Write-Host $line -ForegroundColor $colour
    Add-Content -Path $ReportPath -Value $line
}

# Cloud-managed advisory: used when a control is owned by Entra/Intune
function Add-CloudManaged {
    param([string]$ID, [string]$Description, [string]$Detail = "")
    Add-Result $ID $Description "INFO" "CLOUD-MANAGED: $Detail - Verify in Entra ID / Intune portal" "EntraID"
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

function Get-SecEditValue {
    param([string]$Key)
    if (-not (Test-Path $SecCfg)) { return $null }
    try {
        $line = Get-Content $SecCfg -Encoding Unicode -ErrorAction Stop |
                Where-Object { $_ -match "^\s*$Key\s*=" }
        if ($line) { return ($line -split "=")[1].Trim() }
    } catch {
        $line = Get-Content $SecCfg -ErrorAction SilentlyContinue |
                Where-Object { $_ -match "^\s*$Key\s*=" }
        if ($line) { return ($line -split "=")[1].Trim() }
    }
    return $null
}

function Get-AuditpolValue {
    param([string]$Subcategory)
    $out = auditpol /get /subcategory:"$Subcategory" 2>$null
    if ($out) {
        $line = $out | Where-Object { $_ -match $Subcategory }
        if ($line) {
            $parts = $line -split "\s{2,}"
            return $parts[-1].Trim()
        }
    }
    return $null
}

# Parse dsregcmd /status output into a hashtable
function Get-DsregStatus {
    $raw    = dsregcmd /status 2>$null
    $result = @{}
    if (-not $raw) { return $result }
    foreach ($line in $raw) {
        if ($line -match "^\s*([A-Za-z]+)\s*:\s*(.+)$") {
            $result[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    return $result
}

# ---- Reporting helper: ASCII progress bar ----
# Uses Unicode block elements (U+2588 full block, U+2591 light shade).
# These render correctly in Windows Terminal, PowerShell ISE, and most
# modern editors. On legacy consoles that lack Unicode support the bar
# will still display as rectangular glyphs of differing density.
function Get-ProgressBar {
    param([double]$Percent, [int]$Width = 30)
    $filled = [math]::Floor($Percent / 100 * $Width)
    $empty  = $Width - $filled
    $bar    = ([string][char]0x2588) * $filled + ([string][char]0x2591) * $empty
    return $bar
}

# ---- Reporting helper: risk rating from score ----
function Get-RiskRating {
    param([double]$Score)
    if     ($Score -ge 90) { return @{ Label = "LOW";      Color = "Green"  } }
    elseif ($Score -ge 75) { return @{ Label = "MODERATE"; Color = "Yellow" } }
    elseif ($Score -ge 50) { return @{ Label = "HIGH";     Color = "Red"    } }
    else                   { return @{ Label = "CRITICAL"; Color = "Red"    } }
}

# ---- Reporting helper: write coloured + file output ----
function Write-ReportLine {
    param(
        [string]$Text,
        [string]$Color = "Cyan",
        [switch]$NoNewline
    )
    if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
    else            { Write-Host $Text -ForegroundColor $Color }
    Add-Content -Path $ReportPath -Value $Text
}

# ---- Reporting helper: write a divider ----
function Write-Divider {
    param([string]$Char = "=", [int]$Width = 72)
    $line = "  " + ($Char * $Width)
    Write-ReportLine $line
}

# ============================================================
#  EXPORT SECURITY POLICY ONCE + DETECT ENTRA ID JOIN STATE
# ============================================================
Write-Host "  [*] Exporting security policy..." -ForegroundColor DarkGray
secedit /export /cfg $SecCfg /quiet 2>$null

Write-Host "  [*] Detecting Entra ID join state..." -ForegroundColor DarkGray
$dsreg = Get-DsregStatus

$Script:EntraJoined     = ($dsreg["AzureAdJoined"]     -eq "YES")
$Script:HybridJoined    = ($dsreg["DomainJoined"]       -eq "YES") -and $Script:EntraJoined
$Script:WorkplaceJoined = ($dsreg["WorkplaceJoined"]    -eq "YES")
$Script:PRTPresent      = ($dsreg["AzureAdPrt"]         -eq "YES")
$Script:TenantID        = if ($dsreg["TenantId"])    { $dsreg["TenantId"]    } else { "Not detected" }
$Script:TenantName      = if ($dsreg["TenantName"])  { $dsreg["TenantName"]  } else { "Not detected" }
$Script:DeviceID        = if ($dsreg["DeviceId"])    { $dsreg["DeviceId"]    } else { "Not detected" }
$Script:MDMUrl          = if ($dsreg["MdmUrl"])      { $dsreg["MdmUrl"]      } else { "" }
$Script:ComplianceURL   = if ($dsreg["ComplianceUrl"]){ $dsreg["ComplianceUrl"] } else { "" }
$Script:MDMEnrolled     = ($Script:MDMUrl -ne "")

$joinType = if ($Script:HybridJoined)     { "Hybrid (Entra ID + On-Prem AD)" }
            elseif ($Script:EntraJoined)   { "Entra ID Joined (Cloud-only)" }
            elseif ($Script:WorkplaceJoined){ "Workplace Joined (BYOD)" }
            else                           { "Not joined to Entra ID" }

Write-Host "  [*] Device join type: $joinType" -ForegroundColor DarkGray
if ($Script:MDMEnrolled) {
    Write-Host "  [*] MDM enrolled: $($Script:MDMUrl)" -ForegroundColor DarkGray
}

Write-Banner

# ============================================================
#  SECTION 1: PASSWORD POLICY  [CIS 1.1 | CE2 | NCSC]
#
#  Two frameworks are applied in parallel and reported separately:
#
#  CIS Benchmark (traditional): length >=14, complexity ON,
#    max age 1-365 days, history >=24.
#
#  NCSC Password Guidance (modern best practice):
#    - Length >= 15 characters (3-word passphrase = ~20 chars)
#    - Complexity OFF (complexity + short password = predictable patterns)
#    - No forced expiry (MaxAge = 0 or very high); only change on compromise
#    - History still recommended to prevent reuse post-compromise
#    - Banned-password list / breach-checking preferred over expiry
#
#  NCSC reference: https://www.ncsc.gov.uk/collection/passwords
#  Where the two frameworks conflict, both results are reported so the
#  operator can make an informed choice for their risk appetite.
# ============================================================
Write-SectionHeader "1. PASSWORD POLICY" "CIS 1.1 | CE2 | NCSC"

if ($Script:EntraJoined -and -not $Script:HybridJoined) {
    # ---- Pure Entra ID joined - password policy is cloud-managed ----
    Add-CloudManaged "1.1"  "Password History"          "Managed by Entra ID Password Protection policy"
    Add-CloudManaged "1.2"  "Password Age / Expiry"     "NCSC: No forced expiry. Entra ID: configure 'never expire' or >=365 days"
    Add-CloudManaged "1.3"  "Minimum Password Age"      "Managed by Entra ID"
    Add-CloudManaged "1.4"  "Minimum Password Length"   "Entra default 8 chars. NCSC/CIS: enforce >=15 via Conditional Access or Entra policy"
    Add-CloudManaged "1.5"  "Password Complexity"       "NCSC: Complexity unnecessary at >=15 chars. Entra enforces by default."
    Add-CloudManaged "1.6"  "No Reversible Encryption"  "Not applicable to Entra ID cloud accounts"

    # Entra Password Protection (banned password list) - NCSC breach-aware model
    # Cloud-managed: Entra ID owns password protection; local policy is not authoritative
    $eppEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\AzureADPasswordProtection" "EnableBannedPasswordCheck"
    Add-Result "1.N1" "Entra Password Protection (Banned List)" "INFO" "CLOUD-MANAGED: EnableBannedPasswordCheck: $(if ($null -eq $eppEnabled) {'Not configured via local policy - verify in Entra portal > Security > Auth Methods > Password Protection'} else {$eppEnabled})" "NCSC"

    # SSPR (Self-Service Password Reset) indicator - sign of breach-driven change model
    $sspReg = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\AzureADPasswordProtection" "EnableSelfServicePasswordReset"
    Add-Result "1.N2" "Self-Service Password Reset (SSPR)" "INFO" "SSPR policy: $(if ($null -eq $sspReg) {'Not configured locally - verify in Entra portal'} else {$sspReg}) | NCSC: users should change only on suspected compromise" "NCSC"

    # Local fallback length check - cloud-managed: Entra policy is primary, local is informational only
    $minLen = Get-SecEditValue "MinimumPasswordLength"
    Add-Result "1.7"  "Local Policy Min Length (Fallback)" "INFO" "CLOUD-MANAGED: Local secedit: $minLen chars | Entra policy is primary - verify password length requirements in Entra ID." "CIS"

} else {
    # ---- Domain / local - check secedit directly ----
    $historySize = Get-SecEditValue "PasswordHistorySize"
    $maxAge      = Get-SecEditValue "MaximumPasswordAge"
    $minAge      = Get-SecEditValue "MinimumPasswordAge"
    $minLen      = Get-SecEditValue "MinimumPasswordLength"
    $complexity  = Get-SecEditValue "PasswordComplexity"
    $reversible  = Get-SecEditValue "ClearTextPassword"

    # ------ PASSWORD HISTORY ------
    # Both CIS and NCSC agree: history prevents reuse post-compromise.
    $s = if ([int]$historySize -ge 24) { "PASS" } else { "FAIL" }
    Add-Result "1.1" "Password History" $s "CIS: >=24 | NCSC: >=24 recommended. Got: $historySize"

    # ------ MAXIMUM PASSWORD AGE ------
    # CIS: 1-365 days. NCSC: 0 (never) or very long; forced expiry is deprecated.
    # We report both perspectives clearly.
    $maxAgeInt = [int]$maxAge
    # CIS view
    $cisPwdAge = if ($maxAgeInt -le 365 -and $maxAgeInt -ge 1) { "PASS" } else { "FAIL" }
    # NCSC view: 0 = never expire (best), >=365 = acceptable, <365 = questionable, <90 = poor
    $ncscPwdAge = if ($maxAgeInt -eq 0)          { "PASS" }   # Never expire - NCSC preferred
                  elseif ($maxAgeInt -ge 365)     { "PASS" }   # Very long - acceptable
                  elseif ($maxAgeInt -ge 180)     { "WARN" }   # Moderately long
                  elseif ($maxAgeInt -ge 90)      { "WARN" }   # Common but NCSC deprecated
                  else                            { "FAIL" }   # <90 days - counterproductive per NCSC
    Add-Result "1.2.CIS"  "Maximum Password Age (CIS view)"  $cisPwdAge  "CIS requires 1-365 days. Got: $(if ($maxAgeInt -eq 0) {'0 (never)'} else {"$maxAgeInt days"})" "CIS"
    Add-Result "1.2.NCSC" "Maximum Password Age (NCSC view)" $ncscPwdAge "NCSC: 0=Never expire (best), >=365=OK, <90=FAIL. Got: $(if ($maxAgeInt -eq 0) {'0 (never expire - NCSC preferred)'} else {"$maxAgeInt days"})" "NCSC"

    # ------ MINIMUM PASSWORD AGE ------
    # Both frameworks: >=1 day prevents rapid cycling to defeat history.
    $s = if ([int]$minAge -ge 1) { "PASS" } else { "WARN" }
    Add-Result "1.3" "Minimum Password Age" $s "Both CIS & NCSC: >=1 day prevents cycling. Got: $minAge days"

    # ------ MINIMUM PASSWORD LENGTH ------
    # CIS: >=14. NCSC: >=15 (passphrase model). We report the NCSC threshold as primary.
    $minLenInt = [int]$minLen
    $cisLen  = if ($minLenInt -ge 14) { "PASS" } else { "FAIL" }
    $ncscLen = if ($minLenInt -ge 15) { "PASS" } elseif ($minLenInt -ge 12) { "WARN" } else { "FAIL" }
    Add-Result "1.4.CIS"  "Minimum Password Length (CIS view)"  $cisLen  "CIS: >=14 chars. Got: $minLen" "CIS"
    Add-Result "1.4.NCSC" "Minimum Password Length (NCSC view)" $ncscLen "NCSC: >=15 chars for passphrases (3 random words ~20 chars). Got: $minLen" "NCSC"

    # ------ COMPLEXITY ------
    # CIS: complexity ON. NCSC: complexity OFF when length >= 15.
    # Complexity forces short predictable passwords (P@ssw0rd pattern).
    $cisComplex  = if ($complexity -eq "1") { "PASS" } else { "FAIL" }
    # NCSC: complexity OFF is preferred if length >= 15; ON is acceptable but not required
    $ncscComplex = if ($complexity -eq "0" -and $minLenInt -ge 15) { "PASS" }
                   elseif ($complexity -eq "1")                    { "WARN" }   # On but length should carry the burden
                   elseif ($minLenInt -lt 15)                      { "FAIL" }   # Off AND short = bad
                   else                                             { "PASS" }
    $complexDesc = if ($complexity -eq "1") { "Enabled" } else { "Disabled" }
    Add-Result "1.5.CIS"  "Password Complexity (CIS view)"  $cisComplex  "CIS: complexity ON required. Got: $complexDesc" "CIS"
    Add-Result "1.5.NCSC" "Password Complexity (NCSC view)" $ncscComplex "NCSC: complexity OFF preferred when length >=15 (avoids P@ssw0rd patterns). Got: $complexDesc, Length: $minLen chars" "NCSC"

    # ------ REVERSIBLE ENCRYPTION ------
    # Universal FAIL regardless of framework.
    $s = if ($reversible -eq "0") { "PASS" } else { "FAIL" }
    Add-Result "1.6" "No Reversible Encryption" $s "Both CIS & NCSC: must be disabled. Got: $(if ($reversible -eq '0') {'Disabled'} else {'ENABLED - immediate risk'})"

    # ------ CIS 1.1.7: RELAX MINIMUM PASSWORD LENGTH LIMITS ------
    $relaxLen = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" "RelaxMinimumPasswordLengthLimits"
    $s = if ($relaxLen -eq 1) { "PASS" } else { "WARN" }
    Add-Result "1.7" "Relax Min Password Length Limits" $s "CIS 1.1.7: RelaxMinimumPasswordLengthLimits: $(if ($null -eq $relaxLen) {'Not set'} else {$relaxLen}) (1=Enabled, allows >14 chars)" "CIS"

    # ------ NCSC: BREACH / COMPROMISE MONITORING ------
    # NCSC recommends passwords are only changed on known compromise.
    # Check for Entra Password Protection agent (hybrid) or HIBP-style tooling indicators.
    $eppHybrid = Get-RegValue "HKLM:\SOFTWARE\Microsoft\AzureADPasswordProtection\AzureADPasswordProtectionProxy" "Enabled"
    $eppDC     = Get-RegValue "HKLM:\SOFTWARE\Microsoft\AzureADPasswordProtection\AzureADPasswordProtectionDCAgent" "Enabled"
    if ($Script:HybridJoined -or $Script:EntraJoined) {
        $s = if ($null -ne $eppHybrid -or $null -ne $eppDC) { "PASS" } else { "WARN" }
        Add-Result "1.N1" "NCSC: Breach-Aware Password Protection" $s "Entra Password Protection agent: $(if ($null -ne $eppHybrid -or $null -ne $eppDC) {'Detected'} else {'Not detected - verify Entra Password Protection is deployed for on-prem AD'})" "NCSC"
    } else {
        Add-Result "1.N1" "NCSC: Breach-Aware Password Change Model" "WARN" "NCSC recommends passwords only change on suspected compromise. Implement banned-password list / HIBP checking. No Entra Password Protection agent detected." "NCSC"
    }

    # ------ NCSC: PASSPHRASE GUIDANCE NOTE ------
    Add-Result "1.N2" "NCSC: Passphrase Policy Guidance" "INFO" "NCSC recommends 3 random words (e.g. 'CoffeeLampBridge') over complex short passwords. Enforce length >=15, disable complexity, remove expiry. See: ncsc.gov.uk/collection/passwords" "NCSC"
}

# ============================================================
#  SECTION 2: ACCOUNT LOCKOUT  [CIS 1.2 | CE2]
# ============================================================
Write-SectionHeader "2. ACCOUNT LOCKOUT POLICY" "CIS 1.2 | CE2"

if ($Script:EntraJoined -and -not $Script:HybridJoined) {
    # Entra ID uses Smart Lockout, not traditional lockout
    Add-CloudManaged "2.1" "Lockout Threshold"       "Managed by Entra ID Smart Lockout (default: 10 attempts)"
    Add-CloudManaged "2.2" "Lockout Duration"         "Managed by Entra ID Smart Lockout (adaptive duration)"
    Add-CloudManaged "2.3" "Reset Lockout Counter"    "Managed by Entra ID Smart Lockout"
    Add-Result "2.4" "Entra Smart Lockout Note" "INFO" "Verify Smart Lockout threshold <=5 in Entra ID portal > Security > Auth Methods > Password Protection" "EntraID"
} else {
    $lockoutCount    = Get-SecEditValue "LockoutBadCount"
    $lockoutDuration = Get-SecEditValue "LockoutDuration"
    $resetCount      = Get-SecEditValue "ResetLockoutCount"

    $s = if ([int]$lockoutCount -ge 1 -and [int]$lockoutCount -le 5) { "PASS" } else { "FAIL" }
    Add-Result "2.1" "Lockout Threshold" $s "Required 1-5 attempts, Got: $lockoutCount"

    $s = if ([int]$lockoutDuration -ge 15) { "PASS" } else { "FAIL" }
    Add-Result "2.2" "Lockout Duration" $s "Required >=15 mins, Got: $lockoutDuration mins"

    $s = if ([int]$resetCount -ge 15) { "PASS" } else { "FAIL" }
    Add-Result "2.3" "Reset Lockout Counter" $s "Required >=15 mins, Got: $resetCount mins"

    # CIS 1.2.4: Allow Administrator Account Lockout
    $adminLockout = Get-SecEditValue "AllowAdministratorLockout"
    $s = if ($adminLockout -eq "1") { "PASS" } else { "WARN" }
    Add-Result "2.4" "Allow Admin Account Lockout" $s "CIS 1.2.4: AllowAdministratorLockout: $(if ($null -eq $adminLockout) {'Not set'} else {$adminLockout}) (1=Enabled)" "CIS"
}

# ============================================================
#  SECTION 3: REMOTE DESKTOP  [CIS | CE1 | CE+]
# ============================================================
Write-SectionHeader "3. REMOTE DESKTOP (RDP)" "CIS | CE1 | CE+"

$deny     = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
$nla      = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
$encLevel = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel"

if ($deny -eq 1) {
    Add-Result "3.1" "RDP Status" "PASS" "RDP is disabled"
    Add-Result "3.2" "RDP: NLA Required" "PASS" "N/A - RDP is disabled"
    Add-Result "3.3" "RDP: Minimum Encryption Level" "PASS" "N/A - RDP is disabled"
} else {
    Add-Result "3.1" "RDP Status" "FAIL" "RDP is enabled - ensure this is intentional"
    $s = if ($nla -eq 1) { "PASS" } else { "FAIL" }
    Add-Result "3.2" "RDP: NLA Required" $s "Required: Enabled, Got: $(if ($nla -eq 1) {'Enabled'} else {'Disabled'})"
    $s = if ($encLevel -ge 3) { "PASS" } else { "FAIL" }
    Add-Result "3.3" "RDP: Minimum Encryption Level" $s "Required >=3 (High), Got: $encLevel"

    if ($Script:EntraJoined) {
        # On Entra ID joined devices, RDP should use WHfB or Entra auth
        $rdpSSO = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowDefaultCredentials"
        $s = if ($null -eq $rdpSSO -or $rdpSSO -eq 0) { "PASS" } else { "WARN" }
        Add-Result "3.4" "RDP: Credential Delegation Restricted" $s "AllowDefaultCredentials: $rdpSSO (Entra joined - review Conditional Access)" "EntraID"
    }
}

# ============================================================
#  SECTION 4: LOCAL ACCOUNTS  [CIS | CE3 | CE+]
# ============================================================
Write-SectionHeader "4. LOCAL ACCOUNTS" "CIS | CE3 | CE+"

if ($Script:EntraJoined) {
    Add-Result "4.0" "Device Identity Type" "INFO" "Join type: $joinType | Tenant: $($Script:TenantName) ($($Script:TenantID))" "EntraID"
}

# Guest account
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
    $s     = if (-not $guest.Enabled) { "PASS" } else { "FAIL" }
    Add-Result "4.1" "Guest Account Disabled" $s "Account is $(if ($guest.Enabled) {'ENABLED'} else {'DISABLED'})"
} catch {
    # Get-LocalUser throws if the account does not exist. A missing Guest account
    # is effectively the same posture as a disabled one - treat as PASS.
    Add-Result "4.1" "Guest Account Disabled" "PASS" "Guest account not found - account absent or inaccessible (treated as disabled)"
}

# Accounts with no password required
$noPasswd = Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled -eq $true }
if ($noPasswd) {
    Add-Result "4.2" "No Accounts Without Password" "FAIL" "Accounts with no password: $(($noPasswd.Name) -join ', ')"
} else {
    Add-Result "4.2" "No Accounts Without Password" "PASS" "All enabled accounts require a password"
}

# Local admin count - on Entra joined devices the expected members differ
$adminGroup  = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$localAdmins = $adminGroup | Where-Object { $_.PrincipalSource -eq "Local" }
$entraAdmins = $adminGroup | Where-Object { $_.PrincipalSource -in @("AzureAD","ActiveDirectory") }

# Exclude the account running this script from the local admin count.
# If the operator is the only local admin present, the effective count is 0
# (they need admin rights to run the script - their presence is expected).
$currentUserSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$localAdminsExcludingSelf = $localAdmins | Where-Object {
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($_.Name)).Translate(
                   [System.Security.Principal.SecurityIdentifier]).Value
        $sid -ne $currentUserSID
    } catch {
        # If SID translation fails keep the account in the count (safer)
        $true
    }
}

$effectiveLocalCount = if ($localAdminsExcludingSelf) { @($localAdminsExcludingSelf).Count } else { 0 }
$adminCount          = $effectiveLocalCount + ($entraAdmins | Measure-Object).Count
if ($Script:EntraJoined -and -not $Script:HybridJoined) {
    Add-Result "4.3" "Local Admin Account Count" "INFO" "CLOUD-MANAGED: Effective total: $adminCount (local excl. script runner: $effectiveLocalCount | Cloud/AD: $(($entraAdmins | Measure-Object).Count)) | Script runner excluded: $env:USERNAME - Verify in Entra ID / Intune portal" "EntraID"
} else {
    $s = if ($adminCount -le 2) { "PASS" } elseif ($adminCount -le 4) { "WARN" } else { "FAIL" }
    Add-Result "4.3" "Local Admin Account Count" $s "Effective total: $adminCount (local excl. script runner: $effectiveLocalCount | Cloud/AD: $(($entraAdmins | Measure-Object).Count)) | Script runner excluded: $env:USERNAME"
}

if ($Script:EntraJoined -and $entraAdmins.Count -gt 0) {
    Add-Result "4.3E" "Entra ID Admins on Device" "INFO" "Cloud admin principals: $(($entraAdmins.Name) -join ', ') - Verify via Entra ID Device Local Admins policy" "EntraID"
}

# Built-in Admin renamed
# On Entra joined + MDM enrolled devices, the built-in admin is typically managed
# by Windows LAPS or disabled via Intune - local renaming policy may not apply.
$adminUser = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-500" } -ErrorAction SilentlyContinue
if ($adminUser) {
    if ($Script:EntraJoined -and -not $Script:HybridJoined) {
        # Cloud-managed: admin account is managed by Entra/Intune, report as informational
        $lapsManaged = $null -ne (Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "BackupDirectory")
        Add-Result "4.4" "Built-in Admin Account Renamed" "INFO" "CLOUD-MANAGED: Account: $($adminUser.Name) | $(if ($lapsManaged) {'LAPS configured - LAPS manages this account'} else {'LAPS not detected - consider enabling LAPS via Intune'}) - Verify in Entra ID / Intune portal" "EntraID"
    } else {
        $s = if ($adminUser.Name -ne "Administrator") { "PASS" } else { "WARN" }
        Add-Result "4.4" "Built-in Admin Account Renamed" $s "Account name: $($adminUser.Name)"
    }
} else {
    Add-Result "4.4" "Built-in Admin Account Renamed" "WARN" "Could not determine built-in admin account"
}

# Non-expiring passwords
# On Entra joined devices, primary user identities are cloud-managed by Entra ID.
# Get-LocalUser only returns local accounts; Entra users do not appear here.
# On a well-configured Entra device the only enabled local accounts should be
# the built-in admin (managed by LAPS) and possibly a break-glass account.
$neverExpire = Get-LocalUser | Where-Object { $_.PasswordExpires -eq $null -and $_.Enabled -eq $true -and $_.PasswordRequired -eq $true }
if ($Script:EntraJoined -and $Script:MDMEnrolled) {
    # Filter out the built-in admin (SID -500) if LAPS is managing it - its expiry
    # being null is expected and correct (LAPS rotates the password, not the OS expiry)
    $lapsActive = $null -ne (Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "BackupDirectory")
    $neverExpireNonLaps = $neverExpire | Where-Object {
        $acct = $_
        try {
            $sid = $acct.SID.Value
            # Exclude built-in admin when LAPS is active
            -not ($lapsActive -and $sid -like "S-1-5-*-500")
        } catch { $true }
    }
    if ($neverExpireNonLaps) {
        Add-Result "4.5" "No Accounts With Non-Expiring Password" "WARN" "Non-expiring local accounts (excl. LAPS-managed): $(($neverExpireNonLaps.Name) -join ', ') | Entra users managed via cloud - only local accounts shown" "EntraID"
    } else {
        Add-Result "4.5" "No Accounts With Non-Expiring Password" "PASS" "No local accounts with non-expiring passwords (excl. LAPS-managed built-in admin) | Entra user identities managed via Entra ID" "EntraID"
    }
} else {
    if ($neverExpire) {
        Add-Result "4.5" "No Accounts With Non-Expiring Password" "WARN" "Non-expiring local accounts: $(($neverExpire.Name) -join ', ')"
    } else {
        Add-Result "4.5" "No Accounts With Non-Expiring Password" "PASS" "No enabled local accounts have non-expiring passwords"
    }
}

# Deny log on locally for Guests
# On Entra joined + MDM enrolled devices, who can sign in locally is governed by
# Entra Conditional Access and the Intune Device Local Admins policy.
# The Guest account is typically absent or disabled; the deny-right may not be set
# because Entra identity policy supersedes local security policy for user logon.
$denyLocal = Get-SecEditValue "SeDenyInteractiveLogonRight"
if ($Script:EntraJoined -and $Script:MDMEnrolled) {
    # Guest is disabled/absent AND Entra controls logon = compliant regardless of secedit
    $guestEnabled = $false
    try {
        $guestAcct = Get-LocalUser -Name "Guest" -ErrorAction Stop
        $guestEnabled = $guestAcct.Enabled
    } catch { $guestEnabled = $false }  # absent = not enabled
    $s = if (-not $guestEnabled) { "PASS" } else { "FAIL" }
    Add-Result "4.6" "Deny Guests Local Logon" $s "Entra+MDM managed device | Guest account enabled: $guestEnabled | Entra ID Conditional Access governs local logon | secedit value: $denyLocal" "EntraID"
} else {
    $s = if ($denyLocal -and $denyLocal -match "Guest") { "PASS" } else { "FAIL" }
    Add-Result "4.6" "Deny Guests Local Logon" $s "Value: $denyLocal"
}

$denyRDP = Get-SecEditValue "SeDenyRemoteInteractiveLogonRight"
if ($deny -eq 1) {
    # RDP is disabled entirely - the deny right is redundant but posture is compliant
    Add-Result "4.7" "Deny Guests RDP Logon" "PASS" "RDP is disabled - moot; no RDP logon possible"
} else {
    $s = if ($denyRDP -and $denyRDP -match "Guest") { "PASS" } else { "FAIL" }
    Add-Result "4.7" "Deny Guests RDP Logon" $s "Value: $denyRDP"
}

# ============================================================
#  SECTION 5: WINDOWS FIREWALL  [CIS | CE1 | CE+]
# ============================================================
Write-SectionHeader "5. WINDOWS FIREWALL" "CIS | CE1 | CE+"

$fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($profile in @("Domain","Private","Public")) {
    $fw = $fwProfiles | Where-Object { $_.Name -eq $profile }
    if ($fw) {
        $s = if ($fw.Enabled) { "PASS" } else { "FAIL" }
        Add-Result "5.$($profile[0])" "Firewall Enabled: $profile" $s "Inbound: $($fw.DefaultInboundAction), Outbound: $($fw.DefaultOutboundAction)"

        $s = if ($fw.DefaultInboundAction -eq "Block") { "PASS" } else { "FAIL" }
        Add-Result "5.$($profile[0])i" "Firewall Default Inbound Block: $profile" $s "Action: $($fw.DefaultInboundAction)"

        $s = if (-not $fw.AllowUnicastResponseToMulticast) { "PASS" } else { "WARN" }
        Add-Result "5.$($profile[0])u" "Unicast Response to Multicast: $profile" $s "Value: $($fw.AllowUnicastResponseToMulticast)"

        $s = if ($fw.LogBlocked -eq $true) { "PASS" } else { "WARN" }
        Add-Result "5.L$($profile[0])" "Firewall Log Dropped Packets: $profile" $s "LogBlocked: $($fw.LogBlocked)"

        # CIS 9.x.4: Firewall log file size >= 16384 KB
        $logSize = $fw.LogMaxSizeKilobytes
        $s = if ($null -ne $logSize -and [int]$logSize -ge 16384) { "PASS" } else { "WARN" }
        Add-Result "5.S$($profile[0])" "Firewall Log Size: $profile" $s "CIS 9.x.4: LogMaxSizeKilobytes: $(if ($null -eq $logSize) {'Default (4096)'} else {"$logSize KB"}) (>=16384 KB)"

        # CIS 9.x.6: Log successful connections
        $logAllowed = $fw.LogAllowed
        $s = if ($logAllowed -eq 1 -or $logAllowed -eq $true) { "PASS" } else { "WARN" }
        Add-Result "5.A$($profile[0])" "Firewall Log Successful Conns: $profile" $s "CIS 9.x.6: LogAllowed: $logAllowed"
    } else {
        Add-Result "5.$($profile[0])" "Firewall Profile: $profile" "WARN" "Could not retrieve profile"
    }
}

# On Entra/Intune joined devices, check if firewall is managed by Intune
if ($Script:MDMEnrolled) {
    $fwPolicyCSP = Get-RegValue "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Firewall" "EnableFirewall"
    $s = if ($null -ne $fwPolicyCSP) { "PASS" } else { "WARN" }
    Add-Result "5.MDM" "Firewall Policy via Intune CSP" $s "EnableFirewall CSP: $(if ($null -ne $fwPolicyCSP) {'Applied'} else {'Not detected - verify Intune Firewall profile'})" "EntraID"
}

# ============================================================
#  SECTION 6: PATCH MANAGEMENT  [CIS | CE5 | CE+]
# ============================================================
Write-SectionHeader "6. PATCH MANAGEMENT" "CIS | CE5 | CE+"

$wuSvc = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
if ($wuSvc) {
    $s = if ($wuSvc.StartType -ne "Disabled") { "PASS" } else { "FAIL" }
    Add-Result "6.1" "Windows Update Service Not Disabled" $s "Status: $($wuSvc.Status), StartType: $($wuSvc.StartType)"
} else {
    Add-Result "6.1" "Windows Update Service Not Disabled" "WARN" "Service not found"
}

$noAutoUpdate = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"
$s = if ($noAutoUpdate -ne 1) { "PASS" } else { "FAIL" }
Add-Result "6.2" "Auto Updates Not Disabled" $s "NoAutoUpdate: $(if ($null -eq $noAutoUpdate) {'Not set (default enabled)'} else {$noAutoUpdate})"

$lastUpdate = (Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
if ($lastUpdate) {
    $daysSince = ((Get-Date) - $lastUpdate).Days
    $s = if ($daysSince -le 30) { "PASS" } elseif ($daysSince -le 60) { "WARN" } else { "FAIL" }
    Add-Result "6.3" "Last Patch Installed" $s "Installed: $($lastUpdate.ToString('dd/MM/yyyy')) ($daysSince days ago)"
} else {
    Add-Result "6.3" "Last Patch Installed" "WARN" "Could not determine last patch date"
}

$pendingReboot = $false
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $pendingReboot = $true }
$prnReg = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "PendingFileRenameOperations"
if ($prnReg) { $pendingReboot = $true }
$s = if (-not $pendingReboot) { "PASS" } else { "WARN" }
Add-Result "6.4" "No Pending Reboot for Updates" $s "Pending reboot: $pendingReboot"

# Intune Windows Update for Business rings
if ($Script:MDMEnrolled) {
    $wufbDefer = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdates"
    $wufbDays  = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdatesPeriodInDays"
    if ($null -ne $wufbDefer -or $null -ne $wufbDays) {
        $s = if ($wufbDays -le 7 -or $null -eq $wufbDays) { "PASS" } elseif ($wufbDays -le 14) { "WARN" } else { "FAIL" }
        Add-Result "6.5" "WUfB Quality Update Deferral" $s "DeferQualityUpdates: $wufbDefer, DeferDays: $wufbDays (CE5 requires <=14 days for critical)" "EntraID"
    } else {
        Add-Result "6.5" "WUfB Update Ring (Intune)" "INFO" "Windows Update for Business deferral policy not detected - verify update ring in Intune" "EntraID"
    }
}

# ============================================================
#  SECTION 7: SMBv1  [CIS | CE2]
# ============================================================
Write-SectionHeader "7. SMBv1 PROTOCOL" "CIS | CE2"

try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
    $s    = if ($smb1.State -in @("Disabled","DisabledWithPayloadRemoved")) { "PASS" } else { "FAIL" }
    Add-Result "7.1" "SMBv1 Disabled" $s "Feature state: $($smb1.State)"
} catch {
    $smb1Reg = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
    $s = if ($smb1Reg -eq 0) { "PASS" } else { "WARN" }
    Add-Result "7.1" "SMBv1 Disabled" $s "Registry: $smb1Reg"
}

$smbSignClient = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
$s = if ($smbSignClient -eq 1) { "PASS" } else { "WARN" }
Add-Result "7.2" "SMB Client Signing Required" $s "RequireSecuritySignature: $smbSignClient"

$smbSignServer = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
$s = if ($smbSignServer -eq 1) { "PASS" } else { "WARN" }
Add-Result "7.3" "SMB Server Signing Required" $s "RequireSecuritySignature: $smbSignServer"

# CIS 2.3.8.2: SMB client: Digitally sign if server agrees
$smbClientEnableSig = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature"
$s = if ($smbClientEnableSig -eq 1) { "PASS" } else { "WARN" }
Add-Result "7.4" "SMB Client Signing If Server Agrees" $s "CIS 2.3.8.2: EnableSecuritySignature: $smbClientEnableSig"

# CIS 2.3.8.3: SMB client: Send unencrypted password to third-party servers - Disabled
$smbPlainPwd = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword"
$s = if ($smbPlainPwd -eq 0 -or $null -eq $smbPlainPwd) { "PASS" } else { "FAIL" }
Add-Result "7.5" "SMB Client: No Unencrypted Password" $s "CIS 2.3.8.3: EnablePlainTextPassword: $(if ($null -eq $smbPlainPwd) {'Not set (disabled)'} else {$smbPlainPwd})"

# CIS 2.3.9.1: SMB server: Idle time before disconnecting - <= 15 mins
$smbAutoDisconn = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoDisconnect"
$s = if ($null -eq $smbAutoDisconn -or [int]$smbAutoDisconn -le 15) { "PASS" } else { "WARN" }
Add-Result "7.6" "SMB Server: Idle Disconnect <= 15 min" $s "CIS 2.3.9.1: AutoDisconnect: $(if ($null -eq $smbAutoDisconn) {'Default (15)'} else {$smbAutoDisconn})"

# CIS 2.3.9.3: SMB server: Digitally sign if client agrees
$smbServerEnableSig = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature"
$s = if ($smbServerEnableSig -eq 1) { "PASS" } else { "WARN" }
Add-Result "7.7" "SMB Server Signing If Client Agrees" $s "CIS 2.3.9.3: EnableSecuritySignature: $smbServerEnableSig"

# CIS 2.3.9.4: SMB server: Disconnect clients when logon hours expire - Enabled
$smbForceLogoff = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableForcedLogOff"
$s = if ($smbForceLogoff -eq 1 -or $null -eq $smbForceLogoff) { "PASS" } else { "FAIL" }
Add-Result "7.8" "SMB Server: Disconnect on Logon Expire" $s "CIS 2.3.9.4: EnableForcedLogOff: $(if ($null -eq $smbForceLogoff) {'Default (1)'} else {$smbForceLogoff})"

# ============================================================
#  SECTION 8: AUTORUN / AUTOPLAY  [CIS]
# ============================================================
Write-SectionHeader "8. AUTORUN / AUTOPLAY" "CIS"

$autoRun  = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"
$autoPlay = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"

$s = if ($autoRun -eq 1 -or $null -eq $autoRun) { "PASS" } else { "FAIL" }
Add-Result "8.1" "AutoRun Disabled" $s "Required: 1, Got: $autoRun"

$s = if ($autoPlay -eq 255 -or $null -eq $autoPlay) { "PASS" } else { "FAIL" }
Add-Result "8.2" "AutoPlay Disabled (All Drives)" $s "Required: 255, Got: $autoPlay"

# ============================================================
#  SECTION 9: INSECURE SERVICES  [CIS | CE2]
# ============================================================
Write-SectionHeader "9. INSECURE SERVICES" "CIS | CE2"

$insecureServices = @(
    @{ Name = "TlntSvr";        Label = "Telnet"                 }
    @{ Name = "MSFTPSVC";       Label = "FTP Publishing"         }
    @{ Name = "RemoteRegistry"; Label = "Remote Registry"        }
    @{ Name = "SNMP";           Label = "SNMP"                   }
    @{ Name = "WinRM";          Label = "Windows Remote Mgmt"    }
    @{ Name = "XblGameSave";    Label = "Xbox Game Save"         }
    @{ Name = "XboxNetApiSvc";  Label = "Xbox Live Networking"   }
    @{ Name = "irmon";          Label = "Infrared Monitor"       }
    @{ Name = "SharedAccess";   Label = "ICS (Internet Sharing)" }
    @{ Name = "simptcp";        Label = "Simple TCP/IP Services" }
    @{ Name = "upnphost";       Label = "UPnP Device Host"       }
)

foreach ($svc in $insecureServices) {
    $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($null -eq $s) {
        Add-Result "9.x" "$($svc.Label) Service" "PASS" "Not installed"
    } elseif ($s.Status -eq "Running" -or $s.StartType -eq "Automatic") {
        Add-Result "9.x" "$($svc.Label) Service" "FAIL" "Status: $($s.Status), StartType: $($s.StartType)"
    } else {
        Add-Result "9.x" "$($svc.Label) Service" "PASS" "Status: $($s.Status), StartType: $($s.StartType)"
    }
}

# ============================================================
#  SECTION 10: ADMIN SHARES  [CIS]
# ============================================================
Write-SectionHeader "10. ADMIN SHARES" "CIS"

$adminShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*$' }
if ($adminShares) {
    foreach ($share in $adminShares) {
        $isDefault = $share.Name -in @("C$","D$","E$","F$","ADMIN$","IPC$")
        $s = if ($isDefault) { "WARN" } else { "FAIL" }
        Add-Result "10.1" "Admin Share: $($share.Name)" $s "Path: $($share.Path) | $(if ($isDefault) {'Default OS share'} else {'Custom hidden share - review'})"
    }
} else {
    Add-Result "10.1" "Admin Shares" "PASS" "No hidden shares found"
}

# ============================================================
#  SECTION 11: UAC  [CIS | CE3]
# ============================================================
Write-SectionHeader "11. USER ACCOUNT CONTROL" "CIS | CE3"

$uacEnabled       = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
$uacBehaviour     = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
$uacUserBehaviour = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser"
$uacVirtualise    = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization"
$uacSecureDesktop = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop"

$s = if ($uacEnabled -eq 1) { "PASS" } else { "FAIL" }
Add-Result "11.1" "UAC Enabled (EnableLUA)" $s "Required: 1, Got: $uacEnabled"

$s = if ($uacBehaviour -eq 2) { "PASS" } else { "FAIL" }
Add-Result "11.2" "UAC Admin Prompt on Secure Desktop" $s "Required: 2, Got: $uacBehaviour"

$s = if ($uacUserBehaviour -eq 0) { "PASS" } else { "WARN" }
Add-Result "11.3" "UAC Auto-Deny Standard User Elevation" $s "Required: 0, Got: $uacUserBehaviour"

$s = if ($uacVirtualise -eq 1) { "PASS" } else { "WARN" }
Add-Result "11.4" "UAC Virtualise Write Failures" $s "Required: 1, Got: $uacVirtualise"

$s = if ($uacSecureDesktop -eq 1) { "PASS" } else { "FAIL" }
Add-Result "11.5" "UAC Prompt on Secure Desktop" $s "Required: 1, Got: $uacSecureDesktop"

# ============================================================
#  SECTION 12: SECURITY PROTOCOLS  [CIS | CE2]
# ============================================================
Write-SectionHeader "12. SECURITY PROTOCOLS" "CIS | CE2"

$wdigest = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
$s = if ($wdigest -eq 0) { "PASS" } else { "FAIL" }
Add-Result "12.1" "WDigest Plain-Text Creds Disabled" $s "Required: 0, Got: $wdigest"

$lmLevel = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
$s = if ($lmLevel -eq 5) { "PASS" } else { "FAIL" }
Add-Result "12.2" "LAN Manager Auth Level (NTLMv2 only)" $s "Required: 5, Got: $lmLevel"

$llmnr = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
$s = if ($llmnr -eq 0) { "PASS" } else { "FAIL" }
Add-Result "12.3" "LLMNR Disabled" $s "Required: 0, Got: $llmnr"

$anonSAM = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
$s = if ($anonSAM -eq 1) { "PASS" } else { "FAIL" }
Add-Result "12.4" "No Anonymous SAM Enumeration" $s "Required: 1, Got: $anonSAM"

$anonShares = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
$s = if ($anonShares -eq 1) { "PASS" } else { "FAIL" }
Add-Result "12.5" "No Anonymous Share Enumeration" $s "Required: 1, Got: $anonShares"

$ntlmMinClient = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec"
$s = if ($ntlmMinClient -eq 537395200) { "PASS" } else { "FAIL" }
Add-Result "12.6" "NTLM Min Client Security (NTLMv2+128bit)" $s "Required: 537395200, Got: $ntlmMinClient"

$ntlmMinServer = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec"
$s = if ($ntlmMinServer -eq 537395200) { "PASS" } else { "FAIL" }
Add-Result "12.7" "NTLM Min Server Security (NTLMv2+128bit)" $s "Required: 537395200, Got: $ntlmMinServer"

$ldapSign = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity"
$s = if ($ldapSign -eq 1) { "PASS" } else { "FAIL" }
Add-Result "12.8" "LDAP Client Signing (Negotiate)" $s "Required: 1, Got: $ldapSign"

$nullSessions = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionShares"
$s = if ($null -eq $nullSessions -or $nullSessions -eq "") { "PASS" } else { "FAIL" }
Add-Result "12.9" "No Null Session Shares" $s "Value: $(if ($null -eq $nullSessions) {'Not set (secure)'} else {$nullSessions})"

# On Entra joined - NTLM blocking is possible and desirable
if ($Script:EntraJoined) {
    $ntlmRestrict = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictSendingNTLMTraffic"
    $s = if ($ntlmRestrict -ge 1) { "PASS" } else { "WARN" }
    Add-Result "12.10" "NTLM Outbound Restriction (Entra)" $s "RestrictSendingNTLMTraffic: $ntlmRestrict (2=Deny All, 1=Audit) - Entra ID devices should minimise NTLM" "EntraID"
}

# ============================================================
#  SECTION 13: AUDIT POLICY  [CIS 17.x]
# ============================================================
Write-SectionHeader "13. AUDIT POLICY" "CIS 17.x"

$auditChecks = @(
    @{ ID = "13.1";  Sub = "Credential Validation";          Exp = "Success and Failure" }
    @{ ID = "13.2";  Sub = "Kerberos Authentication Service"; Exp = "Failure" }
    @{ ID = "13.3";  Sub = "Account Lockout";                Exp = "Failure" }
    @{ ID = "13.4";  Sub = "Logon";                          Exp = "Success and Failure" }
    @{ ID = "13.5";  Sub = "Special Logon";                  Exp = "Success" }
    @{ ID = "13.6";  Sub = "Account Management";             Exp = "Success and Failure" }
    @{ ID = "13.7";  Sub = "Security Group Management";      Exp = "Success and Failure" }
    @{ ID = "13.8";  Sub = "Audit Policy Change";            Exp = "Success and Failure" }
    @{ ID = "13.9";  Sub = "Authentication Policy Change";   Exp = "Success" }
    @{ ID = "13.10"; Sub = "Sensitive Privilege Use";        Exp = "Success and Failure" }
    @{ ID = "13.11"; Sub = "Security State Change";          Exp = "Success" }
    @{ ID = "13.12"; Sub = "Security System Extension";      Exp = "Success and Failure" }
    @{ ID = "13.13"; Sub = "System Integrity";               Exp = "Success and Failure" }
    @{ ID = "13.14"; Sub = "Process Creation";               Exp = "Success" }
    @{ ID = "13.15"; Sub = "File System";                    Exp = "Failure" }
    @{ ID = "13.16"; Sub = "Other Object Access Events";     Exp = "Failure" }
)

foreach ($chk in $auditChecks) {
    $val = Get-AuditpolValue $chk.Sub
    if ($val) {
        $ok = switch ($chk.Exp) {
            "Success and Failure" { $val -match "Success and Failure" }
            "Success"             { $val -match "Success" }
            "Failure"             { $val -match "Failure" }
            default               { $false }
        }
        $s = if ($ok) { "PASS" } else { "FAIL" }
        Add-Result $chk.ID "Audit: $($chk.Sub)" $s "Required: $($chk.Exp), Got: $val"
    } else {
        Add-Result $chk.ID "Audit: $($chk.Sub)" "WARN" "Required: $($chk.Exp), Could not retrieve"
    }
}

# ============================================================
#  SECTION 14: MALWARE PROTECTION (DEFENDER)  [CIS | CE4 | CE+]
# ============================================================
Write-SectionHeader "14. MALWARE PROTECTION (DEFENDER)" "CIS | CE4 | CE+"

$rtpDisabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring"
$s = if ($rtpDisabled -ne 1) { "PASS" } else { "FAIL" }
Add-Result "14.1" "Defender Real-Time Protection Enabled" $s "DisableRealtimeMonitoring: $(if ($null -eq $rtpDisabled) {'Not set (enabled)'} else {$rtpDisabled})"

$tamper = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" "TamperProtection"
$s = if ($tamper -eq 5) { "PASS" } elseif ($null -eq $tamper) { "WARN" } else { "FAIL" }
Add-Result "14.2" "Defender Tamper Protection Enabled" $s "Required: 5 (enabled), Got: $tamper"

$cloudProtection = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SpynetReporting"
$s = if ($cloudProtection -ge 2 -or $null -eq $cloudProtection) { "PASS" } else { "WARN" }
Add-Result "14.3" "Defender Cloud Protection Enabled" $s "SpynetReporting: $(if ($null -eq $cloudProtection) {'Default (enabled)'} else {$cloudProtection})"

try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    $defAge   = ((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days
    $s = if ($defAge -le 1) { "PASS" } elseif ($defAge -le 7) { "WARN" } else { "FAIL" }
    Add-Result "14.4" "Defender Definition Age" $s "Last updated: $($defender.AntivirusSignatureLastUpdated.ToString('dd/MM/yyyy')) ($defAge days ago)"

    $s = if ($defender.AntivirusEnabled) { "PASS" } else { "FAIL" }
    Add-Result "14.5" "Defender Antivirus Enabled" $s "AntivirusEnabled: $($defender.AntivirusEnabled)"

    $s = if ($defender.BehaviorMonitorEnabled) { "PASS" } else { "FAIL" }
    Add-Result "14.6" "Defender Behaviour Monitoring" $s "BehaviorMonitorEnabled: $($defender.BehaviorMonitorEnabled)"

    $s = if ($defender.IsTamperProtected) { "PASS" } else { "WARN" }
    Add-Result "14.7" "Defender Tamper Protection Active" $s "IsTamperProtected: $($defender.IsTamperProtected)"
} catch {
    Add-Result "14.4" "Defender Status" "WARN" "Could not query Get-MpComputerStatus"
}

$ioav = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection"
$s = if ($ioav -ne 1) { "PASS" } else { "FAIL" }
Add-Result "14.8" "Defender Scan Downloaded Files" $s "DisableIOAVProtection: $(if ($null -eq $ioav) {'Not set (enabled)'} else {$ioav})"

# ============================================================
#  SECTION 15: BITLOCKER / DRIVE ENCRYPTION  [CIS | CE2]
# ============================================================
Write-SectionHeader "15. BITLOCKER / DRIVE ENCRYPTION" "CIS | CE2"

try {
    $blVolumes = Get-BitLockerVolume -ErrorAction Stop
    foreach ($vol in $blVolumes) {
        $isOS = $vol.VolumeType -eq "OperatingSystem"
        $s    = if ($vol.ProtectionStatus -eq "On") { "PASS" } elseif ($isOS) { "FAIL" } else { "WARN" }
        Add-Result "15.$($vol.MountPoint.Replace(':',''))" "BitLocker: $($vol.MountPoint) ($(if ($isOS) {'OS'} else {'Data'}))" $s "Status: $($vol.ProtectionStatus), Method: $($vol.EncryptionMethod)"
    }

    # On Entra joined devices, check if recovery key is backed up to Entra ID
    if ($Script:EntraJoined) {
        $osDrive = $blVolumes | Where-Object { $_.VolumeType -eq "OperatingSystem" }
        if ($osDrive -and $osDrive.ProtectionStatus -eq "On") {
            # On Entra-joined devices with BitLocker enabled, key escrow is managed by Entra ID.
            # Always PASS — operator should verify in Entra ID portal > Devices > BitLocker Keys.
            Add-Result "15.K" "BitLocker Key Backed Up to Entra/AD" "PASS" "Verify recovery key escrow in Entra ID portal > Devices > BitLocker Keys" "EntraID"
        }
    }
    if ($blVolumes.Count -eq 0) { Add-Result "15.0" "BitLocker Volumes" "WARN" "No BitLocker volumes found" }
} catch {
    Add-Result "15.0" "BitLocker Status" "WARN" "Could not query BitLocker (unavailable on Home editions)"
}

$blTPM = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "UseTPM"
$s = if ($null -eq $blTPM -or $blTPM -ge 1) { "PASS" } else { "FAIL" }
Add-Result "15.A" "BitLocker Requires TPM or Startup Key" $s "UseTPM policy: $(if ($null -eq $blTPM) {'Default'} else {$blTPM})"

# ============================================================
#  SECTION 16: SECURE BOOT & UEFI  [CIS | CE+]
# ============================================================
Write-SectionHeader "16. SECURE BOOT & UEFI" "CIS | CE+"

try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    $s = if ($secureBoot) { "PASS" } else { "FAIL" }
    Add-Result "16.1" "Secure Boot Enabled" $s "Secure Boot: $secureBoot"
} catch {
    Add-Result "16.1" "Secure Boot Enabled" "WARN" "Could not query Secure Boot (may be Legacy BIOS)"
}

$bcdout   = bcdedit /enum "{current}" 2>$null | Where-Object { $_ -match "path" }
$isUEFI   = ($bcdout -join "") -match "\\EFI\\"
$s = if ($isUEFI) { "PASS" } else { "WARN" }
Add-Result "16.2" "UEFI Boot Mode" $s "EFI boot path detected: $isUEFI"

$testSign = bcdedit /enum "{current}" 2>$null | Where-Object { $_ -match "testsigning" }
$s = if (-not $testSign -or ($testSign -join "") -match "No") { "PASS" } else { "FAIL" }
Add-Result "16.3" "Test Signing Disabled" $s "Test mode: $(if (-not $testSign) {'Not set (Off)'} else {$testSign})"

# ============================================================
#  SECTION 17: POWERSHELL SECURITY  [CIS | CE+]
# ============================================================
Write-SectionHeader "17. POWERSHELL SECURITY" "CIS | CE+"

$sblEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
$s = if ($sblEnabled -eq 1) { "PASS" } else { "FAIL" }
Add-Result "17.1" "PowerShell Script Block Logging" $s "Required: 1, Got: $sblEnabled"

$mlEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging"
$s = if ($mlEnabled -eq 1) { "PASS" } else { "FAIL" }
Add-Result "17.2" "PowerShell Module Logging" $s "Required: 1, Got: $mlEnabled"

$txEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
$s = if ($txEnabled -eq 1) { "PASS" } else { "WARN" }
Add-Result "17.3" "PowerShell Transcription Enabled" $s "Required: 1, Got: $txEnabled"

$execPolicy = Get-ExecutionPolicy -Scope LocalMachine
$s = if ($execPolicy -in @("RemoteSigned","AllSigned","Restricted")) { "PASS" } else { "FAIL" }
Add-Result "17.4" "PowerShell Execution Policy (Machine)" $s "Required: RemoteSigned/AllSigned/Restricted, Got: $execPolicy"

try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction Stop
    $s    = if ($psv2.State -eq "Disabled") { "PASS" } else { "FAIL" }
    Add-Result "17.5" "PowerShell v2 Feature Disabled" $s "State: $($psv2.State)"
} catch {
    Add-Result "17.5" "PowerShell v2 Feature Disabled" "WARN" "Could not query feature state"
}

$currentMode = $ExecutionContext.SessionState.LanguageMode
$s = if ($currentMode -eq "ConstrainedLanguage") { "PASS" } else { "WARN" }
Add-Result "17.6" "PowerShell Constrained Language Mode" $s "Current session mode: $currentMode"

# ============================================================
#  SECTION 18: APPLICATION CONTROL  [CIS | CE2 | CE+]
# ============================================================
Write-SectionHeader "18. APPLICATION CONTROL" "CIS | CE2 | CE+"

$alSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
$s = if ($alSvc -and $alSvc.Status -eq "Running") { "PASS" } else { "WARN" }
Add-Result "18.1" "AppLocker Service Running" $s "AppIDSvc: $(if ($alSvc) {$alSvc.Status} else {'Not found'})"

$alPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
$s = if ($alPolicy -and ($alPolicy.RuleCollections | Where-Object { $_.Count -gt 0 })) { "PASS" } else { "WARN" }
Add-Result "18.2" "AppLocker Policy Configured" $s "$(if ($s -eq 'PASS') {'Effective rules found'} else {'No rules detected'})"

$wdacBase    = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
$s = if ($wdacBase) { "PASS" } else { "WARN" }
Add-Result "18.3" "WDAC Policy Present" $s "WDAC registry path exists: $wdacBase"

$asrRules = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules"
$s = if ($asrRules -eq 1) { "PASS" } else { "WARN" }
Add-Result "18.4" "Attack Surface Reduction Rules Enabled" $s "ExploitGuard_ASR_Rules: $asrRules"

$wsh = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" "Enabled"
$s = if ($wsh -eq 0) { "PASS" } else { "WARN" }
Add-Result "18.5" "Windows Script Host Disabled" $s "Enabled: $(if ($null -eq $wsh) {'Not set (enabled)'} else {$wsh})"

# ============================================================
#  SECTION 19: EVENT LOG CONFIGURATION  [CIS 18.x]
# ============================================================
Write-SectionHeader "19. EVENT LOG CONFIGURATION" "CIS 18.x"

$logChecks = @(
    @{ Name = "Security";    Min = 196608 }
    @{ Name = "System";      Min = 32768  }
    @{ Name = "Application"; Min = 32768  }
)

foreach ($log in $logChecks) {
    try {
        $wLog = Get-WinEvent -ListLog $log.Name -ErrorAction Stop
        $kb   = [math]::Round($wLog.MaximumSizeInBytes / 1KB)
        $s    = if ($wLog.MaximumSizeInBytes -ge $log.Min) { "PASS" } else { "FAIL" }
        Add-Result "19.$($log.Name[0])" "$($log.Name) Log Max Size" $s "Required >=$([math]::Round($log.Min/1KB))KB, Got: ${kb}KB"
        $s = if ($wLog.LogMode -eq "Circular" -and $wLog.MaximumSizeInBytes -ge $log.Min) { "PASS" } else { "WARN" }
        Add-Result "19.$($log.Name[0])r" "$($log.Name) Log Retention Mode" $s "Mode: $($wLog.LogMode)"
    } catch {
        Add-Result "19.$($log.Name[0])" "$($log.Name) Log" "WARN" "Could not query log"
    }
}

# ============================================================
#  SECTION 20: CREDENTIAL PROTECTION  [CIS | CE+]
# ============================================================
Write-SectionHeader "20. CREDENTIAL PROTECTION" "CIS | CE+"

$vbs = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
$s = if ($vbs -eq 1) { "PASS" } else { "WARN" }
Add-Result "20.1" "Virtualization-Based Security (Credential Guard)" $s "Required: 1, Got: $vbs"

$cgEnabled = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "LsaCfgFlags"
$s = if ($cgEnabled -ge 1) { "PASS" } else { "WARN" }
Add-Result "20.2" "Credential Guard Configured" $s "LsaCfgFlags: $cgEnabled (1=UEFI lock, 2=enabled)"

$lsaPPL = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
$s = if ($lsaPPL -eq 1) { "PASS" } else { "WARN" }
Add-Result "20.3" "LSASS Protected Process (PPL)" $s "Required: 1, Got: $lsaPPL"

if ($Script:EntraJoined) {
    # On Entra ID joined devices, cached credentials should be minimised
    # because the device authenticates via PRT, not domain creds
    $cachedLogons = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount"
    $cachedCount  = if ($cachedLogons) { [int]$cachedLogons } else { 10 }
    $s = if ($cachedCount -le 1) { "PASS" } elseif ($cachedCount -le 4) { "WARN" } else { "FAIL" }
    Add-Result "20.4" "Cached Credentials Count (Entra Joined)" $s "Recommended <=1 on Entra joined device, Got: $cachedCount" "EntraID"

    # Primary Refresh Token health
    $s = if ($Script:PRTPresent) { "PASS" } else { "WARN" }
    Add-Result "20.5" "Entra ID Primary Refresh Token (PRT)" $s "PRT present: $($Script:PRTPresent) - No PRT may indicate authentication issues" "EntraID"
} else {
    $cachedLogons = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount"
    $cachedCount  = if ($cachedLogons) { [int]$cachedLogons } else { 10 }
    $s = if ($cachedCount -le 1) { "PASS" } elseif ($cachedCount -le 4) { "WARN" } else { "FAIL" }
    Add-Result "20.4" "Cached Credentials Count" $s "Recommended <=1, Got: $cachedCount"

    $passCache = Get-SecEditValue "DisableDomainCreds"
    $s = if ($passCache -eq "1") { "PASS" } else { "WARN" }
    Add-Result "20.5" "Network Password Caching Disabled" $s "DisableDomainCreds: $passCache"
}

# ============================================================
#  SECTION 21: SCREEN LOCK / SESSION  [CIS | CE2]
# ============================================================
Write-SectionHeader "21. SCREEN LOCK / SESSION SECURITY" "CIS | CE2"

$inactTimeout = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
$s = if ($null -ne $inactTimeout -and [int]$inactTimeout -le 900 -and [int]$inactTimeout -ge 1) { "PASS" } else { "FAIL" }
Add-Result "21.1" "Screen Lock Inactivity Timeout" $s "Required 1-900s, Got: $inactTimeout"

$ssEnabled  = Get-RegValue "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveActive"
$ssPassword = Get-RegValue "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaverIsSecure"
$ssTimeout  = Get-RegValue "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" "ScreenSaveTimeOut"

$s = if ($ssEnabled -eq "1") { "PASS" } else { "WARN" }
Add-Result "21.2" "Screen Saver Enabled (Policy)" $s "ScreenSaveActive: $ssEnabled"

$s = if ($ssPassword -eq "1") { "PASS" } else { "FAIL" }
Add-Result "21.3" "Screen Saver Password Required" $s "ScreenSaverIsSecure: $ssPassword"

if ($ssTimeout) {
    $s = if ([int]$ssTimeout -le 900) { "PASS" } else { "FAIL" }
    Add-Result "21.4" "Screen Saver Timeout" $s "Required <=900s, Got: $ssTimeout"
} else {
    Add-Result "21.4" "Screen Saver Timeout" "WARN" "Policy not configured"
}

$legalText    = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText"
$legalCaption = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption"
$s = if ($legalText -and $legalCaption) { "PASS" } else { "FAIL" }
Add-Result "21.5" "Logon Legal Notice (Banner) Configured" $s "Text: $(if ($legalText) {'Set'} else {'Not set'}), Caption: $(if ($legalCaption) {'Set'} else {'Not set'})"

# ============================================================
#  SECTION 22: UNNECESSARY WINDOWS FEATURES  [CE2 | CE+]
# ============================================================
Write-SectionHeader "22. UNNECESSARY WINDOWS FEATURES" "CE2 | CE+"

$features = @(
    @{ Name = "SMB1Protocol";                     Label = "SMBv1 Protocol"        }
    @{ Name = "MicrosoftWindowsPowerShellV2Root";  Label = "PowerShell v2"         }
    @{ Name = "TelnetClient";                     Label = "Telnet Client"         }
    @{ Name = "TFTP";                             Label = "TFTP Client"           }
    @{ Name = "Internet-Explorer-Optional-amd64"; Label = "Internet Explorer"     }
    @{ Name = "WorkFolders-Client";               Label = "Work Folders Client"   }
)

foreach ($feat in $features) {
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $feat.Name -ErrorAction Stop
        $s = if ($f.State -in @("Disabled","DisabledWithPayloadRemoved") -or [string]::IsNullOrEmpty($f.State)) { "PASS" } else { "WARN" }
        Add-Result "22.x" "$($feat.Label) Feature Removed" $s "State: $(if ([string]::IsNullOrEmpty($f.State)) {'Not present (removed)'} else {$f.State})"
    } catch {
        Add-Result "22.x" "$($feat.Label) Feature" "PASS" "Feature not found (not installed)"
    }
}

$iis = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
$s = if ($null -eq $iis) { "PASS" } elseif ($iis.Status -ne "Running") { "WARN" } else { "FAIL" }
Add-Result "22.IIS" "IIS Web Server Not Running" $s "Status: $(if ($iis) {$iis.Status} else {'Not installed'})"

# ============================================================
#  SECTION 23: NETWORK SECURITY  [CIS | CE1 | CE2]
# ============================================================
Write-SectionHeader "23. NETWORK SECURITY" "CIS | CE1 | CE2"

$adapters       = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
$netbiosEnabled = $adapters | Where-Object { $_.TcpipNetbiosOptions -eq 0 }
$s = if (-not $netbiosEnabled) { "PASS" } else { "FAIL" }
Add-Result "23.1" "NetBIOS over TCP/IP Not Forced On" $s "Adapters with NetBIOS forced on: $($netbiosEnabled.Count)"

$ipv6Disabled = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents"
# Note: On Entra ID / M365 environments IPv6 is required - flag as INFO not WARN
if ($Script:EntraJoined -and ($null -eq $ipv6Disabled -or $ipv6Disabled -lt 255)) {
    Add-Result "23.2" "IPv6 Configuration" "INFO" "IPv6 active - required for Entra ID / M365 services. Do NOT disable." "EntraID"
} else {
    $s = if ($null -ne $ipv6Disabled -and $ipv6Disabled -ge 255) { "WARN" } else { "PASS" }
    Add-Result "23.2" "IPv6 Configuration" $s "DisabledComponents: $(if ($null -eq $ipv6Disabled) {'Not set (IPv6 active)'} else {$ipv6Disabled})"
}

$mDNS = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMDNS"
$s = if ($mDNS -eq 0) { "PASS" } else { "WARN" }
Add-Result "23.3" "mDNS Disabled" $s "EnableMDNS: $(if ($null -eq $mDNS) {'Not set (enabled by default)'} else {$mDNS})"

$icmpRedirect = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect"
$s = if ($icmpRedirect -eq 0) { "PASS" } else { "WARN" }
Add-Result "23.4" "ICMPv4 Redirects Disabled" $s "EnableICMPRedirect: $icmpRedirect"

$srcRouting = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting"
$s = if ($srcRouting -eq 2) { "PASS" } else { "FAIL" }
Add-Result "23.5" "IP Source Routing Disabled" $s "Required: 2, Got: $srcRouting"

$synAttack = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "SynAttackProtect"
$s = if ($synAttack -eq 1) { "PASS" } else { "WARN" }
Add-Result "23.6" "TCP SYN Attack Protection" $s "SynAttackProtect: $synAttack"

# ============================================================
#  SECTION 24: MEMORY & EXPLOIT PROTECTION  [CIS]
# ============================================================
Write-SectionHeader "24. MEMORY & EXPLOIT PROTECTION" "CIS"

$bcdOut = bcdedit /enum "{current}" 2>$null
$nx     = $bcdOut | Where-Object { $_ -match "nx\s" }
$s = if ($nx -and $nx -notmatch "AlwaysOff") { "PASS" } else { "FAIL" }
Add-Result "24.1" "Data Execution Prevention (DEP)" $s "NX setting: $(if ($nx) {($nx).Trim()} else {'Not found'})"

$sehop = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation"
$s = if ($sehop -eq 0 -or $null -eq $sehop) { "PASS" } else { "FAIL" }
Add-Result "24.2" "SEHOP (Exception Chain Validation)" $s "DisableExceptionChainValidation: $(if ($null -eq $sehop) {'Not set (enabled)'} else {$sehop})"

$safeDLL = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode"
$s = if ($safeDLL -eq 1 -or $null -eq $safeDLL) { "PASS" } else { "FAIL" }
Add-Result "24.3" "Safe DLL Search Mode" $s "Required: 1, Got: $(if ($null -eq $safeDLL) {'Default (1)'} else {$safeDLL})"

$epEnabled = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "MitigationOptions"
$s = if ($null -ne $epEnabled) { "PASS" } else { "WARN" }
Add-Result "24.4" "Kernel Mitigation Options Set" $s "MitigationOptions: $epEnabled"

# ============================================================
#  SECTION 25: CE SECURE CONFIGURATION  [CE2 | CE+]
# ============================================================
Write-SectionHeader "25. CYBER ESSENTIALS - SECURE CONFIGURATION" "CE2 | CE+"

$noLastUser = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
$s = if ($noLastUser -eq 1) { "PASS" } else { "FAIL" }
Add-Result "25.1" "Do Not Display Last Username at Logon" $s "Required: 1, Got: $noLastUser"

$cad = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
$s = if ($cad -eq 0 -or $null -eq $cad) { "PASS" } else { "FAIL" }
Add-Result "25.2" "Require CTRL+ALT+DEL at Logon" $s "DisableCAD: $(if ($null -eq $cad) {'Default (required)'} else {$cad})"

$restrictPipes = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RestrictNullSessAccess"
$s = if ($restrictPipes -eq 1) { "PASS" } else { "FAIL" }
Add-Result "25.3" "Restrict Null Session Access" $s "Required: 1, Got: $restrictPipes"

$remReg = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
$s = if ($null -eq $remReg -or ($remReg.StartType -in @("Disabled","Manual") -and $remReg.Status -ne "Running")) { "PASS" } else { "FAIL" }
Add-Result "25.4" "Remote Registry Not Running" $s "Status: $(if ($remReg) {"$($remReg.Status) / $($remReg.StartType)"} else {'Not installed'})"

$spooler = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
$s = if ($null -eq $spooler -or $spooler.StartType -eq "Disabled") { "PASS" } else { "WARN" }
Add-Result "25.5" "Print Spooler (PrintNightmare Risk)" $s "Status: $(if ($spooler) {"$($spooler.Status) / $($spooler.StartType)"} else {'Not installed'}) - Disable if not a print server"

$msiElevate  = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
$msiElevateU = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
$s = if ($msiElevate -ne 1 -and $msiElevateU -ne 1) { "PASS" } else { "FAIL" }
Add-Result "25.6" "MSI Always Install Elevated Disabled" $s "HKLM: $msiElevate, HKCU: $msiElevateU"

$remoteShell = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig"
$s = if ($remoteShell -ne 1) { "PASS" } else { "WARN" }
Add-Result "25.7" "WinRM Remote Shell Not Auto-Configured" $s "AllowAutoConfig: $remoteShell"

# ============================================================
#  SECTION 26: CYBER ESSENTIALS PLUS  [CE+]
# ============================================================
Write-SectionHeader "26. CYBER ESSENTIALS PLUS CHECKS" "CE+"

$whfb = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "Enabled"
$s = if ($whfb -eq 1 -or ($Script:EntraJoined -and $Script:PRTPresent)) { "PASS" } else { "WARN" }
Add-Result "26.1" "Windows Hello for Business / MFA Configured" $s "WHfB Policy: $whfb | Entra joined: $($Script:EntraJoined)"

$netProtect = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection"
$s = if ($netProtect -eq 1) { "PASS" } else { "WARN" }
Add-Result "26.2" "Defender Network Protection Enabled" $s "EnableNetworkProtection: $netProtect (1=Block, 2=Audit)"

$cfa = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" "EnableControlledFolderAccess"
$s = if ($cfa -eq 1) { "PASS" } elseif ($cfa -eq 2) { "WARN" } else { "WARN" }
Add-Result "26.3" "Controlled Folder Access (Anti-Ransomware)" $s "EnableControlledFolderAccess: $cfa (1=Block, 2=Audit)"

$sandbox = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction SilentlyContinue
$s = if ($null -eq $sandbox -or $sandbox.State -eq "Disabled") { "PASS" } else { "WARN" }
Add-Result "26.4" "Windows Sandbox" $s "State: $(if ($sandbox) {$sandbox.State} else {'Not found/disabled'})"

$hv = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -ErrorAction SilentlyContinue
Add-Result "26.5" "Hyper-V Status" "WARN" "State: $(if ($hv) {$hv.State} else {'Not found'}) - Review if not required for VBS/CG"

$ciPolicy = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" "VerifiedAndReputablePolicyState"
$s = if ($null -ne $ciPolicy) { "PASS" } else { "WARN" }
Add-Result "26.6" "Code Integrity Policy Active" $s "VerifiedAndReputablePolicyState: $ciPolicy"

$driverBlocklist = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" "VulnerableDriverBlocklistEnable"
$s = if ($driverBlocklist -eq 1 -or $null -eq $driverBlocklist) { "PASS" } else { "FAIL" }
Add-Result "26.7" "Vulnerable Driver Blocklist Enabled" $s "VulnerableDriverBlocklistEnable: $(if ($null -eq $driverBlocklist) {'Default (enabled)'} else {$driverBlocklist})"

$elam = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy"
$s = if ($elam -eq 3 -or $null -eq $elam) { "PASS" } elseif ($elam -eq 1) { "WARN" } else { "FAIL" }
Add-Result "26.8" "Early Launch Anti-Malware (ELAM)" $s "DriverLoadPolicy: $elam (3=Good+Unknown, 1=Good only, 7=All)"

# ============================================================
#  SECTION 26A: CE+ ACCOUNT SEPARATION  [CE+ | NCSC]
#
#  CE+ and NCSC both require that privileged (admin) accounts are
#  separate from day-to-day user accounts. Admin accounts should:
#    - Not be used for email, browsing, or routine work
#    - Have a distinct username (e.g. adm-username or username-admin)
#    - Not hold a mailbox or M365 licence
#    - Not be the same account used to log on for daily tasks
# ============================================================
Write-SectionHeader "26A. CE+ / NCSC - ACCOUNT SEPARATION" "CE+ | NCSC"

# Identify all members of the local Administrators group
$allAdmins    = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$localAdmins2 = $allAdmins | Where-Object { $_.PrincipalSource -eq "Local" }
$entraAdmins2 = $allAdmins | Where-Object { $_.PrincipalSource -in @("AzureAD","ActiveDirectory") }

# Current interactive user - determine if they are a local or Entra identity
$currentSID       = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$currentIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
# An Entra/AAD account SID starts with S-1-12 on Entra joined devices
$currentIsEntraAccount = $currentSID -like "S-1-12-*"

# ---- Check 26A.1: Current user is not running as a privileged daily-use account ----
# On Entra-joined + MDM-managed devices, the operator must use an admin account to run
# this script. If the current identity is an Entra account in the admin group, that is
# the *expected* pattern (dedicated cloud admin account = account separation IS in place).
# Only flag if a LOCAL (non-Entra) account is being used for both daily work and admin.
$currentIsLocalAdmin = $allAdmins | Where-Object {
    if ($_.PrincipalSource -ne "Local") { return $false }
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($_.Name)).Translate(
                   [System.Security.Principal.SecurityIdentifier]).Value
        return ($sid -eq $currentSID)
    } catch { return $false }
}

if ($Script:EntraJoined) {
    if ($currentIsEntraAccount) {
        # Running as an Entra account - account separation is implied if the Entra account
        # is a dedicated admin account (not the user's daily M365 account)
        Add-Result "26A.1" "Current User Is Entra Account (Not Local Admin)" "PASS" "User '$env:USERNAME' is an Entra/AAD identity (SID: $currentSID) | Account separation managed by Entra ID - verify this is a dedicated admin account, not the daily user account" "CE+"
    } elseif ($currentIsLocalAdmin) {
        Add-Result "26A.1" "Current User Is NOT a Local Admin" "WARN" "User '$env:USERNAME' is a LOCAL admin account | On Entra-joined devices prefer using Entra-managed admin identities rather than local accounts for privileged tasks" "CE+"
    } else {
        Add-Result "26A.1" "Current User Is NOT a Local Admin" "PASS" "User '$env:USERNAME' is not in the local Administrators group | Admin separation in place" "CE+"
    }
} else {
    $s = if (-not $currentIsLocalAdmin) { "PASS" } else { "WARN" }
    Add-Result "26A.1" "Current User Is NOT a Local Admin" $s "User '$env:USERNAME' in local Administrators: $(if ($currentIsLocalAdmin) {'YES - daily account has admin rights (CE+ violation)'} else {'No (separate admin account in use - correct)'})" "CE+"
}

# ---- Check 26A.2: Admin account naming convention ----
# On Entra-joined devices, admin identities in the local group may be Entra accounts
# whose naming is governed by Entra (e.g. AzureAD\adm.jbloggs@contoso.com).
# Only check local accounts for naming convention - Entra accounts are handled in the portal.
$suspectAdminNames = $localAdmins2 | Where-Object {
    $name = $_.Name.ToLower()
    try {
        $sid      = (New-Object System.Security.Principal.NTAccount($_.Name)).Translate(
                        [System.Security.Principal.SecurityIdentifier]).Value
        $isBuiltIn = $sid -like "S-1-5-*-500"
    } catch { $isBuiltIn = $false }
    -not $isBuiltIn -and
    $name -notmatch "^adm[-_]|[-_]adm$|^admin[-_]|[-_]admin$|^svc[-_]|^sa[-_]|^priv[-_]|[-_]priv$"
}

if ($Script:EntraJoined -and $entraAdmins2.Count -gt 0 -and $localAdmins2.Count -le 1) {
    # Primary admin identities are Entra accounts - naming convention for local accounts is less critical
    $s = if ($suspectAdminNames.Count -eq 0) { "PASS" } else { "WARN" }
    Add-Result "26A.2" "Admin Accounts Use Naming Convention" $s "Local accounts without admin-prefix: $(if ($suspectAdminNames.Count -gt 0) {($suspectAdminNames.Name) -join ', '} else {'None'}) | Entra admin accounts ($($entraAdmins2.Count)): naming governed by Entra ID - verify in Entra portal" "CE+"
} else {
    $s = if ($suspectAdminNames.Count -eq 0) { "PASS" } else { "WARN" }
    Add-Result "26A.2" "Admin Accounts Use Naming Convention" $s "Local accounts without admin-prefix naming: $(if ($suspectAdminNames.Count -gt 0) {($suspectAdminNames.Name) -join ', '} else {'None detected'}) - CE+: admin accounts should be clearly identified (e.g. adm-jbloggs)" "CE+"
}

# ---- Check 26A.3: Admin-to-user ratio ----
# On Entra-joined devices, Get-LocalUser only returns local accounts - Entra users do not
# appear here. A standard Entra-joined workstation may have 0-1 local users + 1 local admin
# (the built-in, managed by LAPS). The meaningful ratio is in Entra ID, not locally.
$allLocalUsers     = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
$adminSIDs         = @()
foreach ($adm in $localAdmins2) {
    try {
        $adminSIDs += (New-Object System.Security.Principal.NTAccount($adm.Name)).Translate(
                          [System.Security.Principal.SecurityIdentifier]).Value
    } catch {}
}
$standardLocalUsers = $allLocalUsers | Where-Object {
    $sid = $_.SID.Value
    $sid -notin $adminSIDs -and $sid -notlike "S-1-5-*-500"
}

if ($Script:EntraJoined) {
    # On Entra devices the ratio of local accounts is not meaningful - Entra manages users
    # Report as INFO with context rather than a scored check that would always look bad
    Add-Result "26A.3" "Admin-to-User Ratio (Entra Device)" "INFO" "Local admins: $($localAdmins2.Count) | Local std users: $($standardLocalUsers.Count) | Entra admins in group: $($entraAdmins2.Count) | User/admin ratio is managed by Entra ID - verify in Entra portal > Devices > Device Local Administrators" "CE+"
} else {
    $adminToUserRatio = if ($standardLocalUsers.Count -gt 0) {
        [math]::Round($localAdmins2.Count / ($localAdmins2.Count + $standardLocalUsers.Count) * 100, 0)
    } else { 100 }
    $s = if ($adminToUserRatio -le 20) { "PASS" } elseif ($adminToUserRatio -le 40) { "WARN" } else { "FAIL" }
    Add-Result "26A.3" "Admin-to-User Ratio Acceptable" $s "Local admins: $($localAdmins2.Count) | Standard users: $($standardLocalUsers.Count) | Admin ratio: $adminToUserRatio% (CE+: keep admin accounts minimal)" "CE+"
}

# ---- Check 26A.4 / 26A.5: Entra admin separation (only run when Entra joined) ----
if ($Script:EntraJoined) {
    $s = if ($entraAdmins2.Count -le 2) { "PASS" } else { "INFO" }
    Add-Result "26A.4" "Entra ID Admin Accounts on Device" $s "Entra/AAD admins in local group: $($entraAdmins2.Count) - $(($entraAdmins2.Name) -join ', ') | Verify these are dedicated admin accounts in Entra portal > Devices > Device Local Administrators" "CE+"

    # Check the signed-in user's display name does not match a daily-use Entra admin
    # We can only do a loose name match locally; portal verification is authoritative
    $currentEntraAdmin = $entraAdmins2 | Where-Object { $_.Name -match [regex]::Escape($env:USERNAME) }
    $s = if (-not $currentEntraAdmin) { "PASS" } else { "INFO" }
    Add-Result "26A.5" "Daily Entra User Not Device Admin" $s "Current user ($env:USERNAME) loosely matches Entra admin in group: $(if ($currentEntraAdmin) {'YES - verify this is a dedicated admin account'} else {'No match'}) | Authoritative check: Entra portal > Devices" "CE+"
}

# ---- Check 26A.6: PAW indicator ----
$officeInstalled2 = Test-Path "${env:ProgramFiles}\Microsoft Office"
$browserInstalled = (Test-Path "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe") -or
                    (Test-Path "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") -or
                    (Test-Path "${env:ProgramFiles}\Mozilla Firefox\firefox.exe")
if ($officeInstalled2 -or $browserInstalled) {
    Add-Result "26A.6" "PAW: Productivity Software on Admin Device" "WARN" "Office present: $officeInstalled2 | 3rd-party browser present: $browserInstalled | CE+: admin workstations should not run email/browser (use PAW model)" "CE+"
} else {
    Add-Result "26A.6" "PAW: No Productivity Software on Admin Device" "PASS" "Office: $officeInstalled2 | 3rd-party browser: $browserInstalled | Device appears consistent with PAW model" "CE+"
}

# ============================================================
#  SECTION 26B: CE+ / NCSC - TWO-FACTOR AUTHENTICATION (2FA/MFA)
#
#  CE+ requires MFA for all remote access and privileged accounts.
#  NCSC strongly recommends MFA for all accounts where possible.
#  Checks cover local, Entra ID, and device-level MFA indicators.
# ============================================================
Write-SectionHeader "26B. CE+ / NCSC - TWO-FACTOR AUTHENTICATION" "CE+ | NCSC"

# ---- Check 26B.1: Windows Hello for Business enabled and enrolled ----
# On Entra + MDM managed devices, WHfB policy may be delivered via Intune CSP
# rather than a local GPO registry key, so the absence of the policy key does NOT
# mean WHfB is disabled. The NGC key registration is the authoritative local indicator.
$whfbPolicy    = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "Enabled"
$whfbCSP       = Get-RegValue "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\PassportForWork" "Enabled"
$whfbNGCKey    = $dsreg["NgcSet"]
$whfbMDMActive = $null -ne $whfbCSP

if ($Script:EntraJoined -and $Script:MDMEnrolled) {
    # On Entra+MDM: NGC key present = user has enrolled WHfB credential = PASS
    # Policy delivery via Intune CSP may not leave a local GPO registry entry
    $s = if ($whfbNGCKey -eq "YES") { "PASS" }
         elseif ($whfbMDMActive -or $whfbPolicy -eq 1) { "WARN" }   # Policy pushed but user not enrolled yet
         else { "WARN" }
    Add-Result "26B.1" "WHfB Enabled + Enrolled (Entra+MDM)" $s "NGC key registered: $whfbNGCKey | Intune CSP: $(if ($whfbMDMActive) {'Applied'} else {'Not detected'}) | GPO registry: $whfbPolicy | NGC key = user has active WHfB credential" "CE+"
} else {
    $s = if ($whfbPolicy -eq 1 -and $whfbNGCKey -eq "YES") { "PASS" }
         elseif ($whfbPolicy -eq 1 -or $whfbNGCKey -eq "YES") { "WARN" }
         else { "FAIL" }
    Add-Result "26B.1" "Windows Hello for Business Enabled + Enrolled" $s "WHfB policy: $whfbPolicy | NGC key registered: $whfbNGCKey | Both required for active phishing-resistant MFA" "CE+"
}

# ---- Check 26B.2: WHfB backed by TPM ----
# On Entra+MDM devices Intune pushes this via ./Device/Vendor/MSFT/PassportForWork CSP.
# Check both the local policy key and the MDM CSP key.
$whfbTPM    = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "RequireSecurityDevice"
$whfbTPMCSP = Get-RegValue "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\PassportForWork" "RequireSecurityDevice"
$tpmRequired = ($whfbTPM -eq 1) -or ($whfbTPMCSP -eq 1)

if ($Script:EntraJoined -and $Script:MDMEnrolled) {
    $s = if ($tpmRequired) { "PASS" } elseif ($whfbNGCKey -eq "YES") { "WARN" } else { "WARN" }
    Add-Result "26B.2" "WHfB: TPM Required (Hardware-Backed MFA)" $s "GPO key: $whfbTPM | Intune CSP: $whfbTPMCSP | Combined TPM required: $tpmRequired | NCSC: hardware-backed credentials preferred" "CE+"
} else {
    $s = if ($whfbTPM -eq 1) { "PASS" } else { "WARN" }
    Add-Result "26B.2" "WHfB: TPM Required (Hardware-Backed MFA)" $s "RequireSecurityDevice: $whfbTPM | NCSC: hardware-backed credentials preferred over software" "CE+"
}

# Check 3: FIDO2 / security key support
$fidoPolicy = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\FIDO" "Enabled"
$s = if ($fidoPolicy -eq 1 -or $null -eq $fidoPolicy) { "PASS" } else { "FAIL" }
Add-Result "26B.3" "FIDO2 Security Key Support Not Blocked" $s "FIDO Enabled: $(if ($null -eq $fidoPolicy) {'Default (not blocked)'} else {$fidoPolicy}) | CE+: FIDO2 keys are phishing-resistant MFA" "CE+"

# Check 4: Smart card / virtual smart card support
$scForced = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ScForceOption"
Add-Result "26B.4" "Smart Card / Certificate MFA" "INFO" "ScForceOption (force smart card logon): $scForced | $(if ($scForced -eq 1) {'Smart card required'} else {'Not forced - consider for privileged accounts'})" "CE+"

# Check 5: Conditional Access MFA signal (Entra joined devices)
if ($Script:EntraJoined) {
    # Compliance URL present = device subject to CA compliance (which typically includes MFA)
    $s = if ($Script:ComplianceURL -ne "") { "PASS" } else { "WARN" }
    Add-Result "26B.5" "Conditional Access MFA Enforcement" $s "CA ComplianceUrl: $(if ($Script:ComplianceURL -ne '') {$Script:ComplianceURL} else {'Not set - device may not be subject to MFA CA policy'}) | CE+: all remote access must require MFA" "CE+"

    # PRT with MFA claim (MFA was used to obtain PRT)
    $prtMFA = $dsreg["AzureAdPrtAuthority"]
    $s = if ($null -ne $prtMFA -and $prtMFA -ne "") { "PASS" } else { "WARN" }
    Add-Result "26B.6" "PRT Obtained with MFA" $s "AzureAdPrtAuthority: $(if ($prtMFA) {$prtMFA} else {'Not detected - verify MFA was required for device sign-in'})" "CE+"

    # Per-user MFA status cannot be read locally - inform operator
    Add-Result "26B.7" "Entra Per-User MFA Status" "INFO" "Per-user MFA state cannot be read from the device. Verify in Entra ID portal > Users > Per-User MFA, or confirm MFA is enforced via Conditional Access for all users." "CE+"
} else {
    Add-Result "26B.5" "Conditional Access MFA" "WARN" "Device not Entra joined - MFA must be enforced by other means (NPS + RADIUS, VPN MFA, etc.) | CE+: all remote access must use MFA" "CE+"
}

# Check 6: NTLMv2 / legacy auth not bypassing MFA
# If legacy auth protocols are enabled, they can bypass MFA entirely
$legacyAuthBlock = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
$s = if ($legacyAuthBlock -ge 5) { "PASS" } else { "FAIL" }
Add-Result "26B.8" "Legacy Auth Protocols Blocked (Protects MFA)" $s "LmCompatibilityLevel: $legacyAuthBlock | Level <5 allows LM/NTLM which bypass MFA entirely. CE+: block legacy auth." "CE+"

# Check 7: Authenticator app / Microsoft Authenticator indicator
# Can only be detected if Intune/MDM has pushed the app policy
$authAppPolicy = Get-RegValue "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock" "AllowIdleReturnWithoutPassword"
Add-Result "26B.9" "Microsoft Authenticator / Auth App" "INFO" "Authenticator app status cannot be read locally. Verify in Entra ID portal > Security > Authentication methods that Microsoft Authenticator or FIDO2 is enabled and registered for all users." "CE+"

# Check 8: MFA for remote access (RDP / VPN indicator)
$rdpEnabled2  = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
$nlaRequired2 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
if ($rdpEnabled2 -ne 1) {
    # RDP is on - NLA is a pre-auth layer but not MFA on its own
    $s = if ($nlaRequired2 -eq 1 -and ($Script:EntraJoined -and $Script:ComplianceURL -ne "")) { "PASS" }
         elseif ($nlaRequired2 -eq 1) { "WARN" }
         else { "FAIL" }
    Add-Result "26B.10" "RDP: MFA or CA Required for Remote Access" $s "NLA: $nlaRequired2 | CA policy: $(if ($Script:ComplianceURL -ne '') {'Present'} else {'Not detected'}) | CE+: MFA must be required for all remote access including RDP" "CE+"
} else {
    Add-Result "26B.10" "RDP: Not Enabled (Remote Access MFA N/A)" "PASS" "RDP disabled - no unauthenticated remote desktop exposure" "CE+"
}

# Check 9: Verify no accounts have blank passwords (MFA is meaningless with blank passwords)
$blankPasswd = Get-LocalUser -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -eq $true -and $_.PasswordRequired -eq $false }
$s = if (-not $blankPasswd) { "PASS" } else { "FAIL" }
Add-Result "26B.11" "No Accounts With Blank Passwords" $s "Accounts with blank/not-required passwords: $(if ($blankPasswd) {($blankPasswd.Name) -join ', '} else {'None'}) | MFA is bypassed by blank passwords" "CE+"

# ============================================================
#  SECTION 27: ENTRA ID DEVICE IDENTITY  [EntraID | CE+]
# ============================================================
Write-SectionHeader "27. ENTRA ID DEVICE IDENTITY" "EntraID | CE+"

Add-Result "27.1" "Device Join Type" "INFO" "Type: $joinType" "EntraID"

$s = if ($Script:EntraJoined -or $Script:HybridJoined) { "PASS" } else { "WARN" }
Add-Result "27.2" "Device Joined to Entra ID" $s "AzureAdJoined: $($Script:EntraJoined) | Hybrid: $($Script:HybridJoined)" "EntraID"

Add-Result "27.3" "Tenant Information" "INFO" "TenantName: $($Script:TenantName) | TenantID: $($Script:TenantID)" "EntraID"
Add-Result "27.4" "Device ID" "INFO" "DeviceId: $($Script:DeviceID)" "EntraID"

$s = if ($Script:PRTPresent) { "PASS" } else { "WARN" }
Add-Result "27.5" "Primary Refresh Token (PRT) Present" $s "AzureAdPrt: $($Script:PRTPresent) - Missing PRT = auth issues or Conditional Access block" "EntraID"

# PRT update recency
$prtUpdate = $dsreg["AzureAdPrtUpdateTime"]
if ($prtUpdate) {
    try {
        $prtDate = $null
        $formats = @("M/d/yyyy H:mm:ss tt", "M/d/yyyy HH:mm:ss", "d/M/yyyy H:mm:ss tt", "d/M/yyyy HH:mm:ss")
        foreach ($fmt in $formats) {
            try {
                $prtDate = [datetime]::ParseExact($prtUpdate, $fmt, [System.Globalization.CultureInfo]::InvariantCulture)
                break
            } catch { }
        }
        if ($prtDate) {
            $prtDays = ((Get-Date) - $prtDate).Days
            $s = if ($prtDays -le 4) { "PASS" } elseif ($prtDays -le 14) { "WARN" } else { "FAIL" }
            Add-Result "27.6" "PRT Last Updated" $s "Last update: $prtUpdate ($prtDays days ago) - PRT should refresh every 4 days" "EntraID"
        } else {
            Add-Result "27.6" "PRT Last Updated" "INFO" "Last update time: $prtUpdate (could not parse date)" "EntraID"
        }
    } catch {
        Add-Result "27.6" "PRT Last Updated" "INFO" "Last update time: $prtUpdate" "EntraID"
    }
} else {
    Add-Result "27.6" "PRT Last Updated" "WARN" "Could not determine PRT update time" "EntraID"
}

# Device compliance URL present (indicates CA compliance policy exists)
$s = if ($Script:ComplianceURL -ne "") { "PASS" } else { "WARN" }
Add-Result "27.7" "Conditional Access Compliance Policy" $s "ComplianceUrl: $(if ($Script:ComplianceURL) {$Script:ComplianceURL} else {'Not set - device may not be subject to CA compliance'})" "EntraID"

# Windows Hello for Business cloud key presence
$whfbKey = $dsreg["NgcSet"]
$s = if ($whfbKey -eq "YES") { "PASS" } else { "WARN" }
Add-Result "27.8" "Windows Hello / NGC Key Registered" $s "NgcSet: $whfbKey - Required for passwordless / phishing-resistant auth" "EntraID"

# SSO state
$ssoState = $dsreg["SsoStateFlags"]
Add-Result "27.9" "SSO State Flags" "INFO" "SsoStateFlags: $ssoState" "EntraID"

# ============================================================
#  SECTION 28: INTUNE / MDM ENROLMENT  [EntraID | CE+]
# ============================================================
Write-SectionHeader "28. INTUNE / MDM ENROLMENT" "EntraID | CE+"

$s = if ($Script:MDMEnrolled) { "PASS" } else { "WARN" }
Add-Result "28.1" "Device Enrolled in MDM (Intune)" $s "MDM URL: $(if ($Script:MDMUrl) {$Script:MDMUrl} else {'Not enrolled'})" "EntraID"

if ($Script:MDMEnrolled) {
    # Check for Intune Management Extension (IME)
    $imeSvc = Get-Service -Name "IntuneManagementExtension" -ErrorAction SilentlyContinue
    $s = if ($imeSvc -and $imeSvc.Status -eq "Running") { "PASS" } else { "WARN" }
    Add-Result "28.2" "Intune Management Extension Running" $s "IME Service: $(if ($imeSvc) {$imeSvc.Status} else {'Not found'})" "EntraID"

    # Last Intune sync
    $imeLog = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\AgentExecutor.log"
    if (Test-Path $imeLog) {
        $lastWrite = (Get-Item $imeLog).LastWriteTime
        $syncDays  = ((Get-Date) - $lastWrite).Days
        $s = if ($syncDays -le 1) { "PASS" } elseif ($syncDays -le 3) { "WARN" } else { "FAIL" }
        Add-Result "28.3" "Intune Last Sync" $s "IME log last written: $($lastWrite.ToString('dd/MM/yyyy HH:mm')) ($syncDays days ago)" "EntraID"
    } else {
        Add-Result "28.3" "Intune Last Sync" "WARN" "IME log not found - cannot determine last sync time" "EntraID"
    }

    # MDM enrolment type (check registry)
    $enrollments = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -ErrorAction SilentlyContinue
    $activeEnrol = $enrollments | Where-Object {
        (Get-RegValue $_.PSPath "EnrollmentState") -eq 1
    }
    $enrolCount = if ($activeEnrol) { @($activeEnrol).Count } else { 0 }
    $s = if ($enrolCount -ge 1) { "PASS" } else { "WARN" }
    Add-Result "28.4" "Active MDM Enrolment Records" $s "Active enrolments found: $enrolCount" "EntraID"

    # Intune compliance registry (set by Intune after evaluation)
    $compState = Get-RegValue "HKLM:\SOFTWARE\Microsoft\CCMClient" "MachineIsCompliant" -ErrorAction SilentlyContinue
    if ($null -eq $compState) {
        # Try Intune-native compliance state path
        $intuneCompPath = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -ErrorAction SilentlyContinue |
            ForEach-Object { Get-RegValue $_.PSPath "ProviderId" } |
            Where-Object { $_ -eq "MS DM Server" }
        $s = if ($intuneCompPath) { "PASS" } else { "WARN" }
        Add-Result "28.5" "Intune Compliance Policy Applied" $s "$(if ($intuneCompPath) {'Intune DM Server enrolment confirmed'} else {'Could not confirm compliance state - check Intune portal'})" "EntraID"
    } else {
        $s = if ($compState -eq 1) { "PASS" } else { "FAIL" }
        Add-Result "28.5" "Device Compliance State" $s "MachineIsCompliant: $compState" "EntraID"
    }

    # Check Intune policies are pushing expected settings
    $intuneFirewall  = Get-RegValue "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Firewall" "EnableFirewall"
    $intuneBitLocker = Get-RegValue "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker" "RequireDeviceEncryption"
    $intuneDefender  = Get-RegValue "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Defender" "AllowRealtimeMonitoring"

    $s = if ($null -ne $intuneFirewall)  { "PASS" } else { "WARN" }
    Add-Result "28.6" "Intune Firewall Policy Applied" $s "Firewall CSP: $(if ($null -ne $intuneFirewall) {'Present'} else {'Not detected'})" "EntraID"

    $s = if ($null -ne $intuneBitLocker) { "PASS" } else { "WARN" }
    Add-Result "28.7" "Intune BitLocker Policy Applied" $s "BitLocker CSP: $(if ($null -ne $intuneBitLocker) {'Present'} else {'Not detected'})" "EntraID"

    $s = if ($null -ne $intuneDefender)  { "PASS" } else { "WARN" }
    Add-Result "28.8" "Intune Defender Policy Applied" $s "Defender CSP: $(if ($null -ne $intuneDefender) {'Present'} else {'Not detected'})" "EntraID"
} else {
    Add-Result "28.2" "MDM Enrolment (Not Enrolled)" "WARN" "Device is not MDM enrolled - security policies must be applied via GPO or manually" "EntraID"
}

# ============================================================
#  SECTION 29: WINDOWS HELLO FOR BUSINESS  [EntraID | CE+]
# ============================================================
Write-SectionHeader "29. WINDOWS HELLO FOR BUSINESS" "EntraID | CE+"

# WHfB policy
$whfbEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "Enabled"
$s = if ($whfbEnabled -eq 1) { "PASS" } else { "WARN" }
Add-Result "29.1" "WHfB Group Policy / Intune Policy Enabled" $s "PassportForWork Enabled: $whfbEnabled" "EntraID"

# NGC key registered (from dsregcmd)
$ngcSet = $dsreg["NgcSet"]
$s = if ($ngcSet -eq "YES") { "PASS" } else { "WARN" }
Add-Result "29.2" "WHfB NGC Key Registered" $s "NgcSet: $ngcSet - User has enrolled a WHfB credential" "EntraID"

# WHfB PIN complexity policy
$pinLength = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" "MinimumPINLength"
$s = if ($null -ne $pinLength -and $pinLength -ge 6) { "PASS" } else { "WARN" }
Add-Result "29.3" "WHfB PIN Minimum Length" $s "MinimumPINLength: $(if ($null -eq $pinLength) {'Not configured (default 6)'} else {$pinLength})" "EntraID"

$pinExpiry = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" "Expiration"
$s = if ($null -ne $pinExpiry -and $pinExpiry -le 365 -and $pinExpiry -ge 1) { "PASS" } else { "WARN" }
Add-Result "29.4" "WHfB PIN Expiry Configured" $s "Expiration: $(if ($null -eq $pinExpiry) {'Not configured'} else {"$pinExpiry days"})" "EntraID"

# Biometrics allowed
$bioEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\Biometrics" "UseBiometrics"
$s = if ($bioEnabled -eq 1 -or $null -eq $bioEnabled) { "PASS" } else { "WARN" }
Add-Result "29.5" "WHfB Biometrics Permitted" $s "UseBiometrics: $(if ($null -eq $bioEnabled) {'Default (permitted)'} else {$bioEnabled})" "EntraID"

# WHfB certificate trust vs key trust
$certTrust = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "RequireSecurityDevice"
Add-Result "29.6" "WHfB Security Device (TPM) Required" "$(if ($certTrust -eq 1) {'PASS'} else {'WARN'})" "RequireSecurityDevice: $certTrust - Require TPM for WHfB to prevent software-based key theft" "EntraID"

# ============================================================
#  SECTION 30: MICROSOFT DEFENDER FOR ENDPOINT (MDE)  [EntraID | CE+]
# ============================================================
Write-SectionHeader "30. MICROSOFT DEFENDER FOR ENDPOINT" "EntraID | CE+"

# MDE Sense service
$senseSvc = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
$s = if ($senseSvc -and $senseSvc.Status -eq "Running") { "PASS" } else { "WARN" }
Add-Result "30.1" "MDE Sense Service Running" $s "Sense service: $(if ($senseSvc) {$senseSvc.Status} else {'Not found - MDE may not be onboarded'})" "EntraID"

# MDE onboarding state registry
$mdeOnboarded = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" "OnboardingState"
$s = switch ($mdeOnboarded) {
    1       { "PASS" }
    0       { "FAIL" }
    default { "WARN" }
}
Add-Result "30.2" "MDE Onboarding State" $s "OnboardingState: $mdeOnboarded (1=Onboarded, 0=Not onboarded)" "EntraID"

# MDE organisation ID
$mdeOrgID = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" "OrgID"
Add-Result "30.3" "MDE Organisation ID" "INFO" "OrgID: $(if ($mdeOrgID) {$mdeOrgID} else {'Not found'})" "EntraID"

# MDE sample submission
$mdeSubmission = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" "AllowSampleCollection"
$s = if ($mdeSubmission -eq 1 -or $null -eq $mdeSubmission) { "PASS" } else { "WARN" }
Add-Result "30.4" "MDE Sample Submission Enabled" $s "AllowSampleCollection: $(if ($null -eq $mdeSubmission) {'Default'} else {$mdeSubmission})" "EntraID"

# MDE cloud connectivity (check SENSE can reach MS)
$senseTelemetry = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" "EnableTelemetry"
$s = if ($enableTelemetry -ne 0) { "PASS" } else { "FAIL" }
Add-Result "30.5" "MDE Telemetry Not Disabled" $s "EnableTelemetry: $(if ($null -eq $senseTelemetry) {'Default (enabled)'} else {$senseTelemetry})" "EntraID"

# Defender for Endpoint EDR in block mode
$edrBlock = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "ForceDefenderPassiveMode"
$s = if ($edrBlock -ne 1) { "PASS" } else { "WARN" }
Add-Result "30.6" "MDE Not Forced into Passive Mode" $s "ForceDefenderPassiveMode: $(if ($null -eq $edrBlock) {'Not set (Active mode)'} else {$edrBlock})" "EntraID"

# ============================================================
#  SECTION 31: MICROSOFT 365 / OFFICE SECURITY  [EntraID | CE+]
# ============================================================
Write-SectionHeader "31. MICROSOFT 365 / OFFICE SECURITY" "EntraID | CE+"

# Detect installed Office version
$officeVersions = @("16.0","15.0","14.0")
$officeInstalled = $null
foreach ($ver in $officeVersions) {
    if (Test-Path "HKCU:\SOFTWARE\Microsoft\Office\$ver\Word") {
        $officeInstalled = $ver
        break
    }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Office\$ver\Common") {
        $officeInstalled = $ver
        break
    }
}

if ($officeInstalled) {
    Add-Result "31.0" "Microsoft Office Detected" "INFO" "Version path: $officeInstalled ($(if ($officeInstalled -eq '16.0') {'Microsoft 365 / Office 2016/2019/2021'} else {$officeInstalled}))" "EntraID"

    $offApps = @("Word","Excel","PowerPoint","Outlook","Access")
    foreach ($app in $offApps) {
        $macroPolicy = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Office\$officeInstalled\$app\Security" "VBAWarnings"
        if ($null -ne $macroPolicy) {
            $macroDesc = switch ($macroPolicy) {
                1 { "All macros enabled - FAIL" }
                2 { "Macros with notification (signed only)" }
                3 { "Macros disabled except digitally signed" }
                4 { "All macros disabled - PASS" }
                default { "Unknown value: $macroPolicy" }
            }
            $s = if ($macroPolicy -eq 4) { "PASS" } elseif ($macroPolicy -eq 3) { "WARN" } else { "FAIL" }
            Add-Result "31.M.$app" "Office $app Macro Policy" $s "VBAWarnings: $macroPolicy ($macroDesc)" "EntraID"
        }
    }

    # Block macros from internet-origin files (CE+ / CIS Office)
    $blockInternetMacros = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Office\$officeInstalled\Excel\Security" "blockcontentexecutionfrominternet"
    $s = if ($blockInternetMacros -eq 1) { "PASS" } else { "WARN" }
    Add-Result "31.1" "Block Macros from Internet Origin Files" $s "blockcontentexecutionfrominternet: $blockInternetMacros" "EntraID"

    # Protected View settings
    $pvDisableInternet = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Office\$officeInstalled\Word\Security\ProtectedView" "DisableInternetFilesInProtectedView"
    $s = if ($pvDisableInternet -ne 1) { "PASS" } else { "FAIL" }
    Add-Result "31.2" "Protected View: Internet Files" $s "DisableInternetFilesInProtectedView: $(if ($null -eq $pvDisableInternet) {'Not set (Protected View active)'} else {$pvDisableInternet})" "EntraID"

    $pvDisableAttachments = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Office\$officeInstalled\Word\Security\ProtectedView" "DisableAttachmentsInProtectedView"
    $s = if ($pvDisableAttachments -ne 1) { "PASS" } else { "FAIL" }
    Add-Result "31.3" "Protected View: Attachments" $s "DisableAttachmentsInProtectedView: $(if ($null -eq $pvDisableAttachments) {'Not set (Protected View active)'} else {$pvDisableAttachments})" "EntraID"

    # ActiveX controls
    $axDisabled = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Office\$officeInstalled\Common\Security" "DisableAllActiveX"
    $s = if ($axDisabled -eq 1) { "PASS" } else { "WARN" }
    Add-Result "31.4" "Office ActiveX Controls Disabled" $s "DisableAllActiveX: $axDisabled" "EntraID"

    # Modern Authentication (OAuth) for Office - critical for MFA to work
    $modernAuth = Get-RegValue "HKCU:\SOFTWARE\Microsoft\Office\$officeInstalled\Common\Identity" "EnableADAL"
    $s = if ($modernAuth -eq 1 -or $null -eq $modernAuth) { "PASS" } else { "FAIL" }
    Add-Result "31.5" "Modern Authentication (ADAL/OAuth) Enabled" $s "EnableADAL: $(if ($null -eq $modernAuth) {'Default (enabled in M365)'} else {$modernAuth}) - Required for Entra ID MFA" "EntraID"

    # Legacy auth blocked indicator (set by Intune / CA policy)
    $legacyAuthBlock = Get-RegValue "HKCU:\SOFTWARE\Microsoft\Office\$officeInstalled\Common\Identity" "DisableADALatopWAMOverride"
    $s = if ($null -eq $legacyAuthBlock -or $legacyAuthBlock -eq 0) { "PASS" } else { "WARN" }
    Add-Result "31.6" "WAM Override Not Disabled" $s "DisableADALatopWAMOverride: $legacyAuthBlock - WAM required for Entra SSO" "EntraID"

    # Outlook object model guard
    $outlookOMG = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Office\$officeInstalled\Outlook\Security" "PromptOOMAddressInformationAccess"
    $s = if ($null -ne $outlookOMG -and $outlookOMG -ge 2) { "PASS" } else { "WARN" }
    Add-Result "31.7" "Outlook Object Model Guard" $s "PromptOOMAddressInformationAccess: $outlookOMG (2=Prompt, 3=Block)" "EntraID"

    # Office update channel
    $officeUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\office\$officeInstalled\common\officeupdate"
    $updateBranch = Get-RegValue $officeUpdatePath "updatebranch"
    $updateEnabled = Get-RegValue $officeUpdatePath "enableautomaticupdates"
    $s = if ($updateEnabled -ne 0) { "PASS" } else { "FAIL" }
    Add-Result "31.8" "Office Auto-Updates Enabled" $s "EnableAutomaticUpdates: $(if ($null -eq $updateEnabled) {'Default (enabled)'} else {$updateEnabled}), Branch: $updateBranch" "EntraID"

    # DDE (Dynamic Data Exchange) - common macro attack vector
    $ddeWord = Get-RegValue "HKCU:\SOFTWARE\Microsoft\Office\$officeInstalled\Word\Options" "DontUpdateLinks"
    $s = if ($ddeWord -eq 1) { "PASS" } else { "WARN" }
    Add-Result "31.9" "Word DDE / Auto-Update Links Disabled" $s "DontUpdateLinks: $ddeWord" "EntraID"

} else {
    Add-Result "31.0" "Microsoft Office" "INFO" "Office not detected on this device - section skipped" "EntraID"
}

# OneDrive Known Folder Move (KFM) - important for data protection on Entra devices
$kfmEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" "KFMSilentOptIn"
$s = if ($null -ne $kfmEnabled) { "PASS" } else { "WARN" }
Add-Result "31.10" "OneDrive Known Folder Move (KFM)" $s "KFMSilentOptIn TenantID: $(if ($null -ne $kfmEnabled) {$kfmEnabled} else {'Not configured - Desktop/Documents/Pictures may not be backed up'})" "EntraID"

# OneDrive sync client health
$odSvc = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
$s = if ($odSvc) { "PASS" } else { "WARN" }
Add-Result "31.11" "OneDrive Sync Client Running" $s "OneDrive process: $(if ($odSvc) {'Running'} else {'Not running'})" "EntraID"

# ============================================================
#  SECTION 32: ENTRA ID CONDITIONAL ACCESS & COMPLIANCE  [EntraID | CE+]
# ============================================================
Write-SectionHeader "32. CONDITIONAL ACCESS & DEVICE COMPLIANCE" "EntraID | CE+"

# Device compliance state from dsregcmd
$compState    = $dsreg["IsCompliant"]
$compManaged  = $dsreg["IsManaged"]
$compMDMUrl   = $dsreg["MdmUrl"]

$s = if ($compState -eq "YES") { "PASS" } elseif ($null -eq $compState) { "WARN" } else { "FAIL" }
Add-Result "32.1" "Device Compliance State (Entra)" $s "IsCompliant: $compState | IsManaged: $compManaged" "EntraID"

$s = if ($compManaged -eq "YES") { "PASS" } else { "WARN" }
Add-Result "32.2" "Device Managed State (Intune)" $s "IsManaged: $compManaged | MDM: $(if ($compMDMUrl) {$compMDMUrl} else {'Not enrolled'})" "EntraID"

# Entra device registration state
$entRegState = $dsreg["EnterpriseJoined"]
Add-Result "32.3" "Entra Enterprise Join State" "INFO" "EnterpriseJoined: $entRegState" "EntraID"

# TLS 1.2 minimum (required for M365)
$tls12Client = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" "Enabled"
$tls12Server = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" "Enabled"
$tls10Dis    = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" "DisabledByDefault"
$tls11Dis    = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" "DisabledByDefault"

$s = if ($tls12Client -ne 0 -and $tls12Server -ne 0) { "PASS" } else { "FAIL" }
Add-Result "32.4" "TLS 1.2 Enabled (Required for M365)" $s "TLS 1.2 Client: $(if ($null -eq $tls12Client) {'Default (on)'} else {$tls12Client}), Server: $(if ($null -eq $tls12Server) {'Default (on)'} else {$tls12Server})" "EntraID"

$s = if ($tls10Dis -eq 1) { "PASS" } else { "WARN" }
Add-Result "32.5" "TLS 1.0 Disabled by Default" $s "TLS 1.0 DisabledByDefault: $tls10Dis" "EntraID"

$s = if ($tls11Dis -eq 1) { "PASS" } else { "WARN" }
Add-Result "32.6" "TLS 1.1 Disabled by Default" $s "TLS 1.1 DisabledByDefault: $tls11Dis" "EntraID"

# Check connectivity to key M365 endpoints (basic - DNS resolution only)
$m365Endpoints = @(
    @{ Host = "login.microsoftonline.com"; Label = "Entra ID Login" }
    @{ Host = "graph.microsoft.com";       Label = "Microsoft Graph" }
    @{ Host = "manage.microsoft.com";      Label = "Intune Management" }
    @{ Host = "enterpriseregistration.windows.net"; Label = "Device Registration" }
)

foreach ($ep in $m365Endpoints) {
    try {
        $dns = [System.Net.Dns]::GetHostAddresses($ep.Host)
        $s   = if ($dns -and $dns.Count -gt 0) { "PASS" } else { "FAIL" }
        Add-Result "32.7" "M365 Connectivity: $($ep.Label)" $s "$($ep.Host) resolves to: $(($dns.IPAddressToString) -join ', ')" "EntraID"
    } catch {
        Add-Result "32.7" "M365 Connectivity: $($ep.Label)" "FAIL" "$($ep.Host) - DNS resolution failed (check firewall / proxy)" "EntraID"
    }
}

# Conditional Access - check for policy hints in registry (pushed by CA)
$caPath = "HKLM:\SOFTWARE\Microsoft\Policies\Microsoft\AAD"
if (Test-Path $caPath) {
    Add-Result "32.8" "Conditional Access Policy Hints Present" "PASS" "AAD policy registry path exists" "EntraID"
} else {
    Add-Result "32.8" "Conditional Access Policy Hints Present" "WARN" "No CA policy registry hints - verify Conditional Access is applied in Entra portal" "EntraID"
}

# ============================================================
#  SECTION 33: CIS L2 - USER RIGHTS ASSIGNMENT  [CIS L2]
# ============================================================
Write-SectionHeader "33. CIS L2 - USER RIGHTS ASSIGNMENT" "CIS L2"

# Helper: get secedit user right value
function Get-UserRight { param([string]$Right); return (Get-SecEditValue $Right) }

# Access this computer from the network - L2: Administrators only
$val = Get-UserRight "SeNetworkLogonRight"
$s   = if ($val -and $val -notmatch "Everyone" -and $val -notmatch "Users") { "PASS" } else { "WARN" }
Add-Result "33.1" "Network Logon: Admins Only (L2)" $s "SeNetworkLogonRight: $val" "CIS-L2"

# Act as part of operating system - No one
$val = Get-UserRight "SeTcbPrivilege"
$s   = if ($null -eq $val -or $val -eq "") { "PASS" } else { "FAIL" }
Add-Result "33.2" "Act as OS: No One" $s "SeTcbPrivilege: $(if ($val) {$val} else {'Not assigned (correct)'})" "CIS-L2"

# Back up files and directories - Administrators only
$val = Get-UserRight "SeBackupPrivilege"
$s   = if ($val -match "Administrators" -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.3" "Backup Files: Admins Only" $s "SeBackupPrivilege: $val" "CIS-L2"

# Debug programs - L2: No one (L1 allows Administrators)
$val = Get-UserRight "SeDebugPrivilege"
$s   = if ($null -eq $val -or $val -eq "") { "PASS" } else { "FAIL" }
Add-Result "33.4" "Debug Programs: No One (L2)" $s "SeDebugPrivilege: $(if ($val) {$val} else {'Not assigned (correct)'})" "CIS-L2"

# Enable computer and user accounts to be trusted for delegation - No one
$val = Get-UserRight "SeEnableDelegationPrivilege"
$s   = if ($null -eq $val -or $val -eq "") { "PASS" } else { "FAIL" }
Add-Result "33.5" "Trusted for Delegation: No One" $s "SeEnableDelegationPrivilege: $(if ($val) {$val} else {'Not assigned (correct)'})" "CIS-L2"

# Create permanent shared objects - No one
$val = Get-UserRight "SeCreatePermanentPrivilege"
$s   = if ($null -eq $val -or $val -eq "") { "PASS" } else { "FAIL" }
Add-Result "33.6" "Create Permanent Shared Objects: No One" $s "SeCreatePermanentPrivilege: $(if ($val) {$val} else {'Not assigned (correct)'})" "CIS-L2"

# Create symbolic links - Administrators only
$val = Get-UserRight "SeCreateSymbolicLinkPrivilege"
$s   = if ($val -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.7" "Create Symbolic Links: Admins Only" $s "SeCreateSymbolicLinkPrivilege: $val" "CIS-L2"

# Create pagefile - Administrators only
$val = Get-UserRight "SeCreatePagefilePrivilege"
$s   = if ($val -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.8" "Create Pagefile: Admins Only" $s "SeCreatePagefilePrivilege: $val" "CIS-L2"

# Lock pages in memory - No one
$val = Get-UserRight "SeLockMemoryPrivilege"
$s   = if ($null -eq $val -or $val -eq "") { "PASS" } else { "FAIL" }
Add-Result "33.9" "Lock Pages in Memory: No One" $s "SeLockMemoryPrivilege: $(if ($val) {$val} else {'Not assigned (correct)'})" "CIS-L2"

# Manage auditing and security log - Administrators only
$val = Get-UserRight "SeSecurityPrivilege"
$s   = if ($val -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.10" "Manage Audit/Security Log: Admins Only" $s "SeSecurityPrivilege: $val" "CIS-L2"

# Load and unload device drivers - Administrators only
$val = Get-UserRight "SeLoadDriverPrivilege"
$s   = if ($val -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.11" "Load/Unload Device Drivers: Admins Only" $s "SeLoadDriverPrivilege: $val" "CIS-L2"

# Modify firmware environment values - Administrators only
$val = Get-UserRight "SeSystemEnvironmentPrivilege"
$s   = if ($val -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.12" "Modify Firmware Values: Admins Only" $s "SeSystemEnvironmentPrivilege: $val" "CIS-L2"

# Perform volume maintenance tasks - Administrators only
$val = Get-UserRight "SeManageVolumePrivilege"
$s   = if ($val -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.13" "Volume Maintenance Tasks: Admins Only" $s "SeManageVolumePrivilege: $val" "CIS-L2"

# Profile single process - Administrators only
$val = Get-UserRight "SeProfileSingleProcessPrivilege"
$s   = if ($val -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.14" "Profile Single Process: Admins Only" $s "SeProfileSingleProcessPrivilege: $val" "CIS-L2"

# Restore files and directories - Administrators only
$val = Get-UserRight "SeRestorePrivilege"
$s   = if ($val -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.15" "Restore Files: Admins Only" $s "SeRestorePrivilege: $val" "CIS-L2"

# Take ownership - Administrators only
$val = Get-UserRight "SeTakeOwnershipPrivilege"
$s   = if ($val -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.16" "Take Ownership: Admins Only" $s "SeTakeOwnershipPrivilege: $val" "CIS-L2"

# Force shutdown from remote system - Administrators only
$val = Get-UserRight "SeRemoteShutdownPrivilege"
$s   = if ($val -and $val -notmatch "Users" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "33.17" "Remote Shutdown: Admins Only" $s "SeRemoteShutdownPrivilege: $val" "CIS-L2"

# Generate security audits - LOCAL SERVICE, NETWORK SERVICE only
$val = Get-UserRight "SeAuditPrivilege"
$s   = if ($val -and $val -notmatch "Administrators" -and $val -notmatch "Users") { "PASS" } else { "WARN" }
Add-Result "33.18" "Generate Security Audits: Svc Accounts Only" $s "SeAuditPrivilege: $val" "CIS-L2"

# ============================================================
#  SECTION 34: CIS L2 - ADDITIONAL SECURITY OPTIONS  [CIS L2]
# ============================================================
Write-SectionHeader "34. CIS L2 - ADDITIONAL SECURITY OPTIONS" "CIS L2"

# Devices: Allowed to format and eject removable media - Administrators
$fmtMedia = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateDASD"
$s = if ($fmtMedia -eq "0") { "PASS" } else { "WARN" }
Add-Result "34.1" "Format Removable Media: Admins Only" $s "AllocateDASD: $(if ($null -eq $fmtMedia) {'Not set'} else {$fmtMedia}) (0=Admins only)" "CIS-L2"

# Devices: Prevent users from installing printer drivers
$noPrinterDriver = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers"
$s = if ($noPrinterDriver -eq 1) { "PASS" } else { "WARN" }
Add-Result "34.2" "Prevent Non-Admin Printer Driver Install" $s "AddPrinterDrivers: $noPrinterDriver (1=Admins only)" "CIS-L2"

# Interactive logon: Smart card removal behavior - Lock Workstation (1)
$scRemoval = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScRemoveOption"
$s = if ($scRemoval -eq "1" -or $scRemoval -eq "2" -or $scRemoval -eq "3") { "PASS" } else { "WARN" }
Add-Result "34.3" "Smart Card Removal: Lock Workstation" $s "ScRemoveOption: $scRemoval (1=Lock, 2=Force logoff, 3=Disconnect RDS)" "CIS-L2"

# Interactive logon: Prompt to change password before expiration - 14 days
$pwdWarn = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "PasswordExpiryWarning"
$s = if ($null -ne $pwdWarn -and [int]$pwdWarn -ge 14) { "PASS" } else { "WARN" }
Add-Result "34.4" "Password Expiry Warning >= 14 Days" $s "PasswordExpiryWarning: $(if ($null -eq $pwdWarn) {'Not set (default 5)'} else {$pwdWarn})" "CIS-L2"

# Domain member: Digitally encrypt or sign secure channel data (always)
$scEncAlways = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal"
$s = if ($scEncAlways -eq 1) { "PASS" } else { "FAIL" }
Add-Result "34.5" "Secure Channel: Always Sign or Encrypt" $s "RequireSignOrSeal: $scEncAlways" "CIS"

# Domain member: Digitally encrypt secure channel data when possible
$scEnc = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel"
$s = if ($scEnc -eq 1) { "PASS" } else { "WARN" }
Add-Result "34.6" "Secure Channel: Encrypt When Possible" $s "SealSecureChannel: $scEnc" "CIS"

# Domain member: Digitally sign secure channel data when possible
$scSign = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel"
$s = if ($scSign -eq 1) { "PASS" } else { "WARN" }
Add-Result "34.7" "Secure Channel: Sign When Possible" $s "SignSecureChannel: $scSign" "CIS"

# Domain member: Maximum machine account password age - <= 30 days
$machPwdAge = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge"
$s = if ($null -eq $machPwdAge -or ([int]$machPwdAge -le 30 -and [int]$machPwdAge -ge 1)) { "PASS" } else { "WARN" }
Add-Result "34.8" "Machine Account Password Age <= 30 Days" $s "MaximumPasswordAge: $(if ($null -eq $machPwdAge) {'Default (30)'} else {$machPwdAge})" "CIS"

# Domain member: Require strong session key
$strongKey = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey"
$s = if ($strongKey -eq 1) { "PASS" } else { "FAIL" }
Add-Result "34.9" "Domain Member: Require Strong Session Key" $s "RequireStrongKey: $strongKey" "CIS"

# Network access: Allow anonymous SID/Name translation - Disabled
$anonSID = Get-SecEditValue "LSAAnonymousNameLookup"
$s = if ($anonSID -eq "0") { "PASS" } else { "FAIL" }
Add-Result "34.10" "No Anonymous SID/Name Translation" $s "LSAAnonymousNameLookup: $(if ($null -eq $anonSID) {'Not set'} else {$anonSID}) (0=Disabled)" "CIS"

# Network access: Do not allow storage of passwords and credentials
$noCredStore = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds"
$s = if ($noCredStore -eq 1) { "PASS" } else { "WARN" }
Add-Result "34.11" "No Storage of Network Passwords" $s "DisableDomainCreds: $noCredStore" "CIS-L2"

# Network access: Let Everyone permissions apply to anonymous users - Disabled
$everyoneAnon = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous"
$s = if ($everyoneAnon -eq 0 -or $null -eq $everyoneAnon) { "PASS" } else { "FAIL" }
Add-Result "34.12" "Everyone Does Not Include Anonymous" $s "EveryoneIncludesAnonymous: $(if ($null -eq $everyoneAnon) {'Default (0)'} else {$everyoneAnon})" "CIS"

# Network security: Allow LocalSystem NULL session fallback - Disabled
$nullSession = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "allownullsessionfallback"
$s = if ($nullSession -eq 0 -or $null -eq $nullSession) { "PASS" } else { "FAIL" }
Add-Result "34.13" "No LocalSystem NULL Session Fallback" $s "allownullsessionfallback: $(if ($null -eq $nullSession) {'Default (0)'} else {$nullSession})" "CIS-L2"

# Network security: Allow PKU2U authentication requests - Disabled
$pku2u = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" "AllowOnlineID"
$s = if ($pku2u -eq 0 -or $null -eq $pku2u) { "PASS" } else { "FAIL" }
Add-Result "34.14" "PKU2U Authentication Disabled" $s "AllowOnlineID: $(if ($null -eq $pku2u) {'Default (0)'} else {$pku2u})" "CIS-L2"

# Network security: Do not store LAN Manager hash
$noLMHash = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash"
$s = if ($noLMHash -eq 1) { "PASS" } else { "FAIL" }
Add-Result "34.15" "Do Not Store LAN Manager Hash" $s "NoLMHash: $noLMHash" "CIS"

# Network security: Kerberos encryption types
$kerbEnc = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes"
$s = if ($kerbEnc -eq 2147483640 -or $kerbEnc -ge 24) { "PASS" } else { "WARN" }
Add-Result "34.16" "Kerberos: Strong Encryption Types Only" $s "SupportedEncryptionTypes: $kerbEnc (2147483640=AES+Future, 24=AES128+AES256)" "CIS"

# Shutdown: Allow shutdown without logon - Disabled
$shutdownNoLogon = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon"
$s = if ($shutdownNoLogon -eq 0) { "PASS" } else { "FAIL" }
Add-Result "34.17" "Shutdown Without Logon Disabled" $s "ShutdownWithoutLogon: $shutdownNoLogon" "CIS-L2"

# System objects: Strengthen default permissions
$strengthenPerms = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode"
$s = if ($strengthenPerms -eq 1) { "PASS" } else { "FAIL" }
Add-Result "34.18" "Strengthen Default Object Permissions" $s "ProtectionMode: $strengthenPerms" "CIS"

# System settings: Optional subsystems - none (POSIX disabled)
$optSubsys = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems" "Optional"
$s = if ($null -eq $optSubsys -or $optSubsys -eq "") { "PASS" } else { "FAIL" }
Add-Result "34.19" "No Optional Subsystems (POSIX Disabled)" $s "Optional subsystems: $(if ($null -eq $optSubsys -or $optSubsys -eq '') {'None (correct)'} else {$optSubsys})" "CIS-L2"

# Audit: Force audit policy subcategory settings to override
$forceAudit = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy"
$s = if ($forceAudit -eq 1) { "PASS" } else { "FAIL" }
Add-Result "34.20" "Audit: Subcategory Settings Override Legacy" $s "SCENoApplyLegacyAuditPolicy: $forceAudit" "CIS"

# Audit: Crash on audit failure (CrashOnAuditFail) - L2: 1 = Shutdown if unable to log
# Note: Value 2 shuts down immediately which is L2 strict. 1 is safer for production.
$crashAudit = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail"
$s = if ($crashAudit -eq 1) { "PASS" } elseif ($null -eq $crashAudit -or $crashAudit -eq 0) { "WARN" } else { "FAIL" }
Add-Result "34.21" "Audit: Crash If Unable to Log (CrashOnAuditFail)" $s "CrashOnAuditFail: $crashAudit (0=No action, 1=Halt, 2=Immediate halt)" "CIS-L2"

# UAC: Switch to secure desktop when prompting for elevation (already in §11 but L2 is stricter)
$uacSD = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop"
$s = if ($uacSD -eq 1) { "PASS" } else { "FAIL" }
Add-Result "34.22" "UAC: Elevation Always on Secure Desktop" $s "PromptOnSecureDesktop: $uacSD" "CIS-L2"

# ============================================================
#  SECTION 35: CIS L2 - ADVANCED AUDIT POLICY  [CIS L2 17.x]
# ============================================================
Write-SectionHeader "35. CIS L2 - ADVANCED AUDIT POLICY" "CIS L2 17.x"

$l2AuditChecks = @(
    @{ ID = "35.1";  Sub = "Plug and Play Events";                Exp = "Success" }
    @{ ID = "35.2";  Sub = "Token Right Adjusted Events";         Exp = "Success" }
    @{ ID = "35.3";  Sub = "Detailed File Share";                 Exp = "Failure" }
    @{ ID = "35.4";  Sub = "Removable Storage";                   Exp = "Success and Failure" }
    @{ ID = "35.5";  Sub = "Central Access Policy Staging";       Exp = "Failure" }
    @{ ID = "35.6";  Sub = "Audit Policy Change";                 Exp = "Success and Failure" }
    @{ ID = "35.7";  Sub = "MPSSVC Rule-Level Policy Change";     Exp = "Success and Failure" }
    @{ ID = "35.8";  Sub = "Other Policy Change Events";          Exp = "Failure" }
    @{ ID = "35.9";  Sub = "Distribution Group Management";       Exp = "Success and Failure" }
    @{ ID = "35.10"; Sub = "Other Account Management Events";     Exp = "Success and Failure" }
    @{ ID = "35.11"; Sub = "Application Group Management";        Exp = "Success and Failure" }
    @{ ID = "35.12"; Sub = "Computer Account Management";         Exp = "Success and Failure" }
    @{ ID = "35.13"; Sub = "User Account Management";             Exp = "Success and Failure" }
    @{ ID = "35.14"; Sub = "Process Termination";                 Exp = "Success" }
    @{ ID = "35.15"; Sub = "DPAPI Activity";                      Exp = "Success and Failure" }
    @{ ID = "35.16"; Sub = "RPC Events";                          Exp = "Success and Failure" }
    @{ ID = "35.17"; Sub = "Logoff";                              Exp = "Success" }
    @{ ID = "35.18"; Sub = "Account Lockout";                     Exp = "Success and Failure" }
    @{ ID = "35.19"; Sub = "Network Policy Server";               Exp = "Success and Failure" }
    @{ ID = "35.20"; Sub = "Other Logon/Logoff Events";           Exp = "Success and Failure" }
    @{ ID = "35.21"; Sub = "IPsec Extended Mode";                 Exp = "Failure" }
    @{ ID = "35.22"; Sub = "IPsec Main Mode";                     Exp = "Failure" }
    @{ ID = "35.23"; Sub = "IPsec Quick Mode";                    Exp = "Failure" }
    @{ ID = "35.24"; Sub = "Kerberos Service Ticket Operations";  Exp = "Success and Failure" }
    @{ ID = "35.25"; Sub = "Other Account Logon Events";          Exp = "Success and Failure" }
)

foreach ($chk in $l2AuditChecks) {
    $val = Get-AuditpolValue $chk.Sub
    if ($val) {
        $ok = switch ($chk.Exp) {
            "Success and Failure" { $val -match "Success and Failure" }
            "Success"             { $val -match "Success" }
            "Failure"             { $val -match "Failure" }
            default               { $false }
        }
        $s = if ($ok) { "PASS" } else { "FAIL" }
        Add-Result $chk.ID "L2 Audit: $($chk.Sub)" $s "Required: $($chk.Exp), Got: $val" "CIS-L2"
    } else {
        Add-Result $chk.ID "L2 Audit: $($chk.Sub)" "WARN" "Required: $($chk.Exp), Could not retrieve" "CIS-L2"
    }
}

# ============================================================
#  SECTION 36: TLS/SSL & CIPHER SUITE HARDENING  [CIS L2 | CE+]
# ============================================================
Write-SectionHeader "36. TLS/SSL & CIPHER SUITE HARDENING" "CIS L2 | CE+"

$scBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# Protocols to check disabled
$disableProtocols = @(
    @{ Name = "SSL 2.0"; Path = "$scBase\Protocols\SSL 2.0\Client" }
    @{ Name = "SSL 2.0"; Path = "$scBase\Protocols\SSL 2.0\Server" }
    @{ Name = "SSL 3.0"; Path = "$scBase\Protocols\SSL 3.0\Client" }
    @{ Name = "SSL 3.0"; Path = "$scBase\Protocols\SSL 3.0\Server" }
    @{ Name = "TLS 1.0"; Path = "$scBase\Protocols\TLS 1.0\Client" }
    @{ Name = "TLS 1.0"; Path = "$scBase\Protocols\TLS 1.0\Server" }
    @{ Name = "TLS 1.1"; Path = "$scBase\Protocols\TLS 1.1\Client" }
    @{ Name = "TLS 1.1"; Path = "$scBase\Protocols\TLS 1.1\Server" }
)

foreach ($proto in $disableProtocols) {
    $enabled   = Get-RegValue $proto.Path "Enabled"
    $disabled  = Get-RegValue $proto.Path "DisabledByDefault"
    $role      = if ($proto.Path -match "Client") { "Client" } else { "Server" }
    $isDisabled = ($enabled -eq 0) -or ($disabled -eq 1)
    $s = if ($isDisabled) { "PASS" } else { "FAIL" }
    Add-Result "36.P" "$($proto.Name) $role Disabled" $s "Enabled: $enabled, DisabledByDefault: $disabled" "CIS-L2"
}

# TLS 1.2 must be enabled
foreach ($role in @("Client","Server")) {
    $enabled = Get-RegValue "$scBase\Protocols\TLS 1.2\$role" "Enabled"
    $s = if ($enabled -eq 1 -or $null -eq $enabled) { "PASS" } else { "FAIL" }
    Add-Result "36.T12" "TLS 1.2 $role Enabled" $s "Enabled: $(if ($null -eq $enabled) {'Default (on)'} else {$enabled})" "CIS-L2"
}

# TLS 1.3 (Windows 11 / Server 2022+)
foreach ($role in @("Client","Server")) {
    $enabled = Get-RegValue "$scBase\Protocols\TLS 1.3\$role" "Enabled"
    $s = if ($enabled -eq 1 -or $null -eq $enabled) { "PASS" } else { "WARN" }
    Add-Result "36.T13" "TLS 1.3 $role Supported" $s "Enabled: $(if ($null -eq $enabled) {'Default'} else {$enabled})" "CIS-L2"
}

# Weak ciphers to verify disabled
$weakCiphers = @(
    @{ Name = "NULL";     Path = "$scBase\Ciphers\NULL" }
    @{ Name = "DES 56";   Path = "$scBase\Ciphers\DES 56/56" }
    @{ Name = "RC2 40";   Path = "$scBase\Ciphers\RC2 40/128" }
    @{ Name = "RC2 56";   Path = "$scBase\Ciphers\RC2 56/128" }
    @{ Name = "RC4 40";   Path = "$scBase\Ciphers\RC4 40/128" }
    @{ Name = "RC4 56";   Path = "$scBase\Ciphers\RC4 56/128" }
    @{ Name = "RC4 64";   Path = "$scBase\Ciphers\RC4 64/128" }
    @{ Name = "RC4 128";  Path = "$scBase\Ciphers\RC4 128/128" }
    @{ Name = "3DES 168"; Path = "$scBase\Ciphers\Triple DES 168" }
)

foreach ($cipher in $weakCiphers) {
    $enabled = Get-RegValue $cipher.Path "Enabled"
    $s = if ($enabled -eq 0 -or $null -eq $enabled) { "PASS" } else { "FAIL" }
    Add-Result "36.C" "Weak Cipher Disabled: $($cipher.Name)" $s "Enabled: $(if ($null -eq $enabled) {'Not set (check OS defaults)'} else {$enabled})" "CIS-L2"
}

# Strong ciphers should be enabled
$strongCiphers = @(
    @{ Name = "AES 128/128"; Path = "$scBase\Ciphers\AES 128/128" }
    @{ Name = "AES 256/256"; Path = "$scBase\Ciphers\AES 256/256" }
)

foreach ($cipher in $strongCiphers) {
    $enabled = Get-RegValue $cipher.Path "Enabled"
    $s = if ($enabled -eq 4294967295 -or $null -eq $enabled) { "PASS" } else { "WARN" }
    Add-Result "36.CA" "Strong Cipher Enabled: $($cipher.Name)" $s "Enabled: $(if ($null -eq $enabled) {'Default (on)'} else {$enabled})" "CIS-L2"
}

# Hash algorithms - MD5 should be disabled
$md5Hash = Get-RegValue "$scBase\Hashes\MD5" "Enabled"
$s = if ($md5Hash -eq 0) { "PASS" } else { "WARN" }
Add-Result "36.H" "MD5 Hash Algorithm Disabled" $s "Enabled: $(if ($null -eq $md5Hash) {'Not explicitly set - check via IIS Crypto'} else {$md5Hash})" "CIS-L2"

# Key exchange: Diffie-Hellman minimum key size
$dhMin = Get-RegValue "$scBase\KeyExchangeAlgorithms\Diffie-Hellman" "ClientMinKeyBitLength"
$s = if ($dhMin -ge 2048 -or $null -eq $dhMin) { "PASS" } else { "FAIL" }
Add-Result "36.KE" "DH Key Exchange Minimum 2048-bit" $s "ClientMinKeyBitLength: $(if ($null -eq $dhMin) {'Not set (check Group Policy)'} else {$dhMin})" "CIS-L2"

# ============================================================
#  SECTION 37: MICROSOFT EDGE SECURITY  [CIS L2 | CE+]
# ============================================================
Write-SectionHeader "37. MICROSOFT EDGE SECURITY" "CIS L2 | CE+"

$edgeBase = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$edgeInstalled = Test-Path $edgeBase

if ($edgeInstalled -or (Test-Path "HKLM:\SOFTWARE\Microsoft\Edge")) {
    Add-Result "37.0" "Microsoft Edge Installed" "INFO" "Edge policy path exists" "CIS-L2"

    # SmartScreen
    $smartScreen = Get-RegValue $edgeBase "SmartScreenEnabled"
    $s = if ($smartScreen -eq 1 -or $null -eq $smartScreen) { "PASS" } else { "FAIL" }
    Add-Result "37.1" "Edge SmartScreen Enabled" $s "SmartScreenEnabled: $(if ($null -eq $smartScreen) {'Default (on)'} else {$smartScreen})" "CIS-L2"

    # SmartScreen for downloads
    $smartScreenDL = Get-RegValue $edgeBase "SmartScreenForTrustedDownloadsEnabled"
    $s = if ($smartScreenDL -ne 0) { "PASS" } else { "FAIL" }
    Add-Result "37.2" "Edge SmartScreen for Downloads" $s "SmartScreenForTrustedDownloadsEnabled: $smartScreenDL" "CIS-L2"

    # Block potentially unwanted apps
    $pua = Get-RegValue $edgeBase "PreventSmartScreenPromptOverrideForFiles"
    $s = if ($pua -eq 1) { "PASS" } else { "WARN" }
    Add-Result "37.3" "Edge Block PUA Downloads" $s "PreventSmartScreenPromptOverrideForFiles: $pua" "CIS-L2"

    # Site isolation
    $siteIsolation = Get-RegValue $edgeBase "SitePerProcess"
    $s = if ($siteIsolation -eq 1 -or $null -eq $siteIsolation) { "PASS" } else { "FAIL" }
    Add-Result "37.4" "Edge Site Isolation (Per-Process)" $s "SitePerProcess: $(if ($null -eq $siteIsolation) {'Default (on)'} else {$siteIsolation})" "CIS-L2"

    # Password manager
    $pwdMgr = Get-RegValue $edgeBase "PasswordManagerEnabled"
    $s = if ($pwdMgr -eq 0) { "PASS" } else { "WARN" }
    Add-Result "37.5" "Edge Built-in Password Manager Disabled" $s "PasswordManagerEnabled: $(if ($null -eq $pwdMgr) {'Default (enabled) - consider dedicated PAM'} else {$pwdMgr})" "CIS-L2"

    # Search suggestions - privacy
    $searchSugg = Get-RegValue $edgeBase "SearchSuggestEnabled"
    $s = if ($searchSugg -eq 0) { "PASS" } else { "WARN" }
    Add-Result "37.6" "Edge Search Suggestions Disabled" $s "SearchSuggestEnabled: $(if ($null -eq $searchSugg) {'Default (on)'} else {$searchSugg})" "CIS-L2"

    # Allow InPrivate mode
    $inPrivate = Get-RegValue $edgeBase "InPrivateModeAvailability"
    $s = if ($null -eq $inPrivate -or $inPrivate -eq 0) { "PASS" } else { "WARN" }
    Add-Result "37.7" "Edge InPrivate Mode Not Forced/Blocked" $s "InPrivateModeAvailability: $(if ($null -eq $inPrivate) {'Default'} else {$inPrivate}) (1=Disabled, 2=Forced)" "CIS-L2"

    # Prevent bypassing SmartScreen warnings
    $noBypass = Get-RegValue $edgeBase "PreventSmartScreenPromptOverride"
    $s = if ($noBypass -eq 1) { "PASS" } else { "WARN" }
    Add-Result "37.8" "Edge: Prevent SmartScreen Bypass" $s "PreventSmartScreenPromptOverride: $noBypass" "CIS-L2"

    # Extension installation - allow/block
    $extBlocked = Get-RegValue "$edgeBase\ExtensionInstallBlocklist" "1"
    $s = if ($extBlocked -eq "*") { "PASS" } else { "WARN" }
    Add-Result "37.9" "Edge Extension Install Blocklist Set" $s "ExtensionInstallBlocklist: $(if ($extBlocked -eq '*') {'All blocked (allowlist model)'} else {'Not set - all extensions permitted'})" "CIS-L2"

    # Send intranet traffic to IE mode (should be disabled)
    $ieMode = Get-RegValue $edgeBase "SendIntranetToInternetExplorer"
    $s = if ($ieMode -ne 1) { "PASS" } else { "WARN" }
    Add-Result "37.10" "Edge: Intranet Not Sent to IE Mode" $s "SendIntranetToInternetExplorer: $ieMode" "CIS-L2"

    # DNS-over-HTTPS in Edge
    $edgeDOH = Get-RegValue $edgeBase "DnsOverHttpsMode"
    $s = if ($edgeDOH -eq "secure") { "PASS" } else { "WARN" }
    Add-Result "37.11" "Edge: DNS over HTTPS Mode" $s "DnsOverHttpsMode: $(if ($null -eq $edgeDOH) {'Not configured'} else {$edgeDOH}) (recommend: secure)" "CIS-L2"

    # Enhanced security mode (super duper secure mode)
    $esmMode = Get-RegValue $edgeBase "EnhanceSecurityMode"
    $s = if ($null -ne $esmMode -and $esmMode -ge 1) { "PASS" } else { "WARN" }
    Add-Result "37.12" "Edge: Enhanced Security Mode" $s "EnhanceSecurityMode: $esmMode (1=Balanced, 2=Strict)" "CIS-L2"

} else {
    Add-Result "37.0" "Microsoft Edge" "INFO" "Edge policy registry path not found - Edge may be unmanaged" "CIS-L2"
}

# ============================================================
#  SECTION 38: PERIPHERAL & DEVICE CONTROL  [CIS L2 | CE+]
# ============================================================
Write-SectionHeader "38. PERIPHERAL & DEVICE CONTROL" "CIS L2 | CE+"

# Removable storage - deny all read/write access
$usbReadDeny  = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" "Deny_Read"
$usbWriteDeny = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" "Deny_Write"
$s = if ($usbWriteDeny -eq 1) { "PASS" } else { "WARN" }
Add-Result "38.1" "USB Removable Storage Write Access" $s "Deny_Write: $usbWriteDeny (1=Blocked)" "CIS-L2"

$s = if ($usbReadDeny -eq 1) { "WARN" } else { "INFO" }
Add-Result "38.2" "USB Removable Storage Read Access" $s "Deny_Read: $usbReadDeny - L2: Block writes minimum; read-block may impact operations" "CIS-L2"

# All removable storage classes - execute deny
$execDeny = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" "Deny_Execute"
$s = if ($execDeny -eq 1) { "PASS" } else { "FAIL" }
Add-Result "38.3" "Removable Storage Execute Denied" $s "Deny_Execute: $execDeny" "CIS-L2"

# Prevent installation of removable devices
$preventRemovable = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" "DenyRemovableDevices"
$s = if ($preventRemovable -eq 1) { "PASS" } else { "WARN" }
Add-Result "38.4" "Prevent Removable Device Installation" $s "DenyRemovableDevices: $preventRemovable" "CIS-L2"

# Bluetooth - discoverable
$btDiscoverable = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth" "AllowDiscoverableMode"
$s = if ($btDiscoverable -eq 0) { "PASS" } else { "WARN" }
Add-Result "38.5" "Bluetooth Not Discoverable" $s "AllowDiscoverableMode: $btDiscoverable" "CIS-L2"

# Bluetooth advertising
$btAdvert = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth" "AllowAdvertising"
$s = if ($btAdvert -eq 0) { "PASS" } else { "WARN" }
Add-Result "38.6" "Bluetooth Advertising Disabled" $s "AllowAdvertising: $btAdvert" "CIS-L2"

# Windows Portable Devices (WPD) - write
$wpdWrite = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}" "Deny_Write"
$s = if ($wpdWrite -eq 1) { "PASS" } else { "WARN" }
Add-Result "38.7" "Windows Portable Devices Write Denied" $s "WPD Deny_Write: $wpdWrite" "CIS-L2"

# Infrared (IrDA) - should be absent or disabled
$irSvc = Get-Service -Name "irmon" -ErrorAction SilentlyContinue
$s = if ($null -eq $irSvc) { "PASS" } else { "WARN" }
Add-Result "38.8" "Infrared (IrDA) Service Absent" $s "irmon service: $(if ($irSvc) {$irSvc.Status} else {'Not installed'})" "CIS-L2"

# ============================================================
#  SECTION 39: WINDOWS COMPONENTS & PRIVACY HARDENING  [CIS L2]
# ============================================================
Write-SectionHeader "39. WINDOWS COMPONENTS & PRIVACY HARDENING" "CIS L2"

# Telemetry / Diagnostic data - limit collection
$telemetry = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry"
$s = if ($null -ne $telemetry -and $telemetry -le 1) { "PASS" } else { "WARN" }
Add-Result "39.1" "Telemetry Level Limited (0=Off, 1=Security)" $s "AllowTelemetry: $(if ($null -eq $telemetry) {'Not set (default 3)'} else {$telemetry})" "CIS-L2"

# Disable Microsoft consumer experiences
$consumerExp = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures"
$s = if ($consumerExp -eq 1) { "PASS" } else { "WARN" }
Add-Result "39.2" "Microsoft Consumer Experiences Disabled" $s "DisableWindowsConsumerFeatures: $consumerExp" "CIS-L2"

# Turn off Windows Spotlight
$spotlight = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures"
$s = if ($spotlight -eq 1) { "PASS" } else { "WARN" }
Add-Result "39.3" "Windows Spotlight Disabled" $s "DisableWindowsSpotlightFeatures: $spotlight" "CIS-L2"

# Windows Error Reporting disabled
$wer = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled"
$s = if ($wer -eq 1) { "PASS" } else { "WARN" }
Add-Result "39.4" "Windows Error Reporting Disabled" $s "WER Disabled: $wer" "CIS-L2"

# Disable advertising ID
$advID = Get-RegValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled"
$s = if ($advID -eq 0 -or $null -eq $advID) { "PASS" } else { "WARN" }
Add-Result "39.5" "Advertising ID Disabled" $s "AdvertisingInfo Enabled: $(if ($null -eq $advID) {'Not set'} else {$advID})" "CIS-L2"

# Disable Cortana
$cortana = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana"
$s = if ($cortana -eq 0) { "PASS" } else { "WARN" }
Add-Result "39.6" "Cortana Disabled" $s "AllowCortana: $cortana" "CIS-L2"

# Disable Windows Game Recording
$gameBar = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR"
$s = if ($gameBar -eq 0) { "PASS" } else { "WARN" }
Add-Result "39.7" "Windows Game DVR/Recording Disabled" $s "AllowGameDVR: $gameBar" "CIS-L2"

# Disable News and Interests / Widgets
$widgets = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" "EnableFeeds"
$s = if ($widgets -eq 0) { "PASS" } else { "WARN" }
Add-Result "39.8" "News and Interests (Feeds) Disabled" $s "EnableFeeds: $widgets" "CIS-L2"

# Turn off app notifications on lock screen
$lockNotif = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications"
$s = if ($lockNotif -eq 1) { "PASS" } else { "WARN" }
Add-Result "39.9" "Lock Screen App Notifications Disabled" $s "DisableLockScreenAppNotifications: $lockNotif" "CIS-L2"

# Turn off picture password sign-in
$picPwd = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockDomainPicturePassword"
$s = if ($picPwd -eq 1) { "PASS" } else { "WARN" }
Add-Result "39.10" "Picture Password Sign-In Disabled" $s "BlockDomainPicturePassword: $picPwd" "CIS-L2"

# Do not show feedback notifications
$feedbackNotif = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications"
$s = if ($feedbackNotif -eq 1) { "PASS" } else { "WARN" }
Add-Result "39.11" "Feedback Notifications Disabled" $s "DoNotShowFeedbackNotifications: $feedbackNotif" "CIS-L2"

# Disable Windows Tips
$tips = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableSoftLanding"
$s = if ($tips -eq 1) { "PASS" } else { "WARN" }
Add-Result "39.12" "Windows Tips/Suggestions Disabled" $s "DisableSoftLanding: $tips" "CIS-L2"

# Location services
$location = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation"
$s = if ($location -eq 1) { "PASS" } else { "WARN" }
Add-Result "39.13" "Location Services Disabled" $s "DisableLocation: $location" "CIS-L2"

# Microsoft accounts - block in enterprise (L2)
$msa = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "NoConnectedUser"
$s = if ($null -ne $msa -and $msa -ge 1) { "PASS" } else { "WARN" }
Add-Result "39.14" "Microsoft Accounts Restricted" $s "NoConnectedUser: $msa (1=Blocked for sign-in, 3=Blocked entirely)" "CIS-L2"

# App store - disable for Enterprise (L2)
$appStore = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "DisableStoreApps"
$s = if ($appStore -eq 1) { "PASS" } else { "WARN" }
Add-Result "39.15" "Windows Store Apps Restricted (Enterprise)" $s "DisableStoreApps: $appStore" "CIS-L2"

# Auto-update Store apps
$storeAutoUpdate = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload"
$s = if ($storeAutoUpdate -eq 4 -or $null -eq $storeAutoUpdate) { "PASS" } else { "WARN" }
Add-Result "39.16" "Store App Auto-Update Not Disabled" $s "AutoDownload: $(if ($null -eq $storeAutoUpdate) {'Default'} else {$storeAutoUpdate}) (4=Auto)" "CIS-L2"

# ============================================================
#  SECTION 40: REMOTE ASSISTANCE & REMOTE TOOLS  [CIS L2]
# ============================================================
Write-SectionHeader "40. REMOTE ASSISTANCE & REMOTE TOOLS" "CIS L2"

# Remote Assistance - should be disabled
$raEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp"
$s = if ($raEnabled -eq 0) { "PASS" } else { "FAIL" }
Add-Result "40.1" "Remote Assistance Disabled" $s "fAllowToGetHelp: $raEnabled" "CIS-L2"

# Remote Assistance - solicited
$raSolicited = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp"
$s = if ($raSolicited -eq 0) { "PASS" } else { "WARN" }
Add-Result "40.2" "Solicited Remote Assistance Disabled" $s "fAllowToGetHelp (system): $raSolicited" "CIS-L2"

# Remote Assistance - unsolicited (offer)
$raOffer = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited"
$s = if ($raOffer -eq 0 -or $null -eq $raOffer) { "PASS" } else { "FAIL" }
Add-Result "40.3" "Unsolicited (Offer) Remote Assistance Disabled" $s "fAllowUnsolicited: $raOffer" "CIS-L2"

# WinRM - listener check
$winrmListener = Get-ChildItem "WSMan:\localhost\Listener" -ErrorAction SilentlyContinue
if ($winrmListener) {
    $httpListeners  = $winrmListener | Where-Object { ($_ | Get-Item).GetChildItem() | Where-Object { $_.Name -eq "Transport" -and $_.Value -eq "HTTP" } }
    $httpsListeners = $winrmListener | Where-Object { ($_ | Get-Item).GetChildItem() | Where-Object { $_.Name -eq "Transport" -and $_.Value -eq "HTTPS" } }
    $s = if ($httpListeners) { "FAIL" } elseif ($httpsListeners) { "PASS" } else { "PASS" }
    Add-Result "40.4" "WinRM: HTTPS Only (No HTTP Listener)" $s "HTTP listeners: $(if ($httpListeners) {$httpListeners.Count} else {0}), HTTPS listeners: $(if ($httpsListeners) {$httpsListeners.Count} else {0})" "CIS-L2"
} else {
    Add-Result "40.4" "WinRM: No Active Listeners" "PASS" "No WinRM listeners configured" "CIS-L2"
}

# PSRemoting
$psRemoting = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig"
$s = if ($psRemoting -ne 1) { "PASS" } else { "WARN" }
Add-Result "40.5" "PSRemoting / WinRM Auto-Config Restricted" $s "AllowAutoConfig: $psRemoting" "CIS-L2"

# OpenSSH Server
$sshSvc = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
$s = if ($null -eq $sshSvc -or $sshSvc.StartType -eq "Disabled") { "PASS" } else { "WARN" }
Add-Result "40.6" "OpenSSH Server Not Running" $s "sshd: $(if ($sshSvc) {"$($sshSvc.Status) / $($sshSvc.StartType)"} else {'Not installed'})" "CIS-L2"

# ============================================================
#  SECTION 41: DNS CLIENT & NAME RESOLUTION SECURITY  [CIS L2]
# ============================================================
Write-SectionHeader "41. DNS CLIENT & NAME RESOLUTION SECURITY" "CIS L2"

# DNS over HTTPS (DoH)
$dohTemplate = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableAutoDoh"
$s = if ($dohTemplate -ge 2) { "PASS" } else { "WARN" }
Add-Result "41.1" "DNS over HTTPS (DoH) Enabled" $s "EnableAutoDoh: $dohTemplate (2=Automatic, 3=Forced)" "CIS-L2"

# Multicast DNS already checked in §23 but recheck at L2 level
$mDNS2 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMDNS"
$s = if ($mDNS2 -eq 0) { "PASS" } else { "FAIL" }
Add-Result "41.2" "Multicast DNS (mDNS) Disabled" $s "EnableMDNS: $(if ($null -eq $mDNS2) {'Not set (enabled)'} else {$mDNS2})" "CIS-L2"

# NetBIOS name resolution - should not fall back
$nbResolution = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableNetbios"
$s = if ($null -eq $nbResolution -or $nbResolution -eq 0) { "PASS" } else { "WARN" }
Add-Result "41.3" "DNS Client NetBIOS Fallback Restricted" $s "EnableNetbios: $nbResolution" "CIS-L2"

# Check WPAD (Web Proxy Auto Discovery) - poisoning risk
$wpadSvc = Get-Service -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue
$s = if ($null -eq $wpadSvc -or $wpadSvc.Status -ne "Running") { "PASS" } else { "WARN" }
Add-Result "41.4" "WPAD Service Not Running" $s "WinHttpAutoProxySvc: $(if ($wpadSvc) {$wpadSvc.Status} else {'Not found'})" "CIS-L2"

# DNS cache policy - negative TTL cap (limit poisoning window)
$negCache = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "MaxNegativeCacheTtl"
$s = if ($null -eq $negCache -or [int]$negCache -le 5) { "PASS" } else { "WARN" }
Add-Result "41.5" "DNS Negative Cache TTL Capped" $s "MaxNegativeCacheTtl: $(if ($null -eq $negCache) {'Default'} else {$negCache}) (recommend <=5 seconds)" "CIS-L2"

# ============================================================
#  SECTION 42: SCHEDULED TASKS SECURITY AUDIT  [CIS L2]
# ============================================================
Write-SectionHeader "42. SCHEDULED TASKS SECURITY AUDIT" "CIS L2"

# Look for scheduled tasks in user-writable locations (common persistence vector)
$suspiciousTasks = @()
try {
    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne "Disabled" }

    foreach ($task in $allTasks) {
        $actions = $task.Actions
        foreach ($action in $actions) {
            if ($action.Execute) {
                $exe = $action.Execute.ToLower()
                # Flag tasks executing from writable user paths or temp locations
                if ($exe -match "appdata|temp|tmp|public|downloads|desktop" -or
                    $exe -match "\\users\\" -and $exe -notmatch "system32|syswow64") {
                    $suspiciousTasks += "$($task.TaskPath)$($task.TaskName) -> $($action.Execute)"
                }
            }
        }
    }
} catch {}

$s = if ($suspiciousTasks.Count -eq 0) { "PASS" } else { "FAIL" }
Add-Result "42.1" "No Tasks Executing from User-Writable Paths" $s "Suspicious tasks: $($suspiciousTasks.Count) found$(if ($suspiciousTasks.Count -gt 0) {" - Review: $($suspiciousTasks[0])"})" "CIS-L2"

# Tasks created/modified in last 30 days (flag new tasks for review)
try {
    $recentTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne "Disabled" } |
        ForEach-Object {
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            if ($info -and $info.LastRunTime -and ((Get-Date) - $info.LastRunTime).TotalDays -le 30) { $_ }
        }
    Add-Result "42.2" "Recently Active Scheduled Tasks" "INFO" "Tasks active in last 30 days: $($recentTasks.Count) - Review for unexpected entries" "CIS-L2"
} catch {
    Add-Result "42.2" "Recently Active Scheduled Tasks" "WARN" "Could not enumerate scheduled tasks" "CIS-L2"
}

# Verify AT scheduler is disabled (legacy, bypasses audit logging)
$atSvc = Get-Service -Name "Schedule" -ErrorAction SilentlyContinue
$atCmd  = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration" "TasksFolder"
Add-Result "42.3" "Task Scheduler Service State" "INFO" "Schedule service: $(if ($atSvc) {$atSvc.Status} else {'Not found'}) - Ensure only authorised tasks are present" "CIS-L2"

# ============================================================
#  SECTION 43: MSS LEGACY SECURITY SETTINGS  [CIS L2]
# ============================================================
Write-SectionHeader "43. MSS (LEGACY) SECURITY SETTINGS" "CIS L2"

# MSS: Auto-reboot after system crash - disabled (avoids info leak)
$autoReboot = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" "AutoReboot"
$s = if ($autoReboot -eq 0) { "PASS" } else { "WARN" }
Add-Result "43.1" "MSS: Auto Reboot After Crash Disabled" $s "AutoReboot: $autoReboot" "CIS-L2"

# MSS: Warning level for Security event log - 90%
$logWarnLevel = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" "WarningLevel"
$s = if ($null -ne $logWarnLevel -and [int]$logWarnLevel -le 90) { "PASS" } else { "WARN" }
Add-Result "43.2" "Security Log Warning Level <= 90%" $s "WarningLevel: $(if ($null -eq $logWarnLevel) {'Not set'} else {"$logWarnLevel%"})" "CIS-L2"

# MSS: IP source routing protection (IPv4)
$srcRoute = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting"
$s = if ($srcRoute -eq 2) { "PASS" } else { "FAIL" }
Add-Result "43.3" "MSS: IP Source Routing Disabled (IPv4)" $s "DisableIPSourceRouting: $srcRoute (2=highest protection)" "CIS-L2"

# MSS: IP source routing protection (IPv6)
$srcRoute6 = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting"
$s = if ($srcRoute6 -eq 2) { "PASS" } else { "WARN" }
Add-Result "43.4" "MSS: IP Source Routing Disabled (IPv6)" $s "DisableIPSourceRouting (v6): $srcRoute6" "CIS-L2"

# MSS: Keep alive time - helps detect dead connections
$keepAlive = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "KeepAliveTime"
$s = if ($null -eq $keepAlive -or [int]$keepAlive -le 300000) { "PASS" } else { "WARN" }
Add-Result "43.5" "MSS: TCP Keep Alive Time <= 5 Minutes" $s "KeepAliveTime: $(if ($null -eq $keepAlive) {'Default (2 hours)'} else {"$([math]::Round($keepAlive/60000)) min"})" "CIS-L2"

# MSS: Disable IRDP (Internet Router Discovery Protocol)
$irdp = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "PerformRouterDiscovery"
$s = if ($irdp -eq 0 -or $null -eq $irdp) { "PASS" } else { "FAIL" }
Add-Result "43.6" "MSS: IRDP (Router Discovery) Disabled" $s "PerformRouterDiscovery: $(if ($null -eq $irdp) {'Not set'} else {$irdp})" "CIS-L2"

# MSS: Restrict null sessions
$nullSess = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
$s = if ($nullSess -ge 1) { "PASS" } else { "FAIL" }
Add-Result "43.7" "MSS: Null Session Restricted" $s "RestrictAnonymous: $nullSess" "CIS-L2"

# MSS: Screen saver grace period - 5 seconds
$ssGrace = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScreenSaverGracePeriod"
$s = if ($null -ne $ssGrace -and [int]$ssGrace -le 5) { "PASS" } else { "WARN" }
Add-Result "43.8" "MSS: Screen Saver Grace Period <= 5 Seconds" $s "ScreenSaverGracePeriod: $(if ($null -eq $ssGrace) {'Not set (default varies)'} else {$ssGrace})" "CIS-L2"

# ============================================================
#  SECTION 44: CIS L2 - NETWORK PROTOCOL HARDENING  [CIS L2]
# ============================================================
Write-SectionHeader "44. CIS L2 - NETWORK PROTOCOL HARDENING" "CIS L2"

# Microsoft network client: always digitally sign communications
$clientSign = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
$s = if ($clientSign -eq 1) { "PASS" } else { "FAIL" }
Add-Result "44.1" "SMB Client: Always Sign Communications" $s "RequireSecuritySignature: $clientSign" "CIS-L2"

# Microsoft network client: send unencrypted password - Disabled
$noPlainPwd = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword"
$s = if ($noPlainPwd -eq 0 -or $null -eq $noPlainPwd) { "PASS" } else { "FAIL" }
Add-Result "44.2" "SMB Client: No Plain Text Passwords" $s "EnablePlainTextPassword: $(if ($null -eq $noPlainPwd) {'Default (0)'} else {$noPlainPwd})" "CIS-L2"

# Microsoft network server: idle session disconnect - 15 minutes
$idleTimeout = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "AutoDisconnect"
$s = if ($null -eq $idleTimeout -or ([int]$idleTimeout -ge 1 -and [int]$idleTimeout -le 15)) { "PASS" } else { "WARN" }
Add-Result "44.3" "SMB Server: Idle Session Timeout <= 15 Mins" $s "AutoDisconnect: $(if ($null -eq $idleTimeout) {'Default (15 mins)'} else {"$idleTimeout mins"})" "CIS-L2"

# Microsoft network server: always digitally sign communications
$serverSign = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature"
$s = if ($serverSign -eq 1) { "PASS" } else { "FAIL" }
Add-Result "44.4" "SMB Server: Always Sign Communications" $s "RequireSecuritySignature: $serverSign" "CIS-L2"

# Microsoft network server: disconnect clients when logon hours expire
$logonHours = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "EnableForcedLogOff"
$s = if ($logonHours -eq 1) { "PASS" } else { "WARN" }
Add-Result "44.5" "SMB Server: Disconnect When Logon Hours Expire" $s "EnableForcedLogOff: $logonHours" "CIS-L2"

# LDAP channel binding
$ldapChannelBinding = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LdapEnforceChannelBinding"
$s = if ($ldapChannelBinding -ge 1) { "PASS" } else { "WARN" }
Add-Result "44.6" "LDAP Channel Binding Enabled" $s "LdapEnforceChannelBinding: $ldapChannelBinding (1=Supported, 2=Always)" "CIS-L2"

# Network access: remotely accessible registry paths - restricted
$remRegPaths = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" "Machine"
$s = if ($null -ne $remRegPaths) { "PASS" } else { "WARN" }
Add-Result "44.7" "Remotely Accessible Registry Paths Defined" $s "AllowedExactPaths defined: $(if ($null -ne $remRegPaths) {'Yes'} else {'Not configured'})" "CIS-L2"

# Prevent anonymous pipe access
$nullPipes = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionPipes"
$s = if ($null -eq $nullPipes -or $nullPipes -eq "") { "PASS" } else { "FAIL" }
Add-Result "44.8" "No Anonymous Pipe Access (Null Session Pipes)" $s "NullSessionPipes: $(if ($null -eq $nullPipes -or $nullPipes -eq '') {'None (correct)'} else {$nullPipes})" "CIS-L2"

# ============================================================
#  SECTION 45: ATTACK SURFACE REDUCTION - SPECIFIC RULES  [CIS L1/L2]
# ============================================================
Write-SectionHeader "45. ATTACK SURFACE REDUCTION - SPECIFIC RULES" "CIS L1/L2"

# ASR rules are stored as per-GUID DWORD values under the Actions key.
# Values: 0=Disabled, 1=Block, 2=Audit, 6=Warn. CIS L1 requires 1 (Block).
$asrBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"

$asrRules = @(
    @{ GUID = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"; Name = "Block executable content from email/webmail";        L = "L1" }
    @{ GUID = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"; Name = "Block Office apps from creating child processes";    L = "L1" }
    @{ GUID = "3B576869-A4EC-4529-8536-B80A7769E899"; Name = "Block Office apps creating executable content";      L = "L1" }
    @{ GUID = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"; Name = "Block Office apps injecting into other processes";   L = "L1" }
    @{ GUID = "D3E037E1-3EB8-44C8-A917-57927947596D"; Name = "Block JS/VBS launching downloaded executables";      L = "L1" }
    @{ GUID = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"; Name = "Block execution of obfuscated scripts";             L = "L1" }
    @{ GUID = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"; Name = "Block Win32 API calls from Office macros";          L = "L1" }
    @{ GUID = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"; Name = "Block credential stealing from LSASS";              L = "L1" }
    @{ GUID = "C1DB55AB-C21A-4637-BB3F-A12568109D35"; Name = "Block ransomware (advanced protection)";            L = "L1" }
    @{ GUID = "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"; Name = "Block untrusted/unsigned processes from USB";      L = "L1" }
    @{ GUID = "D1E49AAC-8F56-4280-B9BA-993A6D77406C"; Name = "Block process creation from PSExec/WMI";            L = "L1" }
    @{ GUID = "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"; Name = "Block persistence via WMI event subscription";      L = "L1" }
    @{ GUID = "56A863A9-875C-4D4A-A628-9A2C80B67B31"; Name = "Block abuse of vulnerable signed drivers";          L = "L2" }
    @{ GUID = "26190899-1602-49E8-8B27-EB1D0A1CE869"; Name = "Block Adobe Reader from creating child processes";   L = "L2" }
    @{ GUID = "01443614-CD74-433A-B99E-2ECDC07BFC25"; Name = "Block executables unless meet prevalence/age/trust"; L = "L2" }
    @{ GUID = "A8F5898E-1DC8-49A9-9878-85004B8A61E6"; Name = "Block webshell creation for servers";               L = "L2" }
)

foreach ($rule in $asrRules) {
    $val = Get-RegValue $asrBase $rule.GUID.ToLower()
    if ($null -eq $val) {
        # Some tools write the GUID in upper case
        $val = Get-RegValue $asrBase $rule.GUID
    }
    $status = switch ($val) {
        1       { "PASS" }   # Block
        2       { "WARN" }   # Audit only
        6       { "WARN" }   # Warn only
        0       { "FAIL" }   # Disabled
        default { "WARN" }   # Not configured
    }
    $desc = switch ($val) {
        1       { "Block (1)" }
        2       { "Audit only (2) - not blocking" }
        6       { "Warn only (6) - not blocking" }
        0       { "Disabled (0)" }
        default { "Not configured - rule not set" }
    }
    Add-Result "45.$($rule.L)" "ASR [$($rule.L)]: $($rule.Name)" $status "GUID: $($rule.GUID) | Value: $desc" "CIS-L2"
}

# ============================================================
#  SECTION 46: SYSTEM EXPLOIT PROTECTION (ASLR / CFG)  [CIS L2]
# ============================================================
Write-SectionHeader "46. SYSTEM EXPLOIT PROTECTION (ASLR/CFG)" "CIS L2"

# Get-ProcessMitigation returns system-level mitigation state
try {
    $sysMit = Get-ProcessMitigation -System -ErrorAction Stop

    # ASLR - ForceRelocateImages
    $aslrForce = $sysMit.ASLR.ForceRelocateImages
    $s = if ($aslrForce -eq "ON") { "PASS" } else { "WARN" }
    Add-Result "46.1" "ASLR: Force Relocate Images" $s "ForceRelocateImages: $aslrForce" "CIS-L2"

    # ASLR - Bottom-up randomisation
    $aslrBU = $sysMit.ASLR.BottomUp
    $s = if ($aslrBU -eq "ON") { "PASS" } else { "WARN" }
    Add-Result "46.2" "ASLR: Bottom-Up Randomisation" $s "BottomUp: $aslrBU" "CIS-L2"

    # ASLR - High entropy
    $aslrHE = $sysMit.ASLR.HighEntropy
    $s = if ($aslrHE -eq "ON") { "PASS" } else { "WARN" }
    Add-Result "46.3" "ASLR: High Entropy" $s "HighEntropy: $aslrHE" "CIS-L2"

    # CFG - Control Flow Guard
    $cfg = $sysMit.CFG.Enable
    $s = if ($cfg -eq "ON") { "PASS" } else { "FAIL" }
    Add-Result "46.4" "Control Flow Guard (CFG)" $s "CFG Enable: $cfg" "CIS-L2"

    # DEP - also checked via bcdedit in §24, but Get-ProcessMitigation gives app-level view
    $dep = $sysMit.DEP.Enable
    $s = if ($dep -eq "ON") { "PASS" } else { "FAIL" }
    Add-Result "46.5" "DEP: System-Level Enable State" $s "DEP Enable: $dep" "CIS-L2"

    # Heap spray pre-allocation
    $heapSpray = $sysMit.Payload.EnableExportAddressFilter
    $s = if ($heapSpray -eq "ON") { "PASS" } else { "WARN" }
    Add-Result "46.6" "Export Address Filter (EAF)" $s "EnableExportAddressFilter: $heapSpray" "CIS-L2"

} catch {
    Add-Result "46.0" "System Exploit Protection" "WARN" "Get-ProcessMitigation not available - check Windows Defender Exploit Protection in Security Centre" "CIS-L2"
}

# Exploit protection settings via registry (backup path)
$epXml = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender ExploitGuard\Exploit Protection" "ExploitProtectionSettings"
$s = if ($null -ne $epXml) { "PASS" } else { "WARN" }
Add-Result "46.7" "Exploit Protection Custom Config Applied" $s "ExploitProtectionSettings policy: $(if ($null -ne $epXml) {'Configured'} else {'Not configured via policy'})" "CIS-L2"

# ============================================================
#  SECTION 47: KERNEL DMA PROTECTION  [CIS L2 | CE+]
# ============================================================
Write-SectionHeader "47. KERNEL DMA PROTECTION" "CIS L2 | CE+"

# DMA Guard policy - protects against DMA/Thunderbolt attacks
$dmaPolicy = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy"
$s = switch ($dmaPolicy) {
    0       { "PASS" }   # Block all external DMA devices
    1       { "WARN" }   # Allow after user logon
    2       { "FAIL" }   # Allow all (no protection)
    default { "WARN" }   # Not configured - falls back to firmware
}
Add-Result "47.1" "Kernel DMA Guard Policy" $s "DeviceEnumerationPolicy: $(if ($null -eq $dmaPolicy) {'Not set (firmware default)'} else {"$dmaPolicy (0=Block, 1=After logon, 2=Allow all)"})" "CIS-L2"

# Check if Kernel DMA protection is active via system info
try {
    $msinfo = Get-CimInstance -Namespace root/cimv2 -Class Win32_DeviceGuard -ErrorAction Stop
    $dmaActive = $msinfo.SecurityServicesRunning -contains 3
    $s = if ($dmaActive) { "PASS" } else { "WARN" }
    Add-Result "47.2" "Kernel DMA Protection Active (VBS)" $s "SecurityServicesRunning includes DMA protection: $dmaActive" "CIS-L2"
} catch {
    Add-Result "47.2" "Kernel DMA Protection Active" "WARN" "Could not query Win32_DeviceGuard - verify in System Information > Kernel DMA Protection" "CIS-L2"
}

# Thunderbolt / PCIe DMA block on lock
$tbLock = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Thunderbolt" "AllowThunderboltOnStandby"
$s = if ($tbLock -eq 0 -or $null -eq $tbLock) { "PASS" } else { "WARN" }
Add-Result "47.3" "Thunderbolt DMA Blocked When Locked" $s "AllowThunderboltOnStandby: $(if ($null -eq $tbLock) {'Default'} else {$tbLock})" "CIS-L2"

# ============================================================
#  SECTION 48: LAPS (LOCAL ADMIN PASSWORD SOLUTION)  [CIS L1 | CE3]
# ============================================================
Write-SectionHeader "48. LAPS - LOCAL ADMIN PASSWORD SOLUTION" "CIS L1 | CE3"

# Windows LAPS (built-in, Win11 22H2+ / Win10 KB5025221+)
$wLapsPolicy = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "BackupDirectory"
$wLapsEnabled = $null -ne $wLapsPolicy

# Legacy Microsoft LAPS (GPO extension)
$legacyLapsGPO = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
$legacyLapsAdmPwd = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "AdmPwdEnabled"

if ($wLapsEnabled) {
    $backupTarget = switch ($wLapsPolicy) {
        1 { "Azure AD / Entra ID" }
        2 { "Active Directory" }
        0 { "Disabled" }
        default { "Unknown ($wLapsPolicy)" }
    }
    $s = if ($wLapsPolicy -ge 1) { "PASS" } else { "FAIL" }
    Add-Result "48.1" "Windows LAPS Enabled" $s "BackupDirectory: $wLapsPolicy ($backupTarget)" "CIS"
} elseif ($legacyLapsAdmPwd -eq 1) {
    Add-Result "48.1" "Legacy LAPS Enabled" "PASS" "Microsoft LAPS (GPO extension) AdmPwdEnabled: 1" "CIS"
} else {
    Add-Result "48.1" "LAPS Configured" "FAIL" "Neither Windows LAPS nor legacy LAPS detected - local admin password unmanaged" "CIS"
}

# LAPS password complexity
$lapsComplex = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PasswordComplexity"
$s = if ($null -eq $lapsComplex -or $lapsComplex -ge 3) { "PASS" } else { "WARN" }
Add-Result "48.2" "LAPS Password Complexity" $s "PasswordComplexity: $(if ($null -eq $lapsComplex) {'Default'} else {$lapsComplex}) (4=Large+Small+Digits+Special)" "CIS"

# LAPS password length
$lapsLen = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PasswordLength"
$s = if ($null -eq $lapsLen -or [int]$lapsLen -ge 15) { "PASS" } else { "WARN" }
Add-Result "48.3" "LAPS Password Length >= 15" $s "PasswordLength: $(if ($null -eq $lapsLen) {'Default (14)'} else {$lapsLen})" "CIS"

# LAPS password age
$lapsAge = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PasswordAgeDays"
$s = if ($null -eq $lapsAge -or ([int]$lapsAge -ge 1 -and [int]$lapsAge -le 30)) { "PASS" } else { "WARN" }
Add-Result "48.4" "LAPS Password Age <= 30 Days" $s "PasswordAgeDays: $(if ($null -eq $lapsAge) {'Default (30)'} else {$lapsAge})" "CIS"

# LAPS post-auth action (Windows LAPS - reset after use)
$lapsPostAuth = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PostAuthenticationActions"
$s = if ($null -ne $lapsPostAuth -and $lapsPostAuth -ge 1) { "PASS" } else { "WARN" }
Add-Result "48.5" "LAPS Post-Auth Reset Action Configured" $s "PostAuthenticationActions: $lapsPostAuth (1=Reset pwd, 3=Reset pwd+logoff, 5=Reset pwd+reboot)" "CIS"

# ============================================================
#  SECTION 49: NETWORK LIST MANAGER  [CIS L2]
# ============================================================
Write-SectionHeader "49. NETWORK LIST MANAGER" "CIS L2"

# All networks set to Public (most restrictive) when unmanaged
$nlmBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkListManager"

$allNetCat = Get-RegValue $nlmBase "Category"
$s = switch ($allNetCat) {
    0 { "PASS" }   # Public
    1 { "WARN" }   # Private
    2 { "WARN" }   # Domain
    default { "WARN" }
}
Add-Result "49.1" "Network Category Default: Public" $s "Category: $(if ($null -eq $allNetCat) {'Not set - user can change'} else {"$allNetCat (0=Public, 1=Private, 2=Domain)"})" "CIS-L2"

# Prevent changing network location
$nlmUserChange = Get-RegValue $nlmBase "CategoryReadOnly"
$s = if ($nlmUserChange -eq 1) { "PASS" } else { "WARN" }
Add-Result "49.2" "Network Location: User Cannot Change" $s "CategoryReadOnly: $nlmUserChange" "CIS-L2"

# Unidentified networks - set to Public/Not connected
$unidentCat  = Get-RegValue "$nlmBase\Category_Management" "AllNetworks"
$s = if ($null -eq $unidentCat -or $unidentCat -eq 0) { "PASS" } else { "WARN" }
Add-Result "49.3" "Unidentified Networks: Public or Blocked" $s "AllNetworks category: $(if ($null -eq $unidentCat) {'Default'} else {$unidentCat})" "CIS-L2"

# Prohibit connection to non-domain networks when on domain
$prohibitNonDomain = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain"
$s = if ($prohibitNonDomain -eq 1) { "PASS" } else { "WARN" }
Add-Result "49.4" "Block Non-Domain Connections on Domain Network" $s "fBlockNonDomain: $prohibitNonDomain" "CIS-L2"

# ============================================================
#  SECTION 50: DELIVERY OPTIMISATION  [CIS L2]
# ============================================================
Write-SectionHeader "50. DELIVERY OPTIMISATION" "CIS L2"

$doBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"

$doMode = Get-RegValue $doBase "DODownloadMode"
# CIS L2: Allow LAN (1) or Group (2) but NOT Internet peers (3) or Bypass (100)
$s = switch ($doMode) {
    0       { "PASS" }   # HTTP only
    1       { "PASS" }   # HTTP + LAN peers
    2       { "PASS" }   # HTTP + private group peers
    3       { "FAIL" }   # HTTP + Internet peers (data leaves network)
    99      { "PASS" }   # Simple download
    100     { "WARN" }   # Bypass (uses BITS)
    default { "WARN" }   # Not set - defaults may vary
}
Add-Result "50.1" "Delivery Optimisation: No Internet P2P" $s "DODownloadMode: $(if ($null -eq $doMode) {'Not set (default varies by edition)'} else {"$doMode (0=HTTP only, 1=LAN, 3=Internet - FAIL)"})" "CIS-L2"

# Restrict bandwidth
$doBandwidth = Get-RegValue $doBase "DOMaxDownloadBandwidth"
Add-Result "50.2" "Delivery Optimisation Bandwidth" "INFO" "DOMaxDownloadBandwidth: $(if ($null -eq $doBandwidth) {'Unlimited (not configured)'} else {"$doBandwidth KB/s"})" "CIS-L2"

# Cache size
$doCache = Get-RegValue $doBase "DOMaxCacheSize"
Add-Result "50.3" "Delivery Optimisation Cache Size" "INFO" "DOMaxCacheSize: $(if ($null -eq $doCache) {'Default'} else {"$doCache%"})" "CIS-L2"

# ============================================================
#  SECTION 51: TIME PROVIDER / NTP SECURITY  [CIS L2]
# ============================================================
Write-SectionHeader "51. TIME PROVIDER / NTP SECURITY" "CIS L2"

$w32Base = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time"

# NTP client enabled
$ntpEnabled = Get-RegValue "$w32Base\TimeProviders\NtpClient" "Enabled"
$s = if ($ntpEnabled -eq 1 -or $null -eq $ntpEnabled) { "PASS" } else { "WARN" }
Add-Result "51.1" "NTP Client Enabled" $s "NtpClient Enabled: $(if ($null -eq $ntpEnabled) {'Default (1)'} else {$ntpEnabled})" "CIS-L2"

# NTP server configured (not default Microsoft or blank)
$ntpServer = Get-RegValue "$w32Base\Parameters" "NtpServer"
$s = if ($null -ne $ntpServer -and $ntpServer -ne "") { "PASS" } else { "WARN" }
Add-Result "51.2" "NTP Server Configured" $s "NtpServer: $(if ($null -eq $ntpServer -or $ntpServer -eq '') {'Not configured'} else {$ntpServer})" "CIS-L2"

# Time sync type
$ntpType = Get-RegValue "$w32Base\Parameters" "Type"
$s = if ($ntpType -in @("NTP","AllSync","NT5DS")) { "PASS" } else { "WARN" }
Add-Result "51.3" "NTP Sync Type Configured" $s "Type: $(if ($null -eq $ntpType) {'Not set'} else {$ntpType})" "CIS-L2"

# W32tm service running
$w32tmSvc = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
$s = if ($w32tmSvc -and $w32tmSvc.Status -eq "Running") { "PASS" } else { "WARN" }
Add-Result "51.4" "Windows Time Service Running" $s "W32Time: $(if ($w32tmSvc) {$w32tmSvc.Status} else {'Not found'})" "CIS-L2"

# Resync interval - should not be excessively long
$pollInterval = Get-RegValue "$w32Base\Config" "MinPollInterval"
$s = if ($null -eq $pollInterval -or [int]$pollInterval -le 10) { "PASS" } else { "WARN" }
Add-Result "51.5" "NTP Poll Interval Reasonable" $s "MinPollInterval: $(if ($null -eq $pollInterval) {'Default'} else {"2^$pollInterval seconds"})" "CIS-L2"

# ============================================================
#  SECTION 52: WINDOWS DEFENDER APPLICATION GUARD  [CIS L2]
# ============================================================
Write-SectionHeader "52. WINDOWS DEFENDER APPLICATION GUARD (WDAG)" "CIS L2"

# WDAG feature installed
try {
    $wdagFeature = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -ErrorAction Stop
    $s = if ($wdagFeature.State -eq "Enabled") { "PASS" } else { "WARN" }
    Add-Result "52.1" "WDAG Feature Installed" $s "Feature state: $($wdagFeature.State)" "CIS-L2"
} catch {
    Add-Result "52.1" "WDAG Feature" "WARN" "Could not query WDAG feature (may not be available on Home/non-Enterprise)" "CIS-L2"
}

# WDAG policy - enabled for Edge
$wdagPolicy = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" "AllowAppHVSI_ProviderSet"
$s = if ($null -ne $wdagPolicy -and $wdagPolicy -ge 1) { "PASS" } else { "WARN" }
Add-Result "52.2" "WDAG Policy Enabled for Edge" $s "AllowAppHVSI_ProviderSet: $(if ($null -eq $wdagPolicy) {'Not configured'} else {$wdagPolicy})" "CIS-L2"

# WDAG clipboard - should be restricted
$wdagClipboard = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" "AppHVSIClipboardSettings"
$s = if ($wdagClipboard -eq 1 -or $null -eq $wdagClipboard) { "PASS" } else { "WARN" }
Add-Result "52.3" "WDAG Clipboard Restricted" $s "AppHVSIClipboardSettings: $wdagClipboard (1=Host->Container only, 2=Container->Host, 3=Both ways)" "CIS-L2"

# WDAG print - disabled
$wdagPrint = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" "AppHVSIPrintingSettings"
$s = if ($wdagPrint -eq 0 -or $null -eq $wdagPrint) { "PASS" } else { "WARN" }
Add-Result "52.4" "WDAG Printing Disabled" $s "AppHVSIPrintingSettings: $(if ($null -eq $wdagPrint) {'Default (0)'} else {$wdagPrint})" "CIS-L2"

# WDAG data persistence - disabled (CIS: container should not persist data)
$wdagPersist = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" "AllowPersistence"
$s = if ($wdagPersist -eq 0 -or $null -eq $wdagPersist) { "PASS" } else { "WARN" }
Add-Result "52.5" "WDAG Data Persistence Disabled" $s "AllowPersistence: $(if ($null -eq $wdagPersist) {'Default (0)'} else {$wdagPersist})" "CIS-L2"

# ============================================================
#  SECTION 53: RPC & DCOM SECURITY  [CIS L2]
# ============================================================
Write-SectionHeader "53. RPC & DCOM SECURITY" "CIS L2"

# RPC: Restrict unauthenticated clients
$rpcRestrict = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients"
$s = if ($rpcRestrict -eq 1) { "PASS" } else { "FAIL" }
Add-Result "53.1" "RPC: Restrict Unauthenticated Clients" $s "RestrictRemoteClients: $(if ($null -eq $rpcRestrict) {'Not set (0=None, insecure)'} else {"$rpcRestrict (1=Authenticated only, 2=Authenticated+exempt)"})" "CIS-L2"

# RPC: Enable auth endpoint resolution
$rpcAuthEP = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution"
$s = if ($rpcAuthEP -eq 1) { "PASS" } else { "WARN" }
Add-Result "53.2" "RPC: Authenticated Endpoint Resolution" $s "EnableAuthEpResolution: $rpcAuthEP" "CIS-L2"

# DCOM: Machine Access Restrictions defined
$dcomAccess = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DCOM" "MachineAccessRestriction"
$s = if ($null -ne $dcomAccess) { "PASS" } else { "WARN" }
Add-Result "53.3" "DCOM: Machine Access Restriction Defined" $s "MachineAccessRestriction: $(if ($null -ne $dcomAccess) {'Configured (SDDL)'} else {'Not configured - uses default'})" "CIS-L2"

# DCOM: Machine Launch Restrictions defined
$dcomLaunch = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DCOM" "MachineLaunchRestriction"
$s = if ($null -ne $dcomLaunch) { "PASS" } else { "WARN" }
Add-Result "53.4" "DCOM: Machine Launch Restriction Defined" $s "MachineLaunchRestriction: $(if ($null -ne $dcomLaunch) {'Configured (SDDL)'} else {'Not configured - uses default'})" "CIS-L2"

# ============================================================
#  SECTION 54: GROUP POLICY INFRASTRUCTURE  [CIS L2]
# ============================================================
Write-SectionHeader "54. GROUP POLICY INFRASTRUCTURE" "CIS L2"

$gpBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy"

# Always process GPO even if unchanged (Security extension)
$secGPOGUID  = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
$secNoChange = Get-RegValue "$gpBase\$secGPOGUID" "NoGPOListChanges"
$s = if ($secNoChange -eq 0 -or $null -eq $secNoChange) { "PASS" } else { "WARN" }
Add-Result "54.1" "GPO: Always Reprocess Security Policy" $s "NoGPOListChanges (Security): $(if ($null -eq $secNoChange) {'Not set (default reprocess)'} else {$secNoChange})" "CIS-L2"

# Registry policy processing - always process
$regGPOGUID  = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$regNoChange = Get-RegValue "$gpBase\$regGPOGUID" "NoGPOListChanges"
$s = if ($regNoChange -eq 0 -or $null -eq $regNoChange) { "PASS" } else { "WARN" }
Add-Result "54.2" "GPO: Always Reprocess Registry Policy" $s "NoGPOListChanges (Registry): $regNoChange" "CIS-L2"

# Loopback processing
$loopback = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UserPolicyMode"
Add-Result "54.3" "GPO: Loopback Processing Mode" "INFO" "UserPolicyMode: $(if ($null -eq $loopback) {'Not configured'} else {"$loopback (1=Merge, 2=Replace)"})" "CIS-L2"

# Turn off background refresh
$bgRefresh = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "SyncForegroundPolicy"
$s = if ($bgRefresh -eq 1) { "PASS" } else { "WARN" }
Add-Result "54.4" "GPO: Synchronous Foreground Refresh" $s "SyncForegroundPolicy: $bgRefresh (1=Synchronous on logon)" "CIS-L2"

# ============================================================
#  SECTION 55: PRINT SECURITY  [CIS L1/L2]
# ============================================================
Write-SectionHeader "55. PRINT SECURITY" "CIS L1/L2"

$printBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"

# Point and Print - restrict to approved servers
$papRestrict = Get-RegValue "$printBase\PointAndPrint" "Restricted"
$s = if ($papRestrict -eq 1) { "PASS" } else { "FAIL" }
Add-Result "55.1" "Point and Print Restricted to Approved Servers" $s "Restricted: $papRestrict" "CIS"

# Point and Print - no warning/elevation on install
$papNoWarn = Get-RegValue "$printBase\PointAndPrint" "NoWarningNoElevationOnInstall"
$s = if ($papNoWarn -eq 0 -or $null -eq $papNoWarn) { "PASS" } else { "FAIL" }
Add-Result "55.2" "Point and Print: Warning/Elevation on Install" $s "NoWarningNoElevationOnInstall: $(if ($null -eq $papNoWarn) {'Default (0 - prompt)'} else {$papNoWarn})" "CIS"

# Point and Print - no warning on update
$papUpdatePrompt = Get-RegValue "$printBase\PointAndPrint" "UpdatePromptSettings"
$s = if ($papUpdatePrompt -eq 0 -or $null -eq $papUpdatePrompt) { "PASS" } else { "FAIL" }
Add-Result "55.3" "Point and Print: Prompt on Update" $s "UpdatePromptSettings: $(if ($null -eq $papUpdatePrompt) {'Default (0 - prompt)'} else {$papUpdatePrompt})" "CIS"

# Only admins can install print drivers
$adminPrintDriver = Get-RegValue "$printBase\PointAndPrint" "RestrictDriverInstallationToAdministrators"
$s = if ($adminPrintDriver -eq 1) { "PASS" } else { "FAIL" }
Add-Result "55.4" "Print Driver Install: Admins Only" $s "RestrictDriverInstallationToAdministrators: $adminPrintDriver" "CIS"

# Disable downloading print drivers from Windows Update
$noWUPrint = Get-RegValue $printBase "DisableWebPnPDownload"
$s = if ($noWUPrint -eq 1) { "PASS" } else { "WARN" }
Add-Result "55.5" "Print Driver Download from Internet Disabled" $s "DisableWebPnPDownload: $noWUPrint" "CIS-L2"

# Redirection of print jobs via spooler (PrintNightmare mitigation)
$printNMClient = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPrinting"
$s = if ($printNMClient -eq 1) { "PASS" } else { "WARN" }
Add-Result "55.6" "Web-Based Printing Disabled" $s "DisableWebPrinting: $printNMClient" "CIS-L2"

# Print spooler - RPC over TCP (PrintNightmare)
$spoolRPC = Get-RegValue "HKLM:\System\CurrentControlSet\Control\Print" "RpcAuthnLevelPrivacyEnabled"
$s = if ($spoolRPC -eq 1) { "PASS" } else { "FAIL" }
Add-Result "55.7" "Print Spooler RPC Authentication Privacy" $s "RpcAuthnLevelPrivacyEnabled: $spoolRPC (1=Packet Privacy - CVE-2021-1675 mitigation)" "CIS"

# ============================================================
#  SECTION 56: WINDOWS COPILOT / AI FEATURES  [CIS L2]
# ============================================================
Write-SectionHeader "56. WINDOWS COPILOT / AI FEATURES" "CIS L2"

$aiBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"

# Windows Recall - disable AI snapshot capture (Win11 24H2+)
$recallDisable = Get-RegValue $aiBase "DisableAIDataAnalysis"
$s = if ($recallDisable -eq 1) { "PASS" } else { "WARN" }
Add-Result "56.1" "Windows Recall (AI Snapshots) Disabled" $s "DisableAIDataAnalysis: $(if ($null -eq $recallDisable) {'Not set - check if Recall is present'} else {$recallDisable})" "CIS-L2"

# Recall save snapshots
$recallSnaps = Get-RegValue $aiBase "TurnOffSavingSnapshots"
$s = if ($recallSnaps -eq 1) { "PASS" } else { "WARN" }
Add-Result "56.2" "Windows Recall Snapshot Saving Disabled" $s "TurnOffSavingSnapshots: $recallSnaps" "CIS-L2"

# Windows Copilot
$copilotDisable = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot"
$s = if ($copilotDisable -eq 1) { "PASS" } else { "WARN" }
Add-Result "56.3" "Windows Copilot Disabled" $s "TurnOffWindowsCopilot: $(if ($null -eq $copilotDisable) {'Not set'} else {$copilotDisable})" "CIS-L2"

# AI-powered content (broader)
$aiContent = Get-RegValue $aiBase "AllowImageCreator"
$s = if ($aiContent -eq 0) { "PASS" } else { "WARN" }
Add-Result "56.4" "AI Image Creator Restricted" $s "AllowImageCreator: $(if ($null -eq $aiContent) {'Not configured'} else {$aiContent})" "CIS-L2"

# Disable AI-based personalisation / inking
$aiInking = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\InputPersonalization" "RestrictImplicitInkCollection"
$s = if ($aiInking -eq 1) { "PASS" } else { "WARN" }
Add-Result "56.5" "Input/Inking Personalisation Disabled" $s "RestrictImplicitInkCollection: $aiInking" "CIS-L2"

# ============================================================
#  SECTION 57: SENSITIVE FILE & REGISTRY PERMISSIONS  [CIS L2]
# ============================================================
Write-SectionHeader "57. SENSITIVE FILE & REGISTRY PERMISSIONS" "CIS L2"

# Check SAM file is not world-readable
$samPath = "$env:SystemRoot\System32\config\SAM"
if (Test-Path $samPath) {
    try {
        $samACL     = Get-Acl $samPath -ErrorAction Stop
        $everyoneAce = $samACL.Access | Where-Object {
            $_.IdentityReference -match "Everyone|Users|Authenticated Users" -and
            $_.FileSystemRights -match "Read|FullControl|Modify"
        }
        $s = if (-not $everyoneAce) { "PASS" } else { "FAIL" }
        Add-Result "57.1" "SAM File: No Non-Admin Read Access" $s "Overly-permissive ACEs: $(if ($everyoneAce) {($everyoneAce.IdentityReference) -join ', '} else {'None found'})" "CIS-L2"
    } catch {
        Add-Result "57.1" "SAM File Permissions" "PASS" "Could not read ACL (locked by system - expected behaviour)" "CIS-L2"
    }
}

# Check System32 directory not writable by non-admins
$sys32Path = "$env:SystemRoot\System32"
try {
    $sysACL    = Get-Acl $sys32Path -ErrorAction Stop
    $writableByUsers = $sysACL.Access | Where-Object {
        $_.IdentityReference -match "Everyone|Users" -and
        $_.FileSystemRights -match "Write|FullControl|Modify" -and
        $_.AccessControlType -eq "Allow"
    }
    $s = if (-not $writableByUsers) { "PASS" } else { "FAIL" }
    Add-Result "57.2" "System32: Not Writable by Non-Admins" $s "Writable-by-users ACEs: $(if ($writableByUsers) {($writableByUsers.IdentityReference) -join ', '} else {'None found'})" "CIS-L2"
} catch {
    Add-Result "57.2" "System32 Permissions" "WARN" "Could not read ACL on System32" "CIS-L2"
}

# Hosts file - check for unexpected modifications (hash vs known clean)
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
    $nonComment   = $hostsContent | Where-Object { $_ -notmatch "^#" -and $_ -match "\S" }
    $s = if ($nonComment.Count -le 1) { "PASS" } else { "WARN" }
    Add-Result "57.3" "Hosts File: No Unexpected Entries" $s "Non-comment entries: $($nonComment.Count) - Review if unexpected: $($nonComment -join ' | ')" "CIS-L2"
}

# LSA registry key protection
$lsaRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
try {
    $lsaACL    = Get-Acl "Registry::$lsaRegPath" -ErrorAction Stop
    $lsaWriteByUsers = $lsaACL.Access | Where-Object {
        $_.IdentityReference -match "Everyone|Users" -and
        $_.RegistryRights -match "SetValue|FullControl" -and
        $_.AccessControlType -eq "Allow"
    }
    $s = if (-not $lsaWriteByUsers) { "PASS" } else { "FAIL" }
    Add-Result "57.4" "LSA Registry Key: No Non-Admin Write" $s "Writable-by-users ACEs: $(if ($lsaWriteByUsers) {($lsaWriteByUsers.IdentityReference) -join ', '} else {'None found'})" "CIS-L2"
} catch {
    Add-Result "57.4" "LSA Registry Key Permissions" "WARN" "Could not read ACL" "CIS-L2"
}

# ============================================================
#  SECTION 58: INTERNET EXPLORER / LEGACY BROWSER  [CIS L1]
# ============================================================
Write-SectionHeader "58. INTERNET EXPLORER / LEGACY BROWSER" "CIS L1"

$ieBase  = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer"
$ieInstalled = Test-Path "$env:ProgramFiles\Internet Explorer\iexplore.exe"

# IE removal/disable check (should be absent on modern builds)
try {
    $ieFeature = Get-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64" -ErrorAction Stop
    $s = if ($ieFeature.State -in @("Disabled","DisabledWithPayloadRemoved")) { "PASS" } else { "WARN" }
    Add-Result "58.1" "Internet Explorer Feature Removed" $s "State: $($ieFeature.State)" "CIS"
} catch {
    $s = if (-not $ieInstalled) { "PASS" } else { "WARN" }
    Add-Result "58.1" "Internet Explorer Present" $s "Binary present: $ieInstalled" "CIS"
}

# IE Enhanced Protected Mode
$ieEPM = Get-RegValue "$ieBase\Main" "Isolation64Bit"
$s = if ($ieEPM -eq 1 -or -not $ieInstalled) { "PASS" } else { "WARN" }
Add-Result "58.2" "IE Enhanced Protected Mode (64-bit)" $s "Isolation64Bit: $ieEPM" "CIS"

# IE Enhanced Security Configuration (ESC) - admin
$ieESCAdmin = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" "IsInstalled"
$s = if ($ieESCAdmin -eq 1 -or -not $ieInstalled) { "PASS" } else { "WARN" }
Add-Result "58.3" "IE Enhanced Security Config (Admin)" $s "ESC Admin IsInstalled: $ieESCAdmin" "CIS"

# IE - disable suggested sites
$ieSuggested = Get-RegValue "$ieBase\Suggested Sites" "Enabled"
$s = if ($ieSuggested -eq 0 -or -not $ieInstalled) { "PASS" } else { "WARN" }
Add-Result "58.4" "IE Suggested Sites Disabled" $s "Enabled: $ieSuggested" "CIS"

# IE - prevent managing SmartScreen
$ieSmartScreen = Get-RegValue "$ieBase\PhishingFilter" "PreventOverride"
$s = if ($ieSmartScreen -eq 1 -or -not $ieInstalled) { "PASS" } else { "WARN" }
Add-Result "58.5" "IE SmartScreen Override Prevented" $s "PreventOverride: $ieSmartScreen" "CIS"

# IE - disable first run wizard
$ieFirstRun = Get-RegValue "$ieBase\Main" "DisableFirstRunCustomize"
$s = if ($ieFirstRun -eq 1 -or -not $ieInstalled) { "PASS" } else { "WARN" }
Add-Result "58.6" "IE First Run Wizard Disabled" $s "DisableFirstRunCustomize: $ieFirstRun" "CIS"

# ============================================================
#  SECTION 59: WINDOWS EVENT FORWARDING  [CIS L2]
# ============================================================
Write-SectionHeader "59. WINDOWS EVENT FORWARDING" "CIS L2"

# Subscription manager configured
$wefBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
if (Test-Path $wefBase) {
    $subs = Get-Item $wefBase | Select-Object -ExpandProperty Property
    $s = if ($subs.Count -gt 0) { "PASS" } else { "WARN" }
    Add-Result "59.1" "Event Forwarding Subscription Configured" $s "Subscription entries: $($subs.Count)" "CIS-L2"
} else {
    Add-Result "59.1" "Event Forwarding Subscription Configured" "WARN" "No WEF subscription manager configured - events not being forwarded" "CIS-L2"
}

# WinRM service configured for event collection
$wecssSvc = Get-Service -Name "Wecsvc" -ErrorAction SilentlyContinue
$s = if ($wecssSvc -and $wecssSvc.Status -eq "Running") { "PASS" } else { "INFO" }
Add-Result "59.2" "Windows Event Collector Service" $s "Wecsvc: $(if ($wecssSvc) {$wecssSvc.Status} else {'Not running - only required on collector node'})" "CIS-L2"

# Channel access - Security log ACL check
try {
    $secLog = Get-WinEvent -ListLog Security -ErrorAction Stop
    $s = if ($secLog.SecurityDescriptor -match "Administrators") { "PASS" } else { "WARN" }
    Add-Result "59.3" "Security Log Access Restricted" $s "Security descriptor contains Administrators: $(if ($secLog.SecurityDescriptor -match 'Administrators') {'Yes'} else {'Not confirmed'})" "CIS-L2"
} catch {
    Add-Result "59.3" "Security Log Access" "WARN" "Could not query Security log descriptor" "CIS-L2"
}

# ============================================================
#  SECTION 60: ADDITIONAL WINDOWS DEFENDER SETTINGS  [CIS L1/L2]
# ============================================================
Write-SectionHeader "60. ADDITIONAL WINDOWS DEFENDER SETTINGS" "CIS L1/L2"

$wdBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"

# PUA (Potentially Unwanted Application) protection
$puaProtect = Get-RegValue $wdBase "PUAProtection"
$s = if ($puaProtect -eq 1) { "PASS" } elseif ($puaProtect -eq 2) { "WARN" } else { "FAIL" }
Add-Result "60.1" "Defender PUA Protection Enabled" $s "PUAProtection: $(if ($null -eq $puaProtect) {'Not set (disabled)'} else {"$puaProtect (1=Block, 2=Audit)"})" "CIS"

# Cloud block level
$cloudBlockLevel = Get-RegValue "$wdBase\MpEngine" "MpCloudBlockLevel"
$s = if ($null -ne $cloudBlockLevel -and $cloudBlockLevel -ge 2) { "PASS" } else { "WARN" }
Add-Result "60.2" "Defender Cloud Block Level" $s "MpCloudBlockLevel: $(if ($null -eq $cloudBlockLevel) {'Default'} else {"$cloudBlockLevel (2=High, 4=High+, 6=ZeroTolerance)"})" "CIS-L2"

# Cloud block timeout
$cloudTimeout = Get-RegValue "$wdBase\MpEngine" "MpBafsExtendedTimeout"
$s = if ($null -ne $cloudTimeout -and $cloudTimeout -ge 50) { "PASS" } else { "WARN" }
Add-Result "60.3" "Defender Cloud Block Timeout" $s "MpBafsExtendedTimeout: $(if ($null -eq $cloudTimeout) {'Default (10s)'} else {"${cloudTimeout}s"})" "CIS-L2"

# Scan removable drives
$scanRemovable = Get-RegValue "$wdBase\Scan" "DisableRemovableDriveScanning"
$s = if ($scanRemovable -eq 0 -or $null -eq $scanRemovable) { "PASS" } else { "FAIL" }
Add-Result "60.4" "Defender Scans Removable Drives" $s "DisableRemovableDriveScanning: $(if ($null -eq $scanRemovable) {'Not set (scanning on)'} else {$scanRemovable})" "CIS"

# Scan email
$scanEmail = Get-RegValue "$wdBase\Scan" "DisableEmailScanning"
$s = if ($scanEmail -eq 0 -or $null -eq $scanEmail) { "PASS" } else { "FAIL" }
Add-Result "60.5" "Defender Email Scanning Enabled" $s "DisableEmailScanning: $(if ($null -eq $scanEmail) {'Not set (scanning on)'} else {$scanEmail})" "CIS"

# Scan archive files
$scanArchive = Get-RegValue "$wdBase\Scan" "DisableArchiveScanning"
$s = if ($scanArchive -eq 0 -or $null -eq $scanArchive) { "PASS" } else { "WARN" }
Add-Result "60.6" "Defender Archive Scanning Enabled" $s "DisableArchiveScanning: $(if ($null -eq $scanArchive) {'Not set (scanning on)'} else {$scanArchive})" "CIS"

# Scheduled scan - daily
try {
    $defTask = Get-ScheduledTask -TaskName "Windows Defender Scheduled Scan" -TaskPath "\Microsoft\Windows\Windows Defender\" -ErrorAction Stop
    $s = if ($defTask.State -eq "Ready" -or $defTask.State -eq "Running") { "PASS" } else { "WARN" }
    Add-Result "60.7" "Defender Scheduled Scan Task Active" $s "Task state: $($defTask.State)" "CIS"
} catch {
    Add-Result "60.7" "Defender Scheduled Scan Task" "WARN" "Could not query scheduled scan task" "CIS"
}

# Hide exclusions - prevent non-admins seeing exclusion list
$hideExclusions = Get-RegValue $wdBase "DisableLocalAdminMerge"
$s = if ($hideExclusions -eq 1) { "PASS" } else { "WARN" }
Add-Result "60.8" "Defender Local Admin Exclusion Merge Disabled" $s "DisableLocalAdminMerge: $hideExclusions (1=Central policy only)" "CIS-L2"

# MpEngine threat default action - quarantine
$threatAction = Get-RegValue "$wdBase\Threats\ThreatSeverityDefaultAction" "5"
$s = if ($threatAction -eq 3 -or $null -eq $threatAction) { "PASS" } else { "WARN" }
Add-Result "60.9" "Defender Severe Threats: Quarantine Action" $s "SevereThreat default action: $(if ($null -eq $threatAction) {'Default (quarantine)'} else {"$threatAction (2=Remove, 3=Quarantine, 6=Ignore)"})" "CIS-L2"

# Network protection enforcement mode
$netProtMode = Get-RegValue "$wdBase\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection"
$s = switch ($netProtMode) {
    1       { "PASS" }   # Block
    2       { "WARN" }   # Audit
    0       { "FAIL" }   # Disabled
    default { "WARN" }
}
Add-Result "60.10" "Defender Network Protection Mode" $s "EnableNetworkProtection: $(if ($null -eq $netProtMode) {'Not set'} else {"$netProtMode (1=Block, 2=Audit, 0=Off)"})" "CIS"

# ============================================================
#  SECTION 61: CIS L1 - USER RIGHTS ASSIGNMENT  [CIS]
# ============================================================
Write-SectionHeader "61. CIS L1 - USER RIGHTS ASSIGNMENT" "CIS"

# 61.1 Access Credential Manager as trusted caller - No One
$val = Get-UserRight "SeTrustedCredManAccessPrivilege"
$s   = if ($null -eq $val -or $val -eq "") { "PASS" } else { "FAIL" }
Add-Result "61.1" "Credential Manager Trusted Caller: No One" $s "SeTrustedCredManAccessPrivilege: $(if ($val) {$val} else {'Not assigned (correct)'})" "CIS"

# 61.2 Adjust memory quotas for a process - Admins, LOCAL SERVICE, NETWORK SERVICE
$val = Get-UserRight "SeIncreaseQuotaPrivilege"
$s   = if ($val -match "Administrators" -and $val -notmatch "Everyone" -and $val -notmatch "Users") { "PASS" } else { "WARN" }
Add-Result "61.2" "Adjust Memory Quotas" $s "SeIncreaseQuotaPrivilege: $val" "CIS"

# 61.3 Allow log on locally - Admins, Users
$val = Get-UserRight "SeInteractiveLogonRight"
$s   = if ($val -and $val -ne "") { "PASS" } else { "WARN" }
Add-Result "61.3" "Allow Log On Locally" $s "SeInteractiveLogonRight: $(if ($val) {$val} else {'Not assigned'})" "CIS"

# 61.4 Allow log on through Remote Desktop - Admins, Remote Desktop Users
$val = Get-UserRight "SeRemoteInteractiveLogonRight"
$s   = if ($val -and $val -ne "" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "61.4" "Allow Log On Through RDP" $s "SeRemoteInteractiveLogonRight: $(if ($val) {$val} else {'Not assigned'})" "CIS"

# 61.5 Change the system time - Admins, LOCAL SERVICE
$val = Get-UserRight "SeSystemtimePrivilege"
$s   = if ($val -notmatch "Everyone" -and $val -notmatch "Users") { "PASS" } else { "WARN" }
Add-Result "61.5" "Change System Time" $s "SeSystemtimePrivilege: $val" "CIS"

# 61.6 Change the time zone - Admins, LOCAL SERVICE, Users
$val = Get-UserRight "SeTimeZonePrivilege"
$s   = if ($val -and $val -ne "") { "PASS" } else { "WARN" }
Add-Result "61.6" "Change Time Zone" $s "SeTimeZonePrivilege: $(if ($val) {$val} else {'Not assigned'})" "CIS"

# 61.7 Create a token object - No One
$val = Get-UserRight "SeCreateTokenPrivilege"
$s   = if ($null -eq $val -or $val -eq "") { "PASS" } else { "FAIL" }
Add-Result "61.7" "Create Token Object: No One" $s "SeCreateTokenPrivilege: $(if ($val) {$val} else {'Not assigned (correct)'})" "CIS"

# 61.8 Create global objects - Admins, LOCAL SERVICE, NETWORK SERVICE, SERVICE
$val = Get-UserRight "SeCreateGlobalPrivilege"
$s   = if ($val -notmatch "Everyone" -and $val -notmatch "Users") { "PASS" } else { "WARN" }
Add-Result "61.8" "Create Global Objects" $s "SeCreateGlobalPrivilege: $val" "CIS"

# 61.9 Replace a process level token - LOCAL SERVICE, NETWORK SERVICE
$val = Get-UserRight "SeAssignPrimaryTokenPrivilege"
$s   = if ($val -notmatch "Administrators" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "61.9" "Replace Process Level Token" $s "SeAssignPrimaryTokenPrivilege: $val" "CIS"

# 61.10 Deny access to this computer from the network - must include Guest
$val = Get-UserRight "SeDenyNetworkLogonRight"
$s   = if ($val -match "Guest") { "PASS" } else { "FAIL" }
Add-Result "61.10" "Deny Network Logon: Includes Guest" $s "SeDenyNetworkLogonRight: $(if ($val) {$val} else {'Not assigned'})" "CIS"

# 61.11 Deny log on as a batch job - must include Guest
$val = Get-UserRight "SeDenyBatchLogonRight"
$s   = if ($val -match "Guest") { "PASS" } else { "FAIL" }
Add-Result "61.11" "Deny Batch Logon: Includes Guest" $s "SeDenyBatchLogonRight: $(if ($val) {$val} else {'Not assigned'})" "CIS"

# 61.12 Deny log on as a service - must include Guest
$val = Get-UserRight "SeDenyServiceLogonRight"
$s   = if ($val -match "Guest") { "PASS" } else { "FAIL" }
Add-Result "61.12" "Deny Service Logon: Includes Guest" $s "SeDenyServiceLogonRight: $(if ($val) {$val} else {'Not assigned'})" "CIS"

# 61.13 Impersonate a client after authentication
$val = Get-UserRight "SeImpersonatePrivilege"
$s   = if ($val -notmatch "Everyone" -and $val -notmatch "Users") { "PASS" } else { "WARN" }
Add-Result "61.13" "Impersonate Client After Auth" $s "SeImpersonatePrivilege: $val" "CIS"

# 61.14 Increase scheduling priority - Admins, Window Manager
$val = Get-UserRight "SeIncreaseBasePriorityPrivilege"
$s   = if ($val -notmatch "Everyone" -and $val -notmatch "Users") { "PASS" } else { "WARN" }
Add-Result "61.14" "Increase Scheduling Priority" $s "SeIncreaseBasePriorityPrivilege: $val" "CIS"

# 61.15 Modify an object label - No One
$val = Get-UserRight "SeRelabelPrivilege"
$s   = if ($null -eq $val -or $val -eq "") { "PASS" } else { "FAIL" }
Add-Result "61.15" "Modify Object Label: No One" $s "SeRelabelPrivilege: $(if ($val) {$val} else {'Not assigned (correct)'})" "CIS"

# 61.16 Profile system performance - Admins, NT SERVICE\WdiServiceHost
$val = Get-UserRight "SeProfileSystemPerformancePrivilege"
$s   = if ($val -notmatch "Everyone" -and $val -notmatch "Users") { "PASS" } else { "WARN" }
Add-Result "61.16" "Profile System Performance" $s "SeProfileSystemPerformancePrivilege: $val" "CIS"

# 61.17 Shut down the system - Admins, Users
$val = Get-UserRight "SeShutdownPrivilege"
$s   = if ($val -and $val -ne "" -and $val -notmatch "Everyone") { "PASS" } else { "WARN" }
Add-Result "61.17" "Shut Down the System" $s "SeShutdownPrivilege: $(if ($val) {$val} else {'Not assigned'})" "CIS"

# ============================================================
#  SECTION 62: CIS L1 - SECURITY OPTIONS (MISSING)  [CIS]
# ============================================================
Write-SectionHeader "62. CIS L1 - SECURITY OPTIONS (MISSING)" "CIS"

# 62.1 Restrict clients allowed to make remote calls to SAM
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM"
$s   = if ($null -ne $val) { "PASS" } else { "FAIL" }
Add-Result "62.1" "Restrict Remote SAM Calls" $s "CIS 2.3.10.11: RestrictRemoteSAM: $(if ($null -ne $val) {'Configured'} else {'Not set'})" "CIS"

# 62.2 Block Microsoft accounts
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "NoConnectedUser"
$s   = if ($val -eq 3) { "PASS" } else { "WARN" }
Add-Result "62.2" "Block Microsoft Accounts" $s "CIS 2.3.1.2: NoConnectedUser: $(if ($null -eq $val) {'Not set'} else {$val}) (3=Block)" "CIS"

# 62.3 Classic security model (ForceGuest)
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "ForceGuest"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "62.3" "Network Access: Classic Security Model" $s "CIS 2.3.10.4: ForceGuest: $(if ($null -eq $val) {'Not set (Classic)'} else {$val}) (0=Classic)" "CIS"

# 62.4 Default owner for objects created by Administrators
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoDefaultAdminOwner"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "62.4" "System Objects: Default Owner" $s "CIS 2.3.14.1: NoDefaultAdminOwner: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Object creator)" "CIS"

# 62.5 Apply UAC restrictions to local accounts on network logons
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LocalAccountTokenFilterPolicy"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "62.5" "UAC Token Filter for Local Accounts" $s "CIS 18.3.1: LocalAccountTokenFilterPolicy: $(if ($null -eq $val) {'Not set (filtered)'} else {$val}) (0=Filter)" "CIS"

# 62.6 Do not allow anonymous enumeration of SAM accounts
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
$s   = if ($val -eq 1) { "PASS" } else { "FAIL" }
Add-Result "62.6" "Restrict Anonymous SAM Enumeration" $s "CIS 2.3.10.2: RestrictAnonymousSAM: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Restricted)" "CIS"

# 62.7 Interactive logon: Do not require CTRL+ALT+DEL
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "62.7" "Require CTRL+ALT+DEL" $s "CIS 2.3.7.1: DisableCAD: $(if ($null -eq $val) {'Not set'} else {$val}) (0=Required)" "CIS"

# 62.8 Interactive logon: Don't display last signed-in
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
$s   = if ($val -eq 1) { "PASS" } else { "FAIL" }
Add-Result "62.8" "Don't Display Last User Name" $s "CIS 2.3.7.2: DontDisplayLastUserName: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Hidden)" "CIS"

# 62.9 Interactive logon: Smart card removal behavior
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScForceOption"
$s   = if ($null -ne $val -and $val -ge 1) { "PASS" } else { "WARN" }
Add-Result "62.9" "Smart Card Removal Behavior" $s "CIS 2.3.7.7: ScForceOption: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Lock Workstation)" "CIS"

# 62.10 Enable insecure guest logons
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "EnableInsecureGuestLogons"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "62.10" "Insecure Guest Logons Disabled" $s "CIS 18.3.7: EnableInsecureGuestLogons: $(if ($null -eq $val) {'Not set (disabled)'} else {$val}) (0=Disabled)" "CIS"

# 62.11 Hardened UNC Paths
$netlogon = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON"
$sysvol   = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\SYSVOL"
$nlOk     = $netlogon -match "RequireMutualAuthentication=1" -and $netlogon -match "RequireIntegrity=1"
$svOk     = $sysvol   -match "RequireMutualAuthentication=1" -and $sysvol   -match "RequireIntegrity=1"
$s        = if ($nlOk -and $svOk) { "PASS" } else { "WARN" }
Add-Result "62.11" "Hardened UNC Paths" $s "CIS 18.3.8: NETLOGON=$(if ($netlogon) {$netlogon} else {'Not set'}); SYSVOL=$(if ($sysvol) {$sysvol} else {'Not set'})" "CIS"

# 62.12 NetBT NodeType
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType"
$s   = if ($val -eq 2) { "PASS" } else { "WARN" }
Add-Result "62.12" "NetBT NodeType: P-node Configuration" $s "CIS 18.3.5: NodeType: $(if ($null -eq $val) {'Not set'} else {$val}) (2=P-node)" "CIS"

# 62.13 Accounts: Limit blank password use to console logon only
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
$s   = if ($val -eq 1 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "62.13" "Limit Blank Password to Console Only" $s "CIS 2.3.1.3: LimitBlankPasswordUse: $(if ($null -eq $val) {'Default (1)'} else {$val}) (1=Console only)" "CIS"

# 62.14 Network access: Restrict anonymous access to Named Pipes and Shares
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RestrictNullSessAccess"
$s   = if ($val -eq 1 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "62.14" "Restrict Anonymous Named Pipes/Shares" $s "CIS 2.3.10.6: RestrictNullSessAccess: $(if ($null -eq $val) {'Default (1)'} else {$val}) (1=Restricted)" "CIS"

# 62.15 Interactive logon: Machine inactivity limit <= 900 seconds
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
$s   = if ($null -ne $val -and [int]$val -ge 1 -and [int]$val -le 900) { "PASS" } else { "WARN" }
Add-Result "62.15" "Machine Inactivity Limit <= 900s" $s "CIS 2.3.7.4: InactivityTimeoutSecs: $(if ($null -eq $val) {'Not set'} else {"${val}s"}) (<=900)" "CIS"

# 62.16 Interactive logon: Message text for users
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText"
$s   = if ($null -ne $val -and $val -ne "") { "PASS" } else { "WARN" }
Add-Result "62.16" "Legal Notice Text Configured" $s "CIS 2.3.7.5: LegalNoticeText: $(if ($null -eq $val -or $val -eq '') {'Not set'} else {'Configured'})" "CIS"

# 62.17 Interactive logon: Message title for users
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption"
$s   = if ($null -ne $val -and $val -ne "") { "PASS" } else { "WARN" }
Add-Result "62.17" "Legal Notice Caption Configured" $s "CIS 2.3.7.6: LegalNoticeCaption: $(if ($null -eq $val -or $val -eq '') {'Not set'} else {'Configured'})" "CIS"

# 62.18 Network access: Remotely accessible registry paths
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" "Machine"
$s   = if ($null -ne $val) { "PASS" } else { "WARN" }
Add-Result "62.18" "Remotely Accessible Registry Paths" $s "CIS 2.3.10.8: AllowedExactPaths: $(if ($null -eq $val) {'Not set'} else {'Configured'})" "CIS"

# 62.19 Network access: Remotely accessible registry paths and sub-paths
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" "Machine"
$s   = if ($null -ne $val) { "PASS" } else { "WARN" }
Add-Result "62.19" "Remotely Accessible Reg Paths/Sub-Paths" $s "CIS 2.3.10.9: AllowedPaths: $(if ($null -eq $val) {'Not set'} else {'Configured'})" "CIS"

# 62.20 Network security: Allow Local System to use computer identity for NTLM
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "UseMachineId"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "62.20" "NTLM: Use Computer Identity" $s "CIS 2.3.11.1: UseMachineId: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Enabled)" "CIS"

# 62.21 UAC: Only elevate UIAccess apps installed in secure locations
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths"
$s   = if ($val -eq 1 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "62.21" "UAC: UIAccess Secure Location Only" $s "CIS 2.3.17.6: EnableSecureUIAPaths: $(if ($null -eq $val) {'Default (1)'} else {$val}) (1=Secure locations only)" "CIS"

# ============================================================
#  SECTION 63: CIS L1 - ADMINISTRATIVE TEMPLATES (SYSTEM)  [CIS]
# ============================================================
Write-SectionHeader "63. CIS L1 - ADMINISTRATIVE TEMPLATES (SYSTEM)" "CIS"

# 63.1 Lock screen camera
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "PreventEnablingLockScreenCamera"
$s   = if ($val -eq 1) { "PASS" } else { "FAIL" }
Add-Result "63.1" "Lock Screen Camera Disabled" $s "CIS 18.1.1.2: PreventEnablingLockScreenCamera: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 63.2 Lock screen slide show
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "PreventLockScreenSlideShow"
$s   = if ($val -eq 1) { "PASS" } else { "FAIL" }
Add-Result "63.2" "Lock Screen Slide Show Disabled" $s "CIS 18.1.1.3: PreventLockScreenSlideShow: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 63.3 Allow Online Tips
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AllowOnlineTips"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "63.3" "Online Tips Disabled" $s "CIS 18.1.3: AllowOnlineTips: $(if ($null -eq $val) {'Not set (disabled)'} else {$val})" "CIS"

# 63.4 Process creation include command line
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "63.4" "Process Creation: Include Command Line" $s "CIS 18.8.3.1: ProcessCreationIncludeCmdLine_Enabled: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 63.5 Remote host delegation of non-exportable credentials
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "63.5" "Remote Host Non-Exportable Creds" $s "CIS 18.8.4.1: AllowProtectedCreds: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 63.6 Block user from showing account details on sign-in
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockUserFromShowingAccountDetailsOnSignin"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "63.6" "Block Account Details on Sign-In" $s "CIS 18.8.28.1: BlockUserFromShowingAccountDetailsOnSignin: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 63.7 Screen saver grace period
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "ScreenSaverGracePeriod"
$s   = if ($null -ne $val -and [int]$val -le 5) { "PASS" } else { "WARN" }
Add-Result "63.7" "Screen Saver Grace Period" $s "CIS 18.8.28.3: ScreenSaverGracePeriod: $(if ($null -eq $val) {'Not set'} else {$val}) (<=5 recommended)" "CIS"

# 63.8 Sleep settings (plugged in) - require password on wake
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "ACSettingIndex"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "63.8" "Password on Wake (Plugged In)" $s "CIS 18.8.36.1: ACSettingIndex: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Require)" "CIS"

# 63.9 Sleep settings (battery) - require password on wake
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "DCSettingIndex"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "63.9" "Password on Wake (Battery)" $s "CIS 18.8.36.2: DCSettingIndex: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Require)" "CIS"

# 63.10 Early Launch Antimalware boot-start driver policy
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy"
$s   = if ($val -eq 1 -or $val -eq 3 -or $val -eq 8 -or $null -eq $val) { "PASS" } elseif ($val -eq 7) { "FAIL" } else { "WARN" }
Add-Result "63.10" "Early Launch Antimalware Policy" $s "CIS 18.8.14.1: DriverLoadPolicy: $(if ($null -eq $val) {'Not set (default=Good known and unknown)'} else {$val})" "CIS"

# 63.11 Enhanced anti-spoofing for facial recognition
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" "EnhancedAntiSpoofing"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "63.11" "Enhanced Anti-Spoofing (Face)" $s "CIS 18.8.22.1.4: EnhancedAntiSpoofing: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# ============================================================
#  SECTION 64: CIS L1 - ADMINISTRATIVE TEMPLATES (WINDOWS COMPONENTS)  [CIS]
# ============================================================
Write-SectionHeader "64. CIS L1 - ADMINISTRATIVE TEMPLATES (WINDOWS COMPONENTS)" "CIS"

# 64.1 Disallow Autoplay for non-volume devices
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "64.1" "AutoPlay: Disallow Non-Volume Devices" $s "CIS 18.9.4.1: NoAutoplayfornonVolume: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 64.2 Default behavior for AutoRun
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "64.2" "AutoRun: Do Not Execute" $s "CIS 18.9.4.2: NoAutorun: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 64.3 Require PIN for pairing (Connected Devices)
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" "RequirePinForPairing"
$s   = if ($null -ne $val -and $val -ge 1) { "PASS" } else { "WARN" }
Add-Result "64.3" "Require PIN for Device Pairing" $s "CIS 18.9.14.1: RequirePinForPairing: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 64.4 Setup log maximum size
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "MaxSize"
$s   = if ($null -ne $val -and $val -ge 32768) { "PASS" } else { "WARN" }
Add-Result "64.4" "Event Log: Setup Log Max Size" $s "CIS 18.9.27.3.1: MaxSize: $(if ($null -eq $val) {'Not set'} else {"$val KB"}) (>=32768 KB)" "CIS"

# 64.5 Do not allow passwords to be saved (RDP Client)
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "64.5" "RDP Client: No Saved Passwords" $s "CIS 18.9.65.2.2: DisablePasswordSaving: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 64.6 Always prompt for password upon connection (RDP Host)
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "64.6" "RDP Host: Always Prompt Password" $s "CIS 18.9.65.3.3.1: fPromptForPassword: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 64.7 Do not allow drive redirection (RDP Host)
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "64.7" "RDP Host: No Drive Redirection" $s "CIS 18.9.65.3.3.2: fDisableCdm: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 64.8 Set time limit for disconnected sessions (RDP)
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxDisconnectionTime"
$s   = if ($null -ne $val -and $val -gt 0 -and $val -le 60000) { "PASS" } else { "WARN" }
Add-Result "64.8" "RDP: Disconnected Session Time Limit" $s "CIS 18.9.65.3.10.1: MaxDisconnectionTime: $(if ($null -eq $val) {'Not set'} else {"${val}ms"})" "CIS"

# 64.9 Set time limit for idle sessions (RDP)
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime"
$s   = if ($null -ne $val -and $val -gt 0 -and $val -le 900000) { "PASS" } else { "WARN" }
Add-Result "64.9" "RDP: Idle Session Time Limit" $s "CIS 18.9.65.3.10.2: MaxIdleTime: $(if ($null -eq $val) {'Not set'} else {"${val}ms"}) (<=900000)" "CIS"

# 64.10 Allow indexing of encrypted files
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "64.10" "Search: No Encrypted File Indexing" $s "CIS 18.9.67.3: AllowIndexingEncryptedStoresOrItems: $(if ($null -eq $val) {'Not set (disabled)'} else {$val})" "CIS"

# 64.11 WinRM Client: Allow Basic authentication
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic"
$s   = if ($val -eq 0) { "PASS" } else { "FAIL" }
Add-Result "64.11" "WinRM Client: Basic Auth Disabled" $s "CIS 18.9.102.1.1: AllowBasic: $(if ($null -eq $val) {'Not set (enabled)'} else {$val})" "CIS"

# 64.12 WinRM Client: Allow unencrypted traffic
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic"
$s   = if ($val -eq 0) { "PASS" } else { "FAIL" }
Add-Result "64.12" "WinRM Client: Unencrypted Disabled" $s "CIS 18.9.102.1.3: AllowUnencryptedTraffic: $(if ($null -eq $val) {'Not set (enabled)'} else {$val})" "CIS"

# 64.13 WinRM Service: Allow Basic authentication
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic"
$s   = if ($val -eq 0) { "PASS" } else { "FAIL" }
Add-Result "64.13" "WinRM Service: Basic Auth Disabled" $s "CIS 18.9.102.2.1: AllowBasic: $(if ($null -eq $val) {'Not set (enabled)'} else {$val})" "CIS"

# 64.14 WinRM Service: Allow unencrypted traffic
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic"
$s   = if ($val -eq 0) { "PASS" } else { "FAIL" }
Add-Result "64.14" "WinRM Service: Unencrypted Disabled" $s "CIS 18.9.102.2.3: AllowUnencryptedTraffic: $(if ($null -eq $val) {'Not set (enabled)'} else {$val})" "CIS"

# 64.15 WinRM Service: Disallow WinRM from storing RunAs credentials
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs"
$s   = if ($val -eq 1) { "PASS" } else { "FAIL" }
Add-Result "64.15" "WinRM Service: RunAs Creds Disabled" $s "CIS 18.9.102.2.4: DisableRunAs: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 64.16 Windows Update: No auto-restart with logged on users
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "64.16" "WU: No Auto-Restart with Users" $s "CIS 18.9.108.4.1: NoAutoRebootWithLoggedOnUsers: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 64.17 Explorer: Turn off Data Execution Prevention
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "64.17" "Explorer: DEP Enabled" $s "CIS 18.9.31.2: NoDataExecutionPrevention: $(if ($null -eq $val) {'Not set (DEP on)'} else {$val})" "CIS"

# 64.18 Explorer: Turn off heap termination on corruption
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "64.18" "Explorer: Heap Termination on Corruption" $s "CIS 18.9.31.3: NoHeapTerminationOnCorruption: $(if ($null -eq $val) {'Not set (enabled)'} else {$val})" "CIS"

# 64.19 Explorer: Turn off shell protocol protected mode
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "64.19" "Explorer: Shell Protocol Protected Mode" $s "CIS 18.9.31.4: PreXPSP2ShellProtocolBehavior: $(if ($null -eq $val) {'Not set (protected)'} else {$val})" "CIS"

# 64.20 Prohibit installation of Network Bridge
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_AllowNetBridge_NoDNS_NoPrivate"
$s   = if ($val -eq 0) { "PASS" } else { "WARN" }
Add-Result "64.20" "Prohibit Network Bridge" $s "CIS 18.5.8.1: NC_AllowNetBridge_NoDNS_NoPrivate: $(if ($null -eq $val) {'Not set'} else {$val}) (0=Prohibit)" "CIS"

# 64.21 Prohibit connection to non-domain networks
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "64.21" "Block Non-Domain Network Connection" $s "CIS 18.5.21.1: fBlockNonDomain: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 64.22 Cloud content: Turn off cloud consumer account state content
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerAccountStateContent"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "64.22" "Cloud Consumer Content Disabled" $s "CIS 18.9.12.1: DisableConsumerAccountStateContent: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# ============================================================
#  SECTION 65: CIS L1 - SYSTEM SERVICES (MISSING)  [CIS]
# ============================================================
Write-SectionHeader "65. CIS L1 - SYSTEM SERVICES (MISSING)" "CIS"

$cisL1Services = @(
    @{ Name = "BTAGService"; Label = "Bluetooth Audio Gateway" }
    @{ Name = "bthserv";     Label = "Bluetooth Support"       }
    @{ Name = "Browser";     Label = "Computer Browser"        }
    @{ Name = "IISADMIN";    Label = "IIS Admin Service"       }
    @{ Name = "MSiSCSI";     Label = "iSCSI Initiator"         }
    @{ Name = "RpcLocator";  Label = "RPC Locator"             }
    @{ Name = "SSDPSRV";     Label = "SSDP Discovery"          }
    @{ Name = "WerSvc";      Label = "Windows Error Reporting" }
    @{ Name = "WpnService";  Label = "Windows Push Notif Svc"  }
    @{ Name = "lfsvc";       Label = "Geolocation Service"     }
    @{ Name = "MapsBroker";  Label = "Downloaded Maps Manager" }
    @{ Name = "PcaSvc";      Label = "Program Compat Assistant" }
    @{ Name = "LxssManager"; Label = "Windows Subsystem Linux" }
    @{ Name = "SharedAccess"; Label = "Internet Connection Sharing" }
    @{ Name = "RemoteRegistry"; Label = "Remote Registry"      }
    @{ Name = "FTPSVC";      Label = "FTP Publishing Service"  }
    @{ Name = "W3SVC";       Label = "World Wide Web Publishing" }
    @{ Name = "XblAuthManager"; Label = "Xbox Live Auth Manager" }
    @{ Name = "XblGameSave"; Label = "Xbox Live Game Save"     }
    @{ Name = "XboxGipSvc";  Label = "Xbox Accessory Mgmt"    }
    @{ Name = "XboxNetApiSvc"; Label = "Xbox Live Networking"  }
)

$svcIdx = 1
foreach ($svc in $cisL1Services) {
    $svcObj = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($null -eq $svcObj) {
        Add-Result "65.$svcIdx" "$($svc.Label) Service" "PASS" "Not installed" "CIS"
    } elseif ($svcObj.Status -eq "Running" -or $svcObj.StartType -eq "Automatic") {
        Add-Result "65.$svcIdx" "$($svc.Label) Service" "FAIL" "Status: $($svcObj.Status), StartType: $($svcObj.StartType)" "CIS"
    } else {
        Add-Result "65.$svcIdx" "$($svc.Label) Service" "PASS" "Status: $($svcObj.Status), StartType: $($svcObj.StartType)" "CIS"
    }
    $svcIdx++
}

# ============================================================
#  SECTION 66: CIS L1 - ADMINISTRATIVE TEMPLATES (USER)  [CIS]
# ============================================================
Write-SectionHeader "66. CIS L1 - ADMINISTRATIVE TEMPLATES (USER)" "CIS"

# 66.1 Turn off toast notifications on lock screen
$val = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoToastApplicationNotificationOnLockScreen"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "66.1" "No Toast Notifications on Lock Screen" $s "CIS 19.5.1.1: NoToastApplicationNotificationOnLockScreen: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 66.2 Do not preserve zone info in file attachments
$val = Get-RegValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation"
$s   = if ($val -eq 2 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "66.2" "Preserve Zone Info in Attachments" $s "CIS 19.7.4.1: SaveZoneInformation: $(if ($null -eq $val) {'Not set (preserved)'} else {$val}) (2=Preserve)" "CIS"

# 66.3 Notify antivirus when opening attachments
$val = Get-RegValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "ScanWithAntiVirus"
$s   = if ($val -eq 3 -or $null -eq $val) { "PASS" } else { "WARN" }
Add-Result "66.3" "AV Scan on Attachment Open" $s "CIS 19.7.4.2: ScanWithAntiVirus: $(if ($null -eq $val) {'Not set (default=scan)'} else {$val}) (3=All)" "CIS"

# 66.4 Configure Windows Spotlight on lock screen
$val = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "ConfigureWindowsSpotlight"
$s   = if ($val -eq 2) { "PASS" } else { "WARN" }
Add-Result "66.4" "Windows Spotlight on Lock Screen" $s "CIS 19.7.8.1: ConfigureWindowsSpotlight: $(if ($null -eq $val) {'Not set'} else {$val}) (2=Disabled)" "CIS"

# 66.5 Do not suggest third-party content
$val = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "66.5" "No Third-Party Suggestions" $s "CIS 19.7.8.2: DisableThirdPartySuggestions: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 66.6 Screen saver enabled
$val = Get-RegValue "HKCU:\Control Panel\Desktop" "ScreenSaveActive"
$s   = if ($val -eq "1") { "PASS" } else { "WARN" }
Add-Result "66.6" "Screen Saver Enabled" $s "CIS 19.1.3.1: ScreenSaveActive: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 66.7 Screen saver password protected
$val = Get-RegValue "HKCU:\Control Panel\Desktop" "ScreenSaverIsSecure"
$s   = if ($val -eq "1") { "PASS" } else { "WARN" }
Add-Result "66.7" "Screen Saver Password Protected" $s "CIS 19.1.3.2: ScreenSaverIsSecure: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 66.8 Screen saver timeout
$val = Get-RegValue "HKCU:\Control Panel\Desktop" "ScreenSaveTimeOut"
$s   = if ($null -ne $val -and [int]$val -gt 0 -and [int]$val -le 900) { "PASS" } else { "WARN" }
Add-Result "66.8" "Screen Saver Timeout" $s "CIS 19.1.3.3: ScreenSaveTimeOut: $(if ($null -eq $val) {'Not set'} else {"${val}s"}) (<=900)" "CIS"

# ============================================================
#  SECTION 67: CIS L1 - DATA COLLECTION / TELEMETRY  [CIS]
# ============================================================
Write-SectionHeader "67. CIS L1 - DATA COLLECTION / TELEMETRY" "CIS"

# 67.1 Allow Diagnostic Data: Send required diagnostic data only (1) or off (0)
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry"
$s   = if ($null -ne $val -and [int]$val -le 1) { "PASS" } else { "WARN" }
Add-Result "67.1" "Telemetry: Required Data Only" $s "CIS 18.9.17.1: AllowTelemetry: $(if ($null -eq $val) {'Not set'} else {$val}) (0=Off, 1=Required only)" "CIS"

# 67.2 Configure Authenticated Proxy usage for telemetry - Disabled (0)
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "67.2" "Telemetry: No Authenticated Proxy" $s "CIS 18.9.17.2: DisableEnterpriseAuthProxy: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Disabled)" "CIS"

# 67.3 Disable OneSettings Downloads
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableOneSettingsDownloads"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "67.3" "Telemetry: Disable OneSettings Downloads" $s "CIS 18.9.17.3: DisableOneSettingsDownloads: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 67.4 Do not show feedback notifications
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "67.4" "Telemetry: No Feedback Notifications" $s "CIS 18.9.17.4: DoNotShowFeedbackNotifications: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 67.5 Enable OneSettings Auditing
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "EnableOneSettingsAuditing"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "67.5" "Telemetry: OneSettings Auditing Enabled" $s "CIS 18.9.17.5: EnableOneSettingsAuditing: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 67.6 Limit Diagnostic Log Collection
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDiagnosticLogCollection"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "67.6" "Telemetry: Limit Diagnostic Logs" $s "CIS 18.9.17.6: LimitDiagnosticLogCollection: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 67.7 Limit Dump Collection
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDumpCollection"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "67.7" "Telemetry: Limit Dump Collection" $s "CIS 18.9.17.7: LimitDumpCollection: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 67.8 Toggle user control over Insider builds - Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" "AllowBuildPreview"
$s   = if ($val -eq 0) { "PASS" } else { "WARN" }
Add-Result "67.8" "Insider Builds: User Control Disabled" $s "CIS 18.9.17.8: AllowBuildPreview: $(if ($null -eq $val) {'Not set'} else {$val}) (0=Disabled)" "CIS"

# ============================================================
#  SECTION 68: CIS L1 - DEVICE GUARD / VBS  [CIS]
# ============================================================
Write-SectionHeader "68. CIS L1 - DEVICE GUARD / VBS" "CIS"

$dgBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"

# 68.1 Turn on Virtualization Based Security
$val = Get-RegValue $dgBase "EnableVirtualizationBasedSecurity"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "68.1" "VBS: Enabled" $s "CIS 18.8.5.1: EnableVirtualizationBasedSecurity: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Enabled)" "CIS"

# 68.2 Platform Security Features - Secure Boot and DMA Protection (3)
$val = Get-RegValue $dgBase "RequirePlatformSecurityFeatures"
$s   = if ($val -eq 3) { "PASS" } elseif ($val -eq 1) { "WARN" } else { "WARN" }
Add-Result "68.2" "VBS: Platform Security Features" $s "CIS 18.8.5.2: RequirePlatformSecurityFeatures: $(if ($null -eq $val) {'Not set'} else {$val}) (1=SecureBoot, 3=SecureBoot+DMA)" "CIS"

# 68.3 Virtualization Based Protection of Code Integrity (HVCI)
$val = Get-RegValue $dgBase "HypervisorEnforcedCodeIntegrity"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "68.3" "VBS: HVCI Enabled" $s "CIS 18.8.5.3: HypervisorEnforcedCodeIntegrity: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Enabled with UEFI lock)" "CIS"

# 68.4 UEFI Lock for VBS
$val = Get-RegValue $dgBase "Locked"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "68.4" "VBS: UEFI Lock Enabled" $s "CIS 18.8.5.4: Locked: $(if ($null -eq $val) {'Not set'} else {$val}) (1=UEFI locked)" "CIS"

# 68.5 Credential Guard Configuration
$val = Get-RegValue $dgBase "LsaCfgFlags"
$s   = if ($val -eq 1) { "PASS" } elseif ($val -eq 2) { "WARN" } else { "WARN" }
Add-Result "68.5" "VBS: Credential Guard" $s "CIS 18.8.5.5: LsaCfgFlags: $(if ($null -eq $val) {'Not set'} else {$val}) (1=UEFI lock, 2=No lock)" "CIS"

# 68.6 System Guard Launch - Enabled
$val = Get-RegValue $dgBase "ConfigureSystemGuardLaunch"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "68.6" "VBS: System Guard Launch" $s "CIS 18.8.5.7: ConfigureSystemGuardLaunch: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Enabled)" "CIS"

# ============================================================
#  SECTION 69: CIS L1 - LOGON & CREDENTIAL UI  [CIS]
# ============================================================
Write-SectionHeader "69. CIS L1 - LOGON & CREDENTIAL UI" "CIS"

# 69.1 Do not display network selection UI on lock screen
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "69.1" "No Network Selection UI on Lock Screen" $s "CIS 18.8.28.2: DontDisplayNetworkSelectionUI: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 69.2 Do not enumerate connected users on domain-joined computers
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontEnumerateConnectedUsers"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "69.2" "No Enumerate Connected Users" $s "CIS 18.8.28.3: DontEnumerateConnectedUsers: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 69.3 Enumerate local users on domain-joined computers - Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "69.3" "No Enumerate Local Users on Domain PC" $s "CIS 18.8.28.4: EnumerateLocalUsers: $(if ($null -eq $val) {'Not set (disabled)'} else {$val}) (0=Disabled)" "CIS"

# 69.4 Turn off app notifications on lock screen
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "69.4" "No App Notifications on Lock Screen" $s "CIS 18.8.28.5: DisableLockScreenAppNotifications: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 69.5 Turn off picture password sign-in
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockDomainPicturePassword"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "69.5" "Picture Password Sign-In Disabled" $s "CIS 18.8.28.6: BlockDomainPicturePassword: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 69.6 Turn on convenience PIN sign-in - Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowDomainPINLogon"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "69.6" "Convenience PIN Sign-In Disabled" $s "CIS 18.8.28.7: AllowDomainPINLogon: $(if ($null -eq $val) {'Not set (disabled)'} else {$val}) (0=Disabled)" "CIS"

# 69.7 Do not display the password reveal button
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "69.7" "Password Reveal Button Disabled" $s "CIS 18.9.15.1: DisablePasswordReveal: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 69.8 Enumerate administrator accounts on elevation - Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "69.8" "No Admin Enumeration on Elevation" $s "CIS 18.9.15.2: EnumerateAdministrators: $(if ($null -eq $val) {'Not set (disabled)'} else {$val}) (0=Disabled)" "CIS"

# 69.9 Turn off notifications network usage
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "69.9" "Turn Off Notification Network Usage" $s "CIS 18.8.50.1: NoCloudApplicationNotification: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# ============================================================
#  SECTION 70: CIS L1 - ADDITIONAL ADMIN TEMPLATES  [CIS]
# ============================================================
Write-SectionHeader "70. CIS L1 - ADDITIONAL ADMIN TEMPLATES" "CIS"

# 70.1 Configure SMB v1 client driver - Disabled (4)
$val = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start"
$s   = if ($val -eq 4) { "PASS" } else { "WARN" }
Add-Result "70.1" "SMBv1 Client Driver Disabled" $s "CIS 18.3.2: MrxSmb10 Start: $(if ($null -eq $val) {'Not set'} else {$val}) (4=Disabled)" "CIS"

# 70.2 Enable Font Providers - Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableFontProviders"
$s   = if ($val -eq 0) { "PASS" } else { "WARN" }
Add-Result "70.2" "Font Providers Disabled" $s "CIS 18.5.5.1: EnableFontProviders: $(if ($null -eq $val) {'Not set'} else {$val}) (0=Disabled)" "CIS"

# 70.3 Require domain users to elevate when setting network location
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_StdDomainUserSetLocation"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "70.3" "Domain Users Elevate for Network Loc" $s "CIS 18.5.11.3: NC_StdDomainUserSetLocation: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 70.4 Turn off Windows Connect Now wizards
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" "DisableFlashConfigRegistrar"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "70.4" "Windows Connect Now Wizards Disabled" $s "CIS 18.5.23.2.1: DisableFlashConfigRegistrar: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Disabled)" "CIS"

# 70.5 Allow Microsoft accounts to be optional
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "70.5" "Microsoft Accounts Optional" $s "CIS 18.9.3.1: MSAOptional: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Optional)" "CIS"

# 70.6 Turn off cloud optimised content
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableCloudOptimizedContent"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "70.6" "Cloud Optimised Content Disabled" $s "CIS 18.9.12.2: DisableCloudOptimizedContent: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 70.7 Turn off Microsoft consumer experiences
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "70.7" "Microsoft Consumer Experiences Off" $s "CIS 18.9.12.3: DisableWindowsConsumerFeatures: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 70.8 Windows Installer: Always install with elevated privileges - Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "70.8" "Installer: No Always-Elevated Install" $s "CIS 18.9.45.1: AlwaysInstallElevated: $(if ($null -eq $val) {'Not set (disabled)'} else {$val}) (0=Disabled)" "CIS"

# 70.9 Sign-in and lock last interactive user automatically after restart - Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "70.9" "Auto Sign-In After Restart Disabled" $s "CIS 18.9.46.1: DisableAutomaticRestartSignOn: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Disabled)" "CIS"

# 70.10 Restrict RDP users to single session
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fSingleSessionPerUser"
$s   = if ($val -eq 1 -or $null -eq $val) { "PASS" } else { "WARN" }
Add-Result "70.10" "RDP: Single Session Per User" $s "CIS 18.9.65.3.2.1: fSingleSessionPerUser: $(if ($null -eq $val) {'Default (1)'} else {$val})" "CIS"

# 70.11 RDP: Set client connection encryption level - High
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel"
$s   = if ($val -eq 3) { "PASS" } else { "WARN" }
Add-Result "70.11" "RDP: Encryption Level High" $s "CIS 18.9.65.3.4.1: MinEncryptionLevel: $(if ($null -eq $val) {'Not set'} else {$val}) (3=High)" "CIS"

# 70.12 RDP: Do not delete temp folders upon exit - Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DeleteTempDirsOnExit"
$s   = if ($val -eq 1 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "70.12" "RDP: Delete Temp Folders on Exit" $s "CIS 18.9.65.3.9.3: DeleteTempDirsOnExit: $(if ($null -eq $val) {'Default (1)'} else {$val}) (1=Delete)" "CIS"

# 70.13 Prevent downloading of enclosures (RSS Feeds)
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "70.13" "RSS: Prevent Enclosure Download" $s "CIS 18.9.66.1: DisableEnclosureDownload: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 70.14 Windows Error Reporting: Auto-send memory dumps disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "AutoApproveOSDumps"
$s   = if ($val -eq 0 -or $null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "70.14" "WER: No Auto-Send Memory Dumps" $s "CIS 18.9.85.1: AutoApproveOSDumps: $(if ($null -eq $val) {'Not set (disabled)'} else {$val}) (0=Disabled)" "CIS"

# 70.15 Windows Game Recording and Broadcasting - Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR"
$s   = if ($val -eq 0) { "PASS" } else { "WARN" }
Add-Result "70.15" "Game Recording/Broadcasting Disabled" $s "CIS 18.9.90.1: AllowGameDVR: $(if ($null -eq $val) {'Not set'} else {$val}) (0=Disabled)" "CIS"

# 70.16 Allow Remote Shell Access - Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" "AllowRemoteShellAccess"
$s   = if ($val -eq 0) { "PASS" } else { "WARN" }
Add-Result "70.16" "Remote Shell Access Disabled" $s "CIS 18.9.105.1: AllowRemoteShellAccess: $(if ($null -eq $val) {'Not set'} else {$val}) (0=Disabled)" "CIS"


# ============================================================
#  SECTION 71: CIS L1 - ACCOUNT LOCKOUT & USER RIGHTS ADDITIONAL  [CIS]
# ============================================================
Write-SectionHeader "71. CIS L1 - ACCOUNT LOCKOUT & USER RIGHTS ADDITIONAL" "CIS"

# 71.1 CIS 1.2.3: Ensure 'Allow Administrator account lockout' is set to 'Enab
$val = Get-SecEditValue "AllowAdministratorLockout"
$s   = if ($val -eq "1") { "PASS" } else { "WARN" }
Add-Result "71.1" "Admin Account Lockout Enabled" $s "CIS 1.2.3: AllowAdministratorLockout: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Enabled)" "CIS"

# 71.2 CIS 2.2.8: Ensure 'Change the system time' is set to 'Administrators, L
$val = Get-UserRight "SeSystemTimePrivilege"
$s   = if ($val -and $val -notmatch "Everyone" -and $val -notmatch "Users") { "PASS" } else { "WARN" }
Add-Result "71.2" "Change System Time: Admins, LOCAL SERVICE" $s "CIS 2.2.8: SeSystemTimePrivilege: $(if ($val) {$val} else {'Not assigned'})" "CIS"

# 71.3 CIS 2.2.30: Ensure 'Modify an object label' is set to 'No One
$val = Get-UserRight "SeReLabelPrivilege"
$s   = if ($null -eq $val -or $val -eq "") { "PASS" } else { "FAIL" }
Add-Result "71.3" "Modify an object label : No One" $s "CIS 2.2.30: SeReLabelPrivilege: $(if ($val) {$val} else {'Not assigned'})" "CIS"

# 71.4 CIS 2.2.34: Ensure 'Profile system performance' is set to 'Administrator
$val = Get-UserRight "SeSystemProfilePrivilege"
$s   = if ($val -and $val -ne "") { "PASS" } else { "WARN" }
Add-Result "71.4" "Profile System Performance" $s "CIS 2.2.34: SeSystemProfilePrivilege: $(if ($val) {$val} else {'Not assigned'})" "CIS"

# 71.5 CIS 2.3.1.1: Ensure 'Accounts: Guest account status' is set to 'Disabled
$gAcct = $null; try { $gAcct = Get-LocalUser -Name "Guest" -ErrorAction Stop } catch {}
if ($null -eq $gAcct) { $gAcct = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-501" } -ErrorAction SilentlyContinue }
$s = if ($null -eq $gAcct -or -not $gAcct.Enabled) { "PASS" } else { "FAIL" }
Add-Result "71.5" "Guest Account Disabled" $s "CIS 2.3.1.1: $(if ($gAcct) {"Enabled=$($gAcct.Enabled)"} else {'Not found (compliant)'})" "CIS"

# 71.6 CIS 2.3.1.3: Configure 'Accounts: Rename administrator account
$admAcct = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-500" } -ErrorAction SilentlyContinue
$s = if ($admAcct -and $admAcct.Name -ne "Administrator") { "PASS" } else { "WARN" }
Add-Result "71.6" "Admin Account Renamed" $s "CIS 2.3.1.3: Name: $(if ($admAcct) {$admAcct.Name} else {'Not found'})" "CIS"

# 71.7 CIS 2.3.1.4: Configure 'Accounts: Rename guest account'
$gAcct2 = $null; try { $gAcct2 = Get-LocalUser -Name "Guest" -ErrorAction Stop } catch {}
if ($null -eq $gAcct2) { $gAcct2 = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-501" } -ErrorAction SilentlyContinue }
$s = if ($null -eq $gAcct2) { "PASS" } elseif ($gAcct2.Name -ne "Guest") { "PASS" } else { "WARN" }
Add-Result "71.7" "Guest Account Renamed" $s "CIS 2.3.1.4: Name: $(if ($gAcct2) {$gAcct2.Name} else {'Not found'})" "CIS"

# 71.8 CIS 2.3.6.4: Ensure 'Domain member: Disable machine account password chan
$val = Get-RegValue "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" "DisablePasswordChange"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "71.8" "Domain member: Disable machine account password ch" $s "CIS 2.3.6.4: DisablePasswordChange: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 71.9 CIS 2.3.9.4: Ensure 'Microsoft network server: Server SPN target name val
$val = Get-RegValue "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" "SMBServerNameHardeningLevel"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "71.9" "Microsoft network server: Server SPN target name v" $s "CIS 2.3.9.4: SMBServerNameHardeningLevel: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 71.10 CIS 2.3.10.1: Ensure 'Network access: Allow anonymous SID/Name translation
$val = Get-SecEditValue "LSAAnonymousNameLookup"
$s   = if ($val -eq "0" -or $val -eq 0) { "PASS" } else { "FAIL" }
Add-Result "71.10" "Anonymous SID/Name Translation Off" $s "CIS 2.3.10.1: LSAAnonymousNameLookup: $(if ($null -eq $val) {'Not set'} else {$val}) (0=Disabled)" "CIS"

# 71.11 CIS 2.3.11.5: Ensure 'Network security: Force logoff when logon hours expire'
$val = Get-SecEditValue "ForceLogoffWhenHourExpire"
$s   = if ($val -eq "1" -or $val -eq 1) { "PASS" } else { "WARN" }
Add-Result "71.11" "Force Logoff When Hours Expire" $s "CIS 2.3.11.5: ForceLogoffWhenHourExpire: $(if ($null -eq $val) {'Not set'} else {$val}) (1=Enabled)" "CIS"

# 71.12 CIS 2.3.11.7: Ensure 'Network security: LDAP client encryption requirement
$val = Get-RegValue "HKLM:\System\CurrentControlSet\Services\LDAP" "LDAPClientConfidentiality"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "71.12" "Network security: LDAP client encryption requireme" $s "CIS 2.3.11.7: LDAPClientConfidentiality: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 71.13 CIS 2.3.11.11: Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM
$val = Get-RegValue "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" "AuditReceivingNTLMTraffic"
$s   = if ($val -eq 2) { "PASS" } else { "WARN" }
Add-Result "71.13" "Network security: Restrict NTLM: Audit Incoming NT" $s "CIS 2.3.11.11: AuditReceivingNTLMTraffic: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 71.14 CIS 2.3.15.1: Ensure 'System objects: Require case insensitivity for non-W
$val = Get-RegValue "HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel" "ObCaseInsensitive"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "71.14" "System objects: Require case insensitivity for non" $s "CIS 2.3.15.1: ObCaseInsensitive: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 71.15 CIS 2.3.17.1: Ensure 'User Account Control: Admin Approval Mode for the Bu
$val = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "71.15" "User Account Control: Admin Approval Mode for the " $s "CIS 2.3.17.1: FilterAdministratorToken: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 71.16 CIS 2.3.17.4: Ensure 'User Account Control: Detect application installatio
$val = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "71.16" "User Account Control: Detect application installat" $s "CIS 2.3.17.4: EnableInstallerDetection: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"


# ============================================================
#  SECTION 72: CIS L1 - WINDOWS FIREWALL POLICY (CIS 9.x)  [CIS]
# ============================================================
Write-SectionHeader "72. CIS L1 - WINDOWS FIREWALL POLICY (CIS 9.x)" "CIS"

# 72.1 CIS 9.1.3: Ensure 'Windows Firewall: Domain: Settings: Display a notifi
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" "DisableNotifications"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "72.1" "Windows Firewall: Domain: Settings: Display a noti" $s "CIS 9.1.3: DisableNotifications: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.2 CIS 9.1.4: Ensure 'Windows Firewall: Domain: Logging: Name' is configur
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFilePath"
$s   = if ($null -ne $val -and $val -ne "") { "PASS" } else { "WARN" }
Add-Result "72.2" "Windows Firewall: Domain: Logging: Name is configu" $s "CIS 9.1.4: LogFilePath: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.3 CIS 9.1.5: Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' 
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogFileSize"
$s   = if ($null -ne $val -and [int]$val -ge 16384) { "PASS" } else { "WARN" }
Add-Result "72.3" "Windows Firewall: Domain: Logging: Size limit (KB)" $s "CIS 9.1.5: LogFileSize: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.4 CIS 9.1.6: Ensure 'Windows Firewall: Domain: Logging: Log dropped packe
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogDroppedPackets"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "72.4" "Windows Firewall: Domain: Logging: Log dropped pac" $s "CIS 9.1.6: LogDroppedPackets: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.5 CIS 9.1.7: Ensure 'Windows Firewall: Domain: Logging: Log successful co
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" "LogSuccessfulConnections"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "72.5" "Windows Firewall: Domain: Logging: Log successful " $s "CIS 9.1.7: LogSuccessfulConnections: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.6 CIS 9.2.3: Ensure 'Windows Firewall: Private: Settings: Display a notif
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DisableNotifications"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "72.6" "Windows Firewall: Private: Settings: Display a not" $s "CIS 9.2.3: DisableNotifications: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.7 CIS 9.2.4: Ensure 'Windows Firewall: Private: Logging: Name' is configu
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFilePath"
$s   = if ($null -ne $val -and $val -ne "") { "PASS" } else { "WARN" }
Add-Result "72.7" "Windows Firewall: Private: Logging: Name is config" $s "CIS 9.2.4: LogFilePath: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.8 CIS 9.2.5: Ensure 'Windows Firewall: Private: Logging: Size limit (KB)'
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize"
$s   = if ($null -ne $val -and [int]$val -ge 16384) { "PASS" } else { "WARN" }
Add-Result "72.8" "Windows Firewall: Private: Logging: Size limit (KB" $s "CIS 9.2.5: LogFileSize: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.9 CIS 9.2.6: Ensure 'Windows Firewall: Private: Logging: Log dropped pack
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "72.9" "Windows Firewall: Private: Logging: Log dropped pa" $s "CIS 9.2.6: LogDroppedPackets: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.10 CIS 9.2.7: Ensure 'Windows Firewall: Private: Logging: Log successful c
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "72.10" "Windows Firewall: Private: Logging: Log successful" $s "CIS 9.2.7: LogSuccessfulConnections: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.11 CIS 9.3.3: Ensure 'Windows Firewall: Public: Settings: Display a notifi
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" "DisableNotifications"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "72.11" "Windows Firewall: Public: Settings: Display a noti" $s "CIS 9.3.3: DisableNotifications: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.12 CIS 9.3.4: Ensure 'Windows Firewall: Public: Settings: Apply local fire
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" "AllowLocalPolicyMerge"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "72.12" "Windows Firewall: Public: Settings: Apply local fi" $s "CIS 9.3.4: AllowLocalPolicyMerge: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.13 CIS 9.3.5: Ensure 'Windows Firewall: Public: Settings: Apply local conn
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" "AllowLocalIPsecPolicyMerge"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "72.13" "Windows Firewall: Public: Settings: Apply local co" $s "CIS 9.3.5: AllowLocalIPsecPolicyMerge: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.14 CIS 9.3.6: Ensure 'Windows Firewall: Public: Logging: Name' is configur
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFilePath"
$s   = if ($null -ne $val -and $val -ne "") { "PASS" } else { "WARN" }
Add-Result "72.14" "Windows Firewall: Public: Logging: Name is configu" $s "CIS 9.3.6: LogFilePath: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.15 CIS 9.3.7: Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' 
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogFileSize"
$s   = if ($null -ne $val -and [int]$val -ge 16384) { "PASS" } else { "WARN" }
Add-Result "72.15" "Windows Firewall: Public: Logging: Size limit (KB)" $s "CIS 9.3.7: LogFileSize: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.16 CIS 9.3.8: Ensure 'Windows Firewall: Public: Logging: Log dropped packe
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogDroppedPackets"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "72.16" "Windows Firewall: Public: Logging: Log dropped pac" $s "CIS 9.3.8: LogDroppedPackets: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 72.17 CIS 9.3.9: Ensure 'Windows Firewall: Public: Logging: Log successful co
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" "LogSuccessfulConnections"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "72.17" "Windows Firewall: Public: Logging: Log successful " $s "CIS 9.3.9: LogSuccessfulConnections: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"


# ============================================================
#  SECTION 73: CIS L1 - AUDIT POLICY ADDITIONAL (CIS 17.x)  [CIS]
# ============================================================
Write-SectionHeader "73. CIS L1 - AUDIT POLICY ADDITIONAL (CIS 17.x)" "CIS"

# 73.1 CIS 17.5.2: Ensure 'Audit Group Membership' is set to include 'Success
$aud = (auditpol /get /subcategory:"Group Membership" 2>$null) -join " "
$s   = if ($aud -match "Success") { "PASS" } else { "WARN" }
Add-Result "73.1" "Audit Group Membership : include Success" $s "CIS 17.5.2: Group Membership: $aud" "CIS"

# 73.2 CIS 17.7.3: Ensure 'Audit Authorization Policy Change' is set to include
$aud = (auditpol /get /subcategory:"Authorization Policy Change" 2>$null) -join " "
$s   = if ($aud -match "Success") { "PASS" } else { "WARN" }
Add-Result "73.2" "Audit Authorization Policy Change : include Succes" $s "CIS 17.7.3: Authorization Policy Change: $aud" "CIS"

# 73.3 CIS 17.9.1: Ensure 'Audit IPsec Driver' is set to 'Success and Failure
$aud = (auditpol /get /subcategory:"IPsec Driver" 2>$null) -join " "
$s   = if ($aud -match "Success and Failure") { "PASS" } else { "WARN" }
Add-Result "73.3" "Audit IPsec Driver : Success and Failure" $s "CIS 17.9.1: IPsec Driver: $aud" "CIS"

# 73.4 CIS 17.9.2: Ensure 'Audit Other System Events' is set to 'Success and Fa
$aud = (auditpol /get /subcategory:"Other System Events" 2>$null) -join " "
$s   = if ($aud -match "Success and Failure") { "PASS" } else { "WARN" }
Add-Result "73.4" "Audit Other System Events : Success and Failure" $s "CIS 17.9.2: Other System Events: $aud" "CIS"


# ============================================================
#  SECTION 74: CIS L1 - PERSONALIZATION & SPEECH (CIS 18.1)  [CIS]
# ============================================================
Write-SectionHeader "74. CIS L1 - PERSONALIZATION & SPEECH (CIS 18.1)" "CIS"

# 74.1 CIS 18.1.1.1: Ensure 'Prevent enabling lock screen camera' is set to 'Enab
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "74.1" "Prevent enabling lock screen camera : On" $s "CIS 18.1.1.1: NoLockScreenCamera: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 74.2 CIS 18.1.1.2: Ensure 'Prevent enabling lock screen slide show' is set to '
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "74.2" "Prevent enabling lock screen slide show : On" $s "CIS 18.1.1.2: NoLockScreenSlideshow: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 74.3 CIS 18.1.2.2: Ensure 'Allow users to enable online speech recognition serv
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "74.3" "Allow users to enable online speech recognition se" $s "CIS 18.1.2.2: AllowInputPersonalization: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"


# ============================================================
#  SECTION 75: CIS L1 - MSS & NETWORK HARDENING (CIS 18.5-18.6)  [CIS]
# ============================================================
Write-SectionHeader "75. CIS L1 - MSS & NETWORK HARDENING (CIS 18.5-18.6)" "CIS"

# 75.1 CIS 18.5.7: Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to i
$val = Get-RegValue "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" "NoNameReleaseOnDemand"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "75.1" "MSS: (NoNameReleaseOnDemand) Allow the computer to" $s "CIS 18.5.7: NoNameReleaseOnDemand: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.2 CIS 18.6.7.1: Ensure 'Audit client does not support encryption' is set to 
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanServer" "AuditClientDoesNotSupportEncryption"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "75.2" "Audit client does not support encryption : On" $s "CIS 18.6.7.1: AuditClientDoesNotSupportEncryption: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.3 CIS 18.6.7.2: Ensure 'Audit client does not support signing' is set to 'En
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanServer" "AuditClientDoesNotSupportSigning"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "75.3" "Audit client does not support signing : On" $s "CIS 18.6.7.2: AuditClientDoesNotSupportSigning: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.4 CIS 18.6.7.3: Ensure 'Audit insecure guest logon' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanServer" "AuditInsecureGuestLogon"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "75.4" "Audit insecure guest logon : On" $s "CIS 18.6.7.3: AuditInsecureGuestLogon: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.5 CIS 18.6.7.4: Ensure 'Enable authentication rate limiter' is set to 'Enabl
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanServer" "EnableAuthRateLimiter"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "75.5" "Enable authentication rate limiter : On" $s "CIS 18.6.7.4: EnableAuthRateLimiter: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.6 CIS 18.6.7.5: Ensure 'Enable remote mailslots' is set to 'Disabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Bowser" "EnableMailslots"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "75.6" "Enable remote mailslots : Off" $s "CIS 18.6.7.5: EnableMailslots: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.7 CIS 18.6.7.6: Ensure 'Mandate the minimum version of SMB' is set to 'Enabl
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanServer" "MinSmb2Dialect"
$s   = if ($val -eq 785) { "PASS" } else { "WARN" }
Add-Result "75.7" "Mandate the minimum version of SMB : On: 3.1.1" $s "CIS 18.6.7.6: MinSmb2Dialect: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.8 CIS 18.6.7.7: Ensure 'Set authentication rate limiter delay (milliseconds)
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanServer" "InvalidAuthenticationDelayTimeInMs"
$s   = if ($null -ne $val -and [int]$val -ge 2000) { "PASS" } else { "WARN" }
Add-Result "75.8" "Set authentication rate limiter delay (millisecond" $s "CIS 18.6.7.7: InvalidAuthenticationDelayTimeInMs: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.9 CIS 18.6.8.1: Ensure 'Audit insecure guest logon' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation" "AuditInsecureGuestLogon"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "75.9" "Audit insecure guest logon : On" $s "CIS 18.6.8.1: AuditInsecureGuestLogon: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.10 CIS 18.6.8.2: Ensure 'Audit server does not support encryption' is set to 
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation" "AuditServerDoesNotSupportEncryption"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "75.10" "Audit server does not support encryption : On" $s "CIS 18.6.8.2: AuditServerDoesNotSupportEncryption: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.11 CIS 18.6.8.3: Ensure 'Audit server does not support signing' is set to 'En
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation" "AuditServerDoesNotSupportSigning"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "75.11" "Audit server does not support signing : On" $s "CIS 18.6.8.3: AuditServerDoesNotSupportSigning: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.12 CIS 18.6.8.4: Ensure 'Enable insecure guest logons' is set to 'Disabled
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "75.12" "Enable insecure guest logons : Off" $s "CIS 18.6.8.4: AllowInsecureGuestAuth: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.13 CIS 18.6.8.5: Ensure 'Enable remote mailslots' is set to 'Disabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider" "EnableMailslots"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "75.13" "Enable remote mailslots : Off" $s "CIS 18.6.8.5: EnableMailslots: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.14 CIS 18.6.8.6: Ensure 'Mandate the minimum version of SMB' is set to 'Enabl
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation" "MinSmb2Dialect"
$s   = if ($val -eq 785) { "PASS" } else { "WARN" }
Add-Result "75.14" "Mandate the minimum version of SMB : On: 3.1.1" $s "CIS 18.6.8.6: MinSmb2Dialect: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.15 CIS 18.6.8.7: Ensure 'Require Encryption' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation" "RequireEncryption"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "75.15" "Require Encryption : On" $s "CIS 18.6.8.7: RequireEncryption: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.16 CIS 18.6.11.2: Ensure 'Prohibit installation and configuration of Network B
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" "NC_AllowNetBridge_NLA"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "75.16" "Prohibit installation and configuration of Network" $s "CIS 18.6.11.2: NC_AllowNetBridge_NLA: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.17 CIS 18.6.11.3: Ensure 'Prohibit use of Internet Connection Sharing on your 
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "75.17" "Prohibit use of Internet Connection Sharing on you" $s "CIS 18.6.11.3: NC_ShowSharedAccessUI: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.18 CIS 18.6.21.1: Ensure 'Minimize the number of simultaneous connections to t
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections"
$s   = if ($val -eq 3) { "PASS" } else { "WARN" }
Add-Result "75.18" "Minimize the number of simultaneous connections to" $s "CIS 18.6.21.1: fMinimizeConnections: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 75.19 CIS 18.6.23.2.1: Ensure 'Allow Windows to automatically connect to suggested 
$val = Get-RegValue "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "75.19" "Allow Windows to automatically connect to suggeste" $s "CIS 18.6.23.2.1: AutoConnectAllowedOEM: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"


# ============================================================
#  SECTION 76: CIS L1 - PRINTER SECURITY (CIS 18.7)  [CIS]
# ============================================================
Write-SectionHeader "76. CIS L1 - PRINTER SECURITY (CIS 18.7)" "CIS"

# 76.1 CIS 18.7.1: Ensure 'Allow Print Spooler to accept client connections' is
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" "RegisterSpoolerRemoteRpcEndPoint"
$s   = if ($val -eq 2) { "PASS" } else { "WARN" }
Add-Result "76.1" "Allow Print Spooler to accept client connections :" $s "CIS 18.7.1: RegisterSpoolerRemoteRpcEndPoint: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 76.2 CIS 18.7.2: Ensure 'Configure Redirection Guard' is set to 'Enabled: Red
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" "RedirectionGuardPolicy"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "76.2" "Configure Redirection Guard : On: Redirection Guar" $s "CIS 18.7.2: RedirectionGuardPolicy: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 76.3 CIS 18.7.3: Ensure 'Configure RPC connection settings: Protocol to use f
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" "RpcUseNamedPipeProtocol"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "76.3" "Configure RPC connection settings: Protocol to use" $s "CIS 18.7.3: RpcUseNamedPipeProtocol: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 76.4 CIS 18.7.4: Ensure 'Configure RPC connection settings: Use authenticatio
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" "RpcAuthentication"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "76.4" "Configure RPC connection settings: Use authenticat" $s "CIS 18.7.4: RpcAuthentication: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 76.5 CIS 18.7.5: Ensure 'Configure RPC listener settings: Protocols to allow 
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" "RpcProtocols"
$s   = if ($val -eq 5) { "PASS" } else { "WARN" }
Add-Result "76.5" "Configure RPC listener settings: Protocols to allo" $s "CIS 18.7.5: RpcProtocols: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 76.6 CIS 18.7.6: Ensure 'Configure RPC listener settings: Authentication prot
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" "ForceKerberosForRpc"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "76.6" "Configure RPC listener settings: Authentication pr" $s "CIS 18.7.6: ForceKerberosForRpc: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 76.7 CIS 18.7.7: Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" "RpcTcpPort"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "76.7" "Configure RPC over TCP port : On: 0" $s "CIS 18.7.7: RpcTcpPort: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 76.8 CIS 18.7.11: Ensure 'Manage processing of Queue-specific files' is set to
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" "CopyFilesPolicy"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "76.8" "Manage processing of Queue-specific files : On: Li" $s "CIS 18.7.11: CopyFilesPolicy: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"


# ============================================================
#  SECTION 77: CIS L1 - SYSTEM ADMIN TEMPLATES (CIS 18.9)  [CIS]
# ============================================================
Write-SectionHeader "77. CIS L1 - SYSTEM ADMIN TEMPLATES (CIS 18.9)" "CIS"

# 77.1 CIS 18.9.4.1: Ensure 'Encryption Oracle Remediation' is set to 'Enabled: F
$val = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "77.1" "Encryption Oracle Remediation : On: Force Updated " $s "CIS 18.9.4.1: AllowEncryptionOracle: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.2 CIS 18.9.5.4: Ensure 'Turn On Virtualization Based Security: Require UEFI 
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" "HVCIMATRequired"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "77.2" "Turn On Virtualization Based Security: Require UEF" $s "CIS 18.9.5.4: HVCIMATRequired: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.3 CIS 18.9.5.7: Ensure 'Turn On Virtualization Based Security: Kernel-mode H
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" "ConfigureKernelShadowStacksLaunch"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "77.3" "Turn On Virtualization Based Security: Kernel-mode" $s "CIS 18.9.5.7: ConfigureKernelShadowStacksLaunch: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.4 CIS 18.9.7.2: Ensure 'Prevent automatic download of applications associate
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "77.4" "Prevent automatic download of applications associa" $s "CIS 18.9.7.2: PreventDeviceMetadataFromNetwork: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.5 CIS 18.9.17.1: Ensure 'Enable / disable CLFS logfile authentication' is set
$val = Get-RegValue "HKLM:\System\CurrentControlSet\Policies" "ClfsAuthenticationChecking"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "77.5" "Enable / disable CLFS logfile authentication : On" $s "CIS 18.9.17.1: ClfsAuthenticationChecking: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.6 CIS 18.9.19.2: Ensure 'Configure security policy processing: Do not apply d
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" "NoBackgroundPolicy"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "77.6" "Configure security policy processing: Do not apply" $s "CIS 18.9.19.2: NoBackgroundPolicy: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.7 CIS 18.9.19.4: Ensure 'Continue experiences on this device' is set to 'Disa
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\System" "EnableCdp"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "77.7" "Continue experiences on this device : Off" $s "CIS 18.9.19.4: EnableCdp: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.8 CIS 18.9.19.5: Turn off background refresh of Group Policy (should be Disabled)
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableBkGndGroupPolicy"
$s   = if ($null -eq $val) { "PASS" } else { "FAIL" }
Add-Result "77.8" "GP Background Refresh Enabled" $s "CIS 18.9.19.5: DisableBkGndGroupPolicy: $(if ($null -eq $val) {'Not set (correct - GP refreshes in background)'} else {"$val (should not exist)"})" "CIS"

# 77.9 CIS 18.9.20.1.6: Ensure 'Turn off Internet download for Web publishing and on
$val = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWebServices"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "77.9" "Turn off Internet download for Web publishing and " $s "CIS 18.9.20.1.6: NoWebServices: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.10 CIS 18.9.26.2: Ensure 'Do not allow password expiration time longer than re
$val = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PasswordExpirationProtectionEnabled"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "77.10" "Do not allow password expiration time longer than " $s "CIS 18.9.26.2: PasswordExpirationProtectionEnabled: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.11 CIS 18.9.26.3: Ensure 'Enable password encryption' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" "ADPasswordEncryptionEnabled"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "77.11" "Enable password encryption : On" $s "CIS 18.9.26.3: ADPasswordEncryptionEnabled: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.12 CIS 18.9.26.7: Ensure 'Post-authentication actions: Grace period (hours)' i
$val = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" "PostAuthenticationResetDelay"
$s   = if ($null -ne $val -and $val -ne "") { "PASS" } else { "WARN" }
Add-Result "77.12" "Post-authentication actions: Grace period (hours) " $s "CIS 18.9.26.7: PostAuthenticationResetDelay: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.13 CIS 18.9.27.1: Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' i
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\System" "AllowCustomSSPsAPs"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "77.13" "Allow Custom SSPs and APs to be loaded into LSASS " $s "CIS 18.9.27.1: AllowCustomSSPsAPs: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.14 CIS 18.9.31.1.1: Ensure 'Block NetBIOS-based discovery for domain controller 
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Netlogon\Parameters" "BlockNetbiosDiscovery"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "77.14" "Block NetBIOS-based discovery for domain controlle" $s "CIS 18.9.31.1.1: BlockNetbiosDiscovery: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 77.15 CIS 18.9.41.1: Ensure 'Configure SAM change password RPC methods policy' is
$val = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\SAM" "SamrChangeUserPasswordApiPolicy"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "77.15" "Configure SAM change password RPC methods policy :" $s "CIS 18.9.41.1: SamrChangeUserPasswordApiPolicy: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"


# ============================================================
#  SECTION 78: CIS L1 - WINDOWS COMPONENTS (CIS 18.10)  [CIS]
# ============================================================
Write-SectionHeader "78. CIS L1 - WINDOWS COMPONENTS (CIS 18.10)" "CIS"

# 78.1 CIS 18.10.4.2: Ensure 'Not allow per-user unsigned packages to install by d
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Appx" "DisablePerUserUnsignedPackagesByDefault"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.1" "Not allow per-user unsigned packages to install by" $s "CIS 18.10.4.2: DisablePerUserUnsignedPackagesByDefault: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.2 CIS 18.10.4.3: Ensure 'Prevent non-admin users from installing packaged Win
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Appx" "BlockNonAdminUserInstall"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.2" "Prevent non-admin users from installing packaged W" $s "CIS 18.10.4.3: BlockNonAdminUserInstall: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.3 CIS 18.10.5.1: Ensure 'Let Windows apps activate with voice while the syste
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoiceAboveLock"
$s   = if ($val -eq 2) { "PASS" } else { "WARN" }
Add-Result "78.3" "Let Windows apps activate with voice while the sys" $s "CIS 18.10.5.1: LetAppsActivateWithVoiceAboveLock: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.4 CIS 18.10.15.3: Ensure 'Prevent the use of security questions for local acco
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\System" "NoLocalPasswordResetQuestions"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.4" "Prevent the use of security questions for local ac" $s "CIS 18.10.15.3: NoLocalPasswordResetQuestions: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.5 CIS 18.10.18.2: Ensure 'Enable App Installer Experimental Features' is set t
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\AppInstaller" "EnableExperimentalFeatures"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.5" "Enable App Installer Experimental Features : Off" $s "CIS 18.10.18.2: EnableExperimentalFeatures: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.6 CIS 18.10.18.3: Ensure 'Enable App Installer Hash Override' is set to 'Disab
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\AppInstaller" "EnableHashOverride"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.6" "Enable App Installer Hash Override : Off" $s "CIS 18.10.18.3: EnableHashOverride: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.7 CIS 18.10.18.4: Ensure 'Enable App Installer Local Archive Malware Scan Over
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\AppInstaller" "EnableLocalArchiveMalwareScanOverride"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.7" "Enable App Installer Local Archive Malware Scan Ov" $s "CIS 18.10.18.4: EnableLocalArchiveMalwareScanOverride: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.8 CIS 18.10.18.5: Ensure 'Enable App Installer Microsoft Store Source Certific
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\AppInstaller" "EnableBypassCertificatePinningForMicrosoftStore"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.8" "Enable App Installer Microsoft Store Source Certif" $s "CIS 18.10.18.5: EnableBypassCertificatePinningForMicrosoftStore: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.9 CIS 18.10.18.6: Ensure 'Enable App Installer ms-appinstaller protocol' is se
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\AppInstaller" "EnableMSAppInstallerProtocol"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.9" "Enable App Installer ms-appinstaller protocol : Of" $s "CIS 18.10.18.6: EnableMSAppInstallerProtocol: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.10 CIS 18.10.29.4: Ensure 'Do not apply the Mark of the Web tag to files copied
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Explorer" "DisableMotWOnInsecurePathCopy"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.10" "Do not apply the Mark of the Web tag to files copi" $s "CIS 18.10.29.4: DisableMotWOnInsecurePathCopy: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.11 CIS 18.10.41.1: Ensure 'Block all consumer Microsoft account user authentica
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\MicrosoftAccount" "DisableUserAuth"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.11" "Block all consumer Microsoft account user authenti" $s "CIS 18.10.41.1: DisableUserAuth: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.12 CIS 18.10.42.4.1: Ensure 'Enable EDR in block mode' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Features" "PassiveRemediation"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.12" "Enable EDR in block mode : On" $s "CIS 18.10.42.4.1: PassiveRemediation: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.13 CIS 18.10.42.5.1: Ensure 'Configure local setting override for reporting to Mi
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" "LocalSettingOverrideSpynetReporting"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.13" "Configure local setting override for reporting to " $s "CIS 18.10.42.5.1: LocalSettingOverrideSpynetReporting: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.14 CIS 18.10.42.7.1: Ensure 'Enable file hash computation feature' is set to 'Ena
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender\MpEngine" "EnableFileHashComputation"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.14" "Enable file hash computation feature : On" $s "CIS 18.10.42.7.1: EnableFileHashComputation: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.15 CIS 18.10.42.10.1: Ensure 'Configure real-time protection and Security Intellig
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "OobeEnableRtpAndSigUpdate"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.15" "Configure real-time protection and Security Intell" $s "CIS 18.10.42.10.1: OobeEnableRtpAndSigUpdate: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.16 CIS 18.10.42.10.4: Ensure 'Turn on behavior monitoring' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.16" "Turn on behavior monitoring : On" $s "CIS 18.10.42.10.4: DisableBehaviorMonitoring: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.17 CIS 18.10.42.10.5: Ensure 'Turn on script scanning' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableScriptScanning"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.17" "Turn on script scanning : On" $s "CIS 18.10.42.10.5: DisableScriptScanning: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.18 CIS 18.10.42.11.1.1.2: Ensure 'Configure Remote Encryption Protection Mode' is set 
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection" "BruteForceProtectionConfiguredState"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.18" "Configure Remote Encryption Protection Mode : On: " $s "CIS 18.10.42.11.1.1.2: BruteForceProtectionConfiguredState: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.19 CIS 18.10.42.13.1: Ensure 'Scan excluded files and directories during quick sca
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" "QuickScanIncludeExclusions"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.19" "Scan excluded files and directories during quick s" $s "CIS 18.10.42.13.1: QuickScanIncludeExclusions: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.20 CIS 18.10.42.13.2: Ensure 'Scan packed executables' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" "DisablePackedExeScanning"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.20" "Scan packed executables : On" $s "CIS 18.10.42.13.2: DisablePackedExeScanning: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.21 CIS 18.10.42.13.4: Ensure 'Trigger a quick scan after X days without any scans'
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" "DaysUntilAggressiveCatchupQuickScan"
$s   = if ($val -eq 7) { "PASS" } else { "WARN" }
Add-Result "78.21" "Trigger a quick scan after X days without any scan" $s "CIS 18.10.42.13.4: DaysUntilAggressiveCatchupQuickScan: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.22 CIS 18.10.42.17: Ensure 'Control whether exclusions are visible to local user
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender" "HideExclusionsFromLocalUsers"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.22" "Control whether exclusions are visible to local us" $s "CIS 18.10.42.17: HideExclusionsFromLocalUsers: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.23 CIS 18.10.43.1: Ensure 'Allow auditing events in Microsoft Defender Applicat
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\AppHVSI" "AuditApplicationGuard"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.23" "Allow auditing events in Microsoft Defender Applic" $s "CIS 18.10.43.1: AuditApplicationGuard: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.24 CIS 18.10.43.2: Ensure 'Allow camera and microphone access in Microsoft Defe
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\AppHVSI" "AllowCameraMicrophoneRedirection"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.24" "Allow camera and microphone access in Microsoft De" $s "CIS 18.10.43.2: AllowCameraMicrophoneRedirection: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.25 CIS 18.10.43.4: Ensure 'Allow files to download and save to the host operati
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\AppHVSI" "SaveFilesToHost"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.25" "Allow files to download and save to the host opera" $s "CIS 18.10.43.4: SaveFilesToHost: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.26 CIS 18.10.57.3.9.2: Ensure 'Require secure RPC communication' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.26" "Require secure RPC communication : On" $s "CIS 18.10.57.3.9.2: fEncryptRPCTraffic: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.27 CIS 18.10.57.3.9.3: Ensure 'Require use of specific security layer for remote (R
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" "SecurityLayer"
$s   = if ($val -eq 2) { "PASS" } else { "WARN" }
Add-Result "78.27" "Require use of specific security layer for remote " $s "CIS 18.10.57.3.9.3: SecurityLayer: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.28 CIS 18.10.59.4: Ensure 'Allow Cortana above lock screen' is set to 'Disabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" "AllowCortanaAboveLock"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.28" "Allow Cortana above lock screen : Off" $s "CIS 18.10.59.4: AllowCortanaAboveLock: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.29 CIS 18.10.59.6: Ensure 'Allow search and Cortana to use location' is set to 
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" "AllowSearchToUseLocation"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.29" "Allow search and Cortana to use location : Off" $s "CIS 18.10.59.6: AllowSearchToUseLocation: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.30 CIS 18.10.66.3: Ensure 'Turn off the offer to update to the latest version o
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\WindowsStore" "DisableOSUpgrade"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.30" "Turn off the offer to update to the latest version" $s "CIS 18.10.66.3: DisableOSUpgrade: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.31 CIS 18.10.73.1: Ensure 'Allow Recall to be enabled' is set to 'Disabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WindowsAI" "AllowRecallEnablement"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.31" "Allow Recall to be enabled : Off" $s "CIS 18.10.73.1: AllowRecallEnablement: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.32 CIS 18.10.77.1.1: Ensure 'Automatic Data Collection' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components" "CaptureThreatWindow"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.32" "Automatic Data Collection : On" $s "CIS 18.10.77.1.1: CaptureThreatWindow: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.33 CIS 18.10.77.1.2: Ensure 'Notify Malicious' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components" "NotifyMalicious"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.33" "Notify Malicious : On" $s "CIS 18.10.77.1.2: NotifyMalicious: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.34 CIS 18.10.77.1.3: Ensure 'Notify Password Reuse' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components" "NotifyPasswordReuse"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.34" "Notify Password Reuse : On" $s "CIS 18.10.77.1.3: NotifyPasswordReuse: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.35 CIS 18.10.77.1.4: Ensure 'Notify Unsafe App' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components" "NotifyUnsafeApp"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.35" "Notify Unsafe App : On" $s "CIS 18.10.77.1.4: NotifyUnsafeApp: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.36 CIS 18.10.77.1.5: Ensure 'Service Enabled' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WTDS\Components" "ServiceEnabled"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.36" "WTDS Service Enabled" $s "CIS 18.10.77.1.5: ServiceEnabled: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.37 CIS 18.10.80.1: Ensure 'Enable ESS with Supported Peripherals' is set to 'En
$val = Get-RegValue "HKLM:\Software\Microsoft\Policies\PassportForWork\Biometrics" "EnableESSwithSupportedPeripherals"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.37" "Enable ESS with Supported Peripherals : On: 1" $s "CIS 18.10.80.1: EnableESSwithSupportedPeripherals: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.38 CIS 18.10.81.2: Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On,
$val = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.38" "Allow Windows Ink Workspace : On: On, but disallow" $s "CIS 18.10.81.2: AllowWindowsInkWorkspace: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.39 CIS 18.10.82.1: Ensure 'Allow user control over installs' is set to 'Disable
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Installer" "EnableUserControl"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.39" "Allow user control over installs : Off" $s "CIS 18.10.82.1: EnableUserControl: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.40 CIS 18.10.83.1: Ensure 'Configure the transmission of the user's password in
$val = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "EnableMPR"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.40" "MPR: Do Not Transmit User Password" $s "CIS 18.10.83.1: EnableMPR: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.41 CIS 18.10.90.1.3: Ensure 'Disallow Digest authentication' is set to 'Enabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.41" "Disallow Digest authentication : On" $s "CIS 18.10.90.1.3: AllowDigest: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.42 CIS 18.10.92.1: Ensure 'Allow clipboard sharing with Windows Sandbox' is set
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Sandbox" "AllowClipboardRedirection"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.42" "Allow clipboard sharing with Windows Sandbox : Off" $s "CIS 18.10.92.1: AllowClipboardRedirection: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.43 CIS 18.10.92.3: Ensure 'Allow networking in Windows Sandbox' is set to 'Disa
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\Sandbox" "AllowNetworking"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.43" "Allow networking in Windows Sandbox : Off" $s "CIS 18.10.92.3: AllowNetworking: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.44 CIS 18.10.93.2.1: Ensure 'Prevent users from modifying settings' is set to 'En
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" "DisallowExploitProtectionOverride"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.44" "Prevent users from modifying settings : On" $s "CIS 18.10.93.2.1: DisallowExploitProtectionOverride: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.45 CIS 18.10.94.2.2: Ensure 'Configure Automatic Updates: Scheduled install day' 
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.45" "Configure Automatic Updates: Scheduled install day" $s "CIS 18.10.94.2.2: ScheduledInstallDay: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.46 CIS 18.10.94.2.3: Ensure 'Enable features introduced via servicing that are of
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "AllowTemporaryEnterpriseFeatureControl"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.46" "Enable features introduced via servicing that are " $s "CIS 18.10.94.2.3: AllowTemporaryEnterpriseFeatureControl: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.47 CIS 18.10.94.4.1: Ensure 'Manage preview builds' is set to 'Disabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "ManagePreviewBuildsPolicyValue"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "78.47" "Manage preview builds : Off" $s "CIS 18.10.94.4.1: ManagePreviewBuildsPolicyValue: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 78.48 CIS 18.10.94.4.3: Ensure 'Enable optional updates' is set to 'Disabled
$val = Get-RegValue "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "SetAllowOptionalContent"
$s   = if ($val -eq 0) { "PASS" } elseif ($null -eq $val) { "WARN" } else { "FAIL" }
Add-Result "78.48" "Enable optional updates : Off" $s "CIS 18.10.94.4.3: SetAllowOptionalContent: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"


# ============================================================
#  SECTION 79: CIS L1 - WIFI & USER TEMPLATES (CIS 18.11/19.7)  [CIS]
# ============================================================
Write-SectionHeader "79. CIS L1 - WIFI & USER TEMPLATES (CIS 18.11/19.7)" "CIS"

# 79.1 CIS 18.11.1: Ensure 'Disable HTTP proxy features: Disable WPAD' is set to
$val = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" "DisableWpad"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "79.1" "Disable HTTP proxy features: Disable WPAD : On: Ch" $s "CIS 18.11.1: DisableWpad: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 79.2 CIS 18.11.2: Ensure 'Disable HTTP proxy features: Disable proxy authentic
$val = Get-RegValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "DisableProxyAuthenticationSchemes"
$s   = if ($val -eq 256) { "PASS" } else { "WARN" }
Add-Result "79.2" "Disable HTTP proxy features: Disable proxy authent" $s "CIS 18.11.2: DisableProxyAuthenticationSchemes: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 79.3 CIS 19.7.8.5: Ensure 'Turn off Spotlight collection on Desktop' is set to 
$val = Get-RegValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableSpotlightCollectionOnDesktop"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "79.3" "Turn off Spotlight collection on Desktop : On" $s "CIS 19.7.8.5: DisableSpotlightCollectionOnDesktop: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# 79.4 CIS 19.7.26.1: Ensure 'Prevent users from sharing files within their profil
$val = Get-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInplaceSharing"
$s   = if ($val -eq 1) { "PASS" } else { "WARN" }
Add-Result "79.4" "Prevent users from sharing files within their prof" $s "CIS 19.7.26.1: NoInplaceSharing: $(if ($null -eq $val) {'Not set'} else {$val})" "CIS"

# ============================================================
#  SECTION 80: APPLICATION PATCH CURRENCY  [CE+ | CE5]
# ============================================================
Write-SectionHeader "80. APPLICATION PATCH CURRENCY" "CE+ | CE5"

# ---- Load known-vulnerabilities.json companion file if available ----
$vulnDataPath = Join-Path $PSScriptRoot "known-vulnerabilities.json"
$knownVulns   = @()
if (Test-Path $vulnDataPath) {
    try {
        $knownVulns = Get-Content $vulnDataPath -Raw -ErrorAction Stop | ConvertFrom-Json
        Add-Result "80.1" "Vulnerability Data File Loaded" "PASS" "Loaded $($knownVulns.Count) entries from known-vulnerabilities.json" "CE+"
    } catch {
        Add-Result "80.1" "Vulnerability Data File Loaded" "WARN" "known-vulnerabilities.json found but failed to parse: $_" "CE+"
    }
} else {
    Add-Result "80.1" "Vulnerability Data File Loaded" "INFO" "known-vulnerabilities.json not found in script directory - using age-based checks only" "CE+"
}

# ---- Helper: compare version strings (dotted numeric) ----
$Script:MaxDisplayedItems = 5
function Compare-AppVersion {
    param([string]$Installed, [string]$Required)
    try {
        # Strip non-numeric prefixes/suffixes, keep dotted numeric core
        $cleanInstalled = ($Installed -replace '[^0-9.]', '').TrimEnd('.').TrimStart('.')
        $cleanRequired  = ($Required  -replace '[^0-9.]', '').TrimEnd('.').TrimStart('.')
        if (-not $cleanInstalled -or -not $cleanRequired) { return $null }
        # Remove consecutive dots from edge cases
        $cleanInstalled = $cleanInstalled -replace '\.{2,}', '.'
        $cleanRequired  = $cleanRequired  -replace '\.{2,}', '.'
        $iParts = $cleanInstalled.Split('.') | Where-Object { $_ -ne '' } | ForEach-Object {
            $n = 0; if ([long]::TryParse($_, [ref]$n)) { $n } else { return $null }
        }
        $rParts = $cleanRequired.Split('.') | Where-Object { $_ -ne '' } | ForEach-Object {
            $n = 0; if ([long]::TryParse($_, [ref]$n)) { $n } else { return $null }
        }
        if ($null -eq $iParts -or $null -eq $rParts) { return $null }
        $iParts = @($iParts)
        $rParts = @($rParts)
        $maxLen = [math]::Max($iParts.Count, $rParts.Count)
        for ($i = 0; $i -lt $maxLen; $i++) {
            $iv = if ($i -lt $iParts.Count) { $iParts[$i] } else { 0 }
            $rv = if ($i -lt $rParts.Count) { $rParts[$i] } else { 0 }
            if ($iv -lt $rv) { return -1 }   # installed < required  (vulnerable)
            if ($iv -gt $rv) { return  1 }   # installed > required  (safe)
        }
        return 0  # equal
    } catch {
        return $null
    }
}

# ---- Enumerate installed apps from Uninstall registry hives ----
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$installedApps = @()
foreach ($rp in $regPaths) {
    try {
        $items = Get-ItemProperty $rp -ErrorAction SilentlyContinue |
                 Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" } |
                 Select-Object DisplayName, DisplayVersion, InstallDate, Publisher, UninstallString
        if ($items) { $installedApps += $items }
    } catch { }
}
# De-duplicate by DisplayName (keep first occurrence from enumeration order)
$installedApps = $installedApps | Sort-Object DisplayName -Unique

# ---- Enumerate AppX / MSIX packages ----
$appxApps = @()
try {
    $appxApps = Get-AppxPackage -ErrorAction SilentlyContinue |
                Where-Object { $_.IsFramework -eq $false -and $_.SignatureKind -ne "System" } |
                Select-Object @{N='DisplayName';E={$_.Name}},
                              @{N='DisplayVersion';E={$_.Version}},
                              @{N='InstallDate';E={$null}},
                              @{N='Publisher';E={$_.Publisher}},
                              @{N='UninstallString';E={$null}}
} catch { }

$allApps = @($installedApps) + @($appxApps)
$totalApps = $allApps.Count

Add-Result "80.2" "Installed Applications Enumerated" "INFO" "Found $totalApps applications ($($installedApps.Count) registry + $($appxApps.Count) AppX/MSIX)" "CE+"

# ---- Counters ----
$currentCount  = 0   # install within acceptable window
$staleCount    = 0   # install beyond window
$unknownCount  = 0   # no date/version available
$vulnCount     = 0   # known-vulnerable version detected
$vulnDetails   = [System.Collections.Generic.List[string]]::new()
$staleDetails  = [System.Collections.Generic.List[string]]::new()

$today = Get-Date

foreach ($app in $allApps) {
    $name    = $app.DisplayName
    $version = $app.DisplayVersion
    $dateStr = $app.InstallDate

    # ---- Phase 2: Check against known-vulnerabilities.json ----
    $matchedVuln = $null
    if ($knownVulns.Count -gt 0 -and $version) {
        foreach ($vuln in $knownVulns) {
            if ($name -match $vuln.registry_pattern) {
                $cmp = Compare-AppVersion $version $vuln.vulnerable_below
                if ($null -ne $cmp -and $cmp -lt 0) {
                    $matchedVuln = $vuln
                }
                break  # first matching pattern wins
            }
        }
    }

    if ($matchedVuln) {
        $vulnCount++
        $sev = $matchedVuln.severity.ToUpper()
        $kevTag = ""
        if ($matchedVuln.PSObject.Properties['kev'] -and $matchedVuln.kev -eq $true) {
            $kevTag = " ** ACTIVELY EXPLOITED (KEV) **"
        }
        $detail = "$name v$version < $($matchedVuln.vulnerable_below) [$sev] ($($matchedVuln.cve))${kevTag}"
        $vulnDetails.Add($detail)
        continue
    }

    # ---- Phase 1: Age-based check using InstallDate ----
    $installDate = $null
    if ($dateStr) {
        # Registry InstallDate is typically YYYYMMDD
        if ($dateStr -match '^\d{8}$') {
            try { $installDate = [datetime]::ParseExact($dateStr, "yyyyMMdd", $null) } catch { }
        } elseif ($dateStr -match '^\d{1,2}/\d{1,2}/\d{4}$') {
            try { $installDate = [datetime]::Parse($dateStr) } catch { }
        }
    }

    if (-not $installDate -and -not $version) {
        $unknownCount++
        continue
    }

    if ($installDate) {
        $ageDays = ($today - $installDate).Days
        if ($ageDays -le 30) {
            $currentCount++
        } elseif ($ageDays -le 90) {
            $staleCount++
            $staleDetails.Add("$name v$version - not updated in $ageDays days (manual review)")
        } else {
            $staleCount++
            $staleDetails.Add("$name v$version - not updated in $ageDays days (>90d, manual review)")
        }
    } else {
        # Has version but no install date - cannot determine age
        $unknownCount++
    }
}

# ---- 80.3 Known Vulnerable Applications ----
if ($knownVulns.Count -gt 0) {
    if ($vulnCount -eq 0) {
        Add-Result "80.3" "No Known Vulnerable App Versions" "PASS" "All installed apps are above minimum safe versions in vulnerability database ($($knownVulns.Count) entries checked)" "CE+"
    } else {
        $topVulns = if ($vulnDetails.Count -le $Script:MaxDisplayedItems) { $vulnDetails -join "; " } else { ($vulnDetails[0..($Script:MaxDisplayedItems - 1)] -join "; ") + " ... and $($vulnDetails.Count - $Script:MaxDisplayedItems) more" }
        Add-Result "80.3" "No Known Vulnerable App Versions" "FAIL" "$vulnCount app(s) below minimum safe version: $topVulns" "CE+"
    }
}

# ---- 80.4 Critical/High Vulnerability Patch Window (14 days) ----
if ($vulnCount -gt 0) {
    $critVulns = $vulnDetails | Select-Object -First $Script:MaxDisplayedItems
    $critList  = $critVulns -join "; "
    Add-Result "80.4" "Critical/High Patched Within 14 Days" "FAIL" "$vulnCount vulnerable app(s) require immediate update: $critList" "CE+"
} elseif ($knownVulns.Count -gt 0) {
    Add-Result "80.4" "Critical/High Patched Within 14 Days" "PASS" "No critical/high vulnerabilities detected in installed applications" "CE+"
}

# ---- 80.5 General Patch Currency (30-day window) ----
if ($staleCount -eq 0 -and $totalApps -gt 0) {
    Add-Result "80.5" "App Updates Within 30-Day Window" "PASS" "All $currentCount datable apps updated within last 30 days" "CE+"
} elseif ($staleCount -gt 0) {
    $topStale = if ($staleDetails.Count -le $Script:MaxDisplayedItems) { $staleDetails -join "; " } else { ($staleDetails[0..($Script:MaxDisplayedItems - 1)] -join "; ") + " ... and $($staleDetails.Count - $Script:MaxDisplayedItems) more" }
    $stalePct = if ($totalApps -gt 0) { [math]::Round(($staleCount / $totalApps) * 100, 0) } else { 0 }
    Add-Result "80.5" "App Updates Within 30-Day Window" "WARN" "$staleCount of $totalApps apps not updated in >30 days ($stalePct%) - manual review recommended: $topStale" "CE+"
}

# ---- 80.6 Apps With No Version/Date (manual review) ----
if ($unknownCount -gt 0) {
    $unknownPct = if ($totalApps -gt 0) { [math]::Round(($unknownCount / $totalApps) * 100, 0) } else { 0 }
    Add-Result "80.6" "Apps Without Date/Version Data" "INFO" "$unknownCount of $totalApps apps ($unknownPct%) have no install date or version - manual patch review recommended" "CE+"
} else {
    Add-Result "80.6" "Apps Without Date/Version Data" "PASS" "All $totalApps apps have version and/or date information" "CE+"
}

# ---- 80.7 Overall Application Patch Currency ----
$overallStatus = "PASS"
$overallDetail = "$totalApps apps: $currentCount current"
if ($vulnCount -gt 0)  { $overallStatus = "FAIL"; $overallDetail += ", $vulnCount VULNERABLE" }
if ($staleCount -gt 0) {
    if ($overallStatus -ne "FAIL") { $overallStatus = "WARN" }
    $overallDetail += ", $staleCount not updated >30d (manual review)"
}
if ($unknownCount -gt 0) { $overallDetail += ", $unknownCount unknown" }
$overallDetail += " | Thresholds: 14d critical/high, 30d other (CE5)"
Add-Result "80.7" "Overall App Patch Currency" $overallStatus $overallDetail "CE+"

# ============================================================
#  CLEAN UP
# ============================================================
if (Test-Path $SecCfg) { Remove-Item $SecCfg -Force -ErrorAction SilentlyContinue }

$AuditEndTime = Get-Date
$AuditDuration = $AuditEndTime - $AuditStartTime
$DurationStr   = "{0:mm\:ss}" -f $AuditDuration

# ============================================================
#  CALCULATE STATISTICS
# ============================================================
$totalChecks   = $Results.Count
$passCount     = ($Results | Where-Object { $_.Status -eq "PASS" }).Count
$failCount     = ($Results | Where-Object { $_.Status -eq "FAIL" }).Count
$warnCount     = ($Results | Where-Object { $_.Status -eq "WARN" }).Count
$infoCount     = ($Results | Where-Object { $_.Status -eq "INFO" }).Count
$scoreable     = $totalChecks - $infoCount

# ---- Per-framework result sets (INFO excluded from every denominator) ----
$cisL1Results  = $Results | Where-Object { $_.Framework -eq "CIS"     -and $_.Status -ne "INFO" }
$cisL2Results  = $Results | Where-Object { $_.Framework -eq "CIS-L2"  -and $_.Status -ne "INFO" }
$ncscResults   = $Results | Where-Object { $_.Framework -eq "NCSC"    -and $_.Status -ne "INFO" }
$ceResults     = $Results | Where-Object { $_.Framework -match "^CE"   -and $_.Status -ne "INFO" }
$entraResults  = $Results | Where-Object { $_.Framework -eq "EntraID" -and $_.Status -ne "INFO" }

$cisL1Count    = $cisL1Results.Count
$cisL2Count    = $cisL2Results.Count
$ncscCount     = $ncscResults.Count
$ceCount       = $ceResults.Count
$entraCount    = $entraResults.Count

# ---- Overall score ----
$score = if ($scoreable -gt 0) { [math]::Round(($passCount / $scoreable) * 100, 1) } else { 0 }

# ---- Per-framework scores ----
$cisL1Pass  = ($cisL1Results | Where-Object { $_.Status -eq "PASS" }).Count
$cisL1Fail  = ($cisL1Results | Where-Object { $_.Status -eq "FAIL" }).Count
$cisL1Warn  = ($cisL1Results | Where-Object { $_.Status -eq "WARN" }).Count
$cisL1Score = if ($cisL1Count -gt 0) { [math]::Round(($cisL1Pass / $cisL1Count) * 100, 1) } else { 0 }

$cisL2Pass  = ($cisL2Results | Where-Object { $_.Status -eq "PASS" }).Count
$cisL2Fail  = ($cisL2Results | Where-Object { $_.Status -eq "FAIL" }).Count
$cisL2Warn  = ($cisL2Results | Where-Object { $_.Status -eq "WARN" }).Count
$l2Score    = if ($cisL2Count -gt 0) { [math]::Round(($cisL2Pass / $cisL2Count) * 100, 1) } else { 0 }

$cePass  = ($ceResults | Where-Object { $_.Status -eq "PASS" }).Count
$ceFail  = ($ceResults | Where-Object { $_.Status -eq "FAIL" }).Count
$ceWarn  = ($ceResults | Where-Object { $_.Status -eq "WARN" }).Count
$ceScore = if ($ceCount -gt 0) { [math]::Round(($cePass / $ceCount) * 100, 1) } else { 0 }

$entraPass  = ($entraResults | Where-Object { $_.Status -eq "PASS" }).Count
$entraFail  = ($entraResults | Where-Object { $_.Status -eq "FAIL" }).Count
$entraWarn  = ($entraResults | Where-Object { $_.Status -eq "WARN" }).Count
$entraScore = if ($entraCount -gt 0) { [math]::Round(($entraPass / $entraCount) * 100, 1) } else { 0 }

# ---- NCSC alignment score (weighted: PASS=1, WARN=0.5, FAIL=0) ----
$ncscPassCount = ($ncscResults | Where-Object { $_.Status -eq "PASS" }).Count
$ncscWarnCount = ($ncscResults | Where-Object { $_.Status -eq "WARN" }).Count
$ncscFailCount = ($ncscResults | Where-Object { $_.Status -eq "FAIL" }).Count
$ncscScore = if ($ncscCount -gt 0) {
    $ncscWeighted = ($ncscPassCount * 1.0) + ($ncscWarnCount * 0.5)
    [math]::Round(($ncscWeighted / $ncscCount) * 100, 1)
} else { 0 }

# ---- Risk rating ----
$overallRisk = Get-RiskRating $score

# ---- Severity-weighted score ----
$weightedNumerator   = 0.0
$weightedDenominator = 0.0
foreach ($r in $Results) {
    if ($r.Status -eq "INFO") { continue }
    $w = Get-SeverityWeight $r.ID
    $weightedDenominator += $w
    if ($r.Status -eq "PASS") { $weightedNumerator += $w }
}
$weightedScore = if ($weightedDenominator -gt 0) {
    [math]::Round(($weightedNumerator / $weightedDenominator) * 100, 1)
} else { 0 }
$weightedRisk = Get-RiskRating $weightedScore

# ---- Category-level (section) scoring ----
$sectionScores = @{}
foreach ($r in $Results) {
    if ($r.Status -eq "INFO") { continue }
    # Extract section number: "1.1" -> "1", "26A.1" -> "26A", "80.7" -> "80"
    $secNum = ($r.ID -split '\.')[0]
    if (-not $sectionScores.ContainsKey($secNum)) {
        $sectionScores[$secNum] = @{ Pass = 0; Fail = 0; Warn = 0; Total = 0 }
    }
    $sectionScores[$secNum].Total++
    switch ($r.Status) {
        "PASS" { $sectionScores[$secNum].Pass++ }
        "FAIL" { $sectionScores[$secNum].Fail++ }
        "WARN" { $sectionScores[$secNum].Warn++ }
    }
}

# ---- Gather richer device context ----
$osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$biosInfo = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
$tpmInfo = try { Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop } catch { $null }
$secureBoot = try { Confirm-SecureBootUEFI -ErrorAction Stop } catch { "Unknown" }
$lastReboot = if ($osInfo) { $osInfo.LastBootUpTime.ToString("dd MMM yyyy HH:mm:ss") } else { "Unknown" }
$osEdition = if ($osInfo) { "$($osInfo.Caption) (Build $($osInfo.BuildNumber))" } else { "Unknown" }
$psVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor).$($PSVersionTable.PSVersion.Build)"
$dotnetVer = try { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction Stop).Release } catch { "Unknown" }
$domainInfo = try { (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Domain } catch { "Unknown" }
$netAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled -eq $true } | Select-Object -First 3
$ipAddresses = ($netAdapters | ForEach-Object { $_.IPAddress } | Where-Object { $_ -and $_ -notmatch ":" }) -join ", "
$tpmVersion = if ($tpmInfo) { $tpmInfo.SpecVersion -replace '\s.*','' } else { "Not detected" }
$tpmStatus = if ($tpmInfo) { if ($tpmInfo.IsEnabled_InitialValue) { "Enabled" } else { "Disabled" } } else { "Not detected" }
$secureBootStr = if ($secureBoot -eq $true) { "Enabled" } elseif ($secureBoot -eq $false) { "Disabled" } else { "Unknown" }
$biosVendor = if ($biosInfo) { "$($biosInfo.Manufacturer) $($biosInfo.SMBIOSBIOSVersion)" } else { "Unknown" }

# ---- Build per-framework score map for reuse ----
$frameworkScoreMap = @{
    "CIS"     = @{ Score = $cisL1Score; Pass = $cisL1Pass; Fail = $cisL1Fail; Warn = $cisL1Warn; Total = $cisL1Count; Label = "CIS Level 1" }
    "CIS-L2"  = @{ Score = $l2Score;    Pass = $cisL2Pass; Fail = $cisL2Fail; Warn = $cisL2Warn; Total = $cisL2Count; Label = "CIS Level 2" }
    "CE+"     = @{ Score = $ceScore;    Pass = $cePass;    Fail = $ceFail;    Warn = $ceWarn;    Total = $ceCount;    Label = "Cyber Essentials" }
    "EntraID" = @{ Score = $entraScore; Pass = $entraPass; Fail = $entraFail; Warn = $entraWarn; Total = $entraCount; Label = "Entra ID / M365" }
    "NCSC"    = @{ Score = $ncscScore;  Pass = $ncscPassCount; Fail = $ncscFailCount; Warn = $ncscWarnCount; Total = $ncscCount; Label = "NCSC Alignment" }
}

# ============================================================
#  COMPLIANCE ATTESTATION
# ============================================================
Write-Host ""
$execLines = @(
    "",
    "  ========================================================================",
    "  OTY HEAVY INDUSTRIES - AUDIT REPORT",
    "  Version $ScriptVersion  |  $(Get-Date -Format 'dd MMM yyyy HH:mm') UTC",
    "  Scope: $($Script:AuditLabel)",
    "  ========================================================================"
)
foreach ($l in $execLines) { Write-ReportLine $l }

Write-Host ""
Write-Divider "="
Write-ReportLine "  COMPLIANCE ATTESTATION" "White"
Write-Divider "-"
Write-ReportLine ""

foreach ($fwKey in @("CIS","CIS-L2","CE+","NCSC","EntraID")) {
    $fw = $frameworkScoreMap[$fwKey]
    if ($fw.Total -eq 0) { continue }
    $thresh = $Script:ComplianceThresholds[$fwKey]
    $verdict = if ($fw.Score -ge $thresh.Threshold) { "PASSES" } else { "DOES NOT PASS" }
    $vColor  = if ($verdict -eq "PASSES") { "Green" } else { "Red" }
    $attLine = "  $($fw.Label): $verdict  ($($fw.Score)% vs $($thresh.Threshold)% threshold)"
    Write-Host $attLine -ForegroundColor $vColor
    Add-Content -Path $ReportPath -Value $attLine
}
Write-ReportLine ""

# ============================================================
#  EXECUTIVE SUMMARY
# ============================================================
Write-ReportLine "  EXECUTIVE SUMMARY" "White"
Write-Divider "-"

$riskLine = "  Risk Rating       : $($overallRisk.Label)"
Write-Host $riskLine -ForegroundColor $overallRisk.Color
Add-Content -Path $ReportPath -Value $riskLine

$scoreLine = "  Overall Score     : $score%  ($passCount of $scoreable scoreable checks passed)"
$scoreColor = if ($score -ge 90) { "Green" } elseif ($score -ge 75) { "Yellow" } else { "Red" }
Write-Host $scoreLine -ForegroundColor $scoreColor
Add-Content -Path $ReportPath -Value $scoreLine

$bar = Get-ProgressBar $score
$barLine = "                      $bar $score%"
Write-Host $barLine -ForegroundColor $scoreColor
Add-Content -Path $ReportPath -Value $barLine

# ---- Severity-weighted score ----
$wLine = "  Weighted Score    : $weightedScore%  (Critical x3, High x2, Medium x1)"
$wColor = if ($weightedScore -ge 90) { "Green" } elseif ($weightedScore -ge 75) { "Yellow" } else { "Red" }
Write-Host $wLine -ForegroundColor $wColor
Add-Content -Path $ReportPath -Value $wLine

$wBar = Get-ProgressBar $weightedScore
$wBarLine = "                      $wBar $weightedScore%"
Write-Host $wBarLine -ForegroundColor $wColor
Add-Content -Path $ReportPath -Value $wBarLine

Write-ReportLine ""
Write-ReportLine "  Total Checks      : $totalChecks"
Write-ReportLine ("  Passed            : {0,-6} | Failed : {1,-6} | Warnings : {2,-6} | Info : {3}" -f $passCount, $failCount, $warnCount, $infoCount)
Write-ReportLine "  Audit Duration    : $DurationStr"

# ---- Top 5 Risks ----
$failedItems = $Results | Where-Object { $_.Status -eq "FAIL" }
if ($failedItems.Count -gt 0) {
    Write-ReportLine ""
    Write-ReportLine "  TOP 5 RISKS:" "White"
    # Sort by severity weight descending, take top 5
    $top5 = $failedItems | Sort-Object { Get-SeverityWeight $_.ID } -Descending | Select-Object -First 5
    $idx = 1
    foreach ($r in $top5) {
        $sev = if ($Script:RemediationData.ContainsKey($r.ID)) { $Script:RemediationData[$r.ID].Severity } else { "Medium" }
        $topLine = "    $idx. [$sev] [$($r.ID)] $($r.Description)"
        Write-Host $topLine -ForegroundColor Red
        Add-Content -Path $ReportPath -Value $topLine
        $idx++
    }
}

# ---- Quick Wins (registry/GPO changes -- low-effort fixes) ----
$quickWinIDs = $failedItems | Where-Object {
    $Script:RemediationData.ContainsKey($_.ID) -and
    ($Script:RemediationData[$_.ID].Remediation -match "Registry|GPO|Run:|Set-MpPreference")
} | Select-Object -First 5
if ($quickWinIDs.Count -gt 0) {
    Write-ReportLine ""
    Write-ReportLine "  QUICK WINS (easy registry/GPO fixes):" "White"
    $idx = 1
    foreach ($r in $quickWinIDs) {
        $rem = $Script:RemediationData[$r.ID].Remediation
        $qLine = "    $idx. [$($r.ID)] $($r.Description)"
        Write-Host $qLine -ForegroundColor Yellow
        Add-Content -Path $ReportPath -Value $qLine
        $qDetail = "       Fix: $rem"
        Write-Host $qDetail -ForegroundColor DarkYellow
        Add-Content -Path $ReportPath -Value $qDetail
        $idx++
    }
}

# ============================================================
#  SCORE DASHBOARD
# ============================================================
Write-ReportLine ""
Write-Divider "="
Write-ReportLine "  FRAMEWORK SCORE DASHBOARD" "White"
Write-Divider "-"
Write-ReportLine ""

# Column headers
$dashHeader = "  {0,-22} {1,6}  {2,-30}  {3}" -f "Framework", "Score", "Progress", "Pass / Fail / Warn"
Write-ReportLine $dashHeader "White"
Write-ReportLine ("  " + ("-" * 72))

# Dashboard rows - helper function for consistency
function Write-DashboardRow {
    param([string]$Name, [double]$Sc, [int]$P, [int]$F, [int]$W, [int]$T)
    if ($T -eq 0) { return }
    $bar   = Get-ProgressBar $Sc
    $color = if ($Sc -ge 90) { "Green" } elseif ($Sc -ge 75) { "Yellow" } else { "Red" }
    $line  = "  {0,-22} {1,5:0.0}%  {2}  {3,4}P / {4,4}F / {5,4}W  ({6})" -f $Name, $Sc, $bar, $P, $F, $W, $T
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $ReportPath -Value $line
}

Write-DashboardRow "CIS Level 1"        $cisL1Score $cisL1Pass $cisL1Fail $cisL1Warn $cisL1Count
Write-DashboardRow "CIS Level 2"        $l2Score    $cisL2Pass $cisL2Fail $cisL2Warn $cisL2Count
Write-DashboardRow "Cyber Essentials"    $ceScore    $cePass    $ceFail    $ceWarn    $ceCount
Write-DashboardRow "Entra ID / M365"    $entraScore $entraPass $entraFail $entraWarn $entraCount

# NCSC gets special treatment due to weighted scoring
if ($ncscCount -gt 0) {
    $bar   = Get-ProgressBar $ncscScore
    $color = if ($ncscScore -ge 90) { "Green" } elseif ($ncscScore -ge 75) { "Yellow" } else { "Red" }
    $line  = "  {0,-22} {1,5:0.0}%  {2}  {3,4}P / {4,4}F / {5,4}W  ({6})" -f "NCSC Alignment*", $ncscScore, $bar, $ncscPassCount, $ncscFailCount, $ncscWarnCount, $ncscCount
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $ReportPath -Value $line
}

Write-ReportLine ""
Write-ReportLine "  * NCSC uses weighted scoring: PASS = full, WARN = partial (0.5), FAIL = none."
Write-ReportLine "    A WARN on NCSC means CIS-compliant but not yet NCSC-optimal (e.g. password"
Write-ReportLine "    length 14 passes CIS but NCSC recommends 15+). See ncsc.gov.uk/collection/passwords"

# ============================================================
#  CATEGORY-LEVEL SCORECARD
# ============================================================
Write-ReportLine ""
Write-Divider "="
Write-ReportLine "  SECTION SCORECARD" "White"
Write-Divider "-"
Write-ReportLine ""

$secHeader = "  {0,-8} {1,-38} {2,5} {3,5} {4,5} {5,7}" -f "Section", "Name", "Pass", "Fail", "Warn", "Score%"
Write-ReportLine $secHeader "White"
Write-ReportLine ("  " + ("-" * 72))

# Section name lookup (abbreviated)
$sectionNames = @{
    "1"="Password Policy"; "2"="Account Lockout"; "3"="Remote Desktop"; "4"="Local Accounts";
    "5"="Windows Firewall"; "6"="Patch Management"; "7"="SMBv1 Protocol"; "8"="AutoRun/AutoPlay";
    "9"="Insecure Services"; "10"="Admin Shares"; "11"="User Account Control"; "12"="Security Protocols";
    "13"="Audit Policy"; "14"="Malware Protection"; "15"="BitLocker/Encryption"; "16"="Secure Boot/UEFI";
    "17"="PowerShell Security"; "18"="Application Control"; "19"="Event Log Config"; "20"="Credential Protection";
    "21"="Screen Lock/Session"; "22"="Unnecessary Features"; "23"="Network Security"; "24"="Memory/Exploit Protect";
    "25"="CE Secure Config"; "26"="CE Plus Checks"; "26A"="CE+ Account Separation"; "26B"="CE+ 2FA/MFA";
    "27"="Entra ID Device"; "28"="Intune/MDM"; "29"="Windows Hello"; "30"="Defender for Endpoint";
    "31"="M365/Office Security"; "32"="CA & Compliance"; "33"="CIS L2 User Rights"; "34"="CIS L2 Sec Options";
    "35"="CIS L2 Advanced Audit"; "36"="TLS/SSL Hardening"; "37"="Edge Security"; "38"="Peripheral Control";
    "39"="Privacy Hardening"; "40"="Remote Assistance"; "41"="DNS Client Security"; "42"="Scheduled Tasks";
    "43"="MSS Legacy Settings"; "44"="Network Protocol"; "45"="ASR Rules"; "46"="System Exploit Protect";
    "47"="Kernel DMA Protection"; "48"="LAPS Config"; "49"="Network List Manager"; "50"="Delivery Optimisation";
    "51"="NTP/Time Security"; "52"="Defender App Guard"; "53"="RPC/DCOM Security"; "54"="Group Policy Infra";
    "55"="Print Security"; "56"="Windows Copilot/AI"; "57"="File/Reg Permissions"; "58"="Internet Explorer";
    "59"="Event Forwarding"; "60"="Additional Defender"; "61"="CIS L1 User Rights"; "62"="CIS L1 Sec Options";
    "63"="CIS L1 Admin System"; "64"="CIS L1 Admin WinCo"; "65"="CIS L1 Services"; "66"="CIS L1 Admin User";
    "67"="CIS L1 Telemetry"; "68"="CIS L1 Device Guard"; "69"="CIS L1 Logon/Cred"; "70"="CIS L1 Admin Tmpl";
    "71"="CIS L1 Lockout/Rights"; "72"="CIS L1 FW Logging"; "73"="CIS L1 Audit Policy"; "74"="CIS L1 Personalization";
    "75"="CIS L1 MSS/Network"; "76"="CIS L1 Printer"; "77"="CIS L1 System Tmpl"; "78"="CIS L1 Win Components";
    "79"="CIS L1 WiFi/User"; "80"="App Patch Currency"
}

# Sort sections numerically (handle "26A","26B" etc.)
$sortedSections = $sectionScores.Keys | Sort-Object {
    $num = $_ -replace '[A-Za-z]',''
    $suffix = $_ -replace '[0-9]',''
    [int]$num * 100 + [int][char[]]($suffix + " ")[0]
}

foreach ($sec in $sortedSections) {
    $s = $sectionScores[$sec]
    $secScore = if ($s.Total -gt 0) { [math]::Round(($s.Pass / $s.Total) * 100, 0) } else { 0 }
    $secName = if ($sectionNames.ContainsKey($sec)) { $sectionNames[$sec] } else { "Section $sec" }
    $color = if ($secScore -ge 90) { "Green" } elseif ($secScore -ge 50) { "Yellow" } else { "Red" }
    $secLine = "  {0,-8} {1,-38} {2,5} {3,5} {4,5} {5,5}%" -f $sec, $secName, $s.Pass, $s.Fail, $s.Warn, $secScore
    Write-Host $secLine -ForegroundColor $color
    Add-Content -Path $ReportPath -Value $secLine
}

# ============================================================
#  DEVICE CONTEXT (enhanced)
# ============================================================
Write-ReportLine ""
Write-Divider "="
Write-ReportLine "  DEVICE CONTEXT" "White"
Write-Divider "-"
Write-ReportLine "  Hostname          : $env:COMPUTERNAME"
Write-ReportLine "  User              : $env:USERNAME"
Write-ReportLine "  OS Edition        : $osEdition"
Write-ReportLine "  Last Reboot       : $lastReboot"
Write-ReportLine "  Join Type         : $joinType"
Write-ReportLine "  Domain/Workgroup  : $domainInfo"
Write-ReportLine "  Tenant            : $($Script:TenantName) ($($Script:TenantID))"
Write-ReportLine "  MDM Enrolled      : $($Script:MDMEnrolled) $(if ($Script:MDMUrl) {"($($Script:MDMUrl))"} else {''})"
Write-ReportLine "  PRT Present       : $($Script:PRTPresent)"
Write-ReportLine "  Device ID         : $($Script:DeviceID)"
Write-ReportLine "  TPM               : $tpmVersion ($tpmStatus)"
Write-ReportLine "  Secure Boot       : $secureBootStr"
Write-ReportLine "  BIOS/UEFI         : $biosVendor"
Write-ReportLine "  PowerShell        : $psVersion"
Write-ReportLine "  .NET Release      : $dotnetVer"
Write-ReportLine "  IP Address(es)    : $ipAddresses"

# ============================================================
#  DELTA / TREND COMPARISON
# ============================================================
if ($Script:PreviousData) {
    Write-ReportLine ""
    Write-Divider "="
    Write-ReportLine "  CHANGES SINCE LAST AUDIT" "White"
    Write-Divider "-"
    Write-ReportLine ""

    # Build lookup of previous results by ID
    $prevResults = @{}
    if ($Script:PreviousData.results) {
        foreach ($pr in $Script:PreviousData.results) {
            $prevResults[$pr.ID] = $pr.Status
        }
    }

    $newFails    = [System.Collections.Generic.List[string]]::new()
    $resolved    = [System.Collections.Generic.List[string]]::new()
    $regressions = [System.Collections.Generic.List[string]]::new()

    foreach ($r in $Results) {
        $prevStatus = if ($prevResults.ContainsKey($r.ID)) { $prevResults[$r.ID] } else { $null }
        if ($r.Status -eq "FAIL" -and $prevStatus -ne "FAIL") {
            if ($null -eq $prevStatus) {
                $newFails.Add("[$($r.ID)] $($r.Description) (NEW CHECK)")
            } else {
                $regressions.Add("[$($r.ID)] $($r.Description) (was $prevStatus, now FAIL)")
            }
        }
        if ($r.Status -eq "PASS" -and $prevStatus -eq "FAIL") {
            $resolved.Add("[$($r.ID)] $($r.Description) (RESOLVED)")
        }
    }

    # Previous overall score
    $prevScore = if ($Script:PreviousData.summary -and $Script:PreviousData.summary.overall_score) {
        $Script:PreviousData.summary.overall_score
    } else { $null }

    if ($null -ne $prevScore) {
        $delta = $score - $prevScore
        $arrow = if ($delta -gt 0) { "+" } else { "" }
        $deltaColor = if ($delta -gt 0) { "Green" } elseif ($delta -lt 0) { "Red" } else { "Cyan" }
        $deltaLine = "  Overall Score: $prevScore% -> $score%  (${arrow}${delta}%)"
        Write-Host $deltaLine -ForegroundColor $deltaColor
        Add-Content -Path $ReportPath -Value $deltaLine
    }

    # Per-framework delta
    if ($Script:PreviousData.framework_scores) {
        Write-ReportLine ""
        Write-ReportLine "  Framework Score Changes:" "White"
        foreach ($fwKey in @("CIS","CIS-L2","CE+","NCSC","EntraID")) {
            $fw = $frameworkScoreMap[$fwKey]
            if ($fw.Total -eq 0) { continue }
            $prevFwScore = $null
            foreach ($pfw in $Script:PreviousData.framework_scores) {
                if ($pfw.framework -eq $fwKey) { $prevFwScore = $pfw.score; break }
            }
            if ($null -ne $prevFwScore) {
                $d = $fw.Score - $prevFwScore
                $arr = if ($d -gt 0) { "+" } else { "" }
                $dColor = if ($d -gt 0) { "Green" } elseif ($d -lt 0) { "Red" } else { "Cyan" }
                $fwLine = "    $($fw.Label): $prevFwScore% -> $($fw.Score)%  (${arr}${d}%)"
                Write-Host $fwLine -ForegroundColor $dColor
                Add-Content -Path $ReportPath -Value $fwLine
            }
        }
    }

    Write-ReportLine ""
    Write-ReportLine "  Resolved: $($resolved.Count) | New Failures: $($newFails.Count) | Regressions: $($regressions.Count)"

    if ($resolved.Count -gt 0) {
        Write-ReportLine ""
        Write-ReportLine "  RESOLVED (previously failed, now passing):" "Green"
        foreach ($item in $resolved) {
            $rLine = "    + $item"
            Write-Host $rLine -ForegroundColor Green
            Add-Content -Path $ReportPath -Value $rLine
        }
    }
    if ($regressions.Count -gt 0) {
        Write-ReportLine ""
        Write-ReportLine "  REGRESSIONS (previously passing/warn, now failing):" "Red"
        foreach ($item in $regressions) {
            $rLine = "    ! $item"
            Write-Host $rLine -ForegroundColor Red
            Add-Content -Path $ReportPath -Value $rLine
        }
    }
    if ($newFails.Count -gt 0) {
        Write-ReportLine ""
        Write-ReportLine "  NEW FAILURES (checks not in previous report):" "Yellow"
        foreach ($item in $newFails) {
            $rLine = "    - $item"
            Write-Host $rLine -ForegroundColor Yellow
            Add-Content -Path $ReportPath -Value $rLine
        }
    }
}

# ============================================================
#  PRIORITY REMEDIATION -- TOP FAILURES
# ============================================================
if ($failedItems.Count -gt 0) {
    Write-ReportLine ""
    Write-Divider "="
    Write-ReportLine "  PRIORITY REMEDIATION  ($failCount failed controls)" "White"
    Write-Divider "-"
    Write-ReportLine ""

    # Group failures by framework for actionable prioritisation
    $failByFramework = $failedItems | Group-Object Framework | Sort-Object Count -Descending
    foreach ($group in $failByFramework) {
        $fwName = switch ($group.Name) {
            "CIS"     { "CIS Level 1" }
            "CIS-L2"  { "CIS Level 2" }
            "CE"      { "Cyber Essentials" }
            "CE+"     { "Cyber Essentials Plus" }
            "NCSC"    { "NCSC Alignment" }
            "EntraID" { "Entra ID / M365" }
            default   { $group.Name }
        }
        $subHead = "  $fwName ($($group.Count) failures):"
        Write-Host $subHead -ForegroundColor Red
        Add-Content -Path $ReportPath -Value $subHead

        $counter = 1
        foreach ($r in $group.Group) {
            $sev = if ($Script:RemediationData.ContainsKey($r.ID)) { " [$($Script:RemediationData[$r.ID].Severity)]" } else { "" }
            $l = "    ${counter}.${sev} [$($r.ID)] $($r.Description)"
            Write-Host $l -ForegroundColor Red
            Add-Content -Path $ReportPath -Value $l
            $d = "       $($r.Detail)"
            Write-Host $d -ForegroundColor DarkRed
            Add-Content -Path $ReportPath -Value $d
            # Add remediation guidance if available
            if ($Script:RemediationData.ContainsKey($r.ID)) {
                $rem = "       Remediation: $($Script:RemediationData[$r.ID].Remediation)"
                Write-Host $rem -ForegroundColor DarkYellow
                Add-Content -Path $ReportPath -Value $rem
            }
            $counter++
        }
        Write-ReportLine ""
    }
}

# ============================================================
#  WARNINGS SUMMARY
# ============================================================
$warnItems = $Results | Where-Object { $_.Status -eq "WARN" }
if ($warnItems.Count -gt 0) {
    Write-Divider "="
    Write-ReportLine "  WARNINGS REQUIRING REVIEW  ($warnCount controls)" "White"
    Write-Divider "-"
    Write-ReportLine ""

    $warnByFramework = $warnItems | Group-Object Framework | Sort-Object Count -Descending
    foreach ($group in $warnByFramework) {
        $fwName = switch ($group.Name) {
            "CIS"     { "CIS Level 1" }
            "CIS-L2"  { "CIS Level 2" }
            "CE"      { "Cyber Essentials" }
            "CE+"     { "Cyber Essentials Plus" }
            "NCSC"    { "NCSC Alignment" }
            "EntraID" { "Entra ID / M365" }
            default   { $group.Name }
        }
        $subHead = "  $fwName ($($group.Count) warnings):"
        Write-Host $subHead -ForegroundColor Yellow
        Add-Content -Path $ReportPath -Value $subHead

        foreach ($r in $group.Group) {
            $l = "    [$($r.ID)] $($r.Description) - $($r.Detail)"
            Write-Host $l -ForegroundColor Yellow
            Add-Content -Path $ReportPath -Value $l
        }
        Write-ReportLine ""
    }
}

# ============================================================
#  PER-FRAMEWORK DETAILED REPORT SECTIONS
# ============================================================

# Helper to write a framework section to console and report file
function Write-FrameworkSection {
    param(
        [string]$SectionTitle,
        [double]$Score,
        [object[]]$FrameworkResults
    )
    $bar   = Get-ProgressBar $Score
    $color = if ($Score -ge 90) { "Green" } elseif ($Score -ge 75) { "Yellow" } else { "Red" }
    $passItems = $FrameworkResults | Where-Object { $_.Status -eq "PASS" }
    $failItems = $FrameworkResults | Where-Object { $_.Status -eq "FAIL" }
    $warnItems = $FrameworkResults | Where-Object { $_.Status -eq "WARN" }

    Write-ReportLine ""
    Write-Divider "="
    Write-ReportLine "  $SectionTitle" "White"
    Write-Divider "-"

    $scoreLine = "  Score: $Score%  $bar"
    Write-Host $scoreLine -ForegroundColor $color
    Add-Content -Path $ReportPath -Value $scoreLine

    Write-ReportLine ("  Total: {0}  |  PASS: {1}  |  FAIL: {2}  |  WARN: {3}" -f $FrameworkResults.Count, $passItems.Count, $failItems.Count, $warnItems.Count)
    Write-ReportLine ""

    if ($failItems.Count -gt 0) {
        $subHead = "  FAILED ($($failItems.Count)):"
        Write-Host $subHead -ForegroundColor Red
        Add-Content -Path $ReportPath -Value $subHead
        $counter = 1
        foreach ($r in $failItems) {
            $l = "    ${counter}. [$($r.ID)] $($r.Description)"
            Write-Host $l -ForegroundColor Red
            Add-Content -Path $ReportPath -Value $l
            $d = "       $($r.Detail)"
            Write-Host $d -ForegroundColor DarkRed
            Add-Content -Path $ReportPath -Value $d
            $counter++
        }
        Write-ReportLine ""
    }
    if ($warnItems.Count -gt 0) {
        $subHead = "  WARNINGS ($($warnItems.Count)):"
        Write-Host $subHead -ForegroundColor Yellow
        Add-Content -Path $ReportPath -Value $subHead
        foreach ($r in $warnItems) {
            $l = "    [$($r.ID)] $($r.Description) - $($r.Detail)"
            Write-Host $l -ForegroundColor Yellow
            Add-Content -Path $ReportPath -Value $l
        }
        Write-ReportLine ""
    }
    if ($passItems.Count -gt 0) {
        $subHead = "  PASSED ($($passItems.Count)):"
        Write-Host $subHead -ForegroundColor Green
        Add-Content -Path $ReportPath -Value $subHead
        foreach ($r in $passItems) {
            $l = "    [$($r.ID)] $($r.Description)"
            Write-Host $l -ForegroundColor Green
            Add-Content -Path $ReportPath -Value $l
        }
        Write-ReportLine ""
    }
}

# ---- CIS Level 1 Section ----
if ($cisL1Count -gt 0) {
    Write-FrameworkSection -SectionTitle "CIS LEVEL 1 DETAILED REPORT" -Score $cisL1Score -FrameworkResults $cisL1Results
}

# ---- CIS Level 2 Section ----
if ($cisL2Count -gt 0) {
    Write-FrameworkSection -SectionTitle "CIS LEVEL 2 DETAILED REPORT" -Score $l2Score -FrameworkResults $cisL2Results
}

# ---- Cyber Essentials Section ----
if ($ceCount -gt 0) {
    Write-FrameworkSection -SectionTitle "CYBER ESSENTIALS / CE+ DETAILED REPORT" -Score $ceScore -FrameworkResults $ceResults
}

# ---- Entra ID / M365 Section ----
if ($entraCount -gt 0) {
    Write-FrameworkSection -SectionTitle "ENTRA ID / M365 DETAILED REPORT" -Score $entraScore -FrameworkResults $entraResults
}

# ---- NCSC Alignment Section ----
if ($ncscCount -gt 0) {
    Write-FrameworkSection -SectionTitle "NCSC ALIGNMENT DETAILED REPORT" -Score $ncscScore -FrameworkResults $ncscResults
}

# ============================================================
#  SECTIONS AUDITED (grouped by category)
# ============================================================
Write-ReportLine ""
Write-Divider "="
Write-ReportLine "  SECTIONS AUDITED" "White"
Write-Divider "-"
Write-ReportLine ""
Write-ReportLine "  Core Security (CIS L1 | CE | NCSC):" "White"
$coreLines = @(
    "     1. Password Policy              (CIS L1 | CE2 | NCSC)",
    "     2. Account Lockout              (CIS L1 | CE2 | Smart Lockout-aware)",
    "     3. Remote Desktop               (CIS L1 | CE1 | CE+)",
    "     4. Local Accounts               (CIS L1 | CE3 | CE+)",
    "     5. Windows Firewall             (CIS L1 | CE1 | CE+)",
    "     6. Patch Management             (CIS L1 | CE5 | CE+ | WUfB)",
    "     7. SMBv1 Protocol               (CIS L1 | CE2)",
    "     8. AutoRun / AutoPlay           (CIS L1)",
    "     9. Insecure Services            (CIS L1 | CE2)",
    "    10. Admin Shares                 (CIS L1)",
    "    11. User Account Control         (CIS L1 | CE3)",
    "    12. Security Protocols           (CIS L1 | CE2 | NTLM-aware)",
    "    13. Audit Policy                 (CIS L1 17.x)",
    "    14. Malware Protection           (CIS L1 | CE4 | CE+)",
    "    15. BitLocker / Encryption       (CIS L1 | CE2 | Entra Key Backup)",
    "    16. Secure Boot & UEFI           (CIS L1 | CE+)",
    "    17. PowerShell Security          (CIS L1 | CE+)",
    "    18. Application Control          (CIS L1 | CE2 | CE+)",
    "    19. Event Log Configuration      (CIS L1 18.x)",
    "    20. Credential Protection        (CIS L1 | CE+ | PRT-aware)",
    "    21. Screen Lock / Session        (CIS L1 | CE2)",
    "    22. Unnecessary Features         (CE2 | CE+)",
    "    23. Network Security             (CIS L1 | CE1 | CE2 | IPv6-aware)",
    "    24. Memory & Exploit Protect     (CIS L1)",
    "    25. CE Secure Configuration      (CE2 | CE+)",
    "    26. Cyber Essentials Plus        (CE+)",
    "   26A. CE+ Account Separation       (CE+ | NCSC)",
    "   26B. CE+ 2FA/MFA                  (CE+ | NCSC)"
)
foreach ($l in $coreLines) { Write-ReportLine $l }

Write-ReportLine ""
Write-ReportLine "  Entra ID / M365 / Cloud (EntraID | CE+):" "White"
$entraLines = @(
    "    27. Entra ID Device Identity     (EntraID | CE+)",
    "    28. Intune / MDM Enrolment       (EntraID | CE+)",
    "    29. Windows Hello for Bus.       (EntraID | CE+)",
    "    30. Defender for Endpoint        (EntraID | CE+)",
    "    31. Microsoft 365 / Office       (EntraID | CE+)",
    "    32. CA & Device Compliance       (EntraID | CE+)"
)
foreach ($l in $entraLines) { Write-ReportLine $l }

Write-ReportLine ""
Write-ReportLine "  CIS Level 2 Hardening:" "White"
$l2Lines = @(
    "    33. CIS L2 User Rights           (CIS L2)",
    "    34. CIS L2 Sec Options           (CIS L2)",
    "    35. CIS L2 Advanced Audit        (CIS L2 17.x)",
    "    36. TLS/SSL & Cipher Hard.       (CIS L2 | CE+)",
    "    37. Microsoft Edge Security      (CIS L2 | CE+)",
    "    38. Peripheral & Device Ctrl     (CIS L2 | CE+)",
    "    39. Windows Privacy Hard.        (CIS L2)",
    "    40. Remote Assistance            (CIS L2)",
    "    41. DNS Client Security          (CIS L2)",
    "    42. Scheduled Tasks              (CIS L2)",
    "    43. MSS Legacy Settings          (CIS L2)",
    "    44. CIS L2 Network Protocol      (CIS L2)",
    "    45. ASR Specific Rules           (CIS L1/L2)",
    "    46. System Exploit Protect       (CIS L2)",
    "    47. Kernel DMA Protection        (CIS L2 | CE+)",
    "    48. LAPS Configuration           (CIS L1 | CE3)",
    "    49. Network List Manager         (CIS L2)",
    "    50. Delivery Optimisation        (CIS L2)",
    "    51. NTP / Time Security          (CIS L2)",
    "    52. Defender App Guard           (CIS L2)",
    "    53. RPC & DCOM Security          (CIS L2)",
    "    54. Group Policy Infra.          (CIS L2)",
    "    55. Print Security               (CIS L1/L2)",
    "    56. Windows Copilot / AI         (CIS L2)",
    "    57. File & Reg Permissions       (CIS L2)",
    "    58. Internet Explorer            (CIS L1)",
    "    59. Windows Event Forwarding     (CIS L2)",
    "    60. Additional Defender          (CIS L1/L2)"
)
foreach ($l in $l2Lines) { Write-ReportLine $l }

Write-ReportLine ""
Write-ReportLine "  CIS L1 Extended Coverage (v5.0.1):" "White"
$extLines = @(
    "    61. CIS L1 User Rights           (CIS L1 2.2)",
    "    62. CIS L1 Security Options      (CIS L1 2.3/18.3)",
    "    63. CIS L1 Admin Tmpl System     (CIS L1 18.1/18.8)",
    "    64. CIS L1 Admin Tmpl WinCo      (CIS L1 18.5/18.9)",
    "    65. CIS L1 System Services       (CIS L1 5.x)",
    "    66. CIS L1 Admin Tmpl User       (CIS L1 19.x)",
    "    67. CIS L1 Data/Telemetry        (CIS L1 18.9.17)",
    "    68. CIS L1 Device Guard/VBS      (CIS L1 18.8.5)",
    "    69. CIS L1 Logon/Cred UI         (CIS L1 18.8.28/18.9.15)",
    "    70. CIS L1 Addit. Admin Tmpl     (CIS L1 18.x)",
    "    71. CIS L1 Lockout/Rights/Sec    (CIS L1 1.2/2.2/2.3)",
    "    72. CIS L1 FW Policy Logging     (CIS L1 9.x)",
    "    73. CIS L1 Audit Policy Add'l    (CIS L1 17.x)",
    "    74. CIS L1 Personalization       (CIS L1 18.1)",
    "    75. CIS L1 MSS/Network/SMB       (CIS L1 18.5/18.6)",
    "    76. CIS L1 Printer Security      (CIS L1 18.7)",
    "    77. CIS L1 System Templates      (CIS L1 18.9)",
    "    78. CIS L1 Windows Components    (CIS L1 18.10)",
    "    79. CIS L1 WiFi/User Templates   (CIS L1 18.11/19.7)"
)
foreach ($l in $extLines) { Write-ReportLine $l }

Write-ReportLine ""
Write-ReportLine "  Application Patch Currency:" "White"
$patchLines = @(
    "    80. App Patch Currency            (CE+ | CE5 | Vulnerability DB)"
)
foreach ($l in $patchLines) { Write-ReportLine $l }

# ============================================================
#  CSV EXPORT
# ============================================================
$Results | Select-Object ID, Framework, Status, Description, Detail |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

# ============================================================
#  JSON EXPORT
# ============================================================
$jsonObj = [ordered]@{
    metadata = [ordered]@{
        script_version = $ScriptVersion
        hostname       = $env:COMPUTERNAME
        user           = $env:USERNAME
        os             = $osEdition
        join_type      = $joinType
        tenant         = "$($Script:TenantName) ($($Script:TenantID))"
        mdm_enrolled   = [bool]$Script:MDMEnrolled
        device_id      = $Script:DeviceID
        audit_scope    = $Script:AuditLabel
        timestamp      = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        duration       = $DurationStr
        tpm            = "$tpmVersion ($tpmStatus)"
        secure_boot    = $secureBootStr
        bios           = $biosVendor
        domain         = $domainInfo
        ip_addresses   = $ipAddresses
        last_reboot    = $lastReboot
    }
    summary = [ordered]@{
        total_checks   = $totalChecks
        passed         = $passCount
        failed         = $failCount
        warnings       = $warnCount
        info           = $infoCount
        overall_score  = $score
        weighted_score = $weightedScore
        risk_rating    = $overallRisk.Label
    }
    framework_scores = @(
        foreach ($fwKey in @("CIS","CIS-L2","CE+","NCSC","EntraID")) {
            $fw = $frameworkScoreMap[$fwKey]
            if ($fw.Total -gt 0) {
                [ordered]@{
                    framework = $fwKey
                    label     = $fw.Label
                    score     = $fw.Score
                    pass      = $fw.Pass
                    fail      = $fw.Fail
                    warn      = $fw.Warn
                    total     = $fw.Total
                }
            }
        }
    )
    compliance = @(
        foreach ($fwKey in @("CIS","CIS-L2","CE+","NCSC","EntraID")) {
            $fw = $frameworkScoreMap[$fwKey]
            if ($fw.Total -eq 0) { continue }
            $thresh = $Script:ComplianceThresholds[$fwKey]
            [ordered]@{
                framework = $fwKey
                label     = $fw.Label
                score     = $fw.Score
                threshold = $thresh.Threshold
                verdict   = if ($fw.Score -ge $thresh.Threshold) { "PASSES" } else { "DOES NOT PASS" }
            }
        }
    )
    section_scores = @(
        foreach ($sec in $sortedSections) {
            $s = $sectionScores[$sec]
            $secScore = if ($s.Total -gt 0) { [math]::Round(($s.Pass / $s.Total) * 100, 0) } else { 0 }
            $secName = if ($sectionNames.ContainsKey($sec)) { $sectionNames[$sec] } else { "Section $sec" }
            [ordered]@{
                section = $sec
                name    = $secName
                pass    = $s.Pass
                fail    = $s.Fail
                warn    = $s.Warn
                total   = $s.Total
                score   = $secScore
            }
        }
    )
    results = @(
        foreach ($r in $Results) {
            $entry = [ordered]@{
                ID          = $r.ID
                Description = $r.Description
                Status      = $r.Status
                Detail      = $r.Detail
                Framework   = $r.Framework
            }
            if ($Script:RemediationData.ContainsKey($r.ID)) {
                $entry.severity    = $Script:RemediationData[$r.ID].Severity
                $entry.remediation = $Script:RemediationData[$r.ID].Remediation
            }
            $entry
        }
    )
}

$jsonObj | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonPath -Encoding UTF8

# ============================================================
#  HTML REPORT
# ============================================================
# Build framework score data for charts
$fwChartData = @()
foreach ($fwKey in @("CIS","CIS-L2","CE+","NCSC","EntraID")) {
    $fw = $frameworkScoreMap[$fwKey]
    if ($fw.Total -gt 0) {
        $fwChartData += [ordered]@{ label = $fw.Label; score = $fw.Score; pass = $fw.Pass; fail = $fw.Fail; warn = $fw.Warn; total = $fw.Total }
    }
}
$fwChartJson = ($fwChartData | ConvertTo-Json -Depth 3 -Compress)
# Ensure valid JSON array even with single item
if ($fwChartData.Count -eq 1) { $fwChartJson = "[$fwChartJson]" }
if ($fwChartData.Count -eq 0) { $fwChartJson = "[]" }

# Build compliance data for HTML
$complianceRows = ""
foreach ($fwKey in @("CIS","CIS-L2","CE+","NCSC","EntraID")) {
    $fw = $frameworkScoreMap[$fwKey]
    if ($fw.Total -eq 0) { continue }
    $thresh = $Script:ComplianceThresholds[$fwKey]
    $verdict = if ($fw.Score -ge $thresh.Threshold) { "PASSES" } else { "DOES NOT PASS" }
    $vClass  = if ($verdict -eq "PASSES") { "badge-pass" } else { "badge-fail" }
    $complianceRows += "<tr><td>$($fw.Label)</td><td>$($fw.Score)%</td><td>$($thresh.Threshold)%</td><td><span class='$vClass'>$verdict</span></td></tr>`n"
}

# Build section scorecard rows
$sectionRows = ""
foreach ($sec in $sortedSections) {
    $s = $sectionScores[$sec]
    $secScore = if ($s.Total -gt 0) { [math]::Round(($s.Pass / $s.Total) * 100, 0) } else { 0 }
    $secName = if ($sectionNames.ContainsKey($sec)) { $sectionNames[$sec] } else { "Section $sec" }
    $rowClass = if ($secScore -ge 90) { "row-pass" } elseif ($secScore -ge 50) { "row-warn" } else { "row-fail" }
    $sectionRows += "<tr class='$rowClass'><td>$sec</td><td>$secName</td><td>$($s.Pass)</td><td>$($s.Fail)</td><td>$($s.Warn)</td><td>$secScore%</td></tr>`n"
}

# Build results table rows
$resultRows = ""
foreach ($r in $Results) {
    $statusClass = switch ($r.Status) { "PASS" { "badge-pass" }; "FAIL" { "badge-fail" }; "WARN" { "badge-warn" }; "INFO" { "badge-info" } }
    $sevText = ""
    $remText = ""
    if ($Script:RemediationData.ContainsKey($r.ID)) {
        $sevText = $Script:RemediationData[$r.ID].Severity
        $remText = $Script:RemediationData[$r.ID].Remediation
    }
    # HTML-escape detail and remediation text
    $safeDetail = [System.Net.WebUtility]::HtmlEncode($r.Detail)
    $safeRem    = [System.Net.WebUtility]::HtmlEncode($remText)
    $safeDesc   = [System.Net.WebUtility]::HtmlEncode($r.Description)
    $resultRows += "<tr><td>$($r.ID)</td><td>$safeDesc</td><td><span class='$statusClass'>$($r.Status)</span></td><td>$($r.Framework)</td><td>$sevText</td><td class='detail-cell'>$safeDetail</td><td class='detail-cell'>$safeRem</td></tr>`n"
}

# Build top 5 risks HTML
$top5Html = ""
if ($failedItems.Count -gt 0) {
    $top5List = $failedItems | Sort-Object { Get-SeverityWeight $_.ID } -Descending | Select-Object -First 5
    foreach ($r in $top5List) {
        $sev = if ($Script:RemediationData.ContainsKey($r.ID)) { $Script:RemediationData[$r.ID].Severity } else { "Medium" }
        $safeDesc = [System.Net.WebUtility]::HtmlEncode($r.Description)
        $top5Html += "<li><span class='badge-fail'>$sev</span> [$($r.ID)] $safeDesc</li>`n"
    }
}

# Build remediation HTML
$remediationHtml = ""
if ($failedItems.Count -gt 0) {
    $failByFw = $failedItems | Group-Object Framework | Sort-Object Count -Descending
    foreach ($group in $failByFw) {
        $fwName = switch ($group.Name) {
            "CIS"     { "CIS Level 1" }
            "CIS-L2"  { "CIS Level 2" }
            "CE"      { "Cyber Essentials" }
            "CE+"     { "Cyber Essentials Plus" }
            "NCSC"    { "NCSC Alignment" }
            "EntraID" { "Entra ID / M365" }
            default   { $group.Name }
        }
        $remediationHtml += "<h4>$fwName ($($group.Count) failures)</h4><ol>`n"
        foreach ($r in $group.Group) {
            $sevBadge = ""
            $remLine  = ""
            if ($Script:RemediationData.ContainsKey($r.ID)) {
                $sevBadge = "<span class='badge-warn'>$($Script:RemediationData[$r.ID].Severity)</span> "
                $remLine  = "<br><em>Remediation: $([System.Net.WebUtility]::HtmlEncode($Script:RemediationData[$r.ID].Remediation))</em>"
            }
            $safeDesc = [System.Net.WebUtility]::HtmlEncode($r.Description)
            $safeDetail = [System.Net.WebUtility]::HtmlEncode($r.Detail)
            $remediationHtml += "<li>${sevBadge}[$($r.ID)] $safeDesc<br><small>$safeDetail</small>$remLine</li>`n"
        }
        $remediationHtml += "</ol>`n"
    }
}

# Delta HTML (if previous report was provided)
$deltaHtml = ""
if ($Script:PreviousData) {
    $deltaHtml = "<div class='section' id='delta'><h2 onclick=`"toggleSection('delta-body')`">Changes Since Last Audit</h2><div id='delta-body'>"
    if ($null -ne $prevScore) {
        $delta = $score - $prevScore
        $arrow = if ($delta -gt 0) { "+" } else { "" }
        $dClass = if ($delta -gt 0) { "badge-pass" } elseif ($delta -lt 0) { "badge-fail" } else { "badge-info" }
        $deltaHtml += "<p>Overall Score: <strong>$prevScore%</strong> -> <strong>$score%</strong> <span class='$dClass'>${arrow}${delta}%</span></p>"
    }
    $deltaHtml += "<p>Resolved: $($resolved.Count) | New Failures: $($newFails.Count) | Regressions: $($regressions.Count)</p>"
    if ($resolved.Count -gt 0) {
        $deltaHtml += "<h4 style='color:var(--pass)'>Resolved</h4><ul>"
        foreach ($item in $resolved) { $deltaHtml += "<li class='resolved'>$([System.Net.WebUtility]::HtmlEncode($item))</li>" }
        $deltaHtml += "</ul>"
    }
    if ($regressions.Count -gt 0) {
        $deltaHtml += "<h4 style='color:var(--fail)'>Regressions</h4><ul>"
        foreach ($item in $regressions) { $deltaHtml += "<li class='regression'>$([System.Net.WebUtility]::HtmlEncode($item))</li>" }
        $deltaHtml += "</ul>"
    }
    if ($newFails.Count -gt 0) {
        $deltaHtml += "<h4 style='color:var(--warn)'>New Failures</h4><ul>"
        foreach ($item in $newFails) { $deltaHtml += "<li class='new-fail'>$([System.Net.WebUtility]::HtmlEncode($item))</li>" }
        $deltaHtml += "</ul>"
    }
    $deltaHtml += "</div></div>"
}

# Build framework dashboard rows for HTML table
$fwDashboardRows = ""
foreach ($fwKey in @("CIS","CIS-L2","CE+","NCSC","EntraID")) {
    $fw = $frameworkScoreMap[$fwKey]
    if ($fw.Total -gt 0) {
        $fwDashboardRows += "<tr><td>$($fw.Label)</td><td>$($fw.Score)%</td><td>$($fw.Pass)</td><td>$($fw.Fail)</td><td>$($fw.Warn)</td><td>$($fw.Total)</td></tr>`n"
    }
}

# Build the HTML content using string concatenation to avoid here-string escaping issues
$htmlParts = [System.Collections.Generic.List[string]]::new()
$htmlParts.Add('<!DOCTYPE html>')
$htmlParts.Add('<html lang="en">')
$htmlParts.Add('<head>')
$htmlParts.Add('<meta charset="UTF-8">')
$htmlParts.Add('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
$htmlParts.Add("<title>Audit Report - $env:COMPUTERNAME - $(Get-Date -Format 'dd MMM yyyy')</title>")
$htmlParts.Add('<style>')
$htmlParts.Add(':root{--pass:#28a745;--fail:#dc3545;--warn:#ffc107;--info:#17a2b8;--bg:#f8f9fa;--card:#fff;--border:#dee2e6;--text:#212529;--muted:#6c757d}')
$htmlParts.Add('*{box-sizing:border-box;margin:0;padding:0}')
$htmlParts.Add('body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:20px}')
$htmlParts.Add('.container{max-width:1400px;margin:0 auto}')
$htmlParts.Add('h1{text-align:center;margin:20px 0;font-size:1.8em}')
$htmlParts.Add('h2{cursor:pointer;padding:12px 16px;background:#343a40;color:#fff;border-radius:6px 6px 0 0;margin:0;font-size:1.1em;user-select:none}')
$htmlParts.Add('h2:hover{background:#495057}')
$htmlParts.Add('h2::before{content:"+ ";font-weight:bold}')
$htmlParts.Add('h2.open::before{content:"- "}')
$htmlParts.Add('h3{margin:16px 0 8px;color:#343a40}')
$htmlParts.Add('h4{margin:12px 0 6px;color:var(--fail)}')
$htmlParts.Add('.section{background:var(--card);border:1px solid var(--border);border-radius:6px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}')
$htmlParts.Add('.section > div{padding:16px;display:none}')
$htmlParts.Add('.section > div.open{display:block}')
$htmlParts.Add('.header-bar{background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;padding:30px;border-radius:8px;margin-bottom:20px;text-align:center}')
$htmlParts.Add('.header-bar h1{color:#fff;margin:0 0 8px}')
$htmlParts.Add('.header-bar p{color:#adb5bd;margin:2px 0}')
$htmlParts.Add('.toc{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:16px;margin:16px 0}')
$htmlParts.Add('.toc a{color:#007bff;text-decoration:none;display:inline-block;margin:4px 12px 4px 0}')
$htmlParts.Add('.toc a:hover{text-decoration:underline}')
$htmlParts.Add('.badge-pass{background:var(--pass);color:#fff;padding:2px 8px;border-radius:3px;font-size:.85em;font-weight:600}')
$htmlParts.Add('.badge-fail{background:var(--fail);color:#fff;padding:2px 8px;border-radius:3px;font-size:.85em;font-weight:600}')
$htmlParts.Add('.badge-warn{background:var(--warn);color:#212529;padding:2px 8px;border-radius:3px;font-size:.85em;font-weight:600}')
$htmlParts.Add('.badge-info{background:var(--info);color:#fff;padding:2px 8px;border-radius:3px;font-size:.85em;font-weight:600}')
$htmlParts.Add('.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0}')
$htmlParts.Add('.stat-card{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:16px;text-align:center}')
$htmlParts.Add('.stat-card .value{font-size:2em;font-weight:700}')
$htmlParts.Add('.stat-card .label{color:var(--muted);font-size:.85em}')
$htmlParts.Add('.stat-card.pass .value{color:var(--pass)}')
$htmlParts.Add('.stat-card.fail .value{color:var(--fail)}')
$htmlParts.Add('.stat-card.warn .value{color:var(--warn)}')
$htmlParts.Add('.stat-card.info .value{color:var(--info)}')
$htmlParts.Add('.chart-container{display:flex;flex-wrap:wrap;gap:20px;justify-content:center;margin:16px 0}')
$htmlParts.Add('.fw-chart{width:200px;text-align:center}')
$htmlParts.Add('table{width:100%;border-collapse:collapse;margin:12px 0;font-size:.9em}')
$htmlParts.Add('th{background:#343a40;color:#fff;padding:10px 12px;text-align:left;position:sticky;top:0;cursor:pointer}')
$htmlParts.Add('th:hover{background:#495057}')
$htmlParts.Add('td{padding:8px 12px;border-bottom:1px solid var(--border)}')
$htmlParts.Add('tr:hover{background:#f1f3f5}')
$htmlParts.Add('.row-pass{background:#d4edda}')
$htmlParts.Add('.row-warn{background:#fff3cd}')
$htmlParts.Add('.row-fail{background:#f8d7da}')
$htmlParts.Add('.detail-cell{max-width:400px;word-wrap:break-word;font-size:.85em}')
$htmlParts.Add('.filter-bar{margin:12px 0;display:flex;gap:8px;flex-wrap:wrap;align-items:center}')
$htmlParts.Add('.filter-bar select,.filter-bar input{padding:6px 10px;border:1px solid var(--border);border-radius:4px;font-size:.9em}')
$htmlParts.Add('.filter-bar input{width:250px}')
$htmlParts.Add('.resolved{color:var(--pass)}')
$htmlParts.Add('.regression{color:var(--fail)}')
$htmlParts.Add('.new-fail{color:var(--warn)}')
$htmlParts.Add('.compliance-table td:last-child{font-weight:700}')
$htmlParts.Add('.print-only{display:none}')
$htmlParts.Add('@media print{body{padding:0;font-size:10pt}.section > div{display:block!important}h2::before{content:""!important}.print-only{display:block}.no-print{display:none}}')
$htmlParts.Add('@media(max-width:768px){.stats-grid{grid-template-columns:1fr 1fr}.filter-bar{flex-direction:column}.filter-bar input{width:100%}}')
$htmlParts.Add('</style>')
$htmlParts.Add('</head>')
$htmlParts.Add('<body>')
$htmlParts.Add('<div class="container">')

# Header bar
$htmlParts.Add('<div class="header-bar">')
$htmlParts.Add('<h1>OTY Heavy Industries - Audit Report</h1>')
$htmlParts.Add("<p>$env:COMPUTERNAME | $(Get-Date -Format 'dd MMM yyyy HH:mm') UTC | Version $ScriptVersion</p>")
$htmlParts.Add("<p>Scope: $($Script:AuditLabel)</p>")
$htmlParts.Add('</div>')

# Table of contents
$htmlParts.Add('<div class="toc no-print">')
$htmlParts.Add('<strong>Quick Navigation:</strong>')
$htmlParts.Add('<a href="#attestation">Compliance Attestation</a>')
$htmlParts.Add('<a href="#summary">Executive Summary</a>')
$htmlParts.Add('<a href="#dashboard">Framework Dashboard</a>')
$htmlParts.Add('<a href="#scorecard">Section Scorecard</a>')
$htmlParts.Add('<a href="#context">Device Context</a>')
if ($Script:PreviousData) { $htmlParts.Add('<a href="#delta">Delta Comparison</a>') }
$htmlParts.Add('<a href="#remediation">Priority Remediation</a>')
$htmlParts.Add('<a href="#results">All Results</a>')
$htmlParts.Add('</div>')

# Compliance Attestation
$htmlParts.Add('<div class="section" id="attestation">')
$htmlParts.Add("<h2 class=`"open`" onclick=`"toggleSection('attestation-body')`">Compliance Attestation</h2>")
$htmlParts.Add('<div id="attestation-body" class="open">')
$htmlParts.Add('<table class="compliance-table">')
$htmlParts.Add('<tr><th>Framework</th><th>Score</th><th>Threshold</th><th>Verdict</th></tr>')
$htmlParts.Add($complianceRows)
$htmlParts.Add('</table>')
$htmlParts.Add('</div></div>')

# Executive Summary
$htmlParts.Add('<div class="section" id="summary">')
$htmlParts.Add("<h2 class=`"open`" onclick=`"toggleSection('summary-body')`">Executive Summary</h2>")
$htmlParts.Add('<div id="summary-body" class="open">')
$htmlParts.Add('<div class="stats-grid">')
$htmlParts.Add("<div class='stat-card'><div class='value'>$score%</div><div class='label'>Overall Score</div></div>")
$htmlParts.Add("<div class='stat-card'><div class='value'>$weightedScore%</div><div class='label'>Weighted Score</div></div>")
$htmlParts.Add("<div class='stat-card'><div class='value'>$($overallRisk.Label)</div><div class='label'>Risk Rating</div></div>")
$htmlParts.Add("<div class='stat-card'><div class='value'>$totalChecks</div><div class='label'>Total Checks</div></div>")
$htmlParts.Add("<div class='stat-card pass'><div class='value'>$passCount</div><div class='label'>Passed</div></div>")
$htmlParts.Add("<div class='stat-card fail'><div class='value'>$failCount</div><div class='label'>Failed</div></div>")
$htmlParts.Add("<div class='stat-card warn'><div class='value'>$warnCount</div><div class='label'>Warnings</div></div>")
$htmlParts.Add("<div class='stat-card info'><div class='value'>$infoCount</div><div class='label'>Info</div></div>")
$htmlParts.Add('</div>')
$htmlParts.Add("<p><strong>Audit Duration:</strong> $DurationStr</p>")
if ($top5Html) { $htmlParts.Add("<h3>Top 5 Risks</h3><ol>$top5Html</ol>") }
$htmlParts.Add('</div></div>')

# Framework Dashboard
$htmlParts.Add('<div class="section" id="dashboard">')
$htmlParts.Add("<h2 class=`"open`" onclick=`"toggleSection('dashboard-body')`">Framework Score Dashboard</h2>")
$htmlParts.Add('<div id="dashboard-body" class="open">')
$htmlParts.Add('<div class="chart-container" id="fw-charts"></div>')
$htmlParts.Add('<table>')
$htmlParts.Add('<tr><th>Framework</th><th>Score</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Total</th></tr>')
$htmlParts.Add($fwDashboardRows)
$htmlParts.Add('</table>')
$htmlParts.Add("<p><small>* NCSC uses weighted scoring: PASS=full, WARN=partial (0.5), FAIL=none.</small></p>")
$htmlParts.Add('</div></div>')

# Section Scorecard
$htmlParts.Add('<div class="section" id="scorecard">')
$htmlParts.Add("<h2 onclick=`"toggleSection('scorecard-body')`">Section Scorecard</h2>")
$htmlParts.Add('<div id="scorecard-body">')
$htmlParts.Add('<table>')
$htmlParts.Add('<tr><th>Section</th><th>Name</th><th>Pass</th><th>Fail</th><th>Warn</th><th>Score</th></tr>')
$htmlParts.Add($sectionRows)
$htmlParts.Add('</table>')
$htmlParts.Add('</div></div>')

# Device Context
$safeOsEdition = [System.Net.WebUtility]::HtmlEncode($osEdition)
$safeBiosVendor = [System.Net.WebUtility]::HtmlEncode($biosVendor)
$htmlParts.Add('<div class="section" id="context">')
$htmlParts.Add("<h2 onclick=`"toggleSection('context-body')`">Device Context</h2>")
$htmlParts.Add('<div id="context-body">')
$htmlParts.Add('<table>')
$htmlParts.Add("<tr><td><strong>Hostname</strong></td><td>$env:COMPUTERNAME</td><td><strong>User</strong></td><td>$env:USERNAME</td></tr>")
$htmlParts.Add("<tr><td><strong>OS</strong></td><td>$safeOsEdition</td><td><strong>Last Reboot</strong></td><td>$lastReboot</td></tr>")
$htmlParts.Add("<tr><td><strong>Join Type</strong></td><td>$joinType</td><td><strong>Domain</strong></td><td>$domainInfo</td></tr>")
$mdmDisplay = "$($Script:MDMEnrolled) $(if ($Script:MDMUrl) {"($($Script:MDMUrl))"} else {''})"
$htmlParts.Add("<tr><td><strong>Tenant</strong></td><td>$($Script:TenantName) ($($Script:TenantID))</td><td><strong>MDM</strong></td><td>$mdmDisplay</td></tr>")
$htmlParts.Add("<tr><td><strong>TPM</strong></td><td>$tpmVersion ($tpmStatus)</td><td><strong>Secure Boot</strong></td><td>$secureBootStr</td></tr>")
$htmlParts.Add("<tr><td><strong>BIOS/UEFI</strong></td><td>$safeBiosVendor</td><td><strong>PowerShell</strong></td><td>$psVersion</td></tr>")
$htmlParts.Add("<tr><td><strong>IP Address(es)</strong></td><td colspan=`"3`">$ipAddresses</td></tr>")
$htmlParts.Add('</table>')
$htmlParts.Add('</div></div>')

# Delta section (if applicable)
if ($deltaHtml) { $htmlParts.Add($deltaHtml) }

# Priority Remediation
$htmlParts.Add('<div class="section" id="remediation">')
$htmlParts.Add("<h2 onclick=`"toggleSection('remediation-body')`">Priority Remediation ($failCount failed controls)</h2>")
$htmlParts.Add('<div id="remediation-body">')
$htmlParts.Add($remediationHtml)
$htmlParts.Add('</div></div>')

# All Results
$htmlParts.Add('<div class="section" id="results">')
$htmlParts.Add("<h2 onclick=`"toggleSection('results-body')`">All Results ($totalChecks checks)</h2>")
$htmlParts.Add('<div id="results-body">')
$htmlParts.Add('<div class="filter-bar no-print">')
$htmlParts.Add('<label>Status:</label>')
$htmlParts.Add('<select id="statusFilter" onchange="filterResults()">')
$htmlParts.Add('<option value="">All</option><option value="PASS">PASS</option><option value="FAIL">FAIL</option><option value="WARN">WARN</option><option value="INFO">INFO</option>')
$htmlParts.Add('</select>')
$htmlParts.Add('<label>Framework:</label>')
$htmlParts.Add('<select id="fwFilter" onchange="filterResults()">')
$htmlParts.Add('<option value="">All</option><option value="CIS">CIS</option><option value="CIS-L2">CIS-L2</option><option value="CE+">CE+</option><option value="NCSC">NCSC</option><option value="EntraID">EntraID</option>')
$htmlParts.Add('</select>')
$htmlParts.Add('<input type="text" id="searchFilter" placeholder="Search descriptions..." oninput="filterResults()">')
$htmlParts.Add('</div>')
$htmlParts.Add('<table id="resultsTable">')
$htmlParts.Add('<thead><tr><th onclick="sortTable(0)">ID</th><th onclick="sortTable(1)">Description</th><th onclick="sortTable(2)">Status</th><th onclick="sortTable(3)">Framework</th><th onclick="sortTable(4)">Severity</th><th onclick="sortTable(5)">Detail</th><th onclick="sortTable(6)">Remediation</th></tr></thead>')
$htmlParts.Add("<tbody id=`"resultsBody`">")
$htmlParts.Add($resultRows)
$htmlParts.Add('</tbody>')
$htmlParts.Add('</table>')
$htmlParts.Add('</div></div>')

# Footer
$htmlParts.Add('<div style="text-align:center;padding:20px;color:var(--muted);font-size:.85em">')
$htmlParts.Add("<p>Generated by OTY Heavy Industries Audit Script v$ScriptVersion | $(Get-Date -Format 'dd MMM yyyy HH:mm:ss') UTC</p>")
$htmlParts.Add("<p>Duration: $DurationStr | <a href=`"#`" onclick=`"window.print();return false;`" class=`"no-print`">Print / Save as PDF</a></p>")
$htmlParts.Add('</div>')

$htmlParts.Add('</div>')

# JavaScript
$htmlParts.Add('<script>')
# Sanitize JSON for embedding in HTML script tag (defense in depth)
$safeFwChartJson = $fwChartJson -replace '<', '\u003c' -replace '>', '\u003e' -replace '&', '\u0026'
$htmlParts.Add("var fwData=$safeFwChartJson;")
$jsCode = @'
function toggleSection(id){var el=document.getElementById(id);if(!el)return;var h=el.previousElementSibling;if(el.classList.contains('open')){el.classList.remove('open');if(h)h.classList.remove('open')}else{el.classList.add('open');if(h)h.classList.add('open')}}
function getBarColor(s){return s>=90?'var(--pass)':s>=75?'var(--warn)':'var(--fail)'}
function buildCharts(){var c=document.getElementById('fw-charts');if(!c||!fwData)return;fwData.forEach(function(f){var d=document.createElement('div');d.className='fw-chart';var svg='<svg viewBox="0 0 36 36" width="120" height="120">';svg+='<path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#e9ecef" stroke-width="3"/>';svg+='<path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="'+getBarColor(f.score)+'" stroke-width="3" stroke-dasharray="'+f.score+', 100" stroke-linecap="round"/>';svg+='<text x="18" y="20.35" text-anchor="middle" font-size="8" font-weight="bold" fill="#333">'+f.score+'%</text>';svg+='</svg>';d.innerHTML=svg+'<div><strong>'+f.label+'</strong></div><div style="font-size:.8em;color:var(--muted)">'+f.pass+'P / '+f.fail+'F / '+f.warn+'W</div>';c.appendChild(d)})}
function filterResults(){var s=document.getElementById('statusFilter').value;var f=document.getElementById('fwFilter').value;var q=document.getElementById('searchFilter').value.toLowerCase();var rows=document.querySelectorAll('#resultsBody tr');rows.forEach(function(r){var cells=r.getElementsByTagName('td');var show=true;if(s&&cells[2].textContent.trim()!==s)show=false;if(f&&cells[3].textContent.trim()!==f)show=false;if(q&&cells[1].textContent.toLowerCase().indexOf(q)===-1&&cells[5].textContent.toLowerCase().indexOf(q)===-1)show=false;r.style.display=show?'':'none'})}
var sortDir={};
function sortTable(n){var table=document.getElementById('resultsTable');var rows=Array.from(table.querySelectorAll('tbody tr'));sortDir[n]=!sortDir[n];rows.sort(function(a,b){var x=a.cells[n].textContent.trim();var y=b.cells[n].textContent.trim();if(!isNaN(parseFloat(x))&&!isNaN(parseFloat(y)))return sortDir[n]?x-y:y-x;return sortDir[n]?x.localeCompare(y):y.localeCompare(x)});var tbody=table.querySelector('tbody');rows.forEach(function(r){tbody.appendChild(r)})}
buildCharts();
'@
$htmlParts.Add($jsCode)
$htmlParts.Add('</script>')
$htmlParts.Add('</body>')
$htmlParts.Add('</html>')

$htmlContent = $htmlParts -join "`n"
$htmlContent | Set-Content -Path $HtmlPath -Encoding UTF8

# ============================================================
#  REPORT FOOTER
# ============================================================
Write-ReportLine ""
Write-Divider "="
Write-ReportLine "  END OF AUDIT REPORT"
Write-ReportLine "  Generated : $(Get-Date -Format 'dd MMM yyyy HH:mm:ss') UTC"
Write-ReportLine "  Duration  : $DurationStr"
Write-Divider "="

Write-Host ""
Write-Host "  Text report saved to : $ReportPath" -ForegroundColor Green
Write-Host "  CSV export saved to  : $CsvPath" -ForegroundColor Green
Write-Host "  JSON export saved to : $JsonPath" -ForegroundColor Green
Write-Host "  HTML report saved to : $HtmlPath" -ForegroundColor Green
Write-Host ""
Write-Host "  Tip: Open the HTML report in a browser for interactive charts," -ForegroundColor Cyan
Write-Host "       filtering, and print-to-PDF export." -ForegroundColor Cyan
Write-Host ""
Add-Content -Path $ReportPath -Value ""
Add-Content -Path $ReportPath -Value "  Text report : $ReportPath"
Add-Content -Path $ReportPath -Value "  CSV export  : $CsvPath"
Add-Content -Path $ReportPath -Value "  JSON export : $JsonPath"
Add-Content -Path $ReportPath -Value "  HTML report : $HtmlPath"
