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

.NOTES
    Must be run as Administrator.
    Tested on Windows 10/11 22H2+, Entra ID joined and Hybrid joined.
    No Microsoft Graph or Azure AD module required - uses dsregcmd, registry,
    WMI/CIM, and local tooling only so it works offline and without extra modules.
#>

# ============================================================
#  INITIALISATION
# ============================================================
$ScriptVersion = "4.2.2"
$Timestamp     = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportPath    = "$env:USERPROFILE\Desktop\OTY_Heavy_Industries_Audit_$Timestamp.txt"
$SecCfg        = "$env:TEMP\oty_secedit_$Timestamp.cfg"
$Results       = [System.Collections.Generic.List[PSCustomObject]]::new()

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
    $eppEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\AzureADPasswordProtection" "EnableBannedPasswordCheck"
    $s = if ($null -ne $eppEnabled -and $eppEnabled -eq 1) { "PASS" } else { "WARN" }
    Add-Result "1.N1" "Entra Password Protection (Banned List)" $s "EnableBannedPasswordCheck: $(if ($null -eq $eppEnabled) {'Not configured via local policy - verify in Entra portal > Security > Auth Methods > Password Protection'} else {$eppEnabled})" "NCSC"

    # SSPR (Self-Service Password Reset) indicator - sign of breach-driven change model
    $sspReg = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\AzureADPasswordProtection" "EnableSelfServicePasswordReset"
    Add-Result "1.N2" "Self-Service Password Reset (SSPR)" "INFO" "SSPR policy: $(if ($null -eq $sspReg) {'Not configured locally - verify in Entra portal'} else {$sspReg}) | NCSC: users should change only on suspected compromise" "NCSC"

    # Local fallback length check - should not be weaker than 15 on Entra devices
    $minLen = Get-SecEditValue "MinimumPasswordLength"
    $s = if ([int]$minLen -ge 15) { "PASS" } elseif ([int]$minLen -ge 12) { "WARN" } else { "FAIL" }
    Add-Result "1.7"  "Local Policy Min Length (Fallback)" $s "Local secedit: $minLen chars | NCSC: >=15 recommended. Entra policy is primary." "CIS"

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
$s = if ($adminCount -le 2) { "PASS" } elseif ($adminCount -le 4) { "WARN" } else { "FAIL" }
Add-Result "4.3" "Local Admin Account Count" $s "Effective total: $adminCount (local excl. script runner: $effectiveLocalCount | Cloud/AD: $(($entraAdmins | Measure-Object).Count)) | Script runner excluded: $env:USERNAME"

if ($Script:EntraJoined -and $entraAdmins.Count -gt 0) {
    Add-Result "4.3E" "Entra ID Admins on Device" "INFO" "Cloud admin principals: $(($entraAdmins.Name) -join ', ') - Verify via Entra ID Device Local Admins policy" "EntraID"
}

# Built-in Admin renamed
# On Entra joined + MDM enrolled devices, the built-in admin is typically managed
# by Windows LAPS or disabled via Intune - local renaming policy may not apply.
$adminUser = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-500" } -ErrorAction SilentlyContinue
if ($adminUser) {
    if ($Script:EntraJoined -and $Script:MDMEnrolled) {
        # LAPS manages this account - renaming is less critical when LAPS rotates the password
        $lapsManaged = $null -ne (Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" "BackupDirectory")
        if ($lapsManaged) {
            Add-Result "4.4" "Built-in Admin Account Renamed" "PASS" "Account: $($adminUser.Name) | Entra+MDM device with LAPS configured - LAPS manages this account; renaming is supplementary" "EntraID"
        } else {
            $s = if ($adminUser.Name -ne "Administrator") { "PASS" } else { "WARN" }
            Add-Result "4.4" "Built-in Admin Account Renamed" $s "Account: $($adminUser.Name) | Entra+MDM device but LAPS not detected - consider enabling LAPS via Intune"
        }
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

# ============================================================
#  SECTION 8: AUTORUN / AUTOPLAY  [CIS]
# ============================================================
Write-SectionHeader "8. AUTORUN / AUTOPLAY" "CIS"

$autoRun  = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"
$autoPlay = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"

$s = if ($autoRun -eq 1) { "PASS" } else { "FAIL" }
Add-Result "8.1" "AutoRun Disabled" $s "Required: 1, Got: $autoRun"

$s = if ($autoPlay -eq 255) { "PASS" } else { "FAIL" }
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
            $blKeyBackup = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSActiveDirectoryBackup"
            $blAADBackup = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "OSRecoveryPassword"
            # Check for AAD backup via MDM
            $blMDMBackup = Get-RegValue "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker" "EncryptionMethodByDriveType"
            $s = if ($null -ne $blMDMBackup -or $null -ne $blKeyBackup) { "PASS" } else { "WARN" }
            Add-Result "15.K" "BitLocker Key Backed Up to Entra/AD" $s "Verify recovery key escrow in Entra ID portal > Devices > BitLocker Keys" "EntraID"
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
        $s = if ($f.State -in @("Disabled","DisabledWithPayloadRemoved")) { "PASS" } else { "WARN" }
        Add-Result "22.x" "$($feat.Label) Feature Removed" $s "State: $($f.State)"
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
    $_.PrincipalSource -eq "Local" -and
    (try {
        $sid = (New-Object System.Security.Principal.NTAccount($_.Name)).Translate(
                   [System.Security.Principal.SecurityIdentifier]).Value
        $sid -eq $currentSID
    } catch { $false })
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
    $s = if ($entraAdmins2.Count -le 2) { "PASS" } else { "WARN" }
    Add-Result "26A.4" "Entra ID Admin Accounts on Device" $s "Entra/AAD admins in local group: $($entraAdmins2.Count) - $(($entraAdmins2.Name) -join ', ') | Verify these are dedicated admin accounts in Entra portal > Devices > Device Local Administrators" "CE+"

    # Check the signed-in user's display name does not match a daily-use Entra admin
    # We can only do a loose name match locally; portal verification is authoritative
    $currentEntraAdmin = $entraAdmins2 | Where-Object { $_.Name -match [regex]::Escape($env:USERNAME) }
    $s = if (-not $currentEntraAdmin) { "PASS" } else { "WARN" }
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
Add-Result "34.5" "Secure Channel: Always Sign or Encrypt" $s "RequireSignOrSeal: $scEncAlways" "CIS-L2"

# Domain member: Digitally encrypt secure channel data when possible
$scEnc = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel"
$s = if ($scEnc -eq 1) { "PASS" } else { "WARN" }
Add-Result "34.6" "Secure Channel: Encrypt When Possible" $s "SealSecureChannel: $scEnc" "CIS-L2"

# Domain member: Digitally sign secure channel data when possible
$scSign = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel"
$s = if ($scSign -eq 1) { "PASS" } else { "WARN" }
Add-Result "34.7" "Secure Channel: Sign When Possible" $s "SignSecureChannel: $scSign" "CIS-L2"

# Domain member: Maximum machine account password age - <= 30 days
$machPwdAge = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge"
$s = if ($null -eq $machPwdAge -or ([int]$machPwdAge -le 30 -and [int]$machPwdAge -ge 1)) { "PASS" } else { "WARN" }
Add-Result "34.8" "Machine Account Password Age <= 30 Days" $s "MaximumPasswordAge: $(if ($null -eq $machPwdAge) {'Default (30)'} else {$machPwdAge})" "CIS-L2"

# Domain member: Require strong session key
$strongKey = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey"
$s = if ($strongKey -eq 1) { "PASS" } else { "FAIL" }
Add-Result "34.9" "Domain Member: Require Strong Session Key" $s "RequireStrongKey: $strongKey" "CIS-L2"

# Network access: Allow anonymous SID/Name translation - Disabled
$anonSID = Get-SecEditValue "LSAAnonymousNameLookup"
$s = if ($anonSID -eq "0") { "PASS" } else { "FAIL" }
Add-Result "34.10" "No Anonymous SID/Name Translation" $s "LSAAnonymousNameLookup: $(if ($null -eq $anonSID) {'Not set'} else {$anonSID}) (0=Disabled)" "CIS-L2"

# Network access: Do not allow storage of passwords and credentials
$noCredStore = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds"
$s = if ($noCredStore -eq 1) { "PASS" } else { "WARN" }
Add-Result "34.11" "No Storage of Network Passwords" $s "DisableDomainCreds: $noCredStore" "CIS-L2"

# Network access: Let Everyone permissions apply to anonymous users - Disabled
$everyoneAnon = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous"
$s = if ($everyoneAnon -eq 0 -or $null -eq $everyoneAnon) { "PASS" } else { "FAIL" }
Add-Result "34.12" "Everyone Does Not Include Anonymous" $s "EveryoneIncludesAnonymous: $(if ($null -eq $everyoneAnon) {'Default (0)'} else {$everyoneAnon})" "CIS-L2"

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
Add-Result "34.15" "Do Not Store LAN Manager Hash" $s "NoLMHash: $noLMHash" "CIS-L2"

# Network security: Kerberos encryption types
$kerbEnc = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes"
$s = if ($kerbEnc -eq 2147483640 -or $kerbEnc -ge 24) { "PASS" } else { "WARN" }
Add-Result "34.16" "Kerberos: Strong Encryption Types Only" $s "SupportedEncryptionTypes: $kerbEnc (2147483640=AES+Future, 24=AES128+AES256)" "CIS-L2"

# Shutdown: Allow shutdown without logon - Disabled
$shutdownNoLogon = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon"
$s = if ($shutdownNoLogon -eq 0) { "PASS" } else { "FAIL" }
Add-Result "34.17" "Shutdown Without Logon Disabled" $s "ShutdownWithoutLogon: $shutdownNoLogon" "CIS-L2"

# System objects: Strengthen default permissions
$strengthenPerms = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode"
$s = if ($strengthenPerms -eq 1) { "PASS" } else { "FAIL" }
Add-Result "34.18" "Strengthen Default Object Permissions" $s "ProtectionMode: $strengthenPerms" "CIS-L2"

# System settings: Optional subsystems - none (POSIX disabled)
$optSubsys = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems" "Optional"
$s = if ($null -eq $optSubsys -or $optSubsys -eq "") { "PASS" } else { "FAIL" }
Add-Result "34.19" "No Optional Subsystems (POSIX Disabled)" $s "Optional subsystems: $(if ($null -eq $optSubsys -or $optSubsys -eq '') {'None (correct)'} else {$optSubsys})" "CIS-L2"

# Audit: Force audit policy subcategory settings to override
$forceAudit = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy"
$s = if ($forceAudit -eq 1) { "PASS" } else { "FAIL" }
Add-Result "34.20" "Audit: Subcategory Settings Override Legacy" $s "SCENoApplyLegacyAuditPolicy: $forceAudit" "CIS-L2"

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
#  CLEAN UP
# ============================================================
if (Test-Path $SecCfg) { Remove-Item $SecCfg -Force -ErrorAction SilentlyContinue }

# ============================================================
#  SUMMARY
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

# ---- Overall score: PASS / all scoreable checks ----
$score = if ($scoreable -gt 0) { [math]::Round(($passCount / $scoreable) * 100, 1) } else { 0 }

# ---- CIS L1 score ----
$cisL1Score = if ($cisL1Count -gt 0) {
    [math]::Round((($cisL1Results | Where-Object { $_.Status -eq "PASS" }).Count / $cisL1Count) * 100, 1)
} else { 0 }

# ---- CIS L2 score ----
$l2Score = if ($cisL2Count -gt 0) {
    [math]::Round((($cisL2Results | Where-Object { $_.Status -eq "PASS" }).Count / $cisL2Count) * 100, 1)
} else { 0 }

# ---- CE/CE+ score ----
$ceScore = if ($ceCount -gt 0) {
    [math]::Round((($ceResults | Where-Object { $_.Status -eq "PASS" }).Count / $ceCount) * 100, 1)
} else { 0 }

# ---- Entra/M365 score ----
$entraScore = if ($entraCount -gt 0) {
    [math]::Round((($entraResults | Where-Object { $_.Status -eq "PASS" }).Count / $entraCount) * 100, 1)
} else { 0 }

# ---- NCSC alignment score ----
# NCSC checks use WARN to mean "CIS-compliant but not yet NCSC-optimal" rather than
# "broken". A system configured to CIS standards will score mostly WARNs on NCSC checks
# (e.g. length=14 passes CIS but WARNs on NCSC's 15-char threshold). Treating all WARNs
# as 0% would be misleading — a WARN counts as 0.5 (partial alignment) so the score
# reflects the genuine gap between current posture and full NCSC alignment.
$ncscScore = if ($ncscCount -gt 0) {
    $ncscPass    = ($ncscResults | Where-Object { $_.Status -eq "PASS" }).Count
    $ncscWarn    = ($ncscResults | Where-Object { $_.Status -eq "WARN" }).Count
    $ncscFail    = ($ncscResults | Where-Object { $_.Status -eq "FAIL" }).Count
    # Weighted: PASS=1, WARN=0.5, FAIL=0
    $ncscWeighted = ($ncscPass * 1.0) + ($ncscWarn * 0.5)
    [math]::Round(($ncscWeighted / $ncscCount) * 100, 1)
} else { 0 }

# Separate NCSC breakdown figures for display
$ncscPassCount = ($ncscResults | Where-Object { $_.Status -eq "PASS" }).Count
$ncscWarnCount = ($ncscResults | Where-Object { $_.Status -eq "WARN" }).Count
$ncscFailCount = ($ncscResults | Where-Object { $_.Status -eq "FAIL" }).Count

$summaryLines = @(
    "",
    "========================================================================",
    "  OTY HEAVY INDUSTRIES - AUDIT SUMMARY",
    "========================================================================",
    "  Total Checks          : $totalChecks",
    "  PASS                  : $passCount",
    "  FAIL                  : $failCount",
    "  WARN                  : $warnCount",
    "  INFO                  : $infoCount (informational, not scored)",
    "  -----------------------------------------------------------------------",
    "  CIS Level 1 Checks    : $cisL1Count  (INFO excluded)",
    "  CIS Level 2 Checks    : $cisL2Count  (INFO excluded)",
    "  NCSC Checks           : $ncscCount   (INFO excluded)",
    "  CE / CE+ Checks       : $ceCount     (INFO excluded)",
    "  Entra / M365 Checks   : $entraCount  (INFO excluded)",
    "  -----------------------------------------------------------------------",
    "  Overall Compliance    : $score%  (PASS / all scoreable checks)",
    "  CIS Level 1 Score     : $cisL1Score%",
    "  CIS Level 2 Score     : $l2Score%",
    "  CE / CE+ Score        : $ceScore%",
    "  Entra / M365 Score    : $entraScore%",
    "  NCSC Alignment        : $ncscScore%  (PASS=full, WARN=partial, FAIL=none)",
    "    NCSC breakdown      : PASS=$ncscPassCount  WARN=$ncscWarnCount  FAIL=$ncscFailCount",
    "    NOTE: WARN on NCSC = CIS-compliant but not yet NCSC-optimal (e.g. length=14",
    "          passes CIS but NCSC recommends 15+ chars). Improve WARNs to reach full",
    "          NCSC alignment. See ncsc.gov.uk/collection/passwords for guidance.",
    "========================================================================",
    "  Device Context:",
    "  Join Type        : $joinType",
    "  Tenant           : $($Script:TenantName) ($($Script:TenantID))",
    "  MDM Enrolled     : $($Script:MDMEnrolled) $(if ($Script:MDMUrl) {"($($Script:MDMUrl))"} else {''})",
    "  PRT Present      : $($Script:PRTPresent)",
    "  Device ID        : $($Script:DeviceID)",
    "========================================================================",
    "  Sections Audited:",
    "   1.  Password Policy          (CIS L1 | CE2 | NCSC - dual framework)",
    "   2.  Account Lockout          (CIS L1 | CE2 | Smart Lockout-aware)",
    "   3.  Remote Desktop           (CIS L1 | CE1 | CE+)",
    "   4.  Local Accounts           (CIS L1 | CE3 | CE+)",
    "   5.  Windows Firewall         (CIS L1 | CE1 | CE+)",
    "   6.  Patch Management         (CIS L1 | CE5 | CE+ | WUfB)",
    "   7.  SMBv1 Protocol           (CIS L1 | CE2)",
    "   8.  AutoRun / AutoPlay       (CIS L1)",
    "   9.  Insecure Services        (CIS L1 | CE2)",
    "  10.  Admin Shares             (CIS L1)",
    "  11.  User Account Control     (CIS L1 | CE3)",
    "  12.  Security Protocols       (CIS L1 | CE2 | NTLM-aware)",
    "  13.  Audit Policy             (CIS L1 17.x)",
    "  14.  Malware Protection       (CIS L1 | CE4 | CE+)",
    "  15.  BitLocker / Encryption   (CIS L1 | CE2 | Entra Key Backup)",
    "  16.  Secure Boot & UEFI       (CIS L1 | CE+)",
    "  17.  PowerShell Security      (CIS L1 | CE+)",
    "  18.  Application Control      (CIS L1 | CE2 | CE+)",
    "  19.  Event Log Configuration  (CIS L1 18.x)",
    "  20.  Credential Protection    (CIS L1 | CE+ | PRT-aware)",
    "  21.  Screen Lock / Session    (CIS L1 | CE2)",
    "  22.  Unnecessary Features     (CE2 | CE+)",
    "  23.  Network Security         (CIS L1 | CE1 | CE2 | IPv6-aware)",
    "  24.  Memory & Exploit Protect (CIS L1)",
    "  25.  CE Secure Configuration  (CE2 | CE+)",
    "  26.  Cyber Essentials Plus    (CE+)",
    " 26A.  CE+ Account Separation   (CE+ | NCSC)",
    " 26B.  CE+ 2FA/MFA              (CE+ | NCSC)",
    "  27.  Entra ID Device Identity (EntraID | CE+)",
    "  28.  Intune / MDM Enrolment   (EntraID | CE+)",
    "  29.  Windows Hello for Bus.   (EntraID | CE+)",
    "  30.  Defender for Endpoint    (EntraID | CE+)",
    "  31.  Microsoft 365 / Office   (EntraID | CE+)",
    "  32.  CA & Device Compliance   (EntraID | CE+)",
    "  33.  CIS L2 User Rights       (CIS L2)",
    "  34.  CIS L2 Sec Options       (CIS L2)",
    "  35.  CIS L2 Advanced Audit    (CIS L2 17.x)",
    "  36.  TLS/SSL & Cipher Hard.   (CIS L2 | CE+)",
    "  37.  Microsoft Edge Security  (CIS L2 | CE+)",
    "  38.  Peripheral & Device Ctrl (CIS L2 | CE+)",
    "  39.  Windows Privacy Hard.    (CIS L2)",
    "  40.  Remote Assistance        (CIS L2)",
    "  41.  DNS Client Security      (CIS L2)",
    "  42.  Scheduled Tasks          (CIS L2)",
    "  43.  MSS Legacy Settings      (CIS L2)",
    "  44.  CIS L2 Network Protocol  (CIS L2)",
    "  45.  ASR Specific Rules       (CIS L1/L2)",
    "  46.  System Exploit Protect   (CIS L2)",
    "  47.  Kernel DMA Protection    (CIS L2 | CE+)",
    "  48.  LAPS Configuration       (CIS L1 | CE3)",
    "  49.  Network List Manager     (CIS L2)",
    "  50.  Delivery Optimisation    (CIS L2)",
    "  51.  NTP / Time Security      (CIS L2)",
    "  52.  Defender App Guard       (CIS L2)",
    "  53.  RPC & DCOM Security      (CIS L2)",
    "  54.  Group Policy Infra.      (CIS L2)",
    "  55.  Print Security           (CIS L1/L2)",
    "  56.  Windows Copilot / AI     (CIS L2)",
    "  57.  File & Reg Permissions   (CIS L2)",
    "  58.  Internet Explorer        (CIS L1)",
    "  59.  Windows Event Forwarding (CIS L2)",
    "  60.  Additional Defender      (CIS L1/L2)",
    "========================================================================"
)

foreach ($line in $summaryLines) { Write-Host $line -ForegroundColor Cyan }
$summaryLines | Add-Content -Path $ReportPath

# Failed controls list
if ($failCount -gt 0) {
    Write-Host "`n  FAILED CONTROLS:" -ForegroundColor Red
    Add-Content -Path $ReportPath -Value "`n  FAILED CONTROLS:"
    $Results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        $line = "    [$($_.ID)] [$($_.Framework)] $($_.Description) - $($_.Detail)"
        Write-Host $line -ForegroundColor Red
        Add-Content -Path $ReportPath -Value $line
    }
}

# Warnings list
if ($warnCount -gt 0) {
    Write-Host "`n  WARNINGS (review manually):" -ForegroundColor Yellow
    Add-Content -Path $ReportPath -Value "`n  WARNINGS (review manually):"
    $Results | Where-Object { $_.Status -eq "WARN" } | ForEach-Object {
        $line = "    [$($_.ID)] [$($_.Framework)] $($_.Description) - $($_.Detail)"
        Write-Host $line -ForegroundColor Yellow
        Add-Content -Path $ReportPath -Value $line
    }
}

Write-Host "`n  Report saved to: $ReportPath`n" -ForegroundColor Green
Add-Content -Path $ReportPath -Value "`n  Report saved to: $ReportPath"
