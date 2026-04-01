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
$ScriptVersion = "4.0.0"
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
        "  Microsoft Entra ID  |  Microsoft 365  |  Intune / MDM",
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
#  SECTION 1: PASSWORD POLICY  [CIS 1.1 | CE2]
# ============================================================
Write-SectionHeader "1. PASSWORD POLICY" "CIS 1.1 | CE2"

if ($Script:EntraJoined -and -not $Script:HybridJoined) {
    # Pure Entra ID joined - password policy is cloud-managed
    Add-CloudManaged "1.1" "Password History"           "Managed by Entra ID Password Protection policy"
    Add-CloudManaged "1.2" "Maximum Password Age"       "Managed by Entra ID - default 90 days for M365"
    Add-CloudManaged "1.3" "Minimum Password Age"       "Managed by Entra ID"
    Add-CloudManaged "1.4" "Minimum Password Length"    "Managed by Entra ID - default 8 chars (CIS requires 14 in Entra policy)"
    Add-CloudManaged "1.5" "Password Complexity"        "Managed by Entra ID - enforced by default"
    Add-CloudManaged "1.6" "No Reversible Encryption"   "Not applicable to Entra ID cloud accounts"

    # Still check local policy is not LESS restrictive (belt-and-braces)
    $minLen = Get-SecEditValue "MinimumPasswordLength"
    $s = if ([int]$minLen -ge 8) { "PASS" } else { "WARN" }
    Add-Result "1.7" "Local Policy Min Length (Fallback)" $s "Local secedit: $minLen chars (Entra policy primary)" "CIS"
} else {
    # Domain / local - check secedit directly
    $historySize = Get-SecEditValue "PasswordHistorySize"
    $maxAge      = Get-SecEditValue "MaximumPasswordAge"
    $minAge      = Get-SecEditValue "MinimumPasswordAge"
    $minLen      = Get-SecEditValue "MinimumPasswordLength"
    $complexity  = Get-SecEditValue "PasswordComplexity"
    $reversible  = Get-SecEditValue "ClearTextPassword"

    $s = if ([int]$historySize -ge 24) { "PASS" } else { "FAIL" }
    Add-Result "1.1" "Password History" $s "Required >=24, Got: $historySize"

    $s = if ([int]$maxAge -le 365 -and [int]$maxAge -ge 1) { "PASS" } else { "FAIL" }
    Add-Result "1.2" "Maximum Password Age" $s "Required 1-365 days, Got: $maxAge days"

    $s = if ([int]$minAge -ge 1) { "PASS" } else { "FAIL" }
    Add-Result "1.3" "Minimum Password Age" $s "Required >=1 day, Got: $minAge days"

    $s = if ([int]$minLen -ge 14) { "PASS" } else { "FAIL" }
    Add-Result "1.4" "Minimum Password Length" $s "Required >=14 chars, Got: $minLen"

    $s = if ($complexity -eq "1") { "PASS" } else { "FAIL" }
    Add-Result "1.5" "Password Complexity" $s "Required: Enabled, Got: $(if ($complexity -eq '1') {'Enabled'} else {'Disabled'})"

    $s = if ($reversible -eq "0") { "PASS" } else { "FAIL" }
    Add-Result "1.6" "No Reversible Encryption" $s "Required: Disabled, Got: $(if ($reversible -eq '0') {'Disabled'} else {'Enabled'})"
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
    Add-Result "4.1" "Guest Account Disabled" "WARN" "Could not query Guest account"
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

$adminCount = if ($adminGroup) { $adminGroup.Count } else { 0 }
$s = if ($adminCount -le 2) { "PASS" } elseif ($adminCount -le 4) { "WARN" } else { "FAIL" }
Add-Result "4.3" "Local Admin Account Count" $s "Total: $adminCount | Local: $($localAdmins.Count) | Cloud/AD: $($entraAdmins.Count)"

if ($Script:EntraJoined -and $entraAdmins.Count -gt 0) {
    Add-Result "4.3E" "Entra ID Admins on Device" "INFO" "Cloud admin principals: $(($entraAdmins.Name) -join ', ') - Verify via Entra ID Device Local Admins policy" "EntraID"
}

# Built-in Admin renamed
$adminUser = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-500" } -ErrorAction SilentlyContinue
if ($adminUser) {
    $s = if ($adminUser.Name -ne "Administrator") { "PASS" } else { "WARN" }
    Add-Result "4.4" "Built-in Admin Account Renamed" $s "Account name: $($adminUser.Name)"
} else {
    Add-Result "4.4" "Built-in Admin Account Renamed" "WARN" "Could not determine built-in admin account"
}

# Non-expiring passwords (skip Entra cloud accounts as they are not local)
$neverExpire = Get-LocalUser | Where-Object { $_.PasswordExpires -eq $null -and $_.Enabled -eq $true -and $_.PasswordRequired -eq $true }
if ($neverExpire) {
    Add-Result "4.5" "No Accounts With Non-Expiring Password" "WARN" "Non-expiring local accounts: $(($neverExpire.Name) -join ', ')"
} else {
    Add-Result "4.5" "No Accounts With Non-Expiring Password" "PASS" "No enabled local accounts have non-expiring passwords"
}

# Deny log on locally / RDP for Guests
$denyLocal = Get-SecEditValue "SeDenyInteractiveLogonRight"
$s = if ($denyLocal -and $denyLocal -match "Guest") { "PASS" } else { "FAIL" }
Add-Result "4.6" "Deny Guests Local Logon" $s "Value: $denyLocal"

$denyRDP = Get-SecEditValue "SeDenyRemoteInteractiveLogonRight"
$s = if ($denyRDP -and $denyRDP -match "Guest") { "PASS" } else { "FAIL" }
Add-Result "4.7" "Deny Guests RDP Logon" $s "Value: $denyRDP"

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
$entraCount    = ($Results | Where-Object { $_.Framework -eq "EntraID" }).Count
$cisL1Count    = ($Results | Where-Object { $_.Framework -eq "CIS" }).Count
$cisL2Count    = ($Results | Where-Object { $_.Framework -eq "CIS-L2" }).Count
$ceCount       = ($Results | Where-Object { $_.Framework -match "CE" }).Count
$scoreable     = $totalChecks - $infoCount
$score         = if ($scoreable -gt 0) { [math]::Round(($passCount / $scoreable) * 100, 1) } else { 0 }
$l2Score       = if ($cisL2Count -gt 0) {
    $l2Pass = ($Results | Where-Object { $_.Framework -eq "CIS-L2" -and $_.Status -eq "PASS" }).Count
    [math]::Round(($l2Pass / $cisL2Count) * 100, 1)
} else { 0 }

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
    "  CIS Level 1 Checks    : $cisL1Count",
    "  CIS Level 2 Checks    : $cisL2Count",
    "  Entra/M365 Checks     : $entraCount",
    "  CE/CE+ Checks         : $ceCount",
    "  -----------------------------------------------------------------------",
    "  Overall Compliance    : $score%",
    "  CIS L2 Compliance     : $l2Score%",
    "========================================================================",
    "  Device Context:",
    "  Join Type        : $joinType",
    "  Tenant           : $($Script:TenantName) ($($Script:TenantID))",
    "  MDM Enrolled     : $($Script:MDMEnrolled) $(if ($Script:MDMUrl) {"($($Script:MDMUrl))"} else {''})",
    "  PRT Present      : $($Script:PRTPresent)",
    "  Device ID        : $($Script:DeviceID)",
    "========================================================================",
    "  Sections Audited:",
    "   1.  Password Policy                (CIS L1 | CE2 | Entra-aware)",
    "   2.  Account Lockout                (CIS L1 | CE2 | Smart Lockout-aware)",
    "   3.  Remote Desktop                 (CIS L1 | CE1 | CE+)",
    "   4.  Local Accounts                 (CIS L1 | CE3 | CE+)",
    "   5.  Windows Firewall               (CIS L1 | CE1 | CE+)",
    "   6.  Patch Management               (CIS L1 | CE5 | CE+ | WUfB)",
    "   7.  SMBv1 Protocol                 (CIS L1 | CE2)",
    "   8.  AutoRun / AutoPlay             (CIS L1)",
    "   9.  Insecure Services              (CIS L1 | CE2)",
    "  10.  Admin Shares                   (CIS L1)",
    "  11.  User Account Control           (CIS L1 | CE3)",
    "  12.  Security Protocols             (CIS L1 | CE2 | NTLM-aware)",
    "  13.  Audit Policy                   (CIS L1 17.x)",
    "  14.  Malware Protection             (CIS L1 | CE4 | CE+)",
    "  15.  BitLocker / Encryption         (CIS L1 | CE2 | Entra Key Backup)",
    "  16.  Secure Boot & UEFI             (CIS L1 | CE+)",
    "  17.  PowerShell Security            (CIS L1 | CE+)",
    "  18.  Application Control            (CIS L1 | CE2 | CE+)",
    "  19.  Event Log Configuration        (CIS L1 18.x)",
    "  20.  Credential Protection          (CIS L1 | CE+ | PRT-aware)",
    "  21.  Screen Lock / Session          (CIS L1 | CE2)",
    "  22.  Unnecessary Features           (CE2 | CE+)",
    "  23.  Network Security               (CIS L1 | CE1 | CE2 | IPv6-aware)",
    "  24.  Memory & Exploit Protection    (CIS L1)",
    "  25.  CE Secure Configuration        (CE2 | CE+)",
    "  26.  Cyber Essentials Plus          (CE+)",
    "  27.  Entra ID Device Identity       (EntraID | CE+)",
    "  28.  Intune / MDM Enrolment         (EntraID | CE+)",
    "  29.  Windows Hello for Business     (EntraID | CE+)",
    "  30.  Defender for Endpoint (MDE)    (EntraID | CE+)",
    "  31.  Microsoft 365 / Office Sec     (EntraID | CE+)",
    "  32.  Conditional Access & Compliance(EntraID | CE+)",
    "  33.  CIS L2 User Rights Assignment  (CIS L2)",
    "  34.  CIS L2 Additional Sec Options  (CIS L2)",
    "  35.  CIS L2 Advanced Audit Policy   (CIS L2 17.x)",
    "  36.  TLS/SSL & Cipher Hardening     (CIS L2 | CE+)",
    "  37.  Microsoft Edge Security        (CIS L2 | CE+)",
    "  38.  Peripheral & Device Control    (CIS L2 | CE+)",
    "  39.  Windows Components & Privacy   (CIS L2)",
    "  40.  Remote Assistance & Tools      (CIS L2)",
    "  41.  DNS Client & Name Resolution   (CIS L2)",
    "  42.  Scheduled Tasks Security       (CIS L2)",
    "  43.  MSS Legacy Security Settings   (CIS L2)",
    "  44.  CIS L2 Network Protocol Hard.  (CIS L2)",
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
