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
$ScriptVersion = "3.0.0"
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
        "  CIS Level 1  |  Cyber Essentials  |  Cyber Essentials Plus",
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
        $prtDate  = [datetime]::ParseExact($prtUpdate, "M/d/yyyy H:mm:ss AM", $null, [System.Globalization.DateTimeStyles]::None) -ErrorAction SilentlyContinue
        $prtDays  = if ($prtDate) { ((Get-Date) - $prtDate).Days } else { $null }
        $s = if ($null -eq $prtDays -or $prtDays -le 4) { "PASS" } elseif ($prtDays -le 14) { "WARN" } else { "FAIL" }
        Add-Result "27.6" "PRT Last Updated" $s "Last update: $prtUpdate ($prtDays days ago) - PRT should refresh every 4 days" "EntraID"
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
        $dns = [System.Net.Dns]::GetHostAddresses($ep.Host) -ErrorAction Stop
        $s   = if ($dns) { "PASS" } else { "FAIL" }
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
$scoreable     = $totalChecks - $infoCount
$score         = if ($scoreable -gt 0) { [math]::Round(($passCount / $scoreable) * 100, 1) } else { 0 }

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
    "  Entra/M365 Checks     : $entraCount",
    "  Compliance Score      : $score% (PASS / scoreable checks)",
    "========================================================================",
    "  Device Context:",
    "  Join Type        : $joinType",
    "  Tenant           : $($Script:TenantName) ($($Script:TenantID))",
    "  MDM Enrolled     : $($Script:MDMEnrolled) $(if ($Script:MDMUrl) {"($($Script:MDMUrl))"} else {''})",
    "  PRT Present      : $($Script:PRTPresent)",
    "  Device ID        : $($Script:DeviceID)",
    "========================================================================",
    "  Sections Audited:",
    "   1.  Password Policy                (CIS 1.1 | CE2 | Entra-aware)",
    "   2.  Account Lockout                (CIS 1.2 | CE2 | Smart Lockout-aware)",
    "   3.  Remote Desktop                 (CIS | CE1 | CE+)",
    "   4.  Local Accounts                 (CIS | CE3 | CE+)",
    "   5.  Windows Firewall               (CIS | CE1 | CE+)",
    "   6.  Patch Management               (CIS | CE5 | CE+ | WUfB)",
    "   7.  SMBv1 Protocol                 (CIS | CE2)",
    "   8.  AutoRun / AutoPlay             (CIS)",
    "   9.  Insecure Services              (CIS | CE2)",
    "  10.  Admin Shares                   (CIS)",
    "  11.  User Account Control           (CIS | CE3)",
    "  12.  Security Protocols             (CIS | CE2 | NTLM-aware)",
    "  13.  Audit Policy                   (CIS 17.x)",
    "  14.  Malware Protection             (CIS | CE4 | CE+)",
    "  15.  BitLocker / Encryption         (CIS | CE2 | Entra Key Backup)",
    "  16.  Secure Boot & UEFI             (CIS | CE+)",
    "  17.  PowerShell Security            (CIS | CE+)",
    "  18.  Application Control            (CIS | CE2 | CE+)",
    "  19.  Event Log Configuration        (CIS 18.x)",
    "  20.  Credential Protection          (CIS | CE+ | PRT-aware)",
    "  21.  Screen Lock / Session          (CIS | CE2)",
    "  22.  Unnecessary Features           (CE2 | CE+)",
    "  23.  Network Security               (CIS | CE1 | CE2 | IPv6-aware)",
    "  24.  Memory & Exploit Protection    (CIS)",
    "  25.  CE Secure Configuration        (CE2 | CE+)",
    "  26.  Cyber Essentials Plus          (CE+)",
    "  27.  Entra ID Device Identity       (EntraID | CE+)",
    "  28.  Intune / MDM Enrolment         (EntraID | CE+)",
    "  29.  Windows Hello for Business     (EntraID | CE+)",
    "  30.  Defender for Endpoint (MDE)    (EntraID | CE+)",
    "  31.  Microsoft 365 / Office Sec     (EntraID | CE+)",
    "  32.  Conditional Access & Compliance(EntraID | CE+)",
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
