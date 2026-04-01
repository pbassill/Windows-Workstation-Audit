#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Level 1 + Cyber Essentials + Cyber Essentials Plus Auditor
    Author: Peter Bassill. | OTY Heavy Industries
.DESCRIPTION
    Comprehensive local Windows 10/11 audit covering:
      - CIS Microsoft Windows Benchmark Level 1 (~90 controls)
      - Cyber Essentials (CE) controls
      - Cyber Essentials Plus (CE+) additional controls
    Outputs colour-coded console results and a plain-text report to the Desktop.
.NOTES
    Must be run as Administrator.
    Tested on Windows 10/11 22H2+.
#>

# ============================================================
#  INITIALISATION
# ============================================================
$ScriptVersion = "2.0.0"
$Timestamp     = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportPath    = "$env:USERPROFILE\Desktop\OTY_Heavy_Industries_Audit_$Timestamp.txt"
$SecCfg        = "$env:TEMP\oty_secedit_$Timestamp.cfg"
$Results       = [System.Collections.Generic.List[PSCustomObject]]::new()

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
        "  Version $ScriptVersion",
        "========================================================================",
        "  Hostname  : $env:COMPUTERNAME",
        "  User      : $env:USERNAME",
        "  Date/Time : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss') UTC",
        "  OS        : $os (Build $build)",
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
        [ValidateSet("PASS","FAIL","WARN")]
        [string]$Status,
        [string]$Detail = "",
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
        "PASS" { "Green"  }
        "FAIL" { "Red"    }
        "WARN" { "Yellow" }
    }
    $line = "  [{0}] {1,-46} {2}" -f $Status, $Description, $Detail
    Write-Host $line -ForegroundColor $colour
    Add-Content -Path $ReportPath -Value $line
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

# ============================================================
#  EXPORT SECURITY POLICY ONCE
# ============================================================
Write-Host "  [*] Exporting security policy..." -ForegroundColor DarkGray
secedit /export /cfg $SecCfg /quiet 2>$null
Write-Banner

# ============================================================
#  SECTION 1: PASSWORD POLICY  [CIS 1.1 | CE2]
# ============================================================
Write-SectionHeader "1. PASSWORD POLICY" "CIS 1.1 | CE2"

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

# ============================================================
#  SECTION 2: ACCOUNT LOCKOUT  [CIS 1.2 | CE2]
# ============================================================
Write-SectionHeader "2. ACCOUNT LOCKOUT POLICY" "CIS 1.2 | CE2"

$lockoutCount    = Get-SecEditValue "LockoutBadCount"
$lockoutDuration = Get-SecEditValue "LockoutDuration"
$resetCount      = Get-SecEditValue "ResetLockoutCount"

$s = if ([int]$lockoutCount -ge 1 -and [int]$lockoutCount -le 5) { "PASS" } else { "FAIL" }
Add-Result "2.1" "Lockout Threshold" $s "Required 1-5 attempts, Got: $lockoutCount"

$s = if ([int]$lockoutDuration -ge 15) { "PASS" } else { "FAIL" }
Add-Result "2.2" "Lockout Duration" $s "Required >=15 mins, Got: $lockoutDuration mins"

$s = if ([int]$resetCount -ge 15) { "PASS" } else { "FAIL" }
Add-Result "2.3" "Reset Lockout Counter" $s "Required >=15 mins, Got: $resetCount mins"

# ============================================================
#  SECTION 3: REMOTE DESKTOP  [CIS | CE1 | CE+]
# ============================================================
Write-SectionHeader "3. REMOTE DESKTOP (RDP)" "CIS | CE1 | CE+"

$deny = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
$nla  = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"

if ($deny -eq 1) {
    Add-Result "3.1" "RDP Status" "PASS" "RDP is disabled"
    Add-Result "3.2" "RDP: NLA Required" "PASS" "N/A - RDP is disabled"
} else {
    Add-Result "3.1" "RDP Status" "FAIL" "RDP is enabled - ensure this is intentional"
    $s = if ($nla -eq 1) { "PASS" } else { "FAIL" }
    Add-Result "3.2" "RDP: NLA Required" $s "Required: Enabled, Got: $(if ($nla -eq 1) {'Enabled'} else {'Disabled'})"
}

# RDP encryption level
$encLevel = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel"
$s = if ($encLevel -ge 3 -or $deny -eq 1) { "PASS" } else { "FAIL" }
Add-Result "3.3" "RDP: Minimum Encryption Level" $s "Required >=3 (High), Got: $encLevel"

# ============================================================
#  SECTION 4: LOCAL ACCOUNTS  [CIS | CE3 | CE+]
# ============================================================
Write-SectionHeader "4. LOCAL ACCOUNTS" "CIS | CE3 | CE+"

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
    $names = ($noPasswd.Name) -join ", "
    Add-Result "4.2" "No Accounts Without Password" "FAIL" "Accounts with no password: $names"
} else {
    Add-Result "4.2" "No Accounts Without Password" "PASS" "All enabled accounts require a password"
}

# Number of local administrator accounts (CE - should be minimal)
$adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$adminCount = if ($adminGroup) { $adminGroup.Count } else { 0 }
$s = if ($adminCount -le 2) { "PASS" } elseif ($adminCount -le 4) { "WARN" } else { "FAIL" }
Add-Result "4.3" "Local Admin Account Count" $s "Recommended <=2, Found: $adminCount ($(($adminGroup.Name) -join ', '))"

# Default Administrator account renamed (CE2)
$adminUser = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-500" } -ErrorAction SilentlyContinue
if ($adminUser) {
    $s = if ($adminUser.Name -ne "Administrator") { "PASS" } else { "WARN" }
    Add-Result "4.4" "Built-in Admin Account Renamed" $s "Account name: $($adminUser.Name)"
} else {
    Add-Result "4.4" "Built-in Admin Account Renamed" "WARN" "Could not determine built-in admin account"
}

# Accounts with password never expires
$neverExpire = Get-LocalUser | Where-Object { $_.PasswordExpires -eq $null -and $_.Enabled -eq $true -and $_.PasswordRequired -eq $true }
if ($neverExpire) {
    $names = ($neverExpire.Name) -join ", "
    Add-Result "4.5" "No Accounts With Non-Expiring Password" "WARN" "Non-expiring: $names"
} else {
    Add-Result "4.5" "No Accounts With Non-Expiring Password" "PASS" "No enabled accounts have non-expiring passwords"
}

# Deny log on locally for Guests (secedit)
$denyLocal = Get-SecEditValue "SeDenyInteractiveLogonRight"
$s = if ($denyLocal -and $denyLocal -match "Guest") { "PASS" } else { "FAIL" }
Add-Result "4.6" "Deny Guests Local Logon" $s "Value: $denyLocal"

# Deny Guests RDP logon
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
    } else {
        Add-Result "5.$($profile[0])" "Firewall Profile: $profile" "WARN" "Could not retrieve profile"
    }
}

# Log dropped packets (CE+)
foreach ($profile in @("Domain","Private","Public")) {
    $fw = $fwProfiles | Where-Object { $_.Name -eq $profile }
    if ($fw) {
        $s = if ($fw.LogBlocked -eq $true) { "PASS" } else { "WARN" }
        Add-Result "5.L$($profile[0])" "Firewall Log Dropped Packets: $profile" $s "LogBlocked: $($fw.LogBlocked)"
    }
}

# ============================================================
#  SECTION 6: WINDOWS UPDATE / PATCH MANAGEMENT  [CIS | CE5 | CE+]
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
Add-Result "6.2" "Auto Updates Not Disabled" $s "Registry NoAutoUpdate: $(if ($null -eq $noAutoUpdate) {'Not set (default enabled)'} else {$noAutoUpdate})"

# Last installed update recency (CE5 - should be within 14 days for critical)
$lastUpdate = (Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
if ($lastUpdate) {
    $daysSince = ((Get-Date) - $lastUpdate).Days
    $s = if ($daysSince -le 30) { "PASS" } elseif ($daysSince -le 60) { "WARN" } else { "FAIL" }
    Add-Result "6.3" "Last Patch Installed" $s "Installed: $($lastUpdate.ToString('dd/MM/yyyy')) ($daysSince days ago)"
} else {
    Add-Result "6.3" "Last Patch Installed" "WARN" "Could not determine last patch date"
}

# Pending reboot (indicates update not fully applied)
$pendingReboot = $false
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $pendingReboot = $true }
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" ) {
    $prnReg = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "PendingFileRenameOperations"
    if ($prnReg) { $pendingReboot = $true }
}
$s = if (-not $pendingReboot) { "PASS" } else { "WARN" }
Add-Result "6.4" "No Pending Reboot for Updates" $s "Pending reboot: $pendingReboot"

# ============================================================
#  SECTION 7: SMBv1  [CIS | CE2]
# ============================================================
Write-SectionHeader "7. SMBv1 PROTOCOL" "CIS | CE2"

try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
    $s    = if ($smb1.State -eq "Disabled") { "PASS" } else { "FAIL" }
    Add-Result "7.1" "SMBv1 Disabled" $s "Feature state: $($smb1.State)"
} catch {
    $smb1Reg = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
    if ($smb1Reg -eq 0) {
        Add-Result "7.1" "SMBv1 Disabled" "PASS" "Registry explicitly set to 0 (disabled)"
    } else {
        Add-Result "7.1" "SMBv1 Disabled" "WARN" "Could not verify via feature or registry"
    }
}

# SMB signing required (CE+)
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
    @{ Name = "TlntSvr";        Label = "Telnet"                }
    @{ Name = "MSFTPSVC";       Label = "FTP Publishing"        }
    @{ Name = "RemoteRegistry"; Label = "Remote Registry"       }
    @{ Name = "SNMP";           Label = "SNMP"                  }
    @{ Name = "WinRM";          Label = "Windows Remote Mgmt"   }
    @{ Name = "XblGameSave";    Label = "Xbox Game Save"        }
    @{ Name = "XboxNetApiSvc";  Label = "Xbox Live Networking"  }
    @{ Name = "irmon";          Label = "Infrared Monitor"      }
    @{ Name = "SharedAccess";   Label = "ICS (Internet Sharing)"}
    @{ Name = "simptcp";        Label = "Simple TCP/IP Services"}
    @{ Name = "upnphost";       Label = "UPnP Device Host"      }
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

$wdigest  = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
$s = if ($wdigest -eq 0) { "PASS" } else { "FAIL" }
Add-Result "12.1" "WDigest Plain-Text Creds Disabled" $s "Required: 0, Got: $wdigest"

$lmLevel  = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
$s = if ($lmLevel -eq 5) { "PASS" } else { "FAIL" }
Add-Result "12.2" "LAN Manager Auth Level (NTLMv2 only)" $s "Required: 5, Got: $lmLevel"

$llmnr = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
$s = if ($llmnr -eq 0) { "PASS" } else { "FAIL" }
Add-Result "12.3" "LLMNR Disabled" $s "Required: 0, Got: $llmnr"

$anonSAM  = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
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

# No null sessions
$nullSessions = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionShares"
$s = if ($null -eq $nullSessions -or $nullSessions -eq "") { "PASS" } else { "FAIL" }
Add-Result "12.9" "No Null Session Shares" $s "Value: $(if ($null -eq $nullSessions) {'Not set (secure)'} else {$nullSessions})"

# ============================================================
#  SECTION 13: AUDIT POLICY  [CIS 17.x]
# ============================================================
Write-SectionHeader "13. AUDIT POLICY" "CIS 17.x"

$auditChecks = @(
    @{ ID = "13.1";  Sub = "Credential Validation";         Exp = "Success and Failure" }
    @{ ID = "13.2";  Sub = "Kerberos Authentication Service"; Exp = "Failure" }
    @{ ID = "13.3";  Sub = "Account Lockout";               Exp = "Failure" }
    @{ ID = "13.4";  Sub = "Logon";                         Exp = "Success and Failure" }
    @{ ID = "13.5";  Sub = "Special Logon";                 Exp = "Success" }
    @{ ID = "13.6";  Sub = "Account Management";            Exp = "Success and Failure" }
    @{ ID = "13.7";  Sub = "Security Group Management";     Exp = "Success and Failure" }
    @{ ID = "13.8";  Sub = "Audit Policy Change";           Exp = "Success and Failure" }
    @{ ID = "13.9";  Sub = "Authentication Policy Change";  Exp = "Success" }
    @{ ID = "13.10"; Sub = "Sensitive Privilege Use";       Exp = "Success and Failure" }
    @{ ID = "13.11"; Sub = "Security State Change";         Exp = "Success" }
    @{ ID = "13.12"; Sub = "Security System Extension";     Exp = "Success and Failure" }
    @{ ID = "13.13"; Sub = "System Integrity";              Exp = "Success and Failure" }
    @{ ID = "13.14"; Sub = "Process Creation";              Exp = "Success" }
    @{ ID = "13.15"; Sub = "File System";                   Exp = "Failure" }
    @{ ID = "13.16"; Sub = "Other Object Access Events";    Exp = "Failure" }
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
#  SECTION 14: WINDOWS DEFENDER / MALWARE PROTECTION  [CIS | CE4 | CE+]
# ============================================================
Write-SectionHeader "14. MALWARE PROTECTION (DEFENDER)" "CIS | CE4 | CE+"

# Real-time protection
$rtpDisabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring"
$s = if ($rtpDisabled -ne 1) { "PASS" } else { "FAIL" }
Add-Result "14.1" "Defender Real-Time Protection Enabled" $s "DisableRealtimeMonitoring: $(if ($null -eq $rtpDisabled) {'Not set (enabled)'} else {$rtpDisabled})"

# Tamper protection (CE+)
$tamper = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" "TamperProtection"
$s = if ($tamper -eq 5) { "PASS" } elseif ($tamper -eq $null) { "WARN" } else { "FAIL" }
Add-Result "14.2" "Defender Tamper Protection Enabled" $s "Required: 5 (enabled), Got: $tamper"

# Cloud-delivered protection (CE4)
$cloudProtection = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SpynetReporting"
$s = if ($cloudProtection -ge 2 -or $null -eq $cloudProtection) { "PASS" } else { "WARN" }
Add-Result "14.3" "Defender Cloud Protection Enabled" $s "SpynetReporting: $(if ($null -eq $cloudProtection) {'Default (enabled)'} else {$cloudProtection})"

# Defender definition age (CE4 - CE5 requires updates within 14 days)
try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    $defAge   = ((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days
    $s = if ($defAge -le 1) { "PASS" } elseif ($defAge -le 7) { "WARN" } else { "FAIL" }
    Add-Result "14.4" "Defender Definition Age" $s "Last updated: $($defender.AntivirusSignatureLastUpdated.ToString('dd/MM/yyyy')) ($defAge days ago)"

    # Defender enabled and up to date
    $s = if ($defender.AntivirusEnabled) { "PASS" } else { "FAIL" }
    Add-Result "14.5" "Defender Antivirus Enabled" $s "AntivirusEnabled: $($defender.AntivirusEnabled)"

    # Behaviour monitoring
    $s = if ($defender.BehaviorMonitorEnabled) { "PASS" } else { "FAIL" }
    Add-Result "14.6" "Defender Behaviour Monitoring" $s "BehaviorMonitorEnabled: $($defender.BehaviorMonitorEnabled)"

    # Network protection (CE+)
    $s = if ($defender.IsTamperProtected) { "PASS" } else { "WARN" }
    Add-Result "14.7" "Defender Tamper Protection Active" $s "IsTamperProtected: $($defender.IsTamperProtected)"

} catch {
    Add-Result "14.4" "Defender Definition Age" "WARN" "Could not query Get-MpComputerStatus"
    Add-Result "14.5" "Defender Antivirus Enabled" "WARN" "Could not query Get-MpComputerStatus"
}

# IOAV (network-downloaded file scanning)
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
        $isOS     = $vol.VolumeType -eq "OperatingSystem"
        $priority = if ($isOS) { "OS Drive" } else { "Data Drive" }
        $s = if ($vol.ProtectionStatus -eq "On") { "PASS" } elseif ($isOS) { "FAIL" } else { "WARN" }
        Add-Result "15.$($vol.MountPoint.Replace(':',''))" "BitLocker: $($vol.MountPoint) ($priority)" $s "Status: $($vol.ProtectionStatus), Encryption: $($vol.VolumeStatus), Method: $($vol.EncryptionMethod)"
    }
    if ($blVolumes.Count -eq 0) {
        Add-Result "15.0" "BitLocker Volumes" "WARN" "No BitLocker volumes found"
    }
} catch {
    Add-Result "15.0" "BitLocker Status" "WARN" "Could not query BitLocker (module may be unavailable on Home)"
}

# BitLocker TPM requirement
$blTPM = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "UseTPM"
$s = if ($blTPM -eq $null -or $blTPM -ge 1) { "PASS" } else { "FAIL" }
Add-Result "15.A" "BitLocker Requires TPM or Startup Key" $s "UseTPM policy: $(if ($null -eq $blTPM) {'Default'} else {$blTPM})"

# ============================================================
#  SECTION 16: SECURE BOOT & UEFI  [CIS | CE+]
# ============================================================
Write-SectionHeader "16. SECURE BOOT & UEFI" "CIS | CE+"

# Secure Boot
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    $s = if ($secureBoot) { "PASS" } else { "FAIL" }
    Add-Result "16.1" "Secure Boot Enabled" $s "Secure Boot: $secureBoot"
} catch {
    Add-Result "16.1" "Secure Boot Enabled" "WARN" "Could not query Secure Boot (may be Legacy BIOS)"
}

# BIOS mode (UEFI vs Legacy)
$biosMode = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).PCSystemType
$uefiPath  = Test-Path "$env:SystemRoot\Panther\setupact.log"
$bcdout    = bcdedit /enum "{current}" 2>$null | Where-Object { $_ -match "path" }
$isUEFI    = ($bcdout -join "") -match "\\EFI\\"
$s = if ($isUEFI) { "PASS" } else { "WARN" }
Add-Result "16.2" "UEFI Boot Mode" $s "EFI boot path detected: $isUEFI"

# Test signing off
$testSign = bcdedit /enum "{current}" 2>$null | Where-Object { $_ -match "testsigning" }
$s = if (-not $testSign -or ($testSign -join "") -match "No") { "PASS" } else { "FAIL" }
Add-Result "16.3" "Test Signing Disabled" $s "Test mode: $(if (-not $testSign) {'Not set (Off)'} else {$testSign})"

# ============================================================
#  SECTION 17: POWERSHELL SECURITY  [CIS | CE+]
# ============================================================
Write-SectionHeader "17. POWERSHELL SECURITY" "CIS | CE+"

# Script Block Logging (CE+)
$sblEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
$s = if ($sblEnabled -eq 1) { "PASS" } else { "FAIL" }
Add-Result "17.1" "PowerShell Script Block Logging" $s "Required: 1, Got: $sblEnabled"

# Module Logging
$mlEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging"
$s = if ($mlEnabled -eq 1) { "PASS" } else { "FAIL" }
Add-Result "17.2" "PowerShell Module Logging" $s "Required: 1, Got: $mlEnabled"

# Transcription (CE+)
$txEnabled = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
$s = if ($txEnabled -eq 1) { "PASS" } else { "WARN" }
Add-Result "17.3" "PowerShell Transcription Enabled" $s "Required: 1, Got: $txEnabled"

# Execution policy (machine-level should not be Unrestricted or Bypass)
$execPolicy = Get-ExecutionPolicy -Scope LocalMachine
$s = if ($execPolicy -in @("RemoteSigned","AllSigned","Restricted")) { "PASS" } else { "FAIL" }
Add-Result "17.4" "PowerShell Execution Policy (Machine)" $s "Required: RemoteSigned/AllSigned/Restricted, Got: $execPolicy"

# PowerShell v2 disabled (CE+ - v2 bypasses logging)
try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction Stop
    $s    = if ($psv2.State -eq "Disabled") { "PASS" } else { "FAIL" }
    Add-Result "17.5" "PowerShell v2 Feature Disabled" $s "State: $($psv2.State)"
} catch {
    Add-Result "17.5" "PowerShell v2 Feature Disabled" "WARN" "Could not query feature state"
}

# Constrained Language Mode indicator (CE+)
$clm = [System.Management.Automation.LanguageMode] "ConstrainedLanguage"
$currentMode = $ExecutionContext.SessionState.LanguageMode
$s = if ($currentMode -eq "ConstrainedLanguage") { "PASS" } else { "WARN" }
Add-Result "17.6" "PowerShell Constrained Language Mode" $s "Current session mode: $currentMode"

# ============================================================
#  SECTION 18: APPLICATION CONTROL  [CIS | CE2 | CE+]
# ============================================================
Write-SectionHeader "18. APPLICATION CONTROL" "CIS | CE2 | CE+"

# AppLocker
$alSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
if ($alSvc -and $alSvc.Status -eq "Running") {
    Add-Result "18.1" "AppLocker Service Running" "PASS" "AppIDSvc status: $($alSvc.Status)"
} else {
    Add-Result "18.1" "AppLocker Service Running" "WARN" "AppIDSvc status: $(if ($alSvc) {$alSvc.Status} else {'Not found'})"
}

# AppLocker policy exists
$alPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
if ($alPolicy -and ($alPolicy.RuleCollections | Where-Object { $_.Count -gt 0 })) {
    Add-Result "18.2" "AppLocker Policy Configured" "PASS" "Effective AppLocker rules found"
} else {
    Add-Result "18.2" "AppLocker Policy Configured" "WARN" "No effective AppLocker rules detected"
}

# WDAC (Windows Defender Application Control)
$wdacBase = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
$wdacEnabled = Test-Path $wdacBase
$s = if ($wdacEnabled) { "PASS" } else { "WARN" }
Add-Result "18.3" "WDAC Policy Present" $s "WDAC registry path exists: $wdacEnabled"

# Attack Surface Reduction (ASR) - key rules (CE+)
$asrRules = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules"
$s = if ($asrRules -eq 1) { "PASS" } else { "WARN" }
Add-Result "18.4" "Attack Surface Reduction Rules Enabled" $s "ExploitGuard_ASR_Rules: $asrRules"

# Windows Script Host (CE2)
$wsh = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" "Enabled"
$s = if ($wsh -eq 0) { "PASS" } else { "WARN" }
Add-Result "18.5" "Windows Script Host Disabled" $s "Enabled: $(if ($null -eq $wsh) {'Not set (enabled)'} else {$wsh})"

# ============================================================
#  SECTION 19: EVENT LOG CONFIGURATION  [CIS 18.x]
# ============================================================
Write-SectionHeader "19. EVENT LOG CONFIGURATION" "CIS 18.x"

$logChecks = @(
    @{ Name = "Security";    Min = 196608; Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security";    Reg = "MaxSize" }
    @{ Name = "System";      Min = 32768;  Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System";      Reg = "MaxSize" }
    @{ Name = "Application"; Min = 32768;  Path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application"; Reg = "MaxSize" }
)

foreach ($log in $logChecks) {
    # Try WinEvent first, fall back to registry
    try {
        $wLog = Get-WinEvent -ListLog $log.Name -ErrorAction Stop
        $kb   = [math]::Round($wLog.MaximumSizeInBytes / 1KB)
        $s    = if ($wLog.MaximumSizeInBytes -ge $log.Min) { "PASS" } else { "FAIL" }
        Add-Result "19.$($log.Name[0])" "$($log.Name) Log Max Size" $s "Required >=$([math]::Round($log.Min/1KB))KB, Got: ${kb}KB"

        # Retention policy should not be "Overwrite as needed" without a size cap
        $retention = $wLog.LogMode
        $s = if ($retention -ne "Circular" -or $wLog.MaximumSizeInBytes -ge $log.Min) { "PASS" } else { "WARN" }
        Add-Result "19.$($log.Name[0])r" "$($log.Name) Log Retention" $s "Mode: $retention"
    } catch {
        $size = Get-RegValue $log.Path $log.Reg
        $s    = if ($size -and $size -ge $log.Min) { "PASS" } else { "FAIL" }
        Add-Result "19.$($log.Name[0])" "$($log.Name) Log Max Size" $s "Required >=$([math]::Round($log.Min/1KB))KB, Registry: $size"
    }
}

# ============================================================
#  SECTION 20: CREDENTIAL PROTECTION  [CIS | CE+]
# ============================================================
Write-SectionHeader "20. CREDENTIAL PROTECTION" "CIS | CE+"

# Credential Guard (VBS)
$vbs = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
$s = if ($vbs -eq 1) { "PASS" } else { "WARN" }
Add-Result "20.1" "Virtualization-Based Security (Credential Guard)" $s "Required: 1, Got: $vbs"

$cgEnabled = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "LsaCfgFlags"
$s = if ($cgEnabled -ge 1) { "PASS" } else { "WARN" }
Add-Result "20.2" "Credential Guard Configured" $s "LsaCfgFlags: $cgEnabled (1=UEFI lock, 2=enabled)"

# LSASS Protected Process Light (PPL)
$lsaPPL = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
$s = if ($lsaPPL -eq 1) { "PASS" } else { "WARN" }
Add-Result "20.3" "LSASS Protected Process (PPL)" $s "Required: 1, Got: $lsaPPL"

# Cached credentials limit (CE+)
$cachedLogons = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount"
$cachedCount  = if ($cachedLogons) { [int]$cachedLogons } else { 10 }
$s = if ($cachedCount -le 1) { "PASS" } elseif ($cachedCount -le 4) { "WARN" } else { "FAIL" }
Add-Result "20.4" "Cached Credentials Count" $s "Recommended <=1, Got: $cachedCount"

# Prohibit password caching (via secedit)
$passCache = Get-SecEditValue "DisableDomainCreds"
$s = if ($passCache -eq "1") { "PASS" } else { "WARN" }
Add-Result "20.5" "Network Password Caching Disabled" $s "DisableDomainCreds: $passCache"

# ============================================================
#  SECTION 21: SCREEN LOCK / SESSION  [CIS | CE2]
# ============================================================
Write-SectionHeader "21. SCREEN LOCK / SESSION SECURITY" "CIS | CE2"

# Inactivity timeout
$inactTimeout = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
$s = if ($null -ne $inactTimeout -and [int]$inactTimeout -le 900 -and [int]$inactTimeout -ge 1) { "PASS" } else { "FAIL" }
Add-Result "21.1" "Screen Lock Inactivity Timeout" $s "Required 1-900s, Got: $inactTimeout"

# Screensaver enabled and password-protected
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

# Legal notice (logon banner - CE2)
$legalText    = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText"
$legalCaption = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption"
$s = if ($legalText -and $legalCaption) { "PASS" } else { "FAIL" }
Add-Result "21.5" "Logon Legal Notice (Banner) Configured" $s "Text: $(if ($legalText) {'Set'} else {'Not set'}), Caption: $(if ($legalCaption) {'Set'} else {'Not set'})"

# ============================================================
#  SECTION 22: UNNECESSARY WINDOWS FEATURES  [CE2 | CE+]
# ============================================================
Write-SectionHeader "22. UNNECESSARY WINDOWS FEATURES" "CE2 | CE+"

$features = @(
    @{ Name = "SMB1Protocol";                    Label = "SMBv1 Protocol"                  }
    @{ Name = "MicrosoftWindowsPowerShellV2Root";Label = "PowerShell v2"                   }
    @{ Name = "TelnetClient";                    Label = "Telnet Client"                   }
    @{ Name = "TFTP";                            Label = "TFTP Client"                     }
    @{ Name = "Internet-Explorer-Optional-amd64";Label = "Internet Explorer"               }
    @{ Name = "WorkFolders-Client";              Label = "Work Folders Client"             }
)

foreach ($feat in $features) {
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $feat.Name -ErrorAction Stop
        $s = if ($f.State -eq "Disabled") { "PASS" } elseif ($f.State -eq "DisabledWithPayloadRemoved") { "PASS" } else { "WARN" }
        Add-Result "22.x" "$($feat.Label) Feature Removed" $s "State: $($f.State)"
    } catch {
        Add-Result "22.x" "$($feat.Label) Feature" "PASS" "Feature not found (not installed)"
    }
}

# Check for IIS (should be absent on workstations)
$iis = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
$s = if ($null -eq $iis) { "PASS" } elseif ($iis.Status -ne "Running") { "WARN" } else { "FAIL" }
Add-Result "22.IIS" "IIS Web Server Not Running" $s "Status: $(if ($iis) {$iis.Status} else {'Not installed'})"

# ============================================================
#  SECTION 23: NETWORK SECURITY  [CIS | CE1 | CE2]
# ============================================================
Write-SectionHeader "23. NETWORK SECURITY" "CIS | CE1 | CE2"

# NetBIOS over TCP/IP
$adapters        = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
$netbiosEnabled  = $adapters | Where-Object { $_.TcpipNetbiosOptions -eq 0 }
$s = if (-not $netbiosEnabled) { "PASS" } else { "FAIL" }
Add-Result "23.1" "NetBIOS over TCP/IP Not Forced On" $s "Adapters with NetBIOS forced on: $($netbiosEnabled.Count)"

# IPv6 (should be configured or disabled if not in use - CE advisory)
$ipv6Disabled = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents"
$s = if ($null -ne $ipv6Disabled -and $ipv6Disabled -ge 255) { "WARN" } else { "PASS" }
Add-Result "23.2" "IPv6 Configuration" $s "DisabledComponents: $(if ($null -eq $ipv6Disabled) {'Not set (IPv6 active)'} else {$ipv6Disabled}) - Review if not in use"

# mDNS (can be exploited for poisoning)
$mDNS = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMDNS"
$s = if ($mDNS -eq 0) { "PASS" } else { "WARN" }
Add-Result "23.3" "mDNS Disabled" $s "EnableMDNS: $(if ($null -eq $mDNS) {'Not set (enabled by default)'} else {$mDNS})"

# ICMPv4 redirects disabled
$icmpRedirect = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect"
$s = if ($icmpRedirect -eq 0) { "PASS" } else { "WARN" }
Add-Result "23.4" "ICMPv4 Redirects Disabled" $s "EnableICMPRedirect: $icmpRedirect"

# Source routing disabled
$srcRouting = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting"
$s = if ($srcRouting -eq 2) { "PASS" } else { "FAIL" }
Add-Result "23.5" "IP Source Routing Disabled" $s "Required: 2, Got: $srcRouting"

# TCP SYN attack protection
$synAttack = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "SynAttackProtect"
$s = if ($synAttack -eq 1) { "PASS" } else { "WARN" }
Add-Result "23.6" "TCP SYN Attack Protection" $s "SynAttackProtect: $synAttack"

# ============================================================
#  SECTION 24: DEP / SEHOP / SAFE DLL  [CIS]
# ============================================================
Write-SectionHeader "24. MEMORY & EXPLOIT PROTECTION" "CIS"

# DEP via bcdedit
$bcdOut = bcdedit /enum "{current}" 2>$null
$nx     = $bcdOut | Where-Object { $_ -match "nx\s" }
$s = if ($nx -and $nx -notmatch "AlwaysOff") { "PASS" } else { "FAIL" }
Add-Result "24.1" "Data Execution Prevention (DEP)" $s "NX setting: $(if ($nx) {($nx).Trim()} else {'Not found'})"

# SEHOP
$sehop = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation"
$s = if ($sehop -eq 0 -or $null -eq $sehop) { "PASS" } else { "FAIL" }
Add-Result "24.2" "SEHOP (Exception Chain Validation)" $s "DisableExceptionChainValidation: $(if ($null -eq $sehop) {'Not set (enabled)'} else {$sehop})"

# Safe DLL search
$safeDLL = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "SafeDllSearchMode"
$s = if ($safeDLL -eq 1 -or $null -eq $safeDLL) { "PASS" } else { "FAIL" }
Add-Result "24.3" "Safe DLL Search Mode" $s "Required: 1, Got: $(if ($null -eq $safeDLL) {'Default (1)'} else {$safeDLL})"

# Exploit protection (EMET successor)
$epEnabled = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "MitigationOptions"
$s = if ($null -ne $epEnabled) { "PASS" } else { "WARN" }
Add-Result "24.4" "Kernel Mitigation Options Set" $s "MitigationOptions: $epEnabled"

# ============================================================
#  SECTION 25: CE SECURE CONFIGURATION  [CE2 | CE+]
# ============================================================
Write-SectionHeader "25. CYBER ESSENTIALS - SECURE CONFIGURATION" "CE2 | CE+"

# Logon do not display last username
$noLastUser = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
$s = if ($noLastUser -eq 1) { "PASS" } else { "FAIL" }
Add-Result "25.1" "Do Not Display Last Username at Logon" $s "Required: 1, Got: $noLastUser"

# Disable CTRL+ALT+DEL requirement (should be 0 = require it)
$cad = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
$s = if ($cad -eq 0 -or $null -eq $cad) { "PASS" } else { "FAIL" }
Add-Result "25.2" "Require CTRL+ALT+DEL at Logon" $s "DisableCAD: $(if ($null -eq $cad) {'Default (required)'} else {$cad})"

# Restrict anonymous access to named pipes
$restrictPipes = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RestrictNullSessAccess"
$s = if ($restrictPipes -eq 1) { "PASS" } else { "FAIL" }
Add-Result "25.3" "Restrict Null Session Access" $s "Required: 1, Got: $restrictPipes"

# Remote registry restricted (should only be admins)
$remReg = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
$s = if ($null -eq $remReg -or $remReg.StartType -in @("Disabled","Manual") -and $remReg.Status -ne "Running") { "PASS" } else { "FAIL" }
Add-Result "25.4" "Remote Registry Not Running" $s "Status: $(if ($remReg) {"$($remReg.Status) / $($remReg.StartType)"} else {'Not installed'})"

# Print spooler (if not a print server, disable) - CVE-2021-1675 PrintNightmare
$spooler = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
$s = if ($null -eq $spooler -or $spooler.StartType -eq "Disabled") { "PASS" } else { "WARN" }
Add-Result "25.5" "Print Spooler (PrintNightmare Risk)" $s "Status: $(if ($spooler) {"$($spooler.Status) / $($spooler.StartType)"} else {'Not installed'}) - Disable if not a print server"

# Windows Installer elevation disabled
$msiElevate = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
$msiElevateU = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
$s = if ($msiElevate -ne 1 -and $msiElevateU -ne 1) { "PASS" } else { "FAIL" }
Add-Result "25.6" "MSI Always Install Elevated Disabled" $s "HKLM: $msiElevate, HKCU: $msiElevateU"

# Remote shell disabled
$remoteShell = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowAutoConfig"
$s = if ($remoteShell -ne 1) { "PASS" } else { "WARN" }
Add-Result "25.7" "WinRM Remote Shell Not Auto-Configured" $s "AllowAutoConfig: $remoteShell"

# ============================================================
#  SECTION 26: CE PLUS SPECIFIC  [CE+]
# ============================================================
Write-SectionHeader "26. CYBER ESSENTIALS PLUS CHECKS" "CE+"

# MFA / Windows Hello for Business indicator
$whfb = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "Enabled"
$s = if ($whfb -eq 1) { "PASS" } else { "WARN" }
Add-Result "26.1" "Windows Hello for Business / MFA Configured" $s "Passport/WHfB Policy Enabled: $whfb"

# Exploit Guard - Network protection
$netProtect = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection"
$s = if ($netProtect -eq 1) { "PASS" } else { "WARN" }
Add-Result "26.2" "Defender Network Protection Enabled" $s "EnableNetworkProtection: $netProtect (1=Block, 2=Audit)"

# Controlled Folder Access (anti-ransomware - CE+)
$cfa = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" "EnableControlledFolderAccess"
$s = if ($cfa -eq 1) { "PASS" } elseif ($cfa -eq 2) { "WARN" } else { "WARN" }
Add-Result "26.3" "Controlled Folder Access (Anti-Ransomware)" $s "EnableControlledFolderAccess: $cfa (1=Block, 2=Audit)"

# Windows Sandbox disabled (CE+ - attack surface)
$sandbox = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction SilentlyContinue
$s = if ($null -eq $sandbox -or $sandbox.State -eq "Disabled") { "PASS" } else { "WARN" }
Add-Result "26.4" "Windows Sandbox" $s "State: $(if ($sandbox) {$sandbox.State} else {'Not found/disabled'})"

# Hyper-V enabled check (CE+ may require or restrict)
$hv = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -ErrorAction SilentlyContinue
Add-Result "26.5" "Hyper-V Status" "WARN" "State: $(if ($hv) {$hv.State} else {'Not found'}) - Review if not required for VBS/CG"

# WDAC / Code Integrity policy enforced
$ciPolicy = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" "VerifiedAndReputablePolicyState"
$s = if ($null -ne $ciPolicy) { "PASS" } else { "WARN" }
Add-Result "26.6" "Code Integrity Policy Active" $s "VerifiedAndReputablePolicyState: $ciPolicy"

# Microsoft Vulnerable Driver Blocklist
$driverBlocklist = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" "VulnerableDriverBlocklistEnable"
$s = if ($driverBlocklist -eq 1 -or $null -eq $driverBlocklist) { "PASS" } else { "FAIL" }
Add-Result "26.7" "Vulnerable Driver Blocklist Enabled" $s "VulnerableDriverBlocklistEnable: $(if ($null -eq $driverBlocklist) {'Default (enabled)'} else {$driverBlocklist})"

# Early Launch Anti-Malware (ELAM)
$elam = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy"
$s = if ($elam -eq 3 -or $null -eq $elam) { "PASS" } elseif ($elam -eq 1) { "WARN" } else { "FAIL" }
Add-Result "26.8" "Early Launch Anti-Malware (ELAM)" $s "DriverLoadPolicy: $elam (3=Good+Unknown, 1=Good only, 7=All)"

# ============================================================
#  CLEAN UP
# ============================================================
if (Test-Path $SecCfg) { Remove-Item $SecCfg -Force -ErrorAction SilentlyContinue }

# ============================================================
#  SUMMARY
# ============================================================
$totalChecks = $Results.Count
$passCount   = ($Results | Where-Object { $_.Status -eq "PASS" }).Count
$failCount   = ($Results | Where-Object { $_.Status -eq "FAIL" }).Count
$warnCount   = ($Results | Where-Object { $_.Status -eq "WARN" }).Count
$score       = if ($totalChecks -gt 0) { [math]::Round(($passCount / $totalChecks) * 100, 1) } else { 0 }

$cisFail  = ($Results | Where-Object { $_.Status -eq "FAIL" -and $_.Framework -in @("CIS","")}).Count
$ceFail   = ($Results | Where-Object { $_.Status -eq "FAIL" -and $_.Framework -match "CE"  }).Count

$summaryLines = @(
    "",
    "========================================================================",
    "  AUDIT SUMMARY",
    "========================================================================",
    "  Total Checks          : $totalChecks",
    "  PASS                  : $passCount",
    "  FAIL                  : $failCount",
    "  WARN                  : $warnCount",
    "  Overall Score         : $score%",
    "========================================================================",
    "  Sections Audited:",
    "   1.  Password Policy                (CIS 1.1 | CE2)",
    "   2.  Account Lockout                (CIS 1.2 | CE2)",
    "   3.  Remote Desktop                 (CIS | CE1 | CE+)",
    "   4.  Local Accounts                 (CIS | CE3 | CE+)",
    "   5.  Windows Firewall               (CIS | CE1 | CE+)",
    "   6.  Patch Management               (CIS | CE5 | CE+)",
    "   7.  SMBv1 Protocol                 (CIS | CE2)",
    "   8.  AutoRun / AutoPlay             (CIS)",
    "   9.  Insecure Services              (CIS | CE2)",
    "  10.  Admin Shares                   (CIS)",
    "  11.  User Account Control           (CIS | CE3)",
    "  12.  Security Protocols             (CIS | CE2)",
    "  13.  Audit Policy                   (CIS 17.x)",
    "  14.  Malware Protection             (CIS | CE4 | CE+)",
    "  15.  BitLocker / Encryption         (CIS | CE2)",
    "  16.  Secure Boot & UEFI             (CIS | CE+)",
    "  17.  PowerShell Security            (CIS | CE+)",
    "  18.  Application Control            (CIS | CE2 | CE+)",
    "  19.  Event Log Configuration        (CIS 18.x)",
    "  20.  Credential Protection          (CIS | CE+)",
    "  21.  Screen Lock / Session          (CIS | CE2)",
    "  22.  Unnecessary Features           (CE2 | CE+)",
    "  23.  Network Security               (CIS | CE1 | CE2)",
    "  24.  Memory & Exploit Protection    (CIS)",
    "  25.  CE Secure Configuration        (CE2 | CE+)",
    "  26.  Cyber Essentials Plus Checks   (CE+)",
    "========================================================================"
)

foreach ($line in $summaryLines) { Write-Host $line -ForegroundColor Cyan }
$summaryLines | Add-Content -Path $ReportPath

# Failed controls list
if ($failCount -gt 0) {
    Write-Host "`n  FAILED CONTROLS:" -ForegroundColor Red
    Add-Content -Path $ReportPath -Value "`n  FAILED CONTROLS:"
    $Results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        $line = "    [$($_.ID)] $($_.Description) - $($_.Detail)"
        Write-Host $line -ForegroundColor Red
        Add-Content -Path $ReportPath -Value $line
    }
}

# Warnings list
if ($warnCount -gt 0) {
    Write-Host "`n  WARNINGS (review manually):" -ForegroundColor Yellow
    Add-Content -Path $ReportPath -Value "`n  WARNINGS (review manually):"
    $Results | Where-Object { $_.Status -eq "WARN" } | ForEach-Object {
        $line = "    [$($_.ID)] $($_.Description) - $($_.Detail)"
        Write-Host $line -ForegroundColor Yellow
        Add-Content -Path $ReportPath -Value $line
    }
}

Write-Host "`n  Report saved to: $ReportPath`n" -ForegroundColor Green
Add-Content -Path $ReportPath -Value "`n  Report saved to: $ReportPath"
