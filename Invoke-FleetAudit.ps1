<#
.SYNOPSIS
    Runs Windows workstation audits across multiple hosts via PowerShell Remoting.

.DESCRIPTION
    Invoke-FleetAudit is a companion to audit.ps1 that automates security audits
    across a fleet of Windows workstations. It copies the audit script and its
    companion files to each remote host, executes the audit, collects JSON results,
    and produces a fleet-wide summary with an HTML dashboard.

    Prerequisites:
      - PowerShell Remoting (WinRM) must be enabled on target hosts.
      - The executing account must have administrative rights on each target.
      - audit.ps1 and companion files must be accessible locally.

.PARAMETER ComputerName
    One or more hostnames or IP addresses to audit. Cannot be combined with
    -ComputerListFile.

.PARAMETER ComputerListFile
    Path to a text file containing one hostname or IP address per line. Blank
    lines and lines starting with '#' are ignored. Cannot be combined with
    -ComputerName.

.PARAMETER AuditScriptPath
    Path to audit.ps1. Defaults to the same directory as this script.

.PARAMETER OutputDirectory
    Directory where collected results and the fleet summary are saved. Defaults
    to .\FleetAudit_<yyyyMMdd_HHmmss> in the current working directory.

.PARAMETER Credential
    A PSCredential object used to authenticate to remote hosts. When omitted the
    current user context is used.

.PARAMETER Audit
    The audit scope passed through to audit.ps1. Valid values are all, ce, cis1,
    cis2, ncsc, and entra. Defaults to 'all'.

.PARAMETER ThrottleLimit
    Maximum number of concurrent remote sessions. Defaults to 5.

.PARAMETER SkipUnreachable
    When set, hosts that fail the connectivity pre-check are skipped instead of
    aborting the entire run.

.EXAMPLE
    .\Invoke-FleetAudit.ps1 -ComputerName "WS01","WS02","WS03"

    Audits three workstations using the current credentials.

.EXAMPLE
    .\Invoke-FleetAudit.ps1 -ComputerListFile .\hosts.txt -Credential (Get-Credential) -ThrottleLimit 10

    Reads hosts from a file and audits them with explicit credentials, running
    up to 10 sessions in parallel.

.EXAMPLE
    .\Invoke-FleetAudit.ps1 -ComputerName "10.0.0.5" -Audit cis1 -SkipUnreachable

    Runs only CIS Level 1 checks against a single host and continues even when
    that host is unreachable.
#>

#Requires -Version 5.1

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByName', Position = 0)]
    [string[]]$ComputerName,

    [Parameter(Mandatory, ParameterSetName = 'ByFile')]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ComputerListFile,

    [string]$AuditScriptPath,

    [string]$OutputDirectory,

    [PSCredential]$Credential,

    [ValidateSet('all', 'ce', 'cis1', 'cis2', 'ncsc', 'entra')]
    [string]$Audit = 'all',

    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 5,

    [switch]$SkipUnreachable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -- Helpers ------------------------------------------------------------------

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red'; SUCCESS = 'Green' }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Get-RiskRating {
    param([double]$Score)
    if ($Score -ge 90) { return 'LOW' }
    if ($Score -ge 75) { return 'MODERATE' }
    if ($Score -ge 50) { return 'HIGH' }
    return 'CRITICAL'
}

function Get-RiskColor {
    param([string]$Rating)
    switch ($Rating) {
        'LOW'      { '#27ae60' }
        'MODERATE' { '#f39c12' }
        'HIGH'     { '#e74c3c' }
        'CRITICAL' { '#8e44ad' }
        default    { '#95a5a6' }
    }
}

# -- Resolve target list -----------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'ByFile') {
    $ComputerName = Get-Content -Path $ComputerListFile |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' -and $_ -notmatch '^\s*#' }
}

if (-not $ComputerName -or $ComputerName.Count -eq 0) {
    Write-Log 'No target hosts specified. Exiting.' -Level ERROR
    exit 1
}

$ComputerName = $ComputerName | Select-Object -Unique
Write-Log "Target hosts ($($ComputerName.Count)): $($ComputerName -join ', ')"

# -- Resolve paths -----------------------------------------------------------

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

if (-not $AuditScriptPath) {
    $AuditScriptPath = Join-Path $scriptDir 'audit.ps1'
}
if (-not (Test-Path $AuditScriptPath -PathType Leaf)) {
    Write-Log "audit.ps1 not found at: $AuditScriptPath" -Level ERROR
    exit 1
}

$companionFiles = @('remediation.json', 'known-vulnerabilities.json')
$companionPaths = @()
foreach ($f in $companionFiles) {
    $p = Join-Path $scriptDir $f
    if (Test-Path $p -PathType Leaf) {
        $companionPaths += $p
    } else {
        Write-Log "Companion file not found (non-fatal): $p" -Level WARN
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path (Get-Location) "FleetAudit_$timestamp"
}
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
$OutputDirectory = (Resolve-Path $OutputDirectory).Path
Write-Log "Output directory: $OutputDirectory"

# -- Connectivity pre-check --------------------------------------------------

Write-Log 'Testing connectivity to target hosts...'
$reachable = [System.Collections.Generic.List[string]]::new()
$unreachable = [System.Collections.Generic.List[string]]::new()

$wsmanParams = @{ ErrorAction = 'SilentlyContinue' }
if ($Credential) { $wsmanParams['Credential'] = $Credential }

foreach ($host_ in $ComputerName) {
    try {
        $result = Test-WSMan -ComputerName $host_ @wsmanParams
        if ($result) {
            $reachable.Add($host_)
            Write-Log "  $host_ - reachable" -Level SUCCESS
        } else {
            throw 'No response'
        }
    } catch {
        $unreachable.Add($host_)
        Write-Log "  $host_ - unreachable: $($_.Exception.Message)" -Level WARN
    }
}

if ($unreachable.Count -gt 0 -and -not $SkipUnreachable) {
    Write-Log "$($unreachable.Count) host(s) unreachable. Use -SkipUnreachable to continue anyway." -Level ERROR
    exit 1
}

if ($reachable.Count -eq 0) {
    Write-Log 'No reachable hosts. Exiting.' -Level ERROR
    exit 1
}

Write-Log "Proceeding with $($reachable.Count) reachable host(s)."

# -- Deploy audit files ------------------------------------------------------

Write-Log 'Copying audit files to remote hosts...'
$sessionParams = @{ ComputerName = $reachable.ToArray() }
if ($Credential) { $sessionParams['Credential'] = $Credential }

$sessions = @()
try {
    $sessions = New-PSSession @sessionParams -ErrorAction Stop
} catch {
    Write-Log "Failed to create PS sessions: $($_.Exception.Message)" -Level ERROR
    exit 1
}

$remoteTempBase = 'C:\Windows\Temp\FleetAudit'

foreach ($s in $sessions) {
    try {
        Invoke-Command -Session $s -ScriptBlock {
            param($dir)
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        } -ArgumentList $remoteTempBase -ErrorAction Stop

        Copy-Item -Path $AuditScriptPath -Destination $remoteTempBase -ToSession $s -Force
        foreach ($cp in $companionPaths) {
            Copy-Item -Path $cp -Destination $remoteTempBase -ToSession $s -Force
        }
        Write-Log "  $($s.ComputerName) - files deployed" -Level SUCCESS
    } catch {
        Write-Log "  $($s.ComputerName) - deploy failed: $($_.Exception.Message)" -Level ERROR
    }
}

# -- Execute audit on remote hosts -------------------------------------------

Write-Log "Running audit (scope: $Audit) on $($sessions.Count) host(s) with ThrottleLimit=$ThrottleLimit..."

$auditScript = {
    param($remoteDir, $auditScope)
    $scriptPath = Join-Path $remoteDir 'audit.ps1'
    Set-Location $remoteDir
    try {
        $output = & $scriptPath -Audit $auditScope 2>&1
        $jsonFiles = Get-ChildItem -Path $remoteDir -Filter '*_Audit_*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($jsonFiles) {
            $jsonContent = Get-Content -Path $jsonFiles.FullName -Raw -ErrorAction Stop
            return @{
                Success  = $true
                FileName = $jsonFiles.Name
                Json     = $jsonContent
                Host_    = $env:COMPUTERNAME
            }
        } else {
            return @{
                Success = $false
                Host_   = $env:COMPUTERNAME
                Error   = 'No JSON output file was produced by audit.ps1'
            }
        }
    } catch {
        return @{
            Success = $false
            Host_   = $env:COMPUTERNAME
            Error   = $_.Exception.Message
        }
    }
}

$invokeParams = @{
    Session       = $sessions
    ScriptBlock   = $auditScript
    ArgumentList  = @($remoteTempBase, $Audit)
    ErrorAction   = 'SilentlyContinue'
}
if ($ThrottleLimit -and $sessions.Count -gt 1) {
    $invokeParams['ThrottleLimit'] = $ThrottleLimit
}

$remoteResults = @(Invoke-Command @invokeParams)

# -- Collect results ---------------------------------------------------------

Write-Log 'Collecting results...'
$successHosts = [System.Collections.Generic.List[string]]::new()
$failedHosts  = [System.Collections.Generic.List[string]]::new()
$collectedFiles = [System.Collections.Generic.List[string]]::new()

foreach ($r in $remoteResults) {
    $hostLabel = if ($r.Host_) { $r.Host_ } else { 'Unknown' }
    if ($r.Success) {
        try {
            $outFile = Join-Path $OutputDirectory $r.FileName
            Set-Content -Path $outFile -Value $r.Json -Encoding UTF8 -Force
            $collectedFiles.Add($outFile)
            $successHosts.Add($hostLabel)
            Write-Log "  $hostLabel - collected $($r.FileName)" -Level SUCCESS
        } catch {
            $failedHosts.Add($hostLabel)
            Write-Log "  $hostLabel - save failed: $($_.Exception.Message)" -Level ERROR
        }
    } else {
        $failedHosts.Add($hostLabel)
        $errMsg = if ($r.Error) { $r.Error } else { 'Unknown error' }
        Write-Log "  $hostLabel - audit failed: $errMsg" -Level ERROR
    }
}

# -- Clean up remote hosts ---------------------------------------------------

Write-Log 'Cleaning up remote hosts...'
foreach ($s in $sessions) {
    try {
        Invoke-Command -Session $s -ScriptBlock {
            param($dir)
            if (Test-Path $dir) { Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue }
        } -ArgumentList $remoteTempBase -ErrorAction SilentlyContinue
    } catch {
        Write-Log "  $($s.ComputerName) - cleanup warning: $($_.Exception.Message)" -Level WARN
    }
}
$sessions | Remove-PSSession -ErrorAction SilentlyContinue

# -- Generate fleet summary --------------------------------------------------

if ($collectedFiles.Count -eq 0) {
    Write-Log 'No results collected. Fleet summary cannot be generated.' -Level ERROR
    exit 1
}

Write-Log 'Generating fleet summary...'

$allReports = @()
foreach ($f in $collectedFiles) {
    try {
        $data = Get-Content -Path $f -Raw | ConvertFrom-Json
        $allReports += $data
    } catch {
        Write-Log "  Failed to parse $f - $($_.Exception.Message)" -Level WARN
    }
}

if ($allReports.Count -eq 0) {
    Write-Log 'No parseable results. Exiting.' -Level ERROR
    exit 1
}

# Per-host summary
$hostSummaries = @()
foreach ($r in $allReports) {
    $fwScores = @{}
    if ($r.framework_scores) {
        foreach ($fw in $r.framework_scores) {
            $fwScores[$fw.framework] = [math]::Round($fw.score, 1)
        }
    }
    $hostSummaries += [PSCustomObject]@{
        Hostname       = $r.metadata.hostname
        Score          = [math]::Round($r.summary.overall_score, 1)
        WeightedScore  = [math]::Round($r.summary.weighted_score, 1)
        RiskRating     = $r.summary.risk_rating
        TotalChecks    = $r.summary.total_checks
        Passed         = $r.summary.passed
        Failed         = $r.summary.failed
        Warnings       = $r.summary.warnings
        CIS            = if ($fwScores['CIS'])    { $fwScores['CIS'] }    else { $null }
        CISL2          = if ($fwScores['CIS-L2']) { $fwScores['CIS-L2'] } else { $null }
        CEPlus         = if ($fwScores['CE+'])    { $fwScores['CE+'] }    else { $null }
        NCSC           = if ($fwScores['NCSC'])   { $fwScores['NCSC'] }   else { $null }
        EntraID        = if ($fwScores['EntraID']){ $fwScores['EntraID']} else { $null }
    }
}

$scores = $hostSummaries | ForEach-Object { $_.Score }
$avgScore = [math]::Round(($scores | Measure-Object -Average).Average, 1)
$minScore = [math]::Round(($scores | Measure-Object -Minimum).Minimum, 1)
$maxScore = [math]::Round(($scores | Measure-Object -Maximum).Maximum, 1)

# Framework compliance rates
$frameworkCompliance = @{}
$knownFrameworks = @('CIS', 'CIS-L2', 'CE+', 'NCSC', 'EntraID')
$thresholds = @{ 'CIS' = 90; 'CIS-L2' = 90; 'CE+' = 100; 'NCSC' = 85; 'EntraID' = 90 }

foreach ($fw in $knownFrameworks) {
    $passing = 0
    $totalWithFw = 0
    foreach ($r in $allReports) {
        $fwEntry = $r.framework_scores | Where-Object { $_.framework -eq $fw }
        if ($fwEntry) {
            $totalWithFw++
            if ($fwEntry.score -ge $thresholds[$fw]) { $passing++ }
        }
    }
    if ($totalWithFw -gt 0) {
        $frameworkCompliance[$fw] = [PSCustomObject]@{
            Framework   = $fw
            Threshold   = $thresholds[$fw]
            Passing     = $passing
            Total       = $totalWithFw
            Rate        = [math]::Round(($passing / $totalWithFw) * 100, 1)
        }
    }
}

# Most common failures
$failureCounts = @{}
foreach ($r in $allReports) {
    $failures = $r.results | Where-Object { $_.Status -eq 'FAIL' }
    foreach ($f in $failures) {
        $key = $f.ID
        if (-not $failureCounts.ContainsKey($key)) {
            $failureCounts[$key] = [PSCustomObject]@{
                ID          = $f.ID
                Description = $f.Description
                Framework   = $f.Framework
                Count       = 0
            }
        }
        $failureCounts[$key].Count++
    }
}
$topFailures = $failureCounts.Values | Sort-Object Count -Descending | Select-Object -First 25

# Worst-performing hosts
$worstHosts = $hostSummaries | Sort-Object Score | Select-Object -First 10

# Fleet stats object
$fleetStats = [PSCustomObject]@{
    TotalHosts       = $allReports.Count
    AverageScore     = $avgScore
    MinScore         = $minScore
    MaxScore         = $maxScore
    AvgRiskRating    = Get-RiskRating -Score $avgScore
    HostsLowRisk     = @($hostSummaries | Where-Object { $_.RiskRating -eq 'LOW' }).Count
    HostsModerate    = @($hostSummaries | Where-Object { $_.RiskRating -eq 'MODERATE' }).Count
    HostsHighRisk    = @($hostSummaries | Where-Object { $_.RiskRating -eq 'HIGH' }).Count
    HostsCritical    = @($hostSummaries | Where-Object { $_.RiskRating -eq 'CRITICAL' }).Count
}

# -- Save JSON summary -------------------------------------------------------

$summaryObj = [PSCustomObject]@{
    metadata             = [PSCustomObject]@{
        generated   = (Get-Date -Format 'o')
        audit_scope = $Audit
        total_targets    = $ComputerName.Count
        reachable_hosts  = $reachable.Count
        successful_audits = $successHosts.Count
        failed_audits    = $failedHosts.Count
        unreachable      = $unreachable.ToArray()
    }
    fleet_stats          = $fleetStats
    framework_compliance = $frameworkCompliance.Values | Sort-Object Framework
    host_summaries       = $hostSummaries | Sort-Object Score
    top_failures         = $topFailures
    worst_hosts          = $worstHosts
}

$jsonPath = Join-Path $OutputDirectory 'FleetSummary.json'
$summaryObj | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
Write-Log "Fleet summary JSON saved: $jsonPath" -Level SUCCESS

# -- Generate HTML dashboard -------------------------------------------------

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return '' }
    return $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

$hostRowsHtml = ''
foreach ($h in ($hostSummaries | Sort-Object Score)) {
    $riskColor = Get-RiskColor -Rating $h.RiskRating
    $hostRowsHtml += @"
<tr>
<td>$(ConvertTo-HtmlSafe $h.Hostname)</td>
<td>$($h.Score)%</td>
<td>$($h.WeightedScore)%</td>
<td style="color:$riskColor;font-weight:bold;">$($h.RiskRating)</td>
<td>$($h.Passed)/$($h.TotalChecks)</td>
<td>$(if($h.CIS -ne $null){"$($h.CIS)%"}else{'-'})</td>
<td>$(if($h.CEPlus -ne $null){"$($h.CEPlus)%"}else{'-'})</td>
<td>$(if($h.NCSC -ne $null){"$($h.NCSC)%"}else{'-'})</td>
<td>$(if($h.EntraID -ne $null){"$($h.EntraID)%"}else{'-'})</td>
</tr>
"@
}

$failureRowsHtml = ''
foreach ($f in $topFailures) {
    $pct = [math]::Round(($f.Count / $allReports.Count) * 100, 0)
    $failureRowsHtml += @"
<tr>
<td>$(ConvertTo-HtmlSafe $f.ID)</td>
<td>$(ConvertTo-HtmlSafe $f.Description)</td>
<td>$(ConvertTo-HtmlSafe $f.Framework)</td>
<td>$($f.Count) / $($allReports.Count) ($pct%)</td>
</tr>
"@
}

$fwBarsHtml = ''
foreach ($fw in ($frameworkCompliance.Values | Sort-Object Framework)) {
    $barColor = if ($fw.Rate -ge 80) { '#27ae60' } elseif ($fw.Rate -ge 50) { '#f39c12' } else { '#e74c3c' }
    $fwBarsHtml += @"
<div style="margin-bottom:10px;">
<div style="display:flex;align-items:center;margin-bottom:2px;">
<span style="width:80px;font-weight:bold;">$($fw.Framework)</span>
<span style="color:#666;">$($fw.Passing)/$($fw.Total) passing (threshold: $($fw.Threshold)%)</span>
</div>
<div style="background:#ecf0f1;border-radius:4px;height:24px;width:100%;position:relative;">
<div style="background:$barColor;border-radius:4px;height:24px;width:$($fw.Rate)%;min-width:2px;"></div>
<span style="position:absolute;right:8px;top:2px;font-size:13px;font-weight:bold;">$($fw.Rate)%</span>
</div>
</div>
"@
}

$avgRiskColor = Get-RiskColor -Rating (Get-RiskRating -Score $avgScore)

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fleet Audit Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
background:#f5f6fa;color:#2c3e50;line-height:1.6;padding:20px;}
.header{background:linear-gradient(135deg,#2c3e50,#34495e);color:#fff;padding:24px 32px;
border-radius:8px;margin-bottom:24px;}
.header h1{font-size:24px;margin-bottom:4px;}
.header p{opacity:0.85;font-size:14px;}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px;}
.card{background:#fff;border-radius:8px;padding:20px;box-shadow:0 2px 8px rgba(0,0,0,0.08);text-align:center;}
.card .value{font-size:28px;font-weight:bold;margin-bottom:4px;}
.card .label{font-size:13px;color:#7f8c8d;text-transform:uppercase;letter-spacing:0.5px;}
.section{background:#fff;border-radius:8px;padding:24px;box-shadow:0 2px 8px rgba(0,0,0,0.08);margin-bottom:24px;}
.section h2{font-size:18px;margin-bottom:16px;padding-bottom:8px;border-bottom:2px solid #ecf0f1;}
table{width:100%;border-collapse:collapse;font-size:14px;}
th{background:#f8f9fa;text-align:left;padding:10px 12px;border-bottom:2px solid #dee2e6;font-weight:600;}
td{padding:8px 12px;border-bottom:1px solid #ecf0f1;}
tr:hover{background:#f8f9fa;}
.risk-breakdown span{display:inline-block;padding:4px 12px;border-radius:4px;color:#fff;font-weight:bold;
font-size:13px;margin-right:8px;margin-bottom:4px;}
.footer{text-align:center;color:#95a5a6;font-size:12px;margin-top:32px;}
</style>
</head>
<body>
<div class="header">
<h1>Fleet Audit Dashboard</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Scope: $Audit |
Hosts audited: $($allReports.Count) of $($ComputerName.Count) targeted</p>
$(if($unreachable.Count -gt 0){"<p>Unreachable: $($unreachable -join ', ')</p>"})
$(if($failedHosts.Count -gt 0){"<p>Failed: $($failedHosts -join ', ')</p>"})
</div>

<div class="cards">
<div class="card">
<div class="value">$($fleetStats.TotalHosts)</div>
<div class="label">Hosts Audited</div>
</div>
<div class="card">
<div class="value" style="color:$avgRiskColor;">$avgScore%</div>
<div class="label">Average Score</div>
</div>
<div class="card">
<div class="value">$minScore%</div>
<div class="label">Min Score</div>
</div>
<div class="card">
<div class="value">$maxScore%</div>
<div class="label">Max Score</div>
</div>
<div class="card">
<div class="value" style="color:#27ae60;">$($fleetStats.HostsLowRisk)</div>
<div class="label">Low Risk</div>
</div>
<div class="card">
<div class="value" style="color:#f39c12;">$($fleetStats.HostsModerate)</div>
<div class="label">Moderate Risk</div>
</div>
<div class="card">
<div class="value" style="color:#e74c3c;">$($fleetStats.HostsHighRisk)</div>
<div class="label">High Risk</div>
</div>
<div class="card">
<div class="value" style="color:#8e44ad;">$($fleetStats.HostsCritical)</div>
<div class="label">Critical Risk</div>
</div>
</div>

<div class="section">
<h2>Framework Compliance Rates</h2>
$fwBarsHtml
$(if(-not $fwBarsHtml){'<p style="color:#95a5a6;">No framework data available.</p>'})
</div>

<div class="section">
<h2>Per-Host Results (sorted by score, worst first)</h2>
<div style="overflow-x:auto;">
<table>
<thead>
<tr>
<th>Hostname</th><th>Score</th><th>Weighted</th><th>Risk</th><th>Passed</th>
<th>CIS L1</th><th>CE+</th><th>NCSC</th><th>Entra ID</th>
</tr>
</thead>
<tbody>
$hostRowsHtml
</tbody>
</table>
</div>
</div>

<div class="section">
<h2>Most Common Failures Across Fleet</h2>
<div style="overflow-x:auto;">
<table>
<thead>
<tr><th>Check ID</th><th>Description</th><th>Framework</th><th>Hosts Failing</th></tr>
</thead>
<tbody>
$failureRowsHtml
$(if(-not $failureRowsHtml){'<tr><td colspan="4" style="color:#95a5a6;text-align:center;">No failures recorded.</td></tr>'})
</tbody>
</table>
</div>
</div>

<div class="section">
<h2>Worst-Performing Hosts</h2>
<div style="overflow-x:auto;">
<table>
<thead><tr><th>Hostname</th><th>Score</th><th>Risk</th><th>Failed Checks</th><th>Warnings</th></tr></thead>
<tbody>
$(foreach ($w in $worstHosts) {
    $wRiskColor = Get-RiskColor -Rating $w.RiskRating
    "<tr><td>$(ConvertTo-HtmlSafe $w.Hostname)</td><td>$($w.Score)%</td>" +
    "<td style=`"color:$wRiskColor;font-weight:bold;`">$($w.RiskRating)</td>" +
    "<td>$($w.Failed)</td><td>$($w.Warnings)</td></tr>"
})
</tbody>
</table>
</div>
</div>

<div class="footer">
<p>Windows Workstation Fleet Audit | Invoke-FleetAudit.ps1</p>
</div>
</body>
</html>
"@

$htmlPath = Join-Path $OutputDirectory 'FleetDashboard.html'
Set-Content -Path $htmlPath -Value $html -Encoding UTF8
Write-Log "Fleet dashboard HTML saved: $htmlPath" -Level SUCCESS

# -- Console summary ---------------------------------------------------------

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  FLEET AUDIT SUMMARY' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Targets specified:   $($ComputerName.Count)"
Write-Host "  Reachable:           $($reachable.Count)"
Write-Host "  Unreachable:         $($unreachable.Count)"
Write-Host "  Audits succeeded:    $($successHosts.Count)" -ForegroundColor Green
Write-Host "  Audits failed:       $($failedHosts.Count)" -ForegroundColor $(if($failedHosts.Count -gt 0){'Red'}else{'Green'})
Write-Host ''
Write-Host "  Average score:       $avgScore% ($(Get-RiskRating -Score $avgScore))" -ForegroundColor $avgRiskColor
Write-Host "  Score range:         $minScore% - $maxScore%"
Write-Host "  Risk breakdown:      LOW=$($fleetStats.HostsLowRisk)  MODERATE=$($fleetStats.HostsModerate)  HIGH=$($fleetStats.HostsHighRisk)  CRITICAL=$($fleetStats.HostsCritical)"
Write-Host ''

if ($topFailures.Count -gt 0) {
    Write-Host '  Top 5 most common failures:' -ForegroundColor Yellow
    $topFailures | Select-Object -First 5 | ForEach-Object {
        Write-Host "    [$($_.ID)] $($_.Description) - $($_.Count)/$($allReports.Count) hosts" -ForegroundColor Yellow
    }
    Write-Host ''
}

Write-Host "  Results:    $OutputDirectory"
Write-Host "  JSON:       $jsonPath"
Write-Host "  Dashboard:  $htmlPath"
Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan

if ($failedHosts.Count -gt 0) {
    Write-Host ''
    Write-Log "Failed hosts: $($failedHosts -join ', ')" -Level WARN
}

Write-Log 'Fleet audit complete.' -Level SUCCESS
