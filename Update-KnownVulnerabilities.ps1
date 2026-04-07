<#
.SYNOPSIS
    Generates/updates known-vulnerabilities.json from the NIST NVD API.

.DESCRIPTION
    Queries the NIST National Vulnerability Database (NVD) API v2.0 to find the
    latest critical and high severity CVEs for common desktop applications.
    Produces the known-vulnerabilities.json companion file used by audit.ps1
    Section 80 (Application Patch Currency).

    Each output entry contains:
      app              - Human-readable application name
      registry_pattern - Regex to match against Windows registry DisplayName
      vulnerable_below - Minimum safe version (versions below this are flagged)
      severity         - CVE severity (critical or high)
      cve              - CVE identifier (e.g. CVE-2025-1234)
      updated          - Date the entry was last checked (YYYY-MM-DD)

    When an existing known-vulnerabilities.json is present, the script merges
    results: NVD data replaces an entry only when it specifies a higher
    vulnerable_below version.  Entries that the API cannot improve are preserved.

.PARAMETER NvdApiKey
    Optional NVD API key for higher rate limits (50 req/30 s instead of
    5 req/30 s).  Request a free key at:
    https://nvd.nist.gov/developers/request-an-api-key

.PARAMETER OutputPath
    Output file path. Defaults to known-vulnerabilities.json in the script
    directory (or current directory when $PSScriptRoot is empty).

.PARAMETER ResultsPerApp
    Maximum NVD results to retrieve per application. Default: 100.

.EXAMPLE
    .\Update-KnownVulnerabilities.ps1

.EXAMPLE
    .\Update-KnownVulnerabilities.ps1 -NvdApiKey "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    .\Update-KnownVulnerabilities.ps1 -OutputPath "C:\audit\known-vulnerabilities.json"
#>

[CmdletBinding()]
param(
    [string]$NvdApiKey,
    [string]$OutputPath,
    [int]$ResultsPerApp = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- Resolve output path ----
if (-not $OutputPath) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
    $OutputPath = Join-Path $scriptDir "known-vulnerabilities.json"
}

# ---- Ensure TLS 1.2+ for NVD API ----
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# NVD API v2.0 base URL
$NvdApiBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate-limit delay: 5 req/30 s without key, 50 req/30 s with key
$RequestDelaySec = if ($NvdApiKey) { 1 } else { 7 }

# ============================================================
#  TRACKED APPLICATIONS
# ============================================================
# keyword      : search term sent to NVD keywordSearch parameter
# cpe_patterns : "vendor:product" strings matched against CPE criteria in
#                returned CVEs -- multiple alternatives are supported
$TrackedApps = @(
    @{
        app              = "Google Chrome"
        registry_pattern = "Google Chrome"
        keyword          = "google chrome"
        cpe_patterns     = @("google:chrome")
    }
    @{
        app              = "Mozilla Firefox"
        registry_pattern = "Mozilla Firefox"
        keyword          = "mozilla firefox"
        cpe_patterns     = @("mozilla:firefox")
    }
    @{
        app              = "Mozilla Firefox ESR"
        registry_pattern = "Mozilla Firefox.*ESR"
        keyword          = "firefox esr"
        cpe_patterns     = @("mozilla:firefox_esr", "mozilla:firefox")
    }
    @{
        app              = "Microsoft Edge"
        registry_pattern = "Microsoft Edge"
        keyword          = "microsoft edge chromium"
        cpe_patterns     = @("microsoft:edge_chromium", "microsoft:edge")
    }
    @{
        app              = "Adobe Acrobat Reader DC"
        registry_pattern = "Adobe Acrobat.*Reader"
        keyword          = "adobe acrobat reader"
        cpe_patterns     = @("adobe:acrobat_reader_dc", "adobe:acrobat_reader")
    }
    @{
        app              = "Adobe Acrobat DC"
        registry_pattern = "Adobe Acrobat(?!.*Reader)"
        keyword          = "adobe acrobat dc"
        cpe_patterns     = @("adobe:acrobat_dc", "adobe:acrobat")
    }
    @{
        app              = "Java Runtime Environment 8"
        registry_pattern = "Java 8 Update"
        keyword          = "oracle java se"
        cpe_patterns     = @("oracle:jre", "oracle:java_se")
    }
    @{
        app              = "Java SE Development Kit"
        registry_pattern = "Java.*Development Kit"
        keyword          = "oracle jdk"
        cpe_patterns     = @("oracle:jdk", "oracle:java_se")
    }
    @{
        app              = "7-Zip"
        registry_pattern = "7-Zip"
        keyword          = "7-zip"
        cpe_patterns     = @("7-zip:7-zip")
    }
    @{
        app              = "PuTTY"
        registry_pattern = "PuTTY"
        keyword          = "putty"
        cpe_patterns     = @("putty:putty", "simon_tatham:putty")
    }
    @{
        app              = "Zoom Workplace"
        registry_pattern = "Zoom"
        keyword          = "zoom workplace"
        cpe_patterns     = @("zoom:zoom", "zoom:workplace", "zoom:meeting_sdk")
    }
    @{
        app              = "VLC Media Player"
        registry_pattern = "VLC media player"
        keyword          = "vlc media player"
        cpe_patterns     = @("videolan:vlc_media_player")
    }
    @{
        app              = "WinRAR"
        registry_pattern = "WinRAR"
        keyword          = "winrar"
        cpe_patterns     = @("rarlab:winrar")
    }
    @{
        app              = "FileZilla Client"
        registry_pattern = "FileZilla Client"
        keyword          = "filezilla client"
        cpe_patterns     = @("filezilla-project:filezilla_client", "filezilla:filezilla")
    }
    @{
        app              = "Notepad++"
        registry_pattern = "Notepad\\+\\+"
        keyword          = "notepad++"
        cpe_patterns     = @("notepad-plus-plus:notepad\+\+")
    }
    @{
        app              = "Python 3"
        registry_pattern = "Python 3"
        keyword          = "cpython"
        cpe_patterns     = @("python:python", "python_software_foundation:python")
    }
    @{
        app              = "Node.js"
        registry_pattern = "Node\\.js"
        keyword          = "node.js"
        cpe_patterns     = @("nodejs:node.js", "nodejs:nodejs")
    }
    @{
        app              = "Git for Windows"
        registry_pattern = "Git"
        keyword          = "git for windows"
        cpe_patterns     = @("git-scm:git", "git_for_windows_project:git_for_windows")
    }
    @{
        app              = "KeePass"
        registry_pattern = "KeePass"
        keyword          = "keepass"
        cpe_patterns     = @("keepass:keepass", "dominik_reichl:keepass")
    }
    @{
        app              = "Visual Studio Code"
        registry_pattern = "Microsoft Visual Studio Code"
        keyword          = "visual studio code"
        cpe_patterns     = @("microsoft:visual_studio_code")
    }
    @{
        app              = "LibreOffice"
        registry_pattern = "LibreOffice"
        keyword          = "libreoffice"
        cpe_patterns     = @("libreoffice:libreoffice", "documentfoundation:libreoffice")
    }
    @{
        app              = "Wireshark"
        registry_pattern = "Wireshark"
        keyword          = "wireshark"
        cpe_patterns     = @("wireshark:wireshark")
    }
    @{
        app              = "Citrix Workspace"
        registry_pattern = "Citrix Workspace"
        keyword          = "citrix workspace"
        cpe_patterns     = @("citrix:workspace", "citrix:workspace_app")
    }
    @{
        app              = "TeamViewer"
        registry_pattern = "TeamViewer"
        keyword          = "teamviewer"
        cpe_patterns     = @("teamviewer:teamviewer")
    }
    @{
        app              = "Foxit PDF Reader"
        registry_pattern = "Foxit.*Reader"
        keyword          = "foxit pdf reader"
        cpe_patterns     = @("foxit:pdf_reader", "foxit:reader")
    }
)

# ============================================================
#  HELPER FUNCTIONS
# ============================================================

function Compare-VersionStrings {
    <#
    .SYNOPSIS
        Compare two dotted-numeric version strings.
    .OUTPUTS
        -1 if V1 < V2, 0 if equal, 1 if V1 > V2, $null on parse failure.
    #>
    param([string]$V1, [string]$V2)
    try {
        $clean1 = ($V1 -replace '[^0-9.]', '').Trim('.')
        $clean2 = ($V2 -replace '[^0-9.]', '').Trim('.')
        if (-not $clean1 -or -not $clean2) { return $null }
        $p1 = @($clean1.Split('.') | Where-Object { $_ -ne '' } | ForEach-Object {
            $n = 0; if ([long]::TryParse($_, [ref]$n)) { $n } else { return $null }
        })
        $p2 = @($clean2.Split('.') | Where-Object { $_ -ne '' } | ForEach-Object {
            $n = 0; if ([long]::TryParse($_, [ref]$n)) { $n } else { return $null }
        })
        if ($null -eq $p1 -or $null -eq $p2) { return $null }
        $maxLen = [math]::Max($p1.Count, $p2.Count)
        for ($i = 0; $i -lt $maxLen; $i++) {
            $a = if ($i -lt $p1.Count) { $p1[$i] } else { 0 }
            $b = if ($i -lt $p2.Count) { $p2[$i] } else { 0 }
            if ($a -lt $b) { return -1 }
            if ($a -gt $b) { return  1 }
        }
        return 0
    } catch {
        return $null
    }
}

function Invoke-NvdApiQuery {
    <#
    .SYNOPSIS
        Query the NVD CVE API with a keyword search.
    #>
    param(
        [string]$Keyword,
        [int]$MaxResults = 100
    )

    $encodedKeyword = [Uri]::EscapeDataString($Keyword)
    $url = "${NvdApiBase}?keywordSearch=${encodedKeyword}&resultsPerPage=${MaxResults}"

    $headers = @{ "Accept" = "application/json" }
    if ($NvdApiKey) { $headers["apiKey"] = $NvdApiKey }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -TimeoutSec 60 -ErrorAction Stop
        return $response
    } catch {
        Write-Warning "  NVD API request failed for '${Keyword}': $($_.Exception.Message)"
        return $null
    }
}

function Test-CpeMatch {
    <#
    .SYNOPSIS
        Check whether a CPE 2.3 criteria string matches any of the given
        vendor:product patterns.
    #>
    param(
        [string]$CpeCriteria,
        [string[]]$CpePatterns
    )

    foreach ($pattern in $CpePatterns) {
        $parts = $pattern -split ':', 2
        if ($parts.Count -ne 2) { continue }
        $vendor  = [regex]::Escape($parts[0])
        $product = [regex]::Escape($parts[1])
        if ($CpeCriteria -match "cpe:2\.3:a:${vendor}:${product}:") {
            return $true
        }
    }
    return $false
}

function Find-BestVulnerability {
    <#
    .SYNOPSIS
        Scan NVD vulnerability results and return the entry with the highest
        versionEndExcluding for the given CPE patterns.
    #>
    param(
        $Vulnerabilities,
        [string[]]$CpePatterns
    )

    $severityRank = @{ "CRITICAL" = 2; "HIGH" = 1 }
    $bestVersion  = $null
    $bestRank     = 0
    $bestEntry    = $null

    foreach ($vuln in $Vulnerabilities) {
        $cve = $vuln.cve

        # ---- Determine severity ----
        $severity = $null
        $metrics  = $cve.metrics
        if ($metrics -and $metrics.PSObject.Properties['cvssMetricV40'] -and $metrics.cvssMetricV40) {
            $severity = $metrics.cvssMetricV40[0].cvssData.baseSeverity
        } elseif ($metrics -and $metrics.PSObject.Properties['cvssMetricV31'] -and $metrics.cvssMetricV31) {
            $severity = $metrics.cvssMetricV31[0].cvssData.baseSeverity
        } elseif ($metrics -and $metrics.PSObject.Properties['cvssMetricV30'] -and $metrics.cvssMetricV30) {
            $severity = $metrics.cvssMetricV30[0].cvssData.baseSeverity
        } elseif ($metrics -and $metrics.PSObject.Properties['cvssMetricV2'] -and $metrics.cvssMetricV2) {
            # NVD API v2.0: cvssMetricV2 stores baseSeverity at the metric level, not inside cvssData
            $v2sev = $null
            $v2metric = $metrics.cvssMetricV2[0]
            if ($v2metric.PSObject.Properties['baseSeverity']) {
                $v2sev = $v2metric.baseSeverity
            }
            if ($v2sev) { $severity = $v2sev }
        }
        if (-not $severity -or $severity -notin @("CRITICAL", "HIGH")) { continue }
        $rank = $severityRank[$severity]

        # ---- Walk configuration nodes ----
        if (-not $cve.configurations) { continue }

        foreach ($config in $cve.configurations) {
            foreach ($node in $config.nodes) {
                # Collect cpeMatch entries from the node and any children
                $allMatches = [System.Collections.Generic.List[object]]::new()
                if ($node.cpeMatch) { foreach ($m in $node.cpeMatch) { $allMatches.Add($m) } }
                if ($node.children) {
                    foreach ($child in $node.children) {
                        if ($child.cpeMatch) { foreach ($m in $child.cpeMatch) { $allMatches.Add($m) } }
                    }
                }

                foreach ($m in $allMatches) {
                    if (-not $m.vulnerable)          { continue }
                    if (-not $m.versionEndExcluding)  { continue }

                    if (-not (Test-CpeMatch -CpeCriteria $m.criteria -CpePatterns $CpePatterns)) {
                        continue
                    }

                    $fixedVer = $m.versionEndExcluding

                    # Prefer highest version; break ties by severity
                    $isBetter = $false
                    if (-not $bestVersion) {
                        $isBetter = $true
                    } else {
                        $cmp = Compare-VersionStrings $fixedVer $bestVersion
                        if ($null -ne $cmp -and $cmp -gt 0) {
                            $isBetter = $true
                        } elseif ($null -ne $cmp -and $cmp -eq 0 -and $rank -gt $bestRank) {
                            $isBetter = $true
                        }
                    }

                    if ($isBetter) {
                        $bestVersion = $fixedVer
                        $bestRank    = $rank
                        $bestEntry   = @{
                            severity         = $severity.ToLower()
                            cve              = $cve.id
                            vulnerable_below = $fixedVer
                        }
                    }
                }
            }
        }
    }

    return $bestEntry
}

# ============================================================
#  MAIN
# ============================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Update-KnownVulnerabilities           " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Output  : $OutputPath"
Write-Host "  Apps    : $($TrackedApps.Count)"
Write-Host "  API Key : $(if ($NvdApiKey) { 'Yes (high rate limit)' } else { 'No  (5 req / 30 s)' })"
Write-Host "  Delay   : ${RequestDelaySec}s between requests"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ---- Load existing entries for merge / fallback ----
$existingByApp = @{}
if (Test-Path $OutputPath) {
    try {
        $existing = Get-Content $OutputPath -Raw | ConvertFrom-Json
        foreach ($entry in $existing) {
            $existingByApp[$entry.app] = $entry
        }
        Write-Host "Loaded $($existing.Count) existing entries for merge/fallback." -ForegroundColor DarkGray
        Write-Host ""
    } catch {
        Write-Warning "Could not parse existing file -- starting fresh: $_"
    }
}

# ---- Query NVD for each tracked app ----
$results  = [System.Collections.Generic.List[object]]::new()
$cUpdated  = 0
$cKept     = 0
$cMissing  = 0

for ($i = 0; $i -lt $TrackedApps.Count; $i++) {
    $tracked = $TrackedApps[$i]
    Write-Host "[$($i + 1)/$($TrackedApps.Count)] $($tracked.app) " -NoNewline

    $response = Invoke-NvdApiQuery -Keyword $tracked.keyword -MaxResults $ResultsPerApp

    $best = $null
    if ($response -and $response.vulnerabilities -and $response.vulnerabilities.Count -gt 0) {
        Write-Host "($($response.totalResults) CVEs) " -NoNewline -ForegroundColor DarkGray
        $best = Find-BestVulnerability -Vulnerabilities $response.vulnerabilities `
                                       -CpePatterns $tracked.cpe_patterns
    }

    $existingEntry = $existingByApp[$tracked.app]

    if ($best) {
        # Decide whether the new entry improves on the existing one
        $useNew = $true
        if ($existingEntry) {
            $cmp = Compare-VersionStrings $best.vulnerable_below $existingEntry.vulnerable_below
            if ($null -ne $cmp -and $cmp -le 0) {
                $useNew = $false
            }
        }

        if ($useNew) {
            $results.Add([ordered]@{
                app              = $tracked.app
                registry_pattern = $tracked.registry_pattern
                vulnerable_below = $best.vulnerable_below
                severity         = $best.severity
                cve              = $best.cve
                updated          = (Get-Date -Format "yyyy-MM-dd")
            })
            $cUpdated++
            Write-Host "$($best.cve) [$($best.severity)] < $($best.vulnerable_below)" -ForegroundColor Yellow
        } else {
            $results.Add([ordered]@{
                app              = $existingEntry.app
                registry_pattern = $existingEntry.registry_pattern
                vulnerable_below = $existingEntry.vulnerable_below
                severity         = $existingEntry.severity
                cve              = $existingEntry.cve
                updated          = $existingEntry.updated
            })
            $cKept++
            Write-Host "kept existing ($($existingEntry.cve) < $($existingEntry.vulnerable_below))" -ForegroundColor DarkGray
        }
    } elseif ($existingEntry) {
        # No NVD match -- preserve the existing entry
        $results.Add([ordered]@{
            app              = $existingEntry.app
            registry_pattern = $existingEntry.registry_pattern
            vulnerable_below = $existingEntry.vulnerable_below
            severity         = $existingEntry.severity
            cve              = $existingEntry.cve
            updated          = $existingEntry.updated
        })
        $cKept++
        Write-Host "no NVD match -- kept existing ($($existingEntry.cve))" -ForegroundColor DarkGray
    } else {
        $cMissing++
        Write-Host "no data found" -ForegroundColor Red
    }

    # Rate-limit pause (skip after last item)
    if ($i -lt ($TrackedApps.Count - 1)) {
        Start-Sleep -Seconds $RequestDelaySec
    }
}

# ============================================================
#  WRITE OUTPUT
# ============================================================

# ConvertTo-Json emits a bare object instead of an array when Count is 1
if ($results.Count -eq 0) {
    $jsonOutput = "[]"
} elseif ($results.Count -eq 1) {
    $jsonOutput = "[$([System.Environment]::NewLine)  $(($results[0] | ConvertTo-Json -Depth 10 -Compress))$([System.Environment]::NewLine)]"
} else {
    $jsonOutput = ConvertTo-Json @($results) -Depth 10
}

Set-Content -Path $OutputPath -Value $jsonOutput -Encoding UTF8

# ---- Validation: re-read and parse to confirm valid JSON ----
try {
    $check = Get-Content $OutputPath -Raw | ConvertFrom-Json
    $validMsg = "Output validated -- $($check.Count) entries, valid JSON."
} catch {
    $validMsg = "WARNING: Output file failed JSON validation: $_"
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Complete                               " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Updated : $cUpdated entries (new/improved from NVD)"
Write-Host "  Kept    : $cKept entries (existing preserved)"
Write-Host "  Missing : $cMissing entries (no data available)"
Write-Host "  Total   : $($results.Count) entries written"
Write-Host "  Output  : $OutputPath"
Write-Host "  $validMsg"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
