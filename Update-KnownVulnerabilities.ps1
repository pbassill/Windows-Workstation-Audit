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
    [string]$OutputPath
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
    @{
        app              = "Foxit PDF Editor"
        registry_pattern = "Foxit.*Editor"
        keyword          = "foxit pdf editor"
        cpe_patterns     = @("foxit:pdf_editor")
    }
    @{
        app              = "Brave Browser"
        registry_pattern = "Brave"
        keyword          = "brave browser"
        cpe_patterns     = @("brave:brave", "brave:browser")
    }
    @{
        app              = "Opera Browser"
        registry_pattern = "Opera"
        keyword          = "opera browser"
        cpe_patterns     = @("opera:opera_browser", "opera:opera")
    }
    @{
        app              = "Vivaldi Browser"
        registry_pattern = "Vivaldi"
        keyword          = "vivaldi browser"
        cpe_patterns     = @("vivaldi:vivaldi")
    }
    @{
        app              = "Mozilla Thunderbird"
        registry_pattern = "Mozilla Thunderbird"
        keyword          = "mozilla thunderbird"
        cpe_patterns     = @("mozilla:thunderbird")
    }
    @{
        app              = "Slack"
        registry_pattern = "Slack"
        keyword          = "slack desktop"
        cpe_patterns     = @("slack:slack")
    }
    @{
        app              = "Signal Desktop"
        registry_pattern = "Signal"
        keyword          = "signal desktop"
        cpe_patterns     = @("signal:signal-desktop", "signal:signal_desktop")
    }
    @{
        app              = "Telegram Desktop"
        registry_pattern = "Telegram"
        keyword          = "telegram desktop"
        cpe_patterns     = @("telegram:telegram_desktop", "telegram:telegram")
    }
    @{
        app              = "WinSCP"
        registry_pattern = "WinSCP"
        keyword          = "winscp"
        cpe_patterns     = @("winscp:winscp")
    }
    @{
        app              = "OpenVPN"
        registry_pattern = "OpenVPN"
        keyword          = "openvpn"
        cpe_patterns     = @("openvpn:openvpn")
    }
    @{
        app              = "VMware Workstation"
        registry_pattern = "VMware Workstation"
        keyword          = "vmware workstation"
        cpe_patterns     = @("vmware:workstation")
    }
    @{
        app              = "VirtualBox"
        registry_pattern = "Oracle VM VirtualBox"
        keyword          = "oracle virtualbox"
        cpe_patterns     = @("oracle:vm_virtualbox")
    }
    @{
        app              = "Docker Desktop"
        registry_pattern = "Docker Desktop"
        keyword          = "docker desktop"
        cpe_patterns     = @("docker:desktop", "docker:docker_desktop")
    }
    @{
        app              = "Postman"
        registry_pattern = "Postman"
        keyword          = "postman"
        cpe_patterns     = @("postman:postman")
    }
    @{
        app              = "Sublime Text"
        registry_pattern = "Sublime Text"
        keyword          = "sublime text"
        cpe_patterns     = @("sublimetext:sublime_text", "sublimehq:sublime_text")
    }
    @{
        app              = "Tor Browser"
        registry_pattern = "Tor Browser"
        keyword          = "tor browser"
        cpe_patterns     = @("torproject:tor_browser", "torproject:tor")
    }
    @{
        app              = "AnyDesk"
        registry_pattern = "AnyDesk"
        keyword          = "anydesk"
        cpe_patterns     = @("anydesk:anydesk")
    }
    @{
        app              = "RustDesk"
        registry_pattern = "RustDesk"
        keyword          = "rustdesk"
        cpe_patterns     = @("rustdesk:rustdesk")
    }
    @{
        app              = "Cisco Webex"
        registry_pattern = "Cisco Webex"
        keyword          = "cisco webex"
        cpe_patterns     = @("cisco:webex_meetings", "cisco:webex")
    }
    @{
        app              = "GoTo Meeting"
        registry_pattern = "GoTo Meeting"
        keyword          = "gotomeeting"
        cpe_patterns     = @("gotomeeting:gotomeeting", "logmein:gotomeeting")
    }
    @{
        app              = "KeePassXC"
        registry_pattern = "KeePassXC"
        keyword          = "keepassxc"
        cpe_patterns     = @("keepassxc:keepassxc")
    }
    @{
        app              = "Bitwarden"
        registry_pattern = "Bitwarden"
        keyword          = "bitwarden"
        cpe_patterns     = @("bitwarden:desktop", "bitwarden:bitwarden")
    }
    @{
        app              = "Paint.NET"
        registry_pattern = "paint\\.net"
        keyword          = "paint.net"
        cpe_patterns     = @("dotpdn:paint.net", "getpaint:paint.net")
    }
    @{
        app              = "GIMP"
        registry_pattern = "GIMP"
        keyword          = "gimp"
        cpe_patterns     = @("gimp:gimp")
    }
    @{
        app              = "Inkscape"
        registry_pattern = "Inkscape"
        keyword          = "inkscape"
        cpe_patterns     = @("inkscape:inkscape")
    }
    @{
        app              = "OBS Studio"
        registry_pattern = "OBS Studio"
        keyword          = "obs studio"
        cpe_patterns     = @("obsproject:obs_studio")
    }
    @{
        app              = "HandBrake"
        registry_pattern = "HandBrake"
        keyword          = "handbrake"
        cpe_patterns     = @("handbrake:handbrake")
    }
    @{
        app              = "Audacity"
        registry_pattern = "Audacity"
        keyword          = "audacity"
        cpe_patterns     = @("audacityteam:audacity")
    }
    @{
        app              = "qBittorrent"
        registry_pattern = "qBittorrent"
        keyword          = "qbittorrent"
        cpe_patterns     = @("qbittorrent:qbittorrent")
    }
    @{
        app              = "Blender"
        registry_pattern = "Blender"
        keyword          = "blender"
        cpe_patterns     = @("blender:blender")
    }
    @{
        app              = "Calibre"
        registry_pattern = "calibre"
        keyword          = "calibre ebook"
        cpe_patterns     = @("calibre-ebook:calibre")
    }
    @{
        app              = "Sumatra PDF"
        registry_pattern = "SumatraPDF"
        keyword          = "sumatrapdf"
        cpe_patterns     = @("sumatrapdfreader:sumatrapdf")
    }
    @{
        app              = "IrfanView"
        registry_pattern = "IrfanView"
        keyword          = "irfanview"
        cpe_patterns     = @("irfanview:irfanview")
    }
    @{
        app              = "ShareX"
        registry_pattern = "ShareX"
        keyword          = "sharex"
        cpe_patterns     = @("getsharex:sharex")
    }
    @{
        app              = "PowerShell 7"
        registry_pattern = "PowerShell 7"
        keyword          = "powershell"
        cpe_patterns     = @("microsoft:powershell", "microsoft:powershell_core")
    }
    @{
        app              = ".NET Runtime"
        registry_pattern = "Microsoft \\.NET Runtime"
        keyword          = "microsoft .net"
        cpe_patterns     = @("microsoft:.net", "microsoft:.net_framework")
    }
    @{
        app              = "Go Programming Language"
        registry_pattern = "Go Programming Language"
        keyword          = "golang"
        cpe_patterns     = @("golang:go")
    }
    @{
        app              = "Rust"
        registry_pattern = "^Rust "
        keyword          = "rust programming language"
        cpe_patterns     = @("rust-lang:rust")
    }
    @{
        app              = "Ruby"
        registry_pattern = "Ruby"
        keyword          = "ruby programming language"
        cpe_patterns     = @("ruby-lang:ruby")
    }
    @{
        app              = "R for Windows"
        registry_pattern = "R for Windows"
        keyword          = "r project statistical computing"
        cpe_patterns     = @("r-project:r")
    }
    @{
        app              = "Grafana"
        registry_pattern = "Grafana"
        keyword          = "grafana"
        cpe_patterns     = @("grafana:grafana")
    }
    @{
        app              = "Elasticsearch"
        registry_pattern = "Elasticsearch"
        keyword          = "elasticsearch"
        cpe_patterns     = @("elastic:elasticsearch")
    }
    @{
        app              = "PostgreSQL"
        registry_pattern = "PostgreSQL"
        keyword          = "postgresql"
        cpe_patterns     = @("postgresql:postgresql")
    }
    @{
        app              = "MySQL"
        registry_pattern = "MySQL Server"
        keyword          = "mysql server"
        cpe_patterns     = @("oracle:mysql", "mysql:mysql")
    }
    @{
        app              = "MariaDB"
        registry_pattern = "MariaDB"
        keyword          = "mariadb"
        cpe_patterns     = @("mariadb:mariadb")
    }
    @{
        app              = "Apache HTTP Server"
        registry_pattern = "Apache HTTP Server"
        keyword          = "apache http server"
        cpe_patterns     = @("apache:http_server")
    }
    @{
        app              = "Nginx"
        registry_pattern = "nginx"
        keyword          = "nginx"
        cpe_patterns     = @("f5:nginx", "nginx:nginx")
    }
    @{
        app              = "cURL"
        registry_pattern = "curl"
        keyword          = "curl"
        cpe_patterns     = @("haxx:curl", "haxx:libcurl")
    }
    @{
        app              = "OpenSSL"
        registry_pattern = "OpenSSL"
        keyword          = "openssl"
        cpe_patterns     = @("openssl:openssl")
    }
    @{
        app              = "GPG4Win"
        registry_pattern = "Gpg4win"
        keyword          = "gpg4win"
        cpe_patterns     = @("gpg4win:gpg4win", "gnupg:gnupg")
    }
    @{
        app              = "WireGuard"
        registry_pattern = "WireGuard"
        keyword          = "wireguard"
        cpe_patterns     = @("wireguard:wireguard")
    }
    @{
        app              = "Nmap"
        registry_pattern = "Nmap"
        keyword          = "nmap"
        cpe_patterns     = @("nmap:nmap")
    }
    @{
        app              = "Visual Studio"
        registry_pattern = "Microsoft Visual Studio 20"
        keyword          = "microsoft visual studio"
        cpe_patterns     = @("microsoft:visual_studio", "microsoft:visual_studio_2022", "microsoft:visual_studio_2019")
    }
    @{
        app              = "JetBrains IntelliJ IDEA"
        registry_pattern = "IntelliJ IDEA"
        keyword          = "intellij idea"
        cpe_patterns     = @("jetbrains:intellij_idea")
    }
    @{
        app              = "JetBrains PyCharm"
        registry_pattern = "JetBrains PyCharm"
        keyword          = "jetbrains pycharm"
        cpe_patterns     = @("jetbrains:pycharm")
    }
    @{
        app              = "JetBrains WebStorm"
        registry_pattern = "JetBrains WebStorm"
        keyword          = "jetbrains webstorm"
        cpe_patterns     = @("jetbrains:webstorm")
    }
    @{
        app              = "Eclipse IDE"
        registry_pattern = "Eclipse IDE"
        keyword          = "eclipse ide"
        cpe_patterns     = @("eclipse:eclipse_ide")
    }
    @{
        app              = "Terraform"
        registry_pattern = "Terraform"
        keyword          = "hashicorp terraform"
        cpe_patterns     = @("hashicorp:terraform")
    }
    @{
        app              = "Vagrant"
        registry_pattern = "Vagrant"
        keyword          = "hashicorp vagrant"
        cpe_patterns     = @("hashicorp:vagrant")
    }
    @{
        app              = "HashiCorp Packer"
        registry_pattern = "HashiCorp Packer"
        keyword          = "hashicorp packer"
        cpe_patterns     = @("hashicorp:packer")
    }
    @{
        app              = "HashiCorp Vault"
        registry_pattern = "HashiCorp Vault"
        keyword          = "hashicorp vault"
        cpe_patterns     = @("hashicorp:vault")
    }
    @{
        app              = "FFmpeg"
        registry_pattern = "FFmpeg"
        keyword          = "ffmpeg"
        cpe_patterns     = @("ffmpeg:ffmpeg")
    }
    @{
        app              = "ImageMagick"
        registry_pattern = "ImageMagick"
        keyword          = "imagemagick"
        cpe_patterns     = @("imagemagick:imagemagick")
    }
    @{
        app              = "Ghidra"
        registry_pattern = "Ghidra"
        keyword          = "ghidra nsa"
        cpe_patterns     = @("nsa:ghidra")
    }
    @{
        app              = "Sysinternals Suite"
        registry_pattern = "Sysinternals"
        keyword          = "sysinternals"
        cpe_patterns     = @("microsoft:sysinternals")
    }
    @{
        app              = "Microsoft SQL Server Management Studio"
        registry_pattern = "SQL Server Management Studio"
        keyword          = "sql server management studio"
        cpe_patterns     = @("microsoft:sql_server_management_studio")
    }
    @{
        app              = "DBeaver"
        registry_pattern = "DBeaver"
        keyword          = "dbeaver"
        cpe_patterns     = @("dbeaver:dbeaver")
    }
    @{
        app              = "PeaZip"
        registry_pattern = "PeaZip"
        keyword          = "peazip"
        cpe_patterns     = @("peazip:peazip", "peazip_project:peazip")
    }
    @{
        app              = "Greenshot"
        registry_pattern = "Greenshot"
        keyword          = "greenshot"
        cpe_patterns     = @("greenshot:greenshot")
    }
    @{
        app              = "VeraCrypt"
        registry_pattern = "VeraCrypt"
        keyword          = "veracrypt"
        cpe_patterns     = @("idrix:veracrypt")
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
        Query the NVD CVE API with a keyword search, paginating to retrieve ALL
        matching vulnerabilities.
    #>
    param(
        [string]$Keyword
    )

    $encodedKeyword = [Uri]::EscapeDataString($Keyword)
    $pageSize       = 2000          # NVD API v2.0 maximum
    $startIndex     = 0
    $allVulns       = [System.Collections.Generic.List[object]]::new()
    $totalResults   = $null

    $headers = @{ "Accept" = "application/json" }
    if ($NvdApiKey) { $headers["apiKey"] = $NvdApiKey }

    do {
        $url = "${NvdApiBase}?keywordSearch=${encodedKeyword}&resultsPerPage=${pageSize}&startIndex=${startIndex}"

        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -TimeoutSec 60 -ErrorAction Stop
        } catch {
            Write-Warning "  NVD API request failed for '${Keyword}' (startIndex=${startIndex}): $($_.Exception.Message)"
            # Return whatever we have so far rather than discarding partial data
            break
        }

        if ($null -eq $totalResults -and $response.PSObject.Properties['totalResults']) {
            $totalResults = [int]$response.totalResults
        }

        if ($response.PSObject.Properties['vulnerabilities'] -and $response.vulnerabilities.Count -gt 0) {
            foreach ($v in $response.vulnerabilities) { $allVulns.Add($v) }
        }

        $startIndex += $pageSize

        # Pause between pages to respect rate limits (skip if we are done)
        if ($null -ne $totalResults -and $startIndex -lt $totalResults) {
            Start-Sleep -Seconds $RequestDelaySec
        }
    } while ($null -ne $totalResults -and $startIndex -lt $totalResults)

    # Return a synthetic response object matching the original shape
    return @{
        totalResults    = if ($null -ne $totalResults) { $totalResults } else { $allVulns.Count }
        vulnerabilities = $allVulns
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
        try {
            $cve = $vuln.cve

            # ---- Determine severity ----
            # Use .PSObject.Properties[...].Value for every access on the
            # deserialized NVD JSON to avoid PropertyNotFoundException under
            # Set-StrictMode -Version Latest (PS 5.1 strict mode).
            $severity = $null
            $metrics  = $null
            if ($cve.PSObject.Properties['metrics']) { $metrics = $cve.metrics }

            if ($metrics) {
                # Try CVSS v4.0, v3.1, v3.0 (baseSeverity lives inside cvssData)
                foreach ($metricKey in @('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30')) {
                    if ($metrics.PSObject.Properties[$metricKey]) {
                        $metricArray = $metrics.PSObject.Properties[$metricKey].Value
                        if ($metricArray -and @($metricArray).Count -gt 0) {
                            $entry0 = @($metricArray)[0]
                            if ($entry0.PSObject.Properties['cvssData'] -and
                                $entry0.cvssData.PSObject.Properties['baseSeverity']) {
                                $severity = $entry0.cvssData.baseSeverity
                                break
                            }
                        }
                    }
                }
                # Fallback: CVSS v2 -- baseSeverity sits at the metric level
                if (-not $severity -and $metrics.PSObject.Properties['cvssMetricV2']) {
                    $v2Array = $metrics.PSObject.Properties['cvssMetricV2'].Value
                    if ($v2Array -and @($v2Array).Count -gt 0) {
                        $v2metric = @($v2Array)[0]
                        if ($v2metric.PSObject.Properties['baseSeverity']) {
                            $severity = $v2metric.baseSeverity
                        }
                    }
                }
            }

            if (-not $severity -or $severity -notin @("CRITICAL", "HIGH")) { continue }
            $rank = $severityRank[$severity]

            # ---- Walk configuration nodes ----
            if (-not ($cve.PSObject.Properties['configurations'] -and $cve.configurations)) { continue }

            foreach ($config in $cve.configurations) {
                if (-not ($config.PSObject.Properties['nodes'] -and $config.nodes)) { continue }
                foreach ($node in $config.nodes) {
                    # Collect cpeMatch entries from the node and any children
                    $allMatches = [System.Collections.Generic.List[object]]::new()
                    if ($node.PSObject.Properties['cpeMatch'] -and $node.cpeMatch) {
                        foreach ($m in $node.cpeMatch) { $allMatches.Add($m) }
                    }
                    if ($node.PSObject.Properties['children'] -and $node.children) {
                        foreach ($child in $node.children) {
                            if ($child.PSObject.Properties['cpeMatch'] -and $child.cpeMatch) {
                                foreach ($m in $child.cpeMatch) { $allMatches.Add($m) }
                            }
                        }
                    }

                    foreach ($m in $allMatches) {
                        if (-not ($m.PSObject.Properties['vulnerable'] -and $m.vulnerable)) { continue }
                        if (-not ($m.PSObject.Properties['versionEndExcluding'] -and $m.versionEndExcluding)) { continue }

                        $criteria = if ($m.PSObject.Properties['criteria']) { $m.criteria } else { '' }
                        if (-not (Test-CpeMatch -CpeCriteria $criteria -CpePatterns $CpePatterns)) {
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
        } catch {
            # Skip CVEs with unexpected structure rather than aborting the run
            $cveId = if ($vuln -and $vuln.PSObject.Properties['cve'] -and
                         $vuln.cve.PSObject.Properties['id']) { $vuln.cve.id } else { 'unknown' }
            Write-Verbose "  Skipping $cveId -- $($_.Exception.Message)"
            continue
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

    $response = Invoke-NvdApiQuery -Keyword $tracked.keyword

    $best = $null
    if ($response -and $response.vulnerabilities -and $response.vulnerabilities.Count -gt 0) {
        Write-Host "($($response.totalResults) total, $($response.vulnerabilities.Count) fetched) " -NoNewline -ForegroundColor DarkGray
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
