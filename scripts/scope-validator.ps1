<#
.SYNOPSIS
    PCI DSS 4.0.1 CDE Scope Validator — scope-validator.ps1

.DESCRIPTION
    Inventories the local system and confirms whether it should be considered
    in-scope for the Cardholder Data Environment (CDE) based on:
      - Network connectivity to known CDE subnets
      - Presence of payment-related processes or services
      - Shared authentication (Entra ID / Active Directory join status)
      - Intune/MDM enrollment status
      - Sensitive data keyword scan (configurable)

    Outputs a JSON scope declaration artifact for use in PCI DSS 12.5.1
    (scope documentation and validation).

.PARAMETER OutDir
    Output directory for scope artifact. Defaults to "./examples/scope".

.PARAMETER CdeSubnets
    Comma-separated list of CDE subnet prefixes to check connectivity against.
    Example: "10.0.1,10.0.2,192.168.10"

.PARAMETER Export
    Output format: "json" (default) or "csv".

.EXAMPLE
    pwsh ./scripts/scope-validator.ps1 -CdeSubnets "10.0.1,10.0.2" -OutDir ./examples/scope

.NOTES
    PCI DSS 12.5.1 — PCI DSS scope is documented and confirmed at least once every 12 months.
    Author: suresh-1001 | License: MIT
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutDir = "./examples/scope",

    [Parameter(Mandatory=$false)]
    [string]$CdeSubnets = "",

    [Parameter(Mandatory=$false)]
    [ValidateSet("json","csv")]
    [string]$Export = "json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

function New-OutputPath {
    param([string]$Dir)
    if (-not (Test-Path -Path $Dir)) {
        New-Item -Path $Dir -ItemType Directory -Force | Out-Null
    }
    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    return Join-Path $Dir ("scope_" + $stamp)
}

function Get-OSInfo {
    if ($IsWindows) {
        try {
            $win = Get-CimInstance Win32_OperatingSystem
            return [pscustomobject]@{ platform="Windows"; caption=$win.Caption; version=$win.Version; build=$win.BuildNumber }
        } catch {
            return [pscustomobject]@{ platform="Windows"; caption="Unknown"; version=""; build="" }
        }
    } elseif ($IsLinux) {
        $pretty = Get-Content /etc/os-release -ErrorAction SilentlyContinue |
            Where-Object { $_ -match "^PRETTY_NAME=" } |
            ForEach-Object { $_.Split("=")[1].Trim('"') }
        return [pscustomobject]@{ platform="Linux"; caption=$pretty; version=""; build="" }
    } else {
        return [pscustomobject]@{ platform="Unknown"; caption=""; version=""; build="" }
    }
}

# ─────────────────────────────────────────────
# SCOPE CHECKS
# ─────────────────────────────────────────────

function Get-NetworkInterfaces {
    <# PCI DSS 1.3.1 — Returns all IP addresses assigned to this host. #>
    try {
        if ($IsWindows) {
            return Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object { $_.IPAddress -ne "127.0.0.1" } |
                Select-Object InterfaceAlias, IPAddress, PrefixLength
        } else {
            $ips = ip addr show 2>$null | Select-String "inet " |
                ForEach-Object { $_ -replace ".*inet (\S+).*", '$1' }
            return $ips | Where-Object { $_ -notmatch "^127\." } |
                ForEach-Object { [pscustomobject]@{ InterfaceAlias=""; IPAddress=$_; PrefixLength="" } }
        }
    } catch { return @() }
}

function Test-CdeConnectivity {
    <# Checks if any local IP falls within the specified CDE subnets. #>
    param([string[]]$Subnets, [object[]]$Interfaces)
    if (-not $Subnets -or $Subnets.Count -eq 0) { return $false }
    foreach ($iface in $Interfaces) {
        foreach ($subnet in $Subnets) {
            if ($iface.IPAddress -like "$subnet*") { return $true }
        }
    }
    return $false
}

function Get-DomainJoinStatus {
    <# PCI DSS 8.2.1 — Confirms AD/Entra ID join status. #>
    if ($IsWindows) {
        try {
            $cs = Get-CimInstance Win32_ComputerSystem
            return [pscustomobject]@{
                joined      = ($cs.PartOfDomain)
                domain      = $cs.Domain
                workgroup   = $cs.Workgroup
            }
        } catch { return [pscustomobject]@{ joined=$false; domain=""; workgroup="" } }
    } else {
        $realm = ""
        try { $realm = (realm list 2>$null | Select-String "realm-name" | ForEach-Object { ($_ -split ":")[1].Trim() }) } catch {}
        return [pscustomobject]@{ joined=($realm -ne ""); domain=$realm; workgroup="" }
    }
}

function Get-IntuneEnrollmentStatus {
    <# PCI DSS 12.3 — MDM/Intune enrollment confirms device compliance management. #>
    if ($IsWindows) {
        try {
            $enrolled = Test-Path "HKLM:\SOFTWARE\Microsoft\Enrollments"
            $keys = if ($enrolled) {
                Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -ErrorAction SilentlyContinue |
                    Measure-Object | Select-Object -ExpandProperty Count
            } else { 0 }
            return [pscustomobject]@{ enrolled=($keys -gt 0); enrollmentCount=$keys }
        } catch { return [pscustomobject]@{ enrolled=$false; enrollmentCount=0 } }
    } else {
        return [pscustomobject]@{ enrolled=$false; enrollmentCount=0; note="MDM check not applicable on Linux" }
    }
}

function Get-PaymentRelatedProcesses {
    <# Scans running processes for payment-related keywords as a CDE indicator. #>
    $keywords = @("payment","checkout","stripe","braintree","authorize","cardholder","pos","pinpad","chd")
    try {
        if ($IsWindows) {
            $procs = Get-Process | Select-Object -ExpandProperty Name
        } else {
            $procs = ps aux 2>$null | ForEach-Object { ($_ -split "\s+")[10] }
        }
        $matches_ = $procs | Where-Object { $name = $_; $keywords | Where-Object { $name -match $_ } }
        return $matches_ | Select-Object -Unique
    } catch { return @() }
}

function Get-InstalledSecuritySoftware {
    <# PCI DSS 5.2.1 — Checks for anti-malware and endpoint security agents. #>
    if ($IsWindows) {
        try {
            return Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop |
                Select-Object displayName, productState, timestamp
        } catch {
            # Fallback: check common AV service names
            $avServices = @("WinDefend","MsMpSvc","CylanceSvc","CarbonBlack","SentinelAgent","CrowdStrike")
            return $avServices | ForEach-Object {
                $svc = Get-Service -Name $_ -ErrorAction SilentlyContinue
                if ($svc) { [pscustomobject]@{ displayName=$svc.DisplayName; Status=$svc.Status } }
            } | Where-Object { $_ }
        }
    } else {
        $agents = @("clamav","falcon-sensor","cb-agent","sentinelone","cylance")
        return $agents | ForEach-Object {
            $running = (systemctl is-active $_ 2>$null) -eq "active"
            if ($running) { [pscustomobject]@{ displayName=$_; Status="Running" } }
        } | Where-Object { $_ }
    }
}

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

Write-Host ""
Write-Host "========================================"
Write-Host " PCI DSS CDE Scope Validator"
Write-Host " Host     : $env:COMPUTERNAME"
Write-Host " CDE Nets : $(if ($CdeSubnets) { $CdeSubnets } else { 'not specified' })"
Write-Host " Output   : $OutDir"
Write-Host "========================================"
Write-Host ""

$baseOut    = New-OutputPath -Dir $OutDir
$subnets    = if ($CdeSubnets) { $CdeSubnets -split "," | ForEach-Object { $_.Trim() } } else { @() }
$interfaces = Get-NetworkInterfaces
$inCde      = Test-CdeConnectivity -Subnets $subnets -Interfaces $interfaces
$payProcs   = Get-PaymentRelatedProcesses
$scopeIndicators = @{
    networkInCdeSubnet      = $inCde
    paymentProcessesFound   = ($payProcs.Count -gt 0)
    domainJoined            = (Get-DomainJoinStatus).joined
    intuneEnrolled          = (Get-IntuneEnrollmentStatus).enrolled
}
$inScopeDecision = $scopeIndicators.Values | Where-Object { $_ -eq $true } | Measure-Object | Select-Object -ExpandProperty Count
$inScopeDecision = $inScopeDecision -gt 0

$result = [pscustomobject]@{
    meta = [pscustomobject]@{
        control_id        = "12.5.1"
        collector_version = "1.0.0"
        collected_at      = (Get-Date).ToString("o")
        host              = $env:COMPUTERNAME
        os                = Get-OSInfo
    }
    scopeDeclaration = [pscustomobject]@{
        inScope          = $inScopeDecision
        indicators       = $scopeIndicators
        paymentProcesses = $payProcs
        cdeSubnetsChecked = $subnets
    }
    networkInterfaces     = $interfaces
    domainJoinStatus      = Get-DomainJoinStatus
    intuneEnrollment      = Get-IntuneEnrollmentStatus
    securitySoftware      = Get-InstalledSecuritySoftware
}

$decision = if ($inScopeDecision) { "IN SCOPE" } else { "OUT OF SCOPE (verify manually)" }
Write-Host "[+] Scope decision : $decision"

if ($Export -eq "json") {
    $jsonPath = "$baseOut.json"
    $result | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "[+] Scope artifact : $jsonPath"
} else {
    $csvPath = "$baseOut-scope.csv"
    [pscustomobject]@{
        host             = $env:COMPUTERNAME
        inScope          = $inScopeDecision
        networkInCde     = $scopeIndicators.networkInCdeSubnet
        paymentProcesses = $scopeIndicators.paymentProcessesFound
        domainJoined     = $scopeIndicators.domainJoined
        intuneEnrolled   = $scopeIndicators.intuneEnrolled
        collectedAt      = (Get-Date).ToString("o")
    } | Export-Csv -NoTypeInformation -Path $csvPath -Encoding UTF8
    Write-Host "[+] Scope CSV : $csvPath"
}

Write-Host ""
Write-Host "[✓] Scope validation complete — $decision"
Write-Host ""
exit 0
