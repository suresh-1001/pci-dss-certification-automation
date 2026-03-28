<#
.SYNOPSIS
    PCI DSS 4.0.1 Evidence Collector — collect-evidence.ps1

.DESCRIPTION
    Collects evidence for a specified PCI DSS control from local or remote systems.
    Outputs normalized JSON or CSV artifacts with metadata (control_id, host, timestamp, os).
    Designed for use in fintech audit pipelines targeting Windows, Linux, and macOS.

.PARAMETER Control
    PCI DSS control ID to collect evidence for (e.g. "8.1.1", "10.2.1").
    Defaults to "8.1.1".

.PARAMETER Export
    Output format: "json" (default) or "csv".

.PARAMETER OutDir
    Output directory for evidence artifacts. Defaults to "./examples".

.PARAMETER Systems
    Comma-separated list of system types in scope (e.g. "Windows,Ubuntu,Firewalls").
    Used for metadata tagging only in this script — extend collectors per system type as needed.

.EXAMPLE
    pwsh ./scripts/collect-evidence.ps1 -Control "8.1.1" -Export json -OutDir ./examples/8.1.1

.EXAMPLE
    .\scripts\collect-evidence.ps1 -Control "10.2.1" -Systems "Windows,Ubuntu,Firewalls" -Export json -OutDir .\examples\10.2.1

.NOTES
    All output uses synthetic/redacted data in examples.
    Never commit raw log data, keys, or customer PII.
    Author: suresh-1001 | License: MIT
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Control = "8.1.1",

    [Parameter(Mandatory=$false)]
    [ValidateSet("json","csv")]
    [string]$Export = "json",

    [Parameter(Mandatory=$false)]
    [string]$OutDir = "./examples",

    [Parameter(Mandatory=$false)]
    [string]$Systems = "Windows"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

function New-OutputPath {
    <# Creates output directory if needed and returns a timestamped base path. #>
    param([string]$Dir)
    if (-not (Test-Path -Path $Dir)) {
        New-Item -Path $Dir -ItemType Directory -Force | Out-Null
    }
    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    return Join-Path $Dir ("evidence_" + $stamp)
}

function Get-OSInfo {
    <# Returns OS platform, caption, version, and build number. #>
    if ($IsWindows) {
        try {
            $win = Get-CimInstance Win32_OperatingSystem
            return [pscustomobject]@{
                platform = "Windows"
                caption  = $win.Caption
                version  = $win.Version
                build    = $win.BuildNumber
            }
        } catch {
            return [pscustomobject]@{ platform = "Windows"; caption = "Unknown"; version = ""; build = "" }
        }
    } elseif ($IsLinux) {
        $pretty = Get-Content -Path /etc/os-release -ErrorAction SilentlyContinue |
            Where-Object { $_ -match "^PRETTY_NAME=" } |
            ForEach-Object { $_.Split("=")[1].Trim('"') }
        return [pscustomobject]@{ platform = "Linux"; caption = $pretty; version = ""; build = "" }
    } elseif ($IsMacOS) {
        $ver = (sw_vers -productVersion) 2>$null
        return [pscustomobject]@{ platform = "macOS"; caption = "macOS"; version = $ver; build = "" }
    } else {
        return [pscustomobject]@{ platform = "Unknown"; caption = ""; version = ""; build = "" }
    }
}

# ─────────────────────────────────────────────
# EVIDENCE COLLECTORS
# ─────────────────────────────────────────────

function Get-PasswordPolicy {
    <#
    PCI DSS 8.3.6 — Passwords meet minimum length/complexity requirements.
    Collects local password policy via 'net accounts' (Windows) or /etc/login.defs (Linux).
    #>
    if ($IsWindows) {
        $policy = @{}
        try { $net = net accounts } catch { $net = @() }
        $net | ForEach-Object {
            if ($_ -match "(\S.+?)\s{2,}(\S.*)") {
                $policy[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        return $policy
    } else {
        $defs = @{}
        $path = "/etc/login.defs"
        if (Test-Path $path) {
            Get-Content $path |
                Where-Object { $_ -and $_ -notmatch "^#" } |
                ForEach-Object {
                    if ($_ -match "^\s*([A-Z_]+)\s+(.+)$") {
                        $defs[$matches[1]] = $matches[2]
                    }
                }
        }
        return $defs
    }
}

function Get-AdminGroup {
    <#
    PCI DSS 7.2.1 / 8.2.1 — Privileged access limited to authorized users.
    Collects local Administrators group (Windows) or sudo/wheel group members (Linux).
    #>
    if ($IsWindows) {
        try {
            return Get-LocalGroupMember -Group "Administrators" |
                Select-Object -ExpandProperty Name
        } catch { return @() }
    } else {
        $sudoers = @()

        # /etc/sudoers (may require elevation)
        try {
            if (Test-Path "/etc/sudoers") {
                $sudoers += Get-Content "/etc/sudoers" -ErrorAction Stop |
                    Where-Object { $_ -notmatch "^#" -and $_ -match "ALL=\(ALL\)" }
            }
        } catch { }

        # Drop-in files under /etc/sudoers.d
        try {
            Get-ChildItem "/etc/sudoers.d" -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $sudoers += Get-Content $_.FullName -ErrorAction Stop |
                        Where-Object { $_ -notmatch "^#" -and $_ -match "ALL=\(ALL\)" }
                } catch { }
            }
        } catch { }

        # Fallback: group database
        if (Test-Path "/etc/group") {
            $sudoers += Get-Content "/etc/group" |
                Where-Object { $_ -match "^(sudo|wheel):" }
        }

        return $sudoers
    }
}

function Get-LocalUsersSummary {
    <#
    PCI DSS 8.2.1 — All user IDs and accounts managed throughout lifecycle.
    Collects local user accounts with enabled/password status (Windows) or /etc/passwd (Linux).
    #>
    if ($IsWindows) {
        try {
            return Get-LocalUser |
                Select-Object Name, Enabled, PasswordRequired, PasswordExpires, LastLogon
        } catch { return @() }
    } else {
        try {
            return Get-Content /etc/passwd | ForEach-Object {
                $p = $_.Split(":")
                [pscustomobject]@{
                    Name  = $p[0]
                    UID   = $p[2]
                    GID   = $p[3]
                    Home  = $p[5]
                    Shell = $p[6]
                }
            }
        } catch { return @() }
    }
}

function Get-LastLoginActivity {
    <#
    PCI DSS 10.2.1 — Audit log evidence of individual user access.
    Returns last logon info for Windows users; 'last' command output on Linux.
    #>
    if ($IsWindows) {
        try {
            return Get-LocalUser | Select-Object Name, LastLogon, Enabled
        } catch { return @() }
    } else {
        try {
            $last = last -n 20 2>$null
            return $last
        } catch { return @() }
    }
}

# ─────────────────────────────────────────────
# MAIN — BUILD EVIDENCE PACKAGE
# ─────────────────────────────────────────────

Write-Host ""
Write-Host "========================================"
Write-Host " PCI DSS Evidence Collector"
Write-Host " Control  : $Control"
Write-Host " Systems  : $Systems"
Write-Host " Format   : $Export"
Write-Host " Output   : $OutDir"
Write-Host "========================================"
Write-Host ""

$baseOut = New-OutputPath -Dir $OutDir

# Metadata block — included in every evidence artifact
$meta = [pscustomobject]@{
    control_id       = $Control
    collector_version = "1.1.0"
    collected_at     = (Get-Date).ToString("o")   # ISO 8601
    host             = $env:COMPUTERNAME
    systems_in_scope = ($Systems -split "," | ForEach-Object { $_.Trim() })
    os               = Get-OSInfo
}

# Evidence payload — extend with additional collectors per control as needed
$result = [pscustomobject]@{
    meta           = $meta
    passwordPolicy = Get-PasswordPolicy
    adminGroup     = Get-AdminGroup
    localUsers     = Get-LocalUsersSummary
    lastLogins     = Get-LastLoginActivity
}

# ─────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────

if ($Export -eq "json") {
    $jsonPath = "$baseOut.json"
    $result | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "[+] JSON evidence written : $jsonPath"
} else {
    # CSV — export users and admin group as separate files
    $usersPath = "$baseOut-users.csv"
    $adminPath = "$baseOut-admins.csv"

    $result.localUsers | Export-Csv -NoTypeInformation -Path $usersPath -Encoding UTF8
    $result.adminGroup | ForEach-Object { [pscustomobject]@{ Member = $_ } } |
        Export-Csv -NoTypeInformation -Path $adminPath -Encoding UTF8

    Write-Host "[+] CSV users written     : $usersPath"
    Write-Host "[+] CSV admins written    : $adminPath"
}

Write-Host ""
Write-Host "[✓] Evidence collection complete for control $Control"
Write-Host ""
exit 0
