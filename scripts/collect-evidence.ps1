
param(
  [Parameter(Mandatory=$false)][string]$Control = "8.1.1",
  [Parameter(Mandatory=$false)][ValidateSet("json","csv")][string]$Export = "json",
  [Parameter(Mandatory=$false)][string]$OutDir = "./examples"
)

function New-OutputPath {
  param([string]$Dir)
  if (-not (Test-Path -Path $Dir)) { New-Item -Path $Dir -ItemType Directory -Force | Out-Null }
  $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
  $base = Join-Path $Dir ("evidence_" + $stamp)
  return $base
}

function Get-OSInfo {
  if ($IsWindows) {
    try {
      $win = Get-CimInstance Win32_OperatingSystem
      return [pscustomobject]@{ platform="Windows"; caption=$win.Caption; version=$win.Version; build=$win.BuildNumber }
    } catch { return [pscustomobject]@{ platform="Windows"; caption="Unknown"; version=""; build="" } }
  } elseif ($IsLinux) {
    $pretty = (Get-Content -Path /etc/os-release -ErrorAction SilentlyContinue | Where-Object { $_ -match "^PRETTY_NAME=" } | ForEach-Object { $_.Split("=")[1].Trim('"') })
    return [pscustomobject]@{ platform="Linux"; caption=$pretty; version=""; build="" }
  } elseif ($IsMacOS) {
    $ver = (sw_vers -productVersion) 2>$null
    return [pscustomobject]@{ platform="macOS"; caption="macOS"; version=$ver; build="" }
  } else {
    return [pscustomobject]@{ platform="Unknown"; caption=""; version=""; build="" }
  }
}

function Get-PasswordPolicy {
  if ($IsWindows) {
    $policy = @{}
    try { $net = net accounts } catch { $net = @() }
    $net | ForEach-Object {
      if ($_ -match "(\S.+?)\s{2,}(\S.*)") { $policy[$matches[1].Trim()] = $matches[2].Trim() }
    }
    return $policy
  } else {
    $defs = @{}; $path = "/etc/login.defs"
    if (Test-Path $path) {
      Get-Content $path | Where-Object { $_ -and $_ -notmatch "^#" } | ForEach-Object {
        if ($_ -match "^\s*([A-Z_]+)\s+(.+)$") { $defs[$matches[1]] = $matches[2] }
      }
    }
    return $defs
  }
}

function Get-AdminGroup {
  if ($IsWindows) {
    try { (Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name) } catch { @() }
  } else {
    $sudoers = @()
    if (Test-Path "/etc/sudoers") {
      $sudoers += (Get-Content /etc/sudoers | Where-Object {$_ -notmatch "^#" -and $_ -match "ALL=\(ALL\)"})
    }
    if (Test-Path "/etc/group") {
      $sudoers += (Get-Content /etc/group | Where-Object {$_ -match "^sudo:" -or $_ -match "^wheel:"})
    }
    $sudoers
  }
}

function Get-LocalUsersSummary {
  if ($IsWindows) {
    try { Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordExpires } catch { @() }
  } else {
    try {
      Get-Content /etc/passwd | ForEach-Object {
        $p = $_.Split(":"); [pscustomobject]@{ Name=$p[0]; UID=$p[2]; GID=$p[3]; Home=$p[5]; Shell=$p[6] }
      }
    } catch { @() }
  }
}

$baseOut = New-OutputPath -Dir $OutDir
$meta = [pscustomobject]@{
  control     = $Control
  collectedAt = (Get-Date).ToString("o")
  host        = $env:COMPUTERNAME
  os          = Get-OSInfo
}

$result = [pscustomobject]@{
  meta           = $meta
  passwordPolicy = Get-PasswordPolicy
  adminGroup     = Get-AdminGroup
  localUsers     = Get-LocalUsersSummary
}

if ($Export -eq "json") {
  $jsonPath = "$baseOut.json"
  $result | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
  Write-Host "Wrote JSON evidence: $jsonPath"
} else {
  $csvPath = "$baseOut-users.csv"
  $result.localUsers | Export-Csv -NoTypeInformation -Path $csvPath -Encoding UTF8
  Write-Host "Wrote CSV evidence: $csvPath"
}
exit 0
