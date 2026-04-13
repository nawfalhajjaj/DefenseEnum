# ================================
# Module: Security-Related Services
# Queries the status of security-critical Windows services including
# AV, logging, firewall, EDR, and credential protection.
# Mirrors: modules/services.py
# ================================

# Ordered list - hashtables have no guaranteed order
$script:ServiceOrder = @(
    "WinDefend", "Sense", "WdNisSvc", "wscsvc",
    "EventLog", "wecsvc", "Sysmon", "Sysmon64",
    "AppIDSvc", "MpsSvc", "VaultSvc", "NgcSvc",
    "IKEEXT", "PolicyAgent",
    "CSFalconService", "SentinelAgent", "CylanceSvc", "ekrn", "SAVService"
)

# Service name -> [Description, Importance]
$script:SecurityServices = @{
    "WinDefend"       = @("Windows Defender Antivirus",            "CRITICAL")
    "Sense"           = @("Microsoft Defender for Endpoint (MDE)", "CRITICAL")
    "WdNisSvc"        = @("Windows Defender Network Inspection",   "MEDIUM")
    "wscsvc"          = @("Windows Security Center",               "MEDIUM")
    "EventLog"        = @("Windows Event Log",                     "HIGH")
    "wecsvc"          = @("Windows Event Collector",               "MEDIUM")
    "Sysmon"          = @("Sysinternals Sysmon (32-bit)",          "HIGH")
    "Sysmon64"        = @("Sysinternals Sysmon (64-bit)",          "HIGH")
    "AppIDSvc"        = @("Application Identity (AppLocker)",      "HIGH")
    "MpsSvc"          = @("Windows Firewall",                      "HIGH")
    "VaultSvc"        = @("Credential Manager",                    "MEDIUM")
    "NgcSvc"          = @("Microsoft Passport / Windows Hello",    "LOW")
    "IKEEXT"          = @("IKE/AuthIP IPSec Keying",               "MEDIUM")
    "PolicyAgent"     = @("IPSec Policy Agent",                    "MEDIUM")
    "CSFalconService" = @("CrowdStrike Falcon",                    "CRITICAL")
    "SentinelAgent"   = @("SentinelOne Agent",                     "CRITICAL")
    "CylanceSvc"      = @("Cylance PROTECT",                       "CRITICAL")
    "ekrn"            = @("ESET Kernel Service",                   "CRITICAL")
    "SAVService"      = @("Sophos Anti-Virus",                     "CRITICAL")
}

# Stopped state = favorable for attacker (EDR/logging gone)
$script:FavorableStopped = @(
    "Sense", "wecsvc", "Sysmon", "Sysmon64", "AppIDSvc",
    "CSFalconService", "SentinelAgent", "CylanceSvc", "ekrn", "SAVService"
)

# ---------- Service Query ----------------------------------------------------

function _Query-Service {
    param([string]$Name)
    Write-Source "Get-Service -Name $Name"
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        switch ($svc.Status) {
            "Running" { return "running" }
            "Stopped" { return "stopped" }
            default   { return $svc.Status.ToString().ToLower() }
        }
    } catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        return "not_installed"
    } catch {
        return "unknown"
    }
}

# ---------- Risk helpers -----------------------------------------------------

function _Get-SvcRisk {
    param([string]$SvcName, [string]$Status)
    $favorable = $script:FavorableStopped -contains $SvcName
    if ($Status -eq "running") {
        if ($favorable) { return "HIGH" } else { return "LOW" }
    }
    if ($Status -eq "stopped") {
        if ($favorable) { return "LOW" } else { return "HIGH" }
    }
    return "UNKNOWN"
}

function _Get-OverallRisk {
    param($Rows)
    if ($Rows | Where-Object { $_.Risk -eq "CRITICAL" }) { return "CRITICAL" }
    if ($Rows | Where-Object { $_.Risk -eq "HIGH"     }) { return "HIGH" }
    if ($Rows | Where-Object { $_.Risk -eq "MEDIUM"   }) { return "MEDIUM" }
    return "LOW"
}

# ---------- Display ----------------------------------------------------------

function _Write-TableRow {
    param(
        [string]$ServiceName,
        [string]$Status,
        [string]$Severity
    )

    if ($ServiceName.Length -gt 44) {
        $ServiceName = $ServiceName.Substring(0, 41) + "..."
    }
    $col1 = $ServiceName.PadRight(44)
    $col2 = $Status.PadRight(10)
    $col3 = $Severity.PadRight(10)

    $severityColor = switch ($Severity) {
        "CRITICAL" { "Magenta" }
        "HIGH"     { "Red"     }
        "MEDIUM"   { "Yellow"  }
        "LOW"      { "Green"   }
        default    { "DarkGray"}
    }

    Write-Host -NoNewline "    $col1  $col2  "
    Write-Host $col3 -ForegroundColor $severityColor
}

# ---------- Main Entry -------------------------------------------------------

function Invoke-Services {

    Write-Host ""
    Write-Host "--- Running services ---" -ForegroundColor Magenta
    Write-Host "  Running: SECURITY-RELATED SERVICES" -ForegroundColor DarkCyan
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [*] Security-Related Services..." -ForegroundColor DarkGray
    Write-Host ""

    $rows = @()

    foreach ($svcName in $script:ServiceOrder) {
        $desc       = $script:SecurityServices[$svcName][0]
        $importance = $script:SecurityServices[$svcName][1]
        $status     = _Query-Service $svcName

        if ($status -eq "not_installed") { continue }

        $risk = _Get-SvcRisk $svcName $status

        $rows += [PSCustomObject]@{
            Name       = $svcName
            Desc       = $desc
            Importance = $importance
            Status     = $status
            Risk       = $risk
        }
    }

    $overallRisk = _Get-OverallRisk $rows

    $riskColor = switch ($overallRisk) {
        "CRITICAL" { "Magenta" }
        "HIGH"     { "Red"     }
        "MEDIUM"   { "Yellow"  }
        "LOW"      { "Green"   }
        default    { "DarkGray"}
    }

    # -- Header (no border lines) ---------------------------------------------
    $h1 = "Service Name".PadRight(44)
    $h2 = "Status".PadRight(10)
    $h3 = "Severity".PadRight(10)
    Write-Host "    $h1  $h2  $h3" -ForegroundColor White
    Write-Host ""

    # -- Rows -----------------------------------------------------------------
    foreach ($r in $rows) {
        $label = "$($r.Name) ($($r.Desc))"
        _Write-TableRow $label $r.Status $r.Importance
    }

    Write-Host ""
    Write-Host "  Overall Risk: " -NoNewline
    Write-Host "[ $overallRisk ]" -ForegroundColor $riskColor
    Write-Host "  Total services found: $($rows.Count)" -ForegroundColor DarkGray

    # -- Notes ----------------------------------------------------------------
    Write-Host ""
    Write-Host "  [Notes]" -ForegroundColor DarkCyan
    Write-Host "  - Sysmon not installed     : No process/network event logging. Operate freely." -ForegroundColor DarkGray
    Write-Host "  - wecsvc stopped           : Events not forwarded to SIEM; logs remain local only." -ForegroundColor DarkGray
    Write-Host "  - EventLog stopped         : No event logging at all (rare but very loud in IR)." -ForegroundColor DarkGray
    Write-Host "  - AppIDSvc stopped         : AppLocker rules exist but are NOT enforced." -ForegroundColor DarkGray
    Write-Host "  - EDR service stopped      : Verify tamper protection is off before assuming safe." -ForegroundColor DarkGray
    Write-Host "  - WinDefend running        : Combine with defender module for full Defender picture." -ForegroundColor DarkGray
    Write-Host "  - Sense running            : MDE telemetry active; cloud-based detections in play." -ForegroundColor DarkGray
    Write-Host ""

    # -- Feed global results silently -----------------------------------------
    foreach ($r in $rows) {
        $Global:Results += [PSCustomObject]@{
            Module = "Services"
            Name   = "$($r.Name) ($($r.Desc))"
            Value  = $r.Status
            Risk   = $r.Risk
        }
    }
    $Global:Results += [PSCustomObject]@{
        Module = "Services"
        Name   = "Total Services Found"
        Value  = $rows.Count
        Risk   = "INFO"
    }
}
