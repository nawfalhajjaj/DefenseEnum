# ================================
# Module: AV / EDR Detection
# Detects AV/EDR products via WSC (WMI) and running process scan.
# Mirrors: modules/antivirus.py
# ================================

# Known EDR/AV process names mapped to product labels
$script:KnownSecurityProcesses = @{
    "msmpseng.exe"        = "Windows Defender"
    "sentinelagent.exe"   = "SentinelOne"
    "sentinelone.exe"     = "SentinelOne"
    "csagent.exe"         = "CrowdStrike Falcon"
    "csfalconservice.exe" = "CrowdStrike Falcon"
    "cb.exe"              = "Carbon Black"
    "cbsensor.exe"        = "Carbon Black"
    "cylancesvc.exe"      = "Cylance PROTECT"
    "mcshield.exe"        = "McAfee"
    "ekrn.exe"            = "ESET"
    "bdagent.exe"         = "Bitdefender"
    "savservice.exe"      = "Sophos"
    "cyserver.exe"        = "Cybereason"
    "amagent.exe"         = "Trellix (FireEye)"
    "xagt.exe"            = "Trellix (FireEye)"
    "paxentsvc.exe"       = "Palo Alto Cortex XDR"
    "trapsagent.exe"      = "Palo Alto Cortex XDR"
    "wdagentservice.exe"  = "Elastic EDR"
}

# Products known to aggressively block red team tools
$script:HighRiskProducts = @(
    "CrowdStrike Falcon",
    "SentinelOne",
    "Carbon Black",
    "Palo Alto Cortex XDR",
    "Trellix (FireEye)",
    "Cybereason"
)

# ---------- WSC Query --------------------------------------------------------
# Queries Windows Security Center (root\SecurityCenter2) via WMIC.

function _Query-WSC {
    $products = @()
    try {
        Write-Source "wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState /format:list"
        $raw = & wmic /namespace:"\\root\SecurityCenter2" path AntiVirusProduct `
                    get displayName,productState /format:list 2>$null
        $current = @{}
        foreach ($line in $raw) {
            $line = $line.Trim()
            if ($line -match "^(.+?)=(.*)$") {
                $current[$Matches[1].Trim()] = $Matches[2].Trim()
            } elseif ($line -eq "" -and $current.Count -gt 0) {
                $products += $current
                $current = @{}
            }
        }
        if ($current.Count -gt 0) { $products += $current }
    } catch {
        # WSC not available or access denied - silently continue
    }
    return $products
}

# ---------- Process Scan -----------------------------------------------------
# Runs tasklist and checks for known EDR/AV agent process names.

function _Scan-Processes {
    $found = @()
    try {
        Write-Source "tasklist /fo csv /nh"
        $raw = & tasklist /fo csv /nh 2>$null
        $runningLower = ($raw -join "`n").ToLower()
        foreach ($procName in $script:KnownSecurityProcesses.Keys) {
            if ($runningLower -like "*$procName*") {
                $found += $script:KnownSecurityProcesses[$procName]
            }
        }
    } catch {
        # tasklist unavailable - silently continue
    }
    return ($found | Select-Object -Unique)
}

# ---------- Exclusion Paths Query --------------------------------------------
# Reads Defender exclusion paths from the registry.
# These paths are not scanned - dropping payloads here bypasses real-time protection.

function _Query-ExclusionPaths {
    $keyPath = "SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
    Write-Source "[HKLM\$keyPath] :: GetValueNames()"
    $paths = @()
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyPath)
        if ($null -eq $key) { return $paths }
        $paths = @($key.GetValueNames() | Where-Object { $_ -ne "" })
        $key.Close()
    } catch {
        # Access denied or key missing - silently continue
    }
    return $paths
}

# ---------- Display helper ---------------------------------------------------

function _Write-AVRow {
    param([string]$Label, [string]$Value, [string]$Risk, [string]$Detail)

    $icon = switch ($Risk) {
        "CRITICAL" { "!" } "HIGH" { "!" } "MEDIUM" { "~" }
        "LOW"      { "v" } "INFO" { "." } default   { "." }
    }
    $iconColor = switch ($Risk) {
        "CRITICAL" { "Magenta" } "HIGH" { "Red" } "MEDIUM" { "Yellow" }
        "LOW"      { "Green"   } default { "DarkGray" }
    }
    $valueColor = switch ($Risk) {
        "CRITICAL" { "Magenta" } "HIGH" { "Red" } "MEDIUM" { "Yellow" }
        "LOW"      { "Green"   } "INFO" { "Cyan" } default { "DarkGray" }
    }

    $labelPad = $Label.PadRight(28)
    Write-Host -NoNewline "    "
    Write-Host -NoNewline $icon -ForegroundColor $iconColor
    Write-Host -NoNewline "  $labelPad" -ForegroundColor White
    Write-Host $Value -ForegroundColor $valueColor
    Write-Host "         $Detail" -ForegroundColor DarkGray
}

# ---------- Main Entry -------------------------------------------------------

function Invoke-Antivirus {

    Write-Host ""
    Write-Host "--- Running antivirus ---" -ForegroundColor Magenta
    Write-Host "  Running: AV / EDR DETECTION" -ForegroundColor DarkCyan
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [*] AV / EDR Detection..." -ForegroundColor DarkGray
    Write-Host ""

    # -- Query everything first -----------------------------------------------
    $wscProducts = _Query-WSC
    $registered  = @($wscProducts | ForEach-Object {
        if ($_["displayName"]) { $_["displayName"] }
    } | Where-Object { $_ } | Select-Object -Unique)

    $edrHits      = @(_Scan-Processes)
    $allDetected  = @($registered + $edrHits | Select-Object -Unique)
    $highRisk     = @($allDetected | Where-Object { $script:HighRiskProducts -contains $_ })
    $exclusions   = @(_Query-ExclusionPaths)

    # -- Overall risk mirrors Python ------------------------------------------
    if ($highRisk.Count -gt 0) {
        $overallRisk = "CRITICAL"
    } elseif ($edrHits.Count -gt 0) {
        $overallRisk = "HIGH"
    } elseif ($registered.Count -gt 0) {
        $overallRisk = "MEDIUM"
    } else {
        $overallRisk = "LOW"
    }

    # -- Header box -----------------------------------------------------------
    $boxLine = "=" * 60
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    $title = "  AV / EDR DETECTION".PadRight(61)
    Write-Host "  |$title|" -ForegroundColor Cyan
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    Write-Host ""

    $riskColor = switch ($overallRisk) {
        "CRITICAL" { "Magenta" } "HIGH" { "Red" } "MEDIUM" { "Yellow" }
        "LOW"      { "Green"   } default { "DarkGray" }
    }
    Write-Host "     Risk:  [ $overallRisk ]" -ForegroundColor $riskColor
    Write-Host ""

    # -- 1. WSC Registered Products -------------------------------------------
    if ($registered.Count -eq 0) {
        _Write-AVRow "WSC Registered Products" "none" "INFO" `
            "Products registered with Windows Security Center."
    } else {
        foreach ($name in $registered) {
            _Write-AVRow "WSC Registered" $name "INFO" `
                "Products registered with Windows Security Center."
        }
    }

    Write-Host ""

    # -- 2. EDR Process Scan --------------------------------------------------
    if ($edrHits.Count -eq 0) {
        _Write-AVRow "EDR Processes Detected" "none" "LOW" `
            "Known EDR agent processes found in the running process list."
    } else {
        foreach ($product in $edrHits) {
            _Write-AVRow "EDR Process Found" $product "HIGH" `
                "Known EDR agent processes found in the running process list."
        }
    }

    Write-Host ""

    # -- 3. High-Risk EDR Products --------------------------------------------
    if ($highRisk.Count -eq 0) {
        _Write-AVRow "High-Risk EDR Products" "none" "LOW" `
            "These products actively hunt for offensive tooling and memory injection."
    } else {
        foreach ($product in $highRisk) {
            _Write-AVRow "High-Risk EDR" $product "CRITICAL" `
                "These products actively hunt for offensive tooling and memory injection."
        }
    }

    # -- 4. Defender Exclusion Paths ------------------------------------------
    Write-Host ""
    Write-Host "  Defender Exclusion Paths:" -ForegroundColor DarkCyan
    Write-Host ""
    if ($exclusions.Count -eq 0) {
        _Write-AVRow "Exclusion Paths" "none found" "INFO" `
            "No Defender exclusion paths configured, or access denied (requires admin)."
    } else {
        foreach ($path in $exclusions) {
            _Write-AVRow "Exclusion Path" $path "CRITICAL" `
                "Files dropped here are NOT scanned by Defender. Prime payload staging location."
        }
    }

    # -- Notes ----------------------------------------------------------------
    Write-Host ""
    Write-Host "  [Notes]" -ForegroundColor DarkCyan
    Write-Host "  - Windows Defender only    : AMSI bypass + reflective load likely sufficient." -ForegroundColor DarkGray
    Write-Host "  - CrowdStrike/SentinelOne  : Requires injection into trusted processes and PPID spoofing." -ForegroundColor DarkGray
    Write-Host "  - No EDR detected          : Standard Cobalt Strike / Havoc without heavy OPSEC may work." -ForegroundColor DarkGray
    Write-Host "  - Check audit mode         : Audit-only installs don't block, they alert - check event logs." -ForegroundColor DarkGray
    Write-Host "  - EDR exclusion paths      : Listed above. Drop payloads there to bypass real-time scanning." -ForegroundColor DarkGray
    Write-Host ""

    # -- Feed global results silently -----------------------------------------
    if ($registered.Count -eq 0) {
        $Global:Results += [PSCustomObject]@{ Module = "Antivirus"; Name = "WSC Registered Products"; Value = "none"; Risk = "INFO" }
    } else {
        foreach ($name in $registered) {
            $Global:Results += [PSCustomObject]@{ Module = "Antivirus"; Name = "WSC Registered"; Value = $name; Risk = "INFO" }
        }
    }

    if ($edrHits.Count -eq 0) {
        $Global:Results += [PSCustomObject]@{ Module = "Antivirus"; Name = "EDR Processes Detected"; Value = "none"; Risk = "LOW" }
    } else {
        foreach ($product in $edrHits) {
            $Global:Results += [PSCustomObject]@{ Module = "Antivirus"; Name = "EDR Process Found"; Value = $product; Risk = "HIGH" }
        }
    }

    if ($highRisk.Count -eq 0) {
        $Global:Results += [PSCustomObject]@{ Module = "Antivirus"; Name = "High-Risk EDR Products"; Value = "none"; Risk = "LOW" }
    } else {
        foreach ($product in $highRisk) {
            $Global:Results += [PSCustomObject]@{ Module = "Antivirus"; Name = "High-Risk EDR"; Value = $product; Risk = "CRITICAL" }
        }
    }

    if ($exclusions.Count -eq 0) {
        $Global:Results += [PSCustomObject]@{ Module = "Antivirus"; Name = "Exclusion Paths"; Value = "none found"; Risk = "INFO" }
    } else {
        foreach ($path in $exclusions) {
            $Global:Results += [PSCustomObject]@{ Module = "Antivirus"; Name = "Exclusion Path"; Value = $path; Risk = "CRITICAL" }
        }
    }
}
