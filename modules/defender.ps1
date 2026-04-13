# ================================
# Module: Windows Defender Status
# Checks Defender state, real-time/tamper protection, cloud protection,
# and signature version via registry.
# Hive: HKLM\SOFTWARE\Microsoft\Windows Defender
# Mirrors: modules/defender.py
# ================================

$script:DefenderBase = "SOFTWARE\Microsoft\Windows Defender"

# ---------- Registry helper --------------------------------------------------

function _Read-DefReg {
    param([string]$KeyPath, [string]$ValueName)
    Write-Source "[HKLM\$KeyPath] :: GetValue('$ValueName')"
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($KeyPath)
        if ($null -eq $key) { return $null }
        $val = $key.GetValue($ValueName, $null)
        $key.Close()
        return $val
    } catch {
        return $null
    }
}

# ---------- Display helper ---------------------------------------------------

function _Write-DefRow {
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

function Invoke-Defender {

    Write-Host ""
    Write-Host "--- Running defender ---" -ForegroundColor Magenta
    Write-Host "  Running: WINDOWS DEFENDER STATUS" -ForegroundColor DarkCyan
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [*] Windows Defender Status..." -ForegroundColor DarkGray
    Write-Host ""

    # -- Query all values first -----------------------------------------------
    $disabled = _Read-DefReg $script:DefenderBase "DisableAntiSpyware"
    $realtime = _Read-DefReg "$script:DefenderBase\Real-Time Protection" "DisableRealtimeMonitoring"
    $tamper   = _Read-DefReg "$script:DefenderBase\Features"             "TamperProtection"
    $cloud    = _Read-DefReg "$script:DefenderBase\Spynet"               "SpynetReporting"
    $sigVer   = _Read-DefReg "$script:DefenderBase\Signature Updates"    "AVSignatureVersion"

    # -- Build result rows ----------------------------------------------------
    $rows = @()

    # 1. Defender Disabled
    if ($null -eq $disabled) {
        $rows += [PSCustomObject]@{ Label = "Defender Disabled"; Value = "unknown"; Risk = "UNKNOWN"
            Detail = "Registry key not accessible - may require admin rights." }
    } elseif ([bool]$disabled) {
        $rows += [PSCustomObject]@{ Label = "Defender Disabled"; Value = "True"; Risk = "CRITICAL"
            Detail = "Defender is fully disabled. Likely replaced by a third-party EDR or intentionally turned off." }
    } else {
        $rows += [PSCustomObject]@{ Label = "Defender Disabled"; Value = "False"; Risk = "LOW"
            Detail = "Defender is active." }
    }

    # 2. Real-Time Protection (inverted flag: 1 = OFF)
    if ($null -eq $realtime) {
        $rows += [PSCustomObject]@{ Label = "Real-Time Protection"; Value = "unknown"; Risk = "UNKNOWN"
            Detail = "Could not read registry value." }
    } elseif ([bool]$realtime) {
        $rows += [PSCustomObject]@{ Label = "Real-Time Protection"; Value = "disabled"; Risk = "CRITICAL"
            Detail = "Real-time scanning is OFF. Files are not inspected on access." }
    } else {
        $rows += [PSCustomObject]@{ Label = "Real-Time Protection"; Value = "enabled"; Risk = "LOW"
            Detail = "Real-time protection is active." }
    }

    # 3. Tamper Protection (5=on, 4=off/HIGH, other=partial/MEDIUM)
    if ($null -eq $tamper) {
        $rows += [PSCustomObject]@{ Label = "Tamper Protection"; Value = "unknown"; Risk = "UNKNOWN"
            Detail = "Could not read TamperProtection value." }
    } elseif ($tamper -eq 5) {
        $rows += [PSCustomObject]@{ Label = "Tamper Protection"; Value = "enabled"; Risk = "LOW"
            Detail = "Tamper protection is on. Registry/service modifications by non-privileged processes are blocked." }
    } elseif ($tamper -eq 4) {
        $rows += [PSCustomObject]@{ Label = "Tamper Protection"; Value = "disabled (value=4)"; Risk = "HIGH"
            Detail = "Tamper protection is off (value=4). Defender settings can be modified without elevation." }
    } else {
        $rows += [PSCustomObject]@{ Label = "Tamper Protection"; Value = "partially off (value=$tamper)"; Risk = "MEDIUM"
            Detail = "Tamper protection is off (value=$tamper). Defender settings can be modified without elevation." }
    }

    # 4. Cloud Protection (SpynetReporting > 0 = enabled)
    $cloudOn = ($null -ne $cloud) -and ($cloud -gt 0)
    if ($cloudOn) {
        $rows += [PSCustomObject]@{ Label = "Cloud Protection"; Value = "enabled"; Risk = "LOW"
            Detail = "Cloud-delivered protection sends suspicious samples to Microsoft." }
    } else {
        $rows += [PSCustomObject]@{ Label = "Cloud Protection"; Value = "disabled"; Risk = "MEDIUM"
            Detail = "Cloud protection is off. Signature-only detection in use." }
    }

    # 5. Signature Version
    $sigValue = if ($null -eq $sigVer -or $sigVer -eq "") { "unknown" } else { $sigVer }
    $rows += [PSCustomObject]@{ Label = "Signature Version"; Value = $sigValue; Risk = "INFO"
        Detail = "Outdated signatures reduce detection capability." }

    # -- Overall risk: mirrors Python (CRITICAL > HIGH/MEDIUM > LOW) ----------
    $overallRisk = "LOW"
    foreach ($r in $rows) {
        if ($r.Risk -eq "CRITICAL")                                    { $overallRisk = "CRITICAL"; break }
        if ($r.Risk -eq "HIGH"   -and $overallRisk -ne "CRITICAL")    { $overallRisk = "HIGH" }
        if ($r.Risk -eq "MEDIUM" -and $overallRisk -notin @("CRITICAL","HIGH")) { $overallRisk = "MEDIUM" }
    }

    # -- Header box -----------------------------------------------------------
    $boxLine = "=" * 60
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    $title = "  WINDOWS DEFENDER STATUS".PadRight(61)
    Write-Host "  |$title|" -ForegroundColor Cyan
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    Write-Host ""

    $riskColor = switch ($overallRisk) {
        "CRITICAL" { "Magenta" } "HIGH" { "Red" } "MEDIUM" { "Yellow" }
        "LOW"      { "Green"   } default { "DarkGray" }
    }
    Write-Host "     Risk:  [ $overallRisk ]" -ForegroundColor $riskColor
    Write-Host ""

    # -- Rows -----------------------------------------------------------------
    foreach ($r in $rows) {
        _Write-DefRow $r.Label $r.Value $r.Risk $r.Detail
    }

    # -- Notes ----------------------------------------------------------------
    Write-Host ""
    Write-Host "  [Notes]" -ForegroundColor DarkCyan
    Write-Host "  - Real-time protection off : Drop payloads directly without in-memory evasion." -ForegroundColor DarkGray
    Write-Host "  - Tamper protection off    : Modify Defender exclusions via registry (HKLM\...\Exclusions)." -ForegroundColor DarkGray
    Write-Host "  - Cloud protection off     : Unsigned/unknown binaries less likely submitted for analysis." -ForegroundColor DarkGray
    Write-Host "  - Check signature age      : Outdated sigs mean recent payloads may evade detection." -ForegroundColor DarkGray
    Write-Host ""

    # -- Feed global results silently -----------------------------------------
    foreach ($r in $rows) {
        $Global:Results += [PSCustomObject]@{
            Module = "Defender"
            Name   = $r.Label
            Value  = $r.Value
            Risk   = $r.Risk
        }
    }
}
