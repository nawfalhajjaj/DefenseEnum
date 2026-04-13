# ================================
# Module: PowerShell Logging
# Checks Script Block Logging, Module Logging, and Transcription
# settings - the three primary PS visibility controls for defenders.
# Mirrors: modules/ps_logging.py
# ================================

$script:PSBase = "SOFTWARE\Policies\Microsoft\Windows\PowerShell"

# ---------- Registry helper --------------------------------------------------
# Reads a value from a subkey under the PS policy base.
# Returns $null if the key or value is missing (= feature not configured = OFF).

function _Read-PSReg {
    param([string]$SubKey, [string]$ValueName)
    $fullPath = "$script:PSBase\$SubKey"
    Write-Source "[HKLM\$fullPath] :: GetValue('$ValueName')"
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($fullPath)
        if ($null -eq $key) { return $null }
        $val = $key.GetValue($ValueName, $null)
        $key.Close()
        return $val
    } catch {
        return $null
    }
}

# ---------- Transcription path helper ----------------------------------------
# Only called when Transcription is enabled. Returns the configured output
# directory, or "not configured" if the value is absent.

function _Read-TranscriptionPath {
    $fullPath = "$script:PSBase\Transcription"
    Write-Source "[HKLM\$fullPath] :: GetValue('OutputDirectory')"
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($fullPath)
        if ($null -eq $key) { return "not configured" }
        $val = $key.GetValue("OutputDirectory", $null)
        $key.Close()
        if ($null -eq $val -or $val -eq "") { return "not configured" }
        return $val
    } catch {
        return "not configured"
    }
}

# ---------- Display helper ---------------------------------------------------

function _Write-PSLogRow {
    param([string]$Label, [string]$Value, [string]$Risk, [string]$Detail)

    $icon = switch ($Risk) {
        "HIGH"   { "!" } "MEDIUM" { "~" } "LOW" { "v" }
        "INFO"   { "." } default  { "." }
    }
    $iconColor = switch ($Risk) {
        "HIGH"   { "Red"     } "MEDIUM" { "Yellow" } "LOW" { "Green" }
        "INFO"   { "DarkGray"} default  { "DarkGray" }
    }
    $valueColor = switch ($Risk) {
        "HIGH"   { "Red"     } "MEDIUM" { "Yellow" } "LOW" { "Green" }
        "INFO"   { "Cyan"    } default  { "DarkGray" }
    }

    $labelPad = $Label.PadRight(32)
    Write-Host -NoNewline "    "
    Write-Host -NoNewline $icon -ForegroundColor $iconColor
    Write-Host -NoNewline "  $labelPad" -ForegroundColor White
    Write-Host $Value -ForegroundColor $valueColor
    Write-Host "         $Detail" -ForegroundColor DarkGray
}

# ---------- Main Entry -------------------------------------------------------

function Invoke-PSLogging {

    Write-Host ""
    Write-Host "--- Running ps_logging ---" -ForegroundColor Magenta
    Write-Host "  Running: POWERSHELL LOGGING" -ForegroundColor DarkCyan
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [*] PowerShell Logging..." -ForegroundColor DarkGray
    Write-Host ""

    # -- Query all values first -----------------------------------------------
    $sbl       = _Read-PSReg "ScriptBlockLogging" "EnableScriptBlockLogging"
    $sbli      = _Read-PSReg "ScriptBlockLogging" "EnableScriptBlockInvocationLogging"
    $mod       = _Read-PSReg "ModuleLogging"      "EnableModuleLogging"
    $trans     = _Read-PSReg "Transcription"      "EnableTranscription"

    # Absent key = OFF (same default behaviour as Python: missing -> False)
    $sblOn   = ($null -ne $sbl)   -and [bool]$sbl
    $sbliOn  = ($null -ne $sbli)  -and [bool]$sbli
    $modOn   = ($null -ne $mod)   -and [bool]$mod
    $transOn = ($null -ne $trans) -and [bool]$trans

    # Transcription path only relevant when transcription is on
    $transPath = if ($transOn) { _Read-TranscriptionPath } else { "not configured" }

    # -- Overall risk: mirrors Python exactly ---------------------------------
    # Inverted from other modules - logging ON is bad for the attacker
    # LOW  = none of the three main controls are on
    # HIGH = all three are on
    # MEDIUM = some are on
    $anyLogging = $sblOn -or $modOn -or $transOn
    $allLogging = $sblOn -and $modOn -and $transOn

    $overallRisk = if (-not $anyLogging) { "LOW" } `
        elseif ($allLogging)             { "HIGH" } `
        else                             { "MEDIUM" }

    # -- Header box -----------------------------------------------------------
    $boxLine = "=" * 60
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    $title = "  POWERSHELL LOGGING".PadRight(61)
    Write-Host "  |$title|" -ForegroundColor Cyan
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    Write-Host ""

    $riskColor = switch ($overallRisk) {
        "HIGH"   { "Red"    } "MEDIUM" { "Yellow" }
        "LOW"    { "Green"  } default  { "DarkGray" }
    }
    Write-Host "     Risk:  [ $overallRisk ]" -ForegroundColor $riskColor
    Write-Host ""

    # -- Build and display rows -----------------------------------------------
    $rows = @()

    # 1. Script Block Logging
    $sblValue = if ($sblOn) { "enabled" } else { "disabled" }
    $sblRisk  = if ($sblOn) { "HIGH" } else { "LOW" }
    $rows += [PSCustomObject]@{ Label = "Script Block Logging"; Value = $sblValue; Risk = $sblRisk
        Detail = "Captures full script content BEFORE obfuscation is applied. Most impactful PS logging control." }

    # 2. Invocation Logging
    $sbliValue = if ($sbliOn) { "enabled" } else { "disabled" }
    $sbliRisk  = if ($sbliOn) { "MEDIUM" } else { "LOW" }
    $rows += [PSCustomObject]@{ Label = "Invocation Logging"; Value = $sbliValue; Risk = $sbliRisk
        Detail = "Logs start/stop events for every script block. Very verbose - often disabled even when SBL is on." }

    # 3. Module Logging
    $modValue = if ($modOn) { "enabled" } else { "disabled" }
    $modRisk  = if ($modOn) { "HIGH" } else { "LOW" }
    $rows += [PSCustomObject]@{ Label = "Module Logging"; Value = $modValue; Risk = $modRisk
        Detail = "Logs pipeline execution output for specified modules. Catches cmdlet-level activity." }

    # 4. Transcription
    $transValue = if ($transOn) { "enabled" } else { "disabled" }
    $transRisk  = if ($transOn) { "HIGH" } else { "LOW" }
    $rows += [PSCustomObject]@{ Label = "Transcription"; Value = $transValue; Risk = $transRisk
        Detail = "Saves a full session transcript to a file. Reveals commands and output over time." }

    foreach ($r in $rows) {
        _Write-PSLogRow $r.Label $r.Value $r.Risk $r.Detail
    }

    # 5. Transcription path (only shown when transcription is on)
    if ($transOn) {
        Write-Host ""
        _Write-PSLogRow "Transcription Output Dir" $transPath "INFO" `
            "Location where transcript files are written."
    }

    # -- Notes ----------------------------------------------------------------
    Write-Host ""
    Write-Host "  [Notes]" -ForegroundColor DarkCyan
    Write-Host "  - No SBL               : PowerShell payloads will NOT be logged. Use PS freely for staging and lateral movement." -ForegroundColor DarkGray
    Write-Host "  - SBL enabled          : Use .NET direct (Add-Type / [System.Reflection.Assembly]) to bypass PS logging." -ForegroundColor DarkGray
    Write-Host "  - SBL enabled          : Consider PowerShell v2 (powershell -v 2) - it does not support SBL." -ForegroundColor DarkGray
    Write-Host "  - Module logging on    : Avoid using well-known modules (e.g. ActiveDirectory, PSSession)." -ForegroundColor DarkGray
    Write-Host "  - Transcription on     : Output directory path may reveal a central log share - check the path." -ForegroundColor DarkGray
    Write-Host ""

    # -- Feed global results silently -----------------------------------------
    foreach ($r in $rows) {
        $Global:Results += [PSCustomObject]@{
            Module = "PSLogging"
            Name   = $r.Label
            Value  = $r.Value
            Risk   = $r.Risk
        }
    }
    if ($transOn) {
        $Global:Results += [PSCustomObject]@{
            Module = "PSLogging"
            Name   = "Transcription Output Dir"
            Value  = $transPath
            Risk   = "INFO"
        }
    }
}
