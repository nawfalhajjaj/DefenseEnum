# ================================
# Module: UAC Configuration
# Reads User Account Control (UAC) configuration from the registry.
# Hive: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
# Mirrors: modules/uac.py
# ================================

$script:UACKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

$script:AdminPromptMeanings = @{
    0 = "Elevate without prompting"
    1 = "Prompt for credentials on secure desktop"
    2 = "Prompt for credentials"
    3 = "Prompt for consent on secure desktop"
    4 = "Prompt for consent"
    5 = "Prompt for consent for non-Windows binaries (default)"
}

$script:UserPromptMeanings = @{
    0 = "Automatically deny elevation requests"
    1 = "Prompt for credentials on secure desktop"
    3 = "Prompt for credentials"
}

# ---------- Registry helper --------------------------------------------------

function _Read-UACReg {
    param([string]$ValueName)
    Write-Source "[HKLM\$script:UACKey] :: GetValue('$ValueName')"
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:UACKey)
        if ($null -eq $key) { return $null }
        $val = $key.GetValue($ValueName, $null)
        $key.Close()
        return $val
    } catch {
        return $null
    }
}

# ---------- Display helper ---------------------------------------------------

function _Write-UACRow {
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

function Invoke-UAC {

    Write-Host ""
    Write-Host "--- Running uac ---" -ForegroundColor Magenta
    Write-Host "  Running: UAC CONFIGURATION" -ForegroundColor DarkCyan
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [*] UAC Configuration..." -ForegroundColor DarkGray
    Write-Host ""

    # -- Query all values first -----------------------------------------------
    $lua           = _Read-UACReg "EnableLUA"
    $adminBehavior = _Read-UACReg "ConsentPromptBehaviorAdmin"
    $userBehavior  = _Read-UACReg "ConsentPromptBehaviorUser"
    $secureDesktop = _Read-UACReg "PromptOnSecureDesktop"
    $virtualization= _Read-UACReg "EnableVirtualization"

    # -- Build result rows ----------------------------------------------------
    $rows = @()

    # 1. UAC Enabled (EnableLUA)
    if ($null -eq $lua) {
        $rows += [PSCustomObject]@{ Label = "UAC Enabled"; Value = "unknown"; Risk = "UNKNOWN"
            Detail = "EnableLUA=0 means UAC is completely disabled - all processes run with full admin rights." }
    } elseif ([bool]$lua) {
        $rows += [PSCustomObject]@{ Label = "UAC Enabled"; Value = "True"; Risk = "LOW"
            Detail = "EnableLUA=0 means UAC is completely disabled - all processes run with full admin rights." }
    } else {
        $rows += [PSCustomObject]@{ Label = "UAC Enabled"; Value = "False"; Risk = "CRITICAL"
            Detail = "EnableLUA=0 means UAC is completely disabled - all processes run with full admin rights." }
    }

    # 2. Admin Prompt Behavior (ConsentPromptBehaviorAdmin)
    if ($null -eq $adminBehavior) {
        $abLabel = "unknown"
        $abRisk  = "UNKNOWN"
    } else {
        $abLabel = if ($script:AdminPromptMeanings.ContainsKey([int]$adminBehavior)) {
            $script:AdminPromptMeanings[[int]$adminBehavior]
        } else { "unknown (value=$adminBehavior)" }
        # 0 = auto-elevate (CRITICAL), 2/4 = weaker prompts (MEDIUM), others = OK
        $abRisk = if ($adminBehavior -eq 0) { "CRITICAL" } `
             elseif ($adminBehavior -in @(2, 4)) { "MEDIUM" } `
             else { "LOW" }
    }
    $rows += [PSCustomObject]@{ Label = "Admin Prompt Behavior"; Value = $abLabel; Risk = $abRisk
        Detail = "Controls what happens when an admin account needs to elevate." }

    # 3. User Prompt Behavior (ConsentPromptBehaviorUser)
    if ($null -eq $userBehavior) {
        $ubLabel = "unknown"
    } else {
        $ubLabel = if ($script:UserPromptMeanings.ContainsKey([int]$userBehavior)) {
            $script:UserPromptMeanings[[int]$userBehavior]
        } else { "unknown (value=$userBehavior)" }
    }
    $rows += [PSCustomObject]@{ Label = "User Prompt Behavior"; Value = $ubLabel; Risk = "INFO"
        Detail = "Controls what standard users see when elevation is required." }

    # 4. Secure Desktop (PromptOnSecureDesktop)
    if ($null -eq $secureDesktop) {
        $rows += [PSCustomObject]@{ Label = "Secure Desktop"; Value = "unknown"; Risk = "UNKNOWN"
            Detail = "Secure desktop isolates the UAC prompt from user-space processes - prevents UI spoofing attacks." }
    } elseif ([bool]$secureDesktop) {
        $rows += [PSCustomObject]@{ Label = "Secure Desktop"; Value = "True"; Risk = "LOW"
            Detail = "Secure desktop isolates the UAC prompt from user-space processes - prevents UI spoofing attacks." }
    } else {
        $rows += [PSCustomObject]@{ Label = "Secure Desktop"; Value = "False"; Risk = "MEDIUM"
            Detail = "Secure desktop isolates the UAC prompt from user-space processes - prevents UI spoofing attacks." }
    }

    # 5. Virtualization (EnableVirtualization)
    if ($null -eq $virtualization) {
        $virtValue = "unknown"
    } else {
        $virtValue = if ([bool]$virtualization) { "True" } else { "False" }
    }
    $rows += [PSCustomObject]@{ Label = "Virtualization Enabled"; Value = $virtValue; Risk = "INFO"
        Detail = "Redirects legacy app writes to VirtualStore - less relevant for red team." }

    # -- Overall risk: mirrors Python (CRITICAL > MEDIUM > LOW) ---------------
    $overallRisk = "LOW"
    $luaDisabled = ($null -ne $lua -and -not [bool]$lua)
    foreach ($r in $rows) {
        if ($r.Risk -eq "CRITICAL" -or $luaDisabled)                            { $overallRisk = "CRITICAL"; break }
        if ($r.Risk -eq "MEDIUM" -and $overallRisk -notin @("CRITICAL"))        { $overallRisk = "MEDIUM" }
    }

    # -- Header box -----------------------------------------------------------
    $boxLine = "=" * 60
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    $title = "  UAC CONFIGURATION".PadRight(61)
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
        _Write-UACRow $r.Label $r.Value $r.Risk $r.Detail
    }

    # -- Notes ----------------------------------------------------------------
    Write-Host ""
    Write-Host "  [Notes]" -ForegroundColor DarkCyan
    Write-Host "  - UAC disabled (LUA=0)     : All processes are full admin. No elevation bypass needed." -ForegroundColor DarkGray
    Write-Host "  - Admin prompt = 0         : Auto-elevate any requesting process. UAC bypass trivial." -ForegroundColor DarkGray
    Write-Host "  - Secure desktop off       : Spoof or overlay the UAC prompt with a crafted UI." -ForegroundColor DarkGray
    Write-Host "  - Standard UAC (default 5) : Use token impersonation, COM object bypass, or fodhelper.exe." -ForegroundColor DarkGray
    Write-Host "  - Auto-elevated COM objects: reg query HKLM\...\InprocServer32 for DLL hijack opportunities." -ForegroundColor DarkGray
    Write-Host ""

    # -- Feed global results silently -----------------------------------------
    foreach ($r in $rows) {
        $Global:Results += [PSCustomObject]@{
            Module = "UAC"
            Name   = $r.Label
            Value  = $r.Value
            Risk   = $r.Risk
        }
    }
}
