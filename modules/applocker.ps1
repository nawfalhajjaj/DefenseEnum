# ================================
# Module: AppLocker / WDAC
# Enumerates AppLocker enforcement mode per rule collection and
# checks WDAC (Windows Defender App Control) kernel-level policy status.
# Mirrors: modules/applocker.py
# ================================

$script:AppLockerBase = "SOFTWARE\Policies\Microsoft\Windows\SrpV2"

# Registry subkey -> friendly name
$script:RuleCollections = [ordered]@{
    "Exe"    = "Executables"
    "Script" = "Scripts"
    "Msi"    = "Windows Installers"
    "Dll"    = "DLLs"
    "Appx"   = "Packaged Apps"
}

$script:EnforcementModes = @{
    0 = "not configured"
    1 = "enforce"
    2 = "audit only"
}

# ---------- AppIDSvc Query ---------------------------------------------------

function _Query-AppIDSvc {
    Write-Source "Get-Service -Name AppIDSvc"
    try {
        $svc = Get-Service -Name "AppIDSvc" -ErrorAction Stop
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

# ---------- AppLocker Policy Query -------------------------------------------

function _Query-AppLockerPolicies {
    $results = [ordered]@{}
    foreach ($regName in $script:RuleCollections.Keys) {
        $friendly = $script:RuleCollections[$regName]
        $keyPath  = "$script:AppLockerBase\$regName"
        Write-Source "[HKLM\$keyPath] :: GetValue('EnforcementMode')"
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyPath)
            if ($null -eq $key) {
                $results[$friendly] = "not configured"
            } else {
                $val = $key.GetValue("EnforcementMode", $null)
                $key.Close()
                if ($null -eq $val) {
                    $results[$friendly] = "not configured"
                } elseif ($script:EnforcementModes.ContainsKey([int]$val)) {
                    $results[$friendly] = $script:EnforcementModes[[int]$val]
                } else {
                    $results[$friendly] = "unknown (value=$val)"
                }
            }
        } catch {
            $results[$friendly] = "access denied"
        }
    }
    return $results
}

# ---------- WDAC Status Query ------------------------------------------------

function _Query-WDACStatus {
    $keyPath = "SYSTEM\CurrentControlSet\Control\CI\Config"
    Write-Source "[HKLM\$keyPath] :: GetValue('VulnerableDriverBlocklistEnable')"
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyPath)
        if ($null -eq $key) {
            return @{ Present = $false }
        }
        $val = $key.GetValue("VulnerableDriverBlocklistEnable", $null)
        $key.Close()
        return @{
            Present         = $true
            DriverBlocklist = ($null -ne $val -and [bool]$val)
        }
    } catch {
        return @{ Present = "access_denied" }
    }
}

# ---------- Display helpers --------------------------------------------------

function _Write-AppLockerRow {
    param([string]$Collection, [string]$Mode)

    $modeColor = switch ($Mode) {
        "enforce"        { "Red"     }
        "audit only"     { "Yellow"  }
        "not configured" { "Green"   }
        "access denied"  { "DarkGray"}
        default          { "DarkGray"}
    }

    $icon = switch ($Mode) {
        "enforce"        { "!" }
        "audit only"     { "~" }
        "not configured" { "v" }
        default          { "." }
    }

    $iconColor = switch ($Mode) {
        "enforce"        { "Red"    }
        "audit only"     { "Yellow" }
        "not configured" { "Green"  }
        default          { "DarkGray" }
    }

    $label = $Collection.PadRight(22)
    Write-Host -NoNewline "    "
    Write-Host -NoNewline $icon -ForegroundColor $iconColor
    Write-Host -NoNewline "  $label" -ForegroundColor White
    Write-Host $Mode -ForegroundColor $modeColor
}

# ---------- Main Entry -------------------------------------------------------

function Invoke-AppLocker {

    Write-Host ""
    Write-Host "--- Running applocker ---" -ForegroundColor Magenta
    Write-Host "  Running: APPLOCKER / WDAC" -ForegroundColor DarkCyan
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [*] AppLocker / WDAC..." -ForegroundColor DarkGray
    Write-Host ""

    # -- Query everything first -----------------------------------------------
    $svcStatus  = _Query-AppIDSvc
    $policies   = _Query-AppLockerPolicies
    $wdac       = _Query-WDACStatus

    $svcRunning         = $svcStatus -eq "running"
    $enforcedCollections = @($policies.Keys | Where-Object { $policies[$_] -eq "enforce" })
    $auditCollections    = @($policies.Keys | Where-Object { $policies[$_] -eq "audit only" })

    # Overall risk mirrors Python logic
    if ($enforcedCollections.Count -gt 0 -and $svcRunning -and $wdac.Present -eq $true) {
        $overallRisk = "HIGH"
    } elseif ($enforcedCollections.Count -gt 0 -and $svcRunning) {
        $overallRisk = "MEDIUM"
    } else {
        $overallRisk = "LOW"
    }

    # -- Header box -----------------------------------------------------------
    $boxLine = "=" * 60
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    $title = "  APPLOCKER / WDAC".PadRight(61)
    Write-Host "  |$title|" -ForegroundColor Cyan
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    Write-Host ""

    $riskColor = switch ($overallRisk) {
        "HIGH"   { "Red"     }
        "MEDIUM" { "Yellow"  }
        "LOW"    { "Green"   }
        default  { "DarkGray"}
    }
    Write-Host "     Risk:  [ $overallRisk ]" -ForegroundColor $riskColor
    Write-Host ""

    # -- AppIDSvc -------------------------------------------------------------
    $svcColor = if ($svcRunning) { "Yellow" } else { "Green" }
    $svcIcon  = if ($svcRunning) { "!" } else { "v" }
    Write-Host -NoNewline "    "
    Write-Host -NoNewline $svcIcon -ForegroundColor $svcColor
    Write-Host -NoNewline "  AppIDSvc (AppLocker Service)          " -ForegroundColor White
    Write-Host $svcStatus -ForegroundColor $svcColor
    Write-Host "         AppLocker rules are NOT enforced if AppIDSvc is stopped, even if policies are configured." -ForegroundColor DarkGray
    Write-Host ""

    # -- Rule Collections -----------------------------------------------------
    Write-Host "  AppLocker Rule Collections:" -ForegroundColor DarkCyan
    Write-Host ""
    foreach ($collection in $policies.Keys) {
        _Write-AppLockerRow $collection $policies[$collection]
        $mode = $policies[$collection]
        $detail = "AppLocker enforcement for $collection. 'audit only' means violations are logged but not blocked."
        Write-Host "         $detail" -ForegroundColor DarkGray
    }

    # -- WDAC -----------------------------------------------------------------
    Write-Host ""
    Write-Host "  WDAC (Windows Defender App Control):" -ForegroundColor DarkCyan
    Write-Host ""

    if ($wdac.Present -eq "access_denied") {
        Write-Host "    .  WDAC Policy Key          access denied" -ForegroundColor DarkGray
        Write-Host "         Could not read SYSTEM\CurrentControlSet\Control\CI\Config" -ForegroundColor DarkGray
    } elseif ($wdac.Present -eq $true) {
        Write-Host "    !  WDAC Policy Key          present" -ForegroundColor Red
        Write-Host "         WDAC operates at kernel level (CI.dll). Significantly harder to bypass than AppLocker." -ForegroundColor DarkGray

        Write-Host ""
        if ($wdac.DriverBlocklist) {
            Write-Host "    !  Vulnerable Driver Blocklist  enabled" -ForegroundColor Red
        } else {
            Write-Host "    v  Vulnerable Driver Blocklist  disabled" -ForegroundColor Green
        }
        Write-Host "         Blocks known vulnerable drivers used in BYOVD attacks." -ForegroundColor DarkGray
    } else {
        Write-Host "    v  WDAC Policy Key          not present" -ForegroundColor Green
        Write-Host "         WDAC operates at kernel level (CI.dll). Significantly harder to bypass than AppLocker." -ForegroundColor DarkGray
    }

    # -- Notes ----------------------------------------------------------------
    Write-Host ""
    Write-Host "  [Notes]" -ForegroundColor DarkCyan
    Write-Host "  - AppIDSvc stopped     : All AppLocker rules unenforced regardless of policy." -ForegroundColor DarkGray
    Write-Host "  - Audit mode only      : Payloads run but may generate 8003/8004 events. Avoid noisy tools." -ForegroundColor DarkGray
    Write-Host "  - Exe not restricted   : Drop .exe payloads to allowed paths (e.g. C:\Windows\Tasks)." -ForegroundColor DarkGray
    Write-Host "  - Scripts restricted   : Use mshta.exe, wscript.exe, or COM scriptlets instead of .ps1/.vbs." -ForegroundColor DarkGray
    Write-Host "  - DLLs not restricted  : Sideload malicious DLLs via signed host processes." -ForegroundColor DarkGray
    Write-Host "  - WDAC present         : Standard AppLocker bypasses won't work. Research CI policy trust levels." -ForegroundColor DarkGray
    Write-Host "  - No driver blocklist  : BYOVD attacks viable (e.g. RTCore64.sys, gdrv.sys)." -ForegroundColor DarkGray
    Write-Host ""

    # -- Feed global results silently -----------------------------------------
    $Global:Results += [PSCustomObject]@{ Module = "AppLocker"; Name = "AppIDSvc"; Value = $svcStatus; Risk = if ($svcRunning) { "HIGH" } else { "LOW" } }

    foreach ($collection in $policies.Keys) {
        $mode = $policies[$collection]
        $risk = switch ($mode) {
            "enforce"        { "HIGH"    }
            "audit only"     { "MEDIUM"  }
            "not configured" { "LOW"     }
            default          { "UNKNOWN" }
        }
        $Global:Results += [PSCustomObject]@{ Module = "AppLocker"; Name = "AppLocker - $collection"; Value = $mode; Risk = $risk }
    }

    $wdacValue = if ($wdac.Present -eq $true) { "present" } elseif ($wdac.Present -eq $false) { "not present" } else { "access denied" }
    $wdacRisk  = if ($wdac.Present -eq $true) { "HIGH" } else { "LOW" }
    $Global:Results += [PSCustomObject]@{ Module = "AppLocker"; Name = "WDAC Policy Key"; Value = $wdacValue; Risk = $wdacRisk }

    if ($wdac.Present -eq $true) {
        $blRisk  = if ($wdac.DriverBlocklist) { "LOW" } else { "HIGH" }
        $blValue = if ($wdac.DriverBlocklist) { "enabled" } else { "disabled" }
        $Global:Results += [PSCustomObject]@{ Module = "AppLocker"; Name = "Vulnerable Driver Blocklist"; Value = $blValue; Risk = $blRisk }
    }
}
