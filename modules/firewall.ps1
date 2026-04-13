# ================================
# Module: Firewall Configuration
# Reads Firewall profile states (domain/private/public), default
# inbound/outbound actions, and total rule counts via registry + netsh.
# Mirrors: modules/firewall.py
# ================================

$script:FWBase = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

# Registry subkey -> friendly name (ordered for consistent output)
$script:Profiles = [ordered]@{
    "DomainProfile"   = "Domain"
    "StandardProfile" = "Private"
    "PublicProfile"   = "Public"
}

# ---------- Registry helper --------------------------------------------------

function _Read-FWReg {
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

# ---------- Rule count via netsh ---------------------------------------------
# Parses 'netsh advfirewall firewall show rule name=all' and counts
# enabled inbound/outbound rules - mirrors _count_rules() in the Python.

function _Count-FirewallRules {
    Write-Source "netsh advfirewall firewall show rule name=all"
    try {
        [string[]]$lines = & netsh advfirewall firewall show rule name=all 2>$null
        $inbound  = 0
        $outbound = 0
        $direction = $null
        foreach ($line in $lines) {
            $l = $line.Trim().ToLower()
            if ($l -like "direction:*") {
                $direction = ($l -split ":", 2)[1].Trim()
            }
            if ($l -like "enabled:*" -and $l -like "*yes*") {
                if ($direction -eq "in")  { $inbound++  }
                if ($direction -eq "out") { $outbound++ }
            }
        }
        return @{ Inbound = $inbound; Outbound = $outbound }
    } catch {
        return @{ Inbound = 0; Outbound = 0 }
    }
}

# ---------- Display helpers --------------------------------------------------

function _Write-ProfileRow {
    param([string]$Label, [string]$Value, [string]$Risk, [string]$Detail)

    $icon = switch ($Risk) {
        "CRITICAL" { "!" } "HIGH" { "!" } "LOW" { "v" } default { "." }
    }
    $iconColor = switch ($Risk) {
        "CRITICAL" { "Magenta" } "HIGH" { "Red" } "LOW" { "Green" } default { "DarkGray" }
    }
    $valueColor = switch ($Risk) {
        "CRITICAL" { "Magenta" } "HIGH" { "Red" } "MEDIUM" { "Yellow" }
        "LOW"      { "Green"   } default { "Cyan" }
    }

    $labelPad = $Label.PadRight(36)
    Write-Host -NoNewline "    "
    Write-Host -NoNewline $icon -ForegroundColor $iconColor
    Write-Host -NoNewline "  $labelPad" -ForegroundColor White
    Write-Host $Value -ForegroundColor $valueColor
    Write-Host "         $Detail" -ForegroundColor DarkGray
}

# ---------- Main Entry -------------------------------------------------------

function Invoke-Firewall {

    Write-Host ""
    Write-Host "--- Running firewall ---" -ForegroundColor Magenta
    Write-Host "  Running: FIREWALL CONFIGURATION" -ForegroundColor DarkCyan
    Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [*] Firewall Configuration..." -ForegroundColor DarkGray
    Write-Host ""

    # -- Query all profiles from registry -------------------------------------
    $profileRows = @()
    $anyDisabled = $false

    foreach ($regName in $script:Profiles.Keys) {
        $friendly = $script:Profiles[$regName]
        $keyPath  = "$script:FWBase\$regName"

        $enabledVal  = _Read-FWReg $keyPath "EnableFirewall"
        $inboundVal  = _Read-FWReg $keyPath "DefaultInboundAction"
        $outboundVal = _Read-FWReg $keyPath "DefaultOutboundAction"

        # Enabled state
        if ($null -eq $enabledVal) {
            $enabledStr  = "unknown"
            $enabledRisk = "UNKNOWN"
        } elseif ([bool]$enabledVal) {
            $enabledStr  = "enabled"
            $enabledRisk = "LOW"
        } else {
            $enabledStr  = "disabled"
            $enabledRisk = "CRITICAL"
            $anyDisabled = $true
        }

        # Inbound default action: 0=allow, 1=block
        $inStr = if ($null -eq $inboundVal) { "unknown" } elseif ($inboundVal -eq 1) { "block" } else { "allow" }
        $inRisk = switch ($inStr) { "block" { "LOW" } "allow" { "HIGH" } default { "UNKNOWN" } }

        # Outbound default action: 0=allow, 1=block
        $outStr = if ($null -eq $outboundVal) { "unknown" } elseif ($outboundVal -eq 1) { "block" } else { "allow" }

        $profileRows += [PSCustomObject]@{
            Friendly    = $friendly
            EnabledStr  = $enabledStr
            EnabledRisk = $enabledRisk
            InStr       = $inStr
            InRisk      = $inRisk
            OutStr      = $outStr
        }
    }

    # -- Rule counts ----------------------------------------------------------
    $ruleCounts = _Count-FirewallRules

    # -- Overall risk ---------------------------------------------------------
    $overallRisk = if ($anyDisabled) { "CRITICAL" } else { "LOW" }

    # -- Header box -----------------------------------------------------------
    $boxLine = "=" * 60
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    $title = "  FIREWALL CONFIGURATION".PadRight(61)
    Write-Host "  |$title|" -ForegroundColor Cyan
    Write-Host "  +$boxLine+" -ForegroundColor Cyan
    Write-Host ""

    $riskColor = switch ($overallRisk) {
        "CRITICAL" { "Magenta" } "HIGH" { "Red" } "MEDIUM" { "Yellow" }
        "LOW"      { "Green"   } default { "DarkGray" }
    }
    Write-Host "     Risk:  [ $overallRisk ]" -ForegroundColor $riskColor
    Write-Host ""

    # -- Profile rows ---------------------------------------------------------
    foreach ($p in $profileRows) {
        Write-Host "  $($p.Friendly) Profile:" -ForegroundColor DarkCyan
        _Write-ProfileRow "$($p.Friendly) Profile" $p.EnabledStr $p.EnabledRisk `
            "Firewall is $($p.EnabledStr) for the $($p.Friendly) network profile."
        _Write-ProfileRow "$($p.Friendly) Default Inbound" $p.InStr $p.InRisk `
            "Default action for unsolicited inbound traffic on the $($p.Friendly) profile."
        _Write-ProfileRow "$($p.Friendly) Default Outbound" $p.OutStr "INFO" `
            "Default action for outbound traffic on the $($p.Friendly) profile."
        Write-Host ""
    }

    # -- Rule counts ----------------------------------------------------------
    Write-Host "  Rule Counts:" -ForegroundColor DarkCyan
    $inLabel  = "Enabled Inbound Rules".PadRight(36)
    $outLabel = "Enabled Outbound Rules".PadRight(36)
    Write-Host "    .  $inLabel $($ruleCounts.Inbound)" -ForegroundColor Cyan
    Write-Host "         Total enabled inbound rules. High counts may indicate a poorly maintained ruleset." -ForegroundColor DarkGray
    Write-Host "    .  $outLabel $($ruleCounts.Outbound)" -ForegroundColor Cyan
    Write-Host "         Total enabled outbound rules." -ForegroundColor DarkGray

    # -- Notes ----------------------------------------------------------------
    Write-Host ""
    Write-Host "  [Notes]" -ForegroundColor DarkCyan
    Write-Host "  - Profile disabled         : Direct network access without host-based filtering." -ForegroundColor DarkGray
    Write-Host "  - Inbound allow (default)  : Enumerate listening services for direct exploitation." -ForegroundColor DarkGray
    Write-Host "  - Outbound unrestricted    : C2 egress via HTTP/HTTPS beaconing likely works." -ForegroundColor DarkGray
    Write-Host "  - High rule counts         : Look for any/any rules using netsh advfirewall firewall show rule name=all" -ForegroundColor DarkGray
    Write-Host "  - Firewall log             : %systemroot%\system32\LogFiles\Firewall\pfirewall.log" -ForegroundColor DarkGray
    Write-Host ""

    # -- Feed global results silently -----------------------------------------
    foreach ($p in $profileRows) {
        $Global:Results += [PSCustomObject]@{ Module = "Firewall"; Name = "$($p.Friendly) Profile";          Value = $p.EnabledStr; Risk = $p.EnabledRisk }
        $Global:Results += [PSCustomObject]@{ Module = "Firewall"; Name = "$($p.Friendly) Default Inbound";  Value = $p.InStr;      Risk = $p.InRisk }
        $Global:Results += [PSCustomObject]@{ Module = "Firewall"; Name = "$($p.Friendly) Default Outbound"; Value = $p.OutStr;     Risk = "INFO" }
    }
    $Global:Results += [PSCustomObject]@{ Module = "Firewall"; Name = "Enabled Inbound Rules";  Value = $ruleCounts.Inbound;  Risk = "INFO" }
    $Global:Results += [PSCustomObject]@{ Module = "Firewall"; Name = "Enabled Outbound Rules"; Value = $ruleCounts.Outbound; Risk = "INFO" }
}
