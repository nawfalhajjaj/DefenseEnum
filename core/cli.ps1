# ================================
# DefenseEnum CLI v1.0
# ================================

$script:Version = "1.0"
$script:History = [System.Collections.Generic.List[string]]::new()

# ─── Banner ───────────────────────────────────────────────────────────────────

function Show-Banner {
    Write-Host ""
    Write-Host " ██████╗ ███████╗███████╗███████╗███╗   ██╗" -ForegroundColor White
    Write-Host " ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║" -ForegroundColor White
    Write-Host " ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║" -ForegroundColor White
    Write-Host " ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║" -ForegroundColor White
    Write-Host " ██████╔╝███████╗██║     ███████╗██║ ╚████║" -ForegroundColor White
    Write-Host " ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝" -ForegroundColor White
    Write-Host ""
    Write-Host "          Author  : Nawfal Hajjaj" -ForegroundColor DarkGray
    Write-Host "          Version : 1.0" -ForegroundColor DarkGray
    Write-Host ""
}

# ─── Help ─────────────────────────────────────────────────────────────────────

$script:HelpDetails = @{
    "help"    = "  help [command]`n  Show the command list, or detailed info for a specific command.`n  Examples:`n    help`n    help run`n    help export"
    "run"     = "  run <module|all>`n  Execute one or more enumeration modules.`n    defender / firewall : individual modules`n    all               : run every module`n  Examples:`n    run defender`n    run firewall`n    run all`n`n  Tip: use -Mode quick|full|stealth at launch for non-interactive runs."
    "show"    = "  show modules`n  List all registered modules.`n  Example:`n    show modules"
    "export"  = "  export <json|txt|csv|html>`n  Save current results to a file.`n  Examples:`n    export json`n    export html"
    "history" = "  history  (alias: hist)`n  Show commands entered this session.`n  Example:`n    history"
    "save"    = "  save [filename]`n  Save results to a text file. Auto-names if omitted.`n  Examples:`n    save`n    save report.txt"
    "context" = "  context  (alias: ctx)`n  Re-display system context.`n  Example:`n    context"
    "clear"   = "  clear  (alias: cls)`n  Clear the screen.`n  Example:`n    clear"
    "version" = "  version`n  Show DefenseEnum version.`n  Example:`n    version"
    "exit"    = "  exit  (alias: quit)`n  Exit DefenseEnum.`n  Example:`n    exit"
    "verbose" = "  verbose <true|false>`n  Toggle verbose mode. When true, each check prints the exact registry`n  key path or cmdlet used to retrieve its value.`n  Can also be set at launch with: .\main.ps1 -ShowSource`n  Examples:`n    verbose true`n    verbose false"
}

function Show-Help {
    param([string]$Cmd = "")

    if ($Cmd -ne "") {
        if ($script:HelpDetails.ContainsKey($Cmd)) {
            Write-Host ""
            Write-Host $script:HelpDetails[$Cmd] -ForegroundColor Cyan
            Write-Host ""
        } else {
            Write-Host "[!] No help entry for '$Cmd'" -ForegroundColor Yellow
        }
        return
    }

    $h  = [char]0x2500
    $tl = [char]0x250C; $tr = [char]0x2510
    $bl = [char]0x2514; $br = [char]0x2518
    $v  = [char]0x2502
    $line = $h.ToString() * 56

    Write-Host ""
    Write-Host "  $tl$line$tr" -ForegroundColor DarkCyan
    Write-Host "  $v  Commands$((' ' * 47))$v" -ForegroundColor Cyan
    Write-Host "  $bl$line$br" -ForegroundColor DarkCyan
    Write-Host ""

    $rows = @(
        "  help [command]",                      "(?)"
        "  run <module|all>",                    ""
        "  show modules",                        ""
        "  export <json|txt|csv|html>",          ""
        "  history",                             "(hist)"
        "  save [filename]",                     ""
        "  context",                             "(ctx)"
        "  clear",                               "(cls)"
        "  version",                             ""
        "  verbose <true|false>",                ""
        "  exit",                                "(quit)"
    )

    for ($i = 0; $i -lt $rows.Count; $i += 2) {
        $left  = $rows[$i].PadRight(42)
        $right = $rows[$i+1]
        Write-Host -NoNewline $left -ForegroundColor White
        if ($right) { Write-Host $right -ForegroundColor DarkGray }
        else        { Write-Host "" }
    }

    Write-Host ""
    Write-Host "  Type 'help <command>' for details and examples.  TAB to autocomplete." -ForegroundColor DarkGray
    Write-Host ""
}

# ─── Module execution ─────────────────────────────────────────────────────────

function Run-Module([string]$name) {
    if ($Global:Modules.ContainsKey($name)) {
        & $Global:Modules[$name]
    } else {
        Write-Host "[!] Module not found: $name" -ForegroundColor Yellow
    }
}

function Run-All {
    foreach ($m in $Global:Modules.Keys) {
        & $Global:Modules[$m]
    }
}

# ─── show modules ─────────────────────────────────────────────────────────────

# Ordered display list for 'show modules'.
# Each entry: Name, one-line summary, optional tag (e.g. "plugin")
# Add new modules here in the order you want them displayed.
$script:ModuleDisplay = @(
    [PSCustomObject]@{ Name = "defender";   Summary = "Defender state, real-time/tamper protection, signature version";          Tag = "" }
    [PSCustomObject]@{ Name = "firewall";   Summary = "Firewall profiles, default inbound/outbound actions, rule counts";        Tag = "" }
    [PSCustomObject]@{ Name = "antivirus";  Summary = "Installed AV/EDR products via WMI and process scanning";                 Tag = "" }
    [PSCustomObject]@{ Name = "services";   Summary = "Status of security-critical Windows services";                           Tag = "" }
    [PSCustomObject]@{ Name = "uac";        Summary = "UAC level, admin prompt behavior, secure desktop, virtualization";       Tag = "" }
    [PSCustomObject]@{ Name = "ps_logging"; Summary = "Script Block Logging, Module Logging, Transcription status";             Tag = "" }
    [PSCustomObject]@{ Name = "applocker";  Summary = "AppLocker enforcement per collection, WDAC policy status";               Tag = "" }
    [PSCustomObject]@{ Name = "lsass";      Summary = "RunAsPPL, Credential Guard, WDigest, LM compat, null sessions";          Tag = "" }
)

function Show-Modules {
    $h  = [char]0x2500
    $tl = [char]0x250C; $tr = [char]0x2510
    $bl = [char]0x2514; $br = [char]0x2518
    $v  = [char]0x2502
    $width = 64
    $line  = $h.ToString() * $width

    Write-Host ""
    Write-Host "  $tl$line$tr" -ForegroundColor DarkCyan
    $header = "    Available Modules"
    Write-Host "  $v$($header.PadRight($width))$v" -ForegroundColor Cyan
    Write-Host "  $bl$line$br" -ForegroundColor DarkCyan
    Write-Host ""

    # Calculate the longest name so all dashes line up
    $maxLen = ($script:ModuleDisplay | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
    foreach ($entry in $script:ModuleDisplay) {
        $tag     = if ($entry.Tag -ne "") { " [$($entry.Tag)]" } else { "" }
        $namePad = $entry.Name.PadRight($maxLen)

        Write-Host -NoNewline "  "
        Write-Host -NoNewline $namePad -ForegroundColor Cyan
        Write-Host -NoNewline "  -  " -ForegroundColor DarkGray
        Write-Host -NoNewline $entry.Summary -ForegroundColor White

        if ($tag -ne "") {
            Write-Host $tag -ForegroundColor DarkGray
        } else {
            Write-Host ""
        }
    }

    # Catch any registered modules not in the display list (runtime-loaded plugins)
    foreach ($key in $Global:Modules.Keys) {
        $known = $script:ModuleDisplay | Where-Object { $_.Name -eq $key }
        if (-not $known) {
            $namePad = $key.PadRight($maxLen)
            Write-Host -NoNewline "  "
            Write-Host -NoNewline $namePad -ForegroundColor Cyan
            Write-Host "  -  (no description)" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
}

# ─── export ───────────────────────────────────────────────────────────────────

function Export-Results([string]$format) {
    if ($Global:Results.Count -eq 0) {
        Write-Host "[!] No results to export. Run a module first." -ForegroundColor Yellow
        return
    }

    $stamp     = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputDir = Join-Path (Split-Path $PSScriptRoot -Parent) "output"
    if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
    $file      = Join-Path $outputDir "DefenseEnum_$stamp.$format"

    switch ($format) {
        "json" { $Global:Results | ConvertTo-Json -Depth 5 | Out-File $file -Encoding UTF8 }
        "csv"  { $Global:Results | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 }
        "txt"  {
            $Global:Results | ForEach-Object {
                "[$($_.Risk.PadRight(6))] $($_.Module) | $($_.Name) : $($_.Value)"
            } | Out-File $file -Encoding UTF8
        }
        "html" {
            $rows = $Global:Results | ForEach-Object {
                $c = switch ($_.Risk) {
                    "HIGH" {"#ff4c4c"} "MEDIUM" {"#ffa500"} "LOW" {"#4caf50"} default {"#64b5f6"}
                }
                "<tr><td>$($_.Module)</td><td>$($_.Name)</td><td>$($_.Value)</td><td style='color:$c;font-weight:bold'>$($_.Risk)</td></tr>"
            }
            @"
<!DOCTYPE html><html><head><meta charset='UTF-8'><title>DefenseEnum</title>
<style>body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;padding:20px}
h2{color:#4fc3f7}table{border-collapse:collapse;width:100%}
th{background:#2d2d2d;color:#4fc3f7;padding:8px;text-align:left}
td{padding:6px 8px;border-bottom:1px solid #333}tr:hover{background:#2a2a2a}</style></head><body>
<h2>DefenseEnum Results &mdash; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</h2>
<table><tr><th>Module</th><th>Check</th><th>Value</th><th>Risk</th></tr>
$($rows -join "`n")</table></body></html>
"@ | Out-File $file -Encoding UTF8
        }
        default {
            Write-Host "[!] Unknown format: $format  (use json, txt, csv, html)" -ForegroundColor Yellow
            return
        }
    }
    Write-Host "[+] Exported to $file" -ForegroundColor Green
}

# ─── save ─────────────────────────────────────────────────────────────────────

function Save-Results([string]$filename) {
    if ($Global:Results.Count -eq 0) {
        Write-Host "[!] No results to save. Run a module first." -ForegroundColor Yellow
        return
    }
    if (-not $filename) { $filename = "DefenseEnum_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" }
    $Global:Results | ForEach-Object {
        "[$($_.Risk.PadRight(6))] $($_.Module) | $($_.Name) : $($_.Value)"
    } | Out-File $filename -Encoding UTF8
    Write-Host "[+] Saved to $filename" -ForegroundColor Green
}

# ─── history ──────────────────────────────────────────────────────────────────

function Show-History {
    if ($script:History.Count -eq 0) {
        Write-Host "  (no history yet)" -ForegroundColor DarkGray
        return
    }
    Write-Host ""
    $i = 1
    foreach ($entry in $script:History) {
        Write-Host ("  {0,3}  {1}" -f $i, $entry) -ForegroundColor White
        $i++
    }
    Write-Host ""
}

# ─── Autocomplete ─────────────────────────────────────────────────────────────

$script:RunTargets = @("defender","firewall","antivirus","services","applocker","uac","lsass","ps_logging","all")
$script:ExportFmts = @("json","txt","csv","html")
$script:ShowOpts   = @("modules")
$script:VerboseOpts = @("true","false")
$script:HelpOpts   = @("help","run","show","export","history","save","context","clear","version","verbose","exit")
$script:TopCmds    = @("help","run","show","export","history","hist","save","context","ctx","clear","cls","version","verbose","exit","quit")

# Returns a hashtable: @{ Completed = <new buffer string>; Changed = $true/$false }
function Get-Completion([string]$buf) {

    $trailingSpace = $buf -match ' $'

    # Split without dropping anything, force array with @()
    [string[]]$parts = @($buf.TrimEnd() -split '\s+' | Where-Object { $_ -ne "" })

    $verb = if ($parts.Length -ge 1) { $parts[0] } else { "" }
    $sub  = if ($parts.Length -ge 2) { $parts[1] } else { "" }

    # ── Subcommand completion ──────────────────────────────────────────────────
    $inSubPosition = ($verb -ne "") -and ($trailingSpace -or $parts.Length -ge 2)

    if ($inSubPosition) {
        $prefix = if ($trailingSpace) { "" } else { $sub }
        [string[]]$pool = @(switch ($verb) {
            "run"    { $script:RunTargets }
            "export" { $script:ExportFmts }
            "show"   { $script:ShowOpts }
            "help"   { $script:HelpOpts }
            "verbose"{ $script:VerboseOpts }
            default  { @() }
        })

        [string[]]$hits = @($pool | Where-Object { $_ -like "$prefix*" })
        if ($hits.Length -gt 0) {
            return @{ Completed = "$verb $($hits[0])"; Changed = $true }
        }
        return @{ Completed = $buf; Changed = $false }
    }

    # ── Top-level verb completion ──────────────────────────────────────────────
    [string[]]$hits = @($script:TopCmds | Where-Object { $_ -like "$verb*" })
    if ($hits.Length -gt 0) {
        $match = $hits[0]
        # Only update if something actually changes
        if ($match -ne $verb) {
            return @{ Completed = $match; Changed = $true }
        }
        # Verb is already complete — add a trailing space if this verb takes a subcommand
        if ($verb -in @("run","export","show","help")) {
            return @{ Completed = "$verb "; Changed = $true }
        }
    }
    return @{ Completed = $buf; Changed = $false }
}

# ─── Main shell ───────────────────────────────────────────────────────────────

function Start-CLI {

    # History index: -1 means "not browsing history" (fresh prompt)
    [int]$histIdx = -1

    while ($true) {

        Write-Host -NoNewline "DefenseEnum > "
        [string]$buf = ""
        $histIdx = -1          # reset history cursor on each new prompt

        while ($true) {
            $key = [System.Console]::ReadKey($true)

            if ($key.Key -eq "Enter") {
                Write-Host ""
                break
            }
            elseif ($key.Key -eq "Backspace") {
                if ($buf.Length -gt 0) {
                    $buf = $buf.Substring(0, $buf.Length - 1)
                    Write-Host "`b `b" -NoNewline
                }
            }
            elseif ($key.Key -eq "Tab") {
                $result = Get-Completion $buf
                if ($result.Changed) {
                    $buf = $result.Completed
                    # Redraw the whole line cleanly
                    Write-Host ("`rDefenseEnum > " + (" " * 80)) -NoNewline
                    Write-Host "`rDefenseEnum > $buf" -NoNewline
                }
            }
            elseif ($key.Key -eq "UpArrow") {
                if ($script:History.Count -eq 0) { continue }
                # Move backwards through history
                if ($histIdx -eq -1) {
                    $histIdx = $script:History.Count - 1
                } elseif ($histIdx -gt 0) {
                    $histIdx--
                }
                $buf = $script:History[$histIdx]
                Write-Host ("`rDefenseEnum > " + (" " * 80)) -NoNewline
                Write-Host "`rDefenseEnum > $buf" -NoNewline
            }
            elseif ($key.Key -eq "DownArrow") {
                if ($histIdx -eq -1) { continue }
                if ($histIdx -lt $script:History.Count - 1) {
                    $histIdx++
                    $buf = $script:History[$histIdx]
                } else {
                    # Past the end of history — clear to blank prompt
                    $histIdx = -1
                    $buf = ""
                }
                Write-Host ("`rDefenseEnum > " + (" " * 80)) -NoNewline
                Write-Host "`rDefenseEnum > $buf" -NoNewline
            }
            else {
                # Any regular keypress resets history browsing
                $histIdx = -1
                $buf += $key.KeyChar
                Write-Host -NoNewline $key.KeyChar
            }
        }

        [string]$cmd = $buf.Trim()
        if ($cmd -eq "") { continue }

        $script:History.Add($cmd) | Out-Null

        # ── Dispatch ──────────────────────────────────────────────────────────
        if     ($cmd -match '^run (defender|firewall|antivirus|services|applocker|uac|lsass|ps_logging)$')  { Run-Module $Matches[1] }
        elseif ($cmd -eq    'run all')                    { Run-All }
        elseif ($cmd -eq    'show modules')                    { Show-Modules }
        elseif ($cmd -match '^export (\S+)$')                  { Export-Results $Matches[1] }
        elseif ($cmd -eq    'history' -or $cmd -eq 'hist')     { Show-History }
        elseif ($cmd -match '^save (.+)$')                     { Save-Results $Matches[1] }
        elseif ($cmd -eq    'save')                            { Save-Results "" }
        elseif ($cmd -eq    'context' -or $cmd -eq 'ctx')      { Show-SystemContext }
        elseif ($cmd -eq    'clear'   -or $cmd -eq 'cls')      { Clear-Host }
        elseif ($cmd -eq    'version')                         { Write-Host "  DefenseEnum v$script:Version" -ForegroundColor Cyan }
        elseif ($cmd -match '^help (\S+)$')                    { Show-Help $Matches[1] }
        elseif ($cmd -eq    'help')                            { Show-Help }
        elseif ($cmd -eq    'exit'    -or $cmd -eq 'quit')     { Write-Host "Bye." -ForegroundColor DarkGray; exit }
        elseif ($cmd -eq    'verbose true')  {
            $Global:VerboseMode = $true
            Write-Host "  [+] Verbose mode: true" -ForegroundColor DarkYellow
        }
        elseif ($cmd -eq    'verbose false') {
            $Global:VerboseMode = $false
            Write-Host "  [-] Verbose mode: false" -ForegroundColor DarkGray
        }
        elseif ($cmd -eq    'verbose') {
            $state = if ($Global:VerboseMode) { "true" } else { "false" }
            Write-Host "  Verbose is currently: $state" -ForegroundColor DarkYellow
        }
        else                                                   { Write-Host "[!] Unknown command. Type 'help' for a list." -ForegroundColor Yellow }
    }
}
