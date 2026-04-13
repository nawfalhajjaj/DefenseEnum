# ================================
# DefenseEnum - Entry Point
# ================================

[CmdletBinding()]
param(
    [ValidateSet("quick","full","stealth")]
    [string]$Mode = "",

    [switch]$ShowSource
)

Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ---------- Import Core ----------
. "$PSScriptRoot\core\output.ps1"
. "$PSScriptRoot\core\registry.ps1"

# ---------- Import Modules ----------
. "$PSScriptRoot\modules\defender.ps1"
. "$PSScriptRoot\modules\firewall.ps1"
. "$PSScriptRoot\modules\antivirus.ps1"
. "$PSScriptRoot\modules\services.ps1"
. "$PSScriptRoot\modules\applocker.ps1"
. "$PSScriptRoot\modules\uac.ps1"
. "$PSScriptRoot\modules\lsass.ps1"
. "$PSScriptRoot\modules\ps_logging.ps1"

# ---------- Import Context ----------
. "$PSScriptRoot\core\context.ps1"

# ---------- Import CLI ----------
. "$PSScriptRoot\core\cli.ps1"

# ---------- Apply flags ----------
if ($ShowSource) { $Global:VerboseMode = $true }

# ---------- START ----------
Clear-Host

# -- --mode: non-interactive run ----------------------------------------------
if ($Mode -ne "") {

    Show-Banner

    switch ($Mode) {

        "quick" {
            Show-SystemContext
            Write-Host ""
            Write-Host "  [Mode: quick] Running Defender checks only..." -ForegroundColor DarkCyan
            Write-Host ""
            Invoke-Defender
        }

        "full" {
            Show-SystemContext
            Write-Host ""
            Write-Host "  [Mode: full] Running all modules..." -ForegroundColor DarkCyan
            Write-Host ""
            foreach ($m in $Global:Modules.Keys) {
                Write-Host "--- $m ---" -ForegroundColor Magenta
                & $Global:Modules[$m]
                Write-Host ""
            }
        }

        "stealth" {
            # stealth: no banner, no context, no section headers
            # -Verbose is intentionally ignored in stealth mode
            $Global:VerboseMode = $false
            foreach ($m in $Global:Modules.Keys) {
                & $Global:Modules[$m] 2>$null
            }
        }
    }

    Write-Host ""
    Write-Host "  [$Mode] Done. $($Global:Results.Count) result(s) collected." -ForegroundColor DarkGray
    Write-Host "  Tip: run interactively (no -Mode) to export results." -ForegroundColor DarkGray
    Write-Host ""
    exit
}

# -- Interactive mode (no -Mode flag) -----------------------------------------
Show-Banner
Show-SystemContext

Write-Host ""
Write-Host "Type 'help' to begin. TAB to autocomplete." -ForegroundColor DarkGray
Write-Host ""

Start-CLI
