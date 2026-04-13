# Global results
$Global:Results = @()

# Verbose flag — set via -ShowSource switch in main.ps1 or 'verbose true/false' in CLI
$Global:VerboseMode = $false

function Write-Source {
    param([string]$Source)
    if ($Global:VerboseMode) {
        Write-Host "  [src] $Source" -ForegroundColor DarkYellow
    }
}

function Add-Result {
    param($Module, $Name, $Value, $Risk)

    $obj = [PSCustomObject]@{
        Module = $Module
        Name   = $Name
        Value  = $Value
        Risk   = $Risk
    }

    $Global:Results += $obj

    switch ($Risk) {
        "CRITICAL" { Write-Host "[CRIT] $Name : $Value" -ForegroundColor Magenta }
        "HIGH"     { Write-Host "[HIGH] $Name : $Value" -ForegroundColor Red }
        "MEDIUM"   { Write-Host "[MED]  $Name : $Value" -ForegroundColor Yellow }
        "LOW"      { Write-Host "[LOW]  $Name : $Value" -ForegroundColor Green }
        "UNKNOWN"  { Write-Host "[UNK]  $Name : $Value" -ForegroundColor DarkGray }
        default    { Write-Host "[INFO] $Name : $Value" -ForegroundColor Cyan }
    }
}
