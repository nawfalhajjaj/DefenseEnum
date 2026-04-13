# Module registry

$Global:Modules = @{
    "defender"  = { Invoke-Defender }
    "firewall"  = { Invoke-Firewall }
    "antivirus" = { Invoke-Antivirus }
    "services"  = { Invoke-Services }
    "applocker" = { Invoke-AppLocker }
    "uac"       = { Invoke-UAC }
    "lsass"      = { Invoke-LSASS }
    "ps_logging" = { Invoke-PSLogging }
}