#Requires -RunAsAdministrator
<#
.SYNOPSIS
Detects the host role and applies every applicable hardening category without prompting.
Compatible with Windows PowerShell 5.1+.
.DESCRIPTION
Always runs first-hour (account policy, legacy protocols, USB storage, host firewall scoped to the
local subnet(s)), then the role scripts that match what is installed: domain controller, IIS web,
IIS FTP, and workstation. Each step runs in its own process so one failure does not stop the rest.
Use -PlanOnly to preview. Password rotation and scheduled-task disabling are never automatic.
#>
[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [switch]$SkipFirewall,
    [switch]$SkipUsb,
    [string[]]$ManagementRange = @(),
    [string]$ReportDirectory = "$env:LOCALAPPDATA\CCDC\Reports"
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$results = [System.Collections.Generic.List[string]]::new()

function Write-Step { param([string]$Message) Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Cyan }

function Get-LocalSubnets {
    foreach ($ip in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixLength -ge 8 -and $_.PrefixLength -le 32 })) {
        $bytes = [System.Net.IPAddress]::Parse($ip.IPAddress).GetAddressBytes()
        $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $ip.PrefixLength))
        $addr = ([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3]
        $net = $addr -band $mask
        '{0}.{1}.{2}.{3}/{4}' -f (($net -shr 24) -band 255), (($net -shr 16) -band 255), (($net -shr 8) -band 255), ($net -band 255), $ip.PrefixLength
    }
}

function Invoke-Step {
    param([string]$Name, [string]$Script, [string[]]$Arguments)
    Write-Step "$Name -> $(Split-Path $Script -Leaf) $($Arguments -join ' ')"
    $quoted = ($Arguments | ForEach-Object { if ($_ -match '^-') { $_ } else { "'" + ($_ -replace "'", "''") + "'" } }) -join ' '
    $command = "`$ConfirmPreference='None'; & '$Script' $quoted"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $command
    $code = $LASTEXITCODE
    $results.Add(("{0,-28} exit={1}" -f $Name, $code))
    if ($code -ne 0) { Write-Warning "$Name finished with exit code $code; continuing." }
}

$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$isServer = $os.ProductType -ne 1
$isDc = $cs.DomainRole -ge 4
$hasIis = [bool](Get-Service -Name W3SVC -ErrorAction SilentlyContinue)
$hasFtp = [bool](Get-Service -Name FTPSVC -ErrorAction SilentlyContinue)
$roles = @()
if ($isDc) { $roles += 'domain-controller' }
if ($hasIis) { $roles += 'iis-web' }
if ($hasFtp) { $roles += 'iis-ftp' }
if (-not $isServer -or -not $roles) { $roles += 'workstation-baseline' }
Write-Step "Detected: $($os.Caption); server=$isServer; domainRole=$($cs.DomainRole); roles=$($roles -join ', ')"

$mode = @(); if ($PlanOnly) { $mode = @('-PlanOnly') }
$roleMode = @(); if (-not $PlanOnly) { $roleMode = @('-Apply') }
$skipRp = @(); if ($isServer) { $skipRp = @('-SkipRestorePoint') }

$firstHour = @('-SetAccountPolicy', '-DisableLegacyProtocols') + $mode + $skipRp + @('-ReportDirectory', $ReportDirectory)
if (-not $SkipUsb) { $firstHour += '-DisableUsbStorage' }
if (-not $SkipFirewall) {
    if ($ManagementRange.Count -eq 0) { $ManagementRange = @(Get-LocalSubnets | Select-Object -Unique) }
    if ($ManagementRange.Count -gt 0) {
        $firstHour += '-EnforceHostFirewall'
        foreach ($range in $ManagementRange) { $firstHour += @('-ManagementRange', $range) }
        Write-Step "Firewall management scope: $($ManagementRange -join ', ')"
    } else { Write-Warning 'No usable local subnet found; firewall step skipped.' }
}
Invoke-Step 'first-hour (common)' (Join-Path $here 'first-hour.ps1') $firstHour

$common = $roleMode + @('-ReportDirectory', $ReportDirectory)
if ($isDc) { Invoke-Step 'AD/DNS' (Join-Path $here 'addns\harden-addns.ps1') (@('-SecureDnsZones', '-HardenDcAuth', '-DisableSpooler', '-EnableAuditPolicy') + $common) }
if ($hasIis) { Invoke-Step 'IIS web' (Join-Path $here 'webserver\harden-webserver.ps1') (@('-DisableDirectoryBrowsing', '-HideServerHeader', '-HardenTls', '-EnableAuditPolicy') + $common) }
if ($hasFtp) { Invoke-Step 'IIS FTP' (Join-Path $here 'ftpserver\harden-ftpserver.ps1') (@('-DisableAnonymousFtp', '-EnableFtpLogging', '-HardenTls', '-EnableAuditPolicy') + $common) }
if (-not $isServer -or $roles -contains 'workstation-baseline') {
    $ws = @('-HardenCredentials', '-EnablePowerShellLogging', '-DisableAutorun', '-EnableDefender', '-EnableAuditPolicy') + $common
    if ($isServer) { $ws += '-SkipRestorePoint' }
    Invoke-Step 'Workstation baseline' (Join-Path $here 'workstation\harden-workstation.ps1') $ws
}

Write-Step 'Summary'
$results | ForEach-Object { Write-Host "  $_" }
Write-Host "Reports: $ReportDirectory"
Write-Host 'Not automatic: password rotation (-RotatePasswords) and disabling tasks (-KillPersistence); -RequireFtpTls needs a certificate. A reboot may be required.'
