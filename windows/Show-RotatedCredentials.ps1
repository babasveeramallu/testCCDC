#Requires -Version 5.1
<#
.SYNOPSIS
Decodes obfuscated passwords from a rotated-credentials file for on-screen viewing.
Output is shown in the console only; nothing is written to disk.
#>
[CmdletBinding()]
param([string]$Path)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\Obfuscation.ps1')
if (-not $Path) {
    $latest = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'CCDC\Reports') -Filter 'rotated-credentials-*.txt' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) { throw 'No rotated-credentials file found.' }
    $Path = $latest.FullName
}
Get-Content -LiteralPath $Path | ForEach-Object {
    $p = $_ -split "`t"
    if ($p.Count -ge 3) { [pscustomobject]@{ Account = $p[0]; Password = (ConvertFrom-CCDCObfuscated $p[1]); Status = $p[2] } }
    else { [pscustomobject]@{ Account = $p[0]; Password = ''; Status = ($p[1..($p.Count-1)] -join ' ') } }
} | Format-Table -AutoSize
