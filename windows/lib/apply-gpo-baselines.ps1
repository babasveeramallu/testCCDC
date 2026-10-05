#Requires -Version 5.1
<#
.SYNOPSIS
Module 5 - GPO baseline ingestion (LGPO.exe) and Defender Attack Surface Reduction rules (PowerShell 5.1 and 7+).
.DESCRIPTION
1. If LGPO.exe is found, backs up the current local policy and imports GPO backup folders with 'LGPO.exe /g <path>'.
2. Enables three ASR rules (LSASS credential theft, executable content from email, Office child processes).
.PARAMETER GpoBackupPath  Folder containing GPO backups ({GUID} folders), or a single backup folder. Optional.
.PARAMETER LgpoPath       Explicit path to LGPO.exe. Otherwise searched in .\tools, this folder, the repo root, and PATH.
.PARAMETER AsrMode        Enabled (block, default), AuditMode (log only - use first if unsure), or Warn.
.NOTES
ASR needs Defender as the active AV with real-time protection on. The LSASS rule can flag some legitimate
software that touches LSASS - validate in AuditMode if a scored application misbehaves.
#>
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$Force,
    [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'CCDC\Reports'),
    [string]$GpoBackupPath,
    [string]$LgpoPath,
    [ValidateSet('Enabled', 'AuditMode', 'Warn')][string]$AsrMode = 'Enabled'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'Standalone.ps1')
Initialize-CCDCStandalone -Name 'apply-gpo-baselines' -OutputDirectory $OutputDirectory -AuditOnly:$AuditOnly -Force:$Force

# ---------------------------------------------------------------- LGPO ingestion
$lgpo = $null
$candidates = @($LgpoPath, (Join-Path $PSScriptRoot '..\tools\LGPO.exe'), (Join-Path $PSScriptRoot 'LGPO.exe'), (Join-Path $PSScriptRoot '..\..\tools\LGPO.exe')) | Where-Object { $_ }
foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { $lgpo = (Resolve-Path -LiteralPath $c).Path; break } }
if (-not $lgpo) { $cmd = Get-Command 'LGPO.exe' -ErrorAction SilentlyContinue; if ($cmd) { $lgpo = $cmd.Source } }

if (-not $lgpo) { Write-Log SKIP 'LGPO.exe not found (Microsoft Security Compliance Toolkit); GPO ingestion skipped.' }
elseif (-not $GpoBackupPath) { Write-Log SKIP "LGPO.exe found at $lgpo but no -GpoBackupPath given; GPO ingestion skipped." }
elseif (-not (Test-Path -LiteralPath $GpoBackupPath)) { Write-Log ERROR "GPO backup path not found: $GpoBackupPath"; $script:Failures++ }
else {
    # LGPO /g imports a GPO backup folder; a root folder holding several {GUID} backups is imported one at a time.
    $items = @(Get-ChildItem -LiteralPath $GpoBackupPath -Directory | Where-Object { $_.Name -match '^\{[0-9A-Fa-f-]{36}\}$' })
    if ($items.Count -eq 0) { $items = @(Get-Item -LiteralPath $GpoBackupPath) }
    if ($AuditOnly) {
        foreach ($i in $items) { Write-Log FLAG "AUDIT would import GPO backup: $($i.FullName)"; $script:Findings++ }
    }
    else {
        try {
            $bk = Join-Path $OutputDirectory "lgpo-before-$($script:Stamp)"
            New-Item -ItemType Directory -Path $bk -Force | Out-Null
            & $lgpo /b $bk | Out-Null    # /b backs up current local policy so it can be restored with /g
            if ($LASTEXITCODE -ne 0) { throw "LGPO backup exit code $LASTEXITCODE" }
            Write-Log CHANGE "Current local policy backed up: $bk (restore: LGPO.exe /g <that folder>)"
        }
        catch { Write-Log ERROR "Policy backup failed, import aborted: $($_.Exception.Message)"; $script:Failures++; $items = @() }
        foreach ($i in $items) {
            try {
                & $lgpo /g $i.FullName | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "LGPO exit code $LASTEXITCODE" }
                Write-Log CHANGE "Imported GPO backup: $($i.FullName)"
            }
            catch { Write-Log ERROR "GPO import failed for $($i.FullName): $($_.Exception.Message)"; $script:Failures++ }
        }
        if ($items.Count) { & gpupdate.exe /target:computer /force | Out-Null }
    }
}

# ---------------------------------------------------------------- Defender ASR
if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
    Write-Log SKIP 'Defender cmdlets unavailable; ASR rules skipped.'
}
else {
    try { if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled) { Write-Log FLAG 'Defender real-time protection is OFF: ASR rules will not enforce until it is enabled.' } } catch { }
    $actionValue = @{ Enabled = 1; AuditMode = 2; Warn = 6 }[$AsrMode]
    # GUIDs are the ones published by Microsoft (the GUIDs in the original request did not match the published list).
    $rules = [ordered]@{
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    }
    foreach ($id in $rules.Keys) {
        $desc = "ASR rule $id ($($rules[$id])) action=$AsrMode"
        Invoke-CCDCChange -Description $desc `
            -IsCompliant {
                $mp = Get-MpPreference
                $ids = @($mp.AttackSurfaceReductionRules_Ids | ForEach-Object { "$_".ToLower() })
                $pos = [array]::IndexOf($ids, $id.ToLower())
                ($pos -ge 0) -and ([int]@($mp.AttackSurfaceReductionRules_Actions)[$pos] -eq $actionValue)
            } `
            -Apply {
                # Add-MpPreference appends/updates this rule without wiping other configured ASR rules.
                Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions $AsrMode -ErrorAction Stop
            }
    }
}
Complete-CCDCStandalone
if ($script:Failures -gt 0) { exit 1 }
