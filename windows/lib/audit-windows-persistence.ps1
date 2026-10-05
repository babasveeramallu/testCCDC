#Requires -Version 5.1
<#
.SYNOPSIS
Module 4 - Persistence sweeper and PowerShell telemetry (PowerShell 5.1 and 7+).
.DESCRIPTION
Enumerates common persistence locations and returns ONE structured summary object (also saved as JSON in
-OutputDirectory): non-Microsoft scheduled tasks, Run/RunOnce keys (HKLM, WOW6432Node, every loaded user hive),
Winlogon, startup folders, IFEO debugger hijacks, WMI event subscriptions, and services whose binary is outside
C:\Windows\System32 and C:\Program Files*. Then enables Script Block Logging (4104) and transcription unless -AuditOnly.
Audit never deletes anything: review findings, then remove them deliberately.
.PARAMETER TranscriptDirectory  Where PowerShell transcripts go. Created ACL'd: SYSTEM/Administrators full,
                                Authenticated Users write-only (so users can create transcripts but not read others').
#>
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$Force,
    [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'CCDC\Reports'),
    [string]$TranscriptDirectory = (Join-Path $env:ProgramData 'Microsoft\Diagnostics\PSLogs')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'Standalone.ps1')
Initialize-CCDCStandalone -Name 'audit-windows-persistence' -OutputDirectory $OutputDirectory -AuditOnly:$AuditOnly -Force:$Force

$summary = [ordered]@{
    Computer = $env:COMPUTERNAME; Timestamp = (Get-Date -Format o)
    ScheduledTasks = @(); AutorunKeys = @(); StartupFolderItems = @(); IfeoHijacks = @()
    WmiSubscriptions = @(); ServicesOutsideTrustedPaths = @(); Telemetry = $null
}

# ---------------------------------------------------------------- Scheduled tasks (non-Microsoft)
try {
    foreach ($t in (Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\Windows\*' })) {
        $acts = ($t.Actions | ForEach-Object { ("$($_.Execute) $($_.Arguments)").Trim() }) -join ' | '
        $summary.ScheduledTasks += [pscustomobject]@{ Name = $t.TaskName; Path = $t.TaskPath; State = [string]$t.State; RunAs = $t.Principal.UserId; Actions = $acts }
        Write-Log FLAG "Task $($t.TaskPath)$($t.TaskName) [$($t.State)] runas=$($t.Principal.UserId) :: $acts"
    }
}
catch { Write-Log ERROR "Scheduled task sweep failed: $($_.Exception.Message)"; $script:Failures++ }

# ---------------------------------------------------------------- Registry autoruns (Run/RunOnce/Winlogon)
try {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion')
    foreach ($sid in (Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $roots += "Registry::HKEY_USERS\$($sid.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion"
    }
    foreach ($root in $roots) {
        foreach ($k in 'Run', 'RunOnce') {
            $p = "$root\$k"
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $props = Get-ItemProperty -LiteralPath $p
            foreach ($n in ($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                $summary.AutorunKeys += [pscustomobject]@{ Key = $p; Name = $n.Name; Value = [string]$n.Value }
                Write-Log FLAG "Autorun $p :: $($n.Name) = $($n.Value)"
            }
        }
    }
    # Winlogon values attackers replace for logon persistence.
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    foreach ($n in 'Shell', 'Userinit', 'Taskman') {
        if ($wl.$n) {
            $expected = ($n -eq 'Shell' -and $wl.$n -eq 'explorer.exe') -or ($n -eq 'Userinit' -and $wl.$n -match '^C:\\Windows\\system32\\userinit\.exe,?$')
            $summary.AutorunKeys += [pscustomobject]@{ Key = 'Winlogon'; Name = $n; Value = [string]$wl.$n }
            if (-not $expected) { Write-Log FLAG "Winlogon $n = $($wl.$n) (non-default)" }
        }
    }
}
catch { Write-Log ERROR "Autorun sweep failed: $($_.Exception.Message)"; $script:Failures++ }

# ---------------------------------------------------------------- Startup folders
try {
    $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    $folders += Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
    foreach ($f in $folders) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        foreach ($i in (Get-ChildItem -LiteralPath $f -Force -File -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini')) {
            $summary.StartupFolderItems += [pscustomobject]@{ Path = $i.FullName; Modified = $i.LastWriteTime }
            Write-Log FLAG "Startup item: $($i.FullName)"
        }
    }
}
catch { Write-Log ERROR "Startup folder sweep failed: $($_.Exception.Message)"; $script:Failures++ }

# ---------------------------------------------------------------- IFEO Debugger / SilentProcessExit hijacks
# A 'Debugger' value under Image File Execution Options runs an attacker binary whenever the named exe launches (sticky keys etc.).
try {
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($k in (Get-ChildItem $ifeo -ErrorAction SilentlyContinue)) {
        $p = Get-ItemProperty -LiteralPath $k.PSPath
        foreach ($v in 'Debugger', 'MonitorProcess') {
            if ($p.$v) { $summary.IfeoHijacks += [pscustomobject]@{ Target = $k.PSChildName; Value = $v; Data = [string]$p.$v }; Write-Log FLAG "IFEO hijack: $($k.PSChildName) $v = $($p.$v)" }
        }
    }
    $spe = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    foreach ($k in (Get-ChildItem $spe -ErrorAction SilentlyContinue)) {
        $summary.IfeoHijacks += [pscustomobject]@{ Target = $k.PSChildName; Value = 'SilentProcessExit'; Data = [string](Get-ItemProperty -LiteralPath $k.PSPath).MonitorProcess }
        Write-Log FLAG "SilentProcessExit monitor on $($k.PSChildName)"
    }
}
catch { Write-Log ERROR "IFEO sweep failed: $($_.Exception.Message)"; $script:Failures++ }

# ---------------------------------------------------------------- WMI event subscriptions
try {
    foreach ($c in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', 'NTEventLogEventConsumer', 'SMTPEventConsumer', '__EventFilter', '__FilterToConsumerBinding') {
        foreach ($o in (Get-CimInstance -Namespace root\subscription -ClassName $c -ErrorAction SilentlyContinue)) {
            $detail = switch ($c) {
                'CommandLineEventConsumer' { "$($o.Name) :: $($o.CommandLineTemplate)" }
                'ActiveScriptEventConsumer' { "$($o.Name) :: $($o.ScriptText)" }
                '__EventFilter' { "$($o.Name) :: $($o.Query)" }
                '__FilterToConsumerBinding' { "$($o.Filter) -> $($o.Consumer)" }
                default { "$($o.Name)" }
            }
            $summary.WmiSubscriptions += [pscustomobject]@{ Class = $c; Detail = [string]$detail }
            Write-Log FLAG "WMI $c : $detail"
        }
    }
}
catch { Write-Log ERROR "WMI sweep failed: $($_.Exception.Message)"; $script:Failures++ }

# ---------------------------------------------------------------- Services outside trusted paths
try {
    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
        $raw = [string]$s.PathName
        if (-not $raw) { continue }
        $m = [regex]::Match($raw, '^\s*(?:"([^"]+)"|(.+?\.(?:exe|sys|dll))|(\S+))')
        $exe = ($m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value | Where-Object { $_ } | Select-Object -First 1)
        $exe = [Environment]::ExpandEnvironmentVariables(($exe -replace '^\\SystemRoot', $env:SystemRoot))
        if ($exe -notmatch '^[A-Za-z]:') { $exe = Join-Path $env:SystemRoot ($exe -replace '^\\\?\?\\', '') }
        if ($exe -notlike "$env:SystemRoot\System32\*" -and $exe -notlike 'C:\Program Files*' -and $exe -notlike "$env:SystemRoot\SysWOW64\*") {
            $summary.ServicesOutsideTrustedPaths += [pscustomobject]@{ Name = $s.Name; State = $s.State; StartMode = $s.StartMode; Account = $s.StartName; Binary = $raw }
            Write-Log FLAG "Service outside trusted path: $($s.Name) [$($s.State)/$($s.StartMode)] as $($s.StartName) :: $raw"
        }
    }
}
catch { Write-Log ERROR "Service sweep failed: $($_.Exception.Message)"; $script:Failures++ }

# ---------------------------------------------------------------- Telemetry
$psPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
# EnableScriptBlockLogging=1 -> Microsoft-Windows-PowerShell/Operational Event ID 4104 (deobfuscated script text).
Set-CCDCRegValue -Path "$psPol\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1 -Why 'Event 4104'
# EnableTranscripting=1 + OutputDirectory -> full session transcripts; EnableInvocationHeader adds per-command timestamps.
Set-CCDCRegValue -Path "$psPol\Transcription" -Name 'EnableTranscripting' -Value 1 -Why 'PowerShell transcription'
Set-CCDCRegValue -Path "$psPol\Transcription" -Name 'EnableInvocationHeader' -Value 1 -Why 'transcript command headers'
Set-CCDCRegValue -Path "$psPol\Transcription" -Name 'OutputDirectory' -Value $TranscriptDirectory -Type String -Why 'transcript location'
Invoke-CCDCChange -Description "Transcript directory '$TranscriptDirectory' exists with write-only access for users" `
    -IsCompliant { Test-Path -LiteralPath $TranscriptDirectory } `
    -Apply {
        New-Item -ItemType Directory -Path $TranscriptDirectory -Force | Out-Null
        # Admins/SYSTEM full; Authenticated Users can create/append files (WD,AD) but not list or read them.
        & icacls.exe $TranscriptDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-11:(OI)(CI)(WD,AD)' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'icacls failed on transcript directory' }
    }
$summary.Telemetry = [pscustomobject]@{
    ScriptBlockLogging = (Get-ItemProperty "$psPol\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    Transcription = (Get-ItemProperty "$psPol\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting
    TranscriptDirectory = (Get-ItemProperty "$psPol\Transcription" -ErrorAction SilentlyContinue).OutputDirectory
    AuditOnly = [bool]$AuditOnly
}

$result = [pscustomobject]$summary
try {
    $json = Join-Path $OutputDirectory "persistence-summary-$($script:Stamp).json"
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $json -Encoding UTF8
    Write-Log INFO "Structured summary saved: $json"
}
catch { Write-Log ERROR "Could not save summary: $($_.Exception.Message)"; $script:Failures++ }
Write-Log INFO ("Found: tasks={0} autoruns={1} startup={2} ifeo={3} wmi={4} services={5}" -f $summary.ScheduledTasks.Count, $summary.AutorunKeys.Count, $summary.StartupFolderItems.Count, $summary.IfeoHijacks.Count, $summary.WmiSubscriptions.Count, $summary.ServicesOutsideTrustedPaths.Count)
Complete-CCDCStandalone
$result
