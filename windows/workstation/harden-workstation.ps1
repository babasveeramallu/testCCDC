[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$HardenCredentials,
    [switch]$EnablePowerShellLogging,
    [switch]$DisableAutorun,
    [switch]$EnableDefender,
    [switch]$EnableAuditPolicy,
    [switch]$SkipRestorePoint,
    [string]$ReportDirectory = "$env:LOCALAPPDATA\CCDC\Reports"
)
# Target: Windows 11 workstation. Audit-only unless -Apply plus a category switch. Takes before/after restore points.
$ErrorActionPreference = 'Stop'
$lib = Join-Path $PSScriptRoot '..\lib'
. (Join-Path $lib 'Common.ps1')
. (Join-Path $lib 'Baseline.ps1')
. (Join-Path $lib 'RestorePoint.ps1')
. (Join-Path $lib 'RoleCommon.ps1')

try {
    Initialize-CCDCRole -Role 'workstation' -ReportDirectory $ReportDirectory
    $write = $HardenCredentials -or $EnablePowerShellLogging -or $DisableAutorun -or $EnableDefender -or $EnableAuditPolicy
    Get-CCDCBaseline -IsDomainJoined ([bool]$script:Computer.PartOfDomain) -Path (Join-Path $ReportDirectory "workstation-baseline-before-$($script:Stamp).json")
    Show-CCDCCommonHostAudit

    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $psLog = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $autorun = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $wl = Get-ItemProperty $winlogon -ErrorAction SilentlyContinue
    if ($wl.AutoAdminLogon -eq '1') { Write-Log FLAG "Winlogon AutoAdminLogon enabled for '$($wl.DefaultUserName)'; DefaultPassword present=$([bool]$wl.DefaultPassword)." }
    $wd = (Get-ItemProperty $wdigest -ErrorAction SilentlyContinue).UseLogonCredential
    Write-Log INFO "WDigest UseLogonCredential=$wd (1 stores cleartext creds in memory)"
    if ($wd -eq 1) { Write-Log FLAG 'WDigest cleartext credential caching is ON.' }
    $ppl = (Get-ItemProperty $lsa -ErrorAction SilentlyContinue).RunAsPPL
    Write-Log INFO "LSA RunAsPPL=$ppl; UAC EnableLUA=$((Get-ItemProperty $sysPol).EnableLUA) ConsentPromptBehaviorAdmin=$((Get-ItemProperty $sysPol).ConsentPromptBehaviorAdmin)"
    if ((Get-ItemProperty $sysPol).EnableLUA -ne 1) { Write-Log FLAG 'UAC is disabled.' }
    Write-Log INFO "PowerShell ScriptBlockLogging=$((Get-ItemProperty $psLog -ErrorAction SilentlyContinue).EnableScriptBlockLogging); NoDriveTypeAutoRun=$((Get-ItemProperty $autorun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun)"
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { foreach ($v in @(Get-BitLockerVolume -ErrorAction SilentlyContinue)) { Write-Log INFO "BitLocker $($v.MountPoint) protection=$($v.ProtectionStatus)" } }
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        foreach ($m in @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue)) { Write-Log INFO "Local Administrators member: $($m.Name) ($($m.ObjectClass))" }
        foreach ($m in @(Get-LocalGroupMember -SID 'S-1-5-32-555' -ErrorAction SilentlyContinue)) { Write-Log FLAG "Remote Desktop Users member: $($m.Name)" }
    } else { Write-Log FLAG 'Get-LocalGroupMember unavailable; local group membership not collected.' }
    foreach ($share in @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(ADMIN|IPC|[A-Z])\$$' })) { Write-Log FLAG "Non-default SMB share: $($share.Name) -> $($share.Path)" }
    foreach ($dir in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")) {
        if (Test-Path -LiteralPath $dir) { Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue | ForEach-Object { Write-Log FLAG "Startup folder item: $($_.FullName)" } }
    }
    foreach ($hosts in @("$env:SystemRoot\System32\drivers\etc\hosts")) {
        $extra = @(Get-Content -LiteralPath $hosts | Where-Object { $_ -notmatch '^\s*(#|$)' })
        foreach ($line in $extra) { Write-Log FLAG "hosts file entry: $line" }
    }
    $proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($proxy.ProxyEnable -eq 1) { Write-Log FLAG "User proxy enabled: $($proxy.ProxyServer)" }
    foreach ($b in @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)) { Write-Log FLAG "WMI event consumer present: $($b.Name)" }

    if ($write -and -not $Apply) {
        if (-not $SkipRestorePoint) { Write-Log FLAG 'PLAN ONLY: would create a restore point before and after apply.' }
        if ($HardenCredentials) { Write-Log FLAG 'PLAN ONLY: would set WDigest UseLogonCredential=0, LmCompatibilityLevel=5, RunAsPPL=1 (reboot), AutoAdminLogon=0.' }
        if ($EnablePowerShellLogging) { Write-Log FLAG 'PLAN ONLY: would enable PowerShell script block logging.' }
        if ($DisableAutorun) { Write-Log FLAG 'PLAN ONLY: would disable AutoRun/AutoPlay on all drive types.' }
        if ($EnableDefender) { Write-Log FLAG 'PLAN ONLY: would enable Defender real-time, behavior and cloud protection.' }
        if ($EnableAuditPolicy) { Write-Log FLAG 'PLAN ONLY: would enable success+failure audit policy.' }
        Write-Log INFO 'Plan-only complete; add -Apply.'
    } elseif ($write -and $Apply) {
        Assert-CCDCAdmin
        if (-not $SkipRestorePoint) { New-CCDCRestorePoint -Description "CCDC workstation BEFORE $($script:Stamp)" } else { Write-Log FLAG 'Restore point skipped by -SkipRestorePoint.' }
        if ($HardenCredentials -and $PSCmdlet.ShouldProcess('Registry', 'Credential protection settings')) {
            Set-CCDCRegistryValue -Path $wdigest -Name UseLogonCredential -Value 0
            Set-CCDCRegistryValue -Path $lsa -Name LmCompatibilityLevel -Value 5
            Set-CCDCRegistryValue -Path $lsa -Name RunAsPPL -Value 1
            if ($wl.AutoAdminLogon -eq '1') { Set-CCDCRegistryValue -Path $winlogon -Name AutoAdminLogon -Value '0' -Type String }
            Write-Log FLAG 'RunAsPPL takes effect after reboot; legacy NTLMv1 clients will stop authenticating.'
        }
        if ($EnablePowerShellLogging -and $PSCmdlet.ShouldProcess('Registry', 'Enable script block logging')) { Set-CCDCRegistryValue -Path $psLog -Name EnableScriptBlockLogging -Value 1 }
        if ($DisableAutorun -and $PSCmdlet.ShouldProcess('Registry', 'Disable AutoRun')) { Set-CCDCRegistryValue -Path $autorun -Name NoDriveTypeAutoRun -Value 255 }
        if ($EnableDefender -and $PSCmdlet.ShouldProcess('Defender', 'Enable protections')) {
            if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) { throw 'Defender cmdlets unavailable (third-party AV may own protection).' }
            Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -MAPSReporting Advanced
            if ((Get-MpPreference).DisableRealtimeMonitoring) { throw 'Defender real-time verification failed (tamper protection or policy may block it).' }
            Write-Log CHANGE 'Defender real-time, behavior monitoring and cloud reporting enabled.'
        }
        if ($EnableAuditPolicy) { Set-CCDCAuditPolicy -ReportDirectory $ReportDirectory }
        Get-CCDCBaseline -IsDomainJoined ([bool]$script:Computer.PartOfDomain) -Path (Join-Path $ReportDirectory "workstation-baseline-after-$($script:Stamp).json")
        if (-not $SkipRestorePoint) { try { New-CCDCRestorePoint -Description "CCDC workstation AFTER $($script:Stamp)" } catch { Write-Log FLAG "Post-change restore point failed: $($_.Exception.Message)" } }
    }
    Complete-CCDCRole
    exit 0
} catch {
    $m = $_.Exception.Message
    if ($script:Report) { Write-Log ERROR $m } else { Write-Error $m }
    exit 1
}
