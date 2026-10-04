[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$DisableDirectoryBrowsing,
    [switch]$HideServerHeader,
    [switch]$HardenTls,
    [switch]$EnableAuditPolicy,
    [string[]]$ExtraWebRoot = @(),
    [string]$ReportDirectory = "$env:LOCALAPPDATA\CCDC\Reports"
)
# Target: Web server on Windows Server 2019 (IIS). Audit-only unless -Apply plus a category switch.
$ErrorActionPreference = 'Stop'
$lib = Join-Path $PSScriptRoot '..\lib'
. (Join-Path $lib 'Common.ps1')
. (Join-Path $lib 'Baseline.ps1')
. (Join-Path $lib 'RoleCommon.ps1')

try {
    Initialize-CCDCRole -Role 'webserver' -ReportDirectory $ReportDirectory
    $write = $DisableDirectoryBrowsing -or $HideServerHeader -or $HardenTls -or $EnableAuditPolicy
    Get-CCDCBaseline -IsDomainJoined ([bool]$script:Computer.PartOfDomain) -Path (Join-Path $ReportDirectory "webserver-baseline-before-$($script:Stamp).json")
    Show-CCDCCommonHostAudit

    $roots = @($ExtraWebRoot)
    $iis = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    $hasIis = $false
    if ($iis -and (Get-Module -ListAvailable -Name WebAdministration)) {
        Import-Module WebAdministration -ErrorAction Stop
        $hasIis = $true
        Write-Log INFO "W3SVC status=$($iis.Status) start=$($iis.StartType)"
        foreach ($f in @(Get-WindowsFeature -Name Web-* -ErrorAction SilentlyContinue | Where-Object Installed)) { Write-Log INFO "IIS feature installed: $($f.Name)" }
        foreach ($pool in @(Get-ChildItem IIS:\AppPools)) {
            $id = $pool.processModel.identityType
            Write-Log INFO "AppPool $($pool.Name) state=$($pool.State) identity=$id user=$($pool.processModel.userName)"
            if ($id -eq 'LocalSystem') { Write-Log FLAG "AppPool $($pool.Name) runs as LocalSystem; use ApplicationPoolIdentity." }
        }
        foreach ($site in @(Get-ChildItem IIS:\Sites)) {
            $path = [Environment]::ExpandEnvironmentVariables($site.physicalPath)
            $roots += $path
            Write-Log INFO "Site $($site.Name) state=$($site.State) path=$path bindings=$(($site.bindings.Collection | ForEach-Object { $_.protocol + ' ' + $_.bindingInformation }) -join ' | ')"
            $dirBrowse = (Get-WebConfigurationProperty -PSPath "IIS:\Sites\$($site.Name)" -Filter /system.webServer/directoryBrowse -Name enabled).Value
            if ($dirBrowse) { Write-Log FLAG "Site $($site.Name): directory browsing ENABLED." }
            if ($site.bindings.Collection | Where-Object { $_.protocol -eq 'http' }) { Write-Log FLAG "Site $($site.Name): plain HTTP binding present." }
            $anon = (Get-WebConfigurationProperty -PSPath "IIS:\Sites\$($site.Name)" -Filter /system.webServer/security/authentication/anonymousAuthentication -Name userName).Value
            if ($anon) { Write-Log FLAG "Site $($site.Name): anonymous auth runs as fixed account '$anon'." }
            if ($DisableDirectoryBrowsing -and $Apply -and $dirBrowse) {
                Assert-CCDCAdmin
                if ($PSCmdlet.ShouldProcess($site.Name, 'Disable directory browsing')) {
                    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$($site.Name)" -Filter /system.webServer/directoryBrowse -Name enabled -Value $false
                    if ((Get-WebConfigurationProperty -PSPath "IIS:\Sites\$($site.Name)" -Filter /system.webServer/directoryBrowse -Name enabled).Value) { throw "Directory browsing verification failed for $($site.Name)." }
                    Write-Log CHANGE "Site $($site.Name): directory browsing disabled."
                }
            }
        }
        foreach ($hdr in @(Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter /system.webServer/httpProtocol/customHeaders -Name . -ErrorAction SilentlyContinue)) { foreach ($h in $hdr.Collection) { Write-Log INFO "Custom response header: $($h.name)=$($h.value)" } }
        if ($HideServerHeader -and $Apply) {
            Assert-CCDCAdmin
            if ($PSCmdlet.ShouldProcess('IIS', 'Remove Server header and X-Powered-By')) {
                Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter /system.webServer/security/requestFiltering -Name removeServerHeader -Value $true
                Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter /system.webServer/httpProtocol/customHeaders -Name . -AtElement @{ name = 'X-Powered-By' } -ErrorAction SilentlyContinue
                Write-Log CHANGE 'IIS Server header suppressed; X-Powered-By removed if present.'
            }
        }
    } else { Write-Log FLAG 'IIS (W3SVC/WebAdministration) not found. Pass -ExtraWebRoot for a non-IIS web server (Apache/nginx) to still scan content.' }

    $roots = @($roots | Where-Object { $_ } | Select-Object -Unique)
    foreach ($r in $roots) { Show-CCDCWritableAcl -Path $r }
    Save-CCDCFileHashes -Root $roots -Path (Join-Path $ReportDirectory "webserver-webroot-hashes-$($script:Stamp).csv")
    Find-CCDCSuspiciousFiles -Root $roots -Extension @('.asp','.aspx','.ashx','.asmx','.php','.jsp','.cer','.config','.bat','.cmd','.ps1','.exe','.dll') -Days 14
    foreach ($cfg in $roots | ForEach-Object { Join-Path $_ 'web.config' } | Where-Object { Test-Path -LiteralPath $_ }) {
        $txt = Get-Content -LiteralPath $cfg -Raw
        if ($txt -match '(?i)customErrors\s+mode="Off"') { Write-Log FLAG "$cfg : customErrors Off leaks stack traces." }
        if ($txt -match '(?i)<compilation[^>]*debug="true"') { Write-Log FLAG "$cfg : compilation debug=true." }
        if ($txt -match '(?i)(password|pwd)\s*=') { Write-Log FLAG "$cfg : contains credential-looking strings." }
    }
    $schannelTls1 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -ErrorAction SilentlyContinue).Enabled
    Write-Log INFO "SCHANNEL TLS 1.0 server Enabled=$schannelTls1 (null = OS default)"

    if ($write -and -not $Apply) {
        if ($DisableDirectoryBrowsing) { Write-Log FLAG 'PLAN ONLY: would disable directory browsing on every site.' }
        if ($HideServerHeader) { Write-Log FLAG 'PLAN ONLY: would remove the Server and X-Powered-By headers.' }
        if ($HardenTls) { Write-Log FLAG 'PLAN ONLY: would disable SSL 2.0/3.0 and TLS 1.0/1.1 server-side (reboot needed).' }
        if ($EnableAuditPolicy) { Write-Log FLAG 'PLAN ONLY: would enable success+failure audit policy and command-line process logging.' }
        Write-Log INFO 'Plan-only complete; add -Apply. Snapshot the VM and copy the web root first (restore points are not supported on Server).'
    } elseif ($write -and $Apply) {
        Assert-CCDCAdmin
        if ($HardenTls -and $PSCmdlet.ShouldProcess('SCHANNEL', 'Disable legacy TLS/SSL (server)')) { Set-CCDCSchannelHardening }
        if ($EnableAuditPolicy) { Set-CCDCAuditPolicy -ReportDirectory $ReportDirectory }
        Get-CCDCBaseline -IsDomainJoined ([bool]$script:Computer.PartOfDomain) -Path (Join-Path $ReportDirectory "webserver-baseline-after-$($script:Stamp).json")
    }
    Complete-CCDCRole
    exit 0
} catch {
    $m = $_.Exception.Message
    if ($script:Report) { Write-Log ERROR $m } else { Write-Error $m }
    exit 1
}
