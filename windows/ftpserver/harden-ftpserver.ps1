[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$DisableAnonymousFtp,
    [switch]$RequireFtpTls,
    [switch]$EnableFtpLogging,
    [switch]$HardenTls,
    [switch]$EnableAuditPolicy,
    [string[]]$ExtraFtpRoot = @(),
    [string]$ReportDirectory = "$env:LOCALAPPDATA\CCDC\Reports"
)
# Target: FTP server on Windows Server 2022 (IIS FTP). Audit-only unless -Apply plus a category switch.
# -RequireFtpTls needs a bound certificate and a scoring engine that speaks FTPS; confirm before using.
$ErrorActionPreference = 'Stop'
$lib = Join-Path $PSScriptRoot '..\lib'
. (Join-Path $lib 'Common.ps1')
. (Join-Path $lib 'Baseline.ps1')
. (Join-Path $lib 'RoleCommon.ps1')

try {
    Initialize-CCDCRole -Role 'ftpserver' -ReportDirectory $ReportDirectory
    $write = $DisableAnonymousFtp -or $RequireFtpTls -or $EnableFtpLogging -or $HardenTls -or $EnableAuditPolicy
    Get-CCDCBaseline -IsDomainJoined ([bool]$script:Computer.PartOfDomain) -Path (Join-Path $ReportDirectory "ftpserver-baseline-before-$($script:Stamp).json")
    Show-CCDCCommonHostAudit

    $roots = @($ExtraFtpRoot)
    $svc = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
    if ($svc -and (Get-Module -ListAvailable -Name WebAdministration)) {
        Import-Module WebAdministration -ErrorAction Stop
        Write-Log INFO "FTPSVC status=$($svc.Status) start=$($svc.StartType)"
        foreach ($site in @(Get-ChildItem IIS:\Sites | Where-Object { $_.bindings.Collection.protocol -contains 'ftp' })) {
            $name = $site.Name
            $path = [Environment]::ExpandEnvironmentVariables($site.physicalPath)
            $roots += $path
            $ftp = $site.ftpServer
            $anon = $ftp.security.authentication.anonymousAuthentication.enabled
            $basic = $ftp.security.authentication.basicAuthentication.enabled
            $ctl = $ftp.security.ssl.controlChannelPolicy
            $dat = $ftp.security.ssl.dataChannelPolicy
            $iso = $ftp.userIsolation.mode
            Write-Log INFO "FTP site $name state=$($site.State) path=$path bindings=$(($site.bindings.Collection | ForEach-Object { $_.bindingInformation }) -join ' | ')"
            Write-Log INFO "FTP site $name anonymous=$anon basic=$basic sslControl=$ctl sslData=$dat isolation=$iso logging=$($ftp.logFile.enabled)"
            if ($anon) { Write-Log FLAG "FTP site ${name}: anonymous authentication ENABLED." }
            if ([string]$ctl -match 'SslAllow|SslRequireCredentialsOnly|^[02]$') { Write-Log FLAG "FTP site ${name}: TLS not required (credentials in cleartext)." }
            if ([string]$iso -eq 'None') { Write-Log FLAG "FTP site ${name}: user isolation is None; users can browse the whole root." }
            $authSection = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $name -Filter 'system.ftpServer/security/authorization' -Name '.' -ErrorAction SilentlyContinue
            $rules = @(); if ($authSection) { $rules = @($authSection.Collection) }
            foreach ($r in $rules) { Write-Log INFO "FTP authorization rule site=$name users='$($r.users)' roles='$($r.roles)' perm=$($r.permissions) access=$($r.accessType)"; if ($r.users -eq '*' -or $r.users -eq '?') { Write-Log FLAG "FTP site ${name}: authorization rule grants '$($r.users)' $($r.permissions)." } }

            if ($Apply -and $DisableAnonymousFtp -and $anon) {
                Assert-CCDCAdmin
                if ($PSCmdlet.ShouldProcess($name, 'Disable anonymous FTP authentication')) {
                    Set-ItemProperty "IIS:\Sites\$name" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false
                    if ((Get-ItemProperty "IIS:\Sites\$name" -Name ftpServer.security.authentication.anonymousAuthentication.enabled).Value) { throw "Anonymous FTP verification failed for $name." }
                    Write-Log CHANGE "FTP site ${name}: anonymous authentication disabled."
                }
            }
            if ($Apply -and $RequireFtpTls) {
                Assert-CCDCAdmin
                if (-not $ftp.security.ssl.serverCertHash) { throw "FTP site $name has no SSL certificate bound; refusing to require TLS (would break all logins)." }
                if ($PSCmdlet.ShouldProcess($name, 'Require TLS for control and data channels')) {
                    Set-ItemProperty "IIS:\Sites\$name" -Name ftpServer.security.ssl.controlChannelPolicy -Value 'SslRequire'
                    Set-ItemProperty "IIS:\Sites\$name" -Name ftpServer.security.ssl.dataChannelPolicy -Value 'SslRequire'
                    Write-Log CHANGE "FTP site ${name}: TLS required. Verify the scoring engine can still log in."
                }
            }
            if ($Apply -and $EnableFtpLogging -and -not $ftp.logFile.enabled) {
                Assert-CCDCAdmin
                if ($PSCmdlet.ShouldProcess($name, 'Enable FTP logging')) {
                    Set-ItemProperty "IIS:\Sites\$name" -Name ftpServer.logFile.enabled -Value $true
                    Write-Log CHANGE "FTP site ${name}: logging enabled."
                }
            }
        }
    } else { Write-Log FLAG 'IIS FTP (FTPSVC/WebAdministration) not found. Pass -ExtraFtpRoot for another FTP server to still scan content.' }

    $roots = @($roots | Where-Object { $_ } | Select-Object -Unique)
    foreach ($r in $roots) { Show-CCDCWritableAcl -Path $r }
    Save-CCDCFileHashes -Root $roots -Path (Join-Path $ReportDirectory "ftpserver-root-hashes-$($script:Stamp).csv")
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^\.(exe|dll|bat|cmd|ps1|vbs|js|hta|scr|aspx?|php)$' } | ForEach-Object { Write-Log FLAG "Executable/script content in FTP root: $($_.FullName) modified=$($_.LastWriteTime)" }
    }
    if (Get-Command Get-WebConfiguration -ErrorAction SilentlyContinue) {
        $pasv = (Get-WebConfiguration /system.ftpServer/firewallSupport -ErrorAction SilentlyContinue).lowDataChannelPort
        Write-Log INFO "FTP passive data port range low=$pasv (open only this range, not all ports, on the firewall)"
    }

    if ($write -and -not $Apply) {
        if ($DisableAnonymousFtp) { Write-Log FLAG 'PLAN ONLY: would disable anonymous authentication on every FTP site.' }
        if ($RequireFtpTls) { Write-Log FLAG 'PLAN ONLY: would require TLS on control and data channels (only if a certificate is bound).' }
        if ($EnableFtpLogging) { Write-Log FLAG 'PLAN ONLY: would enable FTP site logging.' }
        if ($HardenTls) { Write-Log FLAG 'PLAN ONLY: would disable SSL 2.0/3.0 and TLS 1.0/1.1 server-side (reboot needed).' }
        if ($EnableAuditPolicy) { Write-Log FLAG 'PLAN ONLY: would enable success+failure audit policy.' }
        Write-Log INFO 'Plan-only complete; add -Apply. Snapshot the VM and copy the FTP root first (restore points are not supported on Server).'
    } elseif ($write -and $Apply) {
        Assert-CCDCAdmin
        if ($HardenTls -and $PSCmdlet.ShouldProcess('SCHANNEL', 'Disable legacy TLS/SSL (server)')) { Set-CCDCSchannelHardening }
        if ($EnableAuditPolicy) { Set-CCDCAuditPolicy -ReportDirectory $ReportDirectory }
        Get-CCDCBaseline -IsDomainJoined ([bool]$script:Computer.PartOfDomain) -Path (Join-Path $ReportDirectory "ftpserver-baseline-after-$($script:Stamp).json")
    }
    Complete-CCDCRole
    exit 0
} catch {
    $m = $_.Exception.Message
    if ($script:Report) { Write-Log ERROR $m } else { Write-Error $m }
    exit 1
}
