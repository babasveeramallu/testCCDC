[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$SecureDnsZones,
    [switch]$HardenDcAuth,
    [switch]$DisableSpooler,
    [switch]$EnableAuditPolicy,
    [string[]]$AllowedZoneTransferServer = @(),
    [string]$ReportDirectory = "$env:LOCALAPPDATA\CCDC\Reports"
)
# Target: AD / DNS on Windows Server 2019. Audit-only unless -Apply plus a category switch.
$ErrorActionPreference = 'Stop'
$lib = Join-Path $PSScriptRoot '..\lib'
. (Join-Path $lib 'Common.ps1')
. (Join-Path $lib 'Baseline.ps1')
. (Join-Path $lib 'RoleCommon.ps1')

try {
    Initialize-CCDCRole -Role 'addns' -ReportDirectory $ReportDirectory
    $write = $SecureDnsZones -or $HardenDcAuth -or $DisableSpooler -or $EnableAuditPolicy
    if ($script:Computer.DomainRole -lt 4) { Write-Log FLAG 'This host is not a domain controller (DomainRole<4); AD checks will be skipped.' }
    Get-CCDCBaseline -IsDomainJoined ([bool]$script:Computer.PartOfDomain) -Path (Join-Path $ReportDirectory "addns-baseline-before-$($script:Stamp).json")
    Show-CCDCCommonHostAudit

    $isDc = $script:Computer.DomainRole -ge 4
    $domain = $null
    if ($isDc -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain
        $forest = Get-ADForest
        Write-Log INFO "Domain=$($domain.DNSRoot) domainMode=$($domain.DomainMode) forestMode=$($forest.ForestMode) PDC=$($domain.PDCEmulator)"
        foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners') {
            try {
                $m = @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop)
                Write-Log INFO "Group '$g' members ($($m.Count)): $(($m | ForEach-Object { $_.SamAccountName }) -join ', ')"
                if ($g -in 'Schema Admins','Account Operators','Print Operators','Server Operators','DnsAdmins' -and $m.Count) { Write-Log FLAG "Privileged group '$g' is not empty; verify every member." }
            } catch { Write-Log INFO "Group '$g' not readable/absent: $($_.Exception.Message)" }
        }
        $users = @(Get-ADUser -Filter * -Properties Enabled,PasswordNeverExpires,PasswordNotRequired,DoesNotRequirePreAuth,TrustedForDelegation,ServicePrincipalName,AdminCount,PasswordLastSet,LastLogonDate,SIDHistory,Description)
        Write-Log INFO "Users total=$($users.Count) enabled=$(@($users | Where-Object Enabled).Count) disabled=$(@($users | Where-Object { -not $_.Enabled }).Count)"
        foreach ($u in $users | Where-Object Enabled) {
            if ($u.PasswordNotRequired) { Write-Log FLAG "AD user $($u.SamAccountName): PasswordNotRequired" }
            if ($u.DoesNotRequirePreAuth) { Write-Log FLAG "AD user $($u.SamAccountName): Kerberos pre-auth disabled (AS-REP roastable)" }
            if ($u.TrustedForDelegation) { Write-Log FLAG "AD user $($u.SamAccountName): unconstrained delegation" }
            if ($u.ServicePrincipalName.Count) { Write-Log FLAG "AD user $($u.SamAccountName): has SPN (Kerberoastable): $($u.ServicePrincipalName -join ', ')" }
            if ($u.SIDHistory.Count) { Write-Log FLAG "AD user $($u.SamAccountName): has SIDHistory (possible persistence)" }
            if ($u.AdminCount -eq 1 -and $u.SamAccountName -ne 'Administrator' -and $u.SamAccountName -ne 'krbtgt') { Write-Log FLAG "AD user $($u.SamAccountName): AdminCount=1 (current/former privileged)" }
            if ($u.Description -match '(?i)pass(word)?\s*[:=]') { Write-Log FLAG "AD user $($u.SamAccountName): description may contain a password" }
        }
        foreach ($c in @(Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -ErrorAction SilentlyContinue | Where-Object { $_.DistinguishedName -notmatch 'OU=Domain Controllers' })) { Write-Log FLAG "Computer $($c.Name): unconstrained delegation on a non-DC" }
        $krb = Get-ADUser krbtgt -Properties PasswordLastSet
        Write-Log INFO "krbtgt PasswordLastSet=$($krb.PasswordLastSet) (rotate twice, 10+ h apart, only as a deliberate manual step)"
        $pol = Get-ADDefaultDomainPasswordPolicy
        Write-Log INFO "Domain password policy: min=$($pol.MinPasswordLength) complexity=$($pol.ComplexityEnabled) history=$($pol.PasswordHistoryCount) lockout=$($pol.LockoutThreshold)"
        foreach ($gpo in @(Get-GPO -All -ErrorAction SilentlyContinue)) { Write-Log INFO "GPO '$($gpo.DisplayName)' modified=$($gpo.ModificationTime) status=$($gpo.GpoStatus)" }
        $sysvol = Join-Path $env:SystemRoot "SYSVOL\domain\scripts"
        if (Test-Path -LiteralPath $sysvol) { Get-ChildItem -LiteralPath $sysvol -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { Write-Log FLAG "SYSVOL logon script present, review content: $($_.FullName)" } }
    }

    $dnsFeature = Get-Service -Name DNS -ErrorAction SilentlyContinue
    if ($dnsFeature -and (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) {
        foreach ($z in @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' })) {
            Write-Log INFO "DNS zone $($z.ZoneName) type=$($z.ZoneType) dynamicUpdate=$($z.DynamicUpdate) secondaries=$($z.SecureSecondaries) integrated=$($z.IsDsIntegrated)"
            if ($z.ZoneType -eq 'Primary' -and $z.DynamicUpdate -eq 'NonsecureAndSecure') { Write-Log FLAG "DNS zone $($z.ZoneName) allows NON-secure dynamic updates." }
            if ($z.ZoneType -eq 'Primary' -and $z.SecureSecondaries -eq 'TransferAnyServer') { Write-Log FLAG "DNS zone $($z.ZoneName) allows zone transfer to ANY server." }
            if ($SecureDnsZones -and $Apply -and $z.ZoneType -eq 'Primary' -and $z.IsDsIntegrated -and $z.DynamicUpdate -ne 'Secure') {
                if ($PSCmdlet.ShouldProcess($z.ZoneName, 'Set dynamic update to Secure')) { Set-DnsServerPrimaryZone -Name $z.ZoneName -DynamicUpdate Secure; Write-Log CHANGE "DNS zone $($z.ZoneName): DynamicUpdate=Secure" }
            }
            if ($SecureDnsZones -and $Apply -and $z.ZoneType -eq 'Primary' -and $z.SecureSecondaries -eq 'TransferAnyServer') {
                if ($AllowedZoneTransferServer.Count) {
                    if ($PSCmdlet.ShouldProcess($z.ZoneName, "Limit zone transfer to $($AllowedZoneTransferServer -join ',')")) { Set-DnsServerPrimaryZone -Name $z.ZoneName -SecureSecondaries TransferToSecureServers -SecondaryServers $AllowedZoneTransferServer; Write-Log CHANGE "DNS zone $($z.ZoneName): transfers limited to $($AllowedZoneTransferServer -join ',')" }
                } else {
                    if ($PSCmdlet.ShouldProcess($z.ZoneName, 'Disable zone transfers')) { Set-DnsServerPrimaryZone -Name $z.ZoneName -SecureSecondaries NoTransfer; Write-Log CHANGE "DNS zone $($z.ZoneName): zone transfers disabled" }
                }
            }
        }
        $fwd = Get-DnsServerForwarder -ErrorAction SilentlyContinue
        Write-Log INFO "DNS forwarders: $($fwd.IPAddress -join ', ') recursion=$((Get-DnsServerRecursion -ErrorAction SilentlyContinue).Enable)"
        $zoneName = if ($domain) { $domain.DNSRoot } else { $env:USERDNSDOMAIN }
        if ($zoneName) { foreach ($r in @(Get-DnsServerResourceRecord -ZoneName $zoneName -RRType A -ErrorAction SilentlyContinue | Where-Object { $_.TimeStamp -and $_.TimeStamp -gt (Get-Date).AddHours(-2) })) { Write-Log INFO "Recent DNS A record: $($r.HostName) -> $($r.RecordData.IPv4Address) at $($r.TimeStamp)" } }
    }

    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $netlogon = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    Write-Log INFO "LDAPServerIntegrity=$((Get-ItemProperty $ntds -ErrorAction SilentlyContinue).LDAPServerIntegrity) (2=require signing) FullSecureChannelProtection=$((Get-ItemProperty $netlogon -ErrorAction SilentlyContinue).FullSecureChannelProtection) (1=Zerologon enforcement) RestrictAnonymous=$((Get-ItemProperty $lsa).RestrictAnonymous)"
    $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
    if ($isDc -and $spooler -and $spooler.Status -eq 'Running') { Write-Log FLAG 'Print Spooler is running on a DC (PrintNightmare / coercion risk).' }

    if ($write -and -not $Apply) {
        if ($SecureDnsZones) { Write-Log FLAG 'PLAN ONLY: would set AD-integrated primary zones to Secure dynamic updates and restrict zone transfers.' }
        if ($HardenDcAuth) { Write-Log FLAG 'PLAN ONLY: would set LDAPServerIntegrity=2, FullSecureChannelProtection=1, RestrictAnonymous=1, LmCompatibilityLevel=5.' }
        if ($DisableSpooler) { Write-Log FLAG 'PLAN ONLY: would stop and disable the Print Spooler service.' }
        if ($EnableAuditPolicy) { Write-Log FLAG 'PLAN ONLY: would enable success+failure auditing incl. directory service and Kerberos events.' }
        Write-Log INFO 'Plan-only complete; add -Apply. Take a VM snapshot and a system-state backup first (restore points are not supported on Server).'
    } elseif ($write -and $Apply) {
        if (-not $isDc) { throw 'Refusing to apply DC-specific hardening on a non-domain-controller.' }
        Assert-CCDCAdmin
        if ($HardenDcAuth) {
            if ($PSCmdlet.ShouldProcess('Registry', 'LDAP signing, Zerologon enforcement, anonymous restriction, NTLMv2-only')) {
                Set-CCDCRegistryValue -Path $ntds -Name LDAPServerIntegrity -Value 2
                Set-CCDCRegistryValue -Path $netlogon -Name FullSecureChannelProtection -Value 1
                Set-CCDCRegistryValue -Path $lsa -Name RestrictAnonymous -Value 1
                Set-CCDCRegistryValue -Path $lsa -Name LmCompatibilityLevel -Value 5
                Write-Log FLAG 'Test domain logons from every Windows host and the scoring engine now; revert LDAPServerIntegrity to 1 if LDAP clients break.'
            }
        }
        if ($DisableSpooler -and $PSCmdlet.ShouldProcess('Spooler', 'Stop and disable')) {
            Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled
            if ((Get-Service Spooler).StartType -ne 'Disabled') { throw 'Spooler disable verification failed.' }
            Write-Log CHANGE 'Print Spooler stopped and disabled.'
        }
        if ($EnableAuditPolicy) { Set-CCDCAuditPolicy -ReportDirectory $ReportDirectory -IncludeDomainController }
        Get-CCDCBaseline -IsDomainJoined $true -Path (Join-Path $ReportDirectory "addns-baseline-after-$($script:Stamp).json")
    }
    Complete-CCDCRole
    exit 0
} catch {
    $m = $_.Exception.Message
    if ($script:Report) { Write-Log ERROR $m } else { Write-Error $m }
    exit 1
}
