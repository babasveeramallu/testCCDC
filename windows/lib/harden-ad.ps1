#Requires -Version 5.1
<#
.SYNOPSIS
Module 3 - Active Directory and domain controller security (PowerShell 5.1 and 7+).
.DESCRIPTION
Run on a domain controller (needs the ActiveDirectory module). Audits Kerberoastable accounts, DES-only accounts
and privileged group membership; enforces LDAP signing + channel binding and AES-only Kerberos; optionally performs
the krbtgt double password reset. -AuditOnly makes no changes at all.
.PARAMETER LdapChannelBinding  1 = when supported (default, SLA-safe), 2 = always (strictest; legacy clients fail).
.PARAMETER ResetKrbtgt         Perform the krbtgt double reset. ALWAYS needs typed confirmation, even with -Force.
.PARAMETER KrbtgtWaitMinutes   Minutes to wait (after forced replication) between the two resets. 0 = ask interactively.
                               Microsoft guidance for real incidents is >= max ticket lifetime (10 h); shorten only
                               in a competition where you accept that live tickets may be invalidated.
.NOTES
LDAPServerIntegrity=2 requires signing: clients doing unsigned simple binds on 389 (including some scoring checks)
will fail - use LDAPS/signed binds or test first. DES/RC4 removal breaks accounts that only have RC4 keys; the audit
lists DES-only accounts. krbtgt is reset twice because AD keeps the current and previous password.
#>
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$Force,
    [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'CCDC\Reports'),
    [ValidateSet(1, 2)][int]$LdapChannelBinding = 1,
    [switch]$ResetKrbtgt,
    [int]$KrbtgtWaitMinutes = 0
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'Standalone.ps1')
Initialize-CCDCStandalone -Name 'harden-ad' -OutputDirectory $OutputDirectory -AuditOnly:$AuditOnly -Force:$Force

if ((Get-CCDCDomainRole) -lt 4) {
    Write-Log SKIP 'This host is not a domain controller; AD hardening skipped.'
    Complete-CCDCStandalone
    return
}
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log ERROR 'ActiveDirectory PowerShell module not found.'
    exit 1
}
Import-Module ActiveDirectory

# ---------------------------------------------------------------- Audit: Kerberoastable accounts
# Any user account with an SPN can have a service ticket requested by any domain user and cracked offline.
$result = [ordered]@{ Kerberoastable = @(); DesOnly = @(); PrivilegedGroups = @{} }
try {
    $spnUsers = @(Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' `
            -Properties ServicePrincipalName, PasswordLastSet, AdminCount, 'msDS-SupportedEncryptionTypes', Enabled |
            Where-Object { $_.SamAccountName -ne 'krbtgt' })
    foreach ($u in $spnUsers) {
        $row = [pscustomobject]@{ Account = $u.SamAccountName; Enabled = $u.Enabled; AdminCount = $u.AdminCount; PasswordLastSet = $u.PasswordLastSet; SPNs = ($u.ServicePrincipalName -join '; '); EncTypes = $u.'msDS-SupportedEncryptionTypes' }
        $result.Kerberoastable += $row
        Write-Log FLAG "Kerberoastable: $($u.SamAccountName) (AdminCount=$($u.AdminCount); pwdLastSet=$($u.PasswordLastSet)) SPN=$($row.SPNs)"
    }
    if ($spnUsers.Count -eq 0) { Write-Log INFO 'No user accounts with SPNs found.' }
}
catch { Write-Log ERROR "SPN audit failed: $($_.Exception.Message)"; $script:Failures++ }

# Accounts flagged USE_DES_KEY_ONLY (0x200000) will break once DES is removed.
try {
    $des = @(Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2097152)' -ErrorAction Stop)
    foreach ($d in $des) { $result.DesOnly += $d.SamAccountName; Write-Log FLAG "Account uses DES-only keys: $($d.SamAccountName) - clear the flag / reset its password." }
}
catch { Write-Log ERROR "DES audit failed: $($_.Exception.Message)"; $script:Failures++ }

# ---------------------------------------------------------------- Audit: privileged groups
foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators') {
    try {
        $members = @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName)
        $result.PrivilegedGroups[$g] = $members
        Write-Log INFO "Group '$g' ($($members.Count)): $($members -join ', ')"
    }
    catch { Write-Log FLAG "Could not read group '$g' (may not exist in this domain): $($_.Exception.Message)" }
}

# ---------------------------------------------------------------- Domain policy hardening
$ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
# LDAPServerIntegrity: 0 none, 1 negotiate, 2 require signing - blocks LDAP relay/MITM over unsigned binds.
Set-CCDCRegValue -Path $ntds -Name 'LDAPServerIntegrity' -Value 2 -Why 'require LDAP signing'
# LdapEnforceChannelBinding: 0 never, 1 when supported, 2 always - binds LDAPS auth to the TLS channel (stops NTLM relay).
Set-CCDCRegValue -Path $ntds -Name 'LdapEnforceChannelBinding' -Value $LdapChannelBinding -Why 'LDAP channel binding'
# SupportedEncryptionTypes=0x7FFFFFF8 (2147483640): AES128 + AES256 + future types; DES (1,2) and RC4 (4) cleared.
Set-CCDCRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'SupportedEncryptionTypes' -Value 2147483640 -Why 'Kerberos AES only (no DES/RC4)'

# ---------------------------------------------------------------- krbtgt double reset
function Reset-CCDCKrbtgt {
    $krb = Get-ADUser -Identity krbtgt -Properties PasswordLastSet
    Write-Log INFO "krbtgt password last set: $($krb.PasswordLastSet)"
    if ($script:AuditOnly) { Write-Log FLAG 'AUDIT would perform krbtgt double reset.'; return }
    $pdc = (Get-ADDomain).PDCEmulator
    if ($env:COMPUTERNAME -ne $pdc.Split('.')[0]) { Write-Log FLAG "Run this on the PDC emulator ($pdc) for a clean reset; continuing on $env:COMPUTERNAME." }
    Write-Host "`nThis resets krbtgt TWICE. All existing Kerberos tickets become invalid; users/services must re-authenticate." -ForegroundColor Yellow
    # Typed confirmation is mandatory even with -Force.
    if ((Read-Host "Type RESET KRBTGT to continue") -cne 'RESET KRBTGT') { Write-Log SKIP 'krbtgt reset not confirmed.'; return }

    $newPw = { ConvertTo-SecureString (New-CCDCStrongPassword -Length 64) -AsPlainText -Force }   # throwaway, never stored
    try {
        Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (& $newPw) -ErrorAction Stop
        Write-Log CHANGE 'krbtgt reset #1 complete.'
        & repadmin.exe /syncall /AdeP | Out-Null
        if ($KrbtgtWaitMinutes -gt 0) {
            Write-Log INFO "Waiting $KrbtgtWaitMinutes minute(s) for replication before reset #2."
            Start-Sleep -Seconds ($KrbtgtWaitMinutes * 60)
        }
        elseif ((Read-Host 'Confirm replication has completed on all DCs (repadmin /replsummary), then type SECOND RESET') -cne 'SECOND RESET') {
            Write-Log FLAG 'Second krbtgt reset NOT performed. Run again after replication to finish.'; return
        }
        Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (& $newPw) -ErrorAction Stop
        Write-Log CHANGE 'krbtgt reset #2 complete (old and previous passwords both invalidated).'
    }
    catch { Write-Log ERROR "krbtgt reset failed: $($_.Exception.Message)"; $script:Failures++ }
}

if ($ResetKrbtgt) { Reset-CCDCKrbtgt }
else {
    try { Write-Log INFO "krbtgt password last set: $((Get-ADUser -Identity krbtgt -Properties PasswordLastSet).PasswordLastSet) (use -ResetKrbtgt to rotate)" } catch { }
}

Complete-CCDCStandalone
if ($script:Failures -gt 0) { exit 1 }
[pscustomobject]$result
