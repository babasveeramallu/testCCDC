#Requires -Version 5.1
<#
.SYNOPSIS
Module 1 - Credential and local system hardening (PowerShell 5.1 and 7+).
.DESCRIPTION
Renames/rotates the built-in Administrator, disables Guest, optionally mass-rotates enabled local accounts,
enables LSA protection, forces NTLMv2-only, disables PowerShell v2, enables Defender cloud protection and strict UAC.
Passwords are never printed or logged: they are written to a passphrase-encrypted store (AES-256 + HMAC)
BEFORE any password is changed, inside an ACL-restricted -OutputDirectory.
.PARAMETER AuditOnly   Check state only; change nothing.
.PARAMETER Force       Skip the 'type APPLY' prompt (automation).
.PARAMETER OutputDirectory  Where logs and the encrypted credential store go (ACL-restricted).
.PARAMETER NewAdminName     New name for the built-in Administrator (SID -500).
.PARAMETER RotateAllEnabledUsers  Also rotate every other enabled local account (never done implicitly).
.PARAMETER ExcludeUsers     Accounts never rotated (scoring/service accounts). The current user and accounts
                            used by running services / stored-password tasks are always protected.
.PARAMETER ShowCredentials  Decrypt and display the newest store on screen only, then exit.
.EXAMPLE
.\harden-credentials.ps1 -AuditOnly
.\harden-credentials.ps1 -RotateAllEnabledUsers -ExcludeUsers scoring,svc_web
#>
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$Force,
    [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'CCDC\Reports'),
    [string]$NewAdminName = 'SecAdmin_Local',
    [switch]$RotateAllEnabledUsers,
    [string[]]$ExcludeUsers = @(),
    [ValidateRange(16, 64)][int]$PasswordLength = 24,
    [securestring]$StorePassphrase,
    [switch]$ShowCredentials
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'Standalone.ps1')

if ($ShowCredentials) {
    $latest = Get-ChildItem -LiteralPath $OutputDirectory -Filter 'credstore-*.dat' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) { throw "No credential store in $OutputDirectory" }
    if (-not $StorePassphrase) { $StorePassphrase = Read-CCDCPassphrase }
    Unprotect-CCDCStore -Passphrase $StorePassphrase -Path $latest.FullName | ConvertFrom-Csv -Delimiter "`t" | Format-Table -AutoSize
    return
}

Initialize-CCDCStandalone -Name 'harden-credentials' -OutputDirectory $OutputDirectory -AuditOnly:$AuditOnly -Force:$Force
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

# ---------------------------------------------------------------- Account hygiene
if ((Get-CCDCDomainRole) -ge 4) {
    # Domain controllers have no local SAM accounts; domain accounts are handled by harden-ad.ps1.
    Write-Log SKIP 'Domain controller: local account steps skipped (use harden-ad.ps1 for domain accounts).'
}
elseif (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
    Write-Log FLAG 'Microsoft.PowerShell.LocalAccounts module unavailable in this session; account steps skipped (try Windows PowerShell 5.1 as Administrator).'
    $script:Findings++
}
else {
    try {
        $me =  [Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
        $admin = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
        $planned = New-Object System.Collections.Generic.List[object]

        if ($admin) {
            $inUse = Test-CCDCAccountInUse -Name $admin.Name
            if ($inUse) { Write-Log SKIP "Built-in Administrator '$($admin.Name)' is used by $inUse; not renamed or rotated (SLA protection)." }
            else {
                Invoke-CCDCChange -Description "Rename built-in Administrator '$($admin.Name)' -> '$NewAdminName'" `
                    -IsCompliant { (Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }).Name -ceq $NewAdminName } `
                    -Apply { Rename-LocalUser -InputObject (Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }) -NewName $NewAdminName }
                if (($ExcludeUsers -notcontains $admin.Name) -and ($ExcludeUsers -notcontains $NewAdminName)) {
                    $planned.Add([pscustomobject]@{ Sid = $admin.SID.Value; Role = 'BuiltInAdministrator' })
                }
            }
        }
        else { Write-Log FLAG 'Built-in Administrator (SID -500) not found.' }

        # Guest must stay disabled.
        $guest = Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1
        if ($guest) {
            Invoke-CCDCChange -Description "Built-in Guest account '$($guest.Name)' disabled" `
                -IsCompliant { -not (Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' }).Enabled } `
                -Apply { Disable-LocalUser -InputObject (Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' }) }
        }

        # Mass rotation (explicit opt-in).
        if ($RotateAllEnabledUsers) {
            foreach ($u in (Get-LocalUser | Where-Object { $_.Enabled -and $_.SID.Value -notmatch '-(500|501|503|504)$' })) {
                if ($ExcludeUsers -contains $u.Name) { Write-Log SKIP "Excluded from rotation: $($u.Name)"; continue }
                if ($u.Name -eq $me) { Write-Log SKIP "Current user '$($u.Name)' not rotated (would lock you out of this session)."; continue }
                $inUse = Test-CCDCAccountInUse -Name $u.Name
                if ($inUse) { Write-Log SKIP "Not rotated: $($u.Name) is used by $inUse."; continue }
                $planned.Add([pscustomobject]@{ Sid = $u.SID.Value; Role = 'LocalUser' })
            }
        }
        else { Write-Log INFO 'Mass rotation not requested (use -RotateAllEnabledUsers -ExcludeUsers ...).' }

        if ($planned.Count -eq 0) { Write-Log INFO 'No accounts selected for password rotation.' }
        elseif ($AuditOnly) {
            foreach ($p in $planned) { Write-Log FLAG "AUDIT would rotate password: $((Get-LocalUser -SID $p.Sid).Name) [$($p.Role)]"; $script:Findings++ }
        }
        else {
            # Generate -> store encrypted -> verify store readable -> only then change passwords.
            if (-not $StorePassphrase) { $StorePassphrase = Read-CCDCPassphrase -Confirm }
            $rows = @("Account`tPassword`tRole`tGenerated")
            $secrets = @{}
            foreach ($p in $planned) {
                $name = (Get-LocalUser -SID $p.Sid).Name
                $pw = New-CCDCStrongPassword -Length $PasswordLength
                $secrets[$p.Sid] = $pw
                $rows += ("{0}`t{1}`t{2}`t{3}" -f $name, $pw, $p.Role, (Get-Date -Format s))
            }
            $store = Join-Path $OutputDirectory "credstore-$($script:Stamp).dat"
            Protect-CCDCStore -PlainText ($rows -join "`n") -Passphrase $StorePassphrase -Path $store
            if ((Unprotect-CCDCStore -Passphrase $StorePassphrase -Path $store) -ne ($rows -join "`n")) { throw 'Credential store verification failed; no passwords changed.' }
            Write-Log CHANGE "Encrypted credential store written and verified: $store"
            foreach ($p in $planned) {
                $name = (Get-LocalUser -SID $p.Sid).Name
                try {
                    Set-LocalUser -SID $p.Sid -Password (ConvertTo-SecureString $secrets[$p.Sid] -AsPlainText -Force)
                    Write-Log CHANGE "Password rotated for '$name' [$($p.Role)]"
                }
                catch { Write-Log ERROR "Password rotation failed for '$name': $($_.Exception.Message)"; $script:Failures++ }
            }
            $secrets.Clear()
        }
    }
    catch { Write-Log ERROR "Account hygiene failed: $($_.Exception.Message)"; $script:Failures++ }
}

# ---------------------------------------------------------------- LSASS & credential protection
# RunAsPPL=1: LSASS runs as a Protected Process Light, blocking non-signed code from reading credentials (mimikatz). Needs reboot.
Set-CCDCRegValue -Path $lsa -Name 'RunAsPPL' -Value 1 -Why 'LSA protection; reboot required'
# LmCompatibilityLevel=5: clients send NTLMv2 only; DCs/servers refuse LM and NTLMv1. Old clients (XP, some NAS/scanners) will fail.
Set-CCDCRegValue -Path $lsa -Name 'LmCompatibilityLevel' -Value 5 -Why 'NTLMv2 only; refuse LM and NTLM'
# NoLMHash=1: never store the weak LM hash of passwords in the SAM.
Set-CCDCRegValue -Path $lsa -Name 'NoLMHash' -Value 1 -Why 'no LM hash storage'
# UseLogonCredential=0: stops WDigest caching cleartext passwords in LSASS memory.
Set-CCDCRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Why 'no cleartext creds in memory'

# ---------------------------------------------------------------- Attack surface reduction
# PowerShell v2 has no script block/AMSI logging; attackers downgrade with 'powershell -version 2' to bypass telemetry.
Set-CCDCFeatureDisabled -OptionalName 'MicrosoftWindowsPowerShellV2Root' -ServerName 'PowerShell-V2' -Why '(downgrade-attack protection)'
Set-CCDCFeatureDisabled -OptionalName 'MicrosoftWindowsPowerShellV2' -Why '(downgrade-attack protection)'

# Defender cloud protection: MAPSReporting 2=Advanced; CloudBlockLevel 2=High; samples = send safe samples only.
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    Invoke-CCDCChange -Description 'Defender cloud protection: MAPS Advanced, block level High, safe-sample submission' `
        -IsCompliant { $mp = Get-MpPreference; ($mp.MAPSReporting -eq 2) -and ($mp.CloudBlockLevel -eq 2) -and ($mp.SubmitSamplesConsent -in 1, 3) } `
        -Apply { Set-MpPreference -MAPSReporting Advanced -CloudBlockLevel High -CloudExtendedTimeout 10 -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop }
    Invoke-CCDCChange -Description 'Defender real-time monitoring enabled' `
        -IsCompliant { -not (Get-MpPreference).DisableRealtimeMonitoring } `
        -Apply { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop }
}
else { Write-Log SKIP 'Defender cmdlets unavailable (third-party AV or Defender removed).' }

$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
# EnableLUA=1: User Account Control on (reboot required if it was off).
Set-CCDCRegValue -Path $sys -Name 'EnableLUA' -Value 1 -Why 'UAC enabled'
# ConsentPromptBehaviorAdmin=2: admins get a consent prompt on the secure desktop for every elevation.
Set-CCDCRegValue -Path $sys -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Why 'prompt for consent on secure desktop'

Complete-CCDCStandalone
if ($script:Failures -gt 0) { exit 1 }

