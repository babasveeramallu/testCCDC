# Shared helpers for the standalone competition modules (harden-credentials, disable-legacy-protocols,
# harden-ad, audit-windows-persistence, apply-gpo-baselines). Dot-source AFTER Common.ps1.
# Compatible with Windows PowerShell 5.1 and PowerShell 7+.

function Initialize-CCDCStandalone {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [switch]$AuditOnly,
        [switch]$Force
    )
    $script:Actions = New-Object 'System.Collections.Generic.List[string]'
    $script:Flags = New-Object 'System.Collections.Generic.List[string]'
    $script:LeftAlone = New-Object 'System.Collections.Generic.List[string]'
    $script:AuditOnly = [bool]$AuditOnly
    $script:Failures = 0
    $script:Findings = 0
    $script:OutDir = $OutputDirectory
    $script:Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin -and -not $AuditOnly) { throw 'Run from an elevated PowerShell (or use -AuditOnly for a best-effort read-only check).' }

    # Output directory is ACL-restricted to the current user + SYSTEM so logs/credentials are not world-readable.
    New-ProtectedDirectory -Path $OutputDirectory
    $script:Report = Join-Path $OutputDirectory "$Name-$($script:Stamp).log"
    $mode = if ($AuditOnly) { 'AUDIT ONLY (no changes)' } else { 'APPLY' }
    Write-Log INFO "$Name on $env:COMPUTERNAME; PowerShell=$($PSVersionTable.PSVersion); mode=$mode; log=$($script:Report)"
    if (-not $isAdmin) { Write-Log FLAG 'Not elevated: some checks may be incomplete.' }

    if (-not $AuditOnly -and -not $Force) {
        $answer = Read-Host "This will CHANGE system settings. Type APPLY to continue (or rerun with -AuditOnly / -Force)"
        if ($answer -cne 'APPLY') { throw 'Not confirmed; nothing changed.' }
    }
}

function Complete-CCDCStandalone {
    Write-Log INFO ("Summary: changes={0}; non-compliant(audit)={1}; flags={2}; failures={3}; log={4}" -f $script:Actions.Count, $script:Findings, $script:Flags.Count, $script:Failures, $script:Report)
}

# Core primitive: check state -> (audit | apply) -> verify. Every change goes through try/catch.
function Invoke-CCDCChange {
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$IsCompliant,
        [Parameter(Mandatory)][scriptblock]$Apply
    )
    $okNow = $false
    try { $okNow = [bool](& $IsCompliant) }
    catch { Write-Log ERROR "Check failed: $Description :: $($_.Exception.Message)"; $script:Failures++; return }
    if ($okNow) { Write-Log INFO "Compliant: $Description"; return }
    if ($script:AuditOnly) { Write-Log FLAG "AUDIT non-compliant (would apply): $Description"; $script:Findings++; return }
    try {
        & $Apply | Out-Null
        if (-not [bool](& $IsCompliant)) { throw 'post-change verification failed' }
        Write-Log CHANGE $Description
    }
    catch { Write-Log ERROR "Failed: $Description :: $($_.Exception.Message)"; $script:Failures++ }
}

# Registry DWORD/String helper built on Invoke-CCDCChange.
function Set-CCDCRegValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [string]$Why = '',
        [ValidateSet('DWord', 'String', 'ExpandString')][string]$Type = 'DWord'
    )
    $desc = "Registry $Path :: $Name = $Value" + $(if ($Why) { " ($Why)" } else { '' })
    Invoke-CCDCChange -Description $desc `
        -IsCompliant {
            $cur = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            ($null -ne $cur) -and ("$cur" -eq "$Value")
        } `
        -Apply {
            if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
            New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        }
}

# Returns Enabled / Disabled / DisablePending / NotPresent for a Windows optional feature (client) or server role/feature.
function Get-CCDCFeatureState {
    param([string]$OptionalName, [string]$ServerName)
    try { return [string](Get-WindowsOptionalFeature -Online -FeatureName $OptionalName -ErrorAction Stop).State } catch { }
    if ($ServerName -and (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        try {
            $f = Get-WindowsFeature -Name $ServerName -ErrorAction Stop
            if ($f) { return $(if ($f.Installed) { 'Enabled' } else { 'Disabled' }) }
        } catch { }
    }
    return 'NotPresent'
}

function Set-CCDCFeatureDisabled {
    param([Parameter(Mandatory)][string]$OptionalName, [string]$ServerName, [string]$Why = '')
    Invoke-CCDCChange -Description "Windows feature $OptionalName disabled $Why" `
        -IsCompliant { (Get-CCDCFeatureState -OptionalName $OptionalName -ServerName $ServerName) -in @('Disabled', 'DisablePending', 'NotPresent') } `
        -Apply {
            $done = $false
            try { Disable-WindowsOptionalFeature -Online -FeatureName $OptionalName -NoRestart -ErrorAction Stop | Out-Null; $done = $true } catch { $firstError = $_ }
            if (-not $done -and $ServerName -and (Get-Command Uninstall-WindowsFeature -ErrorAction SilentlyContinue)) {
                Uninstall-WindowsFeature -Name $ServerName -ErrorAction Stop | Out-Null; $done = $true
            }
            if (-not $done) { throw $firstError }
        }
}

function Get-CCDCDomainRole { try { [int](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole } catch { 0 } }

# True if a running service or a stored-password scheduled task runs as this account (rotating would break it - SLA).
function Test-CCDCAccountInUse {
    param([Parameter(Mandatory)][string]$Name)
    $esc = [regex]::Escape($Name)
    $svc = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.StartName -match "(^|\\)$esc$" })
    if ($svc.Count) { return "service(s): $($svc.Name -join ', ')" }
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Principal.UserId -match "(^|\\)$esc$" -and $_.Principal.LogonType -eq 'Password' })
    if ($tasks.Count) { return "scheduled task(s): $($tasks.TaskName -join ', ')" }
    return $null
}

# Strong random password; loops until all four character classes are present.
function New-CCDCStrongPassword {
    param([int]$Length = 24)
    $alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%_-+'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        do {
            $bytes = New-Object byte[] $Length
            $rng.GetBytes($bytes)
            $pw = -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })   # 256 % 64 == 0 -> no modulo bias
        } until ($pw -cmatch '[a-z]' -and $pw -cmatch '[A-Z]' -and $pw -match '\d' -and $pw -match '[!@#$%_+-]')
    } finally { $rng.Dispose() }
    $pw
}

function ConvertTo-CCDCPlainText {
    param([securestring]$Secure)
    $p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) }
}

# Passphrase-encrypted store: salt(16) | iv(16) | AES-256-CBC ciphertext | HMAC-SHA256 (PBKDF2, 200k iterations).
function Protect-CCDCStore {
    param([string]$PlainText, [securestring]$Passphrase, [string]$Path)
    $pass = ConvertTo-CCDCPlainText $Passphrase
    $salt = New-Object byte[] 16; $iv = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($salt); $rng.GetBytes($iv); $rng.Dispose()
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($pass, $salt, 200000)
    $encKey = $kdf.GetBytes(32); $macKey = $kdf.GetBytes(32)
    $aes = [System.Security.Cryptography.Aes]::Create(); $aes.Key = $encKey; $aes.IV = $iv
    $data = [Text.Encoding]::UTF8.GetBytes($PlainText)
    $cipher = $aes.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)
    $body = [byte[]]($salt + $iv + $cipher)
    $mac = (New-Object System.Security.Cryptography.HMACSHA256(, $macKey)).ComputeHash($body)
    [IO.File]::WriteAllBytes($Path, [byte[]]($body + $mac))
    & icacls.exe $Path /inheritance:r /grant:r ("*{0}:F" -f [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) '*S-1-5-18:F' | Out-Null
}

function Unprotect-CCDCStore {
    param([securestring]$Passphrase, [string]$Path)
    $pass = ConvertTo-CCDCPlainText $Passphrase
    $all = [IO.File]::ReadAllBytes($Path)
    if ($all.Length -lt 80) { throw 'Credential file is corrupt.' }
    $body = [byte[]]$all[0..($all.Length - 33)]; $mac = [byte[]]$all[($all.Length - 32)..($all.Length - 1)]
    $salt = [byte[]]$body[0..15]; $iv = [byte[]]$body[16..31]; $cipher = [byte[]]$body[32..($body.Length - 1)]
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($pass, $salt, 200000)
    $encKey = $kdf.GetBytes(32); $macKey = $kdf.GetBytes(32)
    $calc = (New-Object System.Security.Cryptography.HMACSHA256(, $macKey)).ComputeHash($body)
    $diff = 0; for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($calc[$i] -bxor $mac[$i]) }
    if ($diff -ne 0) { throw 'Wrong passphrase or tampered file.' }
    $aes = [System.Security.Cryptography.Aes]::Create(); $aes.Key = $encKey; $aes.IV = $iv
    [Text.Encoding]::UTF8.GetString($aes.CreateDecryptor().TransformFinalBlock($cipher, 0, $cipher.Length))
}

function Read-CCDCPassphrase {
    param([switch]$Confirm)
    $a = Read-Host 'Credential-store passphrase (min 12 chars; never stored)' -AsSecureString
    if ((ConvertTo-CCDCPlainText $a).Length -lt 12) { throw 'Passphrase must be at least 12 characters.' }
    if ($Confirm) {
        $b = Read-Host 'Repeat passphrase' -AsSecureString
        if ((ConvertTo-CCDCPlainText $a) -cne (ConvertTo-CCDCPlainText $b)) { throw 'Passphrases do not match.' }
    }
    $a
}
