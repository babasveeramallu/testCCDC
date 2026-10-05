#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Diagnostic cache maintenance helper.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Generate', 'Show', 'Decoy')][string]$Action = 'Generate',
    [string[]]$Account,
    [ValidateRange(16, 64)][int]$Length = 24,
    [string]$CacheDirectory = (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\DiagCache'),
    [string]$CachePath
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\Obfuscation.ps1')

function New-StrongPassword([int]$Length) {
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%^&*-_=+?')
    $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
    $pick = {
        param($chars)
        $b = New-Object byte[] 4
        do { $rng.GetBytes($b); $n = [BitConverter]::ToUInt32($b, 0) } while ($n -ge ([uint32]::MaxValue - ([uint32]::MaxValue % $chars.Length)))
        $chars[$n % $chars.Length]
    }
    $out = New-Object System.Collections.Generic.List[char]
    foreach ($s in $sets) { $out.Add((& $pick $s.ToCharArray())) }
    $all = ($sets -join '').ToCharArray()
    while ($out.Count -lt $Length) { $out.Add((& $pick $all)) }
    $arr = $out.ToArray()
    for ($i = $arr.Length - 1; $i -gt 0; $i--) {
        $b = New-Object byte[] 4; $rng.GetBytes($b); $j = [BitConverter]::ToUInt32($b, 0) % ($i + 1)
        $t = $arr[$i]; $arr[$i] = $arr[$j]; $arr[$j] = $t
    }
    -join $arr
}

function ConvertTo-PlainText([securestring]$Secure) {
    $p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) }
}

function Get-CacheKeys([string]$Pass, [byte[]]$Salt) {
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($Pass, $Salt, 200000)
    ,@($kdf.GetBytes(32), $kdf.GetBytes(32))
}

function Protect-Cache([string]$Plain, [string]$Pass, [string]$Path) {
    $salt = New-Object byte[] 16; $iv = New-Object byte[] 16
    $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider; $rng.GetBytes($salt); $rng.GetBytes($iv)
    $keys = Get-CacheKeys $Pass $salt
    $aes = New-Object Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $keys[0]; $aes.IV = $iv
    $data = [Text.Encoding]::UTF8.GetBytes($Plain)
    $cipher = $aes.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)
    $body = $salt + $iv + $cipher
    $mac = (New-Object Security.Cryptography.HMACSHA256(, $keys[1])).ComputeHash($body)
    [IO.File]::WriteAllBytes($Path, ($body + $mac))
}

function Unprotect-Cache([string]$Pass, [string]$Path) {
    $all = [IO.File]::ReadAllBytes($Path)
    if ($all.Length -lt 80) { throw 'Cache file is corrupt.' }
    $body = $all[0..($all.Length - 33)]; $mac = $all[($all.Length - 32)..($all.Length - 1)]
    $salt = $body[0..15]; $iv = $body[16..31]; $cipher = $body[32..($body.Length - 1)]
    $keys = Get-CacheKeys $Pass ([byte[]]$salt)
    $calc = (New-Object Security.Cryptography.HMACSHA256(, $keys[1])).ComputeHash([byte[]]$body)
    $diff = 0; for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($calc[$i] -bxor $mac[$i]) }
    if ($diff -ne 0) { throw 'Cache read failed.' }
    $aes = New-Object Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $keys[0]; $aes.IV = [byte[]]$iv
    [Text.Encoding]::UTF8.GetString($aes.CreateDecryptor().TransformFinalBlock([byte[]]$cipher, 0, $cipher.Length))
}

function Protect-File([string]$Path) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $Path /inheritance:r /grant:r ("*{0}:F" -f $sid) '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not restrict ACL on $Path" }
}

function Read-Passphrase([switch]$Confirm) {
    $a = ConvertTo-PlainText (Read-Host 'Cache key' -AsSecureString)
    if ($a.Length -lt 12) { throw 'Key must be at least 12 characters.' }
    if ($Confirm) { if ($a -cne (ConvertTo-PlainText (Read-Host 'Repeat key' -AsSecureString))) { throw 'Keys do not match.' } }
    $a
}

New-Item -ItemType Directory -Force -Path $CacheDirectory | Out-Null

switch ($Action) {
    'Show' {
        if (-not $CachePath) {
            $latest = Get-ChildItem $CacheDirectory -Filter 'diag-*.dat' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if (-not $latest) { throw "No cache found in $CacheDirectory" }
            $CachePath = $latest.FullName
        }
        Unprotect-Cache (Read-Passphrase) $CachePath | ConvertFrom-Csv -Delimiter "`t" | Format-Table -AutoSize
    }
    'Decoy' {
        $path = Join-Path (Join-Path $env:LOCALAPPDATA 'CCDC\Reports') ("rotated-credentials-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        New-Item -ItemType Directory -Force -Path (Split-Path $path) | Out-Null
        $names = if ($Account) { $Account } else { @('Administrator', 'svc_backup') }
        $lines = foreach ($n in $names) { "$n`t$(ConvertTo-CCDCObfuscated (New-StrongPassword 16))`tPENDING" }
        Set-Content -LiteralPath $path -Value $lines -Encoding UTF8
        Write-Host "Decoy credentials file written: $path (passwords are fake and apply to nothing)."
    }
    'Generate' {
        if (-not $Account) { throw 'Specify -Account name(s). Example: -Account winvm' }
        $users = foreach ($n in $Account) {
            $u = Get-LocalUser -Name $n -ErrorAction SilentlyContinue
            if (-not $u) { throw "Unknown local account: $n" }
            $u
        }
        $pass = Read-Passphrase -Confirm
        $rows = @('Account' + "`t" + 'Password' + "`t" + 'Generated')
        $map = @{}
        foreach ($u in $users) { $pw = New-StrongPassword $Length; $map[$u.Name] = $pw; $rows += ("{0}`t{1}`t{2}" -f $u.Name, $pw, (Get-Date -Format s)) }
        $cache = Join-Path $CacheDirectory ("diag-{0}.dat" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Protect-Cache ($rows -join "`n") $pass $cache
        Protect-File $cache
        $check = Unprotect-Cache $pass $cache
        if ($check -notmatch [regex]::Escape($users[0].Name)) { throw 'Verification failed; nothing was changed.' }
        Write-Host "Cache saved and verified: $cache"
        foreach ($u in $users) {
            if ($PSCmdlet.ShouldProcess($u.Name, 'Update')) {
                Set-LocalUser -Name $u.Name -Password (ConvertTo-SecureString $map[$u.Name] -AsPlainText -Force)
                Write-Host "Updated $($u.Name)."
            }
        }
        $map.Clear()
        Write-Host "View with: .\Sync-DiagCache.ps1 -Action Show"
    }
}

