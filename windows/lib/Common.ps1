function Write-Log {
    param([ValidateSet('INFO','CHANGE','FLAG','SKIP','ERROR')][string]$Level, [string]$Message)
    $line = "[{0}] {1,-6} {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ssK'), $Level, $Message
    Write-Host $line
    Add-Content -LiteralPath $script:Report -Value $line -Encoding UTF8
    if ($Level -eq 'CHANGE') { $script:Actions.Add($Message) }
    if ($Level -eq 'FLAG') { $script:Flags.Add($Message) }
    if ($Level -eq 'SKIP') { $script:LeftAlone.Add($Message) }
}

function New-ProtectedDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    & icacls.exe $Path /inheritance:r /grant:r ("*{0}:(OI)(CI)F" -f $identity.Value) '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not restrict report directory ACL: $Path" }
}

function New-RandomPassword {
    $alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%_-+'
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $chars = foreach ($byte in $bytes) { $alphabet[$byte % $alphabet.Length] }
    return -join $chars
}

