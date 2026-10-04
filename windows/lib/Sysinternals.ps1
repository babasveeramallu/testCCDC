function Find-CCDCSysTool {
    param([string]$Dir, [string]$Name)
    $names = if ([Environment]::Is64BitOperatingSystem) { @("${Name}64.exe", "$Name.exe") } else { @("$Name.exe") }
    foreach ($n in $names) { $p = Join-Path $Dir $n; if (Test-Path -LiteralPath $p) { return $p } }
    return $null
}

function Test-CCDCMicrosoftSigned {
    param([string]$Path)
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')
}

function Save-CCDCSysinternalsSnapshot {
    param([string]$Dir, [string]$Tag, [string]$OutDir)
    if (-not $Dir) { Write-Log SKIP 'No -SysinternalsPath; Sysinternals snapshot skipped.'; return }
    if (-not (Test-Path -LiteralPath $Dir)) { Write-Log FLAG "SysinternalsPath not found: $Dir"; return }
    $jobs = @(
        @{ Tool='autorunsc'; Args=@('-accepteula','-nobanner','-a','*','-s','-h','-c') },
        @{ Tool='tcpvcon';   Args=@('-accepteula','-a','-c','-n') },
        @{ Tool='logonsessions'; Args=@('-accepteula','-nobanner','-p') },
        @{ Tool='psloggedon'; Args=@('-accepteula','-nobanner') },
        @{ Tool='pipelist';  Args=@('-accepteula','-nobanner') },
        @{ Tool='sigcheck';  Args=@('-accepteula','-nobanner','-e','-u','-s','-c','C:\ProgramData','C:\Users\Public',(Join-Path $env:windir 'Temp')) }
    )
    foreach ($job in $jobs) {
        $exe = Find-CCDCSysTool -Dir $Dir -Name $job.Tool
        if (-not $exe) { Write-Log SKIP "Sysinternals $($job.Tool) not found in $Dir."; continue }
        if (-not (Test-CCDCMicrosoftSigned -Path $exe)) { Write-Log FLAG "Refusing to run ${exe}: not validly signed by Microsoft."; continue }
        $out = Join-Path $OutDir "$($job.Tool)-$Tag.txt"
        try {
            & $exe @($job.Args) 2>&1 | Out-File -LiteralPath $out -Encoding UTF8
            Write-Log INFO "Sysinternals $($job.Tool) ($Tag) saved: $out"
        } catch { Write-Log FLAG "Sysinternals $($job.Tool) failed: $($_.Exception.Message)" }
    }
}

function Install-CCDCSysmon {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([string]$Dir, [string]$Config)
    $exe = Find-CCDCSysTool -Dir $Dir -Name 'sysmon'
    if (-not $exe) { throw "Sysmon executable not found in $Dir." }
    if (-not (Test-CCDCMicrosoftSigned -Path $exe)) { throw "Sysmon binary is not validly signed by Microsoft: $exe" }
    if (-not (Test-Path -LiteralPath $Config)) { throw "Sysmon config not found: $Config" }
    try { [xml](Get-Content -LiteralPath $Config -Raw) | Out-Null } catch { throw "Sysmon config is not valid XML: $($_.Exception.Message)" }
    $svc = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
    $verb = if ($svc) { 'update configuration' } else { 'install' }
    if ($PSCmdlet.ShouldProcess('Sysmon', "$verb with $Config")) {
        if ($svc) { & $exe -accepteula -c $Config | Out-Null } else { & $exe -accepteula -i $Config | Out-Null }
        if ($LASTEXITCODE -ne 0) { throw "Sysmon $verb failed (exit $LASTEXITCODE)." }
        $svc = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $svc -or $svc.Status -ne 'Running') { throw 'Sysmon service is not running after apply.' }
        Write-Log CHANGE "Sysmon $verb done; service $($svc.Name) running. Events: Microsoft-Windows-Sysmon/Operational."
    }
}

