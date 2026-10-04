function Initialize-CCDCRole {
    param([Parameter(Mandatory)][string]$Role, [Parameter(Mandatory)][string]$ReportDirectory)
    $script:Actions = New-Object 'System.Collections.Generic.List[string]'
    $script:Flags = New-Object 'System.Collections.Generic.List[string]'
    $script:LeftAlone = New-Object 'System.Collections.Generic.List[string]'
    New-ProtectedDirectory -Path $ReportDirectory
    $script:Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:Report = Join-Path $ReportDirectory "${Role}-$($script:Stamp).log"
    New-Item -ItemType File -Path $script:Report -Force | Out-Null
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $script:Computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $script:IsServerOs = ($os.ProductType -ne 1)
    Write-Log INFO "Role=$Role host=$($env:COMPUTERNAME) os=$($os.Caption) build=$($os.BuildNumber) domainJoined=$($script:Computer.PartOfDomain) domainRole=$($script:Computer.DomainRole)"
    Write-Log INFO "PowerShell=$($PSVersionTable.PSVersion); report=$($script:Report)"
}

function Assert-CCDCAdmin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Applying changes requires an elevated administrator session.' }
}

function Complete-CCDCRole {
    Write-Log INFO "Summary changed=$($script:Actions.Count) flagged=$($script:Flags.Count) left-alone=$($script:LeftAlone.Count) report=$($script:Report)"
}

function Set-CCDCRegistryValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Value, [string]$Type = 'DWord')
    $old = $null
    if (Test-Path -LiteralPath $Path) { $old = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue).$Name }
    else { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    $now = (Get-ItemProperty -LiteralPath $Path -Name $Name).$Name
    if ($now -ne $Value) { throw "Registry verification failed: $Path :: $Name expected $Value got $now" }
    Write-Log CHANGE "Registry $Path :: $Name old=$old new=$now"
}

function Save-CCDCFileHashes {
    param([string[]]$Root, [Parameter(Mandatory)][string]$Path)
    $rows = foreach ($r in $Root) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $h = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
            [pscustomobject]@{ Path = $_.FullName; SHA256 = $h.Hash; Length = $_.Length; LastWriteUtc = $_.LastWriteTimeUtc.ToString('o') }
        }
    }
    @($rows) | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    Write-Log INFO "File hash baseline ($(@($rows).Count) files): $Path"
}

function Find-CCDCSuspiciousFiles {
    param([string[]]$Root, [string[]]$Extension, [int]$Days = 14)
    $cut = (Get-Date).AddDays(-$Days)
    $pattern = 'eval\s*\(|base64_decode|Request(\.Form|\[)|cmd\.exe|powershell(\.exe)?\s+-|System\.Diagnostics\.Process|WScript\.Shell|Runtime\.getRuntime|FromBase64String|Assembly\.Load'
    foreach ($r in $Root) {
        if (-not (Test-Path -LiteralPath $r)) { continue }
        Get-ChildItem -LiteralPath $r -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $Extension -contains $_.Extension.ToLowerInvariant() } | ForEach-Object {
            if ($_.LastWriteTime -gt $cut) { Write-Log FLAG "Recently modified (last $Days d) executable/script content: $($_.FullName) at $($_.LastWriteTime)" }
            if ($_.Length -lt 1MB -and (Select-String -LiteralPath $_.FullName -Pattern $pattern -Quiet -ErrorAction SilentlyContinue)) { Write-Log FLAG "Suspicious content pattern: $($_.FullName)" }
        }
    }
}

function Show-CCDCWritableAcl {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        $who = $rule.IdentityReference.Value
        if ($rule.AccessControlType -eq 'Allow' -and "$($rule.FileSystemRights)" -match 'Write|Modify|FullControl|CreateFiles' -and $who -match 'Everyone|BUILTIN\\Users|Authenticated Users|IIS_IUSRS|IUSR') {
            Write-Log FLAG "Writable by low-privilege identity: $Path -> $who ($($rule.FileSystemRights))"
        }
    }
}

function Show-CCDCCommonHostAudit {
    Write-Log INFO 'Common host audit (read-only):'
    if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        $smb = Get-SmbServerConfiguration
        Write-Log INFO "SMB1=$($smb.EnableSMB1Protocol) requireSigning=$($smb.RequireSecuritySignature) encryptData=$($smb.EncryptData)"
        if ($smb.EnableSMB1Protocol) { Write-Log FLAG 'SMBv1 server protocol is enabled.' }
        if (-not $smb.RequireSecuritySignature) { Write-Log FLAG 'SMB signing is not required.' }
    }
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if ($spooler) { Write-Log INFO "Print Spooler status=$($spooler.Status) start=$($spooler.StartType)" }
    $ts = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    $nla = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication
    Write-Log INFO "RDP denyConnections=$($ts.fDenyTSConnections) (0=RDP on) NLA=$nla"
    if ($ts.fDenyTSConnections -eq 0 -and $nla -ne 1) { Write-Log FLAG 'RDP is enabled without Network Level Authentication.' }
    $lm = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).LmCompatibilityLevel
    Write-Log INFO "LmCompatibilityLevel=$lm (5 = NTLMv2 only)"
    if ($null -eq $lm -or $lm -lt 5) { Write-Log FLAG 'LAN Manager auth level allows LM/NTLMv1 responses.' }
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mp = Get-MpComputerStatus
            Write-Log INFO "Defender realtime=$($mp.RealTimeProtectionEnabled) antivirus=$($mp.AntivirusEnabled) signatures=$($mp.AntivirusSignatureLastUpdated)"
            if (-not $mp.RealTimeProtectionEnabled) { Write-Log FLAG 'Defender real-time protection is OFF.' }
        } catch { Write-Log FLAG "Defender status unreadable: $($_.Exception.Message)" }
    }
    $tools = 'AnyDesk','TeamViewer','ngrok','ncat','nc','psexesvc','rclone','chisel','plink','ScreenConnect','Splashtop','meterpreter'
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $tools -contains $_.ProcessName })) { Write-Log FLAG "Remote-access/tunnel tool running: $($p.ProcessName) PID=$($p.Id)" }
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'AnyDesk|TeamViewer|PSEXESVC|ScreenConnect|Splashtop' })) { Write-Log FLAG "Remote-access service present: $($s.Name) state=$($s.State)" }
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort)
    foreach ($l in $listeners) {
        $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
        Write-Log INFO ("Listener TCP/{0} bind={1} process={2} PID={3}" -f $l.LocalPort, $l.LocalAddress, $proc.ProcessName, $l.OwningProcess)
    }
}

function Set-CCDCAuditPolicy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$ReportDirectory, [switch]$IncludeDomainController)
    $subs = [ordered]@{
        'Logon' = '{0CCE9215-69AE-11D9-BED3-505054503030}'
        'Logoff' = '{0CCE9216-69AE-11D9-BED3-505054503030}'
        'Account Lockout' = '{0CCE9217-69AE-11D9-BED3-505054503030}'
        'Special Logon' = '{0CCE921B-69AE-11D9-BED3-505054503030}'
        'Other Object Access (scheduled tasks)' = '{0CCE9227-69AE-11D9-BED3-505054503030}'
        'Process Creation' = '{0CCE922B-69AE-11D9-BED3-505054503030}'
        'Audit Policy Change' = '{0CCE922F-69AE-11D9-BED3-505054503030}'
        'User Account Management' = '{0CCE9235-69AE-11D9-BED3-505054503030}'
        'Security Group Management' = '{0CCE9237-69AE-11D9-BED3-505054503030}'
        'Credential Validation' = '{0CCE923F-69AE-11D9-BED3-505054503030}'
    }
    if ($IncludeDomainController) {
        $subs['Directory Service Changes'] = '{0CCE923C-69AE-11D9-BED3-505054503030}'
        $subs['Kerberos Service Ticket Operations'] = '{0CCE9240-69AE-11D9-BED3-505054503030}'
        $subs['Kerberos Authentication Service'] = '{0CCE9242-69AE-11D9-BED3-505054503030}'
    }
    $backup = Join-Path $ReportDirectory "auditpol-before-$($script:Stamp).csv"
    & auditpol.exe /backup /file:$backup | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backup)) { throw 'Could not back up current audit policy; nothing changed.' }
    Write-Log INFO "Audit policy backup (restore with auditpol /restore /file:<path>): $backup"
    if ($PSCmdlet.ShouldProcess('Advanced audit policy', 'Enable success+failure auditing for key subcategories')) {
        foreach ($name in $subs.Keys) {
            & auditpol.exe /set /subcategory:"$($subs[$name])" /success:enable /failure:enable | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $name." }
            $check = (& auditpol.exe /get /subcategory:"$($subs[$name])" 2>&1) -join ' '
            if ($check -notmatch 'Success') { throw "Audit verification failed for $name : $check" }
            Write-Log CHANGE "Audit enabled (success+failure): $name"
        }
        Set-CCDCRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1
    }
}

function Set-CCDCSchannelHardening {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    foreach ($proto in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
        $key = "$base\$proto\Server"
        Set-CCDCRegistryValue -Path $key -Name Enabled -Value 0
        Set-CCDCRegistryValue -Path $key -Name DisabledByDefault -Value 1
    }
    Write-Log FLAG 'SCHANNEL changes need a reboot; confirm the scoring engine supports TLS 1.2 before rebooting.'
}
