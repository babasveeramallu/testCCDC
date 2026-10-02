[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$RotatePasswords,
    [switch]$RotateBuiltInAdministrator,
    [switch]$DisableLegacyProtocols,
    [switch]$KillPersistence,
    [switch]$SetAccountPolicy,
    [switch]$EnforceHostFirewall,
    [switch]$DisableUsbStorage,
    [string[]]$IncludeAccount = @(),
    [string[]]$ExcludeAccount = @(),
    [string[]]$DisableTask = @(),
    [string[]]$ManagementRange = @(),
    [switch]$AllowPasswordRerotation,
    [string]$ReportDirectory = "$env:LOCALAPPDATA\CCDC\Reports"
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'
$script:Actions = [System.Collections.Generic.List[string]]::new()
$script:Flags = [System.Collections.Generic.List[string]]::new()
$script:LeftAlone = [System.Collections.Generic.List[string]]::new()

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

function Set-CCDCAccountPolicy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][bool]$IsDomainJoined,
        [Parameter(Mandatory)][string]$ReportDirectory
    )
    $maxAge = New-TimeSpan -Days 60
    $lockDuration = New-TimeSpan -Minutes 30
    $lockWindow = New-TimeSpan -Minutes 30
    if ($IsDomainJoined) {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { throw 'Domain-joined host needs RSAT ActiveDirectory tools to set the domain policy; local net accounts would not enforce domain users.' }
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop
        $before = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -ErrorAction Stop
        Write-Log INFO "Domain policy target=$($domain.DNSRoot); current min=$($before.MinPasswordLength) history=$($before.PasswordHistoryCount) maxAge=$($before.MaxPasswordAge) lockThreshold=$($before.LockoutThreshold)"
        if ($PSCmdlet.ShouldProcess("Default domain policy $($domain.DNSRoot)", 'Set password/lockout policy')) {
            Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 8 -ComplexityEnabled $true -PasswordHistoryCount 5 -MaxPasswordAge $maxAge -LockoutThreshold 5 -LockoutDuration $lockDuration -LockoutObservationWindow $lockWindow -ErrorAction Stop
            $after = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -ErrorAction Stop
            if ($after.MinPasswordLength -ne 8 -or -not $after.ComplexityEnabled -or $after.PasswordHistoryCount -ne 5 -or $after.MaxPasswordAge.TotalDays -ne 60 -or $after.LockoutThreshold -ne 5 -or $after.LockoutDuration.TotalMinutes -ne 30) { throw 'Domain policy verification failed.' }
            Write-Log CHANGE "Set and verified default domain password policy for $($domain.DNSRoot)."
        }
        return
    }

    $net = Get-Command net.exe -ErrorAction SilentlyContinue
    $secedit = Get-Command secedit.exe -ErrorAction SilentlyContinue
    if (-not $net -or -not $secedit) { throw 'Standalone policy requires net.exe and secedit.exe; no account policy changed.' }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $template = Join-Path $ReportDirectory "account-policy-$stamp.inf"
    $backup = Join-Path $ReportDirectory "account-policy-before-$stamp.inf"
    $db = Join-Path $ReportDirectory "account-policy-$stamp.sdb"
    & $secedit.Source /export /cfg $template /areas SECURITYPOLICY | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $template)) { throw 'secedit export failed; no account policy changed.' }
    Copy-Item -LiteralPath $template -Destination $backup -Force
    $text = Get-Content -LiteralPath $template -Raw
    if ($text -notmatch '(?m)^\[System Access\]\s*$') { throw 'Exported security template has no [System Access] section; refusing edit.' }
    $settings = [ordered]@{ MinimumPasswordLength = 8; PasswordHistorySize = 5; MaximumPasswordAge = 60; PasswordComplexity = 1; LockoutBadCount = 5; ResetLockoutCount = 30; LockoutDuration = 30 }
    $section = [regex]::Match($text, '(?ms)^\[System Access\]\r?\n.*?(?=^\[|\z)').Value
    foreach ($key in $settings.Keys) {
        $line = "$key = $($settings[$key])"
        if ($section -match "(?m)^\s*$key\s*=.*$") { $section = [regex]::Replace($section, "(?m)^\s*$key\s*=.*$", $line) }
        else { $section = $section.TrimEnd("`r", "`n") + "`r`n$line`r`n" }
    }
    $text = [regex]::Replace($text, '(?ms)^\[System Access\]\r?\n.*?(?=^\[|\z)', [System.Text.RegularExpressions.MatchEvaluator]{ param($match) $section }, 1)
    Set-Content -LiteralPath $template -Value $text -Encoding Unicode
    if ($PSCmdlet.ShouldProcess('Local security policy', 'Apply secedit password complexity/history')) {
        & $secedit.Source /configure /db $db /cfg $template /areas SECURITYPOLICY /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) {
            & $secedit.Source /configure /db (Join-Path $ReportDirectory "rollback-$stamp.sdb") /cfg $backup /areas SECURITYPOLICY /quiet | Out-Null
            throw "secedit configuration failed; attempted restore from $backup."
        }
        $netOutput = & $net.Source accounts /minpwlen:8 /uniquepw:5 /maxpwage:60 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 2>&1
        if ($LASTEXITCODE -ne 0) {
            & $secedit.Source /configure /db (Join-Path $ReportDirectory "rollback-$stamp.sdb") /cfg $backup /areas SECURITYPOLICY /quiet | Out-Null
            throw "net accounts failed: $netOutput; attempted secedit restore from $backup."
        }
        Write-Log CHANGE 'Applied local net accounts and secedit policy.'
        $netVerify = & $net.Source accounts 2>&1
        $verifyTemplate = Join-Path $ReportDirectory "account-policy-verify-$stamp.inf"
        & $secedit.Source /export /cfg $verifyTemplate /areas SECURITYPOLICY | Out-Null
        $verifyText = Get-Content -LiteralPath $verifyTemplate -Raw
        Write-Log INFO "net accounts verification:`n$($netVerify -join [Environment]::NewLine)"
        if ($netVerify -notmatch 'Minimum password length:\s+8' -or $netVerify -notmatch 'Maximum password age \(days\):\s+60' -or $netVerify -notmatch 'Length of password history maintained:\s+5' -or $netVerify -notmatch 'Lockout threshold:\s+5' -or $netVerify -notmatch 'Lockout duration \(minutes\):\s+30' -or $verifyText -notmatch '(?m)^PasswordComplexity\s*=\s*1') {
            & $secedit.Source /configure /db (Join-Path $ReportDirectory "rollback-verify-$stamp.sdb") /cfg $backup /areas SECURITYPOLICY /quiet | Out-Null
            throw "Local account policy verification failed; attempted restore from $backup. Inspect secedit export and net accounts output."
        }
        Write-Log CHANGE 'Verified local lockout settings, password complexity, and history.'
    }
}

function Set-CCDCUsbStorage {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR'
    $current = if (Test-Path $path) { (Get-ItemProperty -LiteralPath $path -Name Start -ErrorAction SilentlyContinue).Start } else { $null }
    Write-Log INFO "USBSTOR driver Start current=$current (4=disabled)"
    if ($current -eq 4) { Write-Log SKIP 'USB mass storage is already disabled.'; return }
    if ($PSCmdlet.ShouldProcess($path, 'Set USBSTOR Start=4 (disable USB mass storage)')) {
        if (-not (Test-Path $path)) { throw 'USBSTOR service key is absent; no registry value changed.' }
        New-ItemProperty -LiteralPath $path -Name Start -PropertyType DWord -Value 4 -Force | Out-Null
        $verify = (Get-ItemProperty -LiteralPath $path -Name Start).Start
        if ($verify -ne 4) { throw "USBSTOR verification failed: Start=$verify" }
        Write-Log CHANGE 'Disabled USB mass storage driver; reconnect/reboot may be needed for existing devices.'
    }
}

function Set-CCDCWindowsFirewall {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string[]]$ManagementRange)
    if (-not $ManagementRange.Count) { throw 'Host firewall requires -ManagementRange; no rules changed.' }
    foreach ($range in $ManagementRange) {
        $parts = $range.Split('/')
        if ($parts.Count -gt 2) { throw "Invalid management address/CIDR: $range" }
        $address = $parts[0]
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsed)) { throw "Invalid management address/CIDR: $range" }
        if ($parts.Count -gt 1) {
            $prefix = 0
            if (-not [int]::TryParse($parts[1], [ref]$prefix)) { throw "Invalid management prefix: $range" }
            $maxPrefix = if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
            if ($prefix -lt 0 -or $prefix -gt $maxPrefix) { throw "Invalid management prefix: $range" }
        }
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $listeners = @()
    $listeners += Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Protocol='TCP'; Port=[int]$_.LocalPort; PID=[int]$_.OwningProcess } }
    $listeners += Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Protocol='UDP'; Port=[int]$_.LocalPort; PID=[int]$_.OwningProcess } }
    $listeners = @($listeners | Sort-Object Protocol,Port,PID -Unique)
    $serviceMap = @(Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction Stop)
    $detected = foreach ($listener in $listeners) {
        $service = $serviceMap | Where-Object { $_.ProcessId -eq $listener.PID } | Select-Object -First 1
        if ($service) { [pscustomobject]@{ Protocol=$listener.Protocol; Port=$listener.Port; Service=$service.Name; PID=$listener.PID } }
        else { Write-Log FLAG "Listener $($listener.Protocol)/$($listener.Port) PID=$($listener.PID) has no mapped running service; not auto-allowed." }
    }
    foreach ($special in @(@{Port=3389;Service='TermService'},@{Port=5985;Service='WinRM'},@{Port=5986;Service='WinRM'})) {
        $hasListener = @($listeners | Where-Object { $_.Protocol -eq 'TCP' -and $_.Port -eq $special.Port }).Count -gt 0
        $service = $serviceMap | Where-Object Name -eq $special.Service | Select-Object -First 1
        if ($hasListener -and $service -and -not (@($detected | Where-Object { $_.Protocol -eq 'TCP' -and $_.Port -eq $special.Port }).Count)) {
            $detected += [pscustomobject]@{ Protocol='TCP'; Port=$special.Port; Service=$special.Service; PID=$service.ProcessId }
            Write-Log INFO "Mapped shared/system listener TCP/$($special.Port) to running service $($special.Service)."
        }
    }
    $gpoAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue | Where-Object { $_.PolicyStoreSourceType -eq 'GroupPolicy' })
    if ($gpoAllows.Count) { throw 'Active GPO inbound allow rules exist; review domain policy before enforcing a local-only allowlist.' }
    Write-Log INFO "Detected $(@($detected).Count) listener/service pairs. Management range=$($ManagementRange -join ',')."
    if ($PSCmdlet.ShouldProcess('Windows Defender Firewall', 'Set default inbound block and replace local inbound allows')) {
        $backupPath = Join-Path $ReportDirectory ("firewall-before-{0}.clixml" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $backupWfw = [System.IO.Path]::ChangeExtension($backupPath, '.wfw')
        Get-NetFirewallProfile | Export-Clixml -LiteralPath $backupPath
        & netsh.exe advfirewall export $backupWfw | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backupWfw)) { throw 'Could not export a restorable Windows Firewall backup; no rules changed.' }
        try {
            $localAllows = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue)
            $localAllows | Export-Clixml -LiteralPath ($backupPath + '.rules')
            $localAllows | Disable-NetFirewallRule
            Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -Enabled True
            foreach ($entry in $detected) {
                $name = switch ($entry.Port) {
                    3389 { "CCDC-Host-RDP-$($entry.Port)"; break }
                    { $_ -in @(5985,5986) } { "CCDC-Host-WinRM-$($entry.Port)"; break }
                    default { "CCDC-Detected-$($entry.Protocol)-$($entry.Port)" }
                }
                $remote = if ($entry.Port -in @(3389,5985,5986)) { $ManagementRange } else { 'Any' }
                $existingRule = Get-NetFirewallRule -PolicyStore PersistentStore -DisplayName $name -ErrorAction SilentlyContinue
                if (-not $existingRule) {
                    $existingRule = New-NetFirewallRule -PolicyStore PersistentStore -DisplayName $name -Direction Inbound -Action Allow -Enabled True -Protocol $entry.Protocol -LocalPort $entry.Port -RemoteAddress $remote -Profile Domain,Private,Public
                } else {
                    Set-NetFirewallRule -InputObject $existingRule -Enabled True -Action Allow -Profile Domain,Private,Public
                    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existingRule
                    Set-NetFirewallPortFilter -InputObject $portFilter -Protocol $entry.Protocol -LocalPort $entry.Port
                }
                $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $existingRule
                Set-NetFirewallAddressFilter -InputObject $addressFilter -RemoteAddress $remote
                Write-Log CHANGE "Allow $($entry.Protocol)/$($entry.Port) service=$($entry.Service) remote=$($remote -join ',')"
            }
            $after = Get-NetFirewallProfile
            if (@($after | Where-Object { $_.DefaultInboundAction -ne 'Block' }).Count) { throw 'Firewall default-action verification failed.' }
            foreach ($port in @(3389,5985,5986)) {
                $name = if ($port -eq 3389) { "CCDC-Host-RDP-$port" } else { "CCDC-Host-WinRM-$port" }
                $rule = Get-NetFirewallRule -PolicyStore PersistentStore -DisplayName $name -ErrorAction SilentlyContinue
                if ($rule -and $rule.Enabled) {
                    $remote = @((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule).RemoteAddress)
                    if (Compare-Object ($ManagementRange | Sort-Object) ($remote | Sort-Object)) { throw "Management source verification failed for $name." }
                }
            }
            Write-Log CHANGE "Firewall defaults verified as Block. Backup=$backupWfw; test scoring/admin reachability before continuing."
        } catch {
            $failure = $_.Exception.Message
            & netsh.exe advfirewall import $backupWfw | Out-Null
            $rollbackCode = $LASTEXITCODE
            if ($rollbackCode -ne 0) { throw "Firewall apply failed: $failure; automatic restore also failed (exit $rollbackCode). Backup=$backupWfw" }
            throw "Firewall apply failed: $failure; restored from $backupWfw."
        }
    }
}

try {
    New-ProtectedDirectory -Path $ReportDirectory
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:Report = Join-Path $ReportDirectory "windows-first-hour-$stamp.log"
    New-Item -ItemType File -Path $script:Report -Force | Out-Null
    $ledger = Join-Path $ReportDirectory 'password-rotation-ledger.txt'
    $credentialPath = Join-Path $ReportDirectory "rotated-credentials-$stamp.txt"

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $edition = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $installationType = [string]$edition.InstallationType
    $editionId = [string]$edition.EditionID
    $productName = [string]$edition.ProductName
    $isServer = ($os.ProductType -ne 1) -or ($installationType -match 'Server')
    $isHome = ($editionId -match 'Core' -and -not $isServer)

    Write-Log INFO "OS=$($os.Caption); product=$productName; editionId=$editionId; installationType=$installationType; server=$isServer; home=$isHome"
    if ($computer.PartOfDomain) {
        Write-Log INFO "Membership=domain; domain=$($computer.Domain). This script will not change domain identities."
    } else {
        Write-Log INFO "Membership=standalone workgroup; workgroup=$($computer.Workgroup)."
    }
    Write-Log INFO "PowerShell=$($PSVersionTable.PSVersion); script syntax target=Windows PowerShell 5.1+"
    Write-Log INFO "Run mode=$(if ($Apply) {'apply'} else {'audit-only'}); report=$script:Report"

    if (($RotatePasswords -or $RotateBuiltInAdministrator) -and ($IncludeAccount.Count -eq 0 -or @($ExcludeAccount | Sort-Object -Unique).Count -lt 2)) {
        throw 'Password rotation plan/apply needs explicit -IncludeAccount values and at least two distinct scoring/service/break-glass exclusions.'
    }
    if ($KillPersistence -and $DisableTask.Count -eq 0) { throw '-KillPersistence plan/apply requires exact -DisableTask task paths.' }
    $writeRequested = $RotatePasswords -or $RotateBuiltInAdministrator -or $DisableLegacyProtocols -or $KillPersistence -or $SetAccountPolicy -or $EnforceHostFirewall -or $DisableUsbStorage
    if ($EnforceHostFirewall) {
        if ($ManagementRange.Count -eq 0) { throw '-EnforceHostFirewall requires -ManagementRange CIDR(s); no firewall changes made.' }
        foreach ($range in $ManagementRange) {
            $parts = $range.Split('/')
            if ($parts.Count -gt 2) { throw "Invalid -ManagementRange value: $range" }
            $parsedAddress = $null
            if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$parsedAddress)) { throw "Invalid -ManagementRange value: $range" }
            if ($parts.Count -gt 1) {
                $prefix = 0
                if (-not [int]::TryParse($parts[1], [ref]$prefix)) { throw "Invalid prefix: $range" }
                $maxPrefix = if ($parsedAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
                if ($prefix -lt 0 -or $prefix -gt $maxPrefix) { throw "Invalid prefix: $range" }
            }
        }
    }
    if ($writeRequested -and -not $Apply) {
        if ($RotatePasswords) { foreach ($name in $IncludeAccount) { Write-Log FLAG "PLAN ONLY: would consider password rotation for explicitly selected local account $name; service/task dependencies and exclusions are rechecked on apply." } }
        if ($RotateBuiltInAdministrator) { Write-Log FLAG 'PLAN ONLY: would rotate the built-in Administrator last, after other selected accounts.' }
        if ($DisableLegacyProtocols) { Write-Log FLAG 'PLAN ONLY: would disable SMBv1, LLMNR, and NetBIOS over TCP/IP using local registry/features.' }
        if ($KillPersistence) { foreach ($name in $DisableTask) { Write-Log FLAG "PLAN ONLY: would disable exact scheduled task $name after ShouldProcess confirmation." } }
        if ($SetAccountPolicy) { Write-Log FLAG "PLAN ONLY: would set account policy via $(if ($computer.PartOfDomain) {'Active Directory default domain policy'} else {'net accounts + secedit local security policy'})." }
        if ($EnforceHostFirewall) { Write-Log FLAG "PLAN ONLY: would set all profile defaults inbound=Block, allow detected service listeners, and scope RDP/WinRM to $($ManagementRange -join ',')." }
        if ($DisableUsbStorage) { Write-Log FLAG 'PLAN ONLY: would set USBSTOR Start=4 after reporting its current state.' }
        Write-Log INFO 'Plan-only complete; no changes made. Add -Apply to execute the selected categories.'
        Write-Log INFO "Summary changed=0 flagged=$($script:Flags.Count) left-alone=0 report=$script:Report"
        exit 0
    }
    if ($writeRequested) {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Applying changes requires an elevated administrator session.' }
    }
    if ($Apply -and $SetAccountPolicy) { Set-CCDCAccountPolicy -IsDomainJoined ([bool]$computer.PartOfDomain) -ReportDirectory $ReportDirectory }
    if ($Apply -and $EnforceHostFirewall) { Set-CCDCWindowsFirewall -ManagementRange $ManagementRange }
    if ($Apply -and $DisableUsbStorage) { Set-CCDCUsbStorage }
    if (($RotatePasswords -or $RotateBuiltInAdministrator) -and -not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        throw 'Get-LocalUser is unavailable in this host/session; refusing password changes.'
    }

    Write-Log INFO 'Local account inventory:'
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $localUsers = @(Get-LocalUser | Sort-Object Name)
        foreach ($user in $localUsers) {
            $category = if (-not $user.Enabled) { 'disabled' } elseif ($user.SID -match '-500$') { 'built-in Administrator; rotate last only when explicitly selected' } else { 'review; confirm not scoring/service/break-glass' }
            Write-Log FLAG "Local account $($user.Name) SID=$($user.SID) Enabled=$($user.Enabled): $category"
        }
    } else { Write-Log FLAG 'LocalAccounts module/Get-LocalUser unavailable; account inventory incomplete.' }

    Write-Log INFO 'Scheduled tasks (review all non-Microsoft/nonstandard tasks):'
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        Get-ScheduledTask | Sort-Object TaskPath,TaskName | ForEach-Object {
            if ($_.TaskPath -like '\Microsoft\*') { Write-Log SKIP "Microsoft task left unchanged: $($_.TaskPath)$($_.TaskName)" }
            else { Write-Log FLAG "Third-party task review: $($_.TaskPath)$($_.TaskName) State=$($_.State)" }
        }
    } else { Write-Log FLAG 'ScheduledTasks module unavailable; task inventory incomplete.' }

    $startupHives = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    try {
        Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop | Where-Object { $_.PSChildName -notmatch '_Classes$' } | ForEach-Object {
            $sid = $_.PSChildName
            $startupHives += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run"
            $startupHives += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        }
    } catch { Write-Log FLAG "Could not enumerate all loaded HKEY_USERS hives: $($_.Exception.Message)" }
    foreach ($profile in Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Loaded -and -not $_.Special }) {
        Write-Log SKIP "Run/RunOnce not read for unloaded profile SID=$($profile.SID); no hive was mounted."
    }
    foreach ($hive in $startupHives) {
        if (Test-Path -LiteralPath $hive) {
            $values = Get-ItemProperty -LiteralPath $hive
            foreach ($property in $values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' }) {
                Write-Log FLAG "Startup value $hive :: $($property.Name) = $($property.Value) (review publisher/path)"
            }
        }
    }

    Write-Log INFO 'WMI event subscriptions:'
    foreach ($className in @('__EventFilter','__EventConsumer','__FilterToConsumerBinding')) {
        try {
            Get-CimInstance -Namespace 'root/subscription' -ClassName $className | ForEach-Object {
                $name = if ($_.Name) { $_.Name } else { $_.Filter -or $_.Consumer }
                Write-Log FLAG "WMI $className Name=$name"
            }
        } catch { Write-Log FLAG "Unable to enumerate WMI ${className}: $($_.Exception.Message)" }
    }

    Write-Log INFO 'Services (review non-Microsoft/unexpected paths, accounts, and start modes):'
    Get-CimInstance Win32_Service | Sort-Object Name | ForEach-Object {
        $service = $_
        $binary = if ($service.PathName -match '^\s*"([^"]+\.exe)"') { $Matches[1] } elseif ($service.PathName -match '^\s*([^\s]+\.exe)') { $Matches[1] } else { $null }
        $expanded = if ($binary) { [Environment]::ExpandEnvironmentVariables($binary) } else { '' }
        $summary = "Service $($service.Name) State=$($service.State) Start=$($service.StartMode) Account=$($service.StartName) Path=$($service.PathName)"
        if ($expanded -match "(?i)^$([regex]::Escape($env:windir))\\|^\\SystemRoot\\|\\system32\\svchost\.exe$") {
            Write-Log SKIP "Windows-path service left unchanged: $summary"
        } elseif ($expanded -match "(?i)^$([regex]::Escape($env:ProgramFiles))\\|^$([regex]::Escape(${env:ProgramFiles(x86)}))\\") {
            Write-Log INFO "Installed-app service; verify publisher/dependency before changing: $summary"
        } else {
            Write-Log FLAG "Nonstandard or unresolved service binary; investigate: $summary"
        }
    }

    foreach ($taskName in $DisableTask) {
        $task = Get-ScheduledTask | Where-Object { "$($_.TaskPath)$($_.TaskName)" -eq $taskName }
        if (-not $task) { throw "Exact scheduled task not found: $taskName" }
        if ($task.TaskPath -like '\Microsoft\Windows\*') { throw "Refusing to disable built-in Microsoft task: $taskName" }
        Write-Log FLAG "Explicit task target $taskName; will disable only if -KillPersistence is present."
    }

    if ($KillPersistence) {
        foreach ($taskName in $DisableTask) {
            if ($PSCmdlet.ShouldProcess($taskName, 'Disable scheduled task')) {
                Disable-ScheduledTask -TaskPath (Split-Path $taskName -Parent) -TaskName (Split-Path $taskName -Leaf) | Out-Null
                Write-Log CHANGE "Disabled explicitly named task $taskName"
            }
        }
    }

    if ($DisableLegacyProtocols) {
        $llmnrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        $llmnrValue = if (Test-Path $llmnrPath) { (Get-ItemProperty -LiteralPath $llmnrPath -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast } else { $null }
        Write-Log INFO "LLMNR policy current EnableMulticast=$llmnrValue (0 disables)"
        $adapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE')
        foreach ($adapter in $adapters) {
            $netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($adapter.SettingID)"
            $netbiosValue = if (Test-Path $netbtPath) { (Get-ItemProperty -LiteralPath $netbtPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions } else { $null }
            Write-Log INFO "NetBIOS adapter=$($adapter.Description) registry=$netbtPath current=$netbiosValue (2 disables)"
        }
        $smb = Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue
        $smbRegistry = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $smbClientRegistry = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        $dism = Get-Command Disable-WindowsOptionalFeature -ErrorAction SilentlyContinue
        if (-not $smb -and -not $dism) { throw 'Neither SMB Server cmdlet nor DISM feature servicing is available; no protocol changes made.' }
        if ($smb) { Write-Log INFO 'Set-SmbServerConfiguration is available for SMBv1 server protocol control.' } else { Write-Log FLAG 'SMB server cmdlet unavailable; SMBv1 state may require feature servicing and reboot.' }
        if ($PSCmdlet.ShouldProcess('Windows protocol policy', 'Disable SMBv1, LLMNR, and NetBIOS over TCP/IP')) {
            if (-not (Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
            New-ItemProperty -LiteralPath $llmnrPath -Name EnableMulticast -PropertyType DWord -Value 0 -Force | Out-Null
            Write-Log CHANGE 'Set LLMNR policy EnableMulticast=0.'
            foreach ($adapter in $adapters) {
                $netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($adapter.SettingID)"
                if (-not (Test-Path $netbtPath)) { throw "NetBIOS registry interface key not found: $netbtPath" }
                New-ItemProperty -LiteralPath $netbtPath -Name NetbiosOptions -PropertyType DWord -Value 2 -Force | Out-Null
                Write-Log CHANGE "Disabled NetBIOS over TCP/IP on $($adapter.Description)."
            }
            if (-not (Test-Path $smbRegistry)) { New-Item -Path $smbRegistry -Force | Out-Null }
            if (-not (Test-Path $smbClientRegistry)) { New-Item -Path $smbClientRegistry -Force | Out-Null }
            New-ItemProperty -LiteralPath $smbRegistry -Name SMB1 -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -LiteralPath $smbClientRegistry -Name SMB1 -PropertyType DWord -Value 0 -Force | Out-Null
            if ($smb) {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
                Write-Log CHANGE 'Disabled SMBv1 server protocol.'
            } else {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
                if ($feature -and $feature.State -eq 'Enabled') { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null }
                Write-Log CHANGE 'Set SMB1=0 and requested SMB1Protocol feature disable; reboot may be required.'
            }
        }
    }

    if ($RotatePasswords -or $RotateBuiltInAdministrator) {
        $users = @(Get-LocalUser)
        $selected = foreach ($name in $IncludeAccount) {
            $user = $users | Where-Object Name -eq $name | Select-Object -First 1
            if (-not $user) { throw "Unknown local account: $name" }
            if ($ExcludeAccount -contains $name) { throw "Account is both included and excluded: $name" }
            if ($user.SID -match '-500$' -and -not $RotateBuiltInAdministrator) { Write-Log INFO "Skip built-in Administrator ${name}: requires -RotateBuiltInAdministrator and should be rotated last."; continue }
            if ($user.SID -match '-500$' -and -not ($IncludeAccount -contains $name)) { throw 'Built-in Administrator must be explicitly included.' }
            if ($user.SID -notmatch '-500$' -and -not $RotatePasswords) { throw "Non-built-in account requires -RotatePasswords: $name" }
            if ($user.Name -in @('krbtgt')) { throw 'krbtgt is never changed by this local-account script.' }
            if ($user.Enabled -or ($user.SID -match '-500$' -and $RotateBuiltInAdministrator)) {
                $escapedName = [regex]::Escape($user.Name)
                $serviceUsers = @(Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -and $_.StartName -match "(^|\\)$escapedName$" })
                if ($serviceUsers.Count) {
                    Write-Log SKIP "Skip ${name}: used by running service(s) $($serviceUsers.Name -join ', ')."
                    continue
                }
                $taskUsers = @(Get-ScheduledTask | Where-Object { $_.Principal.UserId -match "(^|\\)$escapedName$" })
                if ($taskUsers.Count) {
                    Write-Log SKIP "Skip ${name}: scheduled task(s) use this account: $($taskUsers.TaskName -join ', ')."
                    continue
                }
                $user
            }
        }
        $selected = @($selected | Sort-Object @{Expression={ if ($_.SID -match '-500$') { 1 } else { 0 } }},Name)
        if (Test-Path -LiteralPath $ledger) {
            $done = Get-Content -LiteralPath $ledger -ErrorAction Stop
            $repeat = @($selected | Where-Object { $done -contains $_.SID.Value })
            if ($repeat.Count -and -not $AllowPasswordRerotation) { throw "One-shot ledger blocks repeat rotation: $($repeat.Name -join ', '). Manual override: -AllowPasswordRerotation." }
            if ($repeat.Count -and $AllowPasswordRerotation) {
                $answer = Read-Host 'Manual override selected. Type ALLOW PASSWORD REROTATION'
                if ($answer -cne 'ALLOW PASSWORD REROTATION') { throw 'Rerotation override not confirmed.' }
            }
        }
        if ($selected.Count -eq 0) { throw 'No enabled, explicitly selected local accounts remain after exclusions.' }
        foreach ($user in $selected) { Write-Log FLAG "Password rotation candidate $($user.Name) SID=$($user.SID)" }
        $phrase = "ROTATE $($selected.Count) LOCAL PASSWORDS"
        $answer = Read-Host "Type '$phrase' to rotate only these selected accounts"
        if ($answer -cne $phrase) { throw 'Password rotation confirmation did not match.' }
        if ($WhatIfPreference) {
            foreach ($user in $selected) { $PSCmdlet.ShouldProcess($user.Name, 'Rotate local password (one-shot)') | Out-Null }
            Write-Log INFO 'WhatIf complete; no credential, ledger, or account changes made.'
            exit 0
        }
        if (-not (Test-Path -LiteralPath $ledger)) { New-Item -ItemType File -Path $ledger | Out-Null }
        New-Item -ItemType File -Path $credentialPath -ErrorAction Stop | Out-Null
        $fileAcl = Get-Acl -LiteralPath $credentialPath
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        & icacls.exe $credentialPath /inheritance:r /grant:r ("*{0}:F" -f $me.Value) '*S-1-5-18:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not restrict credential file ACL: $credentialPath" }
        foreach ($user in $selected) {
            $password = New-RandomPassword
            if ($PSCmdlet.ShouldProcess($user.Name, 'Rotate local password (one-shot)')) {
                Add-Content -LiteralPath $credentialPath -Value "$($user.Name)`t$password`tPENDING" -Encoding UTF8
                try {
                    Add-Content -LiteralPath $ledger -Value $user.SID.Value -Encoding UTF8
                    Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $password -AsPlainText -Force)
                    Add-Content -LiteralPath $credentialPath -Value "$($user.Name)`tCHANGED" -Encoding UTF8
                    Write-Log CHANGE "Rotated local password for $($user.Name); secret stored in protected output."
                } catch {
                    Add-Content -LiteralPath $credentialPath -Value "$($user.Name)`tFAILED: $($_.Exception.Message)" -Encoding UTF8
                    throw
                }
            }
            $password = $null
        }
        Write-Log INFO "Credential output restricted to current user: $credentialPath"
    }

    if (-not $writeRequested) { Write-Log INFO 'Audit-only complete; no changes requested.' }
    Write-Log INFO "Summary changed=$($script:Actions.Count) flagged=$($script:Flags.Count) left-alone=$($script:LeftAlone.Count) report=$script:Report"
    exit 0
} catch {
    $message = $_.Exception.Message
    if ($script:Report) { Write-Log ERROR $message } else { Write-Error $message }
    exit 1
}
