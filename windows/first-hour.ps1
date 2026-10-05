[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Apply,
    [switch]$PlanOnly,
    [switch]$RotatePasswords,
    [switch]$RotateBuiltInAdministrator,
    [switch]$DisableLegacyProtocols,
    [switch]$KillPersistence,
    [switch]$SetAccountPolicy,
    [switch]$EnforceHostFirewall,
    [switch]$DisableUsbStorage,
    [switch]$RequireSmbSigning,
    [switch]$DisableSpooler,
    [switch]$ScopeSystemPorts,
    [string[]]$IncludeAccount = @(),
    [string[]]$ExcludeAccount = @(),
    [string[]]$DisableTask = @(),
    [string[]]$ManagementRange = @(),
    [switch]$AllowPasswordRerotation,
    [switch]$SkipRestorePoint,
    [string]$SysinternalsPath = '',
    [switch]$InstallSysmon,
    [string]$SysmonConfig = '',
    [string]$ReportDirectory = "$env:LOCALAPPDATA\CCDC\Reports"
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'
$script:Actions = [System.Collections.Generic.List[string]]::new()
$script:Flags = [System.Collections.Generic.List[string]]::new()
$script:LeftAlone = [System.Collections.Generic.List[string]]::new()

. (Join-Path $PSScriptRoot 'lib\AccountPolicy.ps1')
. (Join-Path $PSScriptRoot 'lib\Baseline.ps1')
. (Join-Path $PSScriptRoot 'lib\Common.ps1')
. (Join-Path $PSScriptRoot 'lib\HostFirewall.ps1')
. (Join-Path $PSScriptRoot 'lib\Hardening.ps1')
. (Join-Path $PSScriptRoot 'lib\RestorePoint.ps1')
. (Join-Path $PSScriptRoot 'lib\Sysinternals.ps1')
. (Join-Path $PSScriptRoot 'lib\UsbStorage.ps1')

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
    $script:IsServerOs = $isServer
    $writeRequested = $RotatePasswords -or $RotateBuiltInAdministrator -or $DisableLegacyProtocols -or $KillPersistence -or $SetAccountPolicy -or $EnforceHostFirewall -or $DisableUsbStorage -or $RequireSmbSigning -or $DisableSpooler -or $InstallSysmon
    if ($Apply -and $PlanOnly) { throw '-Apply and -PlanOnly cannot be used together.' }
    $applyChanges = $Apply -or ($writeRequested -and -not $PlanOnly)

    Write-Log INFO "OS=$($os.Caption); product=$productName; editionId=$editionId; installationType=$installationType; server=$isServer; home=$isHome"
    if ($computer.PartOfDomain) {
        Write-Log INFO "Membership=domain; domain=$($computer.Domain). This script will not change domain identities."
    } else {
        Write-Log INFO "Membership=standalone workgroup; workgroup=$($computer.Workgroup)."
    }
    Write-Log INFO "PowerShell=$($PSVersionTable.PSVersion); script syntax target=Windows PowerShell 5.1+"
    $runMode = if (-not $writeRequested) { 'audit-only' } elseif ($applyChanges) { 'apply' } else { 'plan-only' }
    Write-Log INFO "Run mode=$runMode; report=$script:Report"

    if (($RotatePasswords -or $RotateBuiltInAdministrator) -and ($IncludeAccount.Count -eq 0 -or @($ExcludeAccount | Sort-Object -Unique).Count -lt 2)) {
        throw 'Password rotation plan/apply needs explicit -IncludeAccount values and at least two distinct scoring/service/break-glass exclusions.'
    }
    if ($KillPersistence -and $DisableTask.Count -eq 0) { throw '-KillPersistence plan/apply requires exact -DisableTask task paths.' }
    if ($InstallSysmon -and (-not $SysinternalsPath -or -not $SysmonConfig)) { throw '-InstallSysmon requires -SysinternalsPath and -SysmonConfig.' }
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
    Write-Log INFO 'Collecting read-only baseline before any change.'
    Get-CCDCBaseline -IsDomainJoined ([bool]$computer.PartOfDomain) -Path (Join-Path $ReportDirectory "baseline-before-$stamp.json")
    Save-CCDCSysinternalsSnapshot -Dir $SysinternalsPath -Tag "before-$stamp" -OutDir $ReportDirectory
    if ($writeRequested -and -not $applyChanges) {
        if (-not $SkipRestorePoint) { Write-Log FLAG 'PLAN ONLY: would create a restore point before and after apply.' }
        if ($RotatePasswords) { foreach ($name in $IncludeAccount) { Write-Log FLAG "PLAN ONLY: would consider password rotation for explicitly selected local account $name; service/task dependencies and exclusions are rechecked on apply." } }
        if ($RotateBuiltInAdministrator) { Write-Log FLAG 'PLAN ONLY: would rotate the built-in Administrator last, after other selected accounts.' }
        if ($DisableLegacyProtocols) { Write-Log FLAG 'PLAN ONLY: would disable SMBv1, LLMNR, and NetBIOS over TCP/IP using local registry/features.' }
        if ($KillPersistence) { foreach ($name in $DisableTask) { Write-Log FLAG "PLAN ONLY: would disable exact scheduled task $name after ShouldProcess confirmation." } }
        if ($SetAccountPolicy) { Write-Log FLAG "PLAN ONLY: would set account policy via $(if ($computer.PartOfDomain) {'Active Directory default domain policy'} else {'net accounts + secedit local security policy'})." }
        if ($EnforceHostFirewall) { Write-Log FLAG "PLAN ONLY: would set all profile defaults inbound=Block, allow detected service listeners, and scope RDP/WinRM to $($ManagementRange -join ',')." }
        if ($DisableUsbStorage) { Write-Log FLAG 'PLAN ONLY: would set USBSTOR Start=4 after reporting its current state.' }
        if ($RequireSmbSigning) { Write-Log FLAG 'PLAN ONLY: would require SMB signing on server and client.' }
        if ($DisableSpooler) { Write-Log FLAG 'PLAN ONLY: would stop and disable the Print Spooler.' }
        if ($InstallSysmon) { Write-Log FLAG "PLAN ONLY: would install/update Sysmon from $SysinternalsPath with config $SysmonConfig." }
        Write-Log INFO 'Plan-only complete; no changes made. Remove -PlanOnly to execute the selected categories.'
        Write-Log INFO "Summary changed=0 flagged=$($script:Flags.Count) left-alone=0 report=$script:Report"
        exit 0
    }
    if ($writeRequested) {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Applying changes requires an elevated administrator session.' }
    }
    if ($applyChanges -and $writeRequested) {
        if ($SkipRestorePoint) { Write-Log FLAG 'Restore point skipped by -SkipRestorePoint.' }
        else { New-CCDCRestorePoint -Description "CCDC first-hour BEFORE $stamp" }
    }
    if ($applyChanges -and $SetAccountPolicy) { Set-CCDCAccountPolicy -IsDomainJoined ([bool]$computer.PartOfDomain) -ReportDirectory $ReportDirectory }
    if ($applyChanges -and $EnforceHostFirewall) { Set-CCDCWindowsFirewall -ManagementRange $ManagementRange -ScopeSystemPorts:$ScopeSystemPorts }
    if ($applyChanges -and $DisableUsbStorage) { Set-CCDCUsbStorage }
    if ($applyChanges -and $RequireSmbSigning) { Set-CCDCSmbSigning }
    if ($applyChanges -and $DisableSpooler) { Disable-CCDCSpooler }
    if ($applyChanges -and $InstallSysmon) { Install-CCDCSysmon -Dir $SysinternalsPath -Config $SysmonConfig }
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
                $acctTasks = @(Get-ScheduledTask | Where-Object { $_.Principal.UserId -match "(^|\\)$escapedName$" })
                $taskUsers = @($acctTasks | Where-Object { $_.Principal.LogonType -eq 'Password' })
                $interactiveTasks = @($acctTasks | Where-Object { $_.Principal.LogonType -ne 'Password' })
                if ($interactiveTasks.Count) { Write-Log INFO "Account ${name} has interactive-logon task(s) that store no password and are not blocking: $($interactiveTasks.TaskName -join ', ')." }
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
    if ($applyChanges -and $writeRequested) {
        Get-CCDCBaseline -IsDomainJoined ([bool]$computer.PartOfDomain) -Path (Join-Path $ReportDirectory "baseline-after-$stamp.json")
        Save-CCDCSysinternalsSnapshot -Dir $SysinternalsPath -Tag "after-$stamp" -OutDir $ReportDirectory
        if (-not $SkipRestorePoint) {
            try { New-CCDCRestorePoint -Description "CCDC first-hour AFTER $stamp" }
            catch { Write-Log FLAG "Post-change restore point failed: $($_.Exception.Message)" }
        }
    }
    Write-Log INFO "Summary changed=$($script:Actions.Count) flagged=$($script:Flags.Count) left-alone=$($script:LeftAlone.Count) report=$script:Report"
    exit 0
} catch {
    $message = $_.Exception.Message
    if ($script:Report) { Write-Log ERROR $message } else { Write-Error $message }
    exit 1
}


