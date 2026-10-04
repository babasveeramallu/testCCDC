function Get-CCDCBaseline {
    param([bool]$IsDomainJoined, [string]$Path)
    $b = [ordered]@{ Timestamp = (Get-Date -Format 'o'); Host = $env:COMPUTERNAME; DomainJoined = $IsDomainJoined }
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $lu = @(Get-LocalUser)
        $b.LocalUsersTotal = $lu.Count
        $b.LocalUsersEnabled = @($lu | Where-Object Enabled).Count
        $b.LocalUsersDisabled = @($lu | Where-Object { -not $_.Enabled }).Count
        $b.LocalUsersPasswordNeverExpires = @($lu | Where-Object { $_.Enabled -and -not $_.PasswordExpires }).Count
        $b.LocalUsersNoPasswordRequired = @($lu | Where-Object { $_.Enabled -and -not $_.PasswordRequired }).Count
        $b.LocalUserNames = @($lu | ForEach-Object { '{0}(enabled={1})' -f $_.Name, $_.Enabled })
    }
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        try {
            $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
            $b.LocalAdministratorsCount = $admins.Count
            $b.LocalAdministrators = @($admins | ForEach-Object { $_.Name })
        } catch { $b.LocalAdministrators = "unreadable: $($_.Exception.Message)" }
        try { $b.RemoteDesktopUsers = @(Get-LocalGroupMember -SID 'S-1-5-32-555' -ErrorAction Stop | ForEach-Object { $_.Name }) } catch { }
    }
    if ($IsDomainJoined -and (Get-Module -ListAvailable -Name ActiveDirectory)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $b.DomainUsersTotal = @(Get-ADUser -Filter *).Count
            $b.DomainUsersEnabled = @(Get-ADUser -Filter 'Enabled -eq $true').Count
            $b.DomainAdminsCount = @(Get-ADGroupMember -Identity 'Domain Admins' -Recursive).Count
        } catch { $b.DomainQueryError = $_.Exception.Message }
    }
    $b.ListeningTcpPorts = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    $b.ServicesRunning = @(Get-CimInstance Win32_Service -Filter "State='Running'").Count
    $b.ServicesAutoNotRunning = @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'").Count
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $tasks = @(Get-ScheduledTask)
        $b.ScheduledTasksTotal = $tasks.Count
        $b.ScheduledTasksNonMicrosoft = @($tasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }).Count
    }
    if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) { $b.SmbShares = @(Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object { '{0}={1}' -f $_.Name, $_.Path }) }
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) { $b.FirewallProfiles = @(Get-NetFirewallProfile | ForEach-Object { '{0}: enabled={1} inbound={2}' -f $_.Name, $_.Enabled, $_.DefaultInboundAction }) }
    $b.UsbStorStart = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name Start -ErrorAction SilentlyContinue).Start
    $b.NetAccounts = @(& net.exe accounts 2>&1 | ForEach-Object { "$_" })
    foreach ($key in $b.Keys) {
        $value = $b[$key]
        if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { Write-Log INFO "BASELINE $key ($(@($value).Count)): $(@($value) -join '; ')" }
        else { Write-Log INFO "BASELINE $key = $value" }
    }
    $b | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Log INFO "Baseline saved to $Path"
}

