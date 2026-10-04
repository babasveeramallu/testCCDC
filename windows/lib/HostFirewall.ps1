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

