#Requires -Version 5.1
<#
.SYNOPSIS
Module 2 - Legacy protocol removal and host firewall enforcement (PowerShell 5.1 and 7+).
.DESCRIPTION
Disables SMBv1 (feature + server config), LLMNR and NetBIOS over TCP/IP, then enforces the Windows firewall
(all profiles on, inbound Block, outbound Allow) WITHOUT breaking scoring: ICMP echo is allowed, RDP is limited to
management subnets, and every currently-listening service port is allowed first (Block is set last).
A firewall backup (.wfw) is exported before any firewall change so it can be restored with:
    netsh advfirewall import <file>
.PARAMETER AuditOnly         Report only; no changes.
.PARAMETER Force             Skip the 'type APPLY' prompt.
.PARAMETER OutputDirectory   Logs and firewall backup (ACL-restricted).
.PARAMETER ManagementSubnets CIDRs allowed to reach RDP/WinRM, e.g. 10.0.0.0/24. If omitted and RDP is listening,
                             RDP stays open to Any (flagged) so you are not locked out.
.PARAMETER AllowTcpPorts / AllowUdpPorts  Extra scoring ports to allow from Any.
.PARAMETER AllowSmb          Also allow inbound SMB (445) - needed if file shares are scored.
.PARAMETER NoAutoAllowListeners  Do not auto-allow currently listening ports.
.NOTES
'ICMP v4/v5' in the request is implemented as ICMPv4 + ICMPv6 (ICMP version 5 does not exist).
Uses CIM (Get-CimInstance/Invoke-CimMethod) instead of Get-WmiObject, which is absent in PowerShell 7.
#>
[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [switch]$Force,
    [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'CCDC\Reports'),
    [string[]]$ManagementSubnets = @(),
    [int[]]$AllowTcpPorts = @(),
    [int[]]$AllowUdpPorts = @(),
    [switch]$AllowSmb,
    [switch]$NoAutoAllowListeners
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'Standalone.ps1')
Initialize-CCDCStandalone -Name 'disable-legacy-protocols' -OutputDirectory $OutputDirectory -AuditOnly:$AuditOnly -Force:$Force

# ---------------------------------------------------------------- SMBv1
# SMBv1 (EternalBlue/WannaCry) - remove the optional feature AND turn off the server protocol.
Set-CCDCFeatureDisabled -OptionalName 'SMB1Protocol' -ServerName 'FS-SMB1' -Why '(SMBv1 removal)'
if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
    Invoke-CCDCChange -Description 'SMB server: EnableSMB1Protocol = $false' `
        -IsCompliant { -not (Get-SmbServerConfiguration).EnableSMB1Protocol } `
        -Apply { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop }
}
else { Write-Log SKIP 'SMB cmdlets unavailable.' }

# ---------------------------------------------------------------- LLMNR
# EnableMulticast=0 disables LLMNR name resolution, which Responder-style poisoning attacks abuse.
Set-CCDCRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Why 'LLMNR off'

# ---------------------------------------------------------------- NetBIOS over TCP/IP
# TcpipNetbiosOptions: 0=DHCP default, 1=enable, 2=disable. NBT-NS poisoning is disabled by setting 2.
try {
    $adapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction Stop)
    foreach ($nic in $adapters) {
        $idx = $nic.Index
        Invoke-CCDCChange -Description "NetBIOS over TCP/IP disabled on '$($nic.Description)'" `
            -IsCompliant { (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "Index=$idx").TcpipNetbiosOptions -eq 2 } `
            -Apply {
                $r = Invoke-CimMethod -InputObject (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "Index=$idx") -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 }
                if ($r.ReturnValue -notin 0, 1) { throw "SetTcpipNetbios returned $($r.ReturnValue)" }
            }
    }
}
catch { Write-Log ERROR "NetBIOS step failed: $($_.Exception.Message)"; $script:Failures++ }

# ---------------------------------------------------------------- Firewall
if (-not (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue)) {
    Write-Log ERROR 'NetSecurity cmdlets unavailable; firewall step skipped.'; $script:Failures++
}
else {
    $isDc = (Get-CCDCDomainRole) -ge 4
    $mgmt = @($ManagementSubnets | Where-Object { $_ })

    if (-not $AuditOnly) {
        try {
            $backup = Join-Path $OutputDirectory "firewall-before-$($script:Stamp).wfw"
            & netsh.exe advfirewall export $backup | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'netsh export failed' }
            Write-Log CHANGE "Firewall backup exported: $backup (restore: netsh advfirewall import `"$backup`")"
        }
        catch { Write-Log ERROR "Firewall backup failed, firewall changes aborted: $($_.Exception.Message)"; $script:Failures++; Complete-CCDCStandalone; exit 1 }
    }

    function Set-CCDCAllowRule {
        param([string]$RuleName, [string]$Display, [string]$Protocol, [string]$LocalPort, [string[]]$Remote = @('Any'), [string]$IcmpType)
        Invoke-CCDCChange -Description "Firewall allow rule '$Display' ($Protocol $LocalPort $IcmpType from $($Remote -join ','))" `
            -IsCompliant { $r = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue; $r -and ($r.Enabled -eq 'True') } `
            -Apply {
                $p = @{ Name = $RuleName; DisplayName = $Display; Group = 'CCDC'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any'; Protocol = $Protocol; RemoteAddress = $Remote }
                if ($LocalPort) { $p.LocalPort = $LocalPort }
                if ($IcmpType) { $p.IcmpType = $IcmpType }
                Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
                New-NetFirewallRule @p | Out-Null
            }
    }

    # 1) ICMP echo stays allowed - scoring engines use ping for health checks.
    Set-CCDCAllowRule -RuleName 'CCDC-Allow-ICMPv4-Echo' -Display 'CCDC Allow ICMPv4 Echo' -Protocol 'ICMPv4' -IcmpType '8'
    Set-CCDCAllowRule -RuleName 'CCDC-Allow-ICMPv6-Echo' -Display 'CCDC Allow ICMPv6 Echo' -Protocol 'ICMPv6' -IcmpType '128'

    # 2) Currently listening service ports are allowed BEFORE default-inbound is set to Block.
    $tcp = New-Object System.Collections.Generic.HashSet[int]
    $udp = New-Object System.Collections.Generic.HashSet[int]
    foreach ($p in $AllowTcpPorts) { [void]$tcp.Add($p) }
    foreach ($p in $AllowUdpPorts) { [void]$udp.Add($p) }
    if ($isDc) { foreach ($p in 53, 88, 123, 389, 464) { [void]$udp.Add($p) } }   # DNS/Kerberos/NTP/LDAP/kpasswd
    $rdpListening = $false
    if (-not $NoAutoAllowListeners) {
        $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' })
        foreach ($l in $listen) {
            $port = [int]$l.LocalPort
            if ($port -in 3389, 5985, 5986) { if ($port -eq 3389) { $rdpListening = $true }; continue }   # management-scoped below
            if ($port -eq 139) { continue }                                  # NetBIOS session: disabled on purpose
            if ($port -eq 445 -and -not ($AllowSmb -or $isDc)) { Write-Log FLAG 'SMB 445 is listening but not allowed (use -AllowSmb if file shares are scored).'; continue }
            if (-not $isDc -and ($port -in 135, 5040, 7680 -or $port -ge 49152)) { continue }   # client RPC/system noise; DCs need them
            [void]$tcp.Add($port)
        }
    }
    foreach ($port in ($tcp | Sort-Object)) {
        Set-CCDCAllowRule -RuleName "CCDC-Allow-TCP-$port" -Display "CCDC Allow TCP $port" -Protocol 'TCP' -LocalPort "$port"
    }
    foreach ($port in ($udp | Sort-Object)) {
        Set-CCDCAllowRule -RuleName "CCDC-Allow-UDP-$port" -Display "CCDC Allow UDP $port" -Protocol 'UDP' -LocalPort "$port"
    }

    # 3) RDP (and WinRM) restricted to management subnets.
    if ($mgmt.Count -gt 0) {
        Set-CCDCAllowRule -RuleName 'CCDC-Allow-RDP-Mgmt-TCP' -Display 'CCDC Allow RDP (mgmt only) TCP' -Protocol 'TCP' -LocalPort '3389' -Remote $mgmt
        Set-CCDCAllowRule -RuleName 'CCDC-Allow-RDP-Mgmt-UDP' -Display 'CCDC Allow RDP (mgmt only) UDP' -Protocol 'UDP' -LocalPort '3389' -Remote $mgmt
        Set-CCDCAllowRule -RuleName 'CCDC-Allow-WinRM-Mgmt' -Display 'CCDC Allow WinRM (mgmt only)' -Protocol 'TCP' -LocalPort '5985,5986' -Remote $mgmt
        # Built-in 'Remote Desktop' rules allow any source; disable them once the scoped rule exists.
        Invoke-CCDCChange -Description "Built-in 'Remote Desktop' firewall rules disabled (replaced by management-scoped rule)" `
            -IsCompliant { -not (Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' }) } `
            -Apply { Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Disable-NetFirewallRule }
    }
    elseif ($rdpListening) {
        Write-Log FLAG 'RDP is listening and no -ManagementSubnets given: allowing RDP from ANY to avoid lockout. Rerun with -ManagementSubnets to restrict it.'
        Set-CCDCAllowRule -RuleName 'CCDC-Allow-RDP-Any' -Display 'CCDC Allow RDP (UNRESTRICTED - review)' -Protocol 'TCP' -LocalPort '3389'
    }

    # 4) Profiles on, inbound Block, outbound Allow (set last so allow rules already exist).
    foreach ($prof in 'Domain', 'Private', 'Public') {
        Invoke-CCDCChange -Description "Firewall profile $prof : Enabled, inbound Block, outbound Allow" `
            -IsCompliant { $f = Get-NetFirewallProfile -Name $prof; ($f.Enabled -eq 'True') -and ($f.DefaultInboundAction -eq 'Block') -and ($f.DefaultOutboundAction -eq 'Allow') } `
            -Apply { Set-NetFirewallProfile -Name $prof -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow }
    }
    if (-not $AuditOnly) { Write-Log FLAG 'Firewall now blocks unlisted inbound traffic: test every scored service and management access now.' }
}

Complete-CCDCStandalone
if ($script:Failures -gt 0) { exit 1 }
