function Set-CCDCSmbSigning {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue)) { throw 'SMB cmdlets unavailable; SMB signing unchanged.' }
    $before = Get-SmbServerConfiguration
    Write-Log INFO "SMB server signing before: required=$($before.RequireSecuritySignature) enabled=$($before.EnableSecuritySignature)"
    if ($PSCmdlet.ShouldProcess('SMB server and client', 'Require SMB signing')) {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
        Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
        if (-not (Get-SmbServerConfiguration).RequireSecuritySignature -or -not (Get-SmbClientConfiguration).RequireSecuritySignature) { throw 'SMB signing verification failed.' }
        Write-Log CHANGE 'SMB signing required (server and client). Very old SMB clients/NAS devices may fail to connect.'
    }
}

function Disable-CCDCSpooler {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Log SKIP 'Print Spooler not present.'; return }
    if ($svc.StartType -eq 'Disabled' -and $svc.Status -eq 'Stopped') { Write-Log SKIP 'Print Spooler already stopped and disabled.'; return }
    if ($PSCmdlet.ShouldProcess('Spooler', 'Stop and disable')) {
        Stop-Service -Name Spooler -Force
        Set-Service -Name Spooler -StartupType Disabled
        if ((Get-Service -Name Spooler).StartType -ne 'Disabled') { throw 'Print Spooler disable verification failed.' }
        Write-Log CHANGE 'Print Spooler stopped and disabled (printing will not work until re-enabled).'
    }
}
