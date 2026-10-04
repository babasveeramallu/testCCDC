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

