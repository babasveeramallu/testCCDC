function New-CCDCRestorePoint {
    param([Parameter(Mandatory)][string]$Description)
    if ($script:IsServerOs) { throw 'System Restore points are unsupported on Windows Server. Take a VM snapshot/backup and rerun with -SkipRestorePoint.' }
    $srKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $freqName = 'SystemRestorePointCreationFrequency'
    $oldFreq = (Get-ItemProperty -LiteralPath $srKey -Name $freqName -ErrorAction SilentlyContinue).$freqName
    try {
        Enable-ComputerRestore -Drive "$($env:SystemDrive)\" -ErrorAction Stop
        New-ItemProperty -LiteralPath $srKey -Name $freqName -PropertyType DWord -Value 0 -Force | Out-Null
        $beforeCount = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count
        Checkpoint-Computer -Description $Description -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $match = @(Get-ComputerRestorePoint -ErrorAction Stop | Where-Object { $_.Description -eq $Description })
        if (-not $match.Count) { throw "Restore point '$Description' not found after creation (before=$beforeCount)." }
        Write-Log CHANGE "Restore point created: '$Description' sequence=$($match[-1].SequenceNumber)"
    } finally {
        if ($null -eq $oldFreq) { Remove-ItemProperty -LiteralPath $srKey -Name $freqName -ErrorAction SilentlyContinue }
        else { New-ItemProperty -LiteralPath $srKey -Name $freqName -PropertyType DWord -Value $oldFreq -Force | Out-Null }
    }
}

