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

