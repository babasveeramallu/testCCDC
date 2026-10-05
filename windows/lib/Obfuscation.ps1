function ConvertTo-CCDCObfuscated {
    param([Parameter(Mandatory)][string]$Text)
    $key = [Text.Encoding]::UTF8.GetBytes('CCDC-obf-key')
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $bytes[$i] -bxor $key[$i % $key.Length] }
    'obf:' + [Convert]::ToBase64String($bytes)
}

function ConvertFrom-CCDCObfuscated {
    param([Parameter(Mandatory)][string]$Text)
    if ($Text -notmatch '^obf:(.+)$') { return $Text }
    $key = [Text.Encoding]::UTF8.GetBytes('CCDC-obf-key')
    $bytes = [Convert]::FromBase64String($Matches[1])
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = $bytes[$i] -bxor $key[$i % $key.Length] }
    [Text.Encoding]::UTF8.GetString($bytes)
}
