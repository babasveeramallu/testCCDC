# CCDC Scripts Operator Guide

This directory contains Windows and Linux host audit/hardening scripts plus a Splunk configuration generator. Run audits first, review the generated reports, and apply one category at a time on a disposable snapshot before using any script on competition systems.

## Safety Rules

- Audits with no change-category switches are read-only. The Windows first-hour script applies selected categories by default; use `-PlanOnly` to preview them without changes. Windows role scripts still require `-Apply`, and Linux scripts require `--apply`.
- A plan-only run is not a substitute for checking the target service and scoring requirements. Review the plan and report before applying.
- Take a VM snapshot or backup before apply. Windows System Restore points are client-only and are not available on Server; Linux firewall apply has an automatic timed rollback only on systemd hosts.
- Keep console access or a tested out-of-band recovery path. Firewall, authentication, TLS, account policy, and service changes can interrupt scoring or administration.
- Do not put real passwords, private keys, or other secrets in command lines, reports, or version control. Password rotation writes generated passwords to a restricted report file; protect and remove that file after securely recording the credentials.
- The Windows scripts target Windows PowerShell 5.1-compatible syntax. Linux scripts require Bash and the listed system tools. Run scripts from a trusted, administrator-controlled copy.

## Windows

Run from an elevated Windows PowerShell 5.1 session. The role scripts load shared files from `windows\lib`; copy the entire `windows` directory and preserve its layout.

### One-command auto-hardening

Entry point: `windows\auto-harden.ps1` (elevated PowerShell). It detects the host (domain controller, IIS web, IIS FTP, workstation) and applies every applicable category without prompting: account policy, legacy protocols, USB storage, and a host firewall scoped to the local subnet(s), plus the matching role script switches. Each step runs separately, so one failure does not stop the rest.

```powershell
.\windows\auto-harden.ps1              # apply everything applicable
.\windows\auto-harden.ps1 -PlanOnly    # preview only
.\windows\auto-harden.ps1 -SkipFirewall -SkipUsb
```

Not automatic: password rotation, scheduled-task disabling, and `-RequireFtpTls` (needs a certificate). Take a snapshot first; a reboot may be required.

### General first-hour audit and hardening

Entry point: `windows\first-hour.ps1`

Audit only:

```powershell
.\windows\first-hour.ps1
```

Plan selected changes without applying:

```powershell
.\windows\first-hour.ps1 -PlanOnly -SetAccountPolicy -DisableLegacyProtocols -DisableUsbStorage
```

Example apply (replace every example value with the actual environment values first). The selected categories apply even without `-Apply`; it remains accepted for backward compatibility:

```powershell
.\windows\first-hour.ps1 -Apply -SetAccountPolicy -EnforceHostFirewall -ManagementRange '10.20.30.0/24' -DisableUsbStorage
```

Options:

- Supplying any change-category switch applies the selected categories by default. With no category switches, the script remains audit-only.
- `-PlanOnly`: report the selected changes without applying them. Cannot be combined with `-Apply`.
- `-Apply`: explicit apply mode retained for backward compatibility. High-impact operations use PowerShell `ShouldProcess` confirmation; `-WhatIf` can be used to preview ShouldProcess actions.
- `-SetAccountPolicy`: configure local policy on standalone hosts or the AD default domain policy on a domain controller/domain-joined host. Domain mode requires RSAT ActiveDirectory tools. Review domain-wide impact first.
- `-EnforceHostFirewall -ManagementRange CIDR`: set Windows Firewall inbound defaults to Block and allow discovered listeners; RDP/WinRM access is scoped to supplied management ranges. Provide the actual admin range or remote management may be lost.
- `-DisableLegacyProtocols`: disable SMBv1, LLMNR, and NetBIOS over TCP/IP. Some changes may need a reboot.
- `-DisableUsbStorage`: disable the USB mass-storage driver; it does not block every USB device class.
- `-KillPersistence -DisableTask '\TaskPath\TaskName'`: disable only exact named scheduled tasks. Repeat `-DisableTask` for multiple tasks; built-in Microsoft tasks are refused.
- `-RotatePasswords -IncludeAccount NAME -ExcludeAccount NAME -ExcludeAccount NAME`: rotate only explicitly selected local accounts. Use at least two distinct exclusions for scoring/service/break-glass accounts. Each selected account is rechecked for service/task use and requires typed confirmation.
- `-RotateBuiltInAdministrator`: also permits rotating the built-in Administrator, only when explicitly included; it is processed last.
- `-AllowPasswordRerotation`: manually override the one-shot rotation ledger; requires a second typed confirmation.
- `-InstallSysmon -SysinternalsPath PATH -SysmonConfig FILE`: install or update Sysmon using a valid XML config. The script checks that the binary has a valid Microsoft signature and verifies the service after apply. Sysmon is not installed unless this switch is given.
- `-SysinternalsPath PATH`: optionally run available signed `autorunsc`, `tcpvcon`, `logonsessions`, `psloggedon`, `pipelist`, and `sigcheck` tools during the baseline snapshot. Stage and verify the Sysinternals Suite in advance; missing tools are skipped.
- `-SkipRestorePoint`: skip before/after restore point attempts on supported client Windows. On Windows Server, take a VM snapshot and use this switch if running this general script with apply options.
- `-ReportDirectory PATH`: change the default report location (`%LOCALAPPDATA%\CCDC\Reports`).

Password rotation example for plan-only mode (replace names; do not assume these are safe targets):

```powershell
.\windows\first-hour.ps1 -PlanOnly -RotatePasswords -IncludeAccount 'localadmin' -ExcludeAccount 'scoring' -ExcludeAccount 'breakglass'
```

### Role scripts

Each role script is audit-only without `-Apply` and a category switch. Run from the repository root as shown, or from any location using the script's full path. Server roles require a VM snapshot before apply; restore points do not work on Windows Server.

| Script | Intended host | Available apply categories |
| --- | --- | --- |
| `windows\addns\harden-addns.ps1` | AD/DNS, Windows Server 2019 | `-SecureDnsZones`, `-HardenDcAuth`, `-DisableSpooler`, `-EnableAuditPolicy` |
| `windows\webserver\harden-webserver.ps1` | IIS web server, Windows Server 2019 | `-DisableDirectoryBrowsing`, `-HideServerHeader`, `-HardenTls`, `-EnableAuditPolicy` |
| `windows\ftpserver\harden-ftpserver.ps1` | IIS FTP, Windows Server 2022 | `-DisableAnonymousFtp`, `-RequireFtpTls`, `-EnableFtpLogging`, `-HardenTls`, `-EnableAuditPolicy` |
| `windows\workstation\harden-workstation.ps1` | Windows 11 workstation | `-HardenCredentials`, `-EnablePowerShellLogging`, `-DisableAutorun`, `-EnableDefender`, `-EnableAuditPolicy` |

Audit and plan examples:

```powershell
.\windows\addns\harden-addns.ps1
.\windows\webserver\harden-webserver.ps1 -DisableDirectoryBrowsing
.\windows\ftpserver\harden-ftpserver.ps1 -DisableAnonymousFtp
.\windows\workstation\harden-workstation.ps1 -HardenCredentials -EnableDefender
```

Apply examples (only after reviewing the plan and taking a VM snapshot):

```powershell
.\windows\addns\harden-addns.ps1 -Apply -SecureDnsZones -AllowedZoneTransferServer '10.20.30.10'
.\windows\webserver\harden-webserver.ps1 -Apply -DisableDirectoryBrowsing
.\windows\ftpserver\harden-ftpserver.ps1 -Apply -DisableAnonymousFtp
.\windows\workstation\harden-workstation.ps1 -Apply -EnablePowerShellLogging
```

Role-specific cautions:

- **AD/DNS:** apply refuses on a non-domain-controller. `-SecureDnsZones` may change dynamic update and zone transfer behavior. `-HardenDcAuth` changes LDAP signing, secure channel enforcement, anonymous restrictions, and NTLM compatibility; test domain logons, LDAP clients, and scoring immediately.
- **Web:** IIS/WebAdministration is required for IIS settings. `-ExtraWebRoot` can add a non-IIS web root for content and ACL inspection. `-HardenTls` disables legacy TLS/SSL protocols and needs a reboot; ensure the scoring clients support TLS 1.2.
- **FTP:** IIS FTP/WebAdministration is required for IIS FTP settings. `-ExtraFtpRoot` adds another FTP root for content and ACL inspection. `-RequireFtpTls` requires a bound certificate and FTPS-capable scoring clients; it can break plain FTP logins.
- **Workstation:** restore points are attempted before and after apply unless `-SkipRestorePoint` is given. Credential protection, PowerShell logging, AutoRun, Defender, and audit policy are independent switches.
- All role scripts accept `-ReportDirectory PATH`. They write role logs and a before baseline; apply runs also write an after baseline. They use the same `ShouldProcess`/confirmation model as the general script.

### Windows shared library

Files in `windows\lib` define shared functions used by the entry points. Do not run library files directly. Keep them with their scripts when copying or staging the toolkit.

## Linux

### Linux first-hour audit and hardening

Entry point: `linux/first-hour.sh`. Requires Bash. Run from the repository root or invoke by absolute path.

Audit only:

```bash
bash scripts/linux/first-hour.sh
```

Plan-only examples:

```bash
bash scripts/linux/first-hour.sh --set-account-policy
bash scripts/linux/first-hour.sh --apply-host-firewall --management-cidr 10.20.30.0/24
```

Useful options:

- `--apply`: execute requested changes. Must run as root. Destructive/lockout-sensitive actions require interactive typed confirmation.
- `--set-account-policy`: plans or applies Debian/Ubuntu PAM password quality, history, faillock, and login.defs settings. Apply requires `pam_pwquality`, `pam_faillock`, a recognized Debian PAM layout, root, and an interactive terminal; it backs up files and verifies changes. Fedora/RHEL/Oracle Linux PAM changes are intentionally refused by this path.
- `--apply-host-firewall --management-cidr CIDR`: audit or apply a host nftables firewall. Repeat `--management-cidr` for multiple ranges. Requires `ss`, `nft`, Python 3, and for apply: root, systemd, `systemd-run`, an interactive terminal, and a successful nft syntax check. A rollback timer is armed before applying.
- `--disable-smbv1`: if Samba is installed, requires `crudini` and `testparm`, and asks for typed confirmation before changing Samba settings.
- `--kill-persistence --remove-unit UNIT --remove-cron-file /etc/cron.d/FILE`: targets only explicitly named systemd units and regular non-symlink files under `/etc/cron.d`. Repeat target options as needed. Apply disables/masks units or removes the named cron files after confirmation.
- `--rotate-passwords --include-account NAME --exclude-account NAME --exclude-account NAME`: rotate selected eligible local interactive accounts. At least one include and two distinct exclusions are required. Apply requires root, an interactive terminal, `openssl`, and `chpasswd`; it asks for typed confirmation and writes a protected credential file.
- `--allow-rerotate`: explicit override of the one-shot password rotation ledger; use only after manual review and confirmation.
- `--report-dir PATH`: change report/backup directory. Default is `$CCDC_REPORT_DIR` if set, otherwise `./ccdc-reports`.
- `--help`: print the script's usage summary.

Apply examples (use only after validating the plan and values):

```bash
sudo bash scripts/linux/first-hour.sh --apply --set-account-policy
sudo bash scripts/linux/first-hour.sh --apply --apply-host-firewall --management-cidr 10.20.30.0/24
```

The host-firewall mode discovers listener ports and creates rules to allow them; it scopes SSH port 22 to the management CIDRs. Do not assume the discovered listeners are safe or that the CIDR is correct. Confirm scoring and management connectivity before keeping the firewall rules.

### Standalone Linux firewall script

Entry point: `linux/apply-firewall.sh`. It uses `config/firewall.example.json` by default. Replace every `REPLACE_` placeholder and validate scoring/admin ranges and service ports before applying.

```bash
sudo bash scripts/linux/apply-firewall.sh --help
sudo bash scripts/linux/apply-firewall.sh --config config/firewall.example.json
```

The second command validates the config, generates nftables rules under `/run`, and checks syntax; it does not apply rules. Apply only after editing and reviewing the config:

```bash
sudo bash scripts/linux/apply-firewall.sh --apply --config config/firewall.example.json
```

Apply requires root, `nft`, Python 3, a running systemd manager, and an interactive terminal. The script arms the configured rollback timer before applying. It defaults to drop for inbound and outbound traffic, so incomplete allowlists can break services or access. Keep the rollback armed until scoring and administration are verified. To keep the rules after verification, the script prints the exact systemd timer/service command; to roll back immediately, it prints the nft delete command.

### PAM helper

`linux/pam_policy.py` is called by `first-hour.sh`; normally do not invoke it directly. It can be used for fixture-based testing with `--root` pointed at a disposable tree and a fresh `--backup-dir`. It edits only the listed PAM/login.defs files, rejects unrecognized PAM layouts and symlinked files, creates backups, verifies edits, and attempts rollback on failure.

## Splunk configuration generator

`splunk/generate-configs.py` reads `config/splunk.json` and writes deployment artifacts into `generated/splunk/`. It does not install or deploy them.

1. Set `indexer_host`, `indexer_port`, `time_window`, and exactly the required index names in `config/splunk.json`.
1. From the repository root, run:

```bash
python scripts/splunk/generate-configs.py
```

1. Review the generated files: `outputs.conf`, `windows-inputs.conf`, `linux-inputs.conf`, `indexes.conf`, and `first-hour-searches.md`.
1. Deploy each file to the appropriate Splunk forwarder/indexer configuration location for your environment, then restart/reload Splunk according to your deployment process.
1. Verify indexes, sourcetypes, event channels, and field extractions using real events before enabling searches or alerts. The egress query requires normalized flow data; the USB query requires forwarded Windows device-event channels.

The generator validates indexer host/port, time window and index names. Generated searches include index, sourcetype, and time constraints before the first pipe.

## Tests and validation

On Windows PowerShell 5.1, run the safe test runner from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\windows\Test-CCDCScripts.ps1
```

It parses scripts and runs helper/plan-only/fail-closed checks. It does not validate real AD, DNS, IIS, FTP, or apply-mode behavior. Use disposable target-role VMs for integration testing. Never run apply tests against scored systems as your first test.

For Linux, first run `bash -n scripts/linux/first-hour.sh scripts/linux/apply-firewall.sh`, then use an isolated VM matching the target distribution for audit/plan tests. PAM policy is distribution-specific, and nftables apply should only be exercised with console access and rollback verified.

After changes, inspect the report directory specified for the run. Reports may contain sensitive account, host, service, task, or configuration information; restrict access and handle them as sensitive operational data.

## Extra hardening switches (first-hour.ps1)

These apply by default when selected. Add `-PlanOnly` to preview. Each change is logged as `CHANGE` and verified after writing.

| Switch | What it does | What can break |
|---|---|---|
| `-RequireSmbSigning` | Runs `Set-SmbServerConfiguration` and `Set-SmbClientConfiguration` with `-RequireSecuritySignature $true`, then re-reads both and fails if either is not required. | Old SMB clients, NAS devices, and unsigned third-party SMB tools can no longer connect. |
| `-DisableSpooler` | Stops the Print Spooler service and sets it to Disabled, then verifies the startup type. Skipped if already stopped and disabled. Removes the PrintNightmare attack surface. | Printing stops until you run `Set-Service Spooler -StartupType Automatic; Start-Service Spooler`. |
| `-ScopeSystemPorts` | Used with `-EnforceHostFirewall`. Allow rules for SMB/RPC/system ports (135, 137-139, 445, 5040, 5050, 5353, 7680, 1900, 3702) and dynamic RPC ports (49152+) use `-ManagementRange` as the remote address instead of `Any`. Rules for 3389, 5985 and 5986 were already scoped. | Machines outside the management range cannot reach those ports. Set `-ManagementRange` correctly first. |

`auto-harden.ps1` enables `-RequireSmbSigning` and `-DisableSpooler` on every role, and `-ScopeSystemPorts` on non-servers only. Use `-KeepSpooler` to skip the Spooler change.

## Passwords and what to watch for

### Passwords
Nothing rotates passwords automatically, so `auto-harden.ps1` never generates any. To rotate:

```powershell
.\windows\first-hour.ps1 -RotatePasswords -IncludeAccount kali -ExcludeAccount scoring -ExcludeAccount breakglass
```

- At least one `-IncludeAccount` and two `-ExcludeAccount` values are required, and you must type a confirmation.
- New passwords are written to `%LOCALAPPDATA%\CCDC\Reports\rotated-credentials-<stamp>.txt` (for example `C:\Users\kali\AppData\Local\CCDC\Reports`). The file is readable only by the current user and SYSTEM. A `password-rotation-ledger.txt` records what was rotated.
- Record the passwords in your team's secure store, then delete the file.
- Rotating the account you are logged in as is risky: write the new password down before logging out. Keep scoring and break-glass accounts excluded.

### After a hardening run
- **Reboot:** required for LSASS protection (RunAsPPL) to take effect.
- **Auto-logon is turned off:** you must know the local account password to sign in again.
- **Scored services:** confirm each still works after the firewall changes. Port 445 inbound is blocked unless allowed explicitly, and system/RPC ports are limited to the management range on workstations.
- **Legacy auth:** LmCompatibilityLevel 5 means NTLMv1 clients fail; SMB signing means old SMB clients fail.
- **Printing:** stops if the Spooler was disabled.
- **Accounts:** `SecAdmin_Local` (the disabled built-in administrator) remains in the local Administrators group; review it.
- **Logs and rollback:** reports, baselines and the firewall `.wfw` backup are in `%LOCALAPPDATA%\CCDC\Reports`, and a restore point is created before changes on workstations.
