# WinHardening: Windows 10/11 workstation hardening

A PowerShell script that hardens a Windows workstation in four parts: it cleans up the firewall, removes bloatware, disables unneeded services and applies a set of low-risk security settings.

**This script changes the system.** Run it with `-WhatIf` first to see exactly what it would do. For read-only diagnosis (Windows Update failures, compromise indicators, Edge/Copilot abuse), use the separate **WinDiag** toolkit.

## Files

| File | Purpose |
|---|---|
| `Set-WindowsHardening.ps1` | The hardening script. Backs up first; `-WhatIf` previews; `-RestoreFrom <backup>` undoes. |

Requires Windows 10/11 with Windows PowerShell 5.1 (built in) or PowerShell 7, run as Administrator.

## Running it

```powershell
# Dry run: shows every rule, app, service and setting that would change
powershell -ExecutionPolicy Bypass -File .\Set-WindowsHardening.ps1 -WhatIf

# Default hardening with backups; asks once before starting
.\Set-WindowsHardening.ps1

# Keep RDP reachable, leave apps alone, switch outbound to default-deny
.\Set-WindowsHardening.ps1 -KeepInboundRules 'Remote Desktop*' -SkipBloatware -BlockOutboundByDefault

# Undo (firewall, services and registry)
.\Set-WindowsHardening.ps1 -RestoreFrom 'C:\ProgramData\WinHardening\Backup-20261112-101500'
```

If Windows blocks the script because it was downloaded, run `Unblock-File .\Set-WindowsHardening.ps1` once.

The script refuses to touch the firewall from inside a Remote Desktop or SSH session, because removing inbound rules would cut you off. Run it locally, keep your access rule with `-KeepInboundRules`, use `-SkipFirewall`, or pass `-Force`.

## What it changes

**Firewall**
- Turns the firewall on for all profiles, sets default inbound to Block and logs dropped packets.
- Deletes inbound allow rules, except Core Networking and anything in `-KeepInboundRules`.
- Deletes outbound allow rules whose remote ports fall outside `-AllowedOutboundPorts`.
- With `-BlockOutboundByDefault`: sets outbound to default-deny and adds allow rules (group `WinHardening`) for the standard ports only.

**Bloatware**
- Removes consumer and promotional Store apps for all users, and deprovisions them so new profiles don't get them.
- Calculator, Photos, Notepad, Terminal, Paint, Snipping Tool, Store and App Installer are deliberately kept.

**Services**
- Stops and disables services most workstations never need, especially network listeners: Remote Registry, WinRM, SSDP/UPnP, WebClient, peer networking, telemetry, Xbox and others.
- `-DisableRemoteDesktop` and `-DisablePrintSpooler` add RDP and the Print Spooler.

**System settings**
- Turns off SMBv1, requires SMB signing and removes PowerShell 2.0.
- Turns off LLMNR, NetBIOS over TCP/IP and AutoRun.
- Turns off WDigest and turns on LSA protection.
- Restricts anonymous enumeration and allows NTLMv2 only.
- Enforces UAC, turns off Remote Assistance and disables Guest.
- Turns on Defender PUA protection.

Edit the `$BloatwareApps` and `$ServicesToDisable` lists at the top of the script to suit the machine.

### Options

| Option | Effect |
|---|---|
| `-AllowedOutboundPorts <int[]>` | Ports treated as standard. Default: 53, 67, 68, 80, 123, 443, 546, 547, 853. Domain-joined machines also need e.g. 88, 135, 389, 445, 464, 636, 3268. |
| `-KeepInboundRules <wildcards>` | Inbound rules (by DisplayName) to keep. |
| `-KeepFirewallGroups <groups>` | Rule groups never touched (default Core Networking). |
| `-DisableRulesInsteadOfRemoving` | Disable firewall rules rather than delete them. |
| `-BlockOutboundByDefault` | Default-deny outbound with allow rules for the standard ports. |
| `-BlockAllInbound` | "Shields up": ignore every inbound allow rule, including Core Networking. |
| `-DisableRemoteDesktop` | Also turn off RDP and its services. |
| `-DisablePrintSpooler` | Also disable the Print Spooler. This breaks printing. |
| `-KeepApps`, `-KeepServices` | Exclusions for the bloatware and services sections. |
| `-SkipFirewall`, `-SkipBloatware`, `-SkipServices`, `-SkipSystemSettings`, `-SkipRestorePoint` | Skip a section. |
| `-BackupPath <path>` | Backup location (default `C:\ProgramData\WinHardening\Backup-<timestamp>`). |
| `-RestoreFrom <path>` | Roll back from a backup folder. |
| `-WhatIf` | Preview only; nothing is changed and no backup is written. |
| `-Force` | Skip the confirmation prompt and the remote-session check. |

## Backup and restore

Before any change, the script makes a system restore point (unless `-SkipRestorePoint`). It also writes a backup folder:

| File | Contents |
|---|---|
| `firewall.wfw` | Full firewall policy export (`netsh advfirewall export`). |
| `services.csv` | Original startup type and state of every service touched. |
| `registry.json` | Original value of every registry value set. |
| `removed-apps.csv` | Every app package removed. |
| `transcript.txt` | Full console log. |

`-RestoreFrom` rolls back the firewall, services and registry. Removed apps cannot be restored automatically; reinstall them from the Store or winget.

## Limitations

- Group Policy and Intune can re-apply firewall rules and settings this script removes. On a managed (domain or Intune) machine, harden through policy instead.
- `-BlockOutboundByDefault` breaks any app that uses a non-standard port until you add a rule for it.
- Some changes (LSA protection, optional features) need a reboot; the summary says when.
