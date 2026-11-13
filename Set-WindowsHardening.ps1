#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Hardens a Windows 10/11 workstation: firewall cleanup, bloatware removal,
    unnecessary services disabled, and a set of low-risk security settings.

.DESCRIPTION
    THIS SCRIPT CHANGES THE SYSTEM. Run it with -WhatIf first to see exactly
    what it would do. (For read-only diagnosis, use the separate WinDiag toolkit.)

    Before changing anything it writes a backup folder containing:
      firewall.wfw        full firewall policy export (netsh advfirewall export)
      services.csv        original startup type and state of every service it touches
      registry.json       original value of every registry value it sets
      removed-apps.csv    every app package it removes
      transcript.txt      full console log
    Use -RestoreFrom <backup folder> to roll back firewall, services and registry.
    Removed apps cannot be restored automatically; reinstall them from the Store or winget.

    Sections (each can be skipped):
      Firewall  - turns the firewall on for all profiles, default inbound = Block,
                  logs dropped packets, deletes inbound ALLOW rules (except Core
                  Networking and anything you list in -KeepInboundRules), and deletes
                  outbound ALLOW rules whose remote ports fall outside -AllowedOutboundPorts.
                  Add -BlockOutboundByDefault to switch outbound to default-deny with
                  allow rules for the standard ports only.
      Bloatware - removes consumer/promotional Store apps for all users and
                  deprovisions them so new user profiles don't get them.
      Services  - stops and disables services most workstations never need,
                  especially ones that listen on the network.
      System    - SMBv1 off, LLMNR/NetBIOS off, AutoRun off, WDigest off, LSA
                  protection on, anonymous enumeration restricted, Remote Assistance
                  off, UAC enforced, Guest disabled, Defender PUA protection on.

    Group Policy / Intune can re-apply firewall rules and settings this script
    removes. On a managed (domain/Intune) machine, harden through policy instead.

.PARAMETER AllowedOutboundPorts
    Remote ports considered "standard". Default: 53 DNS, 67/68 DHCP, 80 HTTP,
    123 NTP, 443 HTTPS/QUIC, 546/547 DHCPv6, 853 DNS-over-TLS.
    Domain-joined machines also need e.g. 88, 135, 389, 445, 464, 636, 3268.

.PARAMETER KeepInboundRules
    DisplayName wildcards of inbound rules to keep, e.g. 'Remote Desktop*','File and Printer Sharing*'.

.PARAMETER KeepFirewallGroups
    Firewall rule groups (DisplayGroup) that are never touched. Default: Core Networking
    (DHCP, IPv6 neighbour discovery, ICMP). Removing those breaks networking.

.PARAMETER DisableRulesInsteadOfRemoving
    Disable firewall rules rather than delete them. Easier to undo by hand.

.PARAMETER BlockOutboundByDefault
    Sets default outbound action to Block on every profile and adds allow rules for
    -AllowedOutboundPorts. Strong, but apps using other ports will stop working.

.PARAMETER BlockAllInbound
    "Shields up": ignores every inbound allow rule, including Core Networking.

.PARAMETER DisableRemoteDesktop
    Also turns off RDP (fDenyTSConnections) and disables its services.

.PARAMETER DisablePrintSpooler
    Also disables the Print Spooler (PrintNightmare class bugs). Breaks printing.

.PARAMETER KeepApps
    Package-name wildcards to exclude from bloatware removal.

.PARAMETER KeepServices
    Service names to exclude from the services section.

.PARAMETER Force
    Skip the confirmation prompt and the remote-session safety check.

.EXAMPLE
    .\Set-WindowsHardening.ps1 -WhatIf
    Dry run. Shows every rule, app, service and setting that would change.

.EXAMPLE
    .\Set-WindowsHardening.ps1
    Default hardening with backups, asks once before starting.

.EXAMPLE
    .\Set-WindowsHardening.ps1 -KeepInboundRules 'Remote Desktop*' -SkipBloatware -BlockOutboundByDefault

.EXAMPLE
    .\Set-WindowsHardening.ps1 -RestoreFrom 'C:\ProgramData\WinHardening\Backup-20261112-101500'
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Harden')]
param(
    [Parameter(ParameterSetName = 'Harden')]
    [int[]]$AllowedOutboundPorts = @(53, 67, 68, 80, 123, 443, 546, 547, 853),

    [Parameter(ParameterSetName = 'Harden')]
    [string[]]$KeepInboundRules = @(),

    [Parameter(ParameterSetName = 'Harden')]
    [string[]]$KeepFirewallGroups = @('Core Networking'),

    [Parameter(ParameterSetName = 'Harden')] [switch]$DisableRulesInsteadOfRemoving,
    [Parameter(ParameterSetName = 'Harden')] [switch]$BlockOutboundByDefault,
    [Parameter(ParameterSetName = 'Harden')] [switch]$BlockAllInbound,
    [Parameter(ParameterSetName = 'Harden')] [switch]$DisableRemoteDesktop,
    [Parameter(ParameterSetName = 'Harden')] [switch]$DisablePrintSpooler,

    [Parameter(ParameterSetName = 'Harden')] [string[]]$KeepApps = @(),
    [Parameter(ParameterSetName = 'Harden')] [string[]]$KeepServices = @(),

    [Parameter(ParameterSetName = 'Harden')] [switch]$SkipFirewall,
    [Parameter(ParameterSetName = 'Harden')] [switch]$SkipBloatware,
    [Parameter(ParameterSetName = 'Harden')] [switch]$SkipServices,
    [Parameter(ParameterSetName = 'Harden')] [switch]$SkipSystemSettings,
    [Parameter(ParameterSetName = 'Harden')] [switch]$SkipRestorePoint,

    [Parameter(ParameterSetName = 'Harden')]
    [string]$BackupPath = (Join-Path $env:ProgramData ('WinHardening\Backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [Parameter(ParameterSetName = 'Restore', Mandatory = $true)]
    [string]$RestoreFrom,

    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ===========================================================================
# Configuration lists - edit these to suit the machine
# ===========================================================================

# Store apps to remove (wildcards on package Name). Calculator, Photos, Notepad,
# Terminal, Paint, Snipping Tool, Store and App Installer are deliberately absent.
$BloatwareApps = @(
    # Microsoft consumer apps
    'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.BingFinance', 'Microsoft.BingSports',
    'Microsoft.BingSearch', 'Microsoft.GetHelp', 'Microsoft.Getstarted', 'Microsoft.MicrosoftOfficeHub',
    'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.People', 'Microsoft.SkypeApp',
    'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps', 'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo',
    'Microsoft.YourPhone', 'Microsoft.MixedReality.Portal', 'Microsoft.3DBuilder', 'Microsoft.Microsoft3DViewer',
    'Microsoft.Print3D', 'Microsoft.MSPaint', 'Microsoft.OneConnect', 'Microsoft.Messaging',
    'Microsoft.WindowsCommunicationsApps', 'Microsoft.Todos', 'Microsoft.PowerAutomateDesktop',
    'Microsoft.549981C3F5F10', 'Microsoft.Copilot', 'Microsoft.Windows.DevHome', 'Microsoft.OutlookForWindows',
    'MicrosoftTeams', 'MSTeams', 'Clipchamp.Clipchamp', 'Microsoft.Wallet',
    # Quick Assist: a remote-control tool heavily abused in tech-support scams
    'MicrosoftCorporationII.QuickAssist',
    # Xbox / gaming (keep these if you game on this PC)
    'Microsoft.GamingApp', 'Microsoft.XboxApp', 'Microsoft.Xbox.TCUI', 'Microsoft.XboxGamingOverlay',
    'Microsoft.XboxGameOverlay', 'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.XboxIdentityProvider',
    # Sponsored / pre-installed third-party apps
    'king.com.*', '*CandyCrush*', '*BubbleWitch*', 'AdobeSystemsIncorporated.AdobePhotoshopExpress',
    '*Duolingo*', '*EclipseManager*', '*ActiproSoftware*', '*Flipboard*', '*Shazam*'
)

# Services to stop and disable. Missing services are skipped silently.
$ServicesToDisable = [ordered]@{
    'RemoteRegistry'    = 'Remote Registry - lets remote users read/edit the registry'
    'RemoteAccess'      = 'Routing and Remote Access'
    'SharedAccess'      = 'Internet Connection Sharing'
    'icssvc'            = 'Windows Mobile Hotspot'
    'WinRM'             = 'Windows Remote Management (PowerShell remoting listener)'
    'sshd'              = 'OpenSSH Server (if installed)'
    'TlntSvr'           = 'Telnet server (if installed)'
    'ftpsvc'            = 'IIS FTP server (if installed)'
    'SNMP'              = 'SNMP agent (if installed)'
    'SNMPTrap'          = 'SNMP Trap'
    'simptcp'           = 'Simple TCP/IP Services (if installed)'
    'SSDPSrv'           = 'SSDP Discovery (UPnP)'
    'upnphost'          = 'UPnP Device Host'
    'FDResPub'          = 'Function Discovery Resource Publication (advertises this PC on the LAN)'
    'lltdsvc'           = 'Link-Layer Topology Discovery Mapper'
    'WebClient'         = 'WebDAV client (common NTLM-relay vector)'
    'WMPNetworkSvc'     = 'Windows Media Player network sharing'
    'NetTcpPortSharing' = 'Net.Tcp Port Sharing'
    'PeerDistSvc'       = 'BranchCache'
    'p2psvc'            = 'Peer Networking Grouping'
    'p2pimsvc'          = 'Peer Networking Identity Manager'
    'PNRPsvc'           = 'Peer Name Resolution Protocol'
    'PNRPAutoReg'       = 'PNRP Machine Name Publication'
    'AJRouter'          = 'AllJoyn Router (IoT)'
    'TrkWks'            = 'Distributed Link Tracking Client'
    'Fax'               = 'Fax'
    'RetailDemo'        = 'Retail Demo'
    'MapsBroker'        = 'Downloaded Maps Manager'
    'DiagTrack'         = 'Connected User Experiences and Telemetry'
    'dmwappushservice'  = 'WAP Push Message Routing (telemetry)'
    'XblAuthManager'    = 'Xbox Live Auth Manager'
    'XblGameSave'       = 'Xbox Live Game Save'
    'XboxNetApiSvc'     = 'Xbox Live Networking'
    'XboxGipSvc'        = 'Xbox Accessory Management'
}
if ($DisableRemoteDesktop) {
    $ServicesToDisable['TermService']  = 'Remote Desktop Services'
    $ServicesToDisable['SessionEnv']   = 'Remote Desktop Configuration'
    $ServicesToDisable['UmRdpService'] = 'Remote Desktop UserMode Port Redirector'
}
if ($DisablePrintSpooler) {
    $ServicesToDisable['Spooler'] = 'Print Spooler (breaks printing)'
}

# Firewall group used for rules this script creates, so reruns replace them cleanly.
$HardeningGroup = 'WinHardening'
# Language-independent id of the built-in "Core Networking" group.
$CoreNetworkingGroupId = '@FirewallAPI.dll,-25000'

# ===========================================================================
# Helpers
# ===========================================================================
$script:Stats      = [ordered]@{}
$script:RegChanges = New-Object System.Collections.Generic.List[object]
$script:SvcChanges = New-Object System.Collections.Generic.List[object]
$script:AppChanges = New-Object System.Collections.Generic.List[object]
$script:RebootNeeded = $false
$script:DryRun = [bool]$WhatIfPreference

function Write-Log {
    param([string]$Message, [ValidateSet('Info', 'Change', 'Skip', 'Warn', 'Error', 'Head')][string]$Level = 'Info')
    $color = @{ Info = 'Gray'; Change = 'Green'; Skip = 'DarkGray'; Warn = 'Yellow'; Error = 'Red'; Head = 'Cyan' }[$Level]
    $prefix = @{ Info = '   '; Change = ' + '; Skip = ' - '; Warn = ' ! '; Error = ' x '; Head = '' }[$Level]
    if ($Level -eq 'Head') { Write-Host ''; Write-Host ('=== {0} ===' -f $Message) -ForegroundColor $color }
    else { Write-Host ($prefix + $Message) -ForegroundColor $color }
}

function Add-Stat([string]$Name, [int]$By = 1) {
    if (-not $script:Stats.Contains($Name)) { $script:Stats[$Name] = 0 }
    $script:Stats[$Name] += $By
}

function Set-HardenedRegValue {
    <# Sets a registry value and records the original so -RestoreFrom can undo it. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] $Value,
        [ValidateSet('DWord', 'String')] [string]$Type = 'DWord',
        [string]$Reason = ''
    )
    $hadValue = $false; $oldValue = $null; $oldType = $null
    if (Test-Path -LiteralPath $Path) {
        $key = Get-Item -LiteralPath $Path
        if ($key.GetValueNames() -contains $Name) {
            $hadValue = $true
            $oldValue = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
            $oldType  = $key.GetValueKind($Name).ToString()
        }
    }
    $label = "$Path\$Name"
    if ($hadValue -and ("$oldValue" -eq "$Value")) { Write-Log "$label already $Value" Skip; return }
    if ($PSCmdlet.ShouldProcess($label, "Set to $Value ($Reason)")) {
        try {
            if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
            New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
            $script:RegChanges.Add([pscustomobject]@{
                    Path = $Path; Name = $Name; HadValue = $hadValue; OldValue = $oldValue; OldType = $oldType; NewValue = $Value
                })
            Write-Log ("{0} = {1}  ({2})" -f $label, $Value, $Reason) Change
            Add-Stat 'Registry values set'
        } catch { Write-Log "Failed to set ${label}: $($_.Exception.Message)" Error; Add-Stat 'Errors' }
    }
}

function Test-StandardPortList {
    <# True when every remote-port entry is a number/range fully inside $Allowed.
       Keywords such as RPC, RPCEPMap or IPHTTPSOut count as non-standard. #>
    param([string[]]$Ports, [int[]]$Allowed)
    foreach ($p in $Ports) {
        if ($p -match '^\d+$') {
            if ([int]$p -notin $Allowed) { return $false }
        } elseif ($p -match '^(\d+)-(\d+)$') {
            $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
            if (($hi - $lo + 1) -gt $Allowed.Count) { return $false }
            foreach ($i in $lo..$hi) { if ($i -notin $Allowed) { return $false } }
        } else { return $false }
    }
    return $true
}

function Test-KeptRule {
    param($Rule)
    if ($Rule.Group -eq $CoreNetworkingGroupId -and ($KeepFirewallGroups -contains 'Core Networking')) { return $true }
    if ($Rule.DisplayGroup -and ($KeepFirewallGroups -contains $Rule.DisplayGroup)) { return $true }
    if ($Rule.Group -eq $HardeningGroup) { return $true }
    return $false
}

function Remove-HardenedFirewallRule {
    param($Rule, [string]$Why)
    $desc = '[{0}] {1}' -f $Rule.Direction, $Rule.DisplayName
    $verb = if ($DisableRulesInsteadOfRemoving) { 'Disable' } else { 'Remove' }
    if ($PSCmdlet.ShouldProcess($desc, "$verb firewall rule ($Why)")) {
        try {
            if ($DisableRulesInsteadOfRemoving) { $Rule | Disable-NetFirewallRule -ErrorAction Stop }
            else { $Rule | Remove-NetFirewallRule -ErrorAction Stop }
            Write-Log "$verb $desc  ($Why)" Change
            Add-Stat ("{0} rules {1}" -f $Rule.Direction, $(if ($DisableRulesInsteadOfRemoving) { 'disabled' } else { 'removed' }))
        } catch { Write-Log "Could not $($verb.ToLower()) ${desc}: $($_.Exception.Message)" Error; Add-Stat 'Errors' }
    }
}

# ===========================================================================
# Sections
# ===========================================================================
function Invoke-FirewallHardening {
    Write-Log 'Firewall' Head

    # 1. Profiles: on, default-deny inbound, no "allow this app?" prompts, log drops.
    $outbound = if ($BlockOutboundByDefault) { 'Block' } else { 'Allow' }
    if ($PSCmdlet.ShouldProcess('Domain, Private, Public profiles', "Enable; inbound=Block; outbound=$outbound; log dropped")) {
        $profileArgs = @{
            Profile               = 'Domain', 'Private', 'Public'
            Enabled               = 'True'
            DefaultInboundAction  = 'Block'
            DefaultOutboundAction = $outbound
            NotifyOnListen        = 'False'
            LogBlocked            = 'True'
            LogMaxSizeKilobytes   = 16384
            LogFileName           = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
        }
        if ($BlockAllInbound) { $profileArgs['AllowInboundRules'] = 'False' }
        Set-NetFirewallProfile @profileArgs
        Write-Log "All profiles enabled, inbound=Block, outbound=$outbound, dropped packets logged" Change
        if ($BlockAllInbound) { Write-Log 'Shields up: all inbound allow rules are ignored' Change }
    }

    # Rules pushed by Group Policy / MDM live outside the local store and can't be deleted here.
    try {
        $gpo = @(Get-NetFirewallRule -PolicyStore RSOP -ErrorAction SilentlyContinue)
        if ($gpo.Count -gt 0) { Write-Log "$($gpo.Count) rules come from Group Policy and are not touched; change them in the GPO" Warn }
    } catch {}

    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore)
    $portMap = @{}
    foreach ($pf in @(Get-NetFirewallPortFilter -PolicyStore PersistentStore)) { $portMap[$pf.InstanceID] = $pf }

    # 2. Inbound: remove every ALLOW rule except kept groups / names.
    $inbound = $rules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }
    foreach ($r in $inbound) {
        if (Test-KeptRule $r) { Add-Stat 'Inbound rules kept'; continue }
        $keepByName = $false
        foreach ($pattern in $KeepInboundRules) { if ($r.DisplayName -like $pattern) { $keepByName = $true; break } }
        if ($keepByName) { Write-Log "Keep [Inbound] $($r.DisplayName) (matches -KeepInboundRules)" Skip; Add-Stat 'Inbound rules kept'; continue }
        if ($DisableRulesInsteadOfRemoving -and $r.Enabled -eq 'False') { continue }
        Remove-HardenedFirewallRule $r 'inbound allow rule'
    }

    # 3. Outbound: remove ALLOW rules that target non-standard remote ports.
    #    Rules with RemotePort=Any (program-based or ICMP) are left alone.
    $outRules = $rules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Action -eq 'Allow' }
    foreach ($r in $outRules) {
        if (Test-KeptRule $r) { continue }
        $pf = $portMap[$r.Name]
        if (-not $pf) { continue }
        $remote = @($pf.RemotePort | ForEach-Object { "$_" })
        if ($remote.Count -eq 0 -or $remote -contains 'Any') { continue }
        if (Test-StandardPortList -Ports $remote -Allowed $AllowedOutboundPorts) { continue }
        if ($DisableRulesInsteadOfRemoving -and $r.Enabled -eq 'False') { continue }
        Remove-HardenedFirewallRule $r ("remote port {0}" -f ($remote -join ','))
    }

    # 4. Optional default-deny outbound with allow rules for the standard ports only.
    if ($BlockOutboundByDefault) {
        if ($PSCmdlet.ShouldProcess("Group '$HardeningGroup'", 'Recreate outbound allow rules for standard ports')) {
            Get-NetFirewallRule -Group $HardeningGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            $ports = @($AllowedOutboundPorts | Sort-Object -Unique | ForEach-Object { "$_" })
            foreach ($proto in 'TCP', 'UDP') {
                New-NetFirewallRule -DisplayName "WinHardening - Allow outbound $proto (standard ports)" `
                    -Group $HardeningGroup -Direction Outbound -Action Allow -Protocol $proto `
                    -RemotePort $ports -Profile Any -Enabled True | Out-Null
            }
            Write-Log ("Outbound default=Block; allowed TCP/UDP remote ports: {0}" -f ($ports -join ',')) Change
            Write-Log 'Apps that need other ports (VPNs, games, mail on 587/993, SSH 22, RDP 3389) will now fail until allowed' Warn
        }
    } elseif (-not $script:DryRun) {
        Write-Log 'Outbound default is still Allow (Windows default). Removing allow rules only matters once outbound is Block; use -BlockOutboundByDefault for that.' Info
    }
}

function Invoke-BloatwareRemoval {
    Write-Log 'Bloatware' Head
    if ($PSVersionTable.PSEdition -eq 'Core') {
        # The Appx module only works reliably through the Windows PowerShell compatibility layer.
        Import-Module Appx -UseWindowsPowerShell -WarningAction SilentlyContinue
    }
    $installed   = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
    $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue)

    foreach ($pattern in $BloatwareApps) {
        $skip = $false
        foreach ($k in $KeepApps) { if ($pattern -like $k) { $skip = $true } }
        if ($skip) { Write-Log "Keep $pattern (matches -KeepApps)" Skip; continue }

        foreach ($pkg in @($installed | Where-Object { $_.Name -like $pattern })) {
            $kept = $false
            foreach ($k in $KeepApps) { if ($pkg.Name -like $k) { $kept = $true } }
            if ($kept) { continue }
            if ($pkg.PSObject.Properties['NonRemovable'] -and $pkg.NonRemovable) { Write-Log "$($pkg.Name) is a system app, skipped" Skip; continue }
            if ($PSCmdlet.ShouldProcess($pkg.PackageFullName, 'Remove app for all users')) {
                try {
                    Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                    $script:AppChanges.Add([pscustomobject]@{ Kind = 'Installed'; Name = $pkg.Name; Package = $pkg.PackageFullName })
                    Write-Log "Removed $($pkg.Name)" Change
                    Add-Stat 'Apps removed'
                } catch { Write-Log "Could not remove $($pkg.Name): $($_.Exception.Message)" Warn; Add-Stat 'Errors' }
            }
        }
        foreach ($prov in @($provisioned | Where-Object { $_.DisplayName -like $pattern })) {
            if ($PSCmdlet.ShouldProcess($prov.PackageName, 'Deprovision (new users will not get it)')) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
                    $script:AppChanges.Add([pscustomobject]@{ Kind = 'Provisioned'; Name = $prov.DisplayName; Package = $prov.PackageName })
                    Write-Log "Deprovisioned $($prov.DisplayName)" Change
                    Add-Stat 'Apps deprovisioned'
                } catch { Write-Log "Could not deprovision $($prov.DisplayName): $($_.Exception.Message)" Warn; Add-Stat 'Errors' }
            }
        }
    }

    # Stop Windows silently re-installing promoted apps.
    Set-HardenedRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 1 -Reason 'no consumer app auto-install (honoured on Enterprise/Education)'
    $cdm = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    foreach ($v in 'SilentInstalledAppsEnabled', 'PreInstalledAppsEnabled', 'OemPreInstalledAppsEnabled', 'ContentDeliveryAllowed') {
        Set-HardenedRegValue $cdm $v 0 -Reason 'no promoted app installs for the elevated user'
    }
}

function Invoke-ServiceHardening {
    Write-Log 'Services' Head
    foreach ($name in $ServicesToDisable.Keys) {
        $reason = $ServicesToDisable[$name]
        if ($KeepServices -contains $name) { Write-Log "Keep $name (matches -KeepServices)" Skip; continue }
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        $delayed = (Get-ItemProperty -LiteralPath $regPath -Name DelayedAutostart -ErrorAction SilentlyContinue)
        $orig = [pscustomobject]@{
            Name = $name; StartType = $svc.StartType.ToString(); Status = $svc.Status.ToString()
            DelayedAutoStart = [bool]($delayed -and $delayed.DelayedAutostart -eq 1)
        }
        if ($svc.StartType -eq 'Disabled' -and $svc.Status -eq 'Stopped') { Write-Log "$name already disabled" Skip; continue }

        if ($PSCmdlet.ShouldProcess("$name ($reason)", 'Stop and disable service')) {
            $ok = $true
            if ($svc.Status -ne 'Stopped') {
                try { Stop-Service -Name $name -Force -ErrorAction Stop }
                catch { Write-Log "Could not stop ${name}: $($_.Exception.Message) (will be off after reboot)" Warn; $script:RebootNeeded = $true }
            }
            try { Set-Service -Name $name -StartupType Disabled -ErrorAction Stop }
            catch {
                # Some services reject Set-Service; the registry Start value still works.
                try { Set-ItemProperty -LiteralPath $regPath -Name Start -Value 4 -ErrorAction Stop; $script:RebootNeeded = $true }
                catch { $ok = $false; Write-Log "Could not disable ${name}: $($_.Exception.Message)" Error; Add-Stat 'Errors' }
            }
            if ($ok) {
                $script:SvcChanges.Add($orig)
                Write-Log "Disabled $name - $reason (was $($orig.StartType)/$($orig.Status))" Change
                Add-Stat 'Services disabled'
            }
        }
    }
}

function Invoke-SystemHardening {
    Write-Log 'System settings' Head

    # SMBv1: wormable legacy protocol (WannaCry, NotPetya).
    try {
        $smb = Get-SmbServerConfiguration
        if ($smb.EnableSMB1Protocol) {
            if ($PSCmdlet.ShouldProcess('SMB server', 'Disable SMBv1')) {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
                Write-Log 'SMBv1 server protocol disabled' Change; Add-Stat 'Settings changed'
            }
        } else { Write-Log 'SMBv1 server protocol already off' Skip }
        if (-not $smb.RequireSecuritySignature) {
            if ($PSCmdlet.ShouldProcess('SMB server', 'Require SMB signing')) {
                Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
                Write-Log 'SMB server signing required' Change; Add-Stat 'Settings changed'
            }
        }
    } catch { Write-Log "SMB configuration: $($_.Exception.Message)" Warn }

    foreach ($feature in 'SMB1Protocol', 'MicrosoftWindowsPowerShellV2Root') {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($f -and $f.State -eq 'Enabled') {
            if ($PSCmdlet.ShouldProcess($feature, 'Disable optional feature')) {
                try {
                    $res = Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop
                    if ($res.RestartNeeded) { $script:RebootNeeded = $true }
                    Write-Log "Optional feature $feature disabled" Change; Add-Stat 'Settings changed'
                } catch { Write-Log "Could not disable ${feature}: $($_.Exception.Message)" Warn }
            }
        }
    }

    # Name-resolution poisoning (Responder-style attacks): LLMNR and NetBIOS over TCP/IP.
    Set-HardenedRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 -Reason 'disable LLMNR'
    $netbt = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    if (Test-Path $netbt) {
        foreach ($iface in Get-ChildItem $netbt) {
            Set-HardenedRegValue $iface.PSPath.Replace('Microsoft.PowerShell.Core\Registry::', 'Registry::') 'NetbiosOptions' 2 -Reason 'disable NetBIOS over TCP/IP'
        }
    }

    # AutoRun / AutoPlay on all drive types.
    $explorerPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Set-HardenedRegValue $explorerPol 'NoDriveTypeAutoRun' 255 -Reason 'AutoRun off for all drives'
    Set-HardenedRegValue $explorerPol 'NoAutorun' 1 -Reason 'AutoRun off'

    # Credential theft: no cleartext WDigest creds, LSASS as protected process.
    Set-HardenedRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 -Reason 'no cleartext creds in LSASS'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-HardenedRegValue $lsa 'RunAsPPL' 1 -Reason 'LSA protection (reboot)'
    Set-HardenedRegValue $lsa 'RestrictAnonymous' 1 -Reason 'no anonymous share enumeration'
    Set-HardenedRegValue $lsa 'RestrictAnonymousSAM' 1 -Reason 'no anonymous account enumeration'
    Set-HardenedRegValue $lsa 'EveryoneIncludesAnonymous' 0 -Reason 'anonymous is not Everyone'
    Set-HardenedRegValue $lsa 'LmCompatibilityLevel' 5 -Reason 'NTLMv2 only, refuse LM/NTLMv1'

    # UAC on, prompts on the secure desktop.
    $sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-HardenedRegValue $sysPol 'EnableLUA' 1 -Reason 'UAC on'
    Set-HardenedRegValue $sysPol 'PromptOnSecureDesktop' 1 -Reason 'UAC on secure desktop'

    # Remote Assistance off; RDP off on request.
    Set-HardenedRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0 -Reason 'Remote Assistance off'
    if ($DisableRemoteDesktop) {
        Set-HardenedRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1 -Reason 'Remote Desktop off'
    }

    # Built-in Guest account (RID 501).
    try {
        $guest = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' }
        if ($guest -and $guest.Enabled) {
            if ($PSCmdlet.ShouldProcess($guest.Name, 'Disable Guest account')) {
                $guest | Disable-LocalUser
                Write-Log "Guest account '$($guest.Name)' disabled" Change; Add-Stat 'Settings changed'
            }
        }
    } catch { Write-Log "Guest account: $($_.Exception.Message)" Warn }

    # Microsoft Defender, only if it is the active antivirus.
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($mp.AMRunningMode -eq 'Normal') {
            $pref = Get-MpPreference
            if ($pref.PUAProtection -ne 1 -and $PSCmdlet.ShouldProcess('Microsoft Defender', 'Enable PUA protection')) {
                Set-MpPreference -PUAProtection Enabled
                Write-Log 'Defender potentially-unwanted-app blocking enabled' Change; Add-Stat 'Settings changed'
            }
            if (-not $mp.RealTimeProtectionEnabled) { Write-Log 'Defender real-time protection is OFF. Turn it on in Windows Security.' Warn }
            if (-not $mp.IsTamperProtected) { Write-Log 'Defender Tamper Protection is off. Turn it on in Windows Security.' Warn }
        } else { Write-Log "Defender is in '$($mp.AMRunningMode)' mode (another AV is primary); skipped" Skip }
    } catch { Write-Log 'Microsoft Defender not available; skipped' Skip }

    $script:RebootNeeded = $true   # RunAsPPL, NetBIOS and LLMNR take effect after reboot
}

# ===========================================================================
# Restore
# ===========================================================================
function Invoke-Restore {
    param([string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { throw "Backup folder not found: $Dir" }
    Write-Log "Restoring from $Dir" Head

    $fw = Join-Path $Dir 'firewall.wfw'
    if ((Test-Path -LiteralPath $fw) -and $PSCmdlet.ShouldProcess('Firewall policy', "Import $fw")) {
        $out = & netsh.exe advfirewall import "$fw" 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Log 'Firewall policy restored' Change } else { Write-Log "netsh import failed: $out" Error }
    }

    $svcFile = Join-Path $Dir 'services.csv'
    if (Test-Path -LiteralPath $svcFile) {
        foreach ($s in Import-Csv -LiteralPath $svcFile) {
            if (-not $PSCmdlet.ShouldProcess($s.Name, "Restore startup type $($s.StartType)")) { continue }
            try {
                $startArg = switch ($s.StartType) { 'Automatic' { if ($s.DelayedAutoStart -eq 'True') { 'delayed-auto' } else { 'auto' } } 'Manual' { 'demand' } 'Disabled' { 'disabled' } default { 'demand' } }
                $null = & sc.exe config $s.Name start= $startArg
                if ($LASTEXITCODE -ne 0) { throw "sc.exe exit code $LASTEXITCODE" }
                if ($s.Status -eq 'Running') { Start-Service -Name $s.Name -ErrorAction SilentlyContinue }
                Write-Log "$($s.Name) -> $($s.StartType)" Change
            } catch { Write-Log "Could not restore $($s.Name): $($_.Exception.Message)" Error }
        }
    }

    $regFile = Join-Path $Dir 'registry.json'
    if (Test-Path -LiteralPath $regFile) {
        $items = @(Get-Content -LiteralPath $regFile -Raw | ConvertFrom-Json)
        [array]::Reverse($items)
        foreach ($r in $items) {
            $label = "$($r.Path)\$($r.Name)"
            if (-not $PSCmdlet.ShouldProcess($label, 'Restore original value')) { continue }
            try {
                if ($r.HadValue) {
                    New-ItemProperty -LiteralPath $r.Path -Name $r.Name -Value $r.OldValue -PropertyType $r.OldType -Force | Out-Null
                    Write-Log "$label -> $($r.OldValue)" Change
                } else {
                    Remove-ItemProperty -LiteralPath $r.Path -Name $r.Name -ErrorAction SilentlyContinue
                    Write-Log "$label removed (did not exist before)" Change
                }
            } catch { Write-Log "Could not restore ${label}: $($_.Exception.Message)" Error }
        }
    }

    $appFile = Join-Path $Dir 'removed-apps.csv'
    if (Test-Path -LiteralPath $appFile) {
        $names = @(Import-Csv -LiteralPath $appFile | Select-Object -ExpandProperty Name -Unique)
        if ($names.Count) { Write-Log ("Apps are not restored automatically. Reinstall from the Microsoft Store if needed: {0}" -f ($names -join ', ')) Warn }
    }
    Write-Log 'Restore finished. Reboot to complete.' Info
}

# ===========================================================================
# Main
# ===========================================================================
if ($PSCmdlet.ParameterSetName -eq 'Restore') {
    if (-not $Force -and -not $script:DryRun -and -not $PSCmdlet.ShouldContinue("Restore firewall, services and registry from '$RestoreFrom'?", 'Windows hardening restore')) { return }
    Invoke-Restore -Dir $RestoreFrom
    return
}

# Safety: removing inbound rules from inside a remote session cuts you off.
$remoteSession = ($env:SESSIONNAME -like 'RDP-*') -or [bool]$env:SSH_CONNECTION -or [bool]$env:SSH_CLIENT
if ($remoteSession -and -not $SkipFirewall -and -not $Force -and -not $script:DryRun) {
    throw 'This looks like a Remote Desktop or SSH session. Firewall hardening would disconnect you. Run it locally, add -KeepInboundRules for your access rule, use -SkipFirewall, or pass -Force if you accept the risk.'
}

try {
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain) { Write-Log "Domain-joined ($($cs.Domain)): Group Policy may override these changes, and domain traffic needs extra outbound ports." Warn }
} catch {}

if (-not $script:DryRun -and -not $Force) {
    $plan = @()
    if (-not $SkipFirewall) { $plan += 'remove inbound allow rules and non-standard outbound rules' }
    if (-not $SkipBloatware) { $plan += 'uninstall bloatware apps' }
    if (-not $SkipServices) { $plan += 'disable unnecessary services' }
    if (-not $SkipSystemSettings) { $plan += 'apply security settings' }
    $msg = "This will: {0}.`nA backup goes to $BackupPath. Run with -WhatIf first to preview. Continue?" -f ($plan -join '; ')
    if (-not $PSCmdlet.ShouldContinue($msg, 'Windows hardening')) { Write-Log 'Cancelled.' Warn; return }
}

$transcribing = $false
if ($script:DryRun) {
    Write-Log 'DRY RUN (-WhatIf): nothing will be changed and no backup is written.' Head
} else {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    try { Start-Transcript -Path (Join-Path $BackupPath 'transcript.txt') | Out-Null; $transcribing = $true } catch {}
    Write-Log "Backup folder: $BackupPath" Head

    $out = & netsh.exe advfirewall export (Join-Path $BackupPath 'firewall.wfw') 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Firewall export failed, aborting before any change: $out" }
    Write-Log 'Firewall policy exported' Info

    if (-not $SkipRestorePoint) {
        try {
            Checkpoint-Computer -Description 'Before Set-WindowsHardening' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
            Write-Log 'System restore point created' Info
        } catch { Write-Log "No restore point (System Restore off, or one was made in the last 24h): $($_.Exception.Message)" Warn }
    }
}

try {
    if (-not $SkipFirewall)       { Invoke-FirewallHardening }
    if (-not $SkipBloatware)      { Invoke-BloatwareRemoval }
    if (-not $SkipServices)       { Invoke-ServiceHardening }
    if (-not $SkipSystemSettings) { Invoke-SystemHardening }
} finally {
    # Always write what was changed, even if a section threw part-way through.
    if (-not $script:DryRun) {
        $script:SvcChanges | Export-Csv -LiteralPath (Join-Path $BackupPath 'services.csv') -NoTypeInformation
        $script:AppChanges | Export-Csv -LiteralPath (Join-Path $BackupPath 'removed-apps.csv') -NoTypeInformation
        ConvertTo-Json -InputObject @($script:RegChanges) -Depth 3 | Set-Content -LiteralPath (Join-Path $BackupPath 'registry.json') -Encoding UTF8
    }

    Write-Log 'Summary' Head
    if ($script:Stats.Count -eq 0) { Write-Log 'Nothing changed.' Info }
    foreach ($k in $script:Stats.Keys) { Write-Log ('{0,-28} {1}' -f $k, $script:Stats[$k]) Info }
    if (-not $script:DryRun) {
        Write-Log "Undo with: .\Set-WindowsHardening.ps1 -RestoreFrom '$BackupPath'" Info
        if ($script:RebootNeeded) { Write-Log 'Reboot required for some changes to take effect.' Warn }
    }
    if ($transcribing) { try { Stop-Transcript | Out-Null } catch {} }
}
