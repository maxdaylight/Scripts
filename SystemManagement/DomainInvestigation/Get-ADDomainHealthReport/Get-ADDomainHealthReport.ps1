# =============================================================================
# Script: Get-ADDomainHealthReport.ps1
# Author: maxdaylight
# Last Updated: 2026-10-08 21:07:18 UTC
# Updated By: maxdaylight
# Version: 1.0.1
# Additional Info: Allow empty report lines in Add-ReportText under StrictMode
# =============================================================================

<#
.SYNOPSIS
    Collects Active Directory domain health evidence into a dated text report.
.DESCRIPTION
    Gathers domain, forest, FSMO, replication, SYSVOL/DFSR, DNS, DCDIAG, and recent
    event-log evidence for domain controllers in the current domain, or across the
    forest when -ForestWide is specified.

    The script is an evidence collector for go/no-go review. It records collection
    warnings and automated replication findings in a closeout summary.

    Dependencies:
    - ActiveDirectory PowerShell module (RSAT AD tools or domain controller)
    - Domain-joined Windows host with rights to query AD and remote DCs
    - Optional tools on PATH: repadmin, netdom, dcdiag
    - Remote PowerShell remoting for SYSVOL, DNS, and event-log checks unless
      -SkipRemoteChecks is specified

    Results are written to a text report and a companion execution log in the
    report directory. Console output uses color-coded status messages without
    Write-Host.
.PARAMETER ReportPath
    Directory where the text report and execution log are saved.
    Defaults to the script directory. Created automatically if missing.
.PARAMETER EventLookbackHours
    Number of hours of Directory Service, DNS Server, DFS Replication, and
    System KDC event history to collect. Valid range is 1 to 168. Default is 4.
.PARAMETER IncludeRODCs
    Include read-only domain controllers in discovery and remote checks.
    Writable DCs only are collected by default.
.PARAMETER SkipRemoteChecks
    Skip Invoke-Command remote checks for SYSVOL, DNS configuration, and event logs.
.PARAMETER ForestWide
    Collect evidence for every domain in the current forest instead of only the
    current domain.
.PARAMETER SkipDCDiag
    Skip targeted and enterprise DCDIAG collection.
.PARAMETER OpenReport
    Open the completed text report in Notepad after collection finishes.
    Optional and interactive; omit for unattended runs.
.EXAMPLE
    .\Get-ADDomainHealthReport.ps1
    Collects health evidence for the current domain and writes the report and log
    to the script directory.
.EXAMPLE
    .\Get-ADDomainHealthReport.ps1 -ReportPath 'C:\Reports' -EventLookbackHours 24
    Collects evidence with a 24-hour event lookback and saves output under C:\Reports.
.EXAMPLE
    .\Get-ADDomainHealthReport.ps1 -ForestWide -IncludeRODCs -SkipDCDiag
    Collects forest-wide evidence including RODCs while skipping DCDIAG tests.
.EXAMPLE
    .\Get-ADDomainHealthReport.ps1 -SkipRemoteChecks -OpenReport
    Collects local AD evidence only, then opens the text report in Notepad.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateScript({
            if (-not [string]::IsNullOrWhiteSpace($_) -and -not (Test-Path -Path $_ -PathType Container)) {
                New-Item -ItemType Directory -Path $_ -Force | Out-Null
            }
            return $true
        })]
    [string]$ReportPath,

    [Parameter()]
    [ValidateRange(1, 168)]
    [int]$EventLookbackHours = 4,

    [Parameter()]
    [switch]$IncludeRODCs,

    [Parameter()]
    [switch]$SkipRemoteChecks,

    [Parameter()]
    [switch]$ForestWide,

    [Parameter()]
    [switch]$SkipDCDiag,

    [Parameter()]
    [switch]$OpenReport
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Set default ReportPath if not provided
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}

if (-not (Test-Path -Path $ReportPath -PathType Container)) {
    New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
}

# Color system for both PowerShell 5.1 and 7+
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $Script:Colors = @{
        Reset    = "`e[0m"
        White    = "`e[37m"
        Cyan     = "`e[36m"
        Green    = "`e[32m"
        Yellow   = "`e[33m"
        Red      = "`e[31m"
        Magenta  = "`e[35m"
        DarkGray = "`e[90m"
        Bold     = "`e[1m"
    }
    $Script:UseAnsiColors = $true
} else {
    $Script:Colors = @{
        Reset    = ''
        White    = 'White'
        Cyan     = 'Cyan'
        Green    = 'Green'
        Yellow   = 'Yellow'
        Red      = 'Red'
        Magenta  = 'Magenta'
        DarkGray = 'DarkGray'
        Bold     = ''
    }
    $Script:UseAnsiColors = $false
}

$script:SystemName         = $env:COMPUTERNAME
$script:Timestamp          = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogFile            = Join-Path -Path $ReportPath -ChildPath "Get-ADDomainHealthReport_${script:SystemName}_${script:Timestamp}.log"
$script:Report             = Join-Path -Path $ReportPath -ChildPath "ADDomainHealth_${script:SystemName}_${script:Timestamp}.txt"
$script:CollectionWarnings = [System.Collections.Generic.List[string]]::new()
$script:HealthFindings     = [System.Collections.Generic.List[string]]::new()
$script:ExitCode           = 0

function Write-ColorOutput {
    <#
    .SYNOPSIS
        Writes colored output for PowerShell 5.1 and 7+ without Write-Host.
    .DESCRIPTION
        Uses ANSI escape codes on PowerShell 7+ and console foreground color changes
        on PowerShell 5.1. Output is written with Write-Output for automation safety.
    .PARAMETER Message
        Message text to write.
    .PARAMETER Color
        Color name: White, Cyan, Green, Yellow, Red, Magenta, or DarkGray.
    .EXAMPLE
        Write-ColorOutput -Message 'Success' -Color 'Green'
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Color = 'White'
    )

    if ($Script:UseAnsiColors) {
        $colorCode = $Script:Colors[$Color]
        $resetCode = $Script:Colors.Reset
        Write-Output -InputObject "${colorCode}${Message}${resetCode}"
    } else {
        $originalColor = $Host.UI.RawUI.ForegroundColor
        try {
            if ($Script:Colors[$Color] -and $Script:Colors[$Color] -ne '') {
                $Host.UI.RawUI.ForegroundColor = $Script:Colors[$Color]
            }
            Write-Output -InputObject $Message
        } finally {
            $Host.UI.RawUI.ForegroundColor = $originalColor
        }
    }
}

function Write-LogMessage {
    <#
    .SYNOPSIS
        Writes a timestamped message to the execution log and console.
    .PARAMETER Message
        Message text to log.
    .PARAMETER Level
        Log level used for coloring and log tags.
    .EXAMPLE
        Write-LogMessage -Message 'Collection started' -Level 'Process'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Process', 'Success', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )

    $logTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
    $logMessage = "[$logTimestamp] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $logMessage

    $colorMap = @{
        Info    = 'White'
        Process = 'Cyan'
        Success = 'Green'
        Warning = 'Yellow'
        Error   = 'Red'
        Debug   = 'Magenta'
    }

    $color = if ($colorMap.ContainsKey($Level)) { $colorMap[$Level] } else { 'White' }
    Write-ColorOutput -Message $logMessage -Color $color
}

function Add-ReportSection {
    <#
    .SYNOPSIS
        Writes a titled section header to the text report.
    .PARAMETER Title
        Section title text.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title
    )

    @(
        ''
        ('=' * 110)
        $Title
        ('=' * 110)
        "Collected: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        ''
    ) | Out-File -FilePath $script:Report -Append -Encoding utf8
}

function Add-ReportText {
    <#
    .SYNOPSIS
        Appends one or more text lines to the report.
    .PARAMETER Text
        Lines to append.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]$Text
    )

    $Text | Out-File -FilePath $script:Report -Append -Encoding utf8
}

function Add-CommandOutput {
    <#
    .SYNOPSIS
        Runs a command and appends labeled output to the report.
    .PARAMETER Label
        Section label written above the command output.
    .PARAMETER Command
        Script block to execute.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    "---- $Label ----" | Out-File -FilePath $script:Report -Append -Encoding utf8

    try {
        $output = & $Command 2>&1 | Out-String -Width 320
        if ([string]::IsNullOrWhiteSpace($output)) {
            '[No output returned]' | Out-File -FilePath $script:Report -Append -Encoding utf8
        } else {
            $output | Out-File -FilePath $script:Report -Append -Encoding utf8
        }
    } catch {
        $message = "COLLECTION ERROR: $($_.Exception.Message)"
        $script:CollectionWarnings.Add("$Label - $message")
        Write-LogMessage -Message $message -Level 'Warning'
        $message | Out-File -FilePath $script:Report -Append -Encoding utf8
    }

    '' | Out-File -FilePath $script:Report -Append -Encoding utf8
}

function Get-ManagedDomainController {
    <#
    .SYNOPSIS
        Discovers domain controllers for a domain.
    .PARAMETER DomainName
        DNS name of the domain to query.
    .PARAMETER IncludeRODC
        Include read-only domain controllers when present.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter()]
        [switch]$IncludeRODC
    )

    $domainControllerList = Get-ADDomainController -Filter * -Server $DomainName

    if (-not $IncludeRODC) {
        $domainControllerList = $domainControllerList | Where-Object { -not $_.IsReadOnly }
    }

    $domainControllerList | Sort-Object -Property HostName
}

function Add-ReplicationFinding {
    <#
    .SYNOPSIS
        Parses repadmin summary output for non-zero failure counts.
    .PARAMETER ScopeName
        Domain or scope label used in finding text.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScopeName
    )

    try {
        $summary = repadmin /replsummary 2>&1 | Out-String
        if ($summary -match '(?m)^\s*\S+\s+.*\s+([1-9]\d*)\s*/\s*\d+\s+') {
            $script:HealthFindings.Add("${ScopeName}: Repadmin replication summary contains one or more failures. Review the replication section.")
        }
    } catch {
        $script:CollectionWarnings.Add("${ScopeName}: Unable to assess replication summary automatically. $($_.Exception.Message)")
    }
}

function Add-LocalDomainCheck {
    <#
    .SYNOPSIS
        Collects AD health evidence for a single domain scope.
    .PARAMETER DomainName
        DNS name of the domain.
    .PARAMETER DomainController
        Domain controller objects returned by discovery.
    .PARAMETER ScopeName
        Label used in report section titles.
    .PARAMETER SkipRemoteCheck
        Skip remote SYSVOL, DNS, and event-log checks.
    .PARAMETER SkipDCDiagCheck
        Skip DCDIAG collection.
    .PARAMETER EventLookbackHour
        Event log lookback window in hours.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [object[]]$DomainController,

        [Parameter(Mandatory = $true)]
        [string]$ScopeName,

        [Parameter()]
        [switch]$SkipRemoteCheck,

        [Parameter()]
        [switch]$SkipDCDiagCheck,

        [Parameter(Mandatory = $true)]
        [int]$EventLookbackHour
    )

    $domainInfo = Get-ADDomain -Server $DomainName
    $forestInfo = Get-ADForest -Server $DomainName
    $dcNameList = @($DomainController | Select-Object -ExpandProperty HostName)

    Add-ReportSection -Title "$ScopeName - DOMAIN, FOREST, AND FSMO INVENTORY"

    Add-CommandOutput -Label 'Domain configuration' -Command {
        $domainInfo |
            Select-Object -Property DNSRoot, NetBIOSName, DomainMode, DistinguishedName,
            PDCEmulator, RIDMaster, InfrastructureMaster |
            Format-List
    }

    Add-CommandOutput -Label 'Forest configuration' -Command {
        $forestInfo |
            Select-Object -Property Name, ForestMode, RootDomain,
            SchemaMaster, DomainNamingMaster,
            Domains, GlobalCatalogs, Sites |
            Format-List
    }

    Add-CommandOutput -Label 'FSMO role holders' -Command {
        netdom query fsmo
    }

    Add-CommandOutput -Label 'Domain controller inventory' -Command {
        $DomainController |
            Select-Object -Property Name, HostName, IPv4Address, Site,
            IsGlobalCatalog, IsReadOnly, OperatingSystem |
            Format-Table -AutoSize
    }

    Add-ReportSection -Title "$ScopeName - ACTIVE DIRECTORY REPLICATION"

    Add-CommandOutput -Label 'Replication summary' -Command {
        repadmin /replsummary
    }

    Add-CommandOutput -Label 'Inbound replication errors only' -Command {
        repadmin /showrepl * /errorsonly
    }

    Add-CommandOutput -Label 'Replication failure objects' -Command {
        Get-ADReplicationFailure -Scope Forest -Target $DomainName |
            Select-Object -Property Server, Partner, FailureCount, FailureType,
            FirstFailureTime, LastError |
            Format-Table -AutoSize
    }

    Add-CommandOutput -Label 'Replication partner metadata with active failures' -Command {
        Get-ADReplicationPartnerMetadata -Target $DomainName -Scope Domain |
            Where-Object {
                $_.LastReplicationResult -ne 0 -or
                $_.ConsecutiveReplicationFailures -gt 0
            } |
            Select-Object -Property Server, Partner, Partition,
            LastReplicationAttempt, LastReplicationSuccess,
            LastReplicationResult, ConsecutiveReplicationFailures |
            Sort-Object -Property Server, Partner, Partition |
            Format-Table -AutoSize
    }

    foreach ($dc in $DomainController) {
        Add-CommandOutput -Label "Detailed inbound replication: $($dc.HostName)" -Command {
            repadmin /showrepl $dc.HostName /verbose
        }
    }

    Add-ReplicationFinding -ScopeName $ScopeName

    Add-ReportSection -Title "$ScopeName - SYSVOL, NETLOGON, DFSR, AND CORE SERVICES"

    if ($SkipRemoteCheck) {
        Add-ReportText -Text @('Remote checks were skipped because -SkipRemoteChecks was specified.')
    } else {
        Add-CommandOutput -Label 'SYSVOL, NETLOGON, DFSR state, and core services' -Command {
            Invoke-Command -ComputerName $dcNameList -ScriptBlock {
                $sysvolFolders = Get-CimInstance -Namespace 'root\microsoftdfs' -ClassName DfsrReplicatedFolderInfo -ErrorAction SilentlyContinue
                $sysvol = $sysvolFolders | Where-Object { $_.ReplicatedFolderName -eq 'SYSVOL Share' }
                $services = Get-Service -Name ADWS, DNS, DFSR, KDC, Netlogon, NTDS -ErrorAction SilentlyContinue

                [PSCustomObject]@{
                    DC                = $env:COMPUTERNAME
                    SYSVOLShare       = [bool](Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue)
                    NETLOGONShare     = [bool](Get-SmbShare -Name NETLOGON -ErrorAction SilentlyContinue)
                    DFSRState         = $sysvol.State
                    DFSRLastErrorCode = $sysvol.LastErrorCode
                    DFSRLastError     = $sysvol.LastErrorMessage
                    ADWS              = ($services | Where-Object Name -EQ 'ADWS').Status
                    DNS               = ($services | Where-Object Name -EQ 'DNS').Status
                    DFSR              = ($services | Where-Object Name -EQ 'DFSR').Status
                    KDC               = ($services | Where-Object Name -EQ 'KDC').Status
                    Netlogon          = ($services | Where-Object Name -EQ 'Netlogon').Status
                    NTDS              = ($services | Where-Object Name -EQ 'NTDS').Status
                }
            } | Sort-Object -Property PSComputerName | Format-List
        }

        Add-CommandOutput -Label 'SYSVOL DFSR replicated folder status' -Command {
            $remoteResult = Invoke-Command -ComputerName $dcNameList -ScriptBlock {
                $sysvolFolders = Get-CimInstance -Namespace 'root\microsoftdfs' -ClassName DfsrReplicatedFolderInfo -ErrorAction SilentlyContinue
                $sysvolFolders | Where-Object { $_.ReplicatedFolderName -eq 'SYSVOL Share' } | Select-Object -Property MemberName, ReplicatedFolderName, State, LastErrorCode, LastErrorMessage, LastErrorUpdateTime
            }
            $remoteResult | Sort-Object -Property PSComputerName | Format-List
        }
    }

    Add-ReportSection -Title "$ScopeName - DNS CONFIGURATION AND DC LOCATOR RECORDS"

    if ($SkipRemoteCheck) {
        Add-ReportText -Text @('Remote DNS configuration checks were skipped because -SkipRemoteChecks was specified.')
    } else {
        Add-CommandOutput -Label 'DNS client resolver configuration on all included DCs' -Command {
            $remoteResult = Invoke-Command -ComputerName $dcNameList -ScriptBlock {
                Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Select-Object -Property InterfaceAlias, InterfaceIndex, ServerAddresses
            }
            $remoteResult | Sort-Object -Property PSComputerName, InterfaceAlias | Format-Table -Property PSComputerName, InterfaceAlias, InterfaceIndex, ServerAddresses -AutoSize
        }

        Add-CommandOutput -Label 'AD-integrated DNS zones on included DCs' -Command {
            $remoteResult = Invoke-Command -ComputerName $dcNameList -ScriptBlock {
                if (Get-Command -Name Get-DnsServerZone -ErrorAction SilentlyContinue) {
                    Get-DnsServerZone | Where-Object { $_.IsDsIntegrated } | Select-Object -Property ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate, ReplicationScope, IsReverseLookupZone
                } else {
                    [PSCustomObject]@{
                        Note = 'DNS Server PowerShell module is not available on this DC.'
                    }
                }
            }
            $remoteResult | Sort-Object -Property PSComputerName, ZoneName | Format-Table -Property PSComputerName, ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate, ReplicationScope, IsReverseLookupZone, Note -AutoSize
        }
    }

    Add-CommandOutput -Label 'Domain DNS and DC locator SRV records' -Command {
        Resolve-DnsName -Name $DomainName
        Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV
        Resolve-DnsName -Name "_kerberos._tcp.dc._msdcs.$DomainName" -Type SRV
        Resolve-DnsName -Name "_gc._tcp.$DomainName" -Type SRV
    }

    foreach ($dc in $DomainController) {
        Add-CommandOutput -Label "Host and NTDS GUID DNS verification: $($dc.HostName)" -Command {
            $ntdsSettings = Get-ADObject -Identity $dc.NTDSSettingsObjectDN -Server $DomainName -Properties ObjectGuid
            $guid = $ntdsSettings.ObjectGuid.Guid

            [PSCustomObject]@{
                DomainController = $dc.HostName
                IPv4Address      = $dc.IPv4Address
                NTDSSettingsDN   = $dc.NTDSSettingsObjectDN
                NTDSSettingsGuid = $guid
            } | Format-List

            Resolve-DnsName -Name $dc.HostName
            Resolve-DnsName -Name "$guid._msdcs.$DomainName" -Type CNAME
        }
    }

    if (-not $SkipDCDiagCheck) {
        Add-ReportSection -Title "$ScopeName - TARGETED DCDIAG"

        foreach ($dc in $DomainController) {
            Add-CommandOutput -Label "DCDIAG targeted checks: $($dc.HostName)" -Command {
                dcdiag /s:$($dc.HostName) /test:Advertising /test:DNS /test:Replications /test:Services /test:SysVolCheck /test:NetLogons /v
            }
        }

        Add-CommandOutput -Label 'Enterprise DCDIAG quick output' -Command {
            dcdiag /e /q
        }
    } else {
        Add-ReportSection -Title "$ScopeName - TARGETED DCDIAG"
        Add-ReportText -Text @('DCDIAG checks were skipped because -SkipDCDiag was specified.')
    }

    Add-ReportSection -Title "$ScopeName - RECENT EVENT LOG WARNINGS AND ERRORS"

    $startTime = (Get-Date).AddHours(-$EventLookbackHour)

    if ($SkipRemoteCheck) {
        Add-ReportText -Text @('Remote event-log checks were skipped because -SkipRemoteChecks was specified.')
    } else {
        Add-CommandOutput -Label "Directory Service warnings/errors since $startTime" -Command {
            $remoteResult = Invoke-Command -ComputerName $dcNameList -ScriptBlock {
                Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; StartTime = $using:startTime } -ErrorAction SilentlyContinue |
                    Where-Object { $_.LevelDisplayName -in 'Error', 'Warning' } |
                    Select-Object -Property TimeCreated, Id, LevelDisplayName, ProviderName, Message
            }
            $remoteResult | Sort-Object -Property PSComputerName, TimeCreated | Format-List -Property PSComputerName, TimeCreated, Id, LevelDisplayName, ProviderName, Message
        }

        Add-CommandOutput -Label "DNS Server warnings/errors since $startTime" -Command {
            $remoteResult = Invoke-Command -ComputerName $dcNameList -ScriptBlock {
                Get-WinEvent -FilterHashtable @{ LogName = 'DNS Server'; StartTime = $using:startTime } -ErrorAction SilentlyContinue |
                    Where-Object { $_.LevelDisplayName -in 'Error', 'Warning' } |
                    Select-Object -Property TimeCreated, Id, LevelDisplayName, ProviderName, Message
            }
            $remoteResult | Sort-Object -Property PSComputerName, TimeCreated | Format-List -Property PSComputerName, TimeCreated, Id, LevelDisplayName, ProviderName, Message
        }

        Add-CommandOutput -Label "DFS Replication warnings/errors since $startTime" -Command {
            $remoteResult = Invoke-Command -ComputerName $dcNameList -ScriptBlock {
                Get-WinEvent -FilterHashtable @{ LogName = 'DFS Replication'; StartTime = $using:startTime } -ErrorAction SilentlyContinue |
                    Where-Object { $_.LevelDisplayName -in 'Error', 'Warning' } |
                    Select-Object -Property TimeCreated, Id, LevelDisplayName, ProviderName, Message
            }
            $remoteResult | Sort-Object -Property PSComputerName, TimeCreated | Format-List -Property PSComputerName, TimeCreated, Id, LevelDisplayName, ProviderName, Message
        }

        Add-CommandOutput -Label "System-log KDC warnings/errors since $startTime" -Command {
            $remoteResult = Invoke-Command -ComputerName $dcNameList -ScriptBlock {
                Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $using:startTime } -ErrorAction SilentlyContinue |
                    Where-Object { $_.ProviderName -match 'Kerberos|Kdc' -and $_.LevelDisplayName -in 'Error', 'Warning' } |
                    Select-Object -Property TimeCreated, Id, LevelDisplayName, ProviderName, Message
            }
            $remoteResult | Sort-Object -Property PSComputerName, TimeCreated | Format-List -Property PSComputerName, TimeCreated, Id, LevelDisplayName, ProviderName, Message
        }
    }
}

# Main execution
try {
    New-Item -ItemType File -Path $script:LogFile -Force | Out-Null
    New-Item -ItemType File -Path $script:Report -Force | Out-Null

    Write-LogMessage -Message '=== AD Domain Health Report Started ===' -Level 'Process'
    Write-LogMessage -Message "System: $script:SystemName" -Level 'Info'
    Write-LogMessage -Message "Report path: $ReportPath" -Level 'Info'
    Write-LogMessage -Message "Report file: $script:Report" -Level 'Info'
    Write-LogMessage -Message "Log file: $script:LogFile" -Level 'Info'
    Write-LogMessage -Message "Forest-wide: $ForestWide | Include RODCs: $IncludeRODCs | Skip remote: $SkipRemoteChecks | Skip DCDIAG: $SkipDCDiag" -Level 'Info'
    Write-LogMessage -Message "Event lookback hours: $EventLookbackHours" -Level 'Info'

    try {
        Import-Module -Name ActiveDirectory -ErrorAction Stop
    } catch {
        throw "The ActiveDirectory PowerShell module is required. Install RSAT AD tools or run on a domain controller. Details: $($_.Exception.Message)"
    }

    $currentDomain = Get-ADDomain
    $currentForest = Get-ADForest
    $domainsToCheck = @($currentDomain.DNSRoot)

    if ($ForestWide) {
        $domainsToCheck = @($currentForest.Domains | Sort-Object)
    }

    Add-ReportSection -Title 'ACTIVE DIRECTORY DOMAIN HEALTH REPORT'
    Add-ReportText -Text @(
        "Report file: $script:Report"
        "Log file: $script:LogFile"
        "Collection host: $env:COMPUTERNAME"
        "Collection user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        "Current domain: $($currentDomain.DNSRoot)"
        "Current forest: $($currentForest.Name)"
        "Forest-wide collection: $ForestWide"
        "Include RODCs: $IncludeRODCs"
        "Remote checks skipped: $SkipRemoteChecks"
        "DCDIAG skipped: $SkipDCDiag"
        "Event lookback: $EventLookbackHours hour(s)"
        ''
    )

    foreach ($domainName in $domainsToCheck) {
        Write-LogMessage -Message "Collecting evidence for domain: $domainName" -Level 'Process'

        try {
            $domainControllerList = @(
                Get-ManagedDomainController -DomainName $domainName -IncludeRODC:$IncludeRODCs
            )

            if ($domainControllerList.Count -eq 0) {
                $message = "${domainName}: No domain controllers were returned by discovery."
                $script:HealthFindings.Add($message)
                Write-LogMessage -Message $message -Level 'Warning'
                Add-ReportSection -Title "$domainName - DISCOVERY FAILURE"
                Add-ReportText -Text @($message)
                continue
            }

            Add-LocalDomainCheck -DomainName $domainName -DomainController $domainControllerList -ScopeName $domainName -SkipRemoteCheck:$SkipRemoteChecks -SkipDCDiagCheck:$SkipDCDiag -EventLookbackHour $EventLookbackHours

            Write-LogMessage -Message "Completed collection for domain: $domainName" -Level 'Success'
        } catch {
            $message = "${domainName}: Domain collection failed. $($_.Exception.Message)"
            $script:CollectionWarnings.Add($message)
            $script:ExitCode = 1
            Write-LogMessage -Message $message -Level 'Error'
            Add-ReportSection -Title "$domainName - COLLECTION FAILURE"
            Add-ReportText -Text @($message)
        }
    }

    Add-ReportSection -Title 'CLOSEOUT SUMMARY'

    $summary = [System.Collections.Generic.List[string]]::new()
    $summary.Add("Collection completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $summary.Add("Report: $script:Report")
    $summary.Add("Log: $script:LogFile")
    $summary.Add('')
    $summary.Add('Expected healthy indicators:')
    $summary.Add('- Repadmin replication summary shows 0 failures for every source and destination DC.')
    $summary.Add('- Repadmin errors-only output contains no active replication error or KCC warning.')
    $summary.Add('- SYSVOL and NETLOGON shares are present; DFSR SYSVOL State is 4 and error code is 0.')
    $summary.Add('- ADWS, DNS, DFSR, KDC, Netlogon, and NTDS are Running on writable DCs.')
    $summary.Add('- Targeted DCDIAG tests pass, allowing for documented or understood environmental exceptions.')
    $summary.Add('- DC host records, NTDS GUID CNAME records, and DC locator records resolve correctly.')
    $summary.Add('- Recent Directory Service, DNS Server, DFSR, and KDC events have no unexplained errors.')
    $summary.Add('')

    if ($script:HealthFindings.Count -gt 0) {
        $summary.Add('AUTOMATED HEALTH FINDINGS:')
        foreach ($finding in $script:HealthFindings) {
            $summary.Add("- $finding")
        }
        $summary.Add('')
        $script:ExitCode = 1
    } else {
        $summary.Add('AUTOMATED HEALTH FINDINGS: No automated replication-failure condition was detected.')
        $summary.Add('')
    }

    if ($script:CollectionWarnings.Count -gt 0) {
        $summary.Add('COLLECTION WARNINGS / LIMITATIONS:')
        foreach ($warning in $script:CollectionWarnings) {
            $summary.Add("- $warning")
        }
        $summary.Add('')
        if ($script:ExitCode -eq 0) {
            $script:ExitCode = 1
        }
    } else {
        $summary.Add('COLLECTION WARNINGS / LIMITATIONS: None recorded.')
        $summary.Add('')
    }

    $summary.Add('This report is an evidence collector. Review documented exceptions before declaring a formal go/no-go decision.')
    Add-ReportText -Text $summary

    Write-LogMessage -Message "AD health report created: $script:Report" -Level 'Success'
    Write-LogMessage -Message '=== AD Domain Health Report Completed ===' -Level 'Process'

    if ($OpenReport) {
        Write-LogMessage -Message 'Opening report in Notepad because -OpenReport was specified.' -Level 'Info'
        Start-Process -FilePath 'notepad.exe' -ArgumentList $script:Report
    }
} catch {
    $script:ExitCode = 1
    $errorMessage = "Script execution failed: $($_.Exception.Message)"
    if ($script:LogFile -and (Test-Path -Path $script:LogFile)) {
        Write-LogMessage -Message $errorMessage -Level 'Error'
        Write-LogMessage -Message "Stack Trace: $($_.ScriptStackTrace)" -Level 'Error'
    } else {
        Write-ColorOutput -Message $errorMessage -Color 'Red'
    }
    throw
} finally {
    exit $script:ExitCode
}
