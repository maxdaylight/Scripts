# =============================================================================
# Script: Find-LargeFiles.ps1
# Author: maxdaylight
# Last Updated: 2025-11-20 21:31:32 UTC
# Updated By: GitHub Copilot
# Version: 1.0.1
# Additional Info: Resolved analyzer compliance issues and improved formatting
# =============================================================================

<#!
.SYNOPSIS
Finds files that meet or exceed the specified size threshold on all local and mapped drives.

.DESCRIPTION
The Find-LargeFiles script inventories every accessible local and mapped drive and records any files that are at
least the configured size. Results are written to a timestamped text file in the script directory and summarized in
the console using standardized color output. Access and enumeration issues are logged as warnings. Hidden and
system files can optionally be included in the scan.

.PARAMETER MinimumSizeGB
Defines the minimum file size, in gigabytes, that should be reported. Defaults to 1 GB.

.PARAMETER IncludeHidden
Switch parameter that instructs the script to include files marked with the Hidden attribute in the scan results.

.PARAMETER IncludeSystem
Switch parameter that instructs the script to include files marked with the System attribute in the scan results.

.EXAMPLE
.\Find-LargeFiles.ps1 -MinimumSizeGB 2 -IncludeHidden -IncludeSystem
Runs the scan for files sized 2 GB or larger across all discovered drives, including hidden and system files, and
logs the results to the script directory.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MinimumSizeGB = 1,

    [Parameter()]
    [switch]$IncludeHidden,

    [Parameter()]
    [switch]$IncludeSystem
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:UseAnsiColors = $PSVersionTable.PSVersion.Major -ge 7
if ($script:UseAnsiColors) {
    $script:Colors = @{
        White   = "`e[97m"
        Cyan    = "`e[96m"
        Green   = "`e[92m"
        Yellow  = "`e[93m"
        Red     = "`e[91m"
        Magenta = "`e[95m"
        Reset   = "`e[0m"
    }
} else {
    $script:Colors = @{
        White   = [System.ConsoleColor]::White
        Cyan    = [System.ConsoleColor]::Cyan
        Green   = [System.ConsoleColor]::Green
        Yellow  = [System.ConsoleColor]::Yellow
        Red     = [System.ConsoleColor]::Red
        Magenta = [System.ConsoleColor]::Magenta
        Reset   = ""
    }
}

function Write-ColorOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [string]$Color = "White"
    )

    if ($script:UseAnsiColors) {
        $colorCode = $script:Colors[$Color]
        if (-not $colorCode) {
            $colorCode = $script:Colors['White']
        }

        $resetCode = $script:Colors['Reset']
        Write-Output ("{0}{1}{2}" -f $colorCode, $Message, $resetCode)
    } else {
        $originalColor = $Host.UI.RawUI.ForegroundColor
        try {
            if ($script:Colors[$Color] -and $script:Colors[$Color] -ne "") {
                $Host.UI.RawUI.ForegroundColor = $script:Colors[$Color]
            }

            Write-Output $Message
        } finally {
            $Host.UI.RawUI.ForegroundColor = $originalColor
        }
    }
}

function Get-UtcTimestamp {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Format = 'yyyy-MM-dd HH:mm:ss'
    )

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        return Get-Date -Format $Format -AsUTC
    }

    return (Get-Date).ToUniversalTime().ToString($Format)
}

function ConvertTo-ReadableSize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [long]$Bytes
    )

    $units = @('B', 'KB', 'MB', 'GB', 'TB', 'PB')
    $size = [double]$Bytes
    $index = 0

    while ($size -ge 1024 -and $index -lt ($units.Count - 1)) {
        $size /= 1024
        $index += 1
    }

    return ('{0:N2} {1}' -f $size, $units[$index])
}

function Get-TargetDrive {
    [CmdletBinding()]
    param()

    return Get-PSDrive -PSProvider FileSystem |
        Where-Object { $_.Root } |
        Sort-Object -Property Name
}

function Invoke-DriveScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSDriveInfo]$Drive,

        [Parameter(Mandatory = $true)]
        [long]$MinimumSizeBytes,

        [Parameter(Mandatory = $true)]
        [bool]$IncludeHiddenFiles,

        [Parameter(Mandatory = $true)]
        [bool]$IncludeSystemFiles
    )

    $records = [System.Collections.Generic.List[psobject]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path -LiteralPath $Drive.Root)) {
        $errors.Add("Drive $($Drive.Name) skipped: root path '$($Drive.Root)' is unavailable.")
        return [PSCustomObject]@{
            Drive   = $Drive
            Records = $records
            Errors  = $errors
        }
    }

    $gciParameters = @{
        LiteralPath   = $Drive.Root
        File          = $true
        Recurse       = $true
        ErrorAction   = 'SilentlyContinue'
        ErrorVariable = 'driveErrors'
    }

    if ($IncludeHiddenFiles -or $IncludeSystemFiles) {
        $gciParameters['Force'] = $true
    }

    $driveErrors = @()
    foreach ($item in Get-ChildItem @gciParameters) {
        $isHidden = [bool]($item.Attributes -band [System.IO.FileAttributes]::Hidden)
        $isSystem = [bool]($item.Attributes -band [System.IO.FileAttributes]::System)

        if ((-not $IncludeHiddenFiles -and $isHidden) -or (-not $IncludeSystemFiles -and $isSystem)) {
            continue
        }

        if ($item.Length -ge $MinimumSizeBytes) {
            $records.Add([PSCustomObject]@{
            Drive             = $Drive.Name
            Root              = $Drive.Root
            FullName          = $item.FullName
            SizeBytes         = $item.Length
            SizeReadable      = ConvertTo-ReadableSize -Bytes $item.Length
            SizeGB            = [math]::Round($item.Length / 1GB, 2)
            LastWriteTimeUtc  = $item.LastWriteTimeUtc
        })
        }
    }

    if ($driveErrors) {
        foreach ($errorRecord in $driveErrors) {
            if ($null -ne $errorRecord.Exception) {
                $errors.Add("Drive $($Drive.Name): $($errorRecord.Exception.Message)")
            } elseif ($null -ne $errorRecord) {
                $errors.Add("Drive $($Drive.Name): $($errorRecord.ToString())")
            }
        }
    }

    return [PSCustomObject]@{
        Drive   = $Drive
        Records = $records
        Errors  = $errors
    }
}

$script:ScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$timestampUtc = Get-UtcTimestamp -Format 'yyyyMMddTHHmmssZ'
$computerName = $env:COMPUTERNAME
$logFileName = "Find-LargeFiles_{0}_{1}.txt" -f $computerName, $timestampUtc
$script:LogFilePath = Join-Path -Path $script:ScriptDirectory -ChildPath $logFileName

$logContent = [System.Collections.Generic.List[string]]::new()
$scanWarnings = [System.Collections.Generic.List[string]]::new()

$minimumSizeBytes = [long]($MinimumSizeGB * 1GB)

try {
    Write-ColorOutput -Message ("Starting large file discovery at threshold {0} GB." -f $MinimumSizeGB) -Color 'Cyan'

    $drives = Get-TargetDrive
    $logContent.Add("Find-LargeFiles execution on {0} UTC" -f (Get-UtcTimestamp))
    $logContent.Add("Computer Name: $computerName")
    $logContent.Add("Minimum Size (GB): $MinimumSizeGB")
    $logContent.Add("Include Hidden Files: {0}" -f $IncludeHidden.IsPresent)
    $logContent.Add("Include System Files: {0}" -f $IncludeSystem.IsPresent)
    if ($drives) {
        $logContent.Add("Drives Scanned: {0}" -f ($drives.Name -join ', '))
    } else {
        $logContent.Add('Drives Scanned: None detected')
    }
    $logContent.Add('')

    if (-not $drives) {
        $message = 'No file system drives were detected. Nothing to scan.'
        Write-ColorOutput -Message $message -Color 'Yellow'
        $logContent.Add($message)
        $logContent | Out-File -FilePath $script:LogFilePath -Encoding UTF8
        exit 0
    }

    $results = [System.Collections.Generic.List[psobject]]::new()
    foreach ($drive in $drives) {
        Write-ColorOutput -Message ("Scanning drive {0} [{1}]..." -f $drive.Name, $drive.Root) -Color 'Cyan'

        $scanResult = Invoke-DriveScan -Drive $drive -MinimumSizeBytes $minimumSizeBytes -IncludeHiddenFiles:$IncludeHidden.IsPresent -IncludeSystemFiles:$IncludeSystem.IsPresent

        foreach ($record in $scanResult.Records) {
            $results.Add($record)
        }

        foreach ($warning in $scanResult.Errors) {
            Write-ColorOutput -Message "[SYSTEM ERROR DETECTED] $warning" -Color 'Yellow'
            $scanWarnings.Add($warning)
        }
    }

    $resultsSorted = $results | Sort-Object -Property SizeBytes -Descending

    if ($scanWarnings.Count -gt 0) {
        $logContent.Add('Warnings Encountered:')
        foreach ($warning in $scanWarnings) {
            $logContent.Add("- $warning")
        }
        $logContent.Add('')
    }

    if ($resultsSorted.Count -gt 0) {
        Write-ColorOutput -Message ("Large files found: {0}" -f $resultsSorted.Count) -Color 'Green'
        $logContent.Add('Drive\tFullPath\tSize (Readable)\tSize (GB)\tSize (Bytes)\tLast Write Time (UTC)')

        foreach ($record in $resultsSorted) {
            $logContent.Add(
                ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f
                    $record.Drive,
                    $record.FullName,
                    $record.SizeReadable,
                    [string]$record.SizeGB,
                    $record.SizeBytes,
                    $record.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))
            )
        }
    } else {
        $message = 'No files met the specified size threshold.'
        Write-ColorOutput -Message $message -Color 'Magenta'
        $logContent.Add($message)
    }

    $logContent | Out-File -FilePath $script:LogFilePath -Encoding UTF8
    Write-ColorOutput -Message ("Log saved to $script:LogFilePath") -Color 'Green'
    exit 0
} catch {
    Write-ColorOutput -Message ("[SYSTEM ERROR DETECTED] $($_.Exception.Message)") -Color 'Red'
    throw
}
