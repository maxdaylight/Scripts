# =============================================================================
# Script: Get-SetInactivityTimers.ps1
# Created: 2025-04-08 21:45:00 UTC
# Author: maxdaylight
# Last Updated: 2025-04-14 22:04:00 UTC
# Updated By: maxdaylight
# Version: 1.4.0
# Additional Info: Fixed power settings parsing to correctly detect and display monitor and sleep timeouts
# =============================================================================

<#
.SYNOPSIS
Gets and optionally sets Windows system inactivity timers.

.DESCRIPTION
This script retrieves all available system inactivity settings including screen timeout,
sleep settings, power management configurations, and security policies related to machine locking.
It displays these settings to the user and provides the option to modify them. All changes support -WhatIf functionality for safety.

.EXAMPLE
.\Get-SetInactivityTimers.ps1
Displays current inactivity settings and prompts for changes

.EXAMPLE
.\Get-SetInactivityTimers.ps1 -WhatIf
Shows what changes would be made without actually making them
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param()

# Function to safely stop transcript
function Stop-TranscriptSafely {
    try {
        if ([System.Management.Automation.PowerShell]::Create().AddCommand('Get-PSSession').Invoke() | 
            Where-Object { $_.State -eq 'Running' -and $_.Name -like '*Transcript*' }) {
            # Stop any running transcripts
            Stop-Transcript -ErrorAction SilentlyContinue
            # Give the system a moment to release the file handle
            Start-Sleep -Milliseconds 500
            # Force garbage collection to release file handles
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
    }
    catch {
        Write-Debug "Error stopping transcript: $_"
    }
}

# Function to format minutes into a readable string
function Format-Minutes {
    param([int]$Minutes)
    if ($Minutes -eq 0) { return "Never" }
    if ($Minutes -ge 1440) { 
        $hours = [math]::Round($Minutes / 60)
        return "$hours hours" 
    }
    if ($Minutes -ge 60) { 
        $hours = [math]::Round($Minutes / 60)
        return "$hours hours" 
    }
    return "$Minutes minutes"
}

function Get-PowerSettings {
    Write-Host "Retrieving current power settings..." -ForegroundColor Cyan
    Write-Debug "Starting power settings retrieval"
    
    # Get current power scheme info
    $powerSchemeInfo = powercfg /getactivescheme
    Write-Debug "Raw power scheme info: $powerSchemeInfo"
    
    if ([string]::IsNullOrWhiteSpace($powerSchemeInfo)) {
        Write-Warning "Could not retrieve power scheme information"
        return $null
    }
    $schemeName = if ($powerSchemeInfo -match '\(.*\)') { ($powerSchemeInfo -split '\(')[0].Trim() } else { $powerSchemeInfo.Trim() }
    $schemeGuid = ($powerSchemeInfo -split " " | Where-Object { $_ -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$' })
    
    if (-not $schemeGuid) {
        Write-Warning "Could not determine active power scheme GUID"
        return $null
    }
    
    # Get all power settings using powercfg /query
    $powerSettings = powercfg /query $schemeGuid
    if ([string]::IsNullOrWhiteSpace($powerSettings)) {
        Write-Warning "Could not retrieve power settings"
        return $null
    }
    
    Write-Debug "Raw power settings output:"
    $powerSettings | Out-String | Write-Debug

    # Initialize timeout variables
    $monitorTimeoutAC = "0"
    $monitorTimeoutDC = "0"
    $sleepTimeoutAC = "0"
    $sleepTimeoutDC = "0"
    $hibernateTimeoutAC = "0"
    $hibernateTimeoutDC = "0"
    
    # Split the output into blocks for better parsing
    $powerSettingsLines = $powerSettings -split "`r`n"
    
    # Parse monitor timeout settings
    $inDisplaySection = $false
    $inSleepSection = $false
    $inHibernateSection = $false
    
    for ($i = 0; $i -lt $powerSettingsLines.Count; $i++) {
        $line = $powerSettingsLines[$i]
        
        # Check for display section
        if ($line -match "Turn off display after") {
            Write-Debug "Found display section at line $i"
            $inDisplaySection = $true
            $inSleepSection = $false
            $inHibernateSection = $false
            continue
        }
        
        # Check for sleep section
        if ($line -match "Sleep after") {
            Write-Debug "Found sleep section at line $i"
            $inDisplaySection = $false
            $inSleepSection = $true
            $inHibernateSection = $false
            continue
        }
        
        # Check for hibernate section
        if ($line -match "Hibernate after") {
            Write-Debug "Found hibernate section at line $i"
            $inDisplaySection = $false
            $inSleepSection = $false
            $inHibernateSection = $true
            continue
        }
        
        # Parse values for the identified section
        if ($inDisplaySection) {
            if ($line -match "Current AC Power Setting Index: (0x[0-9a-fA-F]+)") {
                $monitorTimeoutAC = $matches[1]
                Write-Debug "Found AC monitor timeout: $monitorTimeoutAC"
            }
            if ($line -match "Current DC Power Setting Index: (0x[0-9a-fA-F]+)") {
                $monitorTimeoutDC = $matches[1]
                Write-Debug "Found DC monitor timeout: $monitorTimeoutDC"
            }
        }
        
        if ($inSleepSection) {
            if ($line -match "Current AC Power Setting Index: (0x[0-9a-fA-F]+)") {
                $sleepTimeoutAC = $matches[1]
                Write-Debug "Found AC sleep timeout: $sleepTimeoutAC"
            }
            if ($line -match "Current DC Power Setting Index: (0x[0-9a-fA-F]+)") {
                $sleepTimeoutDC = $matches[1]
                Write-Debug "Found DC sleep timeout: $sleepTimeoutDC"
            }
        }
        
        if ($inHibernateSection) {
            if ($line -match "Current AC Power Setting Index: (0x[0-9a-fA-F]+)") {
                $hibernateTimeoutAC = $matches[1]
                Write-Debug "Found AC hibernate timeout: $hibernateTimeoutAC"
            }
            if ($line -match "Current DC Power Setting Index: (0x[0-9a-fA-F]+)") {
                $hibernateTimeoutDC = $matches[1]
                Write-Debug "Found DC hibernate timeout: $hibernateTimeoutDC"
            }
        }
        
        # Reset section flags when we encounter a new GUID (indicates a new section)
        if ($line -match "^  Subgroup GUID:" || $line -match "^Power Scheme GUID:") {
            $inDisplaySection = $false
            $inSleepSection = $false
            $inHibernateSection = $false
        }
    }
    
    # Screen saver settings from registry
    $screenSaverTimeout = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeout" -ErrorAction SilentlyContinue
    
    # Convert and log all power settings
    Write-Debug "Converting power settings from hex to decimal..."
    
    $convertedSettings = @{
        PowerPlanName = $schemeName
        PowerPlanGuid = $schemeGuid
    }
    
    # Monitor AC
    Write-Debug "Converting Monitor AC timeout..."
    Write-Debug "Raw Monitor AC value: $monitorTimeoutAC"
    if ($monitorTimeoutAC -match '0x([0-9a-fA-F]+)') {
        $convertedSettings.MonitorAC = [Convert]::ToInt32($matches[1], 16) / 60 # Convert seconds to minutes
        Write-Debug "Converted Monitor AC value: $($convertedSettings.MonitorAC)"
    } else {
        $convertedSettings.MonitorAC = 0
        Write-Debug "Invalid Monitor AC value, using default: 0"
    }
    
    # Monitor DC
    Write-Debug "Converting Monitor DC timeout..."
    Write-Debug "Raw Monitor DC value: $monitorTimeoutDC"
    if ($monitorTimeoutDC -match '0x([0-9a-fA-F]+)') {
        $convertedSettings.MonitorDC = [Convert]::ToInt32($matches[1], 16) / 60 # Convert seconds to minutes
        Write-Debug "Converted Monitor DC value: $($convertedSettings.MonitorDC)"
    } else {
        $convertedSettings.MonitorDC = 0
        Write-Debug "Invalid Monitor DC value, using default: 0"
    }
    
    # Sleep AC
    Write-Debug "Converting Sleep AC timeout..."
    Write-Debug "Raw Sleep AC value: $sleepTimeoutAC"
    if ($sleepTimeoutAC -match '0x([0-9a-fA-F]+)') {
        $convertedSettings.SleepAC = [Convert]::ToInt32($matches[1], 16) / 60 # Convert seconds to minutes
        Write-Debug "Converted Sleep AC value: $($convertedSettings.SleepAC)"
    } else {
        $convertedSettings.SleepAC = 0
        Write-Debug "Invalid Sleep AC value, using default: 0"
    }
    
    # Sleep DC
    Write-Debug "Converting Sleep DC timeout..."
    Write-Debug "Raw Sleep DC value: $sleepTimeoutDC"
    if ($sleepTimeoutDC -match '0x([0-9a-fA-F]+)') {
        $convertedSettings.SleepDC = [Convert]::ToInt32($matches[1], 16) / 60 # Convert seconds to minutes
        Write-Debug "Converted Sleep DC value: $($convertedSettings.SleepDC)"
    } else {
        $convertedSettings.SleepDC = 0
        Write-Debug "Invalid Sleep DC value, using default: 0"
    }
    
    # Hibernate settings
    if ($hibernateTimeoutAC -match '0x([0-9a-fA-F]+)') {
        $convertedSettings.HibernateAC = [Convert]::ToInt32($matches[1], 16) / 60 # Convert seconds to minutes
    } else {
        $convertedSettings.HibernateAC = 0
    }
    
    if ($hibernateTimeoutDC -match '0x([0-9a-fA-F]+)') {
        $convertedSettings.HibernateDC = [Convert]::ToInt32($matches[1], 16) / 60 # Convert seconds to minutes
    } else {
        $convertedSettings.HibernateDC = 0
    }
    
    # Screen saver
    $convertedSettings.ScreenSaver = if ($screenSaverTimeout.ScreenSaveTimeout) { [int]$screenSaverTimeout.ScreenSaveTimeout / 60 } else { 0 }
    
    Write-Debug "Final converted settings:"
    $convertedSettings | ConvertTo-Json | Write-Debug
    
    return $convertedSettings
}

function Get-LockPolicySettings {    Write-Host "Checking Group Policy and security settings..." -ForegroundColor Cyan
    $settings = [PSCustomObject]@{
        PSTypeName = 'LockPolicySettings'
        ScreenSaverForced = $false
        ScreenSaverSecure = $false
        AutoLockEnabled = $false
        AutoLockTimeout = $null
    }
    
    try {
        # Check screen saver policy settings
        $screenSaverPolicy = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue
        if ($screenSaverPolicy -and $null -ne $screenSaverPolicy.ScreenSaverIsSecure) {
            $settings.ScreenSaverForced = $screenSaverPolicy.ScreenSaverIsSecure -eq 1
        }
  

        # Check workstation lock settings
        $lockSettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        if ($lockSettings) {
            $settings.AutoLockEnabled = $lockSettings.DisableLockWorkstation -ne 1
        }

        # Check machine inactivity limit
        $inactivityLimit = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue
        if ($inactivityLimit) {
            $settings.AutoLockTimeout = [math]::Round($inactivityLimit.InactivityTimeoutSecs / 60)
        }
    }
    catch {
        Write-Warning "Error checking security policies: $_"
    }

    return $settings
}

function Set-PowerTimeout {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [int]$MonitorTimeoutAC,
        [Parameter()]
        [int]$MonitorTimeoutDC,
        [Parameter()]
        [int]$SleepTimeoutAC,
        [Parameter()]
        [int]$SleepTimeoutDC,
        [Parameter()]
        [int]$ScreenSaverTimeout
    )
    
    if ($PSCmdlet.ShouldProcess("Power Settings", "Update inactivity timeouts")) {
        try {
            # Get current power scheme GUID
            $schemeGuid = (powercfg /getactivescheme) -split " " | Where-Object { $_ -match '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$' }
            if (-not $schemeGuid) {
                Write-Warning "Could not determine active power scheme GUID"
                return $false
            }
              # Set monitor timeout (AC and DC)
            if ($PSBoundParameters.ContainsKey('MonitorTimeoutAC')) {
                Write-Host "Setting AC monitor timeout..." -ForegroundColor Cyan
                powercfg /change monitor-timeout-ac $MonitorTimeoutAC
            }
            if ($PSBoundParameters.ContainsKey('MonitorTimeoutDC')) {
                Write-Host "Setting DC monitor timeout..." -ForegroundColor Cyan
                powercfg /change monitor-timeout-dc $MonitorTimeoutDC
            }
            
            # Set sleep timeout (AC and DC)
            if ($PSBoundParameters.ContainsKey('SleepTimeoutAC')) {
                Write-Host "Setting AC sleep timeout..." -ForegroundColor Cyan
                powercfg /change standby-timeout-ac $SleepTimeoutAC
            }
            if ($PSBoundParameters.ContainsKey('SleepTimeoutDC')) {
                Write-Host "Setting DC sleep timeout..." -ForegroundColor Cyan
                powercfg /change standby-timeout-dc $SleepTimeoutDC
            }
            
            # Set screen saver timeout
            if ($PSBoundParameters.ContainsKey('ScreenSaverTimeout')) {
                Write-Host "Setting screen saver timeout..." -ForegroundColor Cyan
                $timeoutSeconds = $ScreenSaverTimeout * 60
                Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeout" -Value $timeoutSeconds
            }
            
            Write-Host "All inactivity timers have been updated successfully!" -ForegroundColor Green
        }
        catch {
            Write-Host "Error setting power settings: $_" -ForegroundColor Red
            return $false
        }
    }
    return $true
}

function Set-LockPolicySettings {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [bool]$ScreenSaverForced,
        [Parameter()]
        [bool]$AutoLockEnabled,
        [Parameter()]
        [int]$AutoLockTimeout
    )
    
    if ($PSCmdlet.ShouldProcess("Group Policy Settings", "Update lock policy settings")) {
        try {
            # Set screen saver security enforcement
            if ($PSBoundParameters.ContainsKey('ScreenSaverForced')) {
                Write-Host "Setting screen saver security enforcement..." -ForegroundColor Cyan
                $regPath = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
                if (!(Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "ScreenSaverIsSecure" -Value ([int]$ScreenSaverForced) -Type DWord
            }

            # Set auto lock settings
            if ($PSBoundParameters.ContainsKey('AutoLockEnabled')) {
                Write-Host "Setting auto lock enabled status..." -ForegroundColor Cyan
                $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
                if (!(Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "DisableLockWorkstation" -Value ([int](!$AutoLockEnabled)) -Type DWord
            }

            # Set auto lock timeout
            if ($PSBoundParameters.ContainsKey('AutoLockTimeout')) {
                Write-Host "Setting auto lock timeout..." -ForegroundColor Cyan
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                if (!(Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "InactivityTimeoutSecs" -Value ($AutoLockTimeout * 60) -Type DWord
            }

            Write-Host "Group Policy settings have been updated successfully!" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "Error setting Group Policy settings: $_" -ForegroundColor Red
            return $false
        }
    }
    return $true
}

# Script scope variable to track transcript status
$script:transcriptActive = $false
$script:logPath = $null

# Function to start transcript safely
function Start-TranscriptSafely {
    if ($DebugPreference -ne 'SilentlyContinue' -and -not $script:transcriptActive) {
        try {
            $script:logPath = Join-Path $PSScriptRoot "Get-SetInactivityTimers_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            Start-Transcript -Path $script:logPath -Force
            $script:transcriptActive = $true
            Write-Debug "Debug logging started. Log file: $script:logPath"
        }
        catch {
            Write-Warning "Failed to start transcript: $_"
        }
    }
}

# Register cleanup for unexpected termination
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    if ($script:transcriptActive) {
        Stop-TranscriptSafely
    }
}

# Main script execution
try {
    Start-TranscriptSafely
    
    # Display WhatIf mode disclaimer if applicable
    if ($WhatIfPreference) {
        Write-Host "`n[WhatIf Mode] This script is running in simulation mode. No actual changes will be made.`n" -ForegroundColor Yellow
    }

    # Get current settings
    $currentSettings = Get-PowerSettings
    $lockSettings = Get-LockPolicySettings
      # Display current settings
    Write-Host "`nPower Plan Information:" -ForegroundColor White
    Write-Host "---------------------" -ForegroundColor White
    Write-Host ("Active Power Plan: {0}" -f $currentSettings.PowerPlanName)
    Write-Host ("Plan GUID: {0}" -f $currentSettings.PowerPlanGuid)

    Write-Host "`nCurrent Inactivity Settings:" -ForegroundColor White
    Write-Host "------------------------" -ForegroundColor White
    Write-Host "`nDisplay Settings:" -ForegroundColor Cyan
    Write-Host ("Monitor Timeout (AC Power): {0}" -f (Format-Minutes $currentSettings.MonitorAC))
    Write-Host ("Monitor Timeout (Battery): {0}" -f (Format-Minutes $currentSettings.MonitorDC))
    
    Write-Host "`nSleep Settings:" -ForegroundColor Cyan
    Write-Host ("Sleep Timer (AC Power): {0}" -f (Format-Minutes $currentSettings.SleepAC))
    Write-Host ("Sleep Timer (Battery): {0}" -f (Format-Minutes $currentSettings.SleepDC))
    Write-Host ("Hibernate Timer (AC Power): {0}" -f (Format-Minutes $currentSettings.HibernateAC))
    Write-Host ("Hibernate Timer (Battery): {0}" -f (Format-Minutes $currentSettings.HibernateDC))
    
    Write-Host "`nScreen Saver:" -ForegroundColor Cyan
    Write-Host ("Screen Saver Timeout: {0}" -f (Format-Minutes $currentSettings.ScreenSaver))

        Write-Host "`nSecurity and Group Policy Settings:" -ForegroundColor White
    Write-Host "--------------------------------" -ForegroundColor White
    Write-Host ("Screen Saver Security Enforced (User cannot remove password requirement when returning from Screen Saver): {0}" -f $(if ($lockSettings.ScreenSaverForced) { "Yes" } else { "No" }))
    Write-Host ("Auto Lock Enabled: {0}" -f $(if ($lockSettings.AutoLockEnabled) { "Yes" } else { "No" }))
    if ($null -ne $lockSettings.AutoLockTimeout) {
        Write-Host ("Auto Lock Timeout: {0}" -f (Format-Minutes $lockSettings.AutoLockTimeout))
    }    # Ask if user wants to change settings
    $response = Read-Host "`nWould you like to change these settings? (Y/N)"
      # Stop transcript before exit if user chooses not to make changes
    if ($response -ne "Y") {
        if ($script:transcriptActive) {
            Stop-TranscriptSafely
            $script:transcriptActive = $false
            Start-Sleep -Seconds 1  # Give the system time to fully release handles
        }
        exit 0
    }
    
    # If continuing, prepare power settings params
    $powerParams = @{}
        
        # Monitor timeout AC
        $userInput = Read-Host "Enter new Monitor Timeout for AC power (current: $(Format-Minutes $currentSettings.MonitorAC)) [Enter to skip]"
        if ($userInput -match '^\d+$') { $powerParams['MonitorTimeoutAC'] = [int]$userInput }
        
        # Monitor timeout DC
        $userInput = Read-Host "Enter new Monitor Timeout for Battery (current: $(Format-Minutes $currentSettings.MonitorDC)) [Enter to skip]"
        if ($userInput -match '^\d+$') { $powerParams['MonitorTimeoutDC'] = [int]$userInput }
        
        # Sleep timeout AC
        $userInput = Read-Host "Enter new Sleep Timeout for AC power (current: $(Format-Minutes $currentSettings.SleepAC)) [Enter to skip]"
        if ($userInput -match '^\d+$') { $powerParams['SleepTimeoutAC'] = [int]$userInput }
        
        # Sleep timeout DC
        $userInput = Read-Host "Enter new Sleep Timeout for Battery (current: $(Format-Minutes $currentSettings.SleepDC)) [Enter to skip]"
        if ($userInput -match '^\d+$') { $powerParams['SleepTimeoutDC'] = [int]$userInput }
        
        # Screen saver timeout
        $userInput = Read-Host "Enter new Screen Saver Timeout (current: $(Format-Minutes $currentSettings.ScreenSaver)) [Enter to skip]"
        if ($userInput -match '^\d+$') { $powerParams['ScreenSaverTimeout'] = [int]$userInput }

        # Group Policy settings params
        $gpoParams = @{}

        # Screen Saver Security Enforcement
        $userInput = Read-Host "Enforce Screen Saver Security? (current: $($lockSettings.ScreenSaverForced)) [Y/N/Enter to skip]"
        if ($userInput -match '^[YN]$') { $gpoParams['ScreenSaverForced'] = ($userInput -eq 'Y') }

        # Auto Lock Enabled
        $userInput = Read-Host "Enable Auto Lock? (current: $($lockSettings.AutoLockEnabled)) [Y/N/Enter to skip]"
        if ($userInput -match '^[YN]$') { $gpoParams['AutoLockEnabled'] = ($userInput -eq 'Y') }

        # Auto Lock Timeout
        if ($gpoParams['AutoLockEnabled'] -or ($lockSettings.AutoLockEnabled -and !$PSBoundParameters.ContainsKey('AutoLockEnabled'))) {
            $userInput = Read-Host "Enter Auto Lock Timeout in minutes (current: $(Format-Minutes $lockSettings.AutoLockTimeout)) [Enter to skip]"
            if ($userInput -match '^\d+$') { $gpoParams['AutoLockTimeout'] = [int]$userInput }
        }
        
        # Apply power settings if any were changed
        if ($powerParams.Count -gt 0) {
            if (Set-PowerTimeout @powerParams) {
                Write-Host "Power settings updated successfully!" -ForegroundColor Green
            }
        }

        # Apply GPO settings if any were changed
        if ($gpoParams.Count -gt 0) {
            if (Set-LockPolicySettings @gpoParams) {
                Write-Host "Group Policy settings updated successfully!" -ForegroundColor Green
            }
        }        if ($powerParams.Count -eq 0 -and $gpoParams.Count -eq 0) {
            Write-Host "No changes were made." -ForegroundColor Cyan
        }
}
catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    exit 1
}
finally {
    # Always stop transcript in finally block if it was started
    if ($script:transcriptActive) {
        Stop-TranscriptSafely
        $script:transcriptActive = $false
        Start-Sleep -Seconds 1  # Give the system time to fully release handles
    }
    
    # Clean up any remaining event subscribers
    Get-EventSubscriber -ErrorAction SilentlyContinue | 
        Where-Object { $_.SourceIdentifier -eq [System.Management.Automation.PsEngineEvent]::Exiting } |
        ForEach-Object { 
            Unregister-Event -SubscriptionId $_.SubscriptionId -ErrorAction SilentlyContinue 
        }
    
    # Force final cleanup
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}
