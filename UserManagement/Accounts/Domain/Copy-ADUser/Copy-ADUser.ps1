# =============================================================================
# Script: Copy-ADUser.ps1
# Created: 2024-02-20 17:15:00 UTC
# Author: maxdaylight
# Last Updated: 2024-02-20 17:30:00 UTC
# Updated By: maxdaylight
# Version: 1.1
# Additional Info: Updated to use parameters instead of hard-coded values
# =============================================================================

<#
.SYNOPSIS
    Copies an existing AD user's group memberships to a new user account.
.DESCRIPTION
    This script creates a new Active Directory user account and copies all group
    memberships from a specified source user. The script:
    - Creates new user with specified properties
    - Copies group memberships from source user
    - Enables the account with a specified password
    Dependencies:
    - Active Directory PowerShell module
    - Domain Admin or appropriate AD delegation rights
.PARAMETER SourceUser
    The username of the existing AD user to copy from
.PARAMETER NewUserName
    The new username to be created
.PARAMETER NewUserGivenName
    The given name for the new user
.PARAMETER NewUserSurname
    The surname for the new user
.PARAMETER NewUserPassword
    The initial password for the new user
.PARAMETER NewUserDescription
    The description for the new user account
.EXAMPLE
    .\Copy-ADUser.ps1 -SourceUser "john.doe" -NewUserName "jane.doe" -NewUserGivenName "Jane" -NewUserSurname "Doe" -NewUserPassword "P@ssw0rd123!" -NewUserDescription "Sales Department"
.NOTES
    Security Level: High
    Required Permissions: Domain Admin or delegated AD user creation rights
    Validation Requirements: Verify source user exists, new username doesn't exist
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SourceUser,
    
    [Parameter(Mandatory = $true)]
    [string]$NewUserName,
    
    [Parameter(Mandatory = $true)]
    [string]$NewUserGivenName,
    
    [Parameter(Mandatory = $true)]
    [string]$NewUserSurname,
    
    [Parameter(Mandatory = $true)]
    [string]$NewUserPassword,
    
    [Parameter(Mandatory = $true)]
    [string]$NewUserDescription
)

# Load the Active Directory module
Import-Module ActiveDirectory

# Verify source user exists
try {
    Write-Host "Verifying source user exists..." -ForegroundColor Cyan
    $sourceUserDetails = Get-ADUser -Identity $SourceUser -Properties * -ErrorAction Stop
} catch {
    Write-Error "Source user '$SourceUser' not found. Please verify the username and try again."
    exit 1
}

# Verify new username doesn't exist
if (Get-ADUser -Filter "SamAccountName -eq '$NewUserName'" -ErrorAction SilentlyContinue) {
    Write-Error "User '$NewUserName' already exists. Please choose a different username."
    exit 1
}

Write-Host "Creating new user account..." -ForegroundColor Cyan

# Create the new user with the different name properties and description
New-ADUser `
    -Name "$NewUserGivenName $NewUserSurname" `
    -GivenName $NewUserGivenName `
    -Surname $NewUserSurname `
    -SamAccountName $NewUserName `
    -UserPrincipalName "$NewUserName@$(($sourceUserDetails.UserPrincipalName).Split('@')[1])" `
    -Path $sourceUserDetails.DistinguishedName `
    -Enabled $true `
    -AccountPassword (ConvertTo-SecureString $NewUserPassword -AsPlainText -Force) `
    -Description $NewUserDescription

# Add the new user to the same groups as the source user
$sourceUserGroups = Get-ADUser -Identity $SourceUser -Properties MemberOf | Select-Object -ExpandProperty MemberOf
foreach ($group in $sourceUserGroups) {
    try {
        Add-ADGroupMember -Identity $group -Members $NewUserName
        Write-Host "Added $NewUserName to group $group" -ForegroundColor Cyan
    } catch {
        Write-Warning "Failed to add user to group $group"
    }
}

Write-Host "New user $NewUserName created successfully!" -ForegroundColor Green
Write-Host "Group memberships copied from $SourceUser" -ForegroundColor Green
