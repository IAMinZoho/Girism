<#
.SYNOPSIS
    A self-contained script to monitor the health of the Windows Security log.
    It creates a temporary user, grants necessary logon rights, generates security events every 10 seconds,
    and checks if the events are logged.
.DESCRIPTION
    This script provides a robust way to verify that the Security event
    log is functioning correctly by creating a temporary user, granting
    necessary logon rights, generating periodic security events, and validating their presence.
    1. It creates a temporary, low-privilege local user named 'SecDetective'.
    2. It grants the user the 'Allow log on locally' and 'Allow log on through Remote Desktop Services' rights.
    3. It generates security events every 10 seconds by toggling group membership.
    4. It checks if the events are logged in the Security Log; if not, it shows warnings.
    5. When stopped with CTRL+C, it deletes the user and removes the granted rights.
.NOTES
    Author: Your Name Here
    Date: October 26, 2023
    File: Start-SecurityLogHealthCheck-Final.ps1
    REQUIREMENTS:
    - Must be run in an elevated PowerShell session (Run as Administrator).
    - The "Audit Logon" and "Audit Account Management" policies must be enabled for "Success".
    - For group membership events, "Audit Account Management" must include group changes.
#>
#Requires -RunAsAdministrator
# --- Configuration ---
$DummyUserName = "SecDetective"
$DummyUserDescription = "Temp user for Security Log health monitoring."
$TargetGroup = "Users"  # Local group to toggle membership for security events
$CheckInterval = 10     # Seconds between event generation
$EventCheckTimeout = 8  # Seconds to wait before checking for the event in logs
# --- Script Body ---
# A flag to control the cleanup logic
$cleanupPerformed = $false

try {
    # --- Step 1: Create the Dummy User and Grant ALL Necessary Rights ---
    Write-Host "Phase 1: Setup" -ForegroundColor Cyan
    Write-Host "The following Security Events will be generated during this phase:" -ForegroundColor Yellow
    Write-Host "  - Event ID 4720: A user account was created" -ForegroundColor White
    Write-Host "  - Event ID 4703: A user right was assigned (SeInteractiveLogonRight)" -ForegroundColor White
    Write-Host "  - Event ID 4703: A user right was assigned (SeRemoteInteractiveLogonRight)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Checking for existing user '$DummyUserName'..."
    if (Get-LocalUser -Name $DummyUserName -ErrorAction SilentlyContinue) {
        Write-Warning "User '$DummyUserName' already exists. Deleting it and its configuration before proceeding."
        Remove-LocalUser -Name $DummyUserName -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    Write-Host "Creating temporary user '$DummyUserName'..."
    $PasswordLength = 16
    $Chars = 'abcdefghkmnprstuvwxyzABCDEFGHKLMNPRSTUVWXYZ23456789!$%&?#@'
    $DummyUserPassword = -join ($Chars | Get-Random -Count $PasswordLength)
    $securePassword = ConvertTo-SecureString $DummyUserPassword -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($DummyUserName, $securePassword)
    New-LocalUser -Name $DummyUserName -Password $securePassword -FullName $DummyUserName -Description $DummyUserDescription
    Write-Host "User '$DummyUserName' created successfully." -ForegroundColor Green

    # Get the user's SID for the secedit commands
    $sid = (New-Object System.Security.Principal.NTAccount($DummyUserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    Write-Host "Granting necessary user rights to '$DummyUserName'..."
    # --- Grant "Allow log on locally" (SeInteractiveLogonRight) ---
    secedit /export /cfg C:\secpol.cfg /quiet
    (Get-Content C:\secpol.cfg) -replace "^SeInteractiveLogonRight = .*", "SeInteractiveLogonRight = $sid," | Set-Content C:\secpol.cfg
    secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS /quiet
    Write-Host "Successfully granted 'Allow log on locally' right." -ForegroundColor Green

    # --- Grant "Allow log on through Remote Desktop Services" (SeRemoteInteractiveLogonRight) ---
    secedit /export /cfg C:\secpol.cfg /quiet
    (Get-Content C:\secpol.cfg) -replace "^SeRemoteInteractiveLogonRight = .*", "SeRemoteInteractiveLogonRight = $sid," | Set-Content C:\secpol.cfg
    secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS /quiet
    Write-Host "Successfully granted 'Allow log on through Remote Desktop Services' right." -ForegroundColor Green
   
    Remove-Item -Path "C:\secpol.cfg" -Force
    Write-Host "Setup complete." -ForegroundColor Green
    Write-Host "`nPhase 2: Generating security events every 10 seconds..." -ForegroundColor Cyan
    Write-Host "The following Security Events will be generated periodically:" -ForegroundColor Yellow
    Write-Host "  - Event ID 4732: A member was added to a security-enabled local group" -ForegroundColor White
    Write-Host "  - Event ID 4733: A member was removed from a security-enabled local group" -ForegroundColor White
    Write-Host "  - Event ID 4799 (optional): Additional related event may appear" -ForegroundColor White
    Write-Host "Press CTRL+C to clean up and exit." -ForegroundColor Red

    # Check if the Windows Event Log service is running
    $eventLogService = Get-Service -Name "EventLog" -ErrorAction SilentlyContinue
    if ($eventLogService.Status -ne "Running") {
        Write-Warning "Windows Event Log service is not running. Security events will not be logged. Please start the service."
    }

    # Loop to generate security events every 10 seconds by toggling group membership
    $toggleState = $false
    while ($true) {
        Write-Host "Generating a security event at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')..." -ForegroundColor Yellow
        $expectedEventID = if ($toggleState) { 4733 } else { 4732 }
        if ($toggleState) {
            Remove-LocalGroupMember -Group $TargetGroup -Member $DummyUserName -ErrorAction SilentlyContinue
            Write-Host "Removed '$DummyUserName' from '$TargetGroup' group (Event ID 4733 expected)." -ForegroundColor Green
        } else {
            Add-LocalGroupMember -Group $TargetGroup -Member $DummyUserName -ErrorAction SilentlyContinue
            Write-Host "Added '$DummyUserName' to '$TargetGroup' group (Event ID 4732 expected)." -ForegroundColor Green
        }
        $toggleState = -not $toggleState

        # Check if the security event was logged
        Write-Host "Checking Security Log for Event ID $expectedEventID..." -ForegroundColor Yellow
        Start-Sleep -Seconds $EventCheckTimeout  # Wait a few seconds for the event to be logged
        try {
            $recentEvent = Get-WinEvent -LogName "Security" -MaxEvents 50 -ErrorAction Stop |
                Where-Object { $_.Id -eq $expectedEventID -and $_.TimeCreated -ge (Get-Date).AddSeconds(-15) }
            if ($recentEvent) {
                Write-Host "Success: Event ID $expectedEventID found in Security Log at $($recentEvent.TimeCreated)." -ForegroundColor Green
            } else {
                Write-Warning "Failure: Event ID $expectedEventID not found in Security Log. Possible issues:"
                Write-Warning "  - Security auditing for 'Account Management' may not be enabled."
                Write-Warning "  - Windows Event Log service may be stopped or malfunctioning."
                Write-Warning "  - Security Log may be full or inaccessible."
                Write-Warning "  - Event may have been delayed or filtered out of the recent log entries."
            }
        } catch {
            Write-Error "Error accessing Security Log: $_"
            Write-Warning "Possible issues:"
            Write-Warning "  - Insufficient permissions to read the Security Log."
            Write-Warning "  - Windows Event Log service may be stopped."
        }

        Write-Host "Event check complete. Waiting for $CheckInterval seconds..." -ForegroundColor Green
        Start-Sleep -Seconds $CheckInterval
    }
}
catch {
    Write-Error "An unexpected error occurred: $_"
}
finally {
    # --- Step 3: Cleanup ---
    if (-not $cleanupPerformed) {
        Write-Host "`nPhase 3: Cleanup" -ForegroundColor Cyan
        Write-Host "The following Security Events will be generated during this phase:" -ForegroundColor Yellow
        Write-Host "  - Event ID 4726: A user account was deleted" -ForegroundColor White
        Write-Host "  - Event ID 4729: A security-enabled local group was removed from a security-enabled local group" -ForegroundColor White
        Write-Host ""
        
        Write-Host "Stopping and removing temporary user '$DummyUserName'..."
        # Ensure the user is removed from the group during cleanup
        Remove-LocalGroupMember -Group $TargetGroup -Member $DummyUserName -ErrorAction SilentlyContinue
        $sid = (New-Object System.Security.Principal.NTAccount($DummyUserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        # Remove the user rights we granted
        Write-Host "Removing granted user rights..."
        secedit /export /cfg C:\secpol.cfg /quiet
        (Get-Content C:\secpol.cfg) -replace "$sid,?", "" | Set-Content C:\secpol.cfg
        (Get-Content C:\secpol.cfg) -replace "^SeInteractiveLogonRight = ,", "SeInteractiveLogonRight = " | Set-Content C:\secpol.cfg
        (Get-Content C:\secpol.cfg) -replace "^SeRemoteInteractiveLogonRight = ,", "SeRemoteInteractiveLogonRight = " | Set-Content C:\secpol.cfg
        secedit /configure /db C:\Windows\security\local.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS /quiet
        Remove-Item -Path "C:\secpol.cfg" -Force
        Write-Host "Successfully removed user rights." -ForegroundColor Green

        # Delete the user account
        if (Get-LocalUser -Name $DummyUserName -ErrorAction SilentlyContinue) {
            Remove-LocalUser -Name $DummyUserName -Confirm:$false
            Write-Host "User '$DummyUserName' has been successfully deleted." -ForegroundColor Green
        }
        else {
            Write-Host "User '$DummyUserName' was not found. No deletion necessary." -ForegroundColor White
        }
       
        Write-Host "Cleanup complete. The system has been restored to its original state." -ForegroundColor Green
        $cleanupPerformed = $true
    }
}