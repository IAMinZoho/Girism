# Import necessary modules for GUI and Active Directory
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Check and import required modules with error handling
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
} catch {
    Write-Error "Required modules (ActiveDirectory, GroupPolicy) are not available. Please install RSAT tools."
    return
}

# Define the main function
function Invoke-ScriptSecure {
    <#
    .SYNOPSIS
    ScriptSecure finds misconfigured and dangerous logon scripts.
    .DESCRIPTION
    ScriptSecure searches the NETLOGON share & Group Policy to identify various security issues in logon scripts, including plaintext credentials, dangerous permissions, elevated privileges, malicious code, unsigned scripts, sensitive information, insecure practices, known vulnerable scripts, non-standard locations, unsafe GPO settings, obfuscated code, invalid paths, external resource references, and integration with threat intelligence. It also provides remediation suggestions for identified issues.
    .PARAMETER SaveOutput
    Save the output to a file
    .EXAMPLE
    Invoke-ScriptSecure
    .EXAMPLE
    Invoke-ScriptSecure | Out-File c:\temp\ScriptSecure.txt
    .EXAMPLE
    Invoke-ScriptSecure -SaveOutput $true
    #>
    [CmdletBinding()]
    Param(
        [boolean]$SaveOutput = $false
    )
    
    # Hard-coded VirusTotal API key
    $VTApiKey = "029f77b27ded4b1ce6ac8bb167c7090110d0deecd9ec488d04da43673dc67c04"  # Replace with your actual API key
    
    # Helper function to get logon scripts
    function Get-LogonScripts {
        $Scripts = @()
        $AccessIssues = @()
        
        try {
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        } catch {
            Write-Error "Unable to get current domain: $($_.Exception.Message)"
            return $Scripts, $AccessIssues
        }
        
        $NetlogonPath = "\\$Domain\NETLOGON"
        $SysvolPath = "\\$Domain\SYSVOL\$Domain\Policies"
        
        # Try to access NETLOGON
        try {
            if (Test-Path $NetlogonPath -ErrorAction Stop) {
                $NetlogonScripts = Get-ChildItem -Path $NetlogonPath -Recurse -File -Include *.bat, *.cmd, *.ps1, *.vbs -ErrorAction Stop
                $Scripts += $NetlogonScripts
                Write-Verbose "Found $($NetlogonScripts.Count) scripts in NETLOGON"
            }
        } catch {
            $AccessIssues += [pscustomobject]@{
                Type = 'AccessDenied'
                Path = $NetlogonPath
                Error = $_.Exception.Message
            }
        }
        
        # Try to access SYSVOL
        try {
            if (Test-Path $SysvolPath -ErrorAction Stop) {
                $SysvolScripts = Get-ChildItem -Path $SysvolPath -Recurse -File -Include *.bat, *.cmd, *.ps1, *.vbs -ErrorAction Stop
                $Scripts += $SysvolScripts
                Write-Verbose "Found $($SysvolScripts.Count) scripts in SYSVOL"
            }
        } catch {
            $AccessIssues += [pscustomobject]@{
                Type = 'AccessDenied'
                Path = $SysvolPath
                Error = $_.Exception.Message
            }
        }
        
        return $Scripts, $AccessIssues
    }
    
    # Check for elevated scripts
    function Find-ElevatedScripts {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [array]$LogonScripts
        )
        
        $ElevationPatterns = @(
            'runas',
            'Start-Process.*-Verb.*RunAs',
            'sudo',
            'psexec.*-s',
            'elevate',
            'UAC'
        )
        
        $results = @()
        foreach ($script in $LogonScripts) {
            try {
                $content = Get-Content -Path $script.FullName -Raw -ErrorAction Stop
                foreach ($pattern in $ElevationPatterns) {
                    if ($content -match $pattern) {
                        $results += [pscustomobject]@{
                            Type = 'ElevatedScript'
                            File = $script.FullName
                            Pattern = $pattern
                        }
                    }
                }
            } catch {
                Write-Warning "Could not read script: $($script.FullName) - $($_.Exception.Message)"
            }
        }
        
        return $results
    }
    
    # Check for malicious code
    function Find-MaliciousCode {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [array]$LogonScripts
        )
        
        $MaliciousPatterns = @(
            'Invoke-WebRequest',
            'IEX\s*\(',
            'DownloadString',
            'Invoke-Expression',
            'System\.Net\.WebClient',
            'wget',
            'curl.*-o',
            'bitsadmin.*transfer'
        )
        
        $results = @()
        foreach ($script in $LogonScripts) {
            try {
                $content = Get-Content -Path $script.FullName -Raw -ErrorAction Stop
                foreach ($pattern in $MaliciousPatterns) {
                    if ($content -match $pattern) {
                        $results += [pscustomobject]@{
                            Type = 'MaliciousCode'
                            File = $script.FullName
                            Pattern = $pattern
                        }
                    }
                }
            } catch {
                Write-Warning "Could not read script: $($script.FullName) - $($_.Exception.Message)"
            }
        }
        
        return $results
    }
    
    # Check for unsigned scripts
    function Find-UnsignedScripts {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [array]$LogonScripts
        )
        
        $results = @()
        foreach ($script in $LogonScripts) {
            # Only check PowerShell scripts for signatures
            if ($script.Extension -eq '.ps1') {
                try {
                    $signature = Get-AuthenticodeSignature -FilePath $script.FullName -ErrorAction Stop
                    if ($signature.Status -ne 'Valid') {
                        $results += [pscustomobject]@{
                            Type = 'UnsignedScript'
                            File = $script.FullName
                            Status = $signature.Status.ToString()  # Convert to string
                        }
                    }
                } catch {
                    Write-Warning "Could not check signature for: $($script.FullName) - $($_.Exception.Message)"
                }
            }
        }
        
        return $results
    }
    
    # Check for sensitive information
    function Find-SensitiveInformation {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [array]$LogonScripts
        )
        
        $SensitivePatterns = @(
            'apikey\s*=\s*[''"].*[''"]',
            'token\s*=\s*[''"].*[''"]',
            'password\s*=\s*[''"].*[''"]',
            'secret\s*=\s*[''"].*[''"]',
            'connectionstring.*password',
            'pwd\s*=',
            'pass\s*='
        )
        
        $results = @()
        foreach ($script in $LogonScripts) {
            try {
                $content = Get-Content -Path $script.FullName -Raw -ErrorAction Stop
                foreach ($pattern in $SensitivePatterns) {
                    $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    foreach ($match in $matches) {
                        $results += [pscustomobject]@{
                            Type = 'SensitiveInformation'
                            File = $script.FullName
                            Match = $match.Value.Substring(0, [Math]::Min(50, $match.Value.Length)) + "..."
                        }
                    }
                }
            } catch {
                Write-Warning "Could not read script: $($script.FullName) - $($_.Exception.Message)"
            }
        }
        
        return $results
    }
    
    # Check for insecure practices
    function Find-InsecurePractices {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [array]$LogonScripts
        )
        
        $InsecurePatterns = @(
            'net use .* /user:.*',
            'cmd /c .*',
            'echo.*password',
            'type.*password',
            'reg add.*password'
        )
        
        $results = @()
        foreach ($script in $LogonScripts) {
            try {
                $content = Get-Content -Path $script.FullName -Raw -ErrorAction Stop
                foreach ($pattern in $InsecurePatterns) {
                    if ($content -match $pattern) {
                        $results += [pscustomobject]@{
                            Type = 'InsecurePractice'
                            File = $script.FullName
                            Pattern = $pattern
                        }
                    }
                }
            } catch {
                Write-Warning "Could not read script: $($script.FullName) - $($_.Exception.Message)"
            }
        }
        
        return $results
    }
    
    # Check for known vulnerable scripts
    function Find-KnownVulnerableScripts {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [array]$LogonScripts
        )
        
        $VulnerablePatterns = @(
            'Invoke-Mimikatz',
            'Invoke-Expression.*\$env:',
            'Start-Process.*cmd\.exe.*/c',
            'powershell.*-enc',
            'bypass.*executionpolicy'
        )
        
        $results = @()
        foreach ($script in $LogonScripts) {
            try {
                $content = Get-Content -Path $script.FullName -Raw -ErrorAction Stop
                foreach ($pattern in $VulnerablePatterns) {
                    if ($content -match $pattern) {
                        $results += [pscustomobject]@{
                            Type = 'KnownVulnerableScript'
                            File = $script.FullName
                            Pattern = $pattern
                        }
                    }
                }
            } catch {
                Write-Warning "Could not read script: $($script.FullName) - $($_.Exception.Message)"
            }
        }
        
        return $results
    }
    
    # Check for scripts in non-standard locations
    function Find-NonStandardScriptLocations {
        [CmdletBinding()]
        param()
        
        $results = @()
        try {
            $users = Get-ADUser -Filter 'scriptPath -like "*"' -Properties scriptPath -ErrorAction Stop
            foreach ($user in $users) {
                $scriptPath = $user.scriptPath
                if ($scriptPath -and $scriptPath -like '\\*') {
                    $parts = $scriptPath -split '\\'
                    if ($parts.Count -ge 3) {
                        $share = $parts[2]
                        if ($share -ne 'NETLOGON' -and $share -ne 'SYSVOL') {
                            $results += [pscustomobject]@{
                                Type = 'NonStandardScriptLocation'
                                User = $user.SamAccountName
                                ScriptPath = $scriptPath
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Could not query AD users: $($_.Exception.Message)"
        }
        
        return $results
    }
    
    # Check for unsafe GPO script settings
    function Find-UnsafeGPOScriptSettings {
        [CmdletBinding()]
        param()
        
        $results = @()
        try {
            $GPOs = Get-GPO -All -ErrorAction Stop
            foreach ($GPO in $GPOs) {
                try {
                    $policy = Get-GPRegistryValue -Guid $GPO.Id -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell' -ValueName 'ExecutionPolicy' -ErrorAction SilentlyContinue
                    if ($policy -and $policy.Value -eq 'Unrestricted') {
                        $results += [pscustomobject]@{
                            Type = 'UnsafeGPOScriptSetting'
                            GPO = $GPO.DisplayName
                            Setting = 'ExecutionPolicy = Unrestricted'
                        }
                    }
                } catch {
                    # Silently continue if registry value doesn't exist
                }
            }
        } catch {
            Write-Warning "Could not query GPOs: $($_.Exception.Message)"
        }
        
        return $results
    }
    
    # Function to check for threat intelligence
    function Invoke-ThreatIntelligenceCheck {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Content,
            [Parameter(Mandatory = $true)]
            [string]$ApiKey
        )
        
        if ([string]::IsNullOrEmpty($ApiKey) -or $ApiKey -eq "your_actual_virustotal_api_key_here") {
            Write-Verbose "No valid VirusTotal API key provided, skipping threat intelligence check"
            return "No API key provided"
        }
        
        try {
            # Compute SHA256 hash of the content
            $hasher = [System.Security.Cryptography.SHA256]::Create()
            $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
            $hashBytes = $hasher.ComputeHash($contentBytes)
            $hash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
            $hasher.Dispose()
            
            # Query VirusTotal API
            $uri = "https://www.virustotal.com/api/v3/files/$hash"
            $headers = @{
                "x-apikey" = $ApiKey
            }
            
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 30 -ErrorAction Stop
            
            # Check if the file is flagged as malicious
            if ($response.data.attributes.last_analysis_stats.malicious -gt 0) {
                return "Threat detected: $($response.data.attributes.last_analysis_stats.malicious) engines flagged this as malicious"
            } else {
                return "No threat detected"
            }
        } catch {
            Write-Verbose "Error querying VirusTotal: $($_.Exception.Message)"
            return "Error querying VirusTotal: $($_.Exception.Message)"
        }
    }
    
    # Function to detect obfuscated code
    function Find-ObfuscatedScripts {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [array]$LogonScripts
        )
        
        $ObfuscationPatterns = @(
            'FromBase64String',
            'Invoke-Expression',
            'IEX\s*\(',
            'EncodedCommand',
            '-enc\s+',
            'Convert.*FromBase64',
            'System\.Convert::FromBase64String'
        )
        
        $results = @()
        foreach ($script in $LogonScripts) {
            try {
                $content = Get-Content -Path $script.FullName -Raw -ErrorAction Stop
                foreach ($pattern in $ObfuscationPatterns) {
                    if ($content -match $pattern) {
                        $results += [pscustomobject]@{
                            Type = 'ObfuscatedCode'
                            File = $script.FullName
                            Pattern = $pattern
                        }
                    }
                }
            } catch {
                Write-Warning "Could not read script: $($script.FullName) - $($_.Exception.Message)"
            }
        }
        
        return $results
    }
    
    # Function to validate script paths
    function Validate-ScriptPaths {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [array]$LogonScripts
        )
        
        $results = @()
        foreach ($script in $LogonScripts) {
            try {
                $content = Get-Content -Path $script.FullName -Raw -ErrorAction Stop
                $paths = [regex]::Matches($content, '\\\\[\w\.\-]+\\[\w\-_\\.\\]+')
                foreach ($path in $paths) {
                    if (-not (Test-Path $path.Value -ErrorAction SilentlyContinue)) {
                        $results += [pscustomobject]@{
                            Type = 'InvalidPath'
                            File = $script.FullName
                            Path = $path.Value
                        }
                    }
                }
            } catch {
                Write-Warning "Could not read script: $($script.FullName) - $($_.Exception.Message)"
            }
        }
        
        return $results
    }
    
    # Function to check for external resource references
    function Find-ExternalResourceReferences {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [array]$LogonScripts
        )
        
        $ExternalPatterns = @(
            'https?://[^\s]+',
            'ftp://[^\s]+',
            '\b(?:\d{1,3}\.){3}\d{1,3}\b'
        )
        
        $results = @()
        foreach ($script in $LogonScripts) {
            try {
                $content = Get-Content -Path $script.FullName -Raw -ErrorAction Stop
                foreach ($pattern in $ExternalPatterns) {
                    $matches = [regex]::Matches($content, $pattern)
                    foreach ($match in $matches) {
                        $results += [pscustomobject]@{
                            Type = 'ExternalResource'
                            File = $script.FullName
                            Reference = $match.Value
                        }
                    }
                }
            } catch {
                Write-Warning "Could not read script: $($script.FullName) - $($_.Exception.Message)"
            }
        }
        
        return $results
    }
    
    # Function to provide remediation suggestions
    function Get-RemediationSuggestions {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$IssueType
        )
        
        $RemediationTable = @{
            'ElevatedScript' = 'Ensure scripts do not run with unnecessary elevated privileges. Use least privilege principles.'
            'MaliciousCode' = 'Remove or replace malicious code patterns. Use trusted code only.'
            'UnsignedScript' = 'Sign scripts with a trusted certificate to ensure integrity.'
            'SensitiveInformation' = 'Remove hardcoded sensitive information. Use secure storage or credential prompts.'
            'InsecurePractice' = 'Avoid insecure commands like net use with credentials or cmd /c. Use secure alternatives.'
            'KnownVulnerableScript' = 'Update or remove scripts with known vulnerabilities. Apply patches or use secure versions.'
            'NonStandardScriptLocation' = 'Move scripts to standard locations like NETLOGON or SYSVOL for better management and security.'
            'UnsafeGPOScriptSetting' = 'Set PowerShell execution policy to a more restrictive setting like RemoteSigned or AllSigned.'
            'ObfuscatedCode' = 'Review and deobfuscate the script to ensure it does not contain malicious code. Consider replacing with clear, readable code.'
            'InvalidPath' = 'Verify and correct the invalid path in the script. Ensure the path exists and is accessible.'
            'ExternalResource' = 'Validate the necessity of external resources. Use trusted sources or replace with local alternatives if possible.'
            'ThreatDetected' = 'Quarantine the script and investigate the threat. Remove or replace the malicious content.'
            'AccessDenied' = 'Grant the account running the script read permissions to the affected path (e.g., SYSVOL or NETLOGON). Verify NTFS and share permissions.'
        }
        
        return $RemediationTable[$IssueType]
    }
    
    # Here is the updated section of your code.
# The changes are within the "Show-Results" function and the main execution block.

# Enhanced function to show results in a professional GUI
function Show-Results {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results
    )
    
    # Group results by type for subheadings
    $groupedResults = $Results | Group-Object -Property Type
    
    # Create main form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'ScriptSecure Analysis Results'
    $form.Size = New-Object System.Drawing.Size(1200, 900)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    
    # Use TableLayoutPanel for a more organized layout
    $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $mainLayout.Dock = 'Fill'
    $mainLayout.ColumnCount = 1
    $mainLayout.RowCount = 4  # Header, Filter, ListView, Footer
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 120))) | Out-Null # Header (increased for subheadings)
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 40))) | Out-Null # Filter
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null # ListView
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 50))) | Out-Null # Footer
    
    # Header panel
    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Dock = 'Fill'
    $headerPanel.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    
    # Title label
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = 'ScriptSecure Analysis Report'
    $titleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
    $titleLabel.ForeColor = [System.Drawing.Color]::White
    $titleLabel.AutoSize = $true
    $titleLabel.Location = New-Object System.Drawing.Point(20, 15)
    $headerPanel.Controls.Add($titleLabel) | Out-Null
    
    # Subtitle label - shows total issues
    $subtitleLabel = New-Object System.Windows.Forms.Label
    $subtitleLabel.Text = "Total Issues Found: $($Results.Count)"
    $subtitleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $subtitleLabel.ForeColor = [System.Drawing.Color]::Orange
    $subtitleLabel.AutoSize = $true
    $subtitleLabel.Location = New-Object System.Drawing.Point(25, 45)
    $headerPanel.Controls.Add($subtitleLabel) | Out-Null
    
    # Issue breakdown - show counts by type as subheadings
    $yPos = 70
    $xPos = 25
    foreach ($group in $groupedResults) {
        $issueLabel = New-Object System.Windows.Forms.Label
        $issueLabel.Text = "$($group.Name): $($group.Count)"
        $issueLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        $issueLabel.ForeColor = [System.Drawing.Color]::LightGray
        $issueLabel.AutoSize = $true
        $issueLabel.Location = New-Object System.Drawing.Point($xPos, $yPos)
        $headerPanel.Controls.Add($issueLabel) | Out-Null
        
        # Move to next position (wrap to next line if needed)
        $xPos += 200
        if ($xPos -gt 1000) {
            $xPos = 25
            $yPos += 20
        }
    }
    
    # Filter panel
    $filterPanel = New-Object System.Windows.Forms.Panel
    $filterPanel.Dock = 'Fill'
    $filterPanel.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    
    # Filter label
    $filterLabel = New-Object System.Windows.Forms.Label
    $filterLabel.Text = 'Filter by type:'
    $filterLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $filterLabel.AutoSize = $true
    $filterLabel.Location = New-Object System.Drawing.Point(10, 12)
    $filterPanel.Controls.Add($filterLabel) | Out-Null
    
    # Filter combobox
    $filterComboBox = New-Object System.Windows.Forms.ComboBox
    $filterComboBox.Width = 200
    $filterComboBox.Location = New-Object System.Drawing.Point(90, 10)
    
    # Get unique issue types
    $issueTypes = $Results | Select-Object -ExpandProperty Type -Unique | Sort-Object
    $filterComboBox.Items.Add('All Issues') | Out-Null
    foreach ($type in $issueTypes) {
        $filterComboBox.Items.Add($type) | Out-Null
    }
    $filterComboBox.SelectedIndex = 0
    $filterPanel.Controls.Add($filterComboBox) | Out-Null
    
    # Export button
    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Text = 'Export Results'
    $exportButton.Width = 120
    $exportButton.Location = New-Object System.Drawing.Point(1050, 10)
    $exportButton.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $exportButton.ForeColor = [System.Drawing.Color]::White
    $exportButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $filterPanel.Controls.Add($exportButton) | Out-Null
    
    # ListView
    $listView = New-Object System.Windows.Forms.ListView
    $listView.Dock = 'Fill'
    $listView.View = 'Details'
    $listView.FullRowSelect = $true
    $listView.GridLines = $true
    $listView.MultiSelect = $false
    $listView.Columns.Add('Type', 150) | Out-Null
    $listView.Columns.Add('File/Path', 350) | Out-Null
    $listView.Columns.Add('Details', 250) | Out-Null
    $listView.Columns.Add('Remediation', 400) | Out-Null
    
    # Footer panel
    $footerPanel = New-Object System.Windows.Forms.Panel
    $footerPanel.Dock = 'Fill'
    $footerPanel.Height = 50
    
    # Close button
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = 'Close'
    $closeButton.Width = 100
    $closeButton.Height = 30
    $closeButton.Location = New-Object System.Drawing.Point(1080, 10)
    $closeButton.BackColor = [System.Drawing.Color]::FromArgb(200, 50, 50)
    $closeButton.ForeColor = [System.Drawing.Color]::White
    $closeButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $closeButton.Add_Click({ $form.Close() })
    $footerPanel.Controls.Add($closeButton) | Out-Null
    
    # Add controls to the layout panel
    $mainLayout.Controls.Add($headerPanel, 0, 0) | Out-Null
    $mainLayout.Controls.Add($filterPanel, 0, 1) | Out-Null
    $mainLayout.Controls.Add($listView, 0, 2) | Out-Null
    $mainLayout.Controls.Add($footerPanel, 0, 3) | Out-Null
    
    # Add the layout panel to the form
    $form.Controls.Add($mainLayout) | Out-Null
    
    # Store original results for filtering
    $originalResults = $Results
    
    # Function to populate the ListView with results
    function Populate-ListView {
        param(
            [array]$itemsToDisplay
        )
        
        $listView.Items.Clear()
        
        foreach ($result in $itemsToDisplay) {
            $item = New-Object System.Windows.Forms.ListViewItem($result.Type)
            
            # Handle different property names for file/path
            $fileOrPath = ""
            if ($result.File) { $fileOrPath = $result.File }
            elseif ($result.Path) { $fileOrPath = $result.Path }
            elseif ($result.ScriptPath) { $fileOrPath = $result.ScriptPath }
            elseif ($result.User) { $fileOrPath = $result.User }
            elseif ($result.GPO) { $fileOrPath = $result.GPO }
            
            $item.SubItems.Add($fileOrPath) | Out-Null
            
            # Handle different property names for details - Convert all to string
            $details = ""
            if ($result.Pattern) { $details = $result.Pattern.ToString() }
            elseif ($result.Match) { $details = $result.Match.ToString() }
            elseif ($result.Reference) { $details = $result.Reference.ToString() }
            elseif ($result.Threat) { $details = $result.Threat.ToString() }
            elseif ($result.Error) { $details = $result.Error.ToString() }
            elseif ($result.Setting) { $details = $result.Setting.ToString() }
            elseif ($result.Status) { $details = $result.Status.ToString() }
            
            $item.SubItems.Add($details) | Out-Null
            $item.SubItems.Add($result.Remediation.ToString()) | Out-Null
            $listView.Items.Add($item) | Out-Null
        }
    }
    
    # Initial population of ListView
    Populate-ListView -itemsToDisplay $originalResults
    
    # Filter functionality
    $filterComboBox.Add_SelectedIndexChanged({
        $selectedType = $filterComboBox.SelectedItem
        
        if ($selectedType -eq 'All Issues') {
            Populate-ListView -itemsToDisplay $originalResults
        } else {
            $filteredResults = $originalResults | Where-Object { $_.Type -eq $selectedType }
            Populate-ListView -itemsToDisplay $filteredResults
        }
    })
    
    # Export functionality
    # Export functionality
$exportButton.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "CSV files (*.csv)|*.csv|Text files (*.txt)|*.txt|All files (*.*)|*.*"
    $saveFileDialog.Title = "Export Results"
    $saveFileDialog.FileName = "ScriptSecure_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $exportPath = $saveFileDialog.FileName
            
            # Use the original, unfiltered results for the export
            $resultsToExport = $originalResults
            
            # The original script had logic for CSV vs TXT, which is good.
            # We will use this to ensure the correct export method.
            if ([System.IO.Path]::GetExtension($exportPath) -eq ".csv") {
                # Export the full results array to a CSV
                $resultsToExport | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
            }
            else {
                # This part is for text export, which is a good feature to keep.
                $textOutput = @()
                $textOutput += "ScriptSecure Security Analysis Report"
                $textOutput += "Generated: $(Get-Date)"
                $textOutput += "Total Issues Found: $($resultsToExport.Count)"
                $textOutput += "=" * 80
                $textOutput += ""
                
                $groupedResults = $resultsToExport | Group-Object -Property Type
                
                foreach ($group in $groupedResults) {
                    $textOutput += "$($group.Name) Issues: $($group.Count)"
                    $textOutput += "-" * 40
                    
                    foreach ($result in $group.Group) {
                        # Logic to format the output for a text file
                        $fileOrPath = ""
                        if ($result.File) { $fileOrPath = $result.File }
                        elseif ($result.Path) { $fileOrPath = $result.Path }
                        elseif ($result.ScriptPath) { $fileOrPath = $result.ScriptPath }
                        elseif ($result.User) { $fileOrPath = $result.User }
                        elseif ($result.GPO) { $fileOrPath = $result.GPO }
                        
                        $details = ""
                        if ($result.Pattern) { $details = $result.Pattern.ToString() }
                        elseif ($result.Match) { $details = $result.Match.ToString() }
                        elseif ($result.Reference) { $details = $result.Reference.ToString() }
                        elseif ($result.Threat) { $details = $result.Threat.ToString() }
                        elseif ($result.Error) { $details = $result.Error.ToString() }
                        elseif ($result.Setting) { $details = $result.Setting.ToString() }
                        elseif ($result.Status) { $details = $result.Status.ToString() }
                        
                        $textOutput += "File/Path: $fileOrPath"
                        $textOutput += "Details: $details"
                        $textOutput += "Remediation: $($result.Remediation)"
                        $textOutput += ""
                    }
                    $textOutput += ""
                }
                $textOutput | Out-File -FilePath $exportPath -Encoding UTF8
            }
            
            [System.Windows.Forms.MessageBox]::Show("Results exported successfully to: $exportPath", "Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error exporting results: $($_.Exception.Message)", "Export Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    }
})
    
    # Show the form
    $form.ShowDialog() | Out-Null
}

# Main execution starts here
Write-Host "[+] Starting ScriptSecure Analysis..." -ForegroundColor Green
Write-Host "[*] Scanning for logon scripts and security issues..." -ForegroundColor Yellow

# Initialize results array
$AllResults = @()

# Get logon scripts and access issues
Write-Host "[*] Retrieving logon scripts..." -ForegroundColor Cyan
$LogonScripts, $AccessIssues = Get-LogonScripts

# Add access issues to results
foreach ($issue in $AccessIssues) {
    $issue | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $issue.Type)
    $AllResults += $issue
}

if ($LogonScripts.Count -eq 0) {
    Write-Host "[!] No logon scripts found or accessible." -ForegroundColor Yellow
} else {
    Write-Host "[+] Found $($LogonScripts.Count) logon scripts to analyze." -ForegroundColor Green
    
    # Run all security checks
    Write-Host "[*] Checking for elevated scripts..." -ForegroundColor Cyan
    $ElevatedScripts = Find-ElevatedScripts -LogonScripts $LogonScripts
    foreach ($result in $ElevatedScripts) {
        $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
        $AllResults += $result
    }
    
    Write-Host "[*] Checking for malicious code patterns..." -ForegroundColor Cyan
    $MaliciousCode = Find-MaliciousCode -LogonScripts $LogonScripts
    foreach ($result in $MaliciousCode) {
        $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
        $AllResults += $result
    }
    
    Write-Host "[*] Checking for unsigned scripts..." -ForegroundColor Cyan
    $UnsignedScripts = Find-UnsignedScripts -LogonScripts $LogonScripts
    foreach ($result in $UnsignedScripts) {
        $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
        $AllResults += $result
    }
    
    Write-Host "[*] Checking for sensitive information..." -ForegroundColor Cyan
    $SensitiveInfo = Find-SensitiveInformation -LogonScripts $LogonScripts
    foreach ($result in $SensitiveInfo) {
        $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
        $AllResults += $result
    }
    
    Write-Host "[*] Checking for insecure practices..." -ForegroundColor Cyan
    $InsecurePractices = Find-InsecurePractices -LogonScripts $LogonScripts
    foreach ($result in $InsecurePractices) {
        $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
        $AllResults += $result
    }
    
    Write-Host "[*] Checking for known vulnerable scripts..." -ForegroundColor Cyan
    $VulnerableScripts = Find-KnownVulnerableScripts -LogonScripts $LogonScripts
    foreach ($result in $VulnerableScripts) {
        $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
        $AllResults += $result
    }
    
    Write-Host "[*] Checking for obfuscated code..." -ForegroundColor Cyan
    $ObfuscatedScripts = Find-ObfuscatedScripts -LogonScripts $LogonScripts
    foreach ($result in $ObfuscatedScripts) {
        $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
        $AllResults += $result
    }
    
    Write-Host "[*] Validating script paths..." -ForegroundColor Cyan
    $InvalidPaths = Validate-ScriptPaths -LogonScripts $LogonScripts
    foreach ($result in $InvalidPaths) {
        $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
        $AllResults += $result
    }
    
    Write-Host "[*] Checking for external resource references..." -ForegroundColor Cyan
    $ExternalResources = Find-ExternalResourceReferences -LogonScripts $LogonScripts
    foreach ($result in $ExternalResources) {
        $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
        $AllResults += $result
    }
    
    # Threat intelligence check (if API key is provided)
    if ($VTApiKey -ne "your_actual_virustotal_api_key_here" -and -not [string]::IsNullOrEmpty($VTApiKey)) {
        Write-Host "[*] Running threat intelligence checks..." -ForegroundColor Cyan
        foreach ($script in $LogonScripts) {
            try {
                $content = Get-Content -Path $script.FullName -Raw -ErrorAction Stop
                $threatResult = Invoke-ThreatIntelligenceCheck -Content $content -ApiKey $VTApiKey
                
                if ($threatResult -like "*Threat detected*") {
                    $threatIssue = [pscustomobject]@{
                        Type = 'ThreatDetected'
                        File = $script.FullName
                        Threat = $threatResult
                        Remediation = Get-RemediationSuggestions -IssueType 'ThreatDetected'
                    }
                    $AllResults += $threatIssue
                }
            } catch {
                Write-Warning "Could not perform threat intelligence check on: $($script.FullName) - $($_.Exception.Message)"
            }
        }
    } else {
        Write-Host "[!] Skipping threat intelligence checks (no valid API key provided)" -ForegroundColor Yellow
    }
}

# Check for non-standard script locations
Write-Host "[*] Checking for non-standard script locations..." -ForegroundColor Cyan
$NonStandardLocations = Find-NonStandardScriptLocations
foreach ($result in $NonStandardLocations) {
    $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
    $AllResults += $result
}

# Check for unsafe GPO script settings
Write-Host "[*] Checking for unsafe GPO script settings..." -ForegroundColor Cyan
$UnsafeGPOSettings = Find-UnsafeGPOScriptSettings
foreach ($result in $UnsafeGPOSettings) {
    $result | Add-Member -MemberType NoteProperty -Name 'Remediation' -Value (Get-RemediationSuggestions -IssueType $result.Type)
    $AllResults += $result
}

# Display results
Write-Host "`n[+] Analysis Complete!" -ForegroundColor Green
Write-Host "Total issues found: $($AllResults.Count)" -ForegroundColor $(if ($AllResults.Count -gt 0) { 'Red' } else { 'Green' })

if ($AllResults.Count -gt 0) {
    # Group results by type for summary
    $groupedResults = $AllResults | Group-Object -Property Type
    Write-Host "`nIssue Summary:" -ForegroundColor Yellow
    
    # Create a custom object array for the table
    $summaryTable = @()
    foreach ($group in $groupedResults) {
        $summaryTable += [pscustomobject]@{
            'Issue Type' = $group.Name
            'Count' = $group.Count
        }
    }
    
    # Format the summary as a table for professional output
    $summaryTable | Format-Table -AutoSize
    
    # Show GUI results
    Show-Results -Results $AllResults
    
    # Save output if requested
    if ($SaveOutput) {
        $outputPath = "ScriptSecure_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $AllResults | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n[+] Results saved to: $outputPath" -ForegroundColor Green
    }
    
    # Return results for pipeline usage, but suppress console output
    return $AllResults | Out-Null
} else {
    Write-Host "No security issues found in logon scripts!" -ForegroundColor Green
    
    # Show empty results GUI
    $emptyResult = [pscustomobject]@{
        Type = 'NoIssuesFound'
        File = 'N/A'
        Details = 'No security issues detected'
        Remediation = 'Continue monitoring logon scripts regularly'
    }
    Show-Results -Results @($emptyResult)
    
    # Return empty array, and suppress console output
    return @() | Out-Null
}
}

# If script is run directly (not imported as module), execute the function
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ScriptSecure
}

