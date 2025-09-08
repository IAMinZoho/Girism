<#
.SYNOPSIS
    Performs an advanced in-depth automated security assessment of a Windows client machine.
.DESCRIPTION
    This script evaluates comprehensive security configurations and features on a Windows client,
    focusing on hardening against modern threats like credential theft, privilege escalation,
    malware persistence, and advanced persistent threats. It incorporates checks for NTLM/Kerberos 
    hardening, Defender exploit protections, advanced logging configurations, cloud security 
    integration, hardware security features, and zero-trust validation.
    
    It must be run with administrative privileges for complete results.
    Results are collected and displayed in a summary table at the end and can be exported.
    
    The script's primary goal is to provide a single, actionable report for security teams.
.PARAMETER ExportPath
    Path to export the results file.
.PARAMETER Format
    Export format: CSV, JSON, or HTML.
.PARAMETER SkipCloudChecks
    Skip Azure AD/Entra ID related checks for non-domain joined machines.
.PARAMETER IncludeAdvancedThreatDetection
    Include advanced threat detection and APT indicator checks.
.NOTES
    Author: @dGiri
    Version: 3.1Updated: Complete UI overhaul with historical tracking and professional design.
#>



function Get-SecurityAssessmentReport {

param (
    [string]$ExportPath,
    [ValidateSet("CSV", "JSON", "HTML")][string]$Format = "HTML",
    [switch]$SkipCloudChecks,
    [switch]$IncludeAdvancedThreatDetection
)

$script:results = @()
$script:isElevated = $false
$script:currentCheck = 0
$script:totalChecks = 100
$script:threatIndicators = @()
$script:startTime = Get-Date

function Add-Result {
    param (
        [string]$Category,
        [string]$Subcategory,
        [string]$Result,
        [string]$Remediation = "",
        [string]$RiskLevel = "Medium"
    )
    
    $script:results += [PSCustomObject]@{
        Category     = $Category
        Subcategory  = $Subcategory
        Result       = $Result
        Remediation  = $Remediation
        RiskLevel    = $RiskLevel
        Timestamp    = Get-Date
    }
}

function Add-ThreatIndicator {
    param (
        [string]$Type,
        [string]$Description,
        [string]$Severity,
        [string]$Evidence
    )
    
    $script:threatIndicators += [PSCustomObject]@{
        Type        = $Type
        Description = $Description
        Severity    = $Severity
        Evidence    = $Evidence
        Timestamp   = Get-Date
    }
}

function Get-RegValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    
    try {
        if (-not (Test-Path $Path)) { return $null }
        $value = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        return $value
    }
    catch { return $null }
}

function Get-SecureBootStatus {
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($computerSystem.BootupState -notlike "*UEFI*") {
            return [PSCustomObject]@{
                Status = "Not Supported"
                Message = "System is not running in UEFI mode."
            }
        }
        
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        return [PSCustomObject]@{
            Status = if ($secureBoot) { "Enabled" } else { "Disabled" }
            Message = "Secure Boot check completed successfully."
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        return [PSCustomObject]@{
            Status = "Not Supported"
            Message = "Secure Boot cmdlets are not available on this system."
        }
    }
    catch {
        return [PSCustomObject]@{
            Status = "Error"
            Message = "An unexpected error occurred: $($_.Exception.Message)"
        }
    }
}

function Get-AvStateSummary {
    param([int]$ProductState)
    
    try {
        $on = (($ProductState -band 0x1000) -ne 0)
        $updated = (($ProductState -band 0x10) -eq 0)
        
        if ($on -and $updated) { "On" }
        elseif ($on) { "Outdated" }
        else { "Off" }
    }
    catch { "Unknown" }
}

function Write-StatusMessage {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success", "Critical")]$Type = "Info"
    )
    
    $colors = @{
        "Info" = "Cyan"
        "Warning" = "Yellow"
        "Error" = "Red"
        "Success" = "Green"
        "Critical" = "Magenta"
    }
    
    Write-Host "[$Type] $Message" -ForegroundColor $colors[$Type]
    if ($Type -eq "Info") {
        $script:currentCheck++
        $percent = [Math]::Min(100, ($script:currentCheck / $script:totalChecks) * 100)
        Write-Progress -Activity "Performing Advanced Security Assessment" -Status $Message -PercentComplete $percent
    }
}

function Test-IsElevated {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-DomainJoined {
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        return ($computerSystem.PartOfDomain -eq $true)
    }
    catch { return $false }
}

function Get-AzureADJoinStatus {
    try {
        $dsregcmdExists = Get-Command dsregcmd -ErrorAction SilentlyContinue
        if (-not $dsregcmdExists) { return $null }
        
        $dsregOutput = & dsregcmd /status 2>$null
        if ($dsregOutput) {
            $azureAdJoined = $dsregOutput | Select-String "AzureAdJoined\s*:\s*YES" -Quiet
            $domainJoined = $dsregOutput | Select-String "DomainJoined\s*:\s*YES" -Quiet
            $workplaceJoined = $dsregOutput | Select-String "WorkplaceJoined\s*:\s*YES" -Quiet
            
            return [PSCustomObject]@{
                AzureAdJoined = $azureAdJoined
                DomainJoined = $domainJoined
                WorkplaceJoined = $workplaceJoined
                HybridJoined = ($azureAdJoined -and $domainJoined)
            }
        }
    }
    catch { return $null }
}

function Test-SuspiciousServices {
    try {
        $suspiciousPatterns = @(
            ".*temp.*\.exe",
            ".*\d{8,}\.exe",
            ".*[a-f0-9]{32}.*",
            ".*\\AppData\\.*",
            ".*\\Users\\Public\\.*"
        )
        
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
        $suspiciousServices = @()
        
        foreach ($service in $services) {
            if ($service.PathName) {
                foreach ($pattern in $suspiciousPatterns) {
                    if ($service.PathName -match $pattern -and $service.PathName -notlike "*Windows*") {
                        $suspiciousServices += $service
                        break
                    }
                }
            }
        }
        
        return $suspiciousServices
    }
    catch { return @() }
}

function Test-SuspiciousScheduledTasks {
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        $suspiciousTasks = @()
        
        foreach ($task in $tasks) {
            $isSuspicious = $false
            
            if ($task.TaskPath -like "*Microsoft*" -and 
                ($task.Author -eq "" -or $task.Author -notlike "*Microsoft*")) {
                $isSuspicious = $true
            }
            
            if ($task.Actions -and $task.Actions.Execute -match "Users\\[^\\]+\\AppData") {
                $isSuspicious = $true
            }
            
            if ($task.Actions -and $task.Actions.Execute -match "\.(bat|cmd|ps1|vbs|js)$" -and
                $task.Actions.Execute -notlike "*Windows*") {
                $isSuspicious = $true
            }
            
            if ($isSuspicious) { $suspiciousTasks += $task }
        }
        
        return $suspiciousTasks
    }
    catch { return @() }
}

function Test-WMIPersistence {
    try {
        $wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction Stop
        $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction Stop
        $wmiBindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop
        
        return [PSCustomObject]@{
            EventFilters = $wmiFilters.Count
            EventConsumers = $wmiConsumers.Count
            FilterBindings = $wmiBindings.Count
            HasPersistence = ($wmiFilters.Count -gt 0 -or $wmiConsumers.Count -gt 0 -or $wmiBindings.Count -gt 0)
        }
    }
    catch {
        return [PSCustomObject]@{
            EventFilters = 0
            EventConsumers = 0
            FilterBindings = 0
            HasPersistence = $false
        }
    }
}

function Show-ColoredResults {
    param($Results)
    
    Write-Host "`n=== ADVANCED SECURITY ASSESSMENT RESULTS ===" -ForegroundColor Cyan
    Write-Host ""
    
    $scoreResult = ($Results | Where-Object { $_.Category -eq "Compliance" -and $_.Subcategory -eq "Security Score" })
    if ($scoreResult) {
        $scoreValue = [double]($scoreResult.Result -replace '%', '')
        $scoreColor = switch ($scoreValue) {
            { $_ -ge 90 } { "Green" }
            { $_ -ge 70 } { "Yellow" }
            default { "Red" }
        }
        Write-Host "Overall Security Score: $($scoreResult.Result)" -ForegroundColor $scoreColor
        Write-Host ("-" * 117) -ForegroundColor Gray
    }
    
    if ($script:threatIndicators.Count -gt 0) {
        Write-Host "`n!!! THREAT INDICATORS DETECTED !!!" -ForegroundColor Red -BackgroundColor Yellow
        foreach ($indicator in $script:threatIndicators) {
            Write-Host "[$($indicator.Severity)] $($indicator.Type): $($indicator.Description)" -ForegroundColor Red
        }
        Write-Host ("-" * 117) -ForegroundColor Gray
    }
    
    # Calculate the maximum number of digits needed for serial numbers
    $totalItems = ($Results | Where-Object { $_.Category -ne "Compliance" }).Count
    $maxNumberDigits = [math]::Ceiling([math]::Log10($totalItems + 1))
    $numberColumnWidth = $maxNumberDigits + 2  # +2 for the dot and space (e.g., "100. ")
    
    $colWidths = @{
        Number = $numberColumnWidth
        Subcategory = 40
        Result = 10
        Risk = 12
        Remediation = 50
    }
    
    $totalWidth = $colWidths.Number + $colWidths.Subcategory + $colWidths.Result + $colWidths.Risk + $colWidths.Remediation
    
    $header = "No.".PadRight($colWidths.Number) + 
              "Subcategory".PadRight($colWidths.Subcategory) + 
              "Result".PadRight($colWidths.Result) + 
              "Risk".PadRight($colWidths.Risk) + 
              "Remediation".PadRight($colWidths.Remediation)
    
    Write-Host $header -ForegroundColor Cyan
    Write-Host ("-" * $totalWidth) -ForegroundColor Gray
    
    $i = 1
    $groupedResults = $Results | Where-Object { $_.Category -ne "Compliance" } | Group-Object Category | Sort-Object Name
    
    foreach ($group in $groupedResults) {
        Write-Host "[$($group.Name)]" -ForegroundColor Magenta
        
        foreach ($item in ($group.Group | Sort-Object Subcategory)) {
            $statusColor = switch ($item.Result) {
                "OK" { "Green" }
                "BAD" { "Red" }
                "MAYBE" { "Yellow" }
                "Error" { "Magenta" }
                default { "White" }
            }
            
            $riskColor = switch ($item.RiskLevel) {
                "Critical" { "Red" }
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Green" }
                default { "White" }
            }
            
            # Dynamic number formatting based on total items
            $numberStr = "$i.".PadRight($colWidths.Number)
            
            $subcategoryStr = if ($item.Subcategory.Length -gt $colWidths.Subcategory) { 
                $item.Subcategory.Substring(0, $colWidths.Subcategory - 3) + "..."
            } else { 
                $item.Subcategory 
            }
            $subcategoryStr = $subcategoryStr.PadRight($colWidths.Subcategory)
            
            $resultStr = $item.Result.PadRight($colWidths.Result)
            $riskStr = $item.RiskLevel.PadRight($colWidths.Risk)
            
            $remediationStr = if ($item.Remediation.Length -gt $colWidths.Remediation) {
                $item.Remediation.Substring(0, $colWidths.Remediation - 3) + "..."
            } else {
                $item.Remediation
            }
            
            Write-Host $numberStr -NoNewline -ForegroundColor White
            Write-Host $subcategoryStr -NoNewline -ForegroundColor White
            Write-Host $resultStr -NoNewline -ForegroundColor $statusColor
            Write-Host $riskStr -NoNewline -ForegroundColor $riskColor
            Write-Host $remediationStr -ForegroundColor Gray
            
            $i++
        }
        Write-Host ""
    }
}

function Invoke-AdvancedClientSecurityChecks {
    Write-StatusMessage "Starting Advanced Windows Client Security Assessment..." -Type "Info"
    Write-Host ("=" * 80) -ForegroundColor Gray
    
    $script:isElevated = Test-IsElevated
    
    if ($script:isElevated) {
        Write-StatusMessage "Running with administrative privileges" -Type "Success"
    } else {
        Write-StatusMessage "Running without administrative privileges - some checks will be limited" -Type "Warning"
    }
    
    Add-Result "Elevation" "Admin Rights" $(if ($script:isElevated) { "OK" } else { "BAD" }) "Run as administrator for complete security assessment." "High"
    
    $isDomainJoined = Test-DomainJoined
    $azureStatus = Get-AzureADJoinStatus
    
    Write-StatusMessage "Domain joined: $isDomainJoined" -Type "Info"
    if ($azureStatus) {
        Write-StatusMessage "Azure AD joined: $($azureStatus.AzureAdJoined)" -Type "Info"
        Write-StatusMessage "Hybrid joined: $($azureStatus.HybridJoined)" -Type "Info"
    }
    
    Write-StatusMessage "Checking required modules..." -Type "Info"
    
    $requiredModules = @("ActiveDirectory", "BitLocker", "SpeculationControl", "LAPS", "WindowsDefender", "NetSecurity")
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-StatusMessage "Module '$module' not available" -Type "Warning"
            Add-Result "Dependencies" "Module: $module" "Missing" "Install-Module -Name $module -Force" "Low"
        } else {
            try {
                Import-Module $module -ErrorAction Stop
                Write-StatusMessage "Module '$module' loaded" -Type "Success"
            }
            catch {
                Write-StatusMessage "Failed to load module '$module'" -Type "Warning"
                Add-Result "Dependencies" "Module: $module" "Error" "Module exists but failed to load: $($_.Exception.Message)" "Low"
            }
        }
    }
    
    if ($isDomainJoined) {
        Write-StatusMessage "Evaluating domain password policy..." -Type "Info"
        
        try {
            $defaultPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
            Add-Result "Password Policy" "Complexity" $(if ($defaultPolicy.ComplexityEnabled) { "OK" } else { "BAD" }) "Enable password complexity in domain policy" "High"
            Add-Result "Password Policy" "Lockout Duration" $(if ($defaultPolicy.LockoutDuration.TotalMinutes -gt 14) { "OK" } elseif ($defaultPolicy.LockoutDuration.TotalMinutes -eq 0) { "BAD" } else { "MAYBE" }) "Set lockout duration >14 minutes" "Medium"
            Add-Result "Password Policy" "Lockout Threshold" $(if ($defaultPolicy.LockoutThreshold -eq 0) { "BAD" } elseif ($defaultPolicy.LockoutThreshold -lt 11) { "OK" } else { "MAYBE" }) "Set threshold between 5-10 attempts" "Medium"
            Add-Result "Password Policy" "Min Length" $(if ($defaultPolicy.MinPasswordLength -ge 14) { "OK" } elseif ($defaultPolicy.MinPasswordLength -ge 12) { "MAYBE" } else { "BAD" }) "Set minimum length >=14 characters" "High"
            Add-Result "Password Policy" "Reversible Encryption" $(if ($defaultPolicy.ReversibleEncryptionEnabled) { "BAD" } else { "OK" }) "Disable reversible encryption" "Critical"
        }
        catch {
            Write-StatusMessage "Unable to query domain password policy: $($_.Exception.Message)" -Type "Warning"
            Add-Result "Password Policy" "Domain Query" "Error" "Ensure domain connectivity and permissions" "Medium"
        }
    }
    
    Write-StatusMessage "Checking Windows LAPS configuration..." -Type "Info"
    $lapsPolicyRoots = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    )
    $lapsPolicyFound = $false
    foreach ($root in $lapsPolicyRoots) {
        if (Test-Path $root) { $lapsPolicyFound = $true; break }
    }
    Add-Result "LAPS" "Policy Presence" $(if ($lapsPolicyFound) {"OK"} else {"BAD"}) "Configure Windows LAPS policy and escrow passwords to AD/AAD" "High"
    
    Write-StatusMessage "Verifying LAPS password backup status..." -Type "Info"
    $lapsLogPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS"
    $isLAPSConfigured = (Test-Path $lapsLogPath)
    if ($isLAPSConfigured) {
        try {
            $lastBackupTime = Get-RegValue -Path $lapsLogPath -Name "ADPasswordBackupTimestamp"
            $lastChangeTime = Get-RegValue -Path $lapsLogPath -Name "ADPasswordExpirationTimestamp"
            if ($lastBackupTime -and $lastChangeTime) {
                if ($lastBackupTime -gt $lastChangeTime) {
                    Add-Result "LAPS" "Password Backup" "OK" "Password has been successfully backed up to AD." "Medium"
                } else {
                    Add-Result "LAPS" "Password Backup" "BAD" "Password backup appears out of date. Check LAPS operational log." "High"
                }
            } else {
                Add-Result "LAPS" "Password Backup" "MAYBE" "Timestamps not found; unable to verify backup status." "Medium"
            }
        }
        catch {
            Add-Result "LAPS" "Password Backup" "Error" "Unable to query LAPS registry timestamps." "Medium"
        }
    } else {
        Add-Result "LAPS" "Password Backup" "BAD" "LAPS is not configured on this machine." "High"
    }
    
    try {
        $lapsEvent = Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational" -MaxEvents 1 -ErrorAction Stop
        $lapsEventStatus = if ($lapsEvent) { "OK" } else { "MAYBE" }
        Add-Result "LAPS" "Operational Log" $lapsEventStatus "Verify LAPS is rotating/backing up passwords (see LAPS Operational log)" "Medium"
    }
    catch {
        Add-Result "LAPS" "Operational Log" "Error" "Unable to read LAPS Operational event log" "Medium"
    }
    
    Write-StatusMessage "Evaluating advanced authentication security..." -Type "Info"
    
    $runAsPPL = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
    Add-Result "LSA Protection" "RunAsPPL" $(if ($runAsPPL -in 1,2) { "OK" } elseif ($runAsPPL -eq 0) { "BAD" } else { "MAYBE" }) "Set RunAsPPL=1 in LSA registry" "High"
    
    $ntlmLevel = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
    $status = if ($ntlmLevel -ge 5) { "OK" } elseif ($ntlmLevel -ge 3) { "MAYBE" } else { "BAD" }
    Add-Result "Authentication" "NTLMv2 Level" $status "Set LmCompatibilityLevel to 5 or higher to enforce NTLMv2." "High"
    
    $restrictNTLM = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictSendingNTLMTraffic"
    $status = if ($restrictNTLM -eq 2) { "OK" } elseif ($restrictNTLM -eq 1) { "MAYBE" } else { "BAD" }
    Add-Result "Authentication" "Restrict NTLM" $status "Restrict outbound NTLM traffic to domain controllers." "Medium"
    
    $supportedTypes = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "SupportedEncryptionTypes"
    $status = "OK"
    $remediation = "AES and newer encryption types are supported."
    if ($supportedTypes) {
        if (($supportedTypes -band 0x4) -ne 0 -or ($supportedTypes -band 0x8) -ne 0) {
            $status = "BAD"
            $remediation = "Legacy RC4/DES encryption types are enabled. Disable them via registry or Group Policy."
        }
    } else {
        $status = "MAYBE"
        $remediation = "Kerberos encryption unset — may allow legacy. Use AES."
    }
    Add-Result "Authentication" "Kerberos Encryption" $status $remediation "High"
    
    $kerberosArmoring = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "RequireFast"
    Add-Result "Authentication" "Kerberos Armoring" $(if ($kerberosArmoring -eq 1) { "OK" } else { "MAYBE" }) "Enable Kerberos Armoring (FAST) for additional protection" "Medium"
    
    $wdigest = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential"
    Add-Result "Authentication" "WDigest Storage" $(if ($wdigest -eq 1) { "BAD" } else { "OK" }) "Disable WDigest: Set UseLogonCredential=0" "High"
    
    $cachedLogons = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount"
    $cachedCount = if ($cachedLogons) { [int]$cachedLogons } else { 10 }
    Add-Result "Authentication" "Cached Logons" $(if ($cachedCount -le 2) { "OK" } elseif ($cachedCount -le 10) { "MAYBE" } else { "BAD" }) "Reduce cached logons: Set count to 0-2" "Medium"
    
    $credDelegation = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowDefaultCredentials"
    Add-Result "Authentication" "Credential Delegation" $(if ($credDelegation -ne 1) { "OK" } else { "BAD" }) "Restrict credential delegation" "High"
    
    $remoteCredGuard = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "RemoteHostAllowsDelegateTo"
    $status = if ($remoteCredGuard -eq $null) { "OK" } else { "MAYBE" }
    Add-Result "Authentication" "Remote Credential Guard" $status "Review remote credential guard configuration" "Medium"
    
    Write-StatusMessage "Evaluating hardware security features..." -Type "Info"
    
    $secureBootStatus = Get-SecureBootStatus
    switch ($secureBootStatus.Status) {
        "Enabled" { 
            Write-StatusMessage "Secure Boot is enabled" -Type "Success"
            Add-Result "Hardware Security" "Secure Boot" "OK" "Secure Boot is properly enabled" "Medium"
        }
        "Disabled" { 
            Write-StatusMessage "Secure Boot is disabled" -Type "Warning"
            Add-Result "Hardware Security" "Secure Boot" "BAD" "Enable Secure Boot in BIOS/UEFI" "High"
        }
        "Not Supported" { 
            Write-StatusMessage "Secure Boot not supported on this system" -Type "Warning"
            Add-Result "Hardware Security" "Secure Boot" "MAYBE" "System does not support Secure Boot" "Low"
        }
        default { 
            Write-StatusMessage "Error checking Secure Boot: $($secureBootStatus.Message)" -Type "Error"
            Add-Result "Hardware Security" "Secure Boot" "Error" $secureBootStatus.Message "Medium"
        }
    }
    
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $tpmStatus = if ($tpm.TpmPresent -and $tpm.TpmReady) { "OK" } elseif ($tpm.TpmPresent) { "MAYBE" } else { "BAD" }
        Add-Result "Hardware Security" "TPM Status" $tpmStatus "Ensure TPM is present, enabled, and ready" "High"
        
        if ($tpm.TpmPresent) {
            $tpmVersion = if ($tpm.ManufacturerVersion) { $tpm.ManufacturerVersion } else { "Unknown" }
            Add-Result "Hardware Security" "TPM Version" $(if ($tpmVersion -like "2.*") { "OK" } else { "MAYBE" }) "TPM 2.0 recommended for best security" "Medium"
        }
    }
    catch {
        Add-Result "Hardware Security" "TPM Query" "Error" "Unable to query TPM status - may not be available" "Medium"
    }
    
    $whfbStatus = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled"
    Add-Result "Hardware Security" "Windows Hello" $(if ($whfbStatus -eq 1) { "OK" } elseif ($whfbStatus -eq 0) { "MAYBE" } else { "MAYBE" }) "Consider enabling Windows Hello for Business for passwordless authentication" "Low"
    
    try {
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        $heci = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled"
        Add-Result "Hardware Security" "Memory Integrity" $(if ($heci -eq 1) { "OK" } else { "BAD" }) "Enable Memory Integrity (HVCI)" "High"
    }
    catch {
        Add-Result "Hardware Security" "Memory Integrity Query" "Error" "Unable to query Memory Integrity status" "Medium"
    }
    
    $dmaProtection = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMAType"
    $status = if ($dmaProtection -eq 1) { "OK" } else { "BAD" }
    Add-Result "Hardware Security" "DMA Protection" $status "Enable kernel DMA protection" "High"
    
    Write-StatusMessage "Evaluating Virtualization-Based Security..." -Type "Info"
    
    try {
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        
        $vbsRunning = $deviceGuard.VirtualizationBasedSecurityStatus -eq 2
        Add-Result "VBS" "Status" $(if ($vbsRunning) { "OK" } else { "BAD" }) "Enable Virtualization-Based Security" "High"
        
        $cgRunning = $deviceGuard.SecurityServicesRunning -contains 1
        Add-Result "VBS" "Credential Guard" $(if ($cgRunning -and $vbsRunning) { "OK" } else { "BAD" }) "Enable Credential Guard via GP/registry" "High"
        
        Add-Result "VBS" "Code Integrity Policy" $(if ($deviceGuard.CodeIntegrityPolicyEnforcementStatus -eq 2) { "OK" } elseif ($deviceGuard.CodeIntegrityPolicyEnforcementStatus -eq 1) { "MAYBE" } else { "BAD" }) "Enable WDAC code integrity enforcement" "Medium"
        Add-Result "VBS" "User Mode CI" $(if ($deviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 2) { "OK" } elseif ($deviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus -eq 1) { "MAYBE" } else { "BAD" }) "Enable user mode code integrity" "Medium"
    }
    catch {
        Write-StatusMessage "Unable to query DeviceGuard/VBS status" -Type "Warning"
        Add-Result "VBS" "DeviceGuard Query" "Error" "Check if system supports DeviceGuard/VBS" "Medium"
    }
    
    $dmaAccess = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceLock" -Name "AllowDirectMemoryAccess"
    Add-Result "VBS" "DMA Protection" $(if ($dmaAccess -eq 0) { "OK" } elseif ($dmaAccess -eq 1) { "BAD" } else { "MAYBE" }) "Block DMA: Set AllowDirectMemoryAccess=0" "High"
    
    Write-StatusMessage "Evaluating application control mechanisms..." -Type "Info"
    
    $appLockerService = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    $serviceStatus = if ($appLockerService -and $appLockerService.Status -eq "Running") { "OK" } else { "BAD" }
    Add-Result "App Control" "AppLocker Service" $serviceStatus "Start AppIDSvc and set to Automatic" "Medium"
    
    if ($script:isElevated) {
        try {
            $appGuardFeature = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Defender-ApplicationGuard" -ErrorAction Stop
            $appGuardStatus = if ($appGuardFeature.State -eq "Enabled") { "OK" } else { "MAYBE" }
            Add-Result "App Control" "Application Guard" $appGuardStatus "Enable Application Guard for Edge isolation" "Low"
        }
        catch {
            Add-Result "App Control" "Application Guard Query" "Error" "Unable to check Application Guard feature status" "Low"
        }
    }
    
    try {
        $ciPolicies = Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName Win32_DeviceGuard -ErrorAction Stop
        $wdacStatus = if ($ciPolicies.CodeIntegrityPolicyEnforcementStatus -eq 2) { "OK" } else { "BAD" }
        Add-Result "App Control" "WDAC Enforcement" $wdacStatus "Enable WDAC policy enforcement" "High"
    } catch {
        Add-Result "App Control" "WDAC Query" "Error" "Unable to query WDAC status" "Medium"
    }
    
    try {
        $appLockerRules = Get-AppLockerPolicy -Local -ErrorAction Stop
        $ruleCount = ($appLockerRules.RuleCollections | Measure-Object).Sum
        $status = if ($ruleCount -gt 0) { "OK" } else { "BAD" }
        Add-Result "App Control" "AppLocker Rules" $status "Configure AppLocker rules for application control" "High"
    } catch {
        Add-Result "App Control" "AppLocker Query" "Error" "Unable to query AppLocker policies" "Medium"
    }
    
    $srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
    $srpEnabled = Get-RegValue -Path $srpPath -Name "PolicyScope"
    Add-Result "App Control" "Software Restriction" $(if ($srpEnabled -eq 0) { "OK" } else { "BAD" }) "Disable software restriction policies (prefer WDAC/AppLocker)" "Medium"
    
    Write-StatusMessage "Evaluating UAC settings..." -Type "Info"
    
    $uac = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    Add-Result "UAC" "Enabled" $(if ($uac -eq 1) { "OK" } else { "BAD" }) "Enable UAC: Set EnableLUA=1" "Critical"
    
    $uacPrompt = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"
    Add-Result "UAC" "Admin Prompt" $(if ($uacPrompt -eq 2) { "OK" } elseif ($uacPrompt -in 1,3) { "MAYBE" } else { "BAD" }) "Set ConsentPromptBehaviorAdmin=2 for secure desktop" "High"
    
    $uacSecureDesktop = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop"
    Add-Result "UAC" "Secure Desktop" $(if ($uacSecureDesktop -eq 1) { "OK" } else { "BAD" }) "Enable UAC secure desktop prompts" "Medium"
    
    Write-StatusMessage "Auditing local security configuration..." -Type "Info"
    
    try {
        $guestAccount = Get-CimInstance -ClassName Win32_UserAccount -ErrorAction Stop | Where-Object { $_.SID -match "-501$" }
        if ($guestAccount) {
            Add-Result "Local Security" "Guest Account" $(if ($guestAccount.Disabled) { "OK" } else { "BAD" }) "Disable guest account" "High"
        } else {
            Add-Result "Local Security" "Guest Account" "Error" "Unable to locate guest account" "Medium"
        }
    }
    catch {
        Add-Result "Local Security" "Guest Account Query" "Error" "Unable to query user accounts" "Medium"
    }
    
    try {
        $adminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction Stop
        $members = Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop
        $memberNames = $members.Name | ForEach-Object { $_.Split('\')[-1] }
        $totalMembers = $memberNames.Count
        $standardMembers = @("Administrator", "Domain Admins", "BUILTIN\Administrators")
        $riskyMembers = $memberNames | Where-Object { $_ -notin $standardMembers }
        if ($totalMembers -gt 3 -and $riskyMembers.Count -gt 0) {
            $status = "BAD"
            $remediation = "Review and remove excessive members: $($riskyMembers -join ', ')"
            $riskLevel = "High"
        } elseif ($totalMembers -gt 3) {
            $status = "MAYBE"
            $remediation = "Review admin group members: $($memberNames -join ', ')"
            $riskLevel = "Medium"
        } else {
            $status = "OK"
            $remediation = "Local Administrators group membership is appropriate."
            $riskLevel = "Low"
        }
        
        Add-Result "Local Security" "Admin Group Members" $status $remediation $riskLevel
    }
    catch {
        Add-Result "Local Security" "Admin Group Query" "Error" "Unable to query local Administrators group." "Medium"
    }
    
    $aieEnabled = $false
    $aiePaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer",
        "HKCU:\Software\Policies\Microsoft\Windows\Installer"
    )
    
    foreach ($path in $aiePaths) {
        $val = Get-RegValue -Path $path -Name "AlwaysInstallElevated"
        if ($val -eq 1) { $aieEnabled = $true; break }
    }
    
    Add-Result "Local Security" "Always Install Elevated" $(if ($aieEnabled) { "BAD" } else { "OK" }) "Disable AlwaysInstallElevated policy" "High"
    
    $coInstallers = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" -Name "DisableCoInstallers"
    Add-Result "Local Security" "Device Co-Installers" $(if ($coInstallers -eq 1) { "OK" } else { "BAD" }) "Disable co-installers: Set DisableCoInstallers=1" "Medium"
    
    Write-StatusMessage "Checking BitLocker encryption status..." -Type "Info"
    
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        foreach ($volume in $volumes) {
            $protectionStatus = if ($volume.ProtectionStatus -eq "On") { "OK" } else { "BAD" }
            Add-Result "BitLocker" "$($volume.MountPoint) Protection" $protectionStatus "Enable BitLocker on $($volume.MountPoint)" "High"
            
            if ($volume.KeyProtector) {
                $kpTypes = @($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType })
                $hasSecureKP = $kpTypes | Where-Object { $_ -match "Tpm|RecoveryPassword|Pin" }
                $keyStatus = if ($hasSecureKP) { "OK" } else { "BAD" }
                Add-Result "BitLocker" "$($volume.MountPoint) Key Protectors" $keyStatus "Add secure key protectors (TPM+PIN recommended)" "Medium"
                
                $hasNetworkUnlock = $kpTypes | Where-Object { $_ -eq "NetworkUnlock" }
                if ($hasNetworkUnlock) {
                    Add-Result "BitLocker" "$($volume.MountPoint) Network Unlock" "OK" "Network unlock configured for enterprise deployment" "Low"
                }
            }
            
            if ($isDomainJoined) {
                $recoveryEscrow = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "ActiveDirectoryBackup"
                Add-Result "BitLocker" "Recovery Key Escrow" $(if ($recoveryEscrow -eq 1) { "OK" } else { "MAYBE" }) "Configure recovery key backup to Active Directory" "Medium"
            }
        }
    }
    catch {
        Write-StatusMessage "Unable to query BitLocker status" -Type "Warning"
        Add-Result "BitLocker" "Query" "Error" "Install BitLocker module or check permissions" "Medium"
    }
    
    $networkUnlock = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSManageNetworkUnlockKeys"
    Add-Result "Data Protection" "BitLocker Network Unlock" $(if ($networkUnlock -eq 1) { "OK" } else { "MAYBE" }) "Enable BitLocker Network Unlock for enterprise" "Medium"
    
    try {
        $efsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS"
        $efsEnabled = Test-Path $efsPath
        $status = if ($efsEnabled) { "OK" } else { "MAYBE" }
        Add-Result "Data Protection" "EFS Encryption" $status "Consider enabling EFS for sensitive data" "Low"
    }
    catch {
        Add-Result "Data Protection" "EFS Encryption" "Error" "Unable to check EFS status" "Low"
    }
    
    $wipStatus = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EDP" -Name "EnterpriseIPRange"
    $status = if ($wipStatus) { "OK" } else { "MAYBE" }
    Add-Result "Data Protection" "WIP Policies" $status "Configure Windows Information Protection" "Medium"
    
    Write-StatusMessage "Evaluating network security configuration..." -Type "Info"
    
    $dohEnabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh"
    Add-Result "Network Security" "DNS over HTTPS" $(if ($dohEnabled -eq 2) { "OK" } elseif ($dohEnabled -eq 1) { "MAYBE" } else { "MAYBE" }) "Consider enabling DNS over HTTPS for privacy" "Low"
    
    try {
        $dohStatus = Get-DnsClientDohServerAddress -ErrorAction Stop | 
                     Where-Object { $_.DohSetting -eq "Auto" -or $_.DohSetting -eq "On" }
        $status = if ($dohStatus) { "OK" } else { "MAYBE" }
        Add-Result "Network Security" "DNS over HTTPS" $status "Enable DNS over HTTPS for privacy" "Low"
    } catch {
        Add-Result "Network Security" "DoH Query" "Error" "Unable to query DNS over HTTPS settings" "Low"
    }
    
    $ipv6Privacy = Get-NetIPv6Protocol -ErrorAction SilentlyContinue | 
                   Select-Object -ExpandProperty UseTemporaryAddresses
    Add-Result "Network Security" "IPv6 Privacy" $(if ($ipv6Privacy -eq "Enabled") { "OK" } else { "BAD" }) "Enable IPv6 temporary addresses" "Low"
    
    $teredoStatus = Get-NetTeredoState -ErrorAction SilentlyContinue
    $status = if ($teredoStatus.State -eq "Disabled") { "OK" } else { "BAD" }
    Add-Result "Network Security" "Teredo Tunneling" $status "Disable Teredo tunneling if not required" "Medium"
    
    $llmnr = Get-RegValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"
    Add-Result "Network Security" "LLMNR" $(if ($llmnr -eq 0) { "OK" } else { "BAD" }) "Disable LLMNR: Set EnableMulticast=0" "High"
    
    $netbiosEnabled = $false
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue | ForEach-Object {
        $opt = Get-RegValue -Path $_.PSPath -Name "NetbiosOptions"
        if ($opt -in 0, 1) { $netbiosEnabled = $true }
    }
    Add-Result "Network Security" "NetBIOS" $(if ($netbiosEnabled) { "BAD" } else { "OK" }) "Disable NetBIOS on all interfaces" "High"
    
    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        Add-Result "Network Security" "SMBv1" $(if ($smbConfig.EnableSMB1Protocol) { "BAD" } else { "OK" }) "Disable SMBv1 protocol" "Critical"
        Add-Result "Network Security" "SMB Signing" $(if ($smbConfig.RequireSecuritySignature) { "OK" } else { "BAD" }) "Require SMB signing" "High"
        
        $wkstnPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        $reqSign = Get-RegValue -Path $wkstnPath -Name "RequireSecuritySignature"
        Add-Result "Network Security" "SMB Client Signing" $(if ($reqSign -eq 1) {"OK"} else {"BAD"}) "Require SMB signing on client" "High"
        
        $allowGuestPolicy = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth"
        $allowGuestParam  = Get-RegValue -Path $wkstnPath -Name "AllowInsecureGuestAuth"
        $guestEnabled = ($allowGuestPolicy -eq 1 -or $allowGuestParam -eq 1)
        Add-Result "Network Security" "SMB Guest Access" $(if ($guestEnabled) {"BAD"} else {"OK"}) "Disable insecure guest SMB logons" "High"
    }
    catch {
        Add-Result "Network Security" "SMB Config Query" "Error" "Unable to query SMB configuration" "Medium"
    }
    
    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($profile in $firewallProfiles) {
            $status = if ($profile.Enabled) { "OK" } else { "BAD" }
            Add-Result "Network Security" "Firewall $($profile.Name)" $status "Enable firewall profile" "High"
            
            $stealthMode = Get-NetFirewallProfile -Name $profile.Name | 
                          Select-Object -ExpandProperty DefaultInboundAction
            $status = if ($stealthMode -eq "Block") { "OK" } else { "BAD" }
            Add-Result "Firewall" "$($profile.Name) Stealth Mode" $status "Enable stealth mode to drop unsolicited packets" "Medium"
            
            $outboundAction = Get-NetFirewallProfile -Name $profile.Name | 
                             Select-Object -ExpandProperty DefaultOutboundAction
            $status = if ($outboundAction -eq "Allow") { "OK" } else { "MAYBE" }
            Add-Result "Firewall" "$($profile.Name) Outbound Filtering" $status "Outbound filtering may impact functionality" "Low"
        }
        
        $inboundAction = ($firewallProfiles | Where-Object { $_.Name -eq "Domain" }).DefaultInboundAction
        Add-Result "Network Security" "Firewall Default Inbound" $(if ($inboundAction -eq "Block") { "OK" } else { "BAD" }) "Set default inbound action to Block" "Medium"
    }
    catch {
        Add-Result "Network Security" "Firewall Query" "Error" "Unable to query firewall profiles" "Medium"
    }
    
    Write-StatusMessage "Evaluating Windows Defender configuration..." -Type "Info"
    
    try {
        $avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
        if ($avProducts) {
            foreach ($product in $avProducts) {
                $state = 0
                try { $state = [int]$product.productState } catch { $state = 0 }
                $productStatus = Get-AvStateSummary -ProductState $state
                
                $status = switch ($productStatus) {
                    "On" { "OK" }
                    "Outdated" { "MAYBE" }
                    default { "BAD" }
                }
                
                $productName = if ($product.displayName.Length -gt 20) {
                    $product.displayName.Substring(0, 17) + "..."
                } else {
                    $product.displayName
                }
                
                Add-Result "Antivirus" $productName $status "Ensure AV is enabled and updated" "Critical"
            }
        } else {
            Add-Result "Antivirus" "No Products" "BAD" "Install and configure antivirus software" "Critical"
        }
    }
    catch {
        Write-StatusMessage "Unable to query antivirus products from Security Center" -Type "Warning"
        Add-Result "Antivirus" "Security Center" "Error" "Unable to access Windows Security Center" "Medium"
    }
    
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
        $mpStatus = $null
        
        try {
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        }
        catch {
            Write-StatusMessage "Unable to get Windows Defender status: $($_.Exception.Message)" -Type "Warning"
        }
        
        Add-Result "Windows Defender" "Real-time Protection" $(if ($mpPref.DisableRealtimeMonitoring -eq $false) { "OK" } else { "BAD" }) "Enable real-time protection" "Critical"
        Add-Result "Windows Defender" "Cloud Protection" $(if ($mpPref.MAPSReporting -ne "Disabled") { "OK" } else { "MAYBE" }) "Enable cloud-delivered protection" "Medium"
        
        Add-Result "Windows Defender" "Controlled Folder Access" $(if ($mpPref.EnableControlledFolderAccess -ne "Disabled") { "OK" } else { "BAD" }) "Enable Controlled Folder Access" "Medium"
        
        if ($mpStatus -ne $null) {
            $tpEnabled = $mpStatus.IsTamperProtected
            Add-Result "Windows Defender" "Tamper Protection" $(if ($tpEnabled) { "OK" } else { "BAD" }) "Enable Tamper Protection" "High"
        } else {
            Add-Result "Windows Defender" "Tamper Protection" "MAYBE" "Unable to verify Tamper Protection status" "Medium"
        }
        
        $netProtStatus = if ($mpPref.EnableNetworkProtection -in 1, 2) { "OK" } else { "BAD" }
        Add-Result "Windows Defender" "Network Protection" $netProtStatus "Enable Network Protection (Block or Audit mode)" "Medium"
        
        $puaStatus = if ($mpPref.PUAProtection -eq 1) { "OK" } else { "BAD" }
        Add-Result "Windows Defender" "PUA Protection" $puaStatus "Enable Potentially Unwanted Application protection" "Medium"
        
        $cloudProtection = $mpPref.MAPSReporting
        $status = switch ($cloudProtection) {
            2 { "OK" }
            1 { "MAYBE" }
            default { "BAD" }
        }
        Add-Result "Windows Defender" "Cloud Protection" $status "Enable advanced cloud-delivered protection" "High"
        
        $sampleSubmission = $mpPref.SubmitSamplesConsent
        $status = switch ($sampleSubmission) {
            1 { "OK" }
            2 { "MAYBE" }
            default { "BAD" }
        }
        Add-Result "Windows Defender" "Sample Submission" $status "Configure sample submission for threat analysis" "Medium"
        
        $blockAtFirstSight = $mpPref.DisableBlockAtFirstSeen
        Add-Result "Windows Defender" "Block at First Sight" $(if ($blockAtFirstSight -eq $false) { "OK" } else { "BAD" }) "Enable block at first sight" "High"
        
        $asrActionsMap = $mpPref.AttackSurfaceReductionRules_Actions
        $enabledCount = 0; $auditCount = 0; $warnCount = 0; $disabledCount = 0
        if ($asrActionsMap) {
            foreach ($kv in $asrActionsMap.GetEnumerator()) {
                switch ([int]$kv.Value) {
                    1 { $enabledCount++ }
                    2 { $auditCount++ }
                    6 { $warnCount++ }
                    default { $disabledCount++ }
                }
            }
        } else {
            $ids = $mpPref.AttackSurfaceReductionRules_Ids
            $actions = $mpPref.AttackSurfaceReductionRules_Actions
            if ($ids -and $actions) {
                for ($i=0; $i -lt $ids.Count; $i++) {
                    switch ([int]$actions[$i]) {
                        1 { $enabledCount++ }
                        2 { $auditCount++ }
                        6 { $warnCount++ }
                        default { $disabledCount++ }
                    }
                }
            }
        }
        $asrSummary = "Enabled:$enabledCount Audit:$auditCount Warn:$warnCount Disabled:$disabledCount"
        $asrStatus = if ($enabledCount -gt 5) { "OK" } elseif ($enabledCount -gt 0) { "MAYBE" } else { "BAD" }
        Add-Result "Windows Defender" "ASR Rules" $asrStatus $asrSummary "Medium"
        
    }
    catch {
        Write-StatusMessage "Unable to query Windows Defender preferences" -Type "Warning"
        Add-Result "Windows Defender" "Config Query" "Error" "Windows Defender cmdlets not available" "Medium"
    }
    
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $tamperProtection = $mpStatus.IsTamperProtected
        Add-Result "System Security" "Tamper Protection" $(if ($tamperProtection) { "OK" } else { "BAD" }) "Enable Windows Defender Tamper Protection" "Critical"
    }
    catch {
        Add-Result "System Security" "Tamper Protection" "MAYBE" "Unable to verify Tamper Protection status" "Medium"
    }
    
    if (-not $SkipCloudChecks) {
        Write-StatusMessage "Checking Microsoft Defender for Endpoint status..." -Type "Info"
        $mdePath = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status"
        $onboarded = Get-RegValue -Path $mdePath -Name "OnboardingState"
        $health = Get-RegValue -Path $mdePath -Name "MDEClientManagementStatus"
        if ($onboarded -eq 1 -and $health -in 1, 2) {
            Add-Result "MDE" "Onboarding Status" "OK" "Device is onboarded and healthy." "Low"
        }
        elseif ($onboarded -eq 1) {
            Add-Result "MDE" "Onboarding Status" "MAYBE" "Device is onboarded, but health status needs review." "Medium"
        }
        else {
            Add-Result "MDE" "Onboarding Status" "BAD" "Device is not onboarded to Microsoft Defender for Endpoint." "High"
        }
        
        $edrEnabled = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Name "SenseIsRunning"
        Add-Result "MDE" "EDR Service" $(if ($edrEnabled -eq 1) { "OK" } else { "BAD" }) "Ensure MDE sensor service is running" "High"
    }
    
    Write-StatusMessage "Checking exploit protection baselines..." -Type "Info"
    if ($script:isElevated) {
        try {
            $epSettings = Get-ProcessMitigation -System -ErrorAction Stop
            
            $sehopStatus = if ($epSettings.SEHOP -eq "ON") { "OK" } else { "BAD" }
            Add-Result "Exploit Protection" "SEHOP" $sehopStatus "Enable SEHOP system-wide." "Medium"
            $depStatus = if ($epSettings.DEP -eq "ON") { "OK" } else { "BAD" }
            Add-Result "Exploit Protection" "DEP" $depStatus "Enable DEP system-wide." "High"
            
            $asrStatus = if ($epSettings.BottomUp.ASLR -eq "ON") { "OK" } else { "BAD" }
            Add-Result "Exploit Protection" "ASLR" $asrStatus "Enable Address Space Layout Randomization." "Medium"
            
        }
        catch {
            Add-Result "Exploit Protection" "Query" "Error" "Unable to query Exploit Protection settings." "Medium"
        }
    } else {
        Add-Result "Exploit Protection" "Query" "Error" "Requires elevation to check system mitigation policies." "Medium"
    }
    
    $exploitGuard = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\ExploitGuard" -Name "ExploitGuardSettings"
    $status = if ($exploitGuard) { "OK" } else { "BAD" }
    Add-Result "Application Security" "Exploit Guard" $status "Configure Windows Defender Exploit Guard" "High"
    
    Write-StatusMessage "Evaluating PowerShell security settings..." -Type "Info"
    
    if ($script:isElevated) {
        try {
            $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction Stop
            $psv2Status = if ($psv2Feature -and $psv2Feature.State -eq "Enabled") { "BAD" } else { "OK" }
            Add-Result "PowerShell Security" "Version 2" $psv2Status "Disable PowerShell v2" "High"
        }
        catch {
            Add-Result "PowerShell Security" "Version 2 Check" "Error" "Unable to check PowerShell v2 status" "Medium"
        }
    }
    
    $ep = Get-ExecutionPolicy
    $epStatus = switch ($ep) {
        "AllSigned" { "OK" }
        "RemoteSigned" { "MAYBE" }
        { $_ -in "Unrestricted", "Bypass" } { "BAD" }
        default { "MAYBE" }
    }
    Add-Result "PowerShell Security" "Execution Policy" $epStatus "Set secure execution policy (AllSigned recommended)" "Medium"
    
    $langMode = $ExecutionContext.SessionState.LanguageMode
    $langStatus = if ($langMode -eq "ConstrainedLanguage") { "OK" } else { "MAYBE" }
    Add-Result "PowerShell Security" "Language Mode" $langStatus "Consider ConstrainedLanguage mode in high-security environments" "Low"
    
    $psLogging = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging"
    Add-Result "PowerShell Security" "Script Block Logging" $(if ($psLogging -eq 1) { "OK" } else { "BAD" }) "Enable PowerShell script block logging" "Medium"
    
    $moduleLogging = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging"
    Add-Result "PowerShell Security" "Module Logging" $(if ($moduleLogging -eq 1) { "OK" } else { "BAD" }) "Enable PowerShell module logging" "Medium"
    
    $transcriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $transcriptionEnabled = Get-RegValue -Path $transcriptionPath -Name "EnableTranscripting"
    $outputDirectory = Get-RegValue -Path $transcriptionPath -Name "OutputDirectory"
    $transcriptionStatus = if ($transcriptionEnabled -eq 1) { "OK" } else { "BAD" }
    Add-Result "PowerShell Security" "Transcription" $transcriptionStatus "Enable PowerShell transcription logging." "Medium"
    
    if ($transcriptionEnabled -eq 1) {
        $outputStatus = if ($outputDirectory) { "OK" } else { "BAD" }
        Add-Result "PowerShell Security" "Transcript Location" $outputStatus "Configure centralized transcript storage" "Medium"
    }
    
    $protectedEventLogging = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name "EnableProtectedEventLogging"
    Add-Result "PowerShell Security" "Protected Event Logging" $(if ($protectedEventLogging -eq 1) { "OK" } else { "BAD" }) "Enable protected event logging" "High"
    
    $psOperationalLog = Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue
    $status = if ($psOperationalLog.IsEnabled) { "OK" } else { "BAD" }
    Add-Result "Logging & Auditing" "PowerShell Operational" $status "Enable PowerShell operational logging" "Medium"
    
    Write-StatusMessage "Evaluating logging and auditing configuration..." -Type "Info"
    
    $auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $auditCmdLine = Get-RegValue -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled"
    $status = if ($auditCmdLine -eq 1) { "OK" } else { "BAD" }
    Add-Result "Logging & Auditing" "Command Line Auditing" $status "Enable command-line logging (Event ID 4688)." "Medium"
    
    if ($script:isElevated) {
        try {
            $auditPolicies = @{
                "Logon" = "Logon events auditing"
                "Object Access" = "File system access auditing"
                "Process Tracking" = "Process creation auditing"
                "Privilege Use" = "Sensitive privilege use auditing"
            }
            
            foreach ($policy in $auditPolicies.Keys) {
                try {
                    $auditResult = & auditpol /get /subcategory:$policy 2>$null | Select-String "Success and Failure"
                    $auditStatus = if ($auditResult) { "OK" } else { "MAYBE" }
                    Add-Result "Logging & Auditing" "$policy Auditing" $auditStatus $auditPolicies[$policy] "Medium"
                }
                catch {
                    Add-Result "Logging & Auditing" "$policy Auditing" "Error" "Unable to check $policy audit policy" "Low"
                }
            }
        }
        catch {
            Add-Result "Logging & Auditing" "Audit Policy Check" "Error" "Unable to check advanced audit policies" "Medium"
        }
    }
    
    $securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    $retentionDays = if ($securityLog.MaximumSizeInBytes -gt 100MB) { "OK" } else { "BAD" }
    Add-Result "Logging & Auditing" "Security Log Retention" $retentionDays "Configure security log retention for 30+ days" "Medium"
    
    try {
        $auditPolicy = auditpol /get /category:* /r | ConvertFrom-Csv -Delimiter "," -Header "Subcategory","Setting"
        $criticalCategories = $auditPolicy | Where-Object { $_.Subcategory -match "Logon|Account Logon|Detailed Tracking" }
        $status = if ($criticalCategories.Setting -contains "Success and Failure") { "OK" } else { "BAD" }
        Add-Result "Logging & Auditing" "Advanced Audit Policy" $status "Enable critical audit policy categories" "High"
    } catch {
        Add-Result "Logging & Auditing" "Audit Policy Query" "Error" "Unable to query advanced audit policies" "Medium"
    }
    
    $wefCollector = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" -Name "1"
    Add-Result "Logging & Auditing" "Event Forwarding" $(if ($wefCollector) { "OK" } else { "MAYBE" }) "Consider configuring Windows Event Forwarding for centralized logging" "Low"
    
    $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
    Add-Result "Logging & Auditing" "Sysmon" $(if ($sysmonService) { "OK" } else { "MAYBE" }) "Consider installing Sysmon for enhanced logging" "Low"
    
    Write-StatusMessage "Checking system security configurations..." -Type "Info"
    
    $writeFlag = [System.Security.AccessControl.FileSystemRights]::Write
    $suspects = @("BUILTIN\Users", "NT AUTHORITY\Authenticated Users", "Everyone")
    
    $pathDirs = ($env:Path -split ';' | Where-Object { $_ -and (Test-Path $_ -PathType Container) } | Select-Object -Unique)
    
    $pathVulnCount = 0
    foreach ($dir in $pathDirs[0..9]) {
        try {
            $acl = Get-Acl -Path $dir -ErrorAction Stop
            $usersWrite = $acl.Access | Where-Object {
                ($suspects -contains $_.IdentityReference.Value) -and 
                (($_.FileSystemRights -band $writeFlag) -ne 0) -and
                ($_.AccessControlType -eq "Allow")
            }
            
            if ($usersWrite) { $pathVulnCount++ }
        }
        catch { }
    }
    
    Add-Result "System Security" "PATH ACL Security" $(if ($pathVulnCount -eq 0) { "OK" } elseif ($pathVulnCount -le 2) { "MAYBE" } else { "BAD" }) "Review PATH directory permissions - $pathVulnCount potentially vulnerable" "Medium"
    
    $unquotedServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.PathName -and 
        $_.PathName -notmatch '^".*"' -and 
        $_.PathName -match '\s' -and
        $_.PathName -notlike 'C:\Windows\*'
    }
    
    $serviceCount = ($unquotedServices | Measure-Object).Count
    Add-Result "System Security" "Unquoted Service Paths" $(if ($serviceCount -eq 0) { "OK" } else { "BAD" }) "Fix $serviceCount unquoted service paths" "High"
    
    $wsusServer = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer"
    if ($wsusServer) {
        $wsusStatus = if ($wsusServer -match "^https://") { "OK" } elseif ($wsusServer -match "^http://") { "BAD" } else { "MAYBE" }
        Add-Result "System Security" "WSUS Protocol" $wsusStatus "Configure WSUS to use HTTPS" "Medium"
    } else {
        Add-Result "System Security" "Update Source" "OK" "Using Windows Update (no WSUS configured)" "Low"
    }
    
    try {
        $sandboxFeature = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction Stop
        $status = if ($sandboxFeature.State -eq "Enabled") { "OK" } else { "MAYBE" }
        Add-Result "System Security" "Windows Sandbox" $status "Enable Windows Sandbox for secure browsing" "Low"
    } catch {
        Add-Result "System Security" "Sandbox Query" "Error" "Unable to query Windows Sandbox status" "Low"
    }
    
    try {
        $deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
        $secureLaunch = $deviceGuard.VirtualizationBasedSecurityStatus -eq 2
        Add-Result "System Security" "Secure Launch" $(if ($secureLaunch) { "OK" } else { "BAD" }) "Enable System Guard Secure Launch" "High"
    } catch {
        Add-Result "System Security" "Secure Launch" "Error" "Unable to query Secure Launch status" "Medium"
    }
    
    Write-StatusMessage "Checking Windows Update status..." -Type "Info"
    
    try {
        $updateSession = New-Object -ComObject "Microsoft.Update.Session"
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $pendingUpdates = $searchResult.Updates.Count
        
        $criticalUpdates = $searchResult.Updates | Where-Object { $_.MsrcSeverity -eq "Critical" }
        $criticalCount = ($criticalUpdates | Measure-Object).Count
        
        $qualityUpdates = $searchResult.Updates | Where-Object { $_.MsrcSeverity -eq "Important" }
        $qualityCount = ($qualityUpdates | Measure-Object).Count
        
        if ($criticalCount -gt 0) {
            Add-Result "Windows Updates" "Critical Updates" "BAD" "Install $criticalCount critical security update(s) immediately" "Critical"
        } elseif ($qualityCount -gt 0) {
            Add-Result "System Security" "Quality Updates" "BAD" "Install all quality updates immediately" "Critical"
        } elseif ($pendingUpdates -gt 0) {
            Add-Result "Windows Updates" "Pending Updates" "MAYBE" "Install $pendingUpdates pending update(s)" "Medium"
        } else {
            Add-Result "Windows Updates" "Update Status" "OK" "System is up to date" "Low"
        }
    }
    catch {
        Add-Result "Windows Updates" "Update Check" "Error" "Unable to check for pending updates" "Medium"
    }
    
    Write-StatusMessage "Evaluating remote access security..." -Type "Info"
    
    try {
        $rdp = Get-CimInstance -Namespace "root/CIMv2/TerminalServices" -ClassName "Win32_TerminalServiceSetting" -ErrorAction Stop
        $rdpEnabled = $rdp -and $rdp.AllowTSConnections -eq 1
        
        if ($rdpEnabled) {
            Add-Result "Remote Access" "RDP Enabled" "MAYBE" "RDP is enabled - review necessity and security settings" "Medium"
            
            $rdpSecurity = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer"
            Add-Result "Remote Access" "RDP Security Level" $(if ($rdpSecurity -eq 2) { "OK" } else { "BAD" }) "Set RDP security to TLS (SecurityLayer=2)" "High"
            
            $nlaRequired = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
            Add-Result "Remote Access" "RDP NLA" $(if ($nlaRequired -eq 1) { "OK" } else { "BAD" }) "Require Network Level Authentication" "High"
            
            $rdpTimeout = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime"
            $status = if ($rdpTimeout -gt 0 -and $rdpTimeout -le 15) { "OK" } else { "BAD" }
            Add-Result "Remote Access" "RDP Idle Timeout" $status "Set RDP idle timeout to 15 minutes or less" "Medium"
            
            $restrictedAdmin = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin"
            Add-Result "Remote Access" "RDP Restricted Admin" $(if ($restrictedAdmin -eq 0) { "OK" } else { "BAD" }) "Enable RDP restricted admin mode" "High"
        } else {
            Add-Result "Remote Access" "RDP Enabled" "OK" "RDP is disabled" "Low"
        }
    }
    catch {
        Add-Result "Remote Access" "RDP Query" "Error" "Unable to query RDP settings" "Medium"
    }
    
    try {
        $winrmService = Get-Service -Name WinRM -ErrorAction Stop
        if ($winrmService.Status -eq "Running") {
            Add-Result "Remote Access" "WinRM Service" "MAYBE" "WinRM is running - review configuration and necessity" "Medium"
            
            $httpsListener = Get-ChildItem WSMan:\localhost\Listener\ -ErrorAction SilentlyContinue | Where-Object { $_.Keys -contains "Transport=HTTPS" }
            Add-Result "Remote Access" "WinRM HTTPS" $(if ($httpsListener) { "OK" } else { "BAD" }) "Configure WinRM to use HTTPS transport" "Medium"
            
            $winRMEncryption = Get-ChildItem -Path WSMan:\localhost\Service -ErrorAction SilentlyContinue | 
                               Where-Object { $_.Name -eq "AllowUnencrypted" }
            $status = if ($winRMEncryption.Value -eq $false) { "OK" } else { "BAD" }
            Add-Result "Remote Access" "WinRM Encryption" $status "Require WinRM encryption" "High"
        } else {
            Add-Result "Remote Access" "WinRM Service" "OK" "WinRM is not running" "Low"
        }
    }
    catch {
        Add-Result "Remote Access" "WinRM Query" "Error" "Unable to query WinRM service" "Low"
    }
    
    if (-not $SkipCloudChecks) {
        Write-StatusMessage "Evaluating cloud security integration..." -Type "Info"
        
        if ($azureStatus) {
            if ($azureStatus.AzureAdJoined) {
                Add-Result "Cloud Security" "Azure AD Join" "OK" "Device is Azure AD joined" "Low"
                
                $caCompliance = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Enrollments" -Name "PolicyManagerProvider"
                Add-Result "Cloud Security" "Device Compliance" $status "Configure Azure AD device compliance policies" "Medium"
                
                $conditionalAccess = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Device" -Name "ConditionalAccessPolicies"
                $status = if ($conditionalAccess) { "OK" } else { "MAYBE" }
                Add-Result "Cloud Security" "Conditional Access" $status "Configure Conditional Access policies" "High"
                
            } elseif ($azureStatus.WorkplaceJoined) {
                Add-Result "Cloud Security" "Workplace Join" "MAYBE" "Device is workplace joined - consider full Azure AD join" "Low"
            } else {
                Add-Result "Cloud Security" "Cloud Join Status" "MAYBE" "Device is not cloud-joined - consider Azure AD join for enhanced security" "Low"
            }
            
            if ($azureStatus.HybridJoined) {
                Add-Result "Cloud Security" "Hybrid Join" "OK" "Device is hybrid Azure AD joined" "Low"
            }
        }
        
        $intuneEnrolled = Test-Path "HKLM:\SOFTWARE\Microsoft\Enrollments"
        if ($intuneEnrolled) {
            $enrollmentKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -ErrorAction SilentlyContinue
            $mdmEnrollment = $enrollmentKeys | Where-Object { 
                $_.GetValue("ProviderID") -like "*MS DM Server*" -or 
                $_.GetValue("ProviderID") -like "*Microsoft*" 
            }
            Add-Result "Cloud Security" "Intune Enrollment" $(if ($mdmEnrollment) { "OK" } else { "MAYBE" }) "Microsoft Intune enrollment provides centralized management" "Low"
        }
        
        $autopilotInfo = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\Omadm\Accounts" -Name "https://enrollment.manage.microsoft.com"
        Add-Result "Cloud Security" "Autopilot Deployment" $(if ($autopilotInfo) { "OK" } else { "MAYBE" }) "Windows Autopilot provides zero-touch deployment" "Low"
        
        $vpnProfile = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked" -ErrorAction SilentlyContinue
        $status = if ($vpnProfile) { "OK" } else { "MAYBE" }
        Add-Result "Cloud Security" "Microsoft Tunnel VPN" $status "Configure Microsoft Tunnel for secure remote access" "Medium"
    }
    
    if ($IncludeAdvancedThreatDetection) {
        Write-StatusMessage "Performing advanced threat detection analysis..." -Type "Info"
        
        $suspiciousServices = Test-SuspiciousServices
        if ($suspiciousServices.Count -gt 0) {
            Add-ThreatIndicator "Suspicious Service" "Found $($suspiciousServices.Count) potentially suspicious services" "Medium" ($suspiciousServices.Name -join ", ")
            Add-Result "Threat Detection" "Suspicious Services" "BAD" "Review and investigate suspicious services: $($suspiciousServices.Count) found" "High"
        } else {
            Add-Result "Threat Detection" "Suspicious Services" "OK" "No obviously suspicious services detected" "Low"
        }
        
        $suspiciousTasks = Test-SuspiciousScheduledTasks
        if ($suspiciousTasks.Count -gt 0) {
            Add-ThreatIndicator "Suspicious Task" "Found $($suspiciousTasks.Count) potentially suspicious scheduled tasks" "Medium" ($suspiciousTasks.TaskName -join ", ")
            Add-Result "Threat Detection" "Suspicious Tasks" "BAD" "Review suspicious scheduled tasks: $($suspiciousTasks.Count) found" "High"
        } else {
            Add-Result "Threat Detection" "Suspicious Tasks" "OK" "No obviously suspicious scheduled tasks detected" "Low"
        }
        
        $wmiPersistence = Test-WMIPersistence
        if ($wmiPersistence.HasPersistence) {
            Add-ThreatIndicator "WMI Persistence" "WMI event consumers/filters detected" "High" "Filters:$($wmiPersistence.EventFilters) Consumers:$($wmiPersistence.EventConsumers)"
            Add-Result "Threat Detection" "WMI Persistence" "BAD" "WMI persistence mechanisms detected - investigate immediately" "Critical"
        } else {
            Add-Result "Threat Detection" "WMI Persistence" "OK" "No WMI persistence mechanisms detected" "Low"
        }
        
        try {
            $recentLogonFailures = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 -ErrorAction Stop
            $failureCount = $recentLogonFailures.Count
            if ($failureCount -gt 20) {
                Add-ThreatIndicator "Brute Force" "High number of logon failures in past week" "Medium" "$failureCount failed logon attempts"
                Add-Result "Threat Detection" "Logon Failures" "BAD" "$failureCount logon failures in past week - possible brute force" "High"
            } elseif ($failureCount -gt 5) {
                Add-Result "Threat Detection" "Logon Failures" "MAYBE" "$failureCount logon failures in past week - monitor" "Medium"
            } else {
                Add-Result "Threat Detection" "Logon Failures" "OK" "Low number of logon failures detected" "Low"
            }
        }
        catch {
            Add-Result "Threat Detection" "Logon Analysis" "Error" "Unable to analyze recent security events" "Low"
        }
        
        try {
            $connections = Get-NetTCPConnection -State Established -ErrorAction Stop | 
                Where-Object { $_.RemoteAddress -notlike "127.*" -and $_.RemoteAddress -notlike "10.*" -and $_.RemoteAddress -notlike "192.168.*" -and $_.RemoteAddress -ne "::1" }
            
            $suspiciousConnections = $connections | Where-Object { 
                $_.RemotePort -in @(6667, 6668, 6669, 1337, 31337, 8080) -or  
                $_.LocalPort -in @(4444, 5555, 6666, 7777, 8888, 9999)        
            }
            
            if ($suspiciousConnections) {
                Add-ThreatIndicator "Suspicious Connection" "Unusual network connections detected" "High" ($suspiciousConnections.RemoteAddress -join ", ")
                Add-Result "Threat Detection" "Network Connections" "BAD" "Suspicious network connections found - investigate" "High"
            } else {
                Add-Result "Threat Detection" "Network Connections" "OK" "No obviously suspicious network connections" "Low"
            }
        }
        catch {
            Add-Result "Threat Detection" "Network Analysis" "Error" "Unable to analyze network connections" "Low"
        }
    }
    
    Write-StatusMessage "Evaluating data protection controls..." -Type "Info"
    
    $aipClient = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\MSIPC" -Name "InstallDir"
    Add-Result "Data Protection" "Azure Information Protection" $(if ($aipClient) { "OK" } else { "MAYBE" }) "Consider deploying Azure Information Protection for data classification" "Low"
    
    $dlpEndpoint = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Process/Analytic" -Name "Enabled"
    Add-Result "Data Protection" "DLP Monitoring" $(if ($dlpEndpoint -eq 1) { "OK" } else { "MAYBE" }) "Enable process monitoring for DLP capabilities" "Low"
    
    try {
        $fsrmFeature = Get-WindowsFeature -Name FS-Resource-Manager -ErrorAction Stop 2>$null
        if ($fsrmFeature -and $fsrmFeature.InstallState -eq "Installed") {
            Add-Result "Data Protection" "File Screening" "OK" "File Server Resource Manager available for data governance" "Low"
        }
    }
    catch {
        Add-Result "Data Protection" "File Screening" "MAYBE" "Consider File Server Resource Manager for data governance" "Low"
    }
    
    Write-StatusMessage "Evaluating certificate and PKI security..." -Type "Info"
    
    $certChainPolicy = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Name "Flags"
    Add-Result "PKI Security" "Certificate Validation" $(if ($certChainPolicy -eq 1) { "OK" } else { "MAYBE" }) "Enable certificate chain validation policies" "Medium"
    
    $scForceOption = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "scforceoption"
    Add-Result "PKI Security" "Smart Card Logon" $(if ($scForceOption -eq 1) { "OK" } else { "MAYBE" }) "Smart card enforcement not configured - consider for high-security environments" "Low"
    
    $ctLogs = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\CTLs" -Name "DisallowedCert"
    Add-Result "PKI Security" "Certificate Transparency" $(if ($ctLogs) { "OK" } else { "MAYBE" }) "Certificate Transparency logging enhances PKI security" "Low"
    
    Write-StatusMessage "Checking browser security configurations..." -Type "Info"
    
    $edgeSmartScreen = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled"
    Add-Result "Browser Security" "Edge SmartScreen" $(if ($edgeSmartScreen -eq 1) { "OK" } elseif ($edgeSmartScreen -eq 0) { "BAD" } else { "MAYBE" }) "Enable SmartScreen in Microsoft Edge" "Medium"
    
    $edgePasswordManager = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PasswordManagerEnabled"
    Add-Result "Browser Security" "Edge Password Manager" $(if ($edgePasswordManager -eq 0) { "OK" } else { "MAYBE" }) "Consider disabling built-in password manager in favor of enterprise solution" "Low"
    
    $edgeSiteIsolation = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SitePerProcess"
    Add-Result "Browser Security" "Edge Site Isolation" $(if ($edgeSiteIsolation -eq 1) { "OK" } else { "BAD" }) "Enable Edge site isolation" "Medium"
    
    $trackingPrevention = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "TrackingPrevention"
    $status = if ($trackingPrevention -eq 1) { "OK" } else { "BAD" }
    Add-Result "Browser Security" "Edge Tracking Prevention" $status "Enable Edge tracking prevention" "Medium"
    
    $ieEnhancedSecurity = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled"
    Add-Result "Browser Security" "IE Enhanced Security" $(if ($ieEnhancedSecurity -eq 1) { "OK" } else { "BAD" }) "Enable Internet Explorer Enhanced Security Configuration" "Medium"
    
    $ieProtectedMode = Get-RegValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones" -Name "2500"
    $status = if ($ieProtectedMode -eq 0) { "OK" } else { "BAD" }
    Add-Result "Browser Security" "IE Protected Mode" $status "Enable IE protected mode for all zones" "High"
    
    Write-StatusMessage "Evaluating application security controls..." -Type "Info"
    
    try {
        $jeaEndpoints = Get-PSSessionConfiguration -ErrorAction Stop | Where-Object { $_.Permission -notlike "*Full*" }
        Add-Result "Application Security" "JEA Endpoints" $(if ($jeaEndpoints) { "OK" } else { "MAYBE" }) "Consider implementing Just Enough Administration endpoints" "Low"
    }
    catch {
        Add-Result "Application Security" "JEA Endpoints" "MAYBE" "PowerShell JEA endpoints not configured" "Low"
    }
    
    $appContainerProcesses = Get-Process | Where-Object { $_.ProcessName -like "*RuntimeBroker*" -or $_.ProcessName -like "*ApplicationFrameHost*" } -ErrorAction SilentlyContinue
    Add-Result "Application Security" "App Isolation" $(if ($appContainerProcesses) { "OK" } else { "MAYBE" }) "Modern apps are running in AppContainer isolation" "Low"
    
    $authenticodeRequired = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Trust" -Name "WintrustLevel"
    Add-Result "Application Security" "Code Signing" $(if ($authenticodeRequired -eq 0) { "OK" } else { "MAYBE" }) "Authenticode signature verification is active" "Medium"
    
    Write-Progress -Activity "Performing Advanced Security Assessment" -Completed
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Gray
    Write-StatusMessage "Advanced security assessment complete." -Type "Success"
    
    $passCount = ($script:results | Where-Object { $_.Result -eq "OK" }).Count
    $failCount = ($script:results | Where-Object { $_.Result -eq "BAD" }).Count
    $maybeCount = ($script:results | Where-Object { $_.Result -eq "MAYBE" }).Count
    $errorCount = ($script:results | Where-Object { $_.Result -eq "Error" }).Count
    $criticalFailures = ($script:results | Where-Object { $_.Result -eq "BAD" -and $_.RiskLevel -eq "Critical" }).Count
    $highRiskFailures = ($script:results | Where-Object { $_.Result -eq "BAD" -and $_.RiskLevel -eq "High" }).Count
    $totalChecks = $script:results.Count
    
    $score = 0
    if ($totalChecks -gt 0) {
        $weightedScore = 0
        $totalWeight = 0
        
        foreach ($result in $script:results) {
            $weight = switch ($result.RiskLevel) {
                "Critical" { 4.0 }
                "High" { 3.0 }
                "Medium" { 2.0 }
                "Low" { 1.0 }
                default { 1.5 }
            }
            
            $points = switch ($result.Result) {
                "OK" { $weight }
                "MAYBE" { $weight * 0.5 }
                "BAD" { 0 }
                "Error" { $weight * 0.25 }
                default { 0 }
            }
            
            $weightedScore += $points
            $totalWeight += $weight
        }
        
        if ($totalWeight -gt 0) {
            $score = [Math]::Round(($weightedScore / $totalWeight) * 100, 2)
        }
        
        if ($criticalFailures -gt 0) {
            $penalty = [Math]::Min(50, $criticalFailures * 10)
            $score = $score * (1 - $penalty / 100)
        }
        
        if ($highRiskFailures -gt 5) {
            $penalty = [Math]::Min(20, ($highRiskFailures - 5) * 2)
            $score = $score * (1 - $penalty / 100)
        }
        
        $score = [Math]::Max(0, [Math]::Min(100, [Math]::Round($score, 2)))
    }
    
    $securityPosture = switch ($score) {
        { $_ -ge 95 } { "Excellent" }
        { $_ -ge 90 } { "Very Good" }
        { $_ -ge 80 } { "Good" }
        { $_ -ge 70 } { "Acceptable" }
        { $_ -ge 60 } { "Needs Improvement" }
        { $_ -ge 40 } { "Poor" }
        default { "Critical" }
    }
    
    Add-Result "Compliance" "Security Score" "$score%" "Overall weighted security score based on risk levels."
    Add-Result "Compliance" "Security Posture" $securityPosture "Current security posture classification."
    Add-Result "Compliance" "Assessment Duration" "$([Math]::Round(((Get-Date) - $script:startTime).TotalMinutes, 1)) minutes" "Time taken to complete assessment."
    
    Show-ColoredResults -Results $script:results
    
    $displayResults = $script:results | Where-Object { $_.Category -ne "Compliance" } | 
        Sort-Object -Property @{Expression={
            switch ($_.RiskLevel) {
                "Critical" { 1 }
                "High" { 2 }
                "Medium" { 3 }
                "Low" { 4 }
                default { 5 }
            }
        }}, Category, Subcategory |
        ForEach-Object -Begin { $i=1 } -Process { 
            $_ | Add-Member -MemberType NoteProperty -Name '#' -Value $i -PassThru
            $i++ 
        }
    
    Show-ResultsForm -Results $displayResults -Title "Advanced Security Assessment Results" -Score $score -Posture $securityPosture
    
    Write-Host "`n=== ASSESSMENT SUMMARY ===" -ForegroundColor White
    Write-Host "Security Score: $score% ($securityPosture)" -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 60) { "Yellow" } else { "Red" })
    Write-Host "Assessment Duration: $([Math]::Round(((Get-Date) - $script:startTime).TotalMinutes, 1)) minutes"
    Write-Host ""
    Write-Host "Total Checks: $totalChecks"
    Write-Host "Passed: $passCount" -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor Red
    Write-Host "Needs Review: $maybeCount" -ForegroundColor Yellow
    Write-Host "Errors: $errorCount" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Risk Breakdown:"
    Write-Host "Critical Failures: $criticalFailures" -ForegroundColor Red
    Write-Host "High Risk Failures: $highRiskFailures" -ForegroundColor Red
    
    if ($script:threatIndicators.Count -gt 0) {
        Write-Host ""
        Write-Host "=== THREAT INDICATORS SUMMARY ===" -ForegroundColor Red
        $threatsByType = $script:threatIndicators | Group-Object Type
        foreach ($threatType in $threatsByType) {
            Write-Host "$($threatType.Name): $($threatType.Count)" -ForegroundColor Red
        }
    }
    
    Write-Host "`n=== PRIORITY RECOMMENDATIONS ===" -ForegroundColor Yellow
    Write-Host "1. Address all CRITICAL and HIGH risk 'BAD' findings immediately"
    Write-Host "2. Investigate any threat indicators detected during assessment"
    Write-Host "3. Review 'MAYBE' findings based on your security requirements"
    Write-Host "4. Resolve 'Error' findings to ensure complete assessment coverage"
    Write-Host "5. Establish regular assessment schedule (monthly recommended)"
    Write-Host "6. Consider implementing Microsoft Defender for Endpoint if not present"
    Write-Host "7. Enable advanced logging and monitoring capabilities"
    
    if (-not $script:isElevated) {
        Write-Host "`n??  IMPORTANT: Some checks were limited due to insufficient privileges." -ForegroundColor Red
        Write-Host "    Run as administrator for complete security assessment coverage." -ForegroundColor Red
    }
    
    if ($script:threatIndicators.Count -gt 0) {
        Write-Host "`n?? SECURITY ALERT: Threat indicators detected during assessment!" -ForegroundColor Red -BackgroundColor Yellow
        Write-Host "    Immediate investigation and response may be required." -ForegroundColor Red -BackgroundColor Yellow
    }
    
    return $script:results
}

function Show-ResultsForm {
    param(
        [object]$Results,
        [string]$Title,
        [double]$Score,
        [string]$Posture
    )
    
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
    }
    catch {
        Write-Host "Unable to load Windows Forms assembly. Falling back to console output." -ForegroundColor Yellow
        return
    }
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size(1100, 750)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.BackColor = [System.Drawing.Color]::White
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $titleLabel.Size = New-Object System.Drawing.Size(840, 30)
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $scoreColor = switch ($Score) {
        { $_ -ge 90 } { [System.Drawing.Color]::ForestGreen }
        { $_ -ge 70 } { [System.Drawing.Color]::Orange }
        default { [System.Drawing.Color]::Crimson }
    }
    $titleLabel.ForeColor = $scoreColor
    $titleLabel.Text = "Security Score: $Score% ($Posture)"
    $form.Controls.Add($titleLabel)
    
    $summaryLabel = New-Object System.Windows.Forms.Label
    $summaryLabel.Location = New-Object System.Drawing.Point(20, 60)
    $summaryLabel.Size = New-Object System.Drawing.Size(840, 20)
    $summaryLabel.Text = "Assessment completed in $([Math]::Round(((Get-Date) - $script:startTime).TotalMinutes, 1)) minutes with $($Results.Count) checks"
    $form.Controls.Add($summaryLabel)
    
    $dataGridView = New-Object System.Windows.Forms.DataGridView
    $dataGridView.Location = New-Object System.Drawing.Point(20, 90)
    $dataGridView.Size = New-Object System.Drawing.Size(1040, 420)
    $dataGridView.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::AutoSize
    $dataGridView.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $dataGridView.MultiSelect = $false
    $dataGridView.ReadOnly = $true
    $dataGridView.AllowUserToAddRows = $false
    $dataGridView.AllowUserToDeleteRows = $false
    $dataGridView.RowHeadersVisible = $false
    $dataGridView.BackgroundColor = [System.Drawing.Color]::White
    $dataGridView.DefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $dataGridView.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $dataGridView.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $dataGridView.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
    
    $column1 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $column1.Name = "#"
    $column1.HeaderText = "#"
    $column1.Width = 40
    $column1.ReadOnly = $true
    $column1.DefaultCellStyle.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleCenter
    $column1.HeaderCell.Style.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleCenter
    
    $column2 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $column2.Name = "Category"
    $column2.HeaderText = "Category"
    $column2.Width = 120
    $column2.ReadOnly = $true
    $column2.HeaderCell.Style.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleLeft
    
    $column3 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $column3.Name = "Subcategory"
    $column3.HeaderText = "Subcategory"
    $column3.Width = 250
    $column3.ReadOnly = $true
    $column3.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    $column3.HeaderCell.Style.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleLeft
    
    $column4 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $column4.Name = "Result"
    $column4.HeaderText = "Result"
    $column4.Width = 80
    $column4.ReadOnly = $true
    $column4.DefaultCellStyle.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleCenter
    $column4.HeaderCell.Style.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleCenter
    
    $column5 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $column5.Name = "RiskLevel"
    $column5.HeaderText = "Risk"
    $column5.Width = 80
    $column5.ReadOnly = $true
    $column5.DefaultCellStyle.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleCenter
    $column5.HeaderCell.Style.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleCenter
    
    $column6 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $column6.Name = "Remediation"
    $column6.HeaderText = "Remediation"
    $column6.Width = 400
    $column6.ReadOnly = $true
    $column6.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    $column6.HeaderCell.Style.Alignment = [System.Windows.Forms.DataGridViewContentAlignment]::MiddleLeft
    
    $dataGridView.Columns.AddRange($column1, $column2, $column3, $column4, $column5, $column6)
    
    $i = 1
    foreach ($result in $Results) {
        $row = New-Object System.Windows.Forms.DataGridViewRow
        $row.CreateCells($dataGridView)
        
        $row.Cells[0].Value = $i
        $row.Cells[1].Value = $result.Category
        $row.Cells[2].Value = $result.Subcategory
        $row.Cells[3].Value = $result.Result
        $row.Cells[4].Value = $result.RiskLevel
        $row.Cells[5].Value = $result.Remediation
        
        switch ($result.Result) {
            "OK" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(200, 230, 201) }
            "BAD" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 199, 206) }
            "MAYBE" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 235, 156) }
            "Error" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(220, 220, 220) }
        }
        
        switch ($result.RiskLevel) {
            "Critical" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::Crimson; $row.Cells[4].Style.ForeColor = [System.Drawing.Color]::White }
            "High" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::OrangeRed; $row.Cells[4].Style.ForeColor = [System.Drawing.Color]::White }
            "Medium" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::Orange }
            "Low" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::FromArgb(144, 238, 144) }
        }
        
        $dataGridView.Rows.Add($row)
        $i++
    }
    
    $form.Controls.Add($dataGridView)
    
    $filterPanel = New-Object System.Windows.Forms.Panel
    $filterPanel.Location = New-Object System.Drawing.Point(20, 520)
    $filterPanel.Size = New-Object System.Drawing.Size(1040, 60)
    $filterPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::None
    $filterPanel.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
    $form.Controls.Add($filterPanel)
    
    $categoryLabel = New-Object System.Windows.Forms.Label
    $categoryLabel.Location = New-Object System.Drawing.Point(10, 10)
    $categoryLabel.Size = New-Object System.Drawing.Size(60, 20)
    $categoryLabel.Text = "Category:"
    $categoryLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $filterPanel.Controls.Add($categoryLabel)
    
    $categoryComboBox = New-Object System.Windows.Forms.ComboBox
    $categoryComboBox.Location = New-Object System.Drawing.Point(75, 10)
    $categoryComboBox.Size = New-Object System.Drawing.Size(150, 20)
    $categoryComboBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $categoryComboBox.Items.AddRange(("All", "Authentication", "Network Security", "Windows Defender", "Hardware Security"))
    $categoryComboBox.SelectedIndex = 0
    $filterPanel.Controls.Add($categoryComboBox)
    
    $resultLabel = New-Object System.Windows.Forms.Label
    $resultLabel.Location = New-Object System.Drawing.Point(240, 10)
    $resultLabel.Size = New-Object System.Drawing.Size(40, 20)
    $resultLabel.Text = "Result:"
    $resultLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $filterPanel.Controls.Add($resultLabel)
    
    $resultComboBox = New-Object System.Windows.Forms.ComboBox
    $resultComboBox.Location = New-Object System.Drawing.Point(285, 10)
    $resultComboBox.Size = New-Object System.Drawing.Size(100, 20)
    $resultComboBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $resultComboBox.Items.AddRange(("All", "OK", "BAD", "MAYBE", "Error"))
    $resultComboBox.SelectedIndex = 0
    $filterPanel.Controls.Add($resultComboBox)
    
    $riskLabel = New-Object System.Windows.Forms.Label
    $riskLabel.Location = New-Object System.Drawing.Point(400, 10)
    $riskLabel.Size = New-Object System.Drawing.Size(30, 20)
    $riskLabel.Text = "Risk:"
    $riskLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $filterPanel.Controls.Add($riskLabel)
    
    $riskComboBox = New-Object System.Windows.Forms.ComboBox
    $riskComboBox.Location = New-Object System.Drawing.Point(435, 10)
    $riskComboBox.Size = New-Object System.Drawing.Size(100, 20)
    $riskComboBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $riskComboBox.Items.AddRange(("All", "Critical", "High", "Medium", "Low"))
    $riskComboBox.SelectedIndex = 0
    $filterPanel.Controls.Add($riskComboBox)
    
    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.Location = New-Object System.Drawing.Point(550, 10)
    $searchLabel.Size = New-Object System.Drawing.Size(50, 20)
    $searchLabel.Text = "Search:"
    $searchLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $filterPanel.Controls.Add($searchLabel)
    
    $searchTextBox = New-Object System.Windows.Forms.TextBox
    $searchTextBox.Location = New-Object System.Drawing.Point(605, 10)
    $searchTextBox.Size = New-Object System.Drawing.Size(200, 20)
    $searchTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $filterPanel.Controls.Add($searchTextBox)
    
    $applyFilterButton = New-Object System.Windows.Forms.Button
    $applyFilterButton.Location = New-Object System.Drawing.Point(815, 10)
    $applyFilterButton.Size = New-Object System.Drawing.Size(75, 20)
    $applyFilterButton.Text = "Apply"
    $applyFilterButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $applyFilterButton.BackColor = [System.Drawing.Color]::FromArgb(173, 216, 230)
    $filterPanel.Controls.Add($applyFilterButton)
    
    $resetFilterButton = New-Object System.Windows.Forms.Button
    $resetFilterButton.Location = New-Object System.Drawing.Point(900, 10)
    $resetFilterButton.Size = New-Object System.Drawing.Size(75, 20)
    $resetFilterButton.Text = "Reset"
    $resetFilterButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $resetFilterButton.BackColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $filterPanel.Controls.Add($resetFilterButton)
    
    $applyFilterButton.Add_Click({
        $categoryFilter = $categoryComboBox.SelectedItem
        $resultFilter = $resultComboBox.SelectedItem
        $riskFilter = $riskComboBox.SelectedItem
        $searchText = $searchTextBox.Text.ToLower()
        
        $dataGridView.Rows.Clear()
        
        $i = 1
        foreach ($result in $Results) {
            if ($categoryFilter -ne "All" -and $result.Category -ne $categoryFilter) { continue }
            if ($resultFilter -ne "All" -and $result.Result -ne $resultFilter) { continue }
            if ($riskFilter -ne "All" -and $result.RiskLevel -ne $riskFilter) { continue }
            if ($searchText -ne "" -and 
                $result.Category.ToLower().Contains($searchText) -eq $false -and 
                $result.Subcategory.ToLower().Contains($searchText) -eq $false -and 
                $result.Remediation.ToLower().Contains($searchText) -eq $false) { continue }
            
            $row = New-Object System.Windows.Forms.DataGridViewRow
            $row.CreateCells($dataGridView)
            
            $row.Cells[0].Value = $i
            $row.Cells[1].Value = $result.Category
            $row.Cells[2].Value = $result.Subcategory
            $row.Cells[3].Value = $result.Result
            $row.Cells[4].Value = $result.RiskLevel
            $row.Cells[5].Value = $result.Remediation
            
            switch ($result.Result) {
                "OK" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(200, 230, 201) }
                "BAD" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 199, 206) }
                "MAYBE" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 235, 156) }
                "Error" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(220, 220, 220) }
            }
            
            switch ($result.RiskLevel) {
                "Critical" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::Crimson; $row.Cells[4].Style.ForeColor = [System.Drawing.Color]::White }
                "High" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::OrangeRed; $row.Cells[4].Style.ForeColor = [System.Drawing.Color]::White }
                "Medium" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::Orange }
                "Low" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::FromArgb(144, 238, 144) }
            }
            
            $dataGridView.Rows.Add($row)
            $i++
        }
    })
    
    $resetFilterButton.Add_Click({
        $categoryComboBox.SelectedIndex = 0
        $resultComboBox.SelectedIndex = 0
        $riskComboBox.SelectedIndex = 0
        $searchTextBox.Text = ""
        
        $dataGridView.Rows.Clear()
        
        $i = 1
        foreach ($result in $Results) {
            $row = New-Object System.Windows.Forms.DataGridViewRow
            $row.CreateCells($dataGridView)
            
            $row.Cells[0].Value = $i
            $row.Cells[1].Value = $result.Category
            $row.Cells[2].Value = $result.Subcategory
            $row.Cells[3].Value = $result.Result
            $row.Cells[4].Value = $result.RiskLevel
            $row.Cells[5].Value = $result.Remediation
            
            switch ($result.Result) {
                "OK" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(200, 230, 201) }
                "BAD" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 199, 206) }
                "MAYBE" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 235, 156) }
                "Error" { $row.Cells[3].Style.BackColor = [System.Drawing.Color]::FromArgb(220, 220, 220) }
            }
            
            switch ($result.RiskLevel) {
                "Critical" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::Crimson; $row.Cells[4].Style.ForeColor = [System.Drawing.Color]::White }
                "High" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::OrangeRed; $row.Cells[4].Style.ForeColor = [System.Drawing.Color]::White }
                "Medium" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::Orange }
                "Low" { $row.Cells[4].Style.BackColor = [System.Drawing.Color]::FromArgb(144, 238, 144) }
            }
            
            $dataGridView.Rows.Add($row)
            $i++
        }
    })
    
    $buttonCSV = New-Object System.Windows.Forms.Button
    $buttonCSV.Location = New-Object System.Drawing.Point(20, 590)
    $buttonCSV.Size = New-Object System.Drawing.Size(100, 40)
    $buttonCSV.Text = "Export CSV"
    $buttonCSV.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $buttonCSV.BackColor = [System.Drawing.Color]::FromArgb(173, 216, 230)
    $form.Controls.Add($buttonCSV)
    
    $buttonJSON = New-Object System.Windows.Forms.Button
    $buttonJSON.Location = New-Object System.Drawing.Point(130, 590)
    $buttonJSON.Size = New-Object System.Drawing.Size(100, 40)
    $buttonJSON.Text = "Export JSON"
    $buttonJSON.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $buttonJSON.BackColor = [System.Drawing.Color]::FromArgb(173, 216, 230)
    $form.Controls.Add($buttonJSON)
    
    $buttonHTML = New-Object System.Windows.Forms.Button
    $buttonHTML.Location = New-Object System.Drawing.Point(240, 590)
    $buttonHTML.Size = New-Object System.Drawing.Size(100, 40)
    $buttonHTML.Text = "Export HTML"
    $buttonHTML.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $buttonHTML.BackColor = [System.Drawing.Color]::FromArgb(173, 216, 230)
    $form.Controls.Add($buttonHTML)
    
    $darkModeButton = New-Object System.Windows.Forms.Button
    $darkModeButton.Location = New-Object System.Drawing.Point(350, 590)
    $darkModeButton.Size = New-Object System.Drawing.Size(100, 40)
    $darkModeButton.Text = "Dark Mode"
    $darkModeButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $darkModeButton.BackColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $form.Controls.Add($darkModeButton)
    
    $buttonClose = New-Object System.Windows.Forms.Button
    $buttonClose.Location = New-Object System.Drawing.Point(920, 590)
    $buttonClose.Size = New-Object System.Drawing.Size(100, 40)
    $buttonClose.Text = "Close"
    $buttonClose.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $buttonClose.BackColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $form.Controls.Add($buttonClose)
    
    $buttonCSV.Add_Click({
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "CSV files (*.csv)|*.csv"
        $saveFileDialog.Title = "Export Results to CSV"
        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $Results | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation -Force
                [System.Windows.Forms.MessageBox]::Show("Results exported successfully to CSV file.", "Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Error exporting to CSV: $($_.Exception.Message)", "Export Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    })
    
    $buttonJSON.Add_Click({
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "JSON files (*.json)|*.json"
        $saveFileDialog.Title = "Export Results to JSON"
        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $exportData = [PSCustomObject]@{
                    AssessmentInfo = @{
                        Timestamp = Get-Date
                        Duration = "$([Math]::Round(((Get-Date) - $script:startTime).TotalMinutes, 1)) minutes"
                        Score = $Score
                        Posture = $Posture
                        TotalChecks = $Results.Count
                    }
                    Results = $Results
                    ThreatIndicators = $script:threatIndicators
                }
                $exportData | ConvertTo-Json -Depth 5 | Set-Content -Path $saveFileDialog.FileName -Force
                [System.Windows.Forms.MessageBox]::Show("Results exported successfully to JSON file.", "Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Error exporting to JSON: $($_.Exception.Message)", "Export Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    })
    
    $buttonHTML.Add_Click({
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "HTML files (*.html)|*.html"
        $saveFileDialog.Title = "Export Results to HTML"
        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $head = @'
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f8f9fa; }
.header { background-color: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
.score { font-size: 24px; font-weight: bold; }
.summary { background-color: #ecf0f1; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; box-shadow: 0 2px 3px rgba(0,0,0,0.1); }
th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
th { background-color: #34495e; color: white; }
tr:nth-child(even) { background-color: #f2f2f2; }
tr.OK td:nth-child(4) { background-color: #2ecc71; color: white; font-weight: bold; }
tr.BAD td:nth-child(4) { background-color: #e74c3c; color: white; font-weight: bold; }
tr.MAYBE td:nth-child(4) { background-color: #f39c12; color: white; font-weight: bold; }
tr.Error td:nth-child(4) { background-color: #95a5a6; color: white; font-weight: bold; }
.risk-critical { border-left: 5px solid #e74c3c; }
.risk-high { border-left: 5px solid #e67e22; }
.risk-medium { border-left: 5px solid #f39c12; }
.risk-low { border-left: 5px solid #27ae60; }
.threat-indicators { background-color: #ffebee; border: 2px solid #f44336; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
</style>
'@
                
                $htmlBody = @"
<div class="header">
    <h1>Advanced Windows Security Assessment Report</h1>
    <div class="score">Security Score: $Score% ($Posture)</div>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
</div>
<div class="summary">
    <h2>Assessment Summary</h2>
    <p><strong>Duration:</strong> $([Math]::Round(((Get-Date) - $script:startTime).TotalMinutes, 1)) minutes</p>
    <p><strong>Total Checks:</strong> $($Results.Count)</p>
</div>
"@
                
                if ($script:threatIndicators.Count -gt 0) {
                    $htmlBody += @"
<div class="threat-indicators">
    <h2>?? Threat Indicators Detected</h2>
    <ul>
"@
                    foreach ($indicator in $script:threatIndicators) {
                        $htmlBody += "<li><strong>[$($indicator.Severity)] $($indicator.Type):</strong> $($indicator.Description)</li>"
                    }
                    $htmlBody += "</ul></div>"
                }
                
                $resultsTable = $Results | ConvertTo-Html -Property Category, Subcategory, RiskLevel, Result, Remediation -Fragment
                $resultsTable = $resultsTable -replace '<tr><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td><td>(OK)</td>', '<tr class="OK risk-$($3.ToLower())"><td>$1</td><td>$2</td><td>$3</td><td>$4</td>'
                $resultsTable = $resultsTable -replace '<tr><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td><td>(BAD)</td>', '<tr class="BAD risk-$($3.ToLower())"><td>$1</td><td>$2</td><td>$3</td><td>$4</td>'
                $resultsTable = $resultsTable -replace '<tr><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td><td>(MAYBE)</td>', '<tr class="MAYBE risk-$($3.ToLower())"><td>$1</td><td>$2</td><td>$3</td><td>$4</td>'
                $resultsTable = $resultsTable -replace '<tr><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td><td>(Error)</td>', '<tr class="Error risk-$($3.ToLower())"><td>$1</td><td>$2</td><td>$3</td><td>$4</td>'
                
                $htmlBody += "<h2>Detailed Results</h2>" + $resultsTable
                
                $html = ConvertTo-Html -Head $head -Body $htmlBody -Title "Security Assessment Report"
                $html | Out-File -FilePath $saveFileDialog.FileName -Force
                [System.Windows.Forms.MessageBox]::Show("Results exported successfully to HTML file.", "Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Error exporting to HTML: $($_.Exception.Message)", "Export Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    })
    
    $darkModeButton.Add_Click({
        if ($form.BackColor -eq [System.Drawing.Color]::White) {
            $form.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
            $form.ForeColor = [System.Drawing.Color]::White
            
            $titleLabel.ForeColor = [System.Drawing.Color]::White
            $summaryLabel.ForeColor = [System.Drawing.Color]::White
            
            $dataGridView.BackgroundColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
            $dataGridView.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
            $dataGridView.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
            $dataGridView.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
            $dataGridView.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
            $dataGridView.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(70, 70, 70)
            
            $filterPanel.BackColor = [System.Drawing.Color]::FromArgb(55, 55, 55)
            
            $darkModeButton.Text = "Light Mode"
        }
        else {
            $form.BackColor = [System.Drawing.Color]::White
            $form.ForeColor = [System.Drawing.Color]::Black
            
            $titleLabel.ForeColor = $scoreColor
            $summaryLabel.ForeColor = [System.Drawing.Color]::Black
            
            $dataGridView.BackgroundColor = [System.Drawing.Color]::White
            $dataGridView.DefaultCellStyle.BackColor = [System.Drawing.Color]::White
            $dataGridView.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
            $dataGridView.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
            $dataGridView.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
            $dataGridView.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248, 248, 248)
            
            $filterPanel.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
            
            $darkModeButton.Text = "Dark Mode"
        }
    })
    
    $buttonClose.Add_Click({
        $form.Close()
    })
    
    $form.Add_Shown({$form.Activate()})
    [void]$form.ShowDialog()
}

if ($MyInvocation.InvocationName -ne '.') {
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host "Advanced Windows Client Security Assessment Tool v3.1" -ForegroundColor Green
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host ""
    
    $assessmentResults = Invoke-AdvancedClientSecurityChecks
    
    $complianceResult = $assessmentResults | Where-Object { $_.Category -eq "Compliance" -and $_.Subcategory -eq "Security Score" }
    if ($complianceResult) {
        $score = [double]($complianceResult.Result -replace '%', '')
        $criticalIssues = ($assessmentResults | Where-Object { $_.Result -eq "BAD" -and $_.RiskLevel -eq "Critical" }).Count
        $threatCount = $script:threatIndicators.Count
        
        if ($threatCount -gt 0 -or $criticalIssues -gt 0) {
            exit 4
        } elseif ($score -lt 60) {
            exit 3
        } elseif ($score -lt 70) {
            exit 2
        } elseif ($score -lt 90) {
            exit 1
        } else {
            exit 0
        }
    } else {
        exit 5
    }
}

}

# Example usage: Call the function to start the interactive menu
Get-SecurityAssessmentReport