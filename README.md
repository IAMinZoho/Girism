# Girism
*Automating Penetration testing of Active Directory*

Import-Module .\Girism.ps1
Type Girism and then allow the script to load into the current Powershell session.
Follow the on-screen instructions afterwards.

IEX:

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/IAMinZoho/Girism/main/Girism.ps1'))
