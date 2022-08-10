# Girism
*Automating Penetration testing of Active Directory*

Import-Module .\Girism.ps1
Type Girism and then allow the script to load into the current Powershell session.
Follow the on-screen instructions afterwards.

IEX:

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/IAMinZoho/Girism/main/Girism.ps1'))

##Empty password in Active Directory: I found out that the reason for an empty password in Active Directory can be found here – in the UserAccountControl Attribute.
In this attribute the flag “PASSWD_NOTREQD” can be set. If this flag is set, a domain administrator can issue an empty password, evading the password policy.
For accounts with the flag “PASSWD_NOTREQD” set, the attribute “UserAccountControl” has the value 544.
