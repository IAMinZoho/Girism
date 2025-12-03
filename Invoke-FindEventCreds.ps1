Function Invoke-FindEventCreds {

<#
.SYNOPSIS
    Parses Security and Sysmon event logs on locally or on a remote computer to extract credentials passed on the command line.

.DESCRIPTION
    Invoke-FindEventCreds connects to either the local or a remote computers Security log (Event ID 4688) and Sysmon Operational log (Event ID 1),
    parses each process creation event’s command‑line string, and matches it against a library of regex patterns for common 
    binaries (net, schtasks, wmic, psexec, sc.exe, etc.). 

.PARAMETER ComputerName
    The target computer to query.  If omitted or $null, defaults to the local machine ($env:COMPUTERNAME).

.NOTES
    - Requires local administrator or SYSTEM privileges to local or remote system for successful querys
    - Sysmon must be installed and configured to log ProcessCreate (Event ID 1) for the Sysmon portion to return data
    - Audit Process Creation must be enabled under Advanced Audit Policy Configuration for event ID 4688 to be populated

.EXAMPLE
    # Query the local machine
    Invoke-FindEventCreds

.EXAMPLE
    # Query a remote server named WEB01
    Invoke-FindEventCreds -ComputerName WEB01
#>

    param ([string] $ComputerName)

    if ($ComputerName -ne $Null) {
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
        $Admin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $System = $CurrentUser.Name -eq "NT AUTHORITY\SYSTEM"

        if (-not $Admin -and -not $System) {

            Write-Output "`n [!] Local Administrator or SYSTEM privileges required"
            break
        }
    }

$CredentialPairRegexPatterns = @(
    # ---- Core Windows binaries ----
    'net\s+user\s+(?<username>[^\s]+)\s+(?<password>[^\s]+)',
    'net\s+use\s+\S+\s+(?<password>[^\s]+)\s+/user:(?<username>[^\s]+)',
    'schtasks.+/(?:RU|U)\s+(?<username>[^\s]+).+/(?:RP|P)\s+(?<password>[^\s]+)',
    'wmic.+/user:\s*(?<username>[^\s]+).+/password:\s*(?<password>[^\s]+)',
    'psexec.+-u\s+(?<username>[^\s]+).+-p\s+(?<password>[^\s]+)',
    'cmdkey\s+/(?:add|generic):\S+\s+/user:(?<username>[^\s]+)\s+/pass:(?<password>[^\s]+)',
    'bitsadmin.+/setcredentials\s+\S+\s+(?:SERVER|PROXY)\s+\S+\s+(?<username>[^\s]+)\s+(?<password>[^\s]+)',
    'sc\.exe\s+(?:config|create).+?\bobj=\s*(?<username>[^\s]+)\s+password=\s*(?<password>[^\s]+)',

    # ---- Installers ----
    'msiexec.+\bUSERNAME=(?<username>[^\s]+).+PASSWORD=(?<password>[^\s]+)',

    # ---- Domain / trust tools ----
    'netdom\s+(?:join|trust)\b[^\r\n]+/userD:(?<username>[^\s]+)\s+/passwordD:(?<password>[^\s]+)',
    'nltest\b[^\r\n]+/user:(?<username>[^\s]+)\s+/password:(?<password>[^\s]+)',

    # ---- PuTTY family (command-line) ----
    'plink\b.*?(?<username>[^\s]+)@[^\s]+\s+-pw\s+(?<password>[^\s]+)',
    'plink\b.*?-u\s+(?<username>[^\s]+).+-pw\s+(?<password>[^\s]+)',
    'pscp\b.*?-pw\s+(?<password>[^\s]+).+?(?<username>[^\s]+)@',
    'psftp\b.*?-pw\s+(?<password>[^\s]+).+?(?<username>[^\s]+)@',
    'putty\b.*?-ssh\s+(?<username>[^\s]+)@[^\s]+\s+-pw\s+(?<password>[^\s]+)',

    # ---- Database CLIs ----
    'sqlcmd\b.+-U\s+(?<username>[^\s]+)\s+-P\s+(?<password>[^\s]+)',
    'osql\b.+-U\s+(?<username>[^\s]+)\s+-P\s+(?<password>[^\s]+)',
    'mysql\b.+-u\s*(?<username>[^\s]+)\s+-p(?<password>[^\s]+)',

    # ---- Web tools ----
    'curl\b.+?-u\s+(?<username>[^:\s]+):(?<password>[^\s]+)',
    'wget\b.+?--user=(?<username>[^\s]+)\s+--password=(?<password>[^\s]+)',

    # ---- Event / cert utilities ----
    'wevtutil\b.+/u:(?<username>[^\s]+)\s+/p:(?<password>[^\s]+)',
    'eventcreate\b.+/u\s+(?<username>[^\s]+)\s+/p\s+(?<password>[^\s]+)',
    'certreq\b.+-username\s+(?<username>[^\s]+)\s+-p(?:assword)?\s+(?<password>[^\s]+)',
    'certutil\b.+-username\s+(?<username>[^\s]+)\s+-p(?:assword)?\s+(?<password>[^\s]+)',

    # ---- VPN / sync ----
    'rasdial\s+\S+\s+(?<username>[^\s]+)\s+(?<password>[^\s]+)',
    'vpncmd\b.+/USER:(?<username>[^\s]+)\s+/PASSWORD:(?<password>[^\s]+)',
    'rsync\b.+--password-file=(?<password>[^\s]+)\s+(?<username>[^\s]+)@',

    # ---- Generic patterns ----
    '(?:(?:-u|--?user(?:name)?)\s+(?<username>[^\s]+))[^\\r\\n]+?(?:(?:-p|--?pass(?:word)?)\s+(?<password>[^\s]+))',
    '(?:--username=(?<username>[^\s]+))[^\\r\\n]+?(?:--password=(?<password>[^\s]+))',
    '(?:(?:(?:-u)|(?:-user)|(?:-username)|(?:--user)|(?:--username)|(?:/u)|(?:/USER)|(?:/USERNAME))(?:\s+|:)(?<username>[^\s]+))',
    '(?:(?:(?:-p)|(?:-password)|(?:-passwd)|(?:--password)|(?:--passwd)|(?:/P)|(?:/PASSWD)|(?:/PASS)|(?:/CODE)|(?:/PASSWORD))(?:\s+|:)(?<password>[^\s]+))'
)

    function Get-Md5Hash {
        param([string]$InputText)
        $Md5Hasher = [System.Security.Cryptography.MD5]::Create()
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
        $HashBytes = $Md5Hasher.ComputeHash($Bytes)
        return ([BitConverter]::ToString($HashBytes) -replace '-', '').ToLower()
    }


    if ($ComputerName -eq $Null) { $ComputerName = $env:COMPUTERNAME }

    # Parse system security logs for Event ID 4688
    $SecurityResults = Get-WinEvent -ComputerName "$ComputerName" -FilterHashtable @{LogName = 'Security'; ID = 4688 } -ErrorAction "SilentlyContinue" | ForEach-Object -ErrorAction "SilentlyContinue" {
    
        $EventXml = [XML]$_.ToXml()
        $EventDataItems = $EventXml.Event.EventData.Data
        $CommandLineNode = $EventDataItems | Where-Object Name -in 'ProcessCommandLine', 'CommandLine' | Select-Object -First 1

        if (-not $CommandLineNode -or [string]::IsNullOrWhiteSpace($CommandLineNode.'#text')) {
            return
        }
    
        $CommandLine = $CommandLineNode.'#text'

        foreach ($RegexPattern in $CredentialPairRegexPatterns) {
            if ($CommandLine -match $RegexPattern) {
                if ($Matches['username'] -and $Matches['password']) {
                    $CredentialsKey = "$($Matches['username'])|$($Matches['password'])"
                    $CredentialsHash = Get-Md5Hash $CredentialsKey

                    [PSCustomObject]@{
                        TimeCreated       = $_.TimeCreated
                        AccountName       = ($EventDataItems | Where-Object Name -eq 'SubjectUserName').'#text'
                        ProcessName       = ($EventDataItems | Where-Object Name -eq 'NewProcessName').'#text'
                        ParentProcessName = ($EventDataItems | Where-Object Name -eq 'ParentProcessName').'#text'
                        CommandLine       = $CommandLine
                        Hash              = $CredentialsHash
                    }
                }
                break
            }
        }
    } |

    Group-Object -Property "Hash" | ForEach-Object { $_.Group[0] } | Select-Object -Property "*" -ExcludeProperty "Hash" | Sort-Object "TimeCreated" -Descending | Format-List

    # Parse Sysmon Logs for EventID 1
    $SysmonResults = Get-WinEvent -ComputerName "$ComputerName" -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[(EventID=1)]]" -ErrorAction "SilentlyContinue" | ForEach-Object -ErrorAction "SilentlyContinue" {
    
        $EventXml = [XML]$_.ToXml()
        $EventDataItems = $EventXml.Event.EventData.Data
        $CommandLine = ($EventDataItems | Where-Object Name -eq 'CommandLine').'#text'

        if ([string]::IsNullOrWhiteSpace($CommandLine)) { return }

        foreach ($RegexPattern in $CredentialPairRegexPatterns) {
            if ($CommandLine -match $RegexPattern) {
                if ($Matches['username'] -and $Matches['password']) {
                    $CredentialsKey = "$($Matches['username'])|$($Matches['password'])"
                    $CredentialsHash = Get-Md5Hash $CredentialsKey

                    [PSCustomObject]@{
                        TimeCreated       = $_.TimeCreated
                        AccountName       = ($EventDataItems | Where-Object Name -eq 'User').'#text'
                        ProcessName       = ($EventDataItems | Where-Object Name -eq 'Image').'#text'
                        ParentProcessName = ($EventDataItems | Where-Object Name -eq 'ParentImage').'#text'
                        CommandLine       = $CommandLine
                        Hash              = $CredentialsHash
                    }

                }
                break
            }
        }
    } |

    Group-Object -Property "Hash" | ForEach-Object { $_.Group[0] } | Select-Object -Property "*" -ExcludeProperty "Hash" | Sort-Object "TimeCreated" -Descending | Format-List

    if ($SysmonResults  ) { $SysmonResults }
    if ($SecurityResults) { $SecurityResults }

    if (!$SysmonResults -and (!$SecurityResults)) { return "`nNo Results" }

}
