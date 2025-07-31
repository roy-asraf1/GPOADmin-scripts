# ------------------------------------------------------------------------
# <copyright file="GPOADmin.MinimumPermissions.ps1" company="Quest Software Inc.">
#
# QUEST SOFTWARE PROPRIETARY INFORMATION
#
# This software is confidential.  Quest Software Inc., or one of its
# subsidiaries, has supplied this software to you under terms of a
# license agreement, nondisclosure agreement or both.
#
# You may not copy, disclose, or use this software except in accordance with
#  those terms.
#
#
# Copyright 2023 Quest Software Inc.
# ALL RIGHTS RESERVED.
#
# QUEST SOFTWARE INC. MAKES NO REPRESENTATIONS OR
# WARRANTIES ABOUT THE SUITABILITY OF THE SOFTWARE,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE IMPLIED WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, OR 
# NON-INFRINGEMENT.  QUEST SOFTWARE SHALL NOT BE 
# LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE
# AS A RESULT OF USING, MODIFYING OR DISTRIBUTING
# THIS SOFTWARE OR ITS DERIVATIVES.
#
# </copyright>
# ------------------------------------------------------------------------

Param(
[Parameter(Mandatory=$true)][string]$ServiceAccount,
[Parameter(Mandatory=$true)][string]$Domain,
[Parameter(Mandatory=$true)][string]$LDAPServer,
[Parameter(Mandatory=$true)][string]$Permissions,
[Parameter(Mandatory=$false)][Switch]$Revoke,
[Parameter(Mandatory=$false)][Switch]$Report,
[Parameter(Mandatory=$false)][Switch]$Confirm)

[Flags()]enum Permission
{
    NONE = 0                # Default value
    DELETE = 1              # Grants the "Delete Subtree" right to the service account on each Group Policy Object
    GPO = 2		            # Grants "Create GPOs" to the service account at the domain level
	GPOEDIT	= 4	            # Grants "Edit settings, Delete, Modify security" to the service account on each Group Policy Object
	GPOOWNER = 8            # Assigns the service account as the owner on each Group Policy Object
    GPOMODEL = 16           # Grants the ability for the service account to create the application directory for GPO Modeling Report 
    INSTALL = 32            # Grants "Full Control" to the service account on the install directory
    LINK = 64	            # Grants "Link GPOs" to the service account at the Site, Domain, and OU level
    REGISTRY = 128          # Grants "Full Control" to the service account to HKLM\SOFTWARE\Quest\GPOADmin
				            # Grants "Query Value, Set Value, Create SubKey, Enumerate SubKeys, Delete, and Read Control" to the service account to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics
				            # Grants "Query Value, Set Value, Create SubKey, Enumerate SubKeys, Delete, and Read Control" to the service account to HKLM\SYSTEM\CurrentControlSet\Service\EventLog
    REPLICATION = 256       # Grants “Replicating directory changes" on the Default and Configuration naming contexts (for the Watcher Service)
    RSOP = 512              # Grants "Read Group Polcy Results Data" to the service account at the domain level
    SCP = 1024	            # Grants "Create and Delete serviceConnectionPoint objects" to the service account.
	SCRIPT = 2048           # Grants "List folder contents, Read, and Write" to the service account on the scripts container in SYSVOL
    SPN = 4096              # Grants "Read and Write servicePrincipalName" to the service account.
	STARTERGPO = 8192       # Grants "Create Starter GPOs" to the service account at the domain level and grants the service account Modify, TakeOwnership, and Synchronize on the Starter GPO directory in SYSVOL
	STARTERGPOOWNER = 16384 # Assigns the service account as the owner on each Starter GPO
	WMI = 32768             # Grants "Full Control" to the service account on all WMI Filters
    ALL = 65535             # Grants all of the above
}

enum GPMPermission
{
    GPOApply = 0x10000
    GPORead = 65792
    GPOEdit = 65793
    GPOEditSecurityAndDelete = 65794
    GPOCustom = 65795
    WMIFilterEdit = 0x20000
    WMIFilterFullControl = 131073
    WMIFilterCustom = 131074
    SOMLink = 1835008
    SOMLogging = 1573120
    SOMPlanning = 1573376
    SOMWMICreate = 1049344
    SOMWMIFullControl = 1049345
    SOMGPOCreate = 1049600
    StarterGPORead = 197888
    StarterGPOEdit = 197889
    StarterGPOFullControl = 197890
    StarterGPOCustom = 197891
    SOMStarterGPOCreate = 1049856
}

enum PromptResult
{
    Yes = 0
    YesToAll = 1
    No = 2
    NoToAll = 3
    Cancel = 4
}

Function GetConfirmation
{
    $questionString = "Would you like to proceed?"
    $yesResponse = "[Y] Yes"
    $yesToAllResponse = "[A] Yes to All"
    $noResponse = "[N] No"
    $noToAllResponse = "[L] No to All"
    $cancelResponse = "[C] Cancel"
    $helpText = "[?] Help (default is ""Y"")"
    $helpResponse = '
Y - Continue for this item only.
A - Continue with all the items in this operation.
N - Skip this item and proceed with the next item.
L - Skip this item and all subsequent items.
C - Cancel this operation.
'
    Write-Host $questionString -ForegroundColor White
    Write-Host $yesResponse -ForegroundColor Yellow -NoNewline
    Write-Host "  $yesToAllResponse  $noResponse  $noToAllResponse  $cancelResponse" -ForegroundColor White -NoNewline
    Write-Host "  $($helpText):" -NoNewline
    $userResponse = (Read-Host).ToUpper()

    switch ($userResponse) 
    {
        "" { return [PromptResult]::Yes }
        "Y" { return [PromptResult]::Yes }
        "A" { return [PromptResult]::YesToAll }
        "N" { return [PromptResult]::No }
        "L" { return [PromptResult]::NoToAll }
        "C" { return [PromptResult]::Cancel }
        "?" { Write-Host $helpResponse
              return GetConfirmation $action
            }
        Default { Write-Host "Invalide Response"
                return GetConfirmation $action
            }
    }
}

Function GetLocalComputerLDAPPath
{
    $computerPrincipal = [System.DirectoryServices.AccountManagement.ComputerPrincipal]::FindByIdentity((new-object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain)), $env:COMPUTERNAME)
    return $computerPrincipal.GetUnderlyingObject().Path
}

Function GetTrusteeLDAPPath
{
    $userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity((new-object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain)), [System.DirectoryServices.AccountManagement.IdentityType]::Sid, $gpmTrusteeSid.TrusteeSid)
    return $userPrincipal.GetUnderlyingObject().Path
}

## Group Membership ##
Function VerifyGroupMembership
{
    param( [string] $groupName)
    
    $Script:result = $false

    Trap
	{
		$Script:result = $false
	}

    $principalContext = $null

    try
    {
        $principalContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain)
        $group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($principalContext, $groupName)
        if ($group -ne $null)
        {
            $Script:result = $group.Members.Contains($principalContext, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $newNTOwner)
        }
    }
    finally
    {
        if($principalContext -ne $null -and $principalContext -is [System.IDisposable])
        {
            $principalContext.Dispose()
        }
    }

    return $Script:result
}

Function UpdateGroupMembership
{
    param(
        [string] $groupName,
        [ref]$promptResult)

    $Script:result = $true

    Trap
	{
		$Script:result = $false
	}

if ($promptResult.Value -ne [PromptResult]::YesToAll -and $Confirm.IsPresent)
    {
        $promptResult.Value = GetConfirmation
    }

    if ($promptResult.Value -eq [PromptResult]::Yes -or $promptResult.Value -eq [PromptResult]::YesToAll)
    {
        $principalContext = $null

        try
        {
            $principalContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain)
            $group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($principalContext, $groupName)
            if ($group -ne $null)
            {
                $isMember = $group.Members.Contains($principalContext, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $newNTOwner)

                if($isMember -and $Revoke.IsPresent)
                {
    	            $group.Members.Remove($principalContext, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $newNTOwner)
                    $hasChanged = $true
                }
                elseif(-not $isMember -and $Revoke.IsPresent)
                {
                    Write-Host -ForegroundColor Yellow "The service account '$ServiceAccount' is not a member."
                    return "Skipped"
                }
                elseif (-not $isMember -and -not $Revoke.IsPresent)
                {
                    $group.Members.Add($principalContext, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $newNTOwner)
                    $hasChanged = $true
                }
                else
                {
                    Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' is already a member."
                    return "Skipped"
                }

                if ($hasChanged)
                {
	                $group.Save()
                }
            }
            else
            {
                Write-Error -Message "Could not find the group '$groupName."
                $Script:result = $false
            }
        }
        finally
        {
            if($principalContext -ne $null -and $principalContext -is [System.IDisposable])
            {
                $principalContext.Dispose()
            }
        }
    }

    return $Script:result
}

## GPO Owner ##
Function VerifyGPOOwner
{
	param( [System.Object] $gpo)
	$Script:result = $false
	
    Trap
	{
		$Script:result = $false
	}
    
    $ldapPath = "LDAP://" + $LDAPServer + "/" + $gpo.Path
    $de = new-object System.DirectoryServices.DirectoryEntry $ldapPath
    $currentOwner = $de.ObjectSecurity.GetOwner([System.Security.Principal.SecurityIdentifier])

	return $currentOwner.Value.Equals($gpmTrusteeSid.TrusteeSid)
}

Function UpdateGPOOwner
{
	param(
        [System.Object] $gpo,
        [ref]$promptResult)

	$Script:result = $true

	Trap
	{
		$Script:result = $false
	}

    if ($promptResult.Value -ne [PromptResult]::YesToAll -and $Confirm.IsPresent)
    {
        $promptResult.Value = GetConfirmation
    }

    if ($promptResult.Value -eq [PromptResult]::Yes -or $promptResult.Value -eq [PromptResult]::YesToAll)
    {
        $ldapPath = "LDAP://" + $LDAPServer + "/" + $gpo.Path
        $de = new-object System.DirectoryServices.DirectoryEntry $ldapPath
        $currentOwner = $de.ObjectSecurity.GetOwner([System.Security.Principal.SecurityIdentifier])

	    if ($currentOwner.Value.Equals($gpmTrusteeSid.TrusteeSid) -ne $true)
        {
            $de.ObjectSecurity.SetOwner($newNTOwner)
            $de.CommitChanges()
        }
        else
        {
            Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' is already the owner."
            return "Skipped"
        }
    }	
  
	return $Script:result
}

Function SetGPOOwner
{
    Write-Host
    Write-Host -ForegroundColor White "********** GPO Owner **********"
    Write-Host

    if ($Revoke.IsPresent)
    {
        Write-Host -ForegroundColor Yellow "Revoke not applicable to ownership. Re-run the script specifying the account who is to become the owner in the ServiceAccount parameter."
        return
    }

    $gpmSearchCriteria = $gpm.CreateSearchCriteria()
    
    Write-Host "Enumerating the GPOs in the domain '$Domain'...Please wait."
    $gpmGPOs = $gpmDomain.SearchGPOs($gpmSearchCriteria)
    $count = $gpmGPOs.Count
    Write-host "$count GPOs discovered."
    $confirmResult = [PromptResult]::Yes

    $index = 1
    foreach( $gpmGPO in $gpmGPOs)
    {
        if ($Report.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' is the owner of the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
	        $result = VerifyGPOOwner $gpmGPO
	        if( $result -eq $true)
	        {
		        Write-Host -ForegroundColor Green True
	        }
	        else
	        {
		        Write-Host -ForegroundColor Red False
	        }
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Assigning the service account '$ServiceAccount' as the owner of the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
	        $result = UpdateGPOOwner $gpmGPO ([REF]$confirmResult)
	            
            if( $result -eq $true)
            {
                if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	        {
	    	        Write-Host -ForegroundColor Green Success
                }
                elseif ($confirmResult -eq [PromptResult]::No)
                {
                    Write-Host -ForegroundColor Yellow Skipped
                }
                elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
                {
                    return
                }
	        }
	        elseif ($result -eq $false)
	        {
		        Write-Host -ForegroundColor Red Failed
	        }
            elseif($result -eq "Skipped")
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
        }

        $index++
    }
}

## Create GPO Permission ##
Function VerifyGPMPermissions
{
    param(
        [System.Object] $som,
        [System.Object] $gpmPermission)

	$Script:result = $false
	
    $gpmSecurityInfo = $som.GetSecurityInfo()
    foreach($permInfo in $gpmSecurityInfo)
    {
        if ($permInfo.Permission -eq $gpmPermission.Permission -and $permInfo.Trustee.TrusteeSid -eq $gpmTrusteeSid.TrusteeSid -and -not $permInfo.Denied)
        {
            return $true
        }
    }

	return $Script:result
}

Function UpdateGPMPermissions
{
    param(
        [System.Object] $som,
        [System.Object] $gpmPermission,
        [ref]$promptResult)

	$Script:result = $true
	$hasAccess = $false
    $hasChanged = $false

	Trap
	{
		$Script:result = $false
	}
	
    if ($promptResult.Value -ne [PromptResult]::YesToAll -and $Confirm.IsPresent)
    {
        $promptResult.Value = GetConfirmation
    }

    if ($promptResult.Value -eq [PromptResult]::Yes -or $promptResult.Value -eq [PromptResult]::YesToAll)
    {
        $gpmSecurityInfo = $som.GetSecurityInfo()

        foreach($permInfo in $gpmSecurityInfo)
        {
            if ($permInfo.Permission -eq $gpmPermission.Permission -and $permInfo.Trustee.TrusteeSid -eq $gpmTrusteeSid.TrusteeSid -and -not $permInfo.Denied)
            {
                $hasAccess = $true
                break
            }
        }

        if($hasAccess -and $Revoke.IsPresent)
        {
    	    $gpmSecurityInfo.Remove($gpmPermission)
            $hasChanged = $true
        }
        elseif(-not $hasAccess -and $Revoke.IsPresent)
        {
            Write-Host -ForegroundColor Yellow "The service account '$ServiceAccount' does not have access."
            return "Skipped"
        }
        elseif (-not $hasAccess -and -not $Revoke.IsPresent)
        {
            $gpmSecurityInfo.Add($gpmPermission)
            $hasChanged = $true
        }
        else
        {
            Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' already has access."
            return "Skipped"
        }

        if ($hasChanged)
        {
	        $som.SetSecurityInfo($gpmSecurityInfo)
        }
    }

	return $Script:result
}

Function SetCreateGPOPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** Create GPO **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    $gpmDomainSom = $gpmDomain.GetSOM($null)

    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit access to create GPOs in the domain '{0}'..." -f $Domain) 
	    $result = VerifyGPMPermissions $gpmDomainSom $gpmSOMGPOCreatePermission
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explicts access to create GPOs in the domain '{0}' for the service account '$ServiceAccount' ..." -f $Domain) 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit access to create GPOs in the domain '{0}'..." -f $Domain) 
        }
	    
	    $result = UpdateGPMPermissions $gpmDomainSom $gpmSOMGPOCreatePermission ([REF]$confirmResult)
	            
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## Delete GPO Permission ##
Function SetDeleteGPOPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** Delete GPO **********"
    Write-Host

    $gpmSearchCriteria = $gpm.CreateSearchCriteria()
    
    Write-Host "Enumerating the GPOs in the domain '$Domain'...Please wait."
    $gpmGPOs = $gpmDomain.SearchGPOs($gpmSearchCriteria)
    $count = $gpmGPOs.Count
    Write-host "$count GPOs discovered."
    $confirmResult = [PromptResult]::Yes
    $yesToAllOwner = [PromptResult]::Yes

    $index = 1
    foreach( $gpmGPO in $gpmGPOs)
    {
        $gpoLdapPath = 'LDAP://' + $LDAPServer + '/' + $gpmGPO.Path
        if ($Report.IsPresent)
        {
            if ($perms.HasFlag([Permission]::GPOOWNER))
            {
                Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' is the owner of the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
	            $result = VerifyGPOOwner $gpmGPO
	            if( $result -eq $true)
	            {
		            Write-Host -ForegroundColor Green True
	            }
	            else
	            {
		            Write-Host -ForegroundColor Red False
	            }
            }
            
            Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has the Delete Subtree permission on the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
	        $result = VerifyActiveDirectoryPermissions $gpoLdapPath $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::DeleteTree) $null
	        if( $result -eq $true)
	        {
		        Write-Host -ForegroundColor Green True
	        }
	        else
	        {
		        Write-Host -ForegroundColor Red False
	        }
        }
        else
        {
            if ($perms.HasFlag([Permission]::GPOOWNER))
            {
                if ($Revoke.IsPresent)
                {
                    Write-Host -ForegroundColor Yellow "Revoke not applicable to ownership. Re-run the script specifying the account who is to become the owner in the ServiceAccount parameter."
	            }
                else
                {
                    Write-Host -ForegroundColor White -NoNewline ("Assigning the service account '$ServiceAccount' as the owner of the GPO '{0}' ($index/$count)..." -f$gpmGPO.DisplayName) 
	                $result = UpdateGPOOwner $gpmGPO ([REF]$yesToAllOwner)
	            
	                if( $result -eq $true)
                    {
                        if ($yesToAllOwner -eq [PromptResult]::Yes -or $yesToAllOwner -eq [PromptResult]::YesToAll)
    	                {
	    	                Write-Host -ForegroundColor Green Success
                        }
                        elseif ($yesToAllOwner -eq [PromptResult]::No)
                        {
                            Write-Host -ForegroundColor Yellow Skipped
                        }
                        elseif ($yesToAllOwner -eq [PromptResult]::NoToAll -or $yesToAllOwner -eq [PromptResult]::Cancel)
                        {
                            return
                        }
	                }
	                elseif ($result -eq $false)
	                {
		                Write-Host -ForegroundColor Red Failed
	                }
                    elseif($result -eq "Skipped")
                    {
                        Write-Host -ForegroundColor Yellow Skipped
                    }
                }
            }

            if ($Revoke.IsPresent)
            {
                Write-Host -ForegroundColor White -NoNewline ("Revoking the Delete Subtree permission on the GPO '{0}' for the service account '$ServiceAccount' ($index/$count)..." -f $gpmGPO.DisplayName)
	        }
            else
            {
                Write-Host -ForegroundColor White -NoNewline ("Assigning the service account '$ServiceAccount' the Delete Subtree permission on the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
            }
	        
            $result =  UpdateActiveDirectoryPermissions $gpoLdapPath $newNTOwner $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::DeleteTree) $null ([REF]$confirmResult)
	            
            if( $result -eq $true)
            {
                if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	        {
	    	        Write-Host -ForegroundColor Green Success
                }
                elseif ($confirmResult -eq [PromptResult]::No)
                {
                    Write-Host -ForegroundColor Yellow Skipped
                }
                elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
                {
                    return
                }
	        }
	        elseif ($result -eq $false)
	        {
		        Write-Host -ForegroundColor Red Failed
	        }
            elseif($result -eq "Skipped")
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
        }

        $index++
    }
}

## GPO Edit Permissions ##
Function VerifyGPOEditPermissions
{
	param( [System.Object] $gpo)
	$Script:result = $false
	
	$gpmGPOSecurityInfo = $gpo.GetSecurityInfo()
    foreach($permInfo in $gpmGPOSecurityInfo)
    {
        if ($permInfo.Permission -eq [GPMPermission]::GPOEditSecurityAndDelete -and $permInfo.Trustee.TrusteeSid -eq $gpmTrusteeSid.TrusteeSid -and -not $permInfo.Denied)
        {
            return $true
        }
    }

	return $Script:result
}

Function UpdateGPOEditPermissions
{
	param( [System.Object] $gpo,
    [ref]$promptResult)

	$Script:result = $true
    $hasAccess = $false
	$hasChanged = $false

	Trap
	{
		$Script:result = $false
	}
    
    if ($promptResult.Value -ne [PromptResult]::YesToAll -and $Confirm.IsPresent)
    {
        $promptResult.Value = GetConfirmation
    }

    if ($promptResult.Value -eq [PromptResult]::Yes -or $promptResult.Value -eq [PromptResult]::YesToAll)
    {
        $gpmGPOSecurityInfo = $gpo.GetSecurityInfo()
        foreach($permInfo in $gpmGPOSecurityInfo)
        {
            if ($permInfo.Permission -eq [GPMPermission]::GPOEditSecurityAndDelete -and $permInfo.Trustee.TrusteeSid -eq $gpmTrusteeSid.TrusteeSid -and -not $permInfo.Denied)
            {
                $hasAccess = $true
                break
            }
        }

        if ($hasAccess -and $Revoke.IsPresent)
        {
	        $gpmGPOSecurityInfo.Remove($gpmGPOEditSecurityAndDeletePermission)
            $hasChanged = $true
        }
        elseif(-not $hasAccess -and $Revoke.IsPresent)
        {
            Write-Host -ForegroundColor Yellow "The service account '$ServiceAccount' does not have access."
            return "Skipped"
        }
        elseif(-not $hasAccess -and -not $Revoke.IsPresent)
        {
            $gpmGPOSecurityInfo.Add($gpmGPOEditSecurityAndDeletePermission)
            $hasChanged = $true
        }
        elseif($hasAccess -and -not $Revoke.IsPresent)
        {
            Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' already has access."
            return "Skipped"
        }

        if ($hasChanged)
        {
            $gpo.SetSecurityInfo($gpmGPOSecurityInfo)
        }
    }
    
	return $Script:result
}

Function SetGPOEditPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** GPO Edit **********"
    Write-Host

    $gpmSearchCriteria = $gpm.CreateSearchCriteria()
    
    Write-Host "Enumerating the GPOs in the domain '$Domain'...Please wait."
    $gpmGPOs = $gpmDomain.SearchGPOs($gpmSearchCriteria)
    $count = $gpmGPOs.Count
    Write-host "$count GPOs discovered."
    $yesToAllEdit = [PromptResult]::Yes
    $yesToAllOwner = [PromptResult]::Yes
    $confirmResult = [PromptResult]::Yes

    $index = 1
    foreach( $gpmGPO in $gpmGPOs)
    {
        $gpoLdapPath = 'LDAP://' + $LDAPServer + '/' + $gpmGPO.Path

        if ($Report.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit Edit, Modify Security, and Delete access to the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
	        $result = VerifyGPOEditPermissions $gpmGPO
	        if ($result -ne $null)
            {
                if ($result -eq $true)
	            {
		            Write-Host -ForegroundColor Green True
	            }
	            else
	            {
		            Write-Host -ForegroundColor Red False
	            }
            }

            if ($perms.HasFlag([Permission]::GPOOWNER))
            {
                Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' is the owner of the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
	            $result = VerifyGPOOwner $gpmGPO
	            if( $result -eq $true)
	            {
		            Write-Host -ForegroundColor Green True
	            }
	            else
	            {
		            Write-Host -ForegroundColor Red False
	            }
            }

            if ($perms.HasFlag([Permission]::DELETE))
            {
                Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has the Delete Subtree permission on the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
	            $result = VerifyActiveDirectoryPermissions $gpoLdapPath $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::DeleteTree) $null
	            if( $result -eq $true)
	            {
		            Write-Host -ForegroundColor Green True
	            }
	            else
	            {
		            Write-Host -ForegroundColor Red False
	            }
            }
        }
        else
        {
            if ($Revoke.IsPresent)
            {
                Write-Host -ForegroundColor White -NoNewline ("Revoking explict Edit, Modify Security, and Delete  access to the GPO '{0}' for the service account '$ServiceAccount' ($index/$count)..." -f $gpmGPO.DisplayName)
	            $result = UpdateGPOEditPermissions $gpmGPO ([REF]$yesToAllEdit)
	            
                if( $result -eq $true)
                {
                    if ($yesToAllEdit -eq [PromptResult]::Yes -or $yesToAllEdit -eq [PromptResult]::YesToAll)
    	            {
	    	            Write-Host -ForegroundColor Green Success
                    }
                    elseif ($yesToAllEdit -eq [PromptResult]::No)
                    {
                        Write-Host -ForegroundColor Yellow Skipped
                    }
                    elseif ($yesToAllEdit -eq [PromptResult]::NoToAll -or $yesToAllEdit -eq [PromptResult]::Cancel)
                    {
                        return
                    }
	            }
	            elseif ($result -eq $false)
	            {
		            Write-Host -ForegroundColor Red Failed
	            }
                elseif($result -eq "Skipped")
                {
                    Write-Host -ForegroundColor Yellow Skipped
                }

                if ($perms.HasFlag([Permission]::DELETE))
                {
                    Write-Host -ForegroundColor White -NoNewline ("Revoking the Delete Subtree permission on the GPO '{0}' for the service account '$ServiceAccount' ($index/$count)..." -f $gpmGPO.DisplayName)
                    $result =  UpdateActiveDirectoryPermissions $gpoLdapPath $newNTOwner $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::DeleteTree) $null ([REF]$confirmResult)
	            
                    if( $result -eq $true)
                    {
                        if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	                {
	    	                Write-Host -ForegroundColor Green Success
                        }
                        elseif ($confirmResult -eq [PromptResult]::No)
                        {
                            Write-Host -ForegroundColor Yellow Skipped
                        }
                        elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
                        {
                            return
                        }
	                }
	                elseif ($result -eq $false)
	                {
		                Write-Host -ForegroundColor Red Failed
	                }
                    elseif($result -eq "Skipped")
                    {
                        Write-Host -ForegroundColor Yellow Skipped
                    }
                }
            }
            else
            {
                Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit Edit, Modify Security, and Delete access to the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
	            $result = UpdateGPOEditPermissions $gpmGPO ([REF]$yesToAllEdit)
	            
	            if( $result -eq $true)
                {
                    if ($yesToAllEdit -eq [PromptResult]::Yes -or $yesToAllEdit -eq [PromptResult]::YesToAll)
    	            {
	    	            Write-Host -ForegroundColor Green Success
                    }
                    elseif ($yesToAllEdit -eq [PromptResult]::No)
                    {
                        Write-Host -ForegroundColor Yellow Skipped
                    }
                    elseif ($yesToAllEdit -eq [PromptResult]::NoToAll -or $yesToAllEdit -eq [PromptResult]::Cancel)
                    {
                        return
                    }
	            }
	            elseif ($result -eq $false)
	            {
		            Write-Host -ForegroundColor Red Failed
	            }
                elseif($result -eq "Skipped")
                {
                    Write-Host -ForegroundColor Yellow Skipped
                }
                
                if ($perms.HasFlag([Permission]::GPOOWNER))
                {
                    Write-Host -ForegroundColor White -NoNewline ("Assigning the service account '$ServiceAccount' as the owner of the GPO '{0}' ($index/$count)..." -f$gpmGPO.DisplayName) 
	                $result = UpdateGPOOwner $gpmGPO ([REF]$yesToAllOwner)
	            
	                if( $result -eq $true)
                    {
                        if ($yesToAllOwner -eq [PromptResult]::Yes -or $yesToAllOwner -eq [PromptResult]::YesToAll)
    	                {
	    	                Write-Host -ForegroundColor Green Success
                        }
                        elseif ($yesToAllOwner -eq [PromptResult]::No)
                        {
                            Write-Host -ForegroundColor Yellow Skipped
                        }
                        elseif ($yesToAllOwner -eq [PromptResult]::NoToAll -or $yesToAllOwner -eq [PromptResult]::Cancel)
                        {
                            return
                        }
	                }
	                elseif ($result -eq $false)
	                {
		                Write-Host -ForegroundColor Red Failed
	                }
                    elseif($result -eq "Skipped")
                    {
                        Write-Host -ForegroundColor Yellow Skipped
                    }
                }

                if ($perms.hasFlag([Permission]::DELETE))
                {
                    Write-Host -ForegroundColor White -NoNewline ("Assigning the service account '$ServiceAccount' the Delete Subtree permission on the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
                    $result =  UpdateActiveDirectoryPermissions $gpoLdapPath $newNTOwner $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::DeleteTree) $null ([REF]$confirmResult)
	            
                    if( $result -eq $true)
                    {
                        if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	                {
	    	                Write-Host -ForegroundColor Green Success
                        }
                        elseif ($confirmResult -eq [PromptResult]::No)
                        {
                            Write-Host -ForegroundColor Yellow Skipped
                        }
                        elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
                        {
                            return
                        }
	                }
	                elseif ($result -eq $false)
	                {
		                Write-Host -ForegroundColor Red Failed
	                }
                    elseif($result -eq "Skipped")
                    {
                        Write-Host -ForegroundColor Yellow Skipped
                    }
                    
                }
            }
        }

        $index++
    }
}

## GPO Model ##
Function SetGPOModelPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** GPO Model **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    $partitionsContainerPath  = 'LDAP://' + $LDAPServer + '/' + 'CN=Partitions,CN=Configuration,' + $defaulNamingContext
    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' is a member of the Distributed COM Users group...") 
	    $result = VerifyGroupMembership 'Distributed COM Users'
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }

        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit Read, Write, Create all child objects, Delete all child object, Delete, Delete Subtree, Modify permissions, and All extended rights access on the Partitions container in the Configuration naming context...") 
	    $result = VerifyActiveDirectoryPermissions $partitionsContainerPath $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead -bor [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite -bor [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) $null
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Removing the service account '$ServiceAccount' from the Distributed COM Users group...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Adding the service account '$ServiceAccount' to the Distributed COM Users group...") 
        }

        $result = UpdateGroupMembership 'Distributed COM Users' ([REF]$confirmResult)

        if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }

        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explicit Read, Write, Create all child objects, Delete all child object, Delete, Delete Subtree, Modify permissions, and All extended rights access on the Partitions container in the Configuration naming context for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit Read, Write, Create all child objects, Delete all child object, Delete, Delete Subtree, Modify permissions, and All extended rights access on the Partitions container in the Configuration naming context...") 
        }

        $result = UpdateActiveDirectoryPermissions $partitionsContainerPath $newNTOwner $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::GenericRead -bor [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite -bor [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) $null ([REF]$confirmResult)

        if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## Replication Permission ##
Function SetReplicationPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** Replication **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    $defaultNamingContextPath = 'LDAP://' + $LDAPServer + '/' + $defaulNamingContext
    $configurationNamingcontextPath  = 'LDAP://' + $LDAPServer + '/' + 'CN=Configuration,' + $defaulNamingContext
    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit Replicating directory changes permission on the Configuration naming context...") 
	    $result = VerifyActiveDirectoryPermissions $configurationNamingcontextPath $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) $replicatingDirectoryChanges
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }

        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit Replicating directory changes permission on the Default naming context...") 
	    $result = VerifyActiveDirectoryPermissions $defaultNamingContextPath $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) $replicatingDirectoryChanges
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explicit Replicating directory changes permission on the Configuration naming context for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit Replicating directory changes on the Configuration naming context...") 
        }

        $result = UpdateActiveDirectoryPermissions $configurationNamingcontextPath $newNTOwner $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) $replicatingDirectoryChanges ([REF]$confirmResult)

        if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }

        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explicit Replicating directory changes permission on the Default naming context for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit Replicating directory changes on the Default naming context...") 
        }

        $result = UpdateActiveDirectoryPermissions $defaultNamingContextPath $newNTOwner $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) $replicatingDirectoryChanges ([REF]$confirmResult)

        if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## Directory Permissions ##
Function VerifyDirectoryPermissions
{
    param(
        [string] $path,
        [System.Security.AccessControl.FileSystemRights] $rights)

    if (Test-Path $path)
    {
        $acl = Get-Acl $path
        foreach($ace in $acl.Access)
        {
            if ($ace.FileSystemRights.HasFlag($rights) -and $ace.IdentityReference -eq $newNTOwner -and $acE.AccessControlType -eq "Allow")
            {
                return $true
            }
        }
    }

    return $false
}

Function UpdateDirectoryPermissions
{
    param(
        [string] $path,
        [System.Security.AccessControl.FileSystemRights] $rights,
        [ref]$promptResult)
    
    $Script:result = $true
    $hasAccess = $false
    $hasChanged = $false

    Trap
	{
		$Script:result = $false
	}

    if ($promptResult.Value -ne [PromptResult]::YesToAll -and $Confirm.IsPresent)
    {
        $promptResult.Value = GetConfirmation
    }

    if ($promptResult.Value -eq [PromptResult]::Yes -or $promptResult.Value -eq [PromptResult]::YesToAll)
    {
        if (Test-Path $path)
        {
            $acl = Get-Acl $path

            foreach($ace in $acl.Access)
            {
                if ($ace.FileSystemRights.HasFlag($rights) -and $ace.IdentityReference -eq $newNTOwner -and $ace.AccessControlType -eq "Allow")
                {
                    $hasAccess = $true
                    break
                }
            }

            if ($hasAccess -and $Revoke.IsPresent)
            {
                $acl.RemoveAccessRule($ace)
                $hasChanged = $true
            }
            elseif(-not $hasAccess -and $Revoke.IsPresent)
            {
                Write-Host -ForegroundColor Yellow "The service account '$ServiceAccount' does not have access."
                return "Skipped"
            }
            elseif (-not $hasAccess -and -not $Revoke.IsPresent)
            {
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $newNTOwner,
                    $rights,
                    ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit + [System.Security.AccessControl.InheritanceFlags]::ObjectInherit), 
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow);

                $acl.AddAccessRule($AccessRule)
                $hasChanged = $true
            }
            else
            {
                Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' already has access."
                return "Skipped"
            }

            if ($hasChanged)
            {
                Set-Acl -Path $path -AclObject $acl
            }

            $Script:result = $true
        }
    }

    return $Script:result
}

Function SetInstallDirectoryPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** Install Directory **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit Full Control access to the install directory...") 
	    $result = VerifyDirectoryPermissions $installDir ([System.Security.AccessControl.FileSystemRights]::FullControl)
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explicit Full Control access to the install directory for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit Full Control access to the install directory...") 
        }

        $result = UpdateDirectoryPermissions $installDir ([System.Security.AccessControl.FileSystemRights]::FullControl) ([REF]$confirmResult)

        if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## RSoP Permissions ##
Function VerifyRSoPPermissions
{
    param( [System.Object] $domainSom)
	$Script:result = $false

    $rsopLogging = $false
    $rsopPlanning = $false	

    $gpmDomainSecurityInfo = $domainSom.GetSecurityInfo()
    foreach($permInfo in $gpmDomainSecurityInfo)
    {
        if ($permInfo.Permission -eq [GPMPermission]::SOMLogging -and $permInfo.Trustee.TrusteeSid -eq $gpmTrusteeSid.TrusteeSid -and -not $permInfo.Denied)
        {
            $rsopLogging = $true
        }

        if ($permInfo.Permission -eq [GPMPermission]::SOMPlanning -and $permInfo.Trustee.TrusteeSid -eq $gpmTrusteeSid.TrusteeSid -and -not $permInfo.Denied)
        {
            $rsopPlanning = $true
        }

        if ($rsopLogging -and $rsopPlanning)
        {
            return $true
        }
    }

	return $Script:result
}

Function UpdateRSoPPermissions
{
    param(
        [System.Object] $domainSom,
        [ref]$promptResult)

	$Script:result = $true
	$hasRsopLogging = $false
    $hasRsopPlanning = $false	
    $hasChanged = $false

	Trap
	{
		$Script:result = $false
	}
	
    if ($promptResult.Value -ne [PromptResult]::YesToAll -and $Confirm.IsPresent)
    {
        $promptResult.Value = GetConfirmation
    }

    if ($promptResult.Value -eq [PromptResult]::Yes -or $promptResult.Value -eq [PromptResult]::YesToAll)
    {
	    $gpmDomainSecurityInfo = $domainSom.GetSecurityInfo()

        foreach($permInfo in $gpmDomainSecurityInfo)
        {
            if ($permInfo.Permission -eq [GPMPermission]::SOMLogging -and $permInfo.Trustee.TrusteeSid -eq $gpmTrusteeSid.TrusteeSid -and -not $permInfo.Denied)
            {
                $hasRsopLogging = $true
            }

            if ($permInfo.Permission -eq [GPMPermission]::SOMPlanning -and $permInfo.Trustee.TrusteeSid -eq $gpmTrusteeSid.TrusteeSid -and -not $permInfo.Denied)
            {
                $hasRsopPlanning = $true
            }

            if ($rsopLogging -and $rsopPlanning)
            {
                break
            }
        }

        if (($hasRsopLogging -or $hasRsopPlanning) -and $Revoke.IsPresent)
        {
            if ($hasRsopLogging)
            {
                $gpmDomainSecurityInfo.Remove($gpmRSoPLoggingPermission)
                $hasChanged = $true
            }

            if ($hasRsopPlanning)
            {
                $gpmDomainSecurityInfo.Remove($gpmRSoPPlanningPermission)
                $hasChanged = $true
            }
        }
        elseif(-not $hasRsopLogging -and -not $hasRsopPlanning -and $Revoke.IsPresent)
        {
            Write-Host -ForegroundColor Yellow "The service account '$ServiceAccount' does not have access."
            return "Skipped"
        }
        if ((-not $hasRsopLogging -or -not $hasRsopPlanning) -and -not $Revoke.IsPresent)
        {
            if (-not $hasRsopLogging)
            {
	            $gpmDomainSecurityInfo.Add($gpmRSoPLoggingPermission)
                $hasChanged = $true
            }

            if (-not $hasRsopPlanning)
            {
                $gpmDomainSecurityInfo.Add($gpmRSoPPlanningPermission)
                $hasChanged = $true
            }
        }
        elseif($hasRsopLogging -and $hasRsopPlanning -and -not $Revoke.IsPresent)
        {
            Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' already has access."
            return "Skipped"
        }

        if ($hasChanged)
        {
	        $domainSom.SetSecurityInfo($gpmDomainSecurityInfo)
        }
    }
	
    return $Script:result
}

Function SetRSoPPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** RSoP **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    $gpmDomainSom = $gpmDomain.GetSOM($null)

    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit access to read Group Polcy Results Data and perform Group Policy analysis in the domain '{0}'..." -f $Domain) 
	    $result = VerifyRSoPPermissions $gpmDomainSom
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explict access to read Group Polcy Results Data and perform Group Policy analysis in the domain '{0}' for the service account '$ServiceAccount' ..." -f $Domain) 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit access to read Group Polcy Results Data and perform Group Policy analysis  in the domain '{0}'..." -f $Domain) 
        }

	    $result = UpdateRSoPPermissions $gpmDomainSom ([REF]$confirmResult)
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## Link Permission ##
Function VerifyLinkPermissions
{
    param( [System.Object] $domainSom)
	$Script:result = $false
	
    $gpmDomainSecurityInfo = $domainSom.GetSecurityInfo()
    foreach($permInfo in $gpmDomainSecurityInfo)
    {
        if ($permInfo.Permission -eq [GPMPermission]::SOMLink -and $permInfo.Trustee.TrusteeSid -eq $gpmTrusteeSid.TrusteeSid -and -not $permInfo.Denied)
        {
            return $true
        }
    }

	return $Script:result
}

Function UpdateLinkPermissions
{
    param(
        [System.Object] $domainSom,
        [ref]$promptResult)

	$Script:result = $true
	$hasAccess = $false
    $hasChanged = $false

	Trap
	{
		$Script:result = $false
	}
	
    if ($promptResult.Value -ne [PromptResult]::YesToAll -and $Confirm.IsPresent)
    {
        $promptResult.Value = GetConfirmation
    }

    if ($promptResult.Value -eq [PromptResult]::Yes -or $promptResult.Value -eq [PromptResult]::YesToAll)
    {
        $gpmDomainSecurityInfo = $domainSom.GetSecurityInfo()
        foreach($permInfo in $gpmDomainSecurityInfo)
        {
            if ($permInfo.Permission -eq [GPMPermission]::SOMLink -and $permInfo.Trustee.TrusteeSid -eq $gpmTrusteeSid.TrusteeSid -and -not $permInfo.Denied)
            {
                $hasAccess = $true
                break
            }
        }

        if ($hasAccess -and $Revoke.IsPresent)
        {
    	    $gpmDomainSecurityInfo.Remove($gpmLinkPermission)
            $hasChanged = $true
        }
        elseif(-not $hasAccess -and $Revoke.IsPresent)
        {
            Write-Host -ForegroundColor Yellow "The service account '$ServiceAccount' does not have access."
            return "Skipped"
        }
        elseif (-not$hasAccess -and -not $Revoke.IsPresent)
        {
            $gpmDomainSecurityInfo.Add($gpmLinkPermission)
            $hasChanged = $true
        }
        else
        {
            Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' already has access."
            return "Skipped"
        }

        if ($hasChanged)
        {
	        $domainSom.SetSecurityInfo($gpmDomainSecurityInfo)
        }
    }

	return $Script:result
}

Function SetLinkPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** Link GPO **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    $gpmDomainSom = $gpmDomain.GetSOM($null)

    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit access to link GPOs in the domain '{0}'..." -f $Domain) 
	    $result = VerifyLinkPermissions $gpmDomainSom
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explict access to link GPOs in the domain '{0}' for the service account '$ServiceAccount'..." -f $Domain) 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit access to link GPOs in the domain '{0}'..." -f $Domain) 
        }
	    
	    $result = UpdateLinkPermissions $gpmDomainSom ([REF]$confirmResult)
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## Registry Permissions ##
Function VerifyRegistryPermission
{
    param(
        [string] $path,
        [System.Security.AccessControl.RegistryRights] $permission)

    if (Test-Path $path)
    {
        $acl = Get-Acl $path
        foreach($ace in $acl.Access)
        {
            if ($ace.RegistryRights.HasFlag($permission) -and $ace.IdentityReference -eq $newNTOwner -and $acE.AccessControlType -eq "Allow")
            {
                return $true
            }
        }
    }

    return $false
}

Function UpdateRegistryPermission
{
    param( 
    [string] $path,
    [System.Security.AccessControl.RegistryRights] $permission,
    [bool] $create,
    [ref]$promptResult)
    
    $Script:result = $true
    $hasAccess = $false
    $hasChanged = $false
    
    Trap
	{
		$Script:result = $false
	}

    if ($promptResult.Value -ne [PromptResult]::YesToAll -and $Confirm.IsPresent)
    {
        $promptResult.Value = GetConfirmation
    }

    if ($promptResult.Value -eq [PromptResult]::Yes -or $promptResult.Value -eq [PromptResult]::YesToAll)
    {
        $exists = Test-Path $path 

        if ($exists -or $create -eq $true)
        {
            if (-not $exists -and $create -eq $true)
            {
                $root = [System.IO.Path]::GetDirectoryName($path)
                $key = [System.IO.Path]::GetFileName($path)

                New-Item -Path $root -Name $key
            }
        
            $acl = Get-Acl $path

            foreach($ace in $acl.Access)
            {
                if ($ace.RegistryRights.HasFlag($permission) -and $ace.IdentityReference -eq $newNTOwner -and $ace.AccessControlType -eq "Allow")
                {
                    $hasAccess = $true
                    break
                }
            }

            if ($hasAccess -and $Revoke.IsPresent)
            {
                $acl.RemoveAccessRule($ace)
                $hasChanged = $true
            }
            elseif(-not $hasAccess -and $Revoke.IsPresent)
            {
                Write-Host -ForegroundColor Yellow "The service account '$ServiceAccount' does not have access."
                return "Skipped"
            }
            elseif (-not $hasAccess -and -not $Revoke.IsPresent)
            {
                $AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $newNTOwner,
                    $permission,
                    ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit + [System.Security.AccessControl.InheritanceFlags]::ObjectInherit), 
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow);

                $acl.AddAccessRule($AccessRule)
                $hasChanged = $true
            }
            else
            {
                Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' already has access."
                return "Skipped"
            }

            if ($hasChanged)
            {
                Set-Acl -Path $path -AclObject $acl
            }
        }
    }

    return $Script:result
}

Function SetRegistryPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** Registry **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit access to the registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Quest\GPOADmin'...") 
	    $result = VerifyRegistryPermission 'HKLM:\SOFTWARE\Quest\GPOADmin' ([System.Security.AccessControl.RegistryRights]::FullControl)
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }

        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit access to the registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics'...") 
	    $result = VerifyRegistryPermission 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics' $registryLogginPermission
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }

        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit access to the registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog'...") 
	    $result = VerifyRegistryPermission 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog' $registryLogginPermission
	    if ($result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explict access to the registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Quest\GPOADmin' for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit access to the registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Quest\GPOADmin'...") 
        }
	    
        $result = UpdateRegistryPermission 'HKLM:\SOFTWARE\Quest\GPOADmin' ([System.Security.AccessControl.RegistryRights]::FullControl) $false ([REF]$confirmResult)
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }

        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explict access to the registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics' for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit access to the registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics'...") 
        }
	    
        $result = UpdateRegistryPermission 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics' $registryLogginPermission $true ([REF]$confirmResult)
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }

        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explict access to the registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog' for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit access to the registry key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog'...") 
        }
	    
        $result = UpdateRegistryPermission 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog' $registryLogginPermission $false ([REF]$confirmResult)
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## Scripts Permissions ##
Function SetScriptsPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** Scripts Directory **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit Read, Write, and Synchronize access to the Scripts directory...") 
	    $result = VerifyDirectoryPermissions $scriptsDir ([System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Write -bor [System.Security.AccessControl.FileSystemRights]::Synchronize)
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explicit Read, Write, and Synchronize access to the Scripts directory for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit Read, Write, and Synchronize access to the Scripts directory...") 
        }

	    $result = UpdateDirectoryPermissions $scriptsDir ([System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Write -bor [System.Security.AccessControl.FileSystemRights]::Synchronize) ([REF]$confirmResult)
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## WMI Permissions ##
Function VerifyActiveDirectoryPermissions
{
    param(
        [string] $path,
        [System.Object] $trusteeSid,
        [System.DirectoryServices.ActiveDirectoryRights] $rights,
        [system.Object] $childTypeId)

    $directoryEntry = new-Object -typename System.DirectoryServices.DirectoryEntry($path)
    
    foreach($ace in $directoryEntry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    {
        if ($childTypeId -ne $null)
        {
            if ($ace.ActiveDirectoryRights.HasFlag($rights) -and $ace.IdentityReference -eq $trusteeSid -and $ace.AccessControlType -eq "Allow" -and $ace.ObjectFlags -eq [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent -and $ace.ObjectType -eq $childTypeId)
            {
                return $true
            }
        }
        else
        {
            if ($ace.ActiveDirectoryRights.HasFlag($rights) -and $ace.IdentityReference -eq $trusteeSid -and $acE.AccessControlType -eq "Allow")
            {
                return $true
            }
        }
    }

    return $false
}

Function UpdateActiveDirectoryPermissions
{
    param(
        [string] $path,
        [System.Object] $trusteeName,
        [System.Object] $trusteeSid,
        [System.DirectoryServices.ActiveDirectoryRights] $rights,
        [System.Object] $childTypeId,
        [ref]$promptResult)
    
    $Script:result = $true
    $hasAccess = $false
    $hasChanged = $false

    Trap
	{
		$Script:result = $false
	}

    if ($promptResult.Value -ne [PromptResult]::YesToAll -and $Confirm.IsPresent)
    {
        $promptResult.Value = GetConfirmation
    }

    if ($promptResult.Value -eq [PromptResult]::Yes -or $promptResult.Value -eq [PromptResult]::YesToAll)
    {
        $directoryEntry = new-Object -typename System.DirectoryServices.DirectoryEntry($path)

        foreach($ace in $directoryEntry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        {
            if ($childTypeId -ne $null)
            {
                if ($ace.ActiveDirectoryRights.HasFlag($rights) -and $ace.IdentityReference -eq $trusteeSid -and $ace.AccessControlType -eq "Allow" -and $ace.ObjectFlags -eq [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent -and $ace.ObjectType -eq $childTypeId)
                {
                    $hasAccess = $true
                    break
                }
            }
            else
            {
                if ($ace.ActiveDirectoryRights.HasFlag($rights) -and $ace.IdentityReference -eq $trusteeSid -and $acE.AccessControlType -eq "Allow")
                {
                    $hasAccess = $true
                    break
                }
            }
        }
    
        $directoryEntry = new-Object -typename System.DirectoryServices.DirectoryEntry($path);

        if ($hasAccess -and $Revoke.IsPresent)
        {
            $hasChanged = $directoryEntry.ObjectSecurity.RemoveAccessRule($ace)
            if (-not $hasChanged)
            {
                
                if ($childTypeId -ne $null)
                {
                    switch($childTypeId)
                    {
                        $servicePrincipalNameId {$extendedRight = "Service Principal Name"; break}
                        $serverConnectionPointId {$extendedRight = "Service Connection Point"; break}
                        $replicatingDirectoryChanges {$extendedRight = "Replicating Directory Changes"; break} 
                    }

                    Write-Host -ForegroundColor Red "`nFailed to revoke the explicit rights '$rights' for the extend right '$extendedRight' for the service account '$ServiceAccount' on the object '$path'.`nThis should be manually performed."
                }
                else
                {
                    Write-Host -ForegroundColor Red "`nFailed to revoke the explicit rights '$rights' for the service account '$ServiceAccount' on the object '$path'.`nThis should be manually performed."
                }

                
                $Script:result = $false
            }
        }
        elseif(-not $hasAccess -and $Revoke.IsPresent)
        {
            Write-Host -ForegroundColor Yellow "The service account '$ServiceAccount' does not have access."
            return "Skipped"
        }
        elseif (-not $hasAccess -and -not $Revoke.IsPresent)
        {
            if ($childTypeId -ne $null)
            {
                $AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $trusteeName,
                    $rights,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $childTypeId,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
            }
            else
            {
                $AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $trusteeName,
                    $rights,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
            }

            $directoryEntry.ObjectSecurity.AddAccessRule($AccessRule)
            $hasChanged = $true
        }
        else
        {
            Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' already has access."
            return "Skipped"
        }
   
        if ($hasChanged)
        {
            $directoryEntry.CommitChanges()
        }
    }

    return $Script:result
}

Function SetWMIFilterPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** WMI Filter **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    $wmiFilterLdapPath = 'LDAP://' + $LDAPServer + '/' + $wmiFilterPath
    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit Full Control access to all WMI Filters...") 
	    $result = VerifyActiveDirectoryPermissions $wmiFilterLdapPath $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll) $null
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explicit Full Control access to all WMI Filters for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit Full Control access to all WMI Filters...") 
        }

	    $result = UpdateActiveDirectoryPermissions $wmiFilterLdapPath $newNTOwner $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::GenericAll) $null ([REF]$confirmResult)
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## SCP Permissions ##
Function SetSCPPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** SCP **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    $computerPath = GetLocalComputerLDAPPath
    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit access to Create and Delete service connection points...") 
	    $result = VerifyActiveDirectoryPermissions $computerPath $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild) $serverConnectionPointId
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explicit access to Create and Delete service connection points for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit access to Create and Delete service connection points...") 
        }

	    $result = UpdateActiveDirectoryPermissions $computerPath $newNTOwner $gpmTrusteeSid.TrusteeSid ([System.DirectoryServices.ActiveDirectoryRights]::CreateChild + [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild) $serverConnectionPointId ([REF]$confirmResult)
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## SPN Permissions ##
Function SetSPNPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** SPN **********"
    Write-Host

    $confirmResult = [PromptResult]::Yes

    $selfSid = new-object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::SelfSid, $null)
    $selfNTAccount = [System.Security.Principal.SecurityIdentifier]::new($selfSid).Translate([System.Security.Principal.NTAccount])

    $userPath = GetTrusteeLDAPPath
    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit access to Read and Write servicePrincipalName...") 
	    $result = VerifyActiveDirectoryPermissions $userPath $selfSid ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) $servicePrincipalNameId
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explicit access to Read and Write servicePrincipalName for the service account '$ServiceAccount'...") 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit access to Read and Write servicePrincipalName...") 
        }

	    $result = UpdateActiveDirectoryPermissions $userPath $selfNTAccount $selfSid ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) $servicePrincipalNameId ([REF]$confirmResult)
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## Starter GPO Permissions ##
Function SetStarterGPOPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** Create Starter GPO **********"
    Write-Host

    if (-not [System.IO.Directory]::Exists($starterGPOsDir))
    {
        Write-Host -ForegroundColor Yellow "The StarterGPO directory does not exist. Please use GPMC to create. Skipped"
       return
    }

    $confirmResult = [PromptResult]::Yes

    $gpmDomainSom = $gpmDomain.GetSOM($null)

    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit access to create Starter GPOs in the domain '{0}'..." -f $Domain) 
	    $result = VerifyGPMPermissions $gpmDomainSom $gpmSOMStarterGPOCreatePermission
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explict access to create Starter GPOs in the domain '{0}' for the service account '$ServiceAccount' ..." -f $Domain) 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit access to create Starter GPOs in the domain '{0}'..." -f $Domain) 
        }
	    
        $result = UpdateGPMPermissions $gpmDomainSom $gpmSOMStarterGPOCreatePermission ([REF]$confirmResult)
	    if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

## Starter GPO Directory permissions ##
Function SetStarterGPODirectoryPermission
{
    Write-Host
    Write-Host -ForegroundColor White "********** Starter GPO Directory Permission **********"
    Write-Host

    if (-not [System.IO.Directory]::Exists($starterGPOsDir))
    {
        Write-Host -ForegroundColor Yellow "The StarterGPO directory does not exist. Please use GPMC to create. Skipped"
       return
    }

    $confirmResult = [PromptResult]::Yes

    if ($Report.IsPresent)
    {
        Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' has explicit Modify, TakeOwnership, and Synchronize rights on the Starter GPO directory in the domain '{0}'..." -f $Domain) 
	    $result = VerifyDirectoryPermissions $starterGPOsDir ([System.Security.AccessControl.FileSystemRights]::Modify -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor [System.Security.AccessControl.FileSystemRights]::Synchronize)
	    if( $result -eq $true)
	    {
		    Write-Host -ForegroundColor Green True
	    }
	    else
	    {
		    Write-Host -ForegroundColor Red False
	    }
    }
    else
    {
        if ($Revoke.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Revoking explict Modify, TakeOwnership, and Synchronize rights on the Starter GPO directory in the domain '{0}' for the service account '$ServiceAccount' ..." -f $Domain) 
        }
        else
        {
            Write-Host -ForegroundColor White -NoNewline ("Granting the service account '$ServiceAccount' explicit Modify, TakeOwnership, and Synchronize rights on the Starter GPO directory in the domain '{0}'..." -f $Domain) 
        }
	    
        $result = UpdateStarterGPODirectoryPermission $starterGPOsDir
        if( $result -eq $true)
        {
            if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	    {
	    	    Write-Host -ForegroundColor Green Success
            }
            elseif ($confirmResult -eq [PromptResult]::No)
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
            elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
            {
                return
            }
	    }
	    elseif ($result -eq $false)
	    {
		    Write-Host -ForegroundColor Red Failed
	    }
        elseif($result -eq "Skipped")
        {
            Write-Host -ForegroundColor Yellow Skipped
        }
    }
}

Function UpdateStarterGPODirectoryPermission
{
    param(
        [string] $path)

    $Script:result = $true

    Trap
	{
		$Script:result = $false
	}

    $acl = Get-Acl $path

    if ($Revoke.IsPresent)
    {
        $aceToRemove = $acl.Access | ?{ $_.IsInherited -eq $false -and $_.IdentityReference -eq $ServiceAccount }
        $acl.RemoveAccessRuleAll($aceToRemove)
        Set-Acl -Path $path -AclObject $acl
    }
    else
    {
        $rights = [System.Security.AccessControl.FileSystemRights]::Modify -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
        $ace = $acl.Access | ? {$_.IdentityReference -Like $ServiceAccount -and ($_.FileSystemRights.HasFlag($rights))}
        if ($ace -eq $null)
        {
            $permissions = New-Object System.Security.AccessControl.FileSystemAccessRule($ServiceAccount, "Modify,TakeOwnership,Synchronize", "ContainerInherit, ObjectInherit", "None", "Allow")
            $acl.SetAccessRule($permissions)
            Set-Acl -Path $path -AclObject $acl

        }
        else
        {
            Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' already has the 'Modify, TakeOwnership, and Synchronize' rights on the Starter GPO directory."
            return "Skipped"
        }
    }

    return $Script:result
}

## Starter GPO Owner ##
Function VerifyStarterGPOOwner
{
    param(
        [string] $path)

    if (Test-Path $path)
    {
        $owner = (Get-Acl $path).Owner
        return $owner -eq $newNTOwner
    }

    return $false
}

Function UpdateStarterGPOOwner
{
    param(
        [string] $path,
        [ref]$promptResult)

    $Script:result = $true

    Trap
	{
		$Script:result = $false
	}

    if ($promptResult.Value -ne [PromptResult]::YesToAll -and $Confirm.IsPresent)
    {
        $promptResult.Value = GetConfirmation
    }

    if ($promptResult.Value -eq [PromptResult]::Yes -or $promptResult.Value -eq [PromptResult]::YesToAll)
    {
        if (Test-Path $path)
        {
            $acl = Get-Acl $path

            if ($acl.Owner -ne $newNTOwner)
            {
                $acl.SetOwner($newNTOwner)
                Set-Acl -Path $path -AclObject $acl
            }
            else
            {
                Write-Host -ForegroundColor Yellow "`nThe service account '$ServiceAccount' is already the owner."
                return "Skipped"
            }
        }
    }

    return $Script:result
}

Function SetStarterGPOOwner
{
    Write-Host
    Write-Host -ForegroundColor White "********** Starter GPO Owner **********"
    Write-Host

    if (-not [System.IO.Directory]::Exists($starterGPOsDir))
    {
        Write-Host -ForegroundColor Yellow "The StarterGPO directory does not exist. Please use GPMC to create. Skipped"
       return
    }

    $confirmResult = [PromptResult]::Yes

    if ($Revoke.IsPresent)
    {
        Write-Host -ForegroundColor Yellow "Revoke not applicable to ownership. Re-run the script specifying the account who is to become the owner in the ServiceAccount parameter."
        return
    }

    $gpmSearchCriteria = $gpm.CreateSearchCriteria()
    
    Write-Host "Enumerating the Starter GPOs in the domain '$Domain'...Please wait."
    $gpmGPOs = $gpmDomain.SearchStarterGPOs($gpmSearchCriteria)

    $count = $gpmGPOs.Count
    Write-host "$count Starter GPOs discovered."

    $index = 1
    foreach( $gpmGPO in $gpmGPOs)
    {
        if ($Report.IsPresent)
        {
            Write-Host -ForegroundColor White -NoNewline ("Verifying the service account '$ServiceAccount' is the owner of the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
	        $result = VerifyStarterGPOOwner ([System.IO.Path]::Combine($starterGPOsDir, $gpmGPO.ID))
	        if( $result -eq $true)
	        {
		        Write-Host -ForegroundColor Green True
	        }
	        else
	        {
		        Write-Host -ForegroundColor Red False
	        }
        }
        else
        {
	        Write-Host -ForegroundColor White -NoNewline ("Assigning the service account '$ServiceAccount' as the owner of the GPO '{0}' ($index/$count)..." -f $gpmGPO.DisplayName) 
	        $result = UpdateStarterGPOOwner ([System.IO.Path]::Combine($starterGPOsDir, $gpmGPO.ID)) ([REF]$confirmResult)
	        if( $result -eq $true)
            {
                if ($confirmResult -eq [PromptResult]::Yes -or $confirmResult -eq [PromptResult]::YesToAll)
    	        {
	    	        Write-Host -ForegroundColor Green Success
                }
                elseif ($confirmResult -eq [PromptResult]::No)
                {
                    Write-Host -ForegroundColor Yellow Skipped
                }
                elseif ($confirmResult -eq [PromptResult]::NoToAll -or $confirmResult -eq [PromptResult]::Cancel)
                {
                    return
                }
	        }
	        elseif ($result -eq $false)
	        {
		        Write-Host -ForegroundColor Red Failed
	        }
            elseif($result -eq "Skipped")
            {
                Write-Host -ForegroundColor Yellow Skipped
            }
        }

        $index++
    }
}

Function SetPermissions
{
    # Grants the "Delete Subtree" right to the service account on each Group Policy Object
    if ($perms.HasFlag([Permission]::DELETE) -and -not $perms.HasFlag([Permission]::GPOEDIT))
    {
        SetDeleteGPOPermission
    }

    # Set "Create GPOs" to the service account at the domain level
    if ($perms.HasFlag([Permission]::GPO))
    {
        SetCreateGPOPermission
    }

    # Set "Edit settings, Delete, Modify security" to the service account on each Group Policy Object
    if ($perms.HasFlag([Permission]::GPOEDIT))
    {
        SetGPOEditPermission
    }

    # Assigns the service account as the owner on each Group Policy Object
    if ($perms.HasFlag([Permission]::GPOOWNER) -and -not ($perms.HasFlag([Permission]::GPOEdit) -and $perms.HasFlag([Permission]::DELETE)))
    {
        SetGPOOwner
    }

    # Grants the ability for the service account to create the application directory for GPO Modeling Report 
    if ($perms.HasFlag([Permission]::GPOMODEL))
    {
        SetGPOModelPermission
    }

    # Grants "Link GPOs" to the service account at the Site, Domain, and OU level
    if ($perms.HasFlag([Permission]::LINK))
    {
        SetLinkPermission
    }

    # Grants "Full Control" to the service account to HKLM\SOFTWARE\Quest\GPOADmin
	# Grants "Query Value, Set Value, Create SubKey, Enumerate SubKeys, Delete, and Read Control" to the service account to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics
	# Grants "Query Value, Set Value, Create SubKey, Enumerate SubKeys, Delete, and Read Control" to the service account to HKLM\SYSTEM\CurrentControlSet\Service\EventLog
    if ($perms.HasFlag([Permission]::REGISTRY))
    {
        SetRegistryPermission
    }

    # Grants “Replicating directory changes" on the Default and Configuration naming contexts (for the Watcher Service)
    if ($perms.HasFlag([Permission]::REPLICATION))
    {
        SetReplicationPermission
    }

    # Set permissions on the install directory
    if ($perms.HasFlag([Permission]::INSTALL))
    {
        SetInstallDirectoryPermission
    }

    #Grants "Read Group Polcy Results Data" to the service account at the domain level
    if ($perms.HasFlag([Permission]::RSOP))
    {
        SetRSoPPermission
    }

    # Grants "Create and Delete serviceConnectionPoint objects" to the service account.
    if ($perms.HasFlag([Permission]::SCP))
    {
        SetSCPPermission
    }

    # Grants "List folder contents, Read, and Write" to the service account on the scripts container in SYSVOL
    if ($perms.HasFlag([Permission]::SCRIPT))
    {
        SetScriptsPermission
    }

    # Grants "Read and Write servicePrincipalName" to the service account.
    if ($perms.HasFlag([Permission]::SPN))
    {
        SetSPNPermission
    }

    # Grants "Create Starter GPOs" to the service account at the domain level
    # Grants the Modify, TakeOwnership, and Synchronize rights to the service account on the Starter GPOs container in SYSVOL
    if ($perms.HasFlag([Permission]::STARTERGPO))
    {
        SetStarterGPOPermission
        SetStarterGPODirectoryPermission
    }

    # Assigns the service account as the owner on each Starter GPO
    if ($perms.HasFlag([Permission]::STARTERGPOOWNER))
    {
        SetStarterGPOOwner
    }

    # Grants "Full Control" to the service account on all WMI Filters
    if ($perms.HasFlag([Permission]::WMI))
    {
        SetWMIFilterPermission
    }
}

# Parse the permissions
[Permission]$perms = [Permission]::None

foreach($perm in $Permissions.Split(','))
{
    [Permission]$value = [Permission]::NONE
    if ([Permission]::TryParse($perm.Trim().ToUpper(), [ref]$value))
    {
        $perms = $perms + $value
    }
    else
    {
        Write-Error -Message "'$perm' is an invalid permission. Valid values are: Delete, GPO, GPOEdit, GPOOwner, GPOModel, Install, Link, Registry, Replication, RSoP, SCP, Script, SPN, StarterGPO, StarterGPOOwner, WMI, All"
    }
}

# Get DefaultNamingContext from domain name
$defaulNamingContext = 'DC=' + $Domain.Replace('.', ',DC=')

# Create the GPMC Main object
$gpm = (New-Object -ComObject GPMgmt.GPM)

# Load the GPMC constants
$gpmConstants = $gpm.GetConstants() 
    
# Connect to the domain passed using any DC
$gpmDomain = $gpm.GetDomain($Domain, “”, $gpmConstants.UseAnyDC) 

# Create trustee for comparisons 
$gpmTrusteeSid = $gpm.CreateTrustee($ServiceAccount)

# Create the new owner 
$newNTOwner = [System.Security.Principal.SecurityIdentifier]::new($gpmTrusteeSid.TrusteeSid).Translate([System.Security.Principal.NTAccount])

# Create the SOMGPOCreate permission
$gpmSOMGPOCreatePermission = $gpm.CreatePermission($ServiceAccount, [GPMPermission]::SOMGPOCreate, $true)

# Create the EditSecurityAndDelete permission
$gpmGPOEditSecurityAndDeletePermission = $gpm.CreatePermission($ServiceAccount, [GPMPermission]::GPOEditSecurityAndDelete, $true)

# Create the RSoP Logging permission
$gpmRSoPLoggingPermission = $gpm.CreatePermission($ServiceAccount, [GPMPermission]::SOMLogging, $true)

# Create the RSoP Planning permission
$gpmRSoPPlanningPermission = $gpm.CreatePermission($ServiceAccount, [GPMPermission]::SOMPlanning, $true)

# Create the Link permission
$gpmLinkPermission = $gpm.CreatePermission($ServiceAccount, [GPMPermission]::SOMLink, $true)

# Create the SOMStarterGPOCreate permission
$gpmSOMStarterGPOCreatePermission = $gpm.CreatePermission($ServiceAccount, [GPMPermission]::SOMStarterGPOCreate, $true)

# Registry Logging permission
$registryLogginPermission = ([System.Security.AccessControl.RegistryRights]::QueryValues -bor [System.Security.AccessControl.RegistryRights]::SetValue -bor [System.Security.AccessControl.RegistryRights]::CreateSubKey -bor [System.Security.AccessControl.RegistryRights]::EnumerateSubKeys -bor [System.Security.AccessControl.RegistryRights]::Delete -bor [System.Security.AccessControl.RegistryRights]::ReadPermissions)

# Get the install directory
$installDir = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Quest\GPOADmin -Name InstallPath).InstallPath

# Scripts directory
$scriptsDir = "\\$Domain\sysvol\$Domain\scripts"

# Starter GPOs directory
$starterGPOsDir = "\\$Domain\sysvol\$Domain\StarterGPOs"

# WMIFilter path
$wmiFilterPath = 'CN=SOM,CN=WMIPolicy,CN=System,' + $defaulNamingContext

# Service Connection Point Id
$serverConnectionPointId = "{28630EC1-41D5-11D1-A9C1-0000F80367C1}"

# Service Principal Name Id
$servicePrincipalNameId = "{f3a64788-5306-11d1-a9c5-0000f80367c1}"

# Replicating Directory Changes Id
$replicatingDirectoryChanges = "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"

Add-Type -AssemblyName System.DirectoryServices.AccountManagement

## Notice ##
$valid = $false
Write-Host
Write-Host -ForegroundColor White "*****************************************************************************************"
Write-Host -ForegroundColor White "*                                                                                       *" 
Write-Host -ForegroundColor White -NoNewLine "*  "
Write-Host -ForegroundColor Yellow -NoNewline "To log the results to a file, use the Start-Transcript and Stop-Transcript cmdlets."
Write-Host -ForegroundColor White "  *"
Write-Host -ForegroundColor White "*                                                                                       *" 
Write-Host -ForegroundColor White "*****************************************************************************************"
Write-Host -ForegroundColor Yellow -NoNewline "[C] Continue"
Write-Host -ForegroundColor White -NoNewLine "  [X] Exit (default is ""C"")"
While(-not $valid)
{
    $input = (Read-Host).ToUpper()
    switch ($input) 
    {
        "" {$valid = $true; break }
        "C" {$valid = $true; break }
        "X" {Exit}
        Default { Write-Host "Invalide Response"}
    }
}

SetPermissions

# SIG # Begin signature block
# MIItigYJKoZIhvcNAQcCoIItezCCLXcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBw2Ua4mUudGxYy
# svDht5caSHU2Bd7D8EF6ijbRlxNILqCCEo4wggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggYcMIIEBKADAgECAhAz1wio
# kUBTGeKlu9M5ua1uMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENv
# ZGUgU2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5
# NTlaMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAs
# BgNVBAMTJVNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBFViBSMzYwggGi
# MA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC70f4et0JbePWQp64sg/GNIdMw
# hoV739PN2RZLrIXFuwHP4owoEXIEdiyBxasSekBKxRDogRQ5G19PB/YwMDB/NSXl
# wHM9QAmU6Kj46zkLVdW2DIseJ/jePiLBv+9l7nPuZd0o3bsffZsyf7eZVReqskmo
# PBBqOsMhspmoQ9c7gqgZYbU+alpduLyeE9AKnvVbj2k4aOqlH1vKI+4L7bzQHkND
# brBTjMJzKkQxbr6PuMYC9ruCBBV5DFIg6JgncWHvL+T4AvszWbX0w1Xn3/YIIq62
# 0QlZ7AGfc4m3Q0/V8tm9VlkJ3bcX9sR0gLqHRqwG29sEDdVOuu6MCTQZlRvmcBME
# Jd+PuNeEM4xspgzraLqVT3xE6NRpjSV5wyHxNXf4T7YSVZXQVugYAtXueciGoWnx
# G06UE2oHYvDQa5mll1CeHDOhHu5hiwVoHI717iaQg9b+cYWnmvINFD42tRKtd3V6
# zOdGNmqQU8vGlHHeBzoh+dYyZ+CcblSGoGSgg8sCAwEAAaOCAWMwggFfMB8GA1Ud
# IwQYMBaAFDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBSBMpJBKyjNRsjE
# osYqORLsSKk/FDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAT
# BgNVHSUEDDAKBggrBgEFBQcDAzAaBgNVHSAEEzARMAYGBFUdIAAwBwYFZ4EMAQMw
# SwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdv
# UHVibGljQ29kZVNpZ25pbmdSb290UjQ2LmNybDB7BggrBgEFBQcBAQRvMG0wRgYI
# KwYBBQUHMAKGOmh0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0Nv
# ZGVTaWduaW5nUm9vdFI0Ni5wN2MwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNl
# Y3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBfNqz7+fZyWhS38Asd3tj9lwHS
# /QHumS2G6Pa38Dn/1oFKWqdCSgotFZ3mlP3FaUqy10vxFhJM9r6QZmWLLXTUqwj3
# ahEDCHd8vmnhsNufJIkD1t5cpOCy1rTP4zjVuW3MJ9bOZBHoEHJ20/ng6SyJ6UnT
# s5eWBgrh9grIQZqRXYHYNneYyoBBl6j4kT9jn6rNVFRLgOr1F2bTlHH9nv1HMePp
# GoYd074g0j+xUl+yk72MlQmYco+VAfSYQ6VK+xQmqp02v3Kw/Ny9hA3s7TSoXpUr
# OBZjBXXZ9jEuFWvilLIq0nQ1tZiao/74Ky+2F0snbFrmuXZe2obdq2TWauqDGIgb
# MYL1iLOUJcAhLwhpAuNMu0wqETDrgXkG4UGVKtQg9guT5Hx2DJ0dJmtfhAH2KpnN
# r97H8OQYok6bLyoMZqaSdSa+2UA1E2+upjcaeuitHFFjBypWBmztfhj24+xkc6Zt
# CDaLrw+ZrnVrFyvCTWrDUUZBVumPwo3/E3Gb2u2e05+r5UWmEsUUWlJBl6MGAAjF
# 5hzqJ4I8O9vmRsTvLQA1E802fZ3lqicIBczOwDYOSxlP0GOabb/FKVMxItt1UHeG
# 0PL4au5rBhs+hSMrl8h+eplBDN1Yfw6owxI9OjWb4J0sjBeBVESoeh2YnZZ/WVim
# VGX/UUIL+Efrz/jlvzCCBvcwggVfoAMCAQICEAI4uja9AFT/YrDJfJmvG3AwDQYJ
# KoZIhvcNAQELBQAwVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIENBIEVW
# IFIzNjAeFw0yMzEyMTUwMDAwMDBaFw0yNjEyMTQyMzU5NTlaMIG/MRAwDgYDVQQF
# Ewc0NjQ1MzM2MRMwEQYLKwYBBAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwCAQIT
# CERlbGF3YXJlMR0wGwYDVQQPExRQcml2YXRlIE9yZ2FuaXphdGlvbjELMAkGA1UE
# BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExHDAaBgNVBAoME1FVRVNUIFNPRlRX
# QVJFIElOQy4xHDAaBgNVBAMME1FVRVNUIFNPRlRXQVJFIElOQy4wggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQCvLDKcy/LfjbeYF1j6pj+KFNYmdKIOYV6O
# EyqqxZlxJANsSf6Ro1Coyj6aAwMGZxsz48wVs59mr3tV0k4OBDAnnjH5P71oQv9/
# lAx2FPbK/HKgV2ej8CcNgBiiJbtfpvhILyfaZsaPizmObAo/I+PNF5l8ylAAH5Ed
# dhw7Szy6KtHnsLQ2v1/cxwf+b9472ATgrOfCHudGCzpw/060SGgZZKRReA3CnzkJ
# Zsaz5HLE5IHNa1Yz0w5B0KlRpCPoOKKcirz1hR1f+t5gDWJNraKk9k+rDT2s6ojk
# YrR1okXc4V76OG3w9EMHEdONMdaeonnX+GxTB5DkDk8GhpzgHpuG7xsFm7C447hV
# JxnrZpAknP8QUYbHnaKyBnyn3t5jVyQn3QeLGA35YeqxPoBpXWVQwHnZwGy89rdB
# XrgQzzK8p1YO+02S1xJBk4ycvpP3QMDKqWUkgP3Uk++p2hAMvO3jXoCxpcUHbbCN
# DvPbhp+6RpJpgW3Vml9CvlAL5D3V+U5Ng9bOaPVCMJlRwlR6seRrhS/3HaurpD3b
# cT6pIxCV0nrlFWm7BTIRcbBsK4Ls7lpXu590+88zj+kKhKNLcW+kTa3NDe0q1brQ
# jAdqDUWDZ9Esz3ZgqGsbjf2h0RnQ+nUFDLQnI8yprxYSGaqXuAB0SIrwKJU8j5lv
# Y6rEVM+f4QIDAQABo4IB1DCCAdAwHwYDVR0jBBgwFoAUgTKSQSsozUbIxKLGKjkS
# 7EipPxQwHQYDVR0OBBYEFEWzky8j/tv+Cjeh7XUGf22derCAMA4GA1UdDwEB/wQE
# AwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEkGA1UdIARC
# MEAwNQYMKwYBBAGyMQECAQYBMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGln
# by5jb20vQ1BTMAcGBWeBDAEDMEsGA1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwu
# c2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FFVlIzNi5jcmww
# ewYIKwYBBQUHAQEEbzBtMEYGCCsGAQUFBzAChjpodHRwOi8vY3J0LnNlY3RpZ28u
# Y29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBRVZSMzYuY3J0MCMGCCsGAQUF
# BzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTBGBgNVHREEPzA9oCMGCCsGAQUF
# BwgDoBcwFQwTVVMtREVMQVdBUkUtNDY0NTMzNoEWY2VydGlmaWNhdGVzQHF1ZXN0
# LmNvbTANBgkqhkiG9w0BAQsFAAOCAYEAqCIomlzCLxajp0mDCecAQuaCYbqXeq0A
# lyO9NlkoJYxl5My/J9SU2yMrzG3S90Icf7A7c5C9qd4Qyshi17UzNiQD6kYGeX4e
# z+oPHxczsVyWgggNwdATH6r1OFfcX916va/WbM7RWRDg++2Dh3dgpuRoDNila/dZ
# 8fc2jhrWCr+3h9m/JGfJ0cWlDhPAqRqiLD7KSFFm4urgmsTLJITFXnJAV+aLuScH
# dQ/4wOBSg2ji9tpbAiZaB7FTf0axC9N2N+hBI1IOPacZLBaKged1UBeQcMc2diRj
# lFoQU+s7bSkOV9aFpuQWfvNvgWztR1KqNb3gNMyS/oLQZh8LP+UcMR10H5F5+uuU
# zwVNQAusjFsO0ZsIk5gT0hgiqqDSeQiqo0BVoPTi/DrXBVDi4R9iy9MJ/uRC84YR
# TCkSIVeJaJJ/ssEfnw44R8Ht97nrmQvrvxzHgJJ1Gvx7cqxTL8+nI3pwS4C2Foiz
# 6W09HF3dGkxwx2LhIda2ZXXj1jluPGohMYIaUjCCGk4CAQEwazBXMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgRVYgUjM2AhACOLo2vQBU/2KwyXyZrxtw
# MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIAraoZlXBXi/CHtz8F1N8K7rA2u0826REpXcoYfj7cXGMA0G
# CSqGSIb3DQEBAQUABIICACTdQunDqj6C1UJrGhZ+1dunRJZoPt/R8jMQ2MAw6bKh
# OWZgrOcXdfbm7saMt87WyAW3C1LK1yTWI1iWR8rN+xvVUSOxaaNeWcKTk0BX7+YI
# kTZ8Zy8OBksv1Y7v2toNw5NtmxhtCXnRCOpn5edTwrW4f5wYre7dTg/ic8lj5nnA
# FqzbLzxfYI9DHsX6JPHnvs7V/V6HC7gtHe+z5zh1V43xOs4rBTZu2eF7fS9Fcqhv
# c+KuQDeiA4YRd6c8jTAXDCCATy1pBDXfNKfwoUmvzkr+x3wqyHLYdzjRpjYxtdur
# 0E1JeEFHF4Vqrt/YFx6daDAbB6HN9RYA9g62jDnxfB8Ykgj7K/p7n0GPOOhoq9OU
# 7HZLwmmpZ/Ivs8lW2chZ3nFoc1K6d6ZQ6rHOPpoxqhdw2979+AiQue5xczyGw5x3
# DDERzt0Wp/zXAZx5kW/FUd+Ro9nJ5BlHgA8Ye3wuOw4gRy3SX0UjJ/k/fDJUX1vR
# SOWgQ0TJeLrUC0lq/mzhhc9bCs2IX8okMyrPnDvdOlkxeuodmlAoUI9UsYxWI4Fy
# hm8NIH8BgrHCe44SQ8M1mBb+TFJYKKGXw/tWGmkQSPhSlInym5uPLcEjBErOa+Be
# CPtMcC8ERPuwNRRdhCJ0NnjII1mmvT/AVifTJc6RkAGU6DAqCIT7s0BQ2jK+RyF0
# oYIXOjCCFzYGCisGAQQBgjcDAwExghcmMIIXIgYJKoZIhvcNAQcCoIIXEzCCFw8C
# AQMxDzANBglghkgBZQMEAgEFADB4BgsqhkiG9w0BCRABBKBpBGcwZQIBAQYJYIZI
# AYb9bAcBMDEwDQYJYIZIAWUDBAIBBQAEIB1P3BopsB1wEONKlM7wpuWoV+2baPdl
# zoWsyejvBoL9AhEA+T4C7bha3MN+eqwYQD2GjxgPMjAyNDEwMzAxMzI4NTJaoIIT
# AzCCBrwwggSkoAMCAQICEAuuZrxaun+Vh8b56QTjMwQwDQYJKoZIhvcNAQELBQAw
# YzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQD
# EzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGlu
# ZyBDQTAeFw0yNDA5MjYwMDAwMDBaFw0zNTExMjUyMzU5NTlaMEIxCzAJBgNVBAYT
# AlVTMREwDwYDVQQKEwhEaWdpQ2VydDEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0
# YW1wIDIwMjQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+anOf9pUh
# q5Ywultt5lmjtej9kR8YxIg7apnjpcH9CjAgQxK+CMR0Rne/i+utMeV5bUlYYSuu
# M4vQngvQepVHVzNLO9RDnEXvPghCaft0djvKKO+hDu6ObS7rJcXa/UKvNminKQPT
# v/1+kBPgHGlP28mgmoCw/xi6FG9+Un1h4eN6zh926SxMe6We2r1Z6VFZj75MU/HN
# mtsgtFjKfITLutLWUdAoWle+jYZ49+wxGE1/UXjWfISDmHuI5e/6+NfQrxGFSKx+
# rDdNMsePW6FLrphfYtk/FLihp/feun0eV+pIF496OVh4R1TvjQYpAztJpVIfdNsE
# vxHofBf1BWkadc+Up0Th8EifkEEWdX4rA/FE1Q0rqViTbLVZIqi6viEk3RIySho1
# XyHLIAOJfXG5PEppc3XYeBH7xa6VTZ3rOHNeiYnY+V4j1XbJ+Z9dI8ZhqcaDHOoj
# 5KGg4YuiYx3eYm33aebsyF6eD9MF5IDbPgjvwmnAalNEeJPvIeoGJXaeBQjIK13S
# lnzODdLtuThALhGtyconcVuPI8AaiCaiJnfdzUcb3dWnqUnjXkRFwLtsVAxFvGqs
# xUA2Jq/WTjbnNjIUzIs3ITVC6VBKAOlb2u29Vwgfta8b2ypi6n2PzP0nVepsFk8n
# lcuWfyZLzBaZ0MucEdeBiXL+nUOGhCjl+QIDAQABo4IBizCCAYcwDgYDVR0PAQH/
# BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYD
# VR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSfVywDdw4oFZBmpWNe7k+SH3agWzBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggr
# BgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0G
# CSqGSIb3DQEBCwUAA4ICAQA9rR4fdplb4ziEEkfZQ5H2EdubTggd0ShPz9Pce4FL
# Jl6reNKLkZd5Y/vEIqFWKt4oKcKz7wZmXa5VgW9B76k9NJxUl4JlKwyjUkKhk3aY
# x7D8vi2mpU1tKlY71AYXB8wTLrQeh83pXnWwwsxc1Mt+FWqz57yFq6laICtKjPIC
# YYf/qgxACHTvypGHrC8k1TqCeHk6u4I/VBQC9VK7iSpU5wlWjNlHlFFv/M93748Y
# TeoXU/fFa9hWJQkuzG2+B7+bMDvmgF8VlJt1qQcl7YFUMYgZU1WM6nyw23vT6QSg
# wX5Pq2m0xQ2V6FJHu8z4LXe/371k5QrN9FQBhLLISZi2yemW0P8ZZfx4zvSWzVXp
# Ab9k4Hpvpi6bUe8iK6WonUSV6yPlMwerwJZP/Gtbu3CKldMnn+LmmRTkTXpFIEB0
# 6nXZrDwhCGED+8RsWQSIXZpuG4WLFQOhtloDRWGoCwwc6ZpPddOFkM2LlTbMcqFS
# zm4cd0boGhBq7vkqI1uHRz6Fq1IX7TaRQuR+0BGOzISkcqwXu7nMpFu3mgrlgbAW
# +BzikRVQ3K2YHcGkiKjA4gi4OA/kz1YCsdhIBHXqBzR0/Zd2QwQ/l4Gxftt/8wY3
# grcc/nS//TVkej9nmUYu83BDtccHHXKibMs/yXHhDXNkoPIdynhVAku7aRZOwqw6
# pDCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh
# 1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+Feo
# An39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1
# decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxnd
# X7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6
# Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPj
# Q2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlREr
# WHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JM
# q++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh
# 3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8j
# u2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnS
# DmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# dwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAG
# A1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOC
# AgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp
# /GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40B
# IiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2d
# fNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibB
# t94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7
# T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZA
# myEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdB
# eHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnK
# cPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/
# pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yY
# lvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggWNMIIEdaADAgEC
# AhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4
# MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQAD
# ggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVir
# dprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcW
# WVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5O
# yJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7K
# e13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1
# gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn
# 3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7n
# DmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIR
# t7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEd
# slQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j
# 7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMB
# AAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNV
# HQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8v
# b2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4w
# PDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQAD
# ggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3
# bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP
# 0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZ
# NUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPL
# ILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9
# W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN2MIIDcgIBATB3MGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1
# c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAuuZrxaun+V
# h8b56QTjMwQwDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDEwMzAxMzI4NTJaMCsGCyqGSIb3DQEJ
# EAIMMRwwGjAYMBYEFNvThe5i29I+e+T2cUhQhyTVhltFMC8GCSqGSIb3DQEJBDEi
# BCAhDXnmB7bMjboxYlYDVjeegZzJq3BcmRu4yNkg2RwIkTA3BgsqhkiG9w0BCRAC
# LzEoMCYwJDAiBCB2dp+o8mMvH0MLOiMwrtZWdf7Xc9sF1mW5BZOYQ4+a2zANBgkq
# hkiG9w0BAQEFAASCAgBX5Gg744zGdmIKDD7sre6eDMgexTAfWaNseKpjYm39h0vZ
# euoE5eAbJcbR6o3ZmYT6AC934+raB8Rvea6aoR9y1W7Gpbrvkqd+KHqJ+Sh/NJ7c
# 9AgtgGEMJXqCpHxAP8aI5uB5BVq9SuWRy9LHvE5O+K5EUYUP3qi9HfnwrNs3fLxT
# gb/M66GJfzqlBoBT8sLD68iLFlXE3JM12sdcyi0C4bqGWAgWqEAKYPUYE73JKESs
# kDeSsRrGSRhqkhvF6xllSTREtl0ub61sqmEG/ujGk+4sNciwTNUSH1DpV/269SJb
# sGRmh0bv7CP2epQummVlB4kjMZVPzaFWqV0dBt9KYJ2jn0RlbFAyhd5TeEieXo41
# BTCWQc16Vl/DPnzDpnNtxjeY5Y8DD3eh5UYe1Kpq1QdHwRMTA6zIOo/ssgvtcROJ
# oEuStmaffRpuhp4S8wSmq+daHIcr2Bo4K/Da3YTwqPT5M+YfgEHy8Kjt6i+hXWoZ
# O88tffGK4a7bJrYohuFxTvgfJAt6aN0xnlb/WRkSvq9YmK7oJVop/uxraJ/229K0
# RtWkfeYd/CGcBmlBoeXkA/hcNuMssUkqzLALJnPQe7gQw20ueJXHEODfqVIat5Yc
# AQ2sO+bpxeMPQDb6sh6cubxMCZck5ySvg6LJAjRBqMOsesdqHDz56ajhW9K+Xw==
# SIG # End signature block
