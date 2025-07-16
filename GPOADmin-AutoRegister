# Import the GPOADmin module
Import-Module 'D:\Program Files\Quest\GPOADmin\GPOADmin.psd1'

# Get all managed Organizational Units (OUs) in GPOADmin
$AllManagedOUs = Get-AllManagedObjects -OUs

# Get all unregistered GPOs from Active Directory
$AllUnregisteredGPOs = Get-Unregistered -Domain Domain.Name -GPOs

# Get all unregistered WMI filters from Active Directory
$AllUnamangedWMI = Get-Unregistered -Domain Domain.Name -WMI

# Loop through each Managed OU
foreach ($MOU in $AllManagedOUs) {

    # Get current GPO links on the OU from Active Directory
    $MCurrentLinks = Get-ADOrganizationalUnit -Identity $MOU.Name -Properties gplink -Server Domain.Name

    # Loop through each linked GPO
    foreach ($MCurrentLink in $MCurrentLinks.LinkedGroupPolicyObjects) {

        # Loop through each unregistered GPO
        foreach ($MCurrentGPO in $AllUnregisteredGPOs) {

            # If the AD path of the GPO matches the linked GPO path
            if ($MCurrentGPO.ADPath -eq $MCurrentLink) {

                # Register the GPO in GPOADmin under the specified container
                Select-Register -VCData $MCurrentGPO -Container "VCRoot:\Test"

                # Get the newly registered GPO from Active Directory
                $RegisteredGPO = Get-GPO -Guid $MCurrentGPO.Id

                # Retrieve the name of the WMI filter used by the GPO (if any)
                $WMIName = $RegisteredGPO.WMIFilter.name

                # Loop through each unregistered WMI filter
                foreach ($CurrentWMI in $AllUnamangedWMI) {

                    # If the WMI filter name matches the one used by the GPO
                    if ($CurrentWMI.Name -eq $WMIName) {

                        # Register the WMI filter in GPOADmin
                        Select-Register -VCData $CurrentWMI -Container "VCroot:\Test"
                    }
                }
            }
        }
    }
}
