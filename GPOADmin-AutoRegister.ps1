# Define environment values
$DomainName = "asraf.local"
$DC = "DC01.asraf.local"
$VCPath = "VCroot:\Test"

# Load GPOADmin module
Import-Module 'C:\Program Files\Quest\GPOADmin\GPOADmin.psd1'

# Register any unregistered OUs (not managed yet)
$AllUnregisteredOUs = Get-Unregistered -Domain $DomainName -OUs
foreach ($OU in $AllUnregisteredOUs) {
    Write-Host "📍 Registering unmanaged OU: $($OU.Name)" -ForegroundColor Magenta
    Select-Register -VCData $OU -Container $VCPath
}

# Refresh managed OUs list after registering
$AllManagedOUs = Get-AllManagedObjects -OUs

# Get unregistered GPOs, WMI, and (optionally) script objects
$AllUnregisteredGPOs = Get-Unregistered -Domain $DomainName -GPOs
$AllUnmanagedWMI = Get-Unregistered -Domain $DomainName -WMI
# $AllUnmanagedScripts = Get-Unregistered -Domain $DomainName -Scripts # <- Uncomment if you want scripts

# Loop through managed OUs
foreach ($MOU in $AllManagedOUs) {
    try {
        $OUName = $MOU.Name
        Write-Host "`n🔷 Processing OU: $OUName" -ForegroundColor Cyan
        $MCurrentLinks = Get-ADOrganizationalUnit -Identity $OUName -Properties gplink -Server $DC
    } catch {
        Write-Host "❌ Could not access OU: $OUName" -ForegroundColor Red
        continue
    }

    # Loop through each GPO linked to the OU
    foreach ($MCurrentLink in $MCurrentLinks.LinkedGroupPolicyObjects) {
        Write-Host "➡️  Found GPO Link: $MCurrentLink" -ForegroundColor Yellow

        # Try to find if the linked GPO is unregistered
        foreach ($MCurrentGPO in $AllUnregisteredGPOs) {
            if ($MCurrentGPO.ADPath -eq $MCurrentLink) {
                Write-Host "✅ Registering GPO: $($MCurrentGPO.Name)" -ForegroundColor Green
                Select-Register -VCData $MCurrentGPO -Container $VCPath

                # Get full GPO object to access WMI
                $RegisteredGPO = Get-GPO -Guid $MCurrentGPO.Id
                $WMIName = $RegisteredGPO.WMIFilter.Name

                # Register WMI filter if unregistered
                if ($WMIName) {
                    Write-Host "🔍 GPO uses WMI Filter: $WMIName" -ForegroundColor DarkCyan
                    foreach ($CurrentWMI in $AllUnmanagedWMI) {
                        if ($CurrentWMI.Name -eq $WMIName) {
                            Write-Host "📎 Registering WMI Filter: $WMIName" -ForegroundColor Blue
                            Select-Register -VCData $CurrentWMI -Container $VCPath
                        }
                    }
                } else {
                    Write-Host "ℹ️  No WMI Filter assigned to GPO." -ForegroundColor DarkGray
                }

                # OPTIONAL: Register Script Objects linked to the GPO (e.g., Startup/Logon scripts)
                foreach ($Script in $AllUnmanagedScripts) {
                    if ($Script.Name -like "*$($RegisteredGPO.DisplayName)*") {
                        Write-Host "📜 Registering Script Object: $($Script.Name)" -ForegroundColor DarkYellow
                        Select-Register -VCData $Script -Container $VCPath
                    }
                }
            }
        }
    }
}
