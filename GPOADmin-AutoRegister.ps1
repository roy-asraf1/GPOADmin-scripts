# Define environment values maybe@
#$dom = ("asraf.local")
$DC = ("DC01.asraf.local") #need to add for poalim
$VCPath = ("VCroot:\Test") #need to add for poalim
$Domains = ("asraf.local") #need to add for poalim

# Load GPOADmin module
Import-Module 'C:\Program Files\Quest\GPOADmin\GPOADmin.psd1' #need to change for poalim
foreach ($dom in $Domains){

    # Register any unregistered OUs (not managed yet)
    $AllUnregisteredOUs = Get-Unregistered -Domain $dom -OUs
    foreach ($OU in $AllUnregisteredOUs) {
        Write-Host "📍 Registering unmanaged OU: $($OU.Name)" -ForegroundColor Magenta
        Select-Register -VCData $OU -Container $VCPath
    }

    # Refresh managed OUs list after registering
    $AllManagedOUs = Get-AllManagedObjects -OUs

    # Get unregistered GPOs, WMI, and (optionally) script objects
    $AllUnregisteredGPOs = Get-Unregistered -Domain $dom -GPOs
    $AllUnmanagedWMI = Get-Unregistered -Domain $dom -WMI
    $AllUnmanagedScripts = Get-Unregistered -Domain $dom -Scripts 
    $AllUnregisteredScripts = Get-Unregistered -Domain $dom -Scripts

    foreach ($dom in $Domains){
    # Loop through managed OUs
        foreach ($MOU in $AllManagedOUs) {
            try {
                $OUName = $MOU.Name
                Write-Host "`n🔷 Processing OU: $OUName" -ForegroundColor Cyan
                Get-ADOrganizationalUnit -Identity $MOU.Name -Properties gplink -Server $DC
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
                        $registeredgpo = Get-GPO -Guid $MCurrentGPO.Id
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

                        foreach ($Script in $AllUnregisteredScripts) {
                        Write-Host "📜 Registering Script: $($Script.Name)" -ForegroundColor Yellow
                        Select-Register -VCData $Script -Container $VCPath
                        }

                        $Date = Get-Date -Format "yyyyMMdd_HHmm"
                        $BackupPath = "C:\GPO_Backups\$dom\$Date"

                        if (!(Test-Path $BackupPath)) {
                            New-Item -Path $BackupPath -ItemType Directory | Out-Null
                        }

                        Write-Host "💾 Backing up GPO: $($MCurrentGPO.Name) to $BackupPath" -ForegroundColor DarkGreen
                        try {
                            Backup-GPO -Guid $MCurrentGPO.Id -Path $BackupPath -Domain $dom -Server $DC -ErrorAction Stop
                        } 
                        catch {
                            Write-Host "⚠️ Failed to backup GPO: $($MCurrentGPO.Name)" -ForegroundColor Red
                        }


                    }
                }
            }
        }
    }
}
