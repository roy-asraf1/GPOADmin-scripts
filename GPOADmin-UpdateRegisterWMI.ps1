$Domains = @("asraf.local")
$DC = "DC01.asraf.local"
$VCPath = "VCroot:\Test"

# Load GPOADmin module
Import-Module 'C:\Program Files\Quest\GPOADmin\GPOADmin.psd1'

foreach ($dom in $Domains) {
    # Register unmanaged OUs
    $AllUnregisteredOUs = Get-Unregistered -Domain $dom -OUs
    foreach ($OU in $AllUnregisteredOUs) {
        Write-Host "📍 Registering unmanaged OU: $($OU.Name)" -ForegroundColor Magenta
        Select-Register -VCData $OU -Container $VCPath
    }

    $AllManagedOUs = Get-AllManagedObjects -OUs
    $AllUnregisteredGPOs = Get-Unregistered -Domain $dom -GPOs
    $AllUnmanagedWMI = Get-Unregistered -Domain $dom -WMI
    $AllUnregisteredScripts = Get-Unregistered -Domain $dom -Scripts

    foreach ($MOU in $AllManagedOUs) {
        $OUName = $MOU.Name
        try {
            $MCurrentLinks = (Get-ADOrganizationalUnit -Identity $OUName -Properties gPLink -Server $DC).LinkedGroupPolicyObjects
        } catch {
            Write-Host "❌ Cannot access OU: $OUName" -ForegroundColor Red
            continue
        }

        foreach ($GpoLink in $MCurrentLinks) {
            # Try match unregistered GPOs
            $LinkedGPO = $AllUnregisteredGPOs | Where-Object { $_.ADPath -eq $GpoLink }

            if ($LinkedGPO) {
                Write-Host "✅ Registering GPO: $($LinkedGPO.Name)" -ForegroundColor Green
                Select-Register -VCData $LinkedGPO -Container $VCPath
            }

            # Retrieve GPO object by GUID from ADPath
            $gpoId = ($GpoLink -split ',')[0] -replace '.*\{(.+?)\}.*', '$1'
            try {
                $GPOObject = Get-GPO -Guid $gpoId
            } catch {
                Write-Host "⚠️ Cannot fetch GPO object for: $GpoLink" -ForegroundColor Red
                continue
            }

            # WMI Filter registration
            $WMIName = $GPOObject.WMIFilter.Name
            if ($WMIName) {
                $CurrentWMI = $AllUnmanagedWMI | Where-Object { $_.Name -eq $WMIName }
                if ($CurrentWMI) {
                    Write-Host "📎 Registering WMI Filter: $WMIName" -ForegroundColor Blue
                    Select-Register -VCData $CurrentWMI -Container $VCPath
                }
            }

            # Register script if matching name
            foreach ($Script in $AllUnregisteredScripts) {
                if ($Script.Name -like "*$($GPOObject.DisplayName)*") {
                    Write-Host "📜 Registering Script: $($Script.Name)" -ForegroundColor DarkYellow
                    Select-Register -VCData $Script -Container $VCPath
                }
            }
        }
    }
}
