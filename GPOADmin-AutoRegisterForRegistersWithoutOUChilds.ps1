$VCPath = "VCroot:\Test"
$Domains = @("asraf.local")

# Load GPOADmin module
Import-Module 'C:\Program Files\Quest\GPOADmin\GPOADmin.psd1'

foreach ($dom in $Domains) {
    Write-Host "🔍 Checking domain: $dom" -ForegroundColor Cyan

    # refresh all the objects
    $AllManagedOUs = Get-AllManagedObjects -OUs
    $AllManagedGPOs = Get-AllManagedObjects -GPOs
    $AllUnregisteredGPOs = Get-Unregistered -Domain $dom -GPOs
    $AllUnregisteredWMI = Get-Unregistered -Domain $dom -WMI
    $AllUnregisteredScripts = Get-Unregistered -Domain $dom -Scripts

    foreach ($MOU in $AllManagedOUs) {
        $OUName = $MOU.Name
        Write-Host "`n🔷 Processing Managed OU: $OUName" -ForegroundColor Magenta

        try {
            $OUObject = Get-ADOrganizationalUnit -Identity $OUName -Properties gPLink -ErrorAction Stop
            $LinkedGPOs = $OUObject.LinkedGroupPolicyObjects
        }
        catch {
            Write-Host "⚠️ Cannot read OU or links: $OUName -> $($_.Exception.Message)" -ForegroundColor Yellow
            continue
        }

        if (-not $LinkedGPOs -or $LinkedGPOs.Count -eq 0) {
            Write-Host "ℹ️ No GPO links found for $OUName" -ForegroundColor Gray
            continue
        }

        foreach ($Link in $LinkedGPOs) {
            try {
                # Extract GPO GUID and fetch object
                $GpoId = ($Link -split ',')[0] -replace '.*\{(.+?)\}.*', '$1'
                $GPOObject = Get-GPO -Guid $GpoId -ErrorAction Stop
            }
            catch {
                Write-Host "⚠️ Cannot get GPO from link: $Link -> $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }

            # check if gpo exsist
            $ManagedGPO = $AllManagedGPOs | Where-Object { $_.ADPath -eq $Link }
            if (-not $ManagedGPO) {
                $UnregisteredGPO = $AllUnregisteredGPOs | Where-Object { $_.ADPath -eq $Link }
                if ($UnregisteredGPO) {
                    Write-Host "✅ Registering Unregistered GPO: $($GPOObject.DisplayName)" -ForegroundColor Green
                    try {
                        Select-Register -VCData $UnregisteredGPO -Container $VCPath -ErrorAction Stop
                    }
                    catch {
                        Write-Host "❌ Failed to register GPO: $($GPOObject.DisplayName)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "⚠️ Cannot find unregistered GPO: $($GPOObject.DisplayName)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "✔️ Already Registered GPO: $($GPOObject.DisplayName)" -ForegroundColor Cyan
            }

            # wmifilter
            if ($GPOObject.WMIFilter) {
                $WMIName = $GPOObject.WMIFilter.Name
                $UnregisteredWMI = $AllUnregisteredWMI | Where-Object { $_.Name -eq $WMIName }
                if ($UnregisteredWMI) {
                    Write-Host "📎 Registering WMI Filter: $WMIName" -ForegroundColor Blue
                    try {
                        Select-Register -VCData $UnregisteredWMI -Container $VCPath -ErrorAction Stop
                    }
                    catch {
                        Write-Host "❌ Failed to register WMI: $WMIName" -ForegroundColor Red
                    }
                }
            }

            # scripts
            foreach ($Script in $AllUnregisteredScripts) {
                if ($Script.Name -like "*$($GPOObject.DisplayName)*") {
                    Write-Host "📜 Registering Script: $($Script.Name)" -ForegroundColor Yellow
                    try {
                        Select-Register -VCData $Script -Container $VCPath -ErrorAction Stop
                    }
                    catch {
                        Write-Host "❌ Failed to register Script: $($Script.Name)" -ForegroundColor Red
                    }
                }
            }

            # $GPOs links
            $VCGPO = Get-AllManagedObjects -GPOs | Where-Object { $_.Name -eq $GPOObject.DisplayName }
            if ($VCGPO) {
                Write-Host "🔗 Ensuring GPO is linked to OU: $OUName" -ForegroundColor DarkGreen
                try {
                    New-GPOLink -GPO $VCGPO -Container $MOU -Domain $dom -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Host "⚠️ Could not link GPO $($GPOObject.DisplayName) to $OUName" -ForegroundColor Yellow
                }
            }
        }
    }
}
