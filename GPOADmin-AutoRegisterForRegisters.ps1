$VCPath = "VCroot:\Test"
$Domains = @("asraf.local")

# Load GPOADmin module
Import-Module 'C:\Program Files\Quest\GPOADmin\GPOADmin.psd1'

foreach ($dom in $Domains) {
    Write-Host "🔍 Checking domain: $dom" -ForegroundColor Cyan

    # שלב 1: לרענן אובייקטים מנוהלים ולא רשומים
    $AllManagedOUs = Get-AllManagedObjects -OUs
    $AllManagedGPOs = Get-AllManagedObjects -GPOs
    $AllUnregisteredGPOs = Get-Unregistered -Domain $dom -GPOs
    $AllUnregisteredWMI = Get-Unregistered -Domain $dom -WMI
    $AllUnregisteredScripts = Get-Unregistered -Domain $dom -Scripts

    foreach ($MOU in $AllManagedOUs) {
        try {
            $OUName = $MOU.Name
            Write-Host "`n🔷 Processing Managed OU: $OUName" -ForegroundColor Magenta

            $OUObject = Get-ADOrganizationalUnit -Identity $OUName -Properties gPLink
            $LinkedGPOs = $OUObject.LinkedGroupPolicyObjects

            foreach ($Link in $LinkedGPOs) {
                # Extract GPO GUID
                $GpoId = ($Link -split ',')[0] -replace '.*\{(.+?)\}.*', '$1'
                $GPOObject = $null
                try {
                    $GPOObject = Get-GPO -Guid $GpoId
                } catch {
                    Write-Host "⚠️ Could not get GPO for link: $Link" -ForegroundColor Red
                    continue
                }

                # רענון הרשימות לפני בדיקה
                $AllManagedGPOs = Get-AllManagedObjects -GPOs
                $AllUnregisteredGPOs = Get-Unregistered -Domain $dom -GPOs

                # אם GPO לא רשום – נרשום אותו
                $ManagedGPO = $AllManagedGPOs | Where-Object { $_.ADPath -eq $Link }
                if (-not $ManagedGPO) {
                    $UnregisteredGPO = $AllUnregisteredGPOs | Where-Object { $_.ADPath -eq $Link }
                    if ($UnregisteredGPO) {
                        Write-Host "✅ Registering Unregistered GPO: $($GPOObject.DisplayName)" -ForegroundColor Green
                        Select-Register -VCData $UnregisteredGPO -Container $VCPath

                        # רענון אחרי רישום
                        $AllManagedGPOs = Get-AllManagedObjects -GPOs
                    } else {
                        Write-Host "⚠️ Cannot find unregistered GPO object: $($GPOObject.DisplayName)" -ForegroundColor Red
                        continue
                    }
                } else {
                    Write-Host "✔️ Already Registered GPO: $($GPOObject.DisplayName)" -ForegroundColor Cyan
                }

                
                if ($GPOObject.WMIFilter) {
                    $AllUnregisteredWMI = Get-Unregistered -Domain $dom -WMI
                    $WMIName = $GPOObject.WMIFilter.Name
                    $UnregisteredWMI = $AllUnregisteredWMI | Where-Object { $_.Name -eq $WMIName }
                    if ($UnregisteredWMI) {
                        Write-Host "📎 Registering WMI Filter: $WMIName" -ForegroundColor Blue
                        Select-Register -VCData $UnregisteredWMI -Container $VCPath
                    }
                }

                
                $AllUnregisteredScripts = Get-Unregistered -Domain $dom -Scripts
                foreach ($Script in $AllUnregisteredScripts) {
                    if ($Script.Name -like "*$($GPOObject.DisplayName)*") {
                        Write-Host "📜 Registering Script: $($Script.Name)" -ForegroundColor Yellow
                        Select-Register -VCData $Script -Container $VCPath
                    }
                }

                # ווידוא לינק בין OU ל-GPO
                $VCGPO = Get-AllManagedObjects -GPOs | Where-Object { $_.Name -eq $GPOObject.DisplayName }
                if ($VCGPO) {
                    Write-Host "🔗 Ensuring GPO is linked to OU: $OUName" -ForegroundColor DarkGreen
                    New-GPOLink -GPO $VCGPO -Container $MOU -Domain $dom -ErrorAction SilentlyContinue
                }
            }

        } catch {
            Write-Host "❌ Could not process OU: $OUName" -ForegroundColor Red
            continue
        }
    }
}
