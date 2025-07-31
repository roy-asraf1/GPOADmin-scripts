$VCPath = "VCroot:\Test2"
$Domains = @("asraf.local")

# Load GPOADmin module
Import-Module 'C:\Program Files\Quest\GPOADmin\GPOADmin.psd1'

foreach ($dom in $Domains) {
    Write-Host "🔍 Checking domain: $dom" -ForegroundColor Cyan

    # Refresh all objects
    $AllManagedOUs = Get-AllManagedObjects -OUs
    $AllManagedGPOs = Get-AllManagedObjects -GPOs

    $AllUnregisteredOUs = Get-Unregistered -Domain $dom -OUs
    $AllUnregisteredGPOs = Get-Unregistered -Domain $dom -GPOs
    $AllUnregisteredWMI = Get-Unregistered -Domain $dom -WMI
    $AllUnregisteredScripts = Get-Unregistered -Domain $dom -Scripts

    function Register-ChildOUs {
        param (
            [string]$ParentOU
        )

        $ChildOUs = Get-ADOrganizationalUnit -SearchBase $ParentOU -SearchScope OneLevel -Filter *
        foreach ($ChildOU in $ChildOUs) {
            $ManagedChild = $AllManagedOUs | Where-Object { $_.Name -eq $ChildOU.DistinguishedName }

            # Only handle child OU if it is not already managed
            if (-not $ManagedChild) {
                $UnregisteredChild = $AllUnregisteredOUs | Where-Object { $_.Name -eq $ChildOU.DistinguishedName }
                if ($UnregisteredChild) {
                    Write-Host "🏷️ Registering Child OU: $($ChildOU.DistinguishedName)" -ForegroundColor Yellow
                    try {
                        Select-Register -VCData $UnregisteredChild -Container $VCPath -ErrorAction Stop
                    } catch {
                        Write-Host "❌ Failed to register Child OU: $($ChildOU.DistinguishedName)" -ForegroundColor Red
                    }
                }
            }

            # Recursively process deeper child OUs
            Register-ChildOUs -ParentOU $ChildOU.DistinguishedName
        }
    }

    foreach ($MOU in $AllManagedOUs) {
        $OUName = $MOU.Name
        Write-Host "`n🔷 Processing Managed OU: $OUName" -ForegroundColor Magenta

        # Register child OUs only if parent OU is managed
        $IsManagedParent = $AllManagedOUs | Where-Object { $_.Name -eq $OUName }
        if ($IsManagedParent) {
            Register-ChildOUs -ParentOU $OUName
        } else {
            Write-Host "⏭ Skipping Child OUs for unregistered parent: $OUName" -ForegroundColor DarkGray
        }

        try {
            $OUObject = Get-ADOrganizationalUnit -Identity $OUName -Properties gPLink -ErrorAction Stop
            $LinkedGPOs = $OUObject.LinkedGroupPolicyObjects
        } catch {
            Write-Host " Cannot read OU or links: $OUName -> $($_.Exception.Message)" -ForegroundColor Yellow
            continue
        }

        if (-not $LinkedGPOs -or $LinkedGPOs.Count -eq 0) {
            Write-Host "ℹ️ No new GPO links found for $OUName" -ForegroundColor Gray
            continue
        }

        foreach ($Link in $LinkedGPOs) {
            try {
                # Extract GPO GUID and fetch object [LDAP://cn={1A23B456-C78D-90EF-1234-56789ABCDEF0},cn=policies,cn=system,DC=asraf,DC=local]
                #[0] - [LDAP://cn={1A23B456-C78D-90EF-1234-56789ABCDEF0} - .*\{ ignore until { (.+?) - first group '$1' - only first group

                $GpoId = ($Link -split ',')[0] -replace '.*\{(.+?)\}.*', '$1'
                $GPOObject = Get-GPO -Guid $GpoId -ErrorAction Stop
            } catch {
                Write-Host "⚠️ Cannot get GPO from link: $Link -> $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }

            # Register unregistered GPO
            $ManagedGPO = $AllManagedGPOs | Where-Object { $_.ADPath -eq $Link }
            if (-not $ManagedGPO) {
                $UnregisteredGPO = $AllUnregisteredGPOs | Where-Object { $_.ADPath -eq $Link }
                if ($UnregisteredGPO) {
                    Write-Host " Registering Unregistered GPO: $($GPOObject.DisplayName)" -ForegroundColor Green
                    try {
                        Select-Register -VCData $UnregisteredGPO -Container $VCPath -ErrorAction Stop
                    } catch {
                        Write-Host "❌ Failed to register GPO: $($GPOObject.DisplayName)" -ForegroundColor Red
                    }
                }
                #else {
                #    Write-Host "⚠️ Cannot find unregistered GPO: $($GPOObject.DisplayName)" -ForegroundColor Yellow
                #}
            } else {
                Write-Host "Already Registered GPO: $($GPOObject.DisplayName)" -ForegroundColor Cyan
            }

            # Register WMI filter if needed
            if ($GPOObject.WMIFilter) {
                $WMIName = $GPOObject.WMIFilter.Name
                $UnregisteredWMI = $AllUnregisteredWMI | Where-Object { $_.Name -eq $WMIName }
                if ($UnregisteredWMI) {
                    Write-Host " Registering WMI Filter: $WMIName" -ForegroundColor Blue
                    try {
                        Select-Register -VCData $UnregisteredWMI -Container $VCPath -ErrorAction Stop
                    } catch {
                        Write-Host " Failed to register WMI: $WMIName" -ForegroundColor Red
                    }
                }
            }

            # Register scripts (ensure exact or partial match)
            foreach ($Script in $AllUnregisteredScripts) {
                    
                    try {
                        Write-Host " Registering Script: $($Script.Name)" -ForegroundColor Yellow
                        select-Register -VCData $Script -Container $VCPath
                    } catch {
                        Write-Host " Its register alredey: $($Script.Name)" -ForegroundColor Red
                    }
                }
            }

            # Ensure GPO is linked to OU
            $VCGPO = Get-AllManagedObjects -GPOs | Where-Object { $_.Name -eq $GPOObject.DisplayName }
            if ($VCGPO) {
                Write-Host "Ensuring GPO is linked to OU: $OUName" -ForegroundColor DarkGreen
                try {
                    New-GPOLink -GPO $VCGPO -Domain $dom -OU $MOU -ErrorAction SilentlyContinue
                } catch {
                    Write-Host "link $($GPOObject.DisplayName) to $OUName" -ForegroundColor Yellow
                }
            }
        }
    
}
