# Load GPOADmin module
Import-Module 'D:\Program Files\Quest\GPOADmin\GPOADmin.psd1'

# Define container to clean
$ContainerPath = "VCroot:\Test"

# Get all registered GPOs and WMI Filters in the container
$RegisteredGPOs = Get-ChildItem -Path $ContainerPath | Where-Object { $_.Type -eq 'GPO' }
$RegisteredWMIs = Get-ChildItem -Path $ContainerPath | Where-Object { $_.Type -eq 'WMI Filter' }

# Unregister GPOs
foreach ($gpo in $RegisteredGPOs) {
    Select-Unregister -VCData $gpo
    Write-Host "❌ Unregistered GPO: $($gpo.Name)"
}

# Unregister WMI Filters
foreach ($wmi in $RegisteredWMIs) {
    Select-Unregister -VCData $wmi
    Write-Host "❌ Unregistered WMI Filter: $($wmi.Name)"
}

Write-Host "✅ Cleanup completed from $ContainerPath"
