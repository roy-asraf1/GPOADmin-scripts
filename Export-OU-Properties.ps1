# Define your OU
$OU = "OU=Admins,DC=asraf,DC=local"

# Get full OU object with all properties
$OUDetails = Get-ADOrganizationalUnit -Identity $OU -Properties *

# Display on screen (optional)
$OUDetails | Format-List

# Export all properties to CSV
$OUDetails | Select-Object * | Export-Csv -Path "C:\Temp\OU_Full_Properties.csv" -NoTypeInformation -Encoding UTF8

# Export to HTML
$OUDetails | Select-Object * | ConvertTo-Html -Property * -Title "OU Properties" | Out-File "C:\Temp\OU_Full_Properties.html"

Write-Host "✅ Export completed. Check C:\Temp\OU_Full_Properties.*"
