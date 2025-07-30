Get-WmiObject -Class Win32_Service | Select-Object Name, StartName | Sort-Object StartName

Get-Service | Where-Object { $_.DisplayName -like "*GPO*" } | ForEach-Object {
    Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'" | Select-Object Name, StartName
}
