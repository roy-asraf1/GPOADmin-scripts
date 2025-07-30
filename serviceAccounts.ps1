Get-WmiObject -Class Win32_Service | Select-Object Name, StartName | Sort-Object StartName

Get-Service | Where-Object { $_.DisplayName -like "*GPO*" } | ForEach-Object {
    Get-WmiObject -Class Win32_Service -Filter "Name='$($_.Name)'" | Select-Object Name, StartName
}

Start-Transcript -Path "C:\Logs\ScriptLog.txt" -Append

65536,65792,65793,65794,65795,131072,131073,131074,1835008,1573120,1573376,1049344,1049345,1049600,197888,197889,197890,197891,1049856

cd "C:\Program Files\Quest\GPOADmin"

# דומיין ראשון
.\GPOADmin.MinimumPermissions.ps1 `
   -ServiceAccount "ASRAF\ServiceAccountName" `
   -Domain "asraf.local" `
   -LDAPServer "dc01.asraf.local" `
   -Permissions "All" `
   -Confirm:$false

# דומיין שני
.\GPOADmin.MinimumPermissions.ps1 `
   -ServiceAccount "ASRAF\ServiceAccountName" `
   -Domain "lab.local" `
   -LDAPServer "dc01.lab.local" `
   -Permissions "All" `
   -Confirm:$false
