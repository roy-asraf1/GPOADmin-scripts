Import-Module 'C:\Program Files\Quest\GPOADmin\GPOADmin.psd1'

# List all available commands in the GPOADmin module:
Get-Command -Module GPOADmin

# Get help for a specific command (e.g., Get-Unregistered): Or for full documentation:
Get-Help Get-Unregistered -Detailed
Get-Help Get-Unregistered -Full

# Search for commands by keyword (e.g., anything containing "Register"):
Get-Command -Module GPOADmin | Where-Object Name -like "*Register*"
