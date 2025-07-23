Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create form
$form = New-Object System.Windows.Forms.Form
$form.Text = "GPOADmin Registration Tool"
$form.Size = New-Object System.Drawing.Size(420, 300)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Create GroupBox
$group = New-Object System.Windows.Forms.GroupBox
$group.Text = "Environment Settings"
$group.Size = New-Object System.Drawing.Size(380, 130)
$group.Location = New-Object System.Drawing.Point(15, 15)
$form.Controls.Add($group)

# Label + Domain
$labelDomain = New-Object System.Windows.Forms.Label
$labelDomain.Text = "Domain Name:"
$labelDomain.Location = New-Object System.Drawing.Point(10, 25)
$group.Controls.Add($labelDomain)

$txtDomain = New-Object System.Windows.Forms.TextBox
$txtDomain.Text = "asraf.local"
$txtDomain.Location = New-Object System.Drawing.Point(120, 22)
$txtDomain.Width = 240
$group.Controls.Add($txtDomain)

# Label + DC
$labelDC = New-Object System.Windows.Forms.Label
$labelDC.Text = "DC:"
$labelDC.Location = New-Object System.Drawing.Point(10, 55)
$group.Controls.Add($labelDC)

$txtDC = New-Object System.Windows.Forms.TextBox
$txtDC.Text = "DC01.asraf.local"
$txtDC.Location = New-Object System.Drawing.Point(120, 52)
$txtDC.Width = 240
$group.Controls.Add($txtDC)

# Label + VC Path
$labelVC = New-Object System.Windows.Forms.Label
$labelVC.Text = "VC Path:"
$labelVC.Location = New-Object System.Drawing.Point(10, 85)
$group.Controls.Add($labelVC)

$txtVC = New-Object System.Windows.Forms.TextBox
$txtVC.Text = "VCroot:\Test"
$txtVC.Location = New-Object System.Drawing.Point(120, 82)
$txtVC.Width = 240
$group.Controls.Add($txtVC)

# Button
$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = "▶ Run Registration"
$btnRun.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnRun.Size = New-Object System.Drawing.Size(180, 40)
$btnRun.Location = New-Object System.Drawing.Point(115, 160)
$btnRun.BackColor = [System.Drawing.Color]::LightSteelBlue
$form.Controls.Add($btnRun)

# Action on click
$btnRun.Add_Click({
    $DomainName = $txtDomain.Text
    $DC = $txtDC.Text
    $VCPath = $txtVC.Text

    # Validate allowed domains
    $AllowedDomains = @("asraf.local", "lab.local", "corp.local")
    if ($AllowedDomains -notcontains $DomainName.ToLower()) {
        [System.Windows.Forms.MessageBox]::Show(
            "❌ Invalid domain: $DomainName.`nOnly the following domains are allowed:`n$($AllowedDomains -join "`n")",
            "Domain Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    Import-Module 'C:\Program Files\Quest\GPOADmin\GPOADmin.psd1'

    $AllUnregisteredOUs = Get-Unregistered -Domain $DomainName -OUs
    foreach ($OU in $AllUnregisteredOUs) {
        Write-Host "📍 Registering unmanaged OU: $($OU.Name)" -ForegroundColor Magenta
        Select-Register -VCData $OU -Container $VCPath
    }

    $AllManagedOUs = Get-AllManagedObjects -OUs
    $AllUnregisteredGPOs = Get-Unregistered -Domain $DomainName -GPOs
    $AllUnmanagedWMI = Get-Unregistered -Domain $DomainName -WMI
    $AllUnmanagedScripts = Get-Unregistered -Domain $DomainName -Scripts
    $AllUnregisteredScripts = Get-Unregistered -Domain $DomainName -Scripts

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

        foreach ($MCurrentLink in $MCurrentLinks.LinkedGroupPolicyObjects) {
            Write-Host "➡️  Found GPO Link: $MCurrentLink" -ForegroundColor Yellow

            foreach ($MCurrentGPO in $AllUnregisteredGPOs) {
                if ($MCurrentGPO.ADPath -eq $MCurrentLink) {
                    Write-Host "✅ Registering GPO: $($MCurrentGPO.Name)" -ForegroundColor Green
                    Select-Register -VCData $MCurrentGPO -Container $VCPath

                    $RegisteredGPO = Get-GPO -Guid $MCurrentGPO.Id
                    $WMIName = $RegisteredGPO.WMIFilter.Name

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

                    foreach ($Script in $AllUnregisteredScriptss) {
                        Write-Host "📜 Registering Script: $($Script.Name)" -ForegroundColor Yellow
                        Select-Register -VCData $Script -Container $VCPath
                        }
                    }
                }
            }
        }
    

    [System.Windows.Forms.MessageBox]::Show("Done processing GPOs and OUs!", "Completed", "OK", "Information")
})

# Show form
$form.Topmost = $true
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
