# 🛠️ GPOADmin Automation Scripts

A collection of PowerShell scripts for automating tasks in **GPOADmin** and **Active Directory**, including registration and cleanup of GPOs, WMI filters, and post-user provisioning.

---

## 📦 Scripts Overview

### 📜 `AutoRegister-GPO-WMI.ps1`
Automatically registers **GPOs** and associated **WMI filters** that are:
- Linked to **managed OUs** in Active Directory
- Not yet registered in GPOADmin

#### ✅ Requirements
- GPOADmin PowerShell Module (`GPOADmin.psd1`)
- Active Directory read access
- Replace `Domain.Name` with your domain
- Customize container path (e.g. `VCroot:\Test`)

---

### 📜 `Unregister-GPO-WMI.ps1`
Unregisters **GPOs** and **WMI filters** from a specific GPOADmin container (such as after testing or cleanup).

#### ✅ Requirements
- GPOADmin PowerShell Module
- Edit `$ContainerPath` as needed (e.g. `VCroot:\Test`)

---

### 📜 `PostUserProvisioning.ps1`
Executes post-creation logic for new AD users:
- Clears group memberships
- Sets `DisplayName`, `GivenName`, `Surname`, and `Title`
- Moves users to specific OUs based on `Office`
- Adds users to department-based security groups

#### ✅ Requirements
- ActiveDirectory PowerShell Module
- Variables: `$Request.Name`, `$FirstName`, `$LastName`
- Predefined OU and group naming structure

---

## 📁 Folder Structure Recommendation

