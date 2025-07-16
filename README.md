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


---

## ⚠️ Notes

- 🧪 These scripts are built for **internal environments or labs**
- 🧰 You must adapt OU paths, domain names, and group structures to your environment
- 🔒 Always test scripts in a safe, non-production environment before deployment

---

## 📄 License

MIT License – free for personal and commercial use with attribution.

---


