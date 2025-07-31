# ==============================
# Test GPOADmin Required Ports
# ==============================

# ===== Define your servers here =====
$DNS_Server_IP        = "10.0.0.10"   # DC01 is also the DNS
$WINS_Server_IP       = "10.0.0.10"   # Assuming DC01 is WINS as well
$GPOADmin_Server_IP   = "10.0.0.10"   # Assuming GPOADmin installed on DC01
$LDAP_or_ADLDS_IP     = "10.0.0.10"   # LDAP on DC01
$ADLDS_Server_IP      = "10.0.0.10"   # AD LDS same server (if installed)
$SQL_Server_IP        = "10.0.0.10"   # Assuming SQL Server is also local
$FileShare_Server_IP  = "10.0.0.10"   # GPO Archives (SMB) on DC01

# =====================================

# Define all targets & ports using the variables above
$Targets = @{
    "DNS/WINS Servers" = @(
        @{Server=$DNS_Server_IP;       Port=53;    Name="DNS (TCP/UDP)"},
        @{Server=$WINS_Server_IP;      Port=137;   Name="WINS"}
    )

    "GPOADmin Server (Client -> Server)" = @(
        @{Server=$GPOADmin_Server_IP;  Port=88;    Name="Kerberos"},
        @{Server=$GPOADmin_Server_IP;  Port=464;   Name="Kerberos Password"},
        @{Server=$GPOADmin_Server_IP;  Port=40200; Name="Version Control (Inbound)"}
    )

    "Configuration Storage (GPOADmin -> AD/SQL)" = @(
        @{Server=$LDAP_or_ADLDS_IP;    Port=389;   Name="LDAP / AD LDS (default)"},
        @{Server=$ADLDS_Server_IP;     Port=50000; Name="AD LDS (when AD installed)"},
        @{Server=$SQL_Server_IP;       Port=1433;  Name="SQL Server (default)"}
    )

    "GPO Archives (GPOADmin -> Backup Storage)" = @(
        @{Server=$FileShare_Server_IP; Port=135;   Name="RPC Endpoint Mapper"},
        @{Server=$FileShare_Server_IP; Port=138;   Name="NetBIOS Datagram"},
        @{Server=$FileShare_Server_IP; Port=139;   Name="NetBIOS Session"},
        @{Server=$FileShare_Server_IP; Port=445;   Name="SMB"},
        @{Server=$SQL_Server_IP;       Port=1433;  Name="SQL Server (for GPO Backups)"},
        @{Server=$ADLDS_Server_IP;     Port=389;   Name="AD LDS (default)"},
        @{Server=$ADLDS_Server_IP;     Port=50000; Name="AD LDS (when AD installed)"}
    )
}

Write-Host "`n=== GPOADmin Port Test Report ===`n"

foreach ($category in $Targets.Keys) {
    Write-Host "`n### $category ###`n"
    foreach ($item in $Targets[$category]) {
        $result = Test-NetConnection -ComputerName $item.Server -Port $item.Port -WarningAction SilentlyContinue
        if ($result.TcpTestSucceeded) {
            Write-Host "[OPEN]   $($item.Server):$($item.Port) - $($item.Name)" -ForegroundColor Green
        } else {
            Write-Host "[CLOSED] $($item.Server):$($item.Port) - $($item.Name)" -ForegroundColor Red
        }
    }
}
