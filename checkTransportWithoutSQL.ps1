# ==============================
# Test GPOADmin Required Ports (Final Version - No SQL, No AD LDS, No WINS)
# ==============================

# ===== Define your servers here =====
$DNS_Server_IP        = "10.0.0.10"   # DC01 is also the DNS
$GPOADmin_Server_IP   = "10.0.0.10"   # Assuming GPOADmin installed on DC01
$LDAP_Server_IP       = "10.0.0.10"   # LDAP on DC01
$FileShare_Server_IP  = "10.0.0.10"   # GPO Archives (SMB) on DC01

# =====================================

# Define all targets & ports using the variables above
$Targets = @{
    "DNS Server" = @(
        @{Server=$DNS_Server_IP;       Port=53;    Name="DNS (TCP/UDP)"}
    )

    "GPOADmin Server (Client -> Server)" = @(
        @{Server=$GPOADmin_Server_IP;  Port=88;    Name="Kerberos"},
        @{Server=$GPOADmin_Server_IP;  Port=464;   Name="Kerberos Password"},
        @{Server=$GPOADmin_Server_IP;  Port=40200; Name="Version Control (Inbound)"}
    )

    "Configuration Storage (GPOADmin -> AD)" = @(
        @{Server=$LDAP_Server_IP;      Port=389;   Name="LDAP / Active Directory"}
    )

    "GPO Archives (GPOADmin -> Backup Storage)" = @(
        @{Server=$FileShare_Server_IP; Port=135;   Name="RPC Endpoint Mapper"},
        @{Server=$FileShare_Server_IP; Port=138;   Name="NetBIOS Datagram"},
        @{Server=$FileShare_Server_IP; Port=139;   Name="NetBIOS Session"},
        @{Server=$FileShare_Server_IP; Port=445;   Name="SMB"}
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
