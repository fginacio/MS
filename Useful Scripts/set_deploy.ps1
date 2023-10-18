DSU 

Install-WindowsFeature Hyper-v,Failover-Clustering –IncludeManagementTools -Restart

New-VMSwitch -name "HV-vSW" -NetAdapterName "HV1" , "HV2" -EnableEmbeddedTeaming $true -AllowManagementOS 0

Add-VMNetworkAdapter -ManagementOS -SwitchName "HV-vSW" -Name "MGMT"

Add-VMNetworkAdapter -ManagementOS -SwitchName "HV-vSW" -Name "LiveMigration"

Add-VMNetworkAdapter -ManagementOS -SwitchName "HV-vSW" -Name "HeartBeat"

Get-VMNetworkAdapter –ManagementOS

Get-NetAdapter

New-NetIPAddress -InterfaceIndex 6 -IPAddress 192.168.10.11 -AddressFamily IPv4 -PrefixLength 24 -DefaultGateway 192.168.10.1

New-NetIPAddress -InterfaceIndex 12 -IPAddress 10.0.0.11 -AddressFamily IPv4 -PrefixLength 24 -DefaultGateway 10.0.0.1

New-NetIPAddress -InterfaceIndex 24 -IPAddress 10.0.10.11 -AddressFamily IPv4 -PrefixLength 24 -DefaultGateway 10.0.10.1

New-NetIPAddress -InterfaceIndex 28 -IPAddress 10.0.20.11 -AddressFamily IPv4 -PrefixLength 24 -DefaultGateway 10.0.20.1

Set-DNSClientServerAddress –InterfaceIndex 12 –ServerAddresses 10.0.0.10,8.8.8.8

netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4:8,any dir=in action=allow

Add-Computer -DomainName lab.local -NewName HyperV-001 -Restart

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 0 /f

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f

icm -ComputerName (Get-ClusterNode).name -ScriptBlock {Remove-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-IoTrace/Diagnostic" -Name "Enabled"}




Start-Process "C:\Program Files\Intel\Umb\Winx64\PROSETDX\DxSetup.exe" -ArgumentList "DMIX=0 /qn" -Wait *** SE TIVER PLACA INTEL ***


Comandos uteis:

# Para instalar Drivers e Firmwares
https://www.dell.com/support/kbdoc/pt-br/000116751/como-instalar-drivers-e-firmwares-usando-o-dsu-dell-emc-system-update-no-windows
*** Antes de executar baixe o DSU e instale no servidor isso garante que os ultimos drivers e firmwares serão instalados ***

#Failover Cluster Manager shows iDRAC iSM Card as a cluster interface and available for Live Migration Network#

#Disable IPv6 at iSM Nic ONLY "Ethernet NDIS"

icm -ComputerName (Get-ClusterNode).name -ScriptBlock {Disable-NetAdapterBinding –InterfaceAlias “Ethernet” –ComponentID ms_tcpip6 -verbose}

# Remove DCB das placas de rede Intel
Start-Process "C:\Program Files\Intel\Umb\Winx64\PROSETDX\DxSetup.exe" -ArgumentList "DMIX=0 /qn" -Wait


# Caso queria fazer vlantag
#Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName vNIC_Name -Access -VlanId 100

 

# Caso queria remover vlantag
#Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName vNIC_Name -Untagged

 

# Habilitar ping no firewall
netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4:8,any dir=in action=allow
netsh advfirewall firewall add rule name="Allow ICMPv6" protocol=icmpv6:8,any dir=in action=allow

 

# Desabilitar todos os perfils de firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Lista as vnics criadas
Get-VMNetworkAdapter –ManagementOS

# Lista as pnics
Get-NetAdapter


# Setar ip com dns e gw
Get-NetAdapter -Name Ethernet0| New-NetIPAddress –IPAddress 192.168.2.50 -DefaultGateway 192.168.2.1 -PrefixLength 24

Set-DNSClientServerAddress –InterfaceIndex 8 –ServerAddresses 192.168.2.11,10.1.2.11

# Seta as variaveis e depois  aplica para a nic em questão
$dns1:192.168.0.1

$dns2:192.168.0.2

Set-DNSClientServerAddress –InterfaceIndex 8 –ServerAddresses $dns1,$dns2