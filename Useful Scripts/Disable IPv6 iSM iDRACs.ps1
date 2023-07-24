#Failover Cluster Manager shows iDRAC iSM Card as a cluster interface and available for Live Migration Network#



#Disable IPv6 at iSM Nic ONLY "Ethernet NDIS"

icm -ComputerName (Get-ClusterNode).name -ScriptBlock {Disable-NetAdapterBinding –InterfaceAlias “Ethernet” –ComponentID ms_tcpip6 -verbose}

#Reopen the FCM to refresh






#Option2

#Run on all nodes to exclude Remote NDIS NIC from Cluster Networks
New-item -Path HKLM:\system\currentcontrolset\services\clussvc\parameters -Verbose
New-ItemProperty -Path HKLM:\system\CurrentControlSet\Services\clussvc\parameters -Name ExcludeAdaptersByDescription -Value "Remote NDIS Compatible Device" -verbose
Get-ItemProperty -Path HKLM:\system\CurrentControlSet\Services\clussvc\parameters -Name ExcludeAdaptersByDescription | Fl ExcludeAdaptersByDescription -Verbose