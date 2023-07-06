#Failover Cluster Manager shows iDRAC iSM Card as a cluster interface and available for Live Migration Network#



#Disable IPv6 at iSM Nic ONLY "Ethernet NDIS"

icm -ComputerName (Get-ClusterNode).name -ScriptBlock {Disable-NetAdapterBinding –InterfaceAlias “Ethernet” –ComponentID ms_tcpip6 -verbose}

#Reopen the FCM to refresh