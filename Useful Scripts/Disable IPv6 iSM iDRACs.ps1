#Failover Cluster Manager shows iDRAC iSM Card as a cluster interface and available for Live Migration Network#



#Disable IPv6 at iSM Nic ONLY "Ethernet NDIS"

#icm -ComputerName (Get-ClusterNode).name -ScriptBlock {Disable-NetAdapterBinding –InterfaceAlias “Ethernet” –ComponentID ms_tcpip6 -verbose}

#Reopen the FCM to refresh






#Option2 (Run on all NODES. After, restart the Ethernet Adapter)

#Remove the USB NIC from any cluster communication by using the following script:
$rndisAdapter = Get-NetAdapter -InterfaceDescription 'Remote NDIS Compatible Device' -ErrorAction SilentlyContinue

    if ($rndisAdapter)
    
{
        #Write-Log -Message 'Remote NDIS found on the system. Cluster communication will be disabled on this adapter.'
        
        # Get the network adapter and associated cluster network
        $adapterId = [Regex]::Matches($rndisAdapter.InstanceID, '(?<={)(.*?)(?=})').Value
        $usbNICInterface = (Get-ClusterNetworkInterface).Where({$_.adapterId -eq $adapterId})
        $usbNICClusterNetwork = $usbNICInterface.Network

        # Disable Cluster communication on the identified cluster network
        (Get-ClusterNetwork -Name $usbNICClusterNetwork.ToString()).Role = 0
    }

#Run on all nodes to exclude Remote NDIS NIC from Cluster Networks
New-item -Path HKLM:\system\currentcontrolset\services\clussvc\parameters -Verbose
New-ItemProperty -Path HKLM:\system\CurrentControlSet\Services\clussvc\parameters -Name ExcludeAdaptersByDescription -Value "Remote NDIS Compatible Device" -verbose
Get-ItemProperty -Path HKLM:\system\CurrentControlSet\Services\clussvc\parameters -Name ExcludeAdaptersByDescription | Fl ExcludeAdaptersByDescription -Verbose