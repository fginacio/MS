#install roles and features
Install-WindowsFeature -Name Hyper-V, Failover-Clustering, Data-Center-Bridging , Rsat-Clustering-Powershell -IncludeAllSubFeature -IncludeManagementTools -restart

#Set PowerOptions to Performance
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

#create set teaming and vmnics
New-VMSwitch -Name vSwitch -NetAdapterName "NIC1","NIC2" -EnableEmbeddedTeaming 1 -AllowManagementOS 0 -MinimumBandwidthMode Weight 
Set-VMSwitchTeam -Name vswitch -LoadBalancingAlgorithm HyperVPort 

Add-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName MGMT -SwitchName vSwitch
#Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName MGMT -Access -VlanId 2 
Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName MGMT -Untagged

Add-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName LiveMigration -SwitchName vSwitch
Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName LiveMigration -Access -VlanId 91 

Add-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName Cluster -SwitchName vSwitch
Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName Cluster -Access -VlanId 90


#set nics storage 
#mellanox com windows 22 - RoCEv2
#mellanox com windows 2019 - RoCE
#Qlogic(outros hbas não mellanox) - iWarp
Set-NetAdapter -name Storage1 -VlanID 180
Set-NetAdapter -name Storage2 -VlanID 181
Set-NetAdapterAdvancedProperty -Name "Storage1" -DisplayName "NetworkDirect Technology" -DisplayValue "RoCEv2"
Set-NetAdapterAdvancedProperty -Name "Storage2" -DisplayName "NetworkDirect Technology" -DisplayValue "RoCEv2"
Set-NetAdapterAdvancedProperty "Storage1" -DisplayName "Jumbo Packet" -DisplayValue "9014"
Set-NetAdapterAdvancedProperty "Storage2" -DisplayName "Jumbo Packet" -DisplayValue "9014"
Enable-NetAdapterRDMA -Name "Storage1", "Storage2"
Get-NetAdapter Storage* | Disable-NetAdapterQos


#enable stroage spaces direct
Enable-ClusterS2D -Verbose
Get-ClusterS2D
Get-StoragePool
Get-StorageSubSystem -FriendlyName <clustername> | Get-StorageHealthReport


#set pagefile

$blockCacheMB = (Get-Cluster).BlockCacheSize
$pageFilePath = "C:\pagefile.sys"
$initialSize = [Math]::Round(51200 + $blockCacheMB)
$maximumSize = [Math]::Round(51200 + $blockCacheMB)
$system = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
if ($system.AutomaticManagedPagefile) {
    $system.AutomaticManagedPagefile = $false
    $system.Put()
}
$currentPageFile = Get-WmiObject -Class Win32_PageFileSetting
if ($currentPageFile.Name -eq $pageFilePath)
{
    $currentPageFile.InitialSize = $InitialSize
    $currentPageFile.MaximumSize = $MaximumSize
    $currentPageFile.Put()
}
else
{
    $currentPageFile.Delete()
    Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{Name=$pageFilePath;
InitialSize = $initialSize; MaximumSize = $maximumSize}
}

#check Out-of-box drivers
Get-PnpDevice | Select-Object Name, @
{
    l='DriverVersion';
e={
    (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion').Data
  }
} -Unique | 

Where-Object 
{
    ($_.Name -like "*HBA*") -or 
    ($_.Name -like "*mellanox*") -or 
    ($_.Name -like "*Qlogic*") -or 
    ($_.Name -like "*X710*") -or 
    ($_.Name -like "*Broadcom*") -or 
    ($_.Name -like "*marvell*")
}

Get-PnpDevice -PresentOnly | Where-Object {
    ($_.Status -ne 'OK') -and 
    ($_.Problem -ne 'CM_PROB_NONE' -and $_.Problem -ne 'CM_PROB_DISABLED')
}

#set storport
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x000027

#set live migration mode
Set-VMHost -VirtualMachineMigrationPerformanceOption SMB
