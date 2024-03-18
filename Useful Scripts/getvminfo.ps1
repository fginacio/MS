$CSVLocation = "C:\DELL\GetVMInfo.CSV"

Get-Cluster | Get-ClusterResource | ? ResourceType -Like "Virtual Machine" | %{

$VM = Get-VM -ComputerName $_.OwnerNode -Name $_.OwnerGroup

$Basic = $VM | Select-Object VMName,ProcessorCount,@{label='Memory';expression={$_.MemoryAssigned/1gb -as [int]}},ComputerName

$NIC = ($VM | Select-Object -ExpandProperty Networkadapters).IPAddresses -join ';'

$Disks = $VM | Select-Object VMId | get-vhd -ComputerName $_.OwnerNode | Select-Object Path,@{label='DiskSize';expression={$_.Size/1gb -as [int]}}

$DiskPath = $Disks.Path -join ';'

$DiskSize = $Disks.DiskSize -join ';'

$Info = [PScustomObject]@{Guest = $Basic.VMName; Processors = $Basic.ProcessorCount; Memory = $Basic.Memory; Host = $Basic.ComputerName; IPs = $NIC; DiskLocation = $DiskPath; DiskSize = $DiskSize}

$Info | Export-CSV -Path $CSVLocation -NoTypeInformation -Append
}