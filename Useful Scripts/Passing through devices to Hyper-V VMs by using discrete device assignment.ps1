﻿# Disable the GPU card in Hyper-V host
# Get the GPU Location path from the GPU properties
# Notice after dismount from Hyper-V the GPU will disappear. Notice after dismount from Hyper-V the GPU will disappear

# Add the GPU into the VM
$VM= 'YOUR VM'
$Location= 'PCIROOT(B4)#PCI(0100)#PCI(0000)#PCI(0200)#PCI(0000)#PCI(0800)#PCI(0000)'
 
Dismount-VMHostAssignableDevice -LocationPath $Location -force

# Set automatic stop action to TurnOff
Set-VM -VM $vm AutomaticStopAction TurnOff
 
Add-VMAssignableDevice -LocationPath $Location -VMName $VM

# Enable Write-Combining on the CPU
Set-VM -GuestControlledCacheTypes $true -VMName $vm
 
# Configure 32 bit MMIO space
Set-VM -LowMemoryMappedIoSpace 3Gb -VMName $vm

# Configure Greater than 32 bit MMIO space
Set-VM -HighMemoryMappedIoSpace 33280Mb -VMName $vm

# Check the GPU was assigned to VM 
Get-VMAssignableDevice -VMName $VM


#Remove a device and return it to the host
#If you want to return the device back to its original state, you must stop the VM and issue this command:

# Remove the device from the VM
Remove-VMAssignableDevice -LocationPath $locationPath -VMName VMName

# Mount the device back in the host
Mount-VMHostAssignableDevice -LocationPath $locationPath
#You can then re-enable the device in Device Manager, and the host operating system is able to interact with the device again.


# Set the MMIO Space the default MMIO space is insufficient for GPU.
# Please refer to Nvidia documentation for the MMIO space requirement
# https://docs.nvidia.com/grid/latest/grid-vgpu-release-notes-vmware-vsphere/index.html#pascal-gpus-in-passthrough-mode
# Start the VM and the VM will be able to pickup the pass-through card

# For Linux Guests:
<# Command summary
In this example the GPU PCI Location path is PCIROOT(17)#PCI(0000)#PCI(0000)#PCI(0000)#PCI(0000) and the VM Name is Centos
 
	1. Dismount-VMHostAssignableDevice -LocationPath PCIROOT(17)#PCI(0000)#PCI(0000)#PCI(0000)#PCI(0000) -force
	2. Add-VMAssignableDevice -LocationPath PCIROOT(17)#PCI(0000)#PCI(0000)#PCI(0000)#PCI(0000) -VMName vm-Centos
	3. Get-VMAssignableDevice -VMName Centos
	4. Set-VM -HighMemoryMappedIoSpace 64GB -VMName Centos
 
Reference Document:
Commands for pass-though
https://docs.nvidia.com/grid/12.0/grid-vgpu-user-guide/index.html#using-gpu-pass-through-windows-server-hyper-v
MMIO Space requirement
https://docs.nvidia.com/grid/latest/grid-vgpu-release-notes-vmware-vsphere/index.html#pascal-gpus-in-passthrough-mode
Deploy graphics devices by using Discrete Device Assignment
https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/deploy/deploying-graphics-devices-using-dda 
#>