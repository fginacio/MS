 

#The Racadm Commands are supposed to run in CMD. you can run in powershell with the .\ but its not 100% reliable- depending on the command

##Begin PowerShell Script – Paste this in ISE PowerShell##
$a= Read-Host “what is the full domain name?”
$str1="*" 
$ans1= $str1+"."+$a
$ans1 
#Fix target machines

 
netsh advfirewall set allprofiles state off
Set-NetFirewallRule -Name WINRM-HTTP-In-TCP-PUBLIC -RemoteAddress Any 
# for NVME failed disks – reset-physicaldisk -serialnumber xxxxx
Set-Executionpolicy -executionpolicy remotesigned 
Set-Item WSMan:\localhost\Client\TrustedHosts *
Enable-WSManCredSSP -Role Client -Delegate $ans1
Enable-WSManCredSSP -Role Server
Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb 8192
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name AllowFreshCredentialsWhenNTLMOnly -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name 1 -Value * -PropertyType String
 
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name  'LocalAccountTokenFilterPolicy' -Value '1' -PropertyType 'DWORD' –Force
# Get out of the Registry
Pop-Location
if (Test-Path "c:\program files\dell\sysmgt\idractools\racadm\" -WarningAction SilentlyContinue -ErrorAction SilentlyContinue )
{
set-location "c:\program files\dell\sysmgt\idractools\racadm\" -PassThru
.\racadm set idrac.os-bmc.adminstate 1
.\racadm set iDRAC.WebServer.HostHeaderCheck Disabled
.\racadm set LifeCycleController.LCAttributes.LifecycleControllerState 1
.\racadm closessn –u AzSHCIAdmin
# n45d5 if your using drac8 – check the sessions tab to make sure racadm closessn –u n45d5
.\Racadm set idrac.OS-BMC.PTMode 1
.\racadm set idrac.lockdown.SystemLockdownMode 0
}
 
## End ###
#Run these commands on the WAC server. 
 
##Begin PowerShell Script – Paste this in ISE PowerShell##
#$a= Read-Host “what is the full domain name?”
#$str1="*" 
#$ans1= $str1+"."+$a
#$ans1 
#fix source machines
#Set-Executionpolicy -executionpolicy unrestricted 
#Set-Item WSMan:\localhost\Client\TrustedHosts *
#Enable-WSManCredSSP -Role Client -Delegate $ans1
#Enable-WSManCredSSP -Role Server
#Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb 8192
##End PowerShell Script – Paste this in ISE PowerShell##


