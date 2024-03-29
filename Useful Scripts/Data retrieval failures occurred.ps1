#Server Manager problem: Online - Data retrieval failures occurred#

#To set Enable to 0

icm -ComputerName (Get-ClusterNode).name -ScriptBlock {
Set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-IoTrace/Diagnostic" -Name "Enabled" -Value 0; 
Set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-HIDI2C/Analytic" -Name "Enabled" -Value 0; 
Set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Debug" -Name "Enabled" -Value 0; 
Set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Diagnostic" -Name "Enabled" -Value 0; 
Set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Operational" -Name "Enabled" -Value 0;
Set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NIS-Driver-WFP/Diagnostic" -Name "Enabled" -Value 0}


#To remove the Enable key

icm -ComputerName (Get-ClusterNode).name -ScriptBlock
{Remove-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-IoTrace/Diagnostic" -Name "Enabled" ;
Remove-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-HIDI2C/Analytic" -Name "Enabled" ;
Remove-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Debug" -Name "Enabled" ;
Remove-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Diagnostic" -Name "Enabled" ;
Remove-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Operational" -Name "Enabled" ;
Remove-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\NIS-Driver-WFP/Diagnostic" -Name "Enabled"}


#To remove ONLY the Enable key on Kernel-IoTrace/Diagnostic

icm -ComputerName (Get-ClusterNode).name -ScriptBlock
{Remove-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-IoTrace/Diagnostic" -Name "Enabled"}

#Restart all nodes to apply the changes