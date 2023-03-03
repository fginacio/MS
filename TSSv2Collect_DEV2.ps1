<#
    .Synopsis
       TSSv2Collect_DEV2.ps1
    .DESCRIPTION
       This script Colect the TSSv2 logs from Microsoft Support Cases
    .EXAMPLES
       Invoke-TSSv2Collect_DEV2
#>

Function EndScript{ 
    break
}


Function Invoke-TSSv2Collect_DEV2{
#Clear-Host
$Ver=1.0000
$text = @"
v$Ver
	   +===============================================+
	   |  TSSv2 - Log Collection  v$Ver                |     
	   |                                               |
	   |           By: Fabiano Inacio                  |
       +===============================================+
"@
#IE Fix
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

#Set Execution Policy
Set-ExecutionPolicy Unrestricted

$dell="c:\Dell\"


#Clear-Host
Write-Host "Downloading TSSv2..."
#Deleting old log collections and transcript logs
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    Remove-Item "C:\Dell\TSSv2Collect*.log" -recurse -force -ErrorAction Ignore
    #Remove-Item "C:\Dell\Tssv2" -recurse -force -ErrorAction Ignore
    #Remove-Item "C:\Dell\TSSv2.zip" -recurse -force -ErrorAction Ignore
#Creating c:\Dell folder and downloading TSSv2
    mkdir c:\Dell -ErrorAction Ignore
    #wget http://aka.ms/getTss -OutFile c:\Dell\TSSv2.zip
#Unpacking TSSv2 at C:\Dell
    #Expand-Archive -Path c:\Dell\TSSv2.zip -DestinationPath c:\Dell\TSSv2\ -ErrorAction Ignore

Function ShowMenu{
$MainMenu = {
Write-Host "+===============================================+"
Write-Host "|                                               |"
Write-Host "|    1: Press '1' for Default collection.       |"
Write-Host "|    2: Press '2' for Cluster collection.       |"
Write-Host "|    3: Press '3' for HyperV collection.        |"
Write-Host "|    4: Press '4' for Exit.                     |"
Write-Host "+===============================================+" 
Write-Host 
Write-Host " Select an option and press Enter: "  -nonewline
}
Clear-Host

Do { 
Clear-Host
Invoke-Command $MainMenu
$Select = Read-Host
Switch ($Select)
    {
    '1' {
       Write-Host
       invoke-expression -command C:\dell\TSSv2\TSSv2.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula
       Clear-Host
       Write-Host
       Clear-Host
       }
    '2' {
       Write-Host
       C:\dell\TSSv2\TSSv2.ps1 -sdp Cluster -LogFolderPath $dell -AcceptEula
       Clear-Host
       Write-Host
       Clear-Host
       }
    '3' {
       Write-Host
       C:\dell\TSSv2\TSSv2.ps1 -sdp HyperV -LogFolderPath $dell -AcceptEula
       Clear-Host
       Write-Host
       Write-Host " Selected virtual machines have been started."
       Clear-Host
       }
    }
}
While ($Select -ne '4')

}#End of ShowMenu
ShowMenu
}


	
