<#
    .Synopsis
       TSSv2Collect.ps1
    .DESCRIPTION
       This script Colect the TSSv2 logs from Microsoft Support Cases
    .EXAMPLES
       Invoke-TSSv2Collect
#>

Function EndScript{ 
    break
}


Function Invoke-TSSv2Collect{
#Clear-Host
$Ver=1.0
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
    wget http://aka.ms/getTss -OutFile c:\Dell\TSSv2.zip
#Unpacking TSSv2 at C:\Dell
    Expand-Archive -Path c:\Dell\TSSv2.zip -DestinationPath c:\Dell\TSSv2\ -ErrorAction Ignore


Function ShowMenu{
    do
     {

         $selection=""
         #Start-Transcript -NoClobber -Path "C:\Dell\TSSv2Collect_$DateTime.log"
	   Clear-Host
	   Write-Host $text
	   Write-Host "+===============================================+"
	   Write-Host "|                                               |"
	   Write-Host "|    1: Press '1' for Default collection.       |"
	   Write-Host "|    2: Press '2' for Cluster collection.       |"
	   Write-Host "|    3: Press '3' for HyperV collection.        |"
	   Write-Host "|    Q: Press 'Q' for Exit.                     |"
	   Write-Host "+===============================================+"
	   $selection = Read-Host "Please make a selection"
    }
    until ($selection -match '[1-3,qQ]')
    $Global:Confirm=$False
    Pause
    ShowMenu
      
	IF ($selection -match 1) {
		C:\dell\TSSv2\TSSv2.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula
	}

	IF ($selection -match 2) {
		C:\dell\TSSv2\TSSv2.ps1 -sdp Cluster -LogFolderPath $dell -AcceptEula
	}

	IF ($selection -match 3) {
		C:\dell\TSSv2\TSSv2.ps1 -sdp HyperV -LogFolderPath $dell -AcceptEula
	}

	IF($selection -imatch 'q'){
		Write-Host "Bye... "
	    EndScript
	}
}#End of ShowMenu
ShowMenu
}

	
