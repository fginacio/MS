#$TSSv2 = C:\dell\TSSv2\TSSv2.ps1 -sdp
$dell="c:\Dell\"
Clear-Host
Write-Host "Downloading TSSv2..."
mkdir c:\Dell -ErrorAction Ignore
wget http://aka.ms/getTss -OutFile c:\Dell\TSSv2.zip
Expand-Archive -Path c:\Dell\TSSv2.zip -DestinationPath c:\Dell\TSSv2\ -ErrorAction Ignore
Clear-Host
$Ver="1.2"

    function DisplayMenu {
    Clear-Host
    Write-Host @"
    +===============================================+
    |  TSSv2 - Log Collection  v$Ver                 |     
    |                                               |
    |           By: Fabiano Inacio                  | 
    +===============================================+
    |                                               |
    |    1: Press '1' for Default collection.       |
    |    2: Press '2' for Cluster collection.       |
    |    3: Press '3' for HyperV collection.        |
    |    Q: Press 'Q' for Exit.                     |
    +===============================================+



"@

$MENU = Read-Host "OPTION"
Switch ($MENU)
    {
        1 {
    #OPTION1 - Default Collection
    C:\dell\TSSv2\TSSv2.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula
    #Write-Host "Logs available at C:\Dell\SDP_Setup\"
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at C:\Dell\SDP_Setup\", 0, "Collection Successfull", 0)
    #Start-Sleep -Seconds 2
    DisplayMenu
  }
        2 {
    #OPTION2 - Cluster Collection
    C:\dell\TSSv2\TSSv2.ps1 -sdp Cluster -LogFolderPath $dell -AcceptEula
    #Write-Host "Logs available at c:\Dell\SDP_*"
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at C:\Dell\SDP_Cluster\", 0, "Collection Successfull", 0)
    Start-Sleep -Seconds 2
    DisplayMenu
  }
        3 {
    #OPTION3 - HyperV Collection
    C:\dell\TSSv2\TSSv2.ps1 -sdp HyperV -LogFolderPath $dell -AcceptEula
    #Write-Host "Logs available at c:\Dell\SDP_*"
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at C:\Dell\SDP_HyperV\", 0, "Collection Successfull", 0)
    Start-Sleep -Seconds 2
    DisplayMenu
    }
        Q {
    #OPTIONQ - EXIT
    Write-Host "Bye"
    Break
    }
default {
    #DEFAULT OPTION
    Write-Host "Option not available"
    Start-Sleep -Seconds 2
    DisplayMenu
        }
                    }
}
DisplayMenu