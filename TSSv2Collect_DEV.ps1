<#
    .Synopsis
       TSSv2Collect.ps1
    .EXAMPLES
       Invoke-TSSv2Collect

Fixes and Improvements:
V 1.2
    User can choose the output file name.

#>
Function EndScript{ 
    break
}
#Function Invoke-TSSv2Collect{

    function DisplayMenu {
    $DateTime=Get-Date -Format yyyyMMdd_HHmmss
    Start-Transcript -NoClobber -Path "C:\Dell\TSSv2Collect_$DateTime.log"
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
    $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag"
    if ([string]::IsNullOrWhiteSpace($CaseNumber))
        {
            $CaseNumber = ‘Default Collection’
        }
    invoke-expression -command "C:\dell\TSSv2\TSSv2.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula -noZip"
    cd $tss
    Compress-Archive -path "C:\Dell\SDP_Setup\" -DestinationPath $dell\$CaseNumber
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at $dell\$CaseNumber", 0, "Collection Successfull", 0)
    DisplayMenu
  }
        2 {
    #OPTION2 - Cluster Collection
    $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag"
    if ([string]::IsNullOrWhiteSpace($CaseNumber))
        {
            $CaseNumber = ‘DefaultCluster Collection’
        }
    invoke-expression -command "C:\dell\TSSv2\TSSv2.ps1 -sdp Cluster -LogFolderPath $dell -AcceptEula -noZip"
    cd $tss
    Compress-Archive -path "C:\Dell\SDP_Cluster\" -DestinationPath $dell\$CaseNumber
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at $dell\$CaseNumber", 0, "Collection Successfull", 0)
    Start-Sleep -Seconds 2
    DisplayMenu
  }
        3 {
    #OPTION3 - HyperV Collection
    $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag"
    if ([string]::IsNullOrWhiteSpace($CaseNumber))
        {
            $CaseNumber = ‘DefaultHyperV Collection’
        }
    invoke-expression -command "C:\dell\TSSv2\TSSv2.ps1 -sdp HyperV -LogFolderPath $dell -AcceptEula -noZip"
    cd $tss
    Compress-Archive -path "C:\Dell\SDP_HyperV\" -DestinationPath $dell\$CaseNumber
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at $dell\$CaseNumber", 0, "Collection Successfull", 0)
    Start-Sleep -Seconds 2
    DisplayMenu
    }
        lled {
    #Hidden OPTION - Mini Collection
    $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag"
    if ([string]::IsNullOrWhiteSpace($CaseNumber))
        {
            $CaseNumber = ‘Mini Collection’
        }
    invoke-expression -command "C:\dell\TSSv2\TSSv2.ps1 -Mini HyperV -LogFolderPath $dell -AcceptEula -noZip"
    cd $tss
    Compress-Archive -path "C:\Dell\SDP_Mini\" -DestinationPath $dell\$CaseNumber
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at $dell\$CaseNumber.zip", 0, "Collection Successfull", 0)
    Start-Sleep -Seconds 2
    DisplayMenu
    } 
        Q {
    #OPTIONQ - EXIT
    Write-Host "Bye"
    Stop-Transcript
    EndScript
    }
default {
    #DEFAULT OPTION
    Write-Host "Option not available"
    Start-Sleep -Seconds 2
    DisplayMenu
        }
                    }
    }
#}

$dell="c:\Dell\"
$TSS="C:\dell\TSSv2\"
Clear-Host
Write-Host "Downloading TSSv2..."
#Deleting old log collections and transcript logs
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    Remove-Item "C:\Dell\TSSv2Collect*.log" -recurse -force -ErrorAction Ignore
    Remove-Item "C:\Dell\Tssv2" -recurse -force -ErrorAction Ignore
    Remove-Item "C:\Dell\TSSv2.zip" -recurse -force -ErrorAction Ignore
#Creating c:\Dell folder and downloading TSSv2
    mkdir c:\Dell -ErrorAction Ignore
    wget http://aka.ms/getTss -OutFile c:\Dell\TSSv2.zip
#Unpacking TSSv2 at C:\Dell
    Expand-Archive -Path c:\Dell\TSSv2.zip -DestinationPath c:\Dell\TSSv2\ -ErrorAction Ignore
Clear-Host
$Ver="1.2"

#IE Fix
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

#Set Execution Policy
Set-ExecutionPolicy Unrestricted

DisplayMenu

#Invoke-TSSv2Collect

$logfolder=(gci -Path c:\dell\$CaseNumber.zip | ? { $_.PSIsContainer } | sort CreationTime).name
#Write-Host "Logs available at c:\Dell\$logfolder"
Write-Host "Logs available at $dell\$CaseNumber.zip"

#Removing extracted collector and zip file
    Remove-Item "C:\Dell\Tssv2" -recurse -force -ErrorAction Ignore

#}