<#
    .Synopsis
       TSSv2Collect.ps1
    .EXAMPLES
       Invoke-TSSv2Collect

Fixes and Improvements:
V 1.2
    User can choose the output file name.
    Check requirements before start scritp (powershell version 5.1 minimum)
V 1.3
    Improvements at compression/unpacking logs.
    New option for collect BSDO files.
    Fixed incorrect Unicode characters;
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
    |    4: Press '4' for BSOD collection.          |
    |    Q: Press 'Q' for Exit.                     |
    +===============================================+
"@

$MENU = Read-Host "OPTION"
Switch ($MENU)
    {
        1 {
    #OPTION1 - Default Collection
    Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
	Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
    If($CaseNumber.length -eq 0){$CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag"}
    #$destinationZip = "$dell$CaseNumber.zip"
        if ([string]::IsNullOrWhiteSpace($CaseNumber))
            {
                $CaseNumber = "Default Collection $DateTime"
            }
    invoke-expression -command "C:\dell\TSSv2\TSSv2.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula"
    cd $tss
    
    #Compressing logs
        Clear-Host
        $sourceFolder = "C:\Dell\SDP_Setup\"
        Write-Host "Compressing $sourceFolder folder to "c:\Dell\$CaseNumber.zip". This might take a while."
        $logtemp = gci -Path C:\Dell\SDP_Setup\*setup.zip
        Mi -Path C:\Dell\SDP_Setup\*setup.zip -Destination "c:\Dell\$CaseNumber.zip"
    
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at $dell$CaseNumber .zip", 0, "Collection Successfull", 0)
    Start-Sleep -Seconds 2
    Remove-Variable CaseNumber
    DisplayMenu
  }
        2 {
    #OPTION2 - Cluster Collection
    Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
	Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
    If($CaseNumber.length -eq 0){$CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag"}
    #$destinationZip = "$dell$CaseNumber.zip"
        if ([string]::IsNullOrWhiteSpace($CaseNumber))
            {
                $CaseNumber = "DefaultCluster Collection $DateTime"
            }
    invoke-expression -command "C:\dell\TSSv2\TSSv2.ps1 -sdp Cluster -LogFolderPath $dell -AcceptEula"
    cd $tss
    
    #Compressing logs
        Clear-Host
        $sourceFolder = "C:\Dell\SDP_Cluster\"
        Write-Host "Compressing $sourceFolder folder to "c:\Dell\$CaseNumber.zip". This might take a while."
        $logtemp = gci -Path c:\Dell\SDP_Cluster\*Cluster.zip
        Mi -Path c:\Dell\SDP_Cluster\*cluster.zip -Destination "c:\Dell\$CaseNumber.zip"
    
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at $dell$CaseNumber .zip", 0, "Collection Successfull", 0)
    Start-Sleep -Seconds 2
    Remove-Variable CaseNumber
    DisplayMenu
  }
        3 {
    #OPTION3 - HyperV Collection
    Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
	Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
    If($CaseNumber.length -eq 0){$CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag"}
    #$destinationZip = "$dell$CaseNumber.zip"
        if ([string]::IsNullOrWhiteSpace($CaseNumber))
            {
                $CaseNumber = "DefaultHyperV Collection $DateTime"
            }
    invoke-expression -command "C:\dell\TSSv2\TSSv2.ps1 -sdp HyperV -LogFolderPath $dell -AcceptEula"
    cd $tss
    
    #Compressing logs
    Clear-Host
        $sourceFolder = "C:\Dell\SDP_HyperV\"
        Write-Host "Compressing $sourceFolder folder to "c:\Dell\$CaseNumber.zip". This might take a while."
        $logtemp = gci -Path c:\Dell\SDP_HyperV\*HyperV.zip
        Mi -Path c:\Dell\SDP_HyperV\*HyperV.zip -Destination "c:\Dell\$CaseNumber.zip"
    
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at $dell$CaseNumber .zip", 0, "Collection Successfull", 0)
    Start-Sleep -Seconds 2
    Remove-Variable CaseNumber
    DisplayMenu
    }
        4 {
    #Hidden OPTION - BSOD Collection
    Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
	Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
    If($CaseNumber.length -eq 0){$CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag"}
    #$destinationZip = "$dell$CaseNumber.zip"
        if ([string]::IsNullOrWhiteSpace($CaseNumber))
            {
                $CaseNumber = "Default BSOD Collection $DateTime"
            }
    #Copying logs
        #Creating a temporary dumps folder
        $DumpFolder = "c:\dell\dumps"
        if(Test-Path "$DumpFolder")
            {
                Write-Host "Folder Exists"
                #Get-ChildItem -Path $DumpFolder | Where-Object {$_.CreationTime -gt (Get-Date).Date}   
                Get-ChildItem -Path $DumpFolder | Remove-Item -Recurse -Force 
            }
            else
            {
                Write-Host "Folder Doesn't Exists, creating..."
    
                #PowerShell Create directory if not exists
                New-Item $DumpFolder -ItemType Directory
            }
        #New-Item -path c:\dell\dumps -ItemType Directory
        #Copying Memory.dmp
        Copy-Item -path "C:\Windows\MEMORY.DMP" -Destination "$DumpFolder" -Recurse
        #Copying MiniDump folder
        Copy-Item -path "C:\Windows\Minidump" -Destination "$DumpFolder" -Recurse

    #Compressing logs

        Write-Host "Compressing $DumpFolder folder to "c:\Dell\$CaseNumber.zip". This might take a while."
        Start-Sleep -s 5 #give some time for logging to complete before starting zip
        
        #Compress-Archive -path "$DumpFolder" -DestinationPath "c:\Dell\$CaseNumber.zip" -Force

        [Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" )
        [System.IO.Compression.ZipFile]::CreateFromDirectory("$DumpFolder", "c:\Dell\$CaseNumber.zip", [System.IO.Compression.CompressionLevel]::Optimal, $true)
     

    #Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    Remove-Item "C:\Dell\dumps" -recurse -force -ErrorAction Ignore
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at c:\Dell\$CaseNumber.zip", 0, "Collection Successfull", 0)
    Start-Sleep -Seconds 2
    Remove-Variable CaseNumber
    DisplayMenu
    }
        m {
    #Hidden OPTION - Mini Collection
    Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
	Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
    If($CaseNumber.length -eq 0){$CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag"}
    #$destinationZip = "$dell$CaseNumber.zip"
        if ([string]::IsNullOrWhiteSpace($CaseNumber))
            {
                $CaseNumber = "DefaultMini Collection $DateTime"
            }
    invoke-expression -command "C:\dell\TSSv2\TSSv2.ps1 -sdp Mini -LogFolderPath $dell -AcceptEula"
    cd $tss
    
    #Compressing logs
        Clear-Host
        $sourceFolder = "C:\Dell\SDP_Mini\"
        Write-Host "Compressing $sourceFolder folder to "c:\Dell\$CaseNumber.zip". This might take a while."
        $logtemp = gci -Path c:\Dell\SDP_Mini\*mini.zip
        Mi -Path c:\Dell\SDP_Mini\*mini.zip -Destination "c:\Dell\$CaseNumber.zip"
        
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at $dell$CaseNumber.zip", 0, "Collection Successfull", 0)
    Start-Sleep -Seconds 2
    Remove-Variable CaseNumber 
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
#$destinationZip = "$dell$CaseNumber.zip" 
Clear-Host
Write-Host "Downloading and Unpacking TSSv2..."
#Deleting old log collections and transcript logs
    Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
    Remove-Item "C:\Dell\TSSv2Collect*.log" -recurse -force -ErrorAction Ignore
    Remove-Item "C:\Dell\Tssv2" -recurse -force -ErrorAction Ignore
    Remove-Item "C:\Dell\TSSv2.zip" -recurse -force -ErrorAction Ignore

#Checking requirements to run (Minimun Powershell 5.1)
$ps=($PSVersionTable).PSVersion.Major

#Creating c:\Dell folder and downloading TSSv2
    #mkdir c:\Dell -ErrorAction Ignore
    New-Item -path C:\Dell\TSSv2 -ItemType Directory
    Start-Sleep -Seconds 5
    wget http://aka.ms/getTss -OutFile "c:\Dell\TSSv2.zip" -ErrorAction SilentlyContinue
    

#Unpacking TSSv2 at C:\Dell
if ($ps -ge 5)
    {
        #(Expand-Archive -Path c:\Dell\TSSv2.zip -DestinationPath c:\Dell\TSSv2\ -ErrorAction Ignore)
        [Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" )
        $zip = [System.IO.Compression.ZipFile]::Open("c:\dell\TSSv2.zip", 'read')
        [System.IO.Compression.ZipFileExtensions]::ExtractToDirectory($zip, "C:\Dell\TSSv2")
        
    }
else
    {
        $ErrorMSG = 
            @"

            Your system dont meet the minimum requirements to run TSSv2 Collector.
            Your current Powershell version is $ps.

            Install Windows Management Framework 5.1 available at 
            https://www.microsoft.com/en-us/download/details.aspx?id=54616

            Or Use the TSSv2 Offline available at 
            https://github.com/fginacio/MS#how-to-use-tssv2collect_offline

"@
        Write-Host $ErrorMSG -ForegroundColor Red -BackgroundColor Yellow
        EndScript
    }

#    Expand-Archive -Path c:\Dell\TSSv2.zip -DestinationPath c:\Dell\TSSv2\ -ErrorAction Ignore
Clear-Host
$Ver="1.3"

#IE Fix
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

#Set Execution Policy
$ExecutionPolicy = Get-ExecutionPolicy
Set-ExecutionPolicy Unrestricted
DisplayMenu

#Invoke-TSSv2Collect
Remove-Item -Path "C:\Dell\TSSv2.zip" -recurse -force -ErrorAction Ignore
$logfolder=(gci -Path c:\dell\*.zip -name)
#$logfolder=(gci -Path c:\dell\*.zip | ? { $_.PSIsContainer } | sort CreationTime).name
#Write-Host "Logs available at c:\Dell\$logfolder"
Write-Host "Logs available at $dell$logfolder"
Set-ExecutionPolicy $ExecutionPolicy

#Removing extracted collector and zip file
    Remove-Item "C:\Dell\Tssv2" -recurse -force -ErrorAction Ignore
 
#}