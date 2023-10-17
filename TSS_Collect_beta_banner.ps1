<#
    .Synopsis
       TssCollect.ps1
    .EXAMPLES
       Invoke-TssCollect
Fixes and Improvements:
V 1.2
    User can choose the output file name.
    Check requirements before start scritp (powershell version 5.1 minimum)
V 1.3
    Improvements at compression/unpacking logs.
    New option for collect BSDO files.
    Fixed incorrect Unicode characters;
V 1.4
    Now TSS run automatically and collect SDP based on installed Roles/Features
    BSOD collection includes SDP_Setup
    Rename main scritp to TSS.ps1
#>
Function EndScript {
    break
}

Function DisplayMenu {
    $DateTime = Get-Date -Format yyyyMMdd_HHmmss
    Start-Transcript -NoClobber -Path "C:\Dell\TssCollect_$DateTime.log"
    Clear-Host

    Write-Host @"

    +======================================================================+
    |                                                                      |
    |                                                                      |                
    |   _____  ___  ___   _                  ___       _  _           _    |
    |  |_   _|/ __|/ __| | |    ___  __ _   / __| ___ | || | ___  __ | |_  |
    |    | |  \__ \\__ \ | |__ / _ \/ _`  | | (__ / _ \| || |/ -_)/ _||  _| |
    |    |_|  |___/|___/ |____|\___/\__, |  \___|\___/|_||_|\___|\__| \__| |
    |                               |___/                                  |
    |                                                                      | 
    |                                           v$Ver                       |     
    |                                                                      |
    |                               By: Fabiano Inacio                     |
    |                                                                      |
    | Press Q for Quit                                                     |
    +======================================================================+

"@
      
    $MENU = Read-Host "Is this a Blue Screen (BSOD) Case (Y/N)"
    switch ($MENU)
    {
        Y {
        #OPTION - BSOD Collection#
            Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
            Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
            if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag for Dump log" }
            if ([string]::IsNullOrWhiteSpace($CaseNumber))
                {
                    $CaseNumber = "BSOD Collection Only $DateTime"
                }
            #Copying logs#
            #Creating a temporary dumps folder#
            $DumpFolder = "c:\dell\dumps"
            if (Test-Path "$DumpFolder")
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
            #Copying Memory.dmp#
            Copy-Item -Path "C:\Windows\MEMORY.DMP" -Destination "$DumpFolder" -Recurse
            
            #Copying MiniDump folder#
            Copy-Item -Path "C:\Windows\Minidump" -Destination "$DumpFolder" -Recurse

            #Compressing logs#
            Write-Host "Compressing $DumpFolder folder to " c:\Dell\$CaseNumber.zip". This might take a while."
            Start-Sleep -s 5 #give some time for logging to complete before starting zip

            $DestPath = "C:\Dell\$CaseNumber.zip"
            $maximumFileSize = 4GB
            $files = Get-ChildItem -Path $DumpFolder -File -Recurse

            $totalSize = ($files | Measure-Object -Property Length -Sum).Sum

            if ($totalSize -gt $maximumFileSize) 
                {
                    Write-Warning "Starting a fresh compression for large files using the System.IO.Compression.ZipFile class."

                    $smallFiles = $files | Where-Object { $_.Length -le $maximumFileSize }

                    #Create a temporary directory to store the large files#
                    $tempDir = New-Item -ItemType Directory -Path (Join-Path -Path $env:TEMP -ChildPath "LargeFilesTemp")
                    $largeFiles = $files | Where-Object { $_.Length -gt $maximumFileSize }
    
                    #Copy the large files to the temporary directory#
                                foreach ($file in $largeFiles) 
                                {
                                    $destinationPath = Join-Path -Path $tempDir.FullName -ChildPath $file.Name
                                    Copy-Item -Path $file.FullName -Destination $destinationPath -Force
                                }

                    #Create a new zip archive#
                    [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir.FullName, $DestPath, 'Optimal', $true)

                    #Include the small files in the zip archive#
                    $zipArchive = [System.IO.Compression.ZipFile]::Open($DestPath, 'Update')
                    $progress = 0
                    $totalProgress = 0
                    foreach ($file in $smallFiles) 
                        {
                            $entryName = $file.FullName.Substring($DumpFolder.Length + 1)
                            $entry = $zipArchive.CreateEntry($entryName, 'Optimal')
                            $stream = $entry.Open()
                            $fileStream = [System.IO.File]::OpenRead($file.FullName)
                            $bufferSize = 8KB
                            $buffer = New-Object byte[] $bufferSize
                            $count = $fileStream.Read($buffer, 0, $bufferSize)

                        while ($count -gt 0) 
                            {
                                $stream.Write($buffer, 0, $count)
                                $count = $fileStream.Read($buffer, 0, $bufferSize)

                                $progress += $count
                                $currentProgress = [math]::Min(($progress / $file.Length * 100), 100)
                                $totalProgress = ($totalProgress + $currentProgress) / 2
                                Write-Progress -Activity "Compactando Arquivos" -Status "Progresso" -PercentComplete $totalProgress
                            }

                            $stream.Close()
                            $fileStream.Close()
                        }
                    $zipArchive.Dispose()

                    #Remove the temporary directory#
                    Remove-Item -Path $tempDir.FullName -Force -Recurse
                } 
            else 
                {
                    # Compress all files using Compress-Archive
                    $files | Compress-Archive -DestinationPath $DestPath -Update -CompressionLevel Optimal

                    # Calculate the progress per file
                    $progressPerFile = 100 / $files.Count
                    $totalProgress = 0

                    foreach ($file in $files) 
                        {
                            $totalProgress += $progressPerFile
                            Write-Progress -Activity "Compactando Arquivos" -Status "Progresso" -PercentComplete $totalProgress
                        }

                }

    #Remove-Variable CaseNumber
    Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
    Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
    if ($CaseNumber2.length -eq 0) { $CaseNumber2 = Read-Host -Prompt "Please enter relevant case number or Service tag for TSS log" }
    if ([string]::IsNullOrWhiteSpace($CaseNumber2))
        {
            $CaseNumber2 = "SDP Collection Only $DateTime"
        }
           

    #OPTION - Default Collection + DUMP LOGS
    Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula"
    #Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula -noUpdate"
    Set-Location $tss

    #Compressing logs
    Clear-Host
    $sourceFolder = "C:\Dell\SDP_Setup\"
    Write-Host "Compressing $sourceFolder folder to " c:\Dell\$CaseNumber2.zip". This might take a while."
    $logtemp = Get-ChildItem -Path C:\Dell\SDP_Setup\*Setup.zip
    Move-Item -Path C:\Dell\SDP_Setup\*Setup.zip -Destination "c:\Dell\$CaseNumber2.zip"

    #Display the completion message after the progress bar#
    Write-Host "Compactação concluída."
    Remove-Item "C:\Dell\dumps" -Recurse -Force -ErrorAction Ignore
    Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
    $Shell = New-Object -ComObject "WScript.Shell"
    $Button = $Shell.Popup("Logs available at $dell$CaseNumber and $dell$CaseNumber2 .zip",0,"Collection Successfull",0)
    Start-Sleep -Seconds 2
    Remove-Variable CaseNumber
    #DisplayMenu
    Clear-Host
    Write-Host "Bye"
    Stop-Transcript
    EndScript
        }
        N {
    IF      (get-WindowsFeature -Name Failover-clustering | where Installed) {
    #OPTION - Cluster Collection#
            Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
            Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
            if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag" }
            if ([string]::IsNullOrWhiteSpace($CaseNumber))
                {
                    $CaseNumber = "Cluster Collection $DateTime"
                }
            
            Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp Cluster -LogFolderPath $dell -AcceptEula"
            #Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp Cluster -LogFolderPath $dell -AcceptEula -noUpdate"
            Set-Location $tss

            #Compressing logs#
            Clear-Host
            $sourceFolder = "C:\Dell\SDP_Cluster\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path c:\Dell\SDP_Cluster\*Cluster.zip
            Move-Item -Path c:\Dell\SDP_Cluster\*Cluster.zip -Destination "c:\Dell\$CaseNumber.zip"

            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("Logs available at $dell$CaseNumber .zip",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            Clear-Host
            Write-Host "Bye"
            Stop-Transcript
            EndScript
            }
    ELSEIF  (get-WindowsFeature -Name Hyper-V | where Installed) {
    #OPTION - HyperV Collection#
            Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
            Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
            if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag" }
            if ([string]::IsNullOrWhiteSpace($CaseNumber))
                {
                    $CaseNumber = "HyperV Collection $DateTime"
                }
            
            Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp HyperV -LogFolderPath $dell -AcceptEula"
            #Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp HyperV -LogFolderPath $dell -AcceptEula -noUpdate"
            Set-Location $tss

            #Compressing logs#
            Clear-Host
            $sourceFolder = "C:\Dell\SDP_HyperV\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path c:\Dell\SDP_HyperV\*HyperV.zip
            Move-Item -Path c:\Dell\SDP_HyperV\*HyperV.zip -Destination "c:\Dell\$CaseNumber.zip"

            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("Logs available at $dell$CaseNumber .zip",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            Clear-Host
            Write-Host "Bye"
            Stop-Transcript
            EndScript
            }
    ELSEIF  (get-WindowsFeature -Name AD-Domain-Services | where Installed) {
    #OPTION - Active Directory Collection#
            Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
            Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
            if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag" }
            if ([string]::IsNullOrWhiteSpace($CaseNumber))
            {
                $CaseNumber = "Domain Controller Collection $DateTime"
            }
            
            Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp DOM -LogFolderPath $dell -AcceptEula"
            #Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp dom -LogFolderPath $dell -AcceptEula -noUpdate"
            Set-Location $tss

            #Compressing logs#
            Clear-Host
            $sourceFolder = "C:\Dell\SDP_DOM\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path C:\Dell\SDP_DOM\*DOM.zip
            Move-Item -Path C:\Dell\SDP_DOM\*DOM.zip -Destination "c:\Dell\$CaseNumber.zip"

            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("Logs available at $dell$CaseNumber .zip",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            Clear-Host
            Write-Host "Bye"
            Stop-Transcript
            EndScript
            }
    ELSE {
    #OPTION - Default Collection#
  
            Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
            Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
            if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag" }
            if ([string]::IsNullOrWhiteSpace($CaseNumber))
                {
                    $CaseNumber = "Default Collection $DateTime"
                }
            
            Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula"
            #Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula -noUpdate"
            Set-Location $tss

            #Compressing logs#
            Clear-Host
            $sourceFolder = "C:\Dell\SDP_Setup\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path C:\Dell\SDP_Setup\*Setup.zip
            Move-Item -Path C:\Dell\SDP_Setup\*Setup.zip -Destination "c:\Dell\$CaseNumber.zip"

            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("Logs available at $dell$CaseNumber .zip",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            Clear-Host
            Write-Host "Bye"
            Stop-Transcript
            EndScript
}

            #Remove-Item "C:\Dell\dumps" -Recurse -Force -ErrorAction Ignore
            #$Shell = New-Object -ComObject "WScript.Shell"
            #$Button = $Shell.Popup("Logs available at c:\Dell\$CaseNumber.zip",0,"Collection Successfull",0)
            #Start-Sleep -Seconds 2
            #Remove-Variable CaseNumber
            #DisplayMenu

            }
        Q {
            #OPTIONQ - EXIT#
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

$dell = "c:\Dell\"
$TSS = "C:\dell\Tss\"
Clear-Host
Write-Host "Downloading and Unpacking Tss..."

#Deleting old log collections and transcript logs#
Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\TssCollect*.log" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\Tss" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\Tss.zip" -Recurse -Force -ErrorAction Ignore

#Checking requirements to run (Minimun Powershell 5.1)#
$ps = ($PSVersionTable).PSVersion.Major

#Creating c:\Dell folder and downloading Tss#
New-Item -Path C:\Dell\Tss -ItemType Directory
Start-Sleep -Seconds 5

#Downloading TSS#
wget http://aka.ms/getTss -OutFile "c:\Dell\Tss.zip" -ErrorAction SilentlyContinue
#wget https://github.com/fginacio/MS/raw/main/Tss.zip -OutFile c:\Dell\Tss.zip


#Unpacking Tss at C:\Dell#
if ($ps -ge 5)
    {
        [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem")
        $zip = [System.IO.Compression.ZipFile]::Open("c:\dell\Tss.zip",'read')
        [System.IO.Compression.ZipFileExtensions]::ExtractToDirectory($zip,"C:\Dell\Tss")

    }
else
{
    $ErrorMSG =
    @"
            Your system dont meet the minimum requirements to run Tss Collector.
            Your current Powershell version is $ps.
            Install Windows Management Framework 5.1 available at 
            https://www.microsoft.com/en-us/download/details.aspx?id=54616
            Or Use the Tss Offline available at 
            https://github.com/fginacio/MS#how-to-use-Tsscollect_offline
"@
    Write-Host $ErrorMSG -ForegroundColor Red -BackgroundColor Yellow
    EndScript
}

Clear-Host
$Ver = "1.4"

#IE Fix#
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

#Set Execution Policy#
$ExecutionPolicy = Get-ExecutionPolicy
Set-ExecutionPolicy Unrestricted

#Detect Roles/Features#
$roles= get-WindowsFeature -Name * | where Installed
Write-Host "Checking installed Features/Roles. " -ForegroundColor Green -BackgroundColor DarkGray
Start-Sleep -Seconds 2
Clear-Host

#MainMenu#
DisplayMenu

#Invoke-TssCollect#
Remove-Item -Path "C:\Dell\Tss.zip" -Recurse -Force -ErrorAction Ignore
$logfolder = (Get-ChildItem -Path c:\dell\*.zip -Name)
Write-Host "Logs available at $dell$logfolder"
Set-ExecutionPolicy $ExecutionPolicy

#Removing extracted collector and zip file#
Remove-Item "C:\Dell\Tss" -Recurse -Force -ErrorAction Ignore