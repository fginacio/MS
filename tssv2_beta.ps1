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
function EndScript {
    break
}
#Function Invoke-TSSv2Collect{

function DisplayMenu {
    $DateTime = Get-Date -Format yyyyMMdd_HHmmss
    Start-Transcript -NoClobber -Path "C:\Dell\TSSv2Collect_$DateTime.log"
    Clear-Host
    $roles= get-WindowsFeature -Name * | where Installed
    Write-Host "Checking installed Features/Roles. " -ForegroundColor Green -BackgroundColor DarkGray
    Start-Sleep -Seconds 2
    Clear-Host

    Write-Host @"

    +===============================================+
    |  TSS - Log Collection  v$Ver                  |     
    |                                               |
    |           By: Fabiano Inacio                  |
    |                                               |
    | Press Q for Quit                              |
    +===============================================+

"@
      
    $MENU = Read-Host "Is this a Blue Screen (BSOD) Case (Y/N)"
    switch ($MENU)
    {
        Y {
        #OPTION - BSOD Collection
            Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
            Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
            if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag" }
            if ([string]::IsNullOrWhiteSpace($CaseNumber))
                {
                    $CaseNumber = "BSOD Collection $DateTime"
                }
            #Copying logs
            #Creating a temporary dumps folder
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
            #New-Item -path c:\dell\dumps -ItemType Directory
            #Copying Memory.dmp
            Copy-Item -Path "C:\Windows\MEMORY.DMP" -Destination "$DumpFolder" -Recurse
            #Copying MiniDump folder
            Copy-Item -Path "C:\Windows\Minidump" -Destination "$DumpFolder" -Recurse

            #Compressing logs

            Write-Host "Compressing $DumpFolder folder to " c:\Dell\$CaseNumber.zip". This might take a while."
            Start-Sleep -s 5 #give some time for logging to complete before starting zip

            #Compress-Archive -path "$DumpFolder" -DestinationPath "c:\Dell\$CaseNumber.zip" -Force
            $DestPath = "C:\Dell\$CaseNumber.zip"
            $maximumFileSize = 4GB
            $files = Get-ChildItem -Path $DumpFolder -File -Recurse

            $totalSize = ($files | Measure-Object -Property Length -Sum).Sum

            if ($totalSize -gt $maximumFileSize) 
                {
                    Write-Warning "Starting a fresh compression for large files using the System.IO.Compression.ZipFile class."

                    $smallFiles = $files | Where-Object { $_.Length -le $maximumFileSize }

                    # Create a temporary directory to store the large files
                    $tempDir = New-Item -ItemType Directory -Path (Join-Path -Path $env:TEMP -ChildPath "LargeFilesTemp")

                    $largeFiles = $files | Where-Object { $_.Length -gt $maximumFileSize }
    
                    # Copy the large files to the temporary directory
                                foreach ($file in $largeFiles) 
                                {
                                    $destinationPath = Join-Path -Path $tempDir.FullName -ChildPath $file.Name
                                    Copy-Item -Path $file.FullName -Destination $destinationPath -Force
                                }

                    # Create a new zip archive
                    [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir.FullName, $DestPath, 'Optimal', $true)

                    # Include the small files in the zip archive
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

                    # Remove the temporary directory
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
                    #OPTION - Default Collection + DUMP LOGS
                    Invoke-Expression -Command "C:\dell\TSSv2\TSS.ps1 -sdp mini -LogFolderPath $dell -AcceptEula"
                    #Invoke-Expression -Command "C:\dell\TSSv2\TSS.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula -noUpdate"
                    Set-Location $tss

                    #Compressing logs
                    Clear-Host
                    $sourceFolder = "C:\Dell\SDP_Setup\"
                    Write-Host "Compressing $sourceFolder folder to " c:\Dell\$CaseNumber_SDP.zip". This might take a while."
                    $logtemp = Get-ChildItem -Path C:\Dell\SDP_Setup\*setup.zip
                    Move-Item -Path C:\Dell\SDP_Setup\*setup.zip -Destination "c:\Dell\$CaseNumber_SDP.zip"

                    Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
                    $Shell = New-Object -ComObject "WScript.Shell"
                    $Button = $Shell.Popup("Logs available at $dell$CaseNumber_SDP .zip",0,"Collection Successfull",0)

                }

    # Display the completion message after the progress bar
    Write-Host "Compactação concluída."
         <#       
            [Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" )
            [System.IO.Compression.ZipFile]::CreateFromDirectory("$DumpFolder", "c:\Dell\$CaseNumber.zip", [System.IO.Compression.CompressionLevel]::Optimal, $true)
     
        #>

            #Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
            Remove-Item "C:\Dell\dumps" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("Logs available at c:\Dell\$CaseNumber.zip",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            DisplayMenu
        }
        N {
    IF      (get-WindowsFeature -Name Failover-clustering | where Installed) {
    #OPTION - Cluster Collection
            Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
            Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
            if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag" }
            if ([string]::IsNullOrWhiteSpace($CaseNumber))
                {
                    $CaseNumber = "Cluster Collection $DateTime"
                }
            
            Invoke-Expression -Command "C:\dell\TSSv2\TSS.ps1 -sdp mini -LogFolderPath $dell -AcceptEula"
            #Invoke-Expression -Command "C:\dell\TSSv2\TSS.ps1 -sdp Cluster -LogFolderPath $dell -AcceptEula -noUpdate"
            Set-Location $tss

            #Compressing logs
            Clear-Host
            $sourceFolder = "C:\Dell\SDP_Cluster\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path c:\Dell\SDP_Cluster\*Cluster.zip
            Move-Item -Path c:\Dell\SDP_Cluster\*cluster.zip -Destination "c:\Dell\$CaseNumber.zip"

            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("Logs available at $dell$CaseNumber .zip",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            DisplayMenu
            }
    ELSEIF  (get-WindowsFeature -Name Hyper-V | where Installed) {
    #OPTION - HyperV Collection
            Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
            Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
            if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag" }
            if ([string]::IsNullOrWhiteSpace($CaseNumber))
                {
                    $CaseNumber = "HyperV Collection $DateTime"
                }
            
            Invoke-Expression -Command "C:\dell\TSSv2\TSS.ps1 -sdp mini -LogFolderPath $dell -AcceptEula"
            #Invoke-Expression -Command "C:\dell\TSSv2\TSS.ps1 -sdp HyperV -LogFolderPath $dell -AcceptEula -noUpdate"
            Set-Location $tss

            #Compressing logs
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
            DisplayMenu
            }
    ELSEIF  (get-WindowsFeature -Name AD-Domain-Services | where Installed) {
    #OPTION - Active Directory Collection
            Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
            Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
            if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag" }
            if ([string]::IsNullOrWhiteSpace($CaseNumber))
            {
                $CaseNumber = "Domain Controller Collection $DateTime"
            }
            
            Invoke-Expression -Command "C:\dell\TSSv2\TSS.ps1 -sdp mini -LogFolderPath $dell -AcceptEula"
            #Invoke-Expression -Command "C:\dell\TSSv2\TSS.ps1 -sdp dom -LogFolderPath $dell -AcceptEula -noUpdate"
            Set-Location $tss

            #Compressing logs
            Clear-Host
            $sourceFolder = "C:\Dell\SDP_DOM\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path C:\Dell\SDP_DOM\*setup.zip
            Move-Item -Path C:\Dell\SDP_Setup\*setup.zip -Destination "c:\Dell\$CaseNumber.zip"

            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("Logs available at $dell$CaseNumber .zip",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            DisplayMenu
            }
    ELSE {
    #OPTION - Default Collection
  
            Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
            Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
            if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag" }
            if ([string]::IsNullOrWhiteSpace($CaseNumber))
                {
                    $CaseNumber = "Default Collection $DateTime"
                }
            
            Invoke-Expression -Command "C:\dell\TSSv2\TSS.ps1 -sdp mini -LogFolderPath $dell -AcceptEula"
            #Invoke-Expression -Command "C:\dell\TSSv2\TSS.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula -noUpdate"
            Set-Location $tss

            #Compressing logs
            Clear-Host
            $sourceFolder = "C:\Dell\SDP_Setup\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path C:\Dell\SDP_Setup\*setup.zip
            Move-Item -Path C:\Dell\SDP_Setup\*setup.zip -Destination "c:\Dell\$CaseNumber.zip"

            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("Logs available at $dell$CaseNumber .zip",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            DisplayMenu

}

            #Remove-Item "C:\Dell\SDP_*" -recurse -force -ErrorAction Ignore
            Remove-Item "C:\Dell\dumps" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("Logs available at c:\Dell\$CaseNumber.zip",0,"Collection Successfull",0)
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

$dell = "c:\Dell\"
$TSS = "C:\dell\TSSv2\"
Clear-Host
Write-Host "Downloading and Unpacking TSSv2..."
#Deleting old log collections and transcript logs
Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\TSSv2Collect*.log" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\Tssv2" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\TSSv2.zip" -Recurse -Force -ErrorAction Ignore

#Checking requirements to run (Minimun Powershell 5.1)
$ps = ($PSVersionTable).PSVersion.Major

#Creating c:\Dell folder and downloading TSSv2
#mkdir c:\Dell -ErrorAction Ignore
New-Item -Path C:\Dell\TSSv2 -ItemType Directory
Start-Sleep -Seconds 5

wget http://aka.ms/getTss -OutFile "c:\Dell\TSSv2.zip" -ErrorAction SilentlyContinue
#wget https://github.com/fginacio/MS/raw/main/TSSv2.zip -OutFile c:\Dell\TSSv2.zip


#Unpacking TSSv2 at C:\Dell
if ($ps -ge 5)
    {
        #(Expand-Archive -Path c:\Dell\TSSv2.zip -DestinationPath c:\Dell\TSSv2\ -ErrorAction Ignore)
        [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem")
        $zip = [System.IO.Compression.ZipFile]::Open("c:\dell\TSSv2.zip",'read')
        [System.IO.Compression.ZipFileExtensions]::ExtractToDirectory($zip,"C:\Dell\TSSv2")

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
$Ver = "1.4"

#IE Fix
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

#Set Execution Policy
$ExecutionPolicy = Get-ExecutionPolicy
Set-ExecutionPolicy Unrestricted
DisplayMenu

#Invoke-TSSv2Collect
Remove-Item -Path "C:\Dell\TSSv2.zip" -Recurse -Force -ErrorAction Ignore
$logfolder = (Get-ChildItem -Path c:\dell\*.zip -Name)
#$logfolder=(gci -Path c:\dell\*.zip | ? { $_.PSIsContainer } | sort CreationTime).name
#Write-Host "Logs available at c:\Dell\$logfolder"
Write-Host "Logs available at $dell$logfolder"
Set-ExecutionPolicy $ExecutionPolicy

#Removing extracted collector and zip file
Remove-Item "C:\Dell\Tssv2" -Recurse -Force -ErrorAction Ignore

#}