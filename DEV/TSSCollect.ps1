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
    Checks for BSOD events with less than 30 days and collect Dump log (Memory.dmp and minidump folder) 
    Renamed main script to TSS.ps1
    Output logs available at c:\Dell\Logs
#>
Function Invoke-TssCollect {

Function EndScript {
Break
}
Function Check-FreeSpace {
    # Get the free space of the C:\ drive in gigabytes
    $freeSpaceGB = [math]::Round((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB, 2)
    # Define the threshold
    $thresholdGB = 6
    # Check if free space is less than the threshold
    if ($freeSpaceGB -lt $thresholdGB) {
        $Shell = New-Object -ComObject "WScript.Shell"
        $Button = $Shell.Popup("There is not enough space in C: to run de data collection tool. Please release space in C: drive and try again. Available space: $($freeSpaceGB.ToString("0.00")) GB", 0, "Error", 0x0)
        Write-Host "Error: There is not enough space in C: to run de data collection tool. Please release space in C: drive and try again. Available space: $($freeSpaceGB.ToString("0.00")) GB" -ForegroundColor Red -BackgroundColor Yellow
        Remove-Item "C:\Dell\Dumps" -Recurse -Force -ErrorAction Ignore
        Remove-Item "C:\Dell\Logs" -Recurse -Force -ErrorAction Ignore
        Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
        Remove-Item "C:\Dell\TssCollect*.log" -Recurse -Force -ErrorAction Ignore
        Remove-Item "C:\Dell\Tss" -Recurse -Force -ErrorAction Ignore
        Remove-Item "C:\Dell\Tss.zip" -Recurse -Force -ErrorAction Ignore
        EndScript
    } 
    #else {Write-Host "Free space on C:\ drive is sufficient: $($freeSpaceGB.ToString("0.00")) GB"}
}
Function DisplayMenu {

    $DateTime = Get-Date -Format yyyyMMdd_HHmmss
    Start-Transcript -NoClobber -Path "C:\Dell\TssCollect_$DateTime.log"
    clear-host
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
    |                                                                      |
    +======================================================================+
"@
    Write-Host "Below symbols are not allowed." -ForegroundColor Yellow -BackgroundColor DarkGray
    Write-Host "=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\" -ForegroundColor Yellow -BackgroundColor DarkGray
    if ($CaseNumber.length -eq 0) { $CaseNumber = Read-Host -Prompt "Please enter relevant case number or Service tag" }
        if ([string]::IsNullOrWhiteSpace($CaseNumber))
            {
                $CaseNumber = "TSS Collection $DateTime"
            }
              
    $MENU = Read-Host "Start the collection (Y/N)"
    switch ($MENU)
    {
 
    Y {
    IF      (get-WindowsFeature -Name Failover-clustering | where Installed) {
    #OPTION - Cluster Collection#
            
            Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp Cluster -LogFolderPath $dell -AcceptEula"
            Set-Location $tss
            #Compressing logs#
            clear-host
            $sourceFolder = "C:\Dell\SDP_Cluster\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\Logs\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path c:\Dell\SDP_Cluster\*Cluster.zip
            Move-Item -Path c:\Dell\SDP_Cluster\*Cluster.zip -Destination "c:\Dell\Logs\$CaseNumber.zip"
                            
            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("$Button at c:\Dell\Logs",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            clear-host
            Write-Host "Bye"
            Stop-Transcript
            EndScript
            }
    ELSEIF  (get-WindowsFeature -Name Hyper-V | where Installed) {
    #OPTION - HyperV Collection#
            
            Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp HyperV -LogFolderPath $dell -AcceptEula"
            Set-Location $tss
            #Compressing logs#
            clear-host
            $sourceFolder = "C:\Dell\SDP_HyperV\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\Logs\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path c:\Dell\SDP_HyperV\*HyperV.zip
            Move-Item -Path c:\Dell\SDP_HyperV\*HyperV.zip -Destination "c:\Dell\Logs\$CaseNumber.zip"
               
            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("$Button at c:\Dell\Logs",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            clear-host
            Write-Host "Bye"
            Stop-Transcript
            EndScript
            }
    ELSEIF  (get-WindowsFeature -Name AD-Domain-Services | where Installed) {
    #OPTION - Active Directory Collection#
            Check-FreeSpace
            Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp DOM -LogFolderPath $dell -AcceptEula"
            #Check-FreeSpace
            Set-Location $tss
            Compressing logs#
            clear-host
            $sourceFolder = "C:\Dell\SDP_DOM\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\Logs\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path C:\Dell\SDP_DOM\*DOM.zip
            Move-Item -Path C:\Dell\SDP_DOM\*DOM.zip -Destination "c:\Dell\Logs\$CaseNumber.zip"
            
            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("$Button at c:\Dell\Logs",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            clear-host
            Write-Host "Bye"
            Stop-Transcript
            EndScript
            }
    ELSE {
    #OPTION - Default Collection#
            
            Invoke-Expression -Command "C:\dell\Tss\TSS.ps1 -sdp Setup -LogFolderPath $dell -AcceptEula"
            Set-Location $tss
            #Compressing logs#
            clear-host
            $sourceFolder = "C:\Dell\SDP_Setup\"
            Write-Host "Compressing $sourceFolder folder to " c:\Dell\Logs\$CaseNumber.zip". This might take a while."
            $logtemp = Get-ChildItem -Path C:\Dell\SDP_Setup\*Setup.zip
            Move-Item -Path C:\Dell\SDP_Setup\*Setup.zip -Destination "c:\Dell\Logs\$CaseNumber.zip"
            
            Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
            $Shell = New-Object -ComObject "WScript.Shell"
            $Button = $Shell.Popup("Logs available at c:\Dell\Logs",0,"Collection Successfull",0)
            Start-Sleep -Seconds 2
            Remove-Variable CaseNumber
            clear-host
            Write-Host "Bye"
            Stop-Transcript
            EndScript
}
            }
        N {
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
Set-PSDebug -Trace 0
$dell = "c:\Dell\"
$TSS = "C:\dell\Tss\"
clear-host
Write-Host "Downloading and Unpacking Tss..."
#Deleting old log collections and transcript logs#
Remove-Item "C:\Dell\Dumps" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\Logs" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\SDP_*" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\TssCollect*.log" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\Tss" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\Tss.zip" -Recurse -Force -ErrorAction Ignore
#Checking requirements to run (Minimun Powershell 5.1)#
$ps = ($PSVersionTable).PSVersion.Major
#Creating c:\Dell folder and downloading Tss#
New-Item -Path C:\Dell\Tss -ItemType Directory
New-Item -Path C:\Dell\Logs -ItemType Directory
Start-Sleep -Seconds 5
Check-FreeSpace
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
clear-host
$Ver = "DEV"
#IE Fix#
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
#Set Execution Policy#
#$ExecutionPolicy = Get-ExecutionPolicy
Write-Host "Set ExecutionPolicy Bypass..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
Write-Host "    ExecutionPolicy:"$env:PSExecutionPolicyPreference
#Detect Roles/Features#
$roles= get-WindowsFeature -Name * | where Installed
Write-Host "Checking installed Features/Roles. " -ForegroundColor Green -BackgroundColor DarkGray
Start-Sleep -Seconds 2
clear-host
#OPTION - BSOD Collection#
#Copying logs#
#Creating a temporary dumps folder#
         <#   $DumpFolder = "c:\dell\dumps"
            if (Test-Path "$DumpFolder")
                {
                    #Write-Host "Folder Exists"
                    Get-ChildItem -Path $DumpFolder | Remove-Item -Recurse -Force
                }
            else
                {
                    #Write-Host "Folder Doesn't Exists, creating..."
                    #PowerShell Create directory if not exists
                    New-Item $DumpFolder -ItemType Directory
                }#>
        # Checking dump file timestamp is more than 30 Days
        $memoryDmpPath = "c:\windows\memory.dmp"
        $minidumpPath = "c:\windows\minidump"
        #$DumpFolder = "c:\dell\dumps"
        $DumpFolder = "C:\Dell\logs\dump.zip"
        # Check if at least one of the paths exist before accessing their LastWriteTime
        if ((Test-Path $memoryDmpPath) -or (Test-Path $minidumpPath)) {
           
            # Check if the file exists before accessing its LastWriteTime
            if (Test-Path $memoryDmpPath) {
                $memoryDmpTimestamp = (Get-Item $memoryDmpPath).LastWriteTime
                $currentTimestamp = Get-Date
                $daysDifference = ($currentTimestamp - $memoryDmpTimestamp).Days
                # Copy Memory.dmp if the conditions are met
                if ($daysDifference -lt 300) {
                    #Copy-Item -Path $memoryDmpPath -Destination $DumpFolder -Recurse -ErrorAction SilentlyContinue
                    #Compress-Archive -Path $memoryDmpPath -DestinationPath $DumpFolder -Force -CompressionLevel Optimal
                    [System.IO.Compression.ZipFile]::CreateFromDirectory($memoryDmpPath.FullName, $DestPath, 'Optimal', $true)

                }
            }
            # Check if the file exists before accessing its LastWriteTime
            if (Test-Path $minidumpPath) {
                $minidumpPathTimestamp = (Get-Item $minidumpPath).LastWriteTime
                $currentTimestamp = Get-Date
                $daysDifference2 = ($currentTimestamp - $minidumpPathTimestamp).Days
                # Copy files from minidump folder if the conditions are met
                if ($daysDifference2 -lt 30) {
                    #Copy-Item -Path $minidumpPath -Destination $DumpFolder -Recurse -ErrorAction SilentlyContinue
                    Compress-Archive -Path $memoryDmpPath -DestinationPath $DumpFolder -Update -CompressionLevel Optimal -Force
                }
            }
        }
<# # Compressing logs #
$DumpFolder = "c:\dell\dumps"
$DestPath = "C:\Dell\logs\dump.zip"
$maximumFileSize = 4GB
# Check if there are files in the folder before proceeding with compression
$files = Get-ChildItem -Path $DumpFolder -File -Recurse -Force
if ($files.Count -gt 0) {
    # Give some time for logging to complete before starting zip
    Start-Sleep -Seconds 5
    $totalSize = ($files | Measure-Object -Property Length -Sum).Sum
    if ($totalSize -gt $maximumFileSize) {
        Write-Host "Starting a fresh compression for large files using System.IO.Compression.ZipFile class."
        # Create a temporary directory to store the large files
        $tempDir = New-Item -ItemType Directory -Path (Join-Path -Path $env:TEMP -ChildPath "LargeFilesTemp")
        # Separate large and small files
        $largeFiles = $files | Where-Object { $_.Length -gt $maximumFileSize }
        $smallFiles = $files | Where-Object { $_.Length -le $maximumFileSize }
        # Copy the large files to the temporary directory
        foreach ($file in $largeFiles) {
            $destinationPath = Join-Path -Path $tempDir.FullName -ChildPath $file.Name
            Copy-Item -Path $file.FullName -Destination $destinationPath -Force
        }
        # Create a new zip archive
        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir.FullName, $DestPath, 'Optimal', $true)
        # Include the small files in the zip archive
        $smallFiles | Compress-Archive -DestinationPath $DestPath -Update -CompressionLevel Optimal
        # Remove the temporary directory
        Remove-Item -Path $tempDir.FullName -Force -Recurse
    } else {
        # Compress all files using Compress-Archive
        $files | Compress-Archive -DestinationPath $DestPath -Update -CompressionLevel Optimal
        # Calculate the progress per file
        $progressPerFile = 100 / $files.Count
        $totalProgress = 0
        foreach ($file in $files) {
            $totalProgress += $progressPerFile
            Write-Progress -Activity "Compressing Files" -Status "Progress" -PercentComplete $totalProgress
        }
    }
}#> 
#MainMenu#
DisplayMenu
#Invoke-TssCollect#
clear-host
Remove-Item -Path "C:\Dell\Tss.zip" -Recurse -Force -ErrorAction Ignore
$logfolder = (Get-ChildItem -Path c:\dell\Logs\*.zip -Name)
Write-Host "Logs available at c:\Dell\Logs"
#Removing extracted collector and zip file#
Remove-Item "C:\Dell\Tss" -Recurse -Force -ErrorAction Ignore
Remove-Item "C:\Dell\Dumps" -Recurse -Force -ErrorAction Ignore
}