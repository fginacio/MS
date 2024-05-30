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
V 1.5
    Memory.dmp now is directly compressed to c:\dell\logs without a temp folder
    Check-Freespae function will monitoring the free space available on system during execution

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
    Check-FreeSpace
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
$Ver = "1.5"
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
<##Creating a temporary dumps folder#
        # Checking dump file timestamp is more than 30 Days
        $memoryDmpPath = "c:\windows\memory.dmp"
        $minidumpPath = "c:\windows\minidump"
        $DumpFolder = "C:\Dell\logs\dump.zip"
        #$zipArchive = [System.IO.Compression.ZipFile]::Open($DumpFolder, 'Create')

        # Check if at least one of the paths exist before accessing their LastWriteTime
        if ((Test-Path $memoryDmpPath) -or (Test-Path $minidumpPath)) {
        $zipArchive = [System.IO.Compression.ZipFile]::Open($DumpFolder, 'Create')
        Write-Host "Collecting Dump files, This process may take around 5-10 minutes, please wait!"
           
            # Check if the file exists before accessing its LastWriteTime
            if (Test-Path $memoryDmpPath) {
                $memoryDmpTimestamp = (Get-Item $memoryDmpPath).LastWriteTime
                $currentTimestamp = Get-Date
                $daysDifference = ($currentTimestamp - $memoryDmpTimestamp).Days
                
                # Checking Memory.dmp if the conditions are met
                if ($daysDifference -lt 30) {
                    Get-ChildItem -Path $memoryDmpPath | ForEach-Object {
                    
                    # Compressing MEMORY.DMP log #
                        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipArchive, $_.FullName, $_.Name)
                    }
                    

                }
            }
            # Check if the file exists before accessing its LastWriteTime
            if (Test-Path $minidumpPath) {
                $minidumpPathTimestamp = (Get-Item $minidumpPath).LastWriteTime
                $currentTimestamp = Get-Date
                $daysDifference2 = ($currentTimestamp - $minidumpPathTimestamp).Days
                
                # Checking files from minidump folder if the conditions are met
                if ($daysDifference2 -lt 30) {
                    
                    # Get all files in the minidump folder
                    $minidumpFiles = Get-ChildItem -Path $minidumpPath
                    foreach ($file in $minidumpFiles) {
                       
                    # Compressing MiniDump logs
                        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipArchive, $file.FullName, $file.Name)
                    }
                }
            }
            # Close ZipFile #
            $zipArchive.Dispose()
        }#>
        #Creating a temporary dumps folder#
        # Checking dump file timestamp is more than 30 Days
        $memoryDmpPath = "c:\windows\memory.dmp"
        $minidumpPath = "c:\windows\minidump"
        $DumpFolder = "C:\Dell\logs\dump.zip"

        # Check if at least one of the paths exist before accessing their LastWriteTime
        if ((Test-Path $memoryDmpPath -and ((Get-Date) - (Get-Item $memoryDmpPath).LastWriteTime).Days -lt 30) -or 
            (Test-Path $minidumpPath -and ((Get-Date) - (Get-Item $minidumpPath).LastWriteTime).Days -lt 30)) {
    
            $zipArchive = [System.IO.Compression.ZipFile]::Open($DumpFolder, 'Create')
            Write-Host "Collecting Dump files, This process may take around 5-10 minutes, please wait!"
    
            # Check if the file exists before accessing its LastWriteTime
            if (Test-Path $memoryDmpPath) {
                $memoryDmpTimestamp = (Get-Item $memoryDmpPath).LastWriteTime
                $currentTimestamp = Get-Date
                $daysDifference = ($currentTimestamp - $memoryDmpTimestamp).Days
        
                # Checking Memory.dmp if the conditions are met
                if ($daysDifference -lt 30) {
                    Get-ChildItem -Path $memoryDmpPath | ForEach-Object {
            
                    # Compressing MEMORY.DMP log #
                        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipArchive, $_.FullName, $_.Name)
                    }
                }
            }
            # Check if the file exists before accessing its LastWriteTime
            if (Test-Path $minidumpPath) {
                $minidumpPathTimestamp = (Get-Item $minidumpPath).LastWriteTime
                $currentTimestamp = Get-Date
                $daysDifference2 = ($currentTimestamp - $minidumpPathTimestamp).Days
        
                # Checking files from minidump folder if the conditions are met
                if ($daysDifference2 -lt 30) {
            
                    # Get all files in the minidump folder
                    $minidumpFiles = Get-ChildItem -Path $minidumpPath
                    foreach ($file in $minidumpFiles) {
               
                    # Compressing MiniDump logs
                        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipArchive, $file.FullName, $file.Name)
                    }
                }
            }
            # Close ZipFile #
            $zipArchive.Dispose()
        }


#MainMenu#
DisplayMenu
#Invoke-TssCollect#
clear-host
Remove-Item -Path "C:\Dell\Tss.zip" -Recurse -Force -ErrorAction Ignore
$logfolder = (Get-ChildItem -Path c:\dell\Logs\*.zip -Name)
Write-Host "Logs available at c:\Dell\Logs"
#Removing extracted collector and zip file#
Remove-Item "C:\Dell\Tss" -Recurse -Force -ErrorAction Ignore
}