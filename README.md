# TSSCollect
Repository for MS products

TSSCollect:

TSSv2: Windows PowerShell based Troubleshshooting script (TSS) toolset

This is the Windows PowerShell based equivalent for the CMD based TSS toolset.

For Downlaods please use official Microsoft sites:

https://aka.ms/getTSS
https://cesdiagtools.blob.core.windows.net/windows/TSSv2.zip
Note: https://cesdiagtools.blob.core.windows.net/windows/TSSv2.ver will always reflect latest version number

This script simplify the log collection and will gather logs based on installed roles/features.

    +======================================================================+
    |                                                                      |
    |                                                                      |                
    |   _____  ___  ___   _                  ___       _  _           _    |
    |  |_   _|/ __|/ __| | |    ___  __ _   / __| ___ | || | ___  __ | |_  |
    |    | |  \__ \\__ \ | |__ / _ \/ _` | | (__ / _ \| || |/ -_)/ _||  _  |
    |    |_|  |___/|___/ |____|\___/\__, |  \___|\___/|_||_|\___|\__| \__| |
    |                               |___/                                  |
    |                                                                      | 
    |                                           v1.4                       |     
    |                                                                      |
    |                               By: Fabiano Inacio                     |
    |                                                                      |
    |                                                                      |
    +======================================================================+   

### Usage
Copy the below powershell code and paste into PowerShell
```Powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-Expression('$module="TSSCollect"; $repo="PowershellScripts"'+(new-object net.webclient).DownloadString('https://raw.githubusercontent.com/fginacio/MS/main/TSSCollect.ps1'));Invoke-TSSCollect
``` 

-------------------------------------------------------------------------------------------------------------------------------------------------

### How To Use TSSv2Collect_Offline

1. Download the TSSv2 from this link <https://aka.ms/getTSS>;
2. On server where you need make the collection, save the TSS.zip at c:\Dell\ folder and unzip to c:\dell\TSSv2\;
3. Download the TSSv2Collect_Offline.ps1 from this link <https://raw.githubusercontent.com/fginacio/MS/main/TSSv2Collect_Offline.ps1> and save at c:\Dell\ folder;
4. Run the copied code
```Powershell
Echo TSSv2Collect_Offline;[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-Expression('$module="TSSv2Collect_Offline"; $repo="PowershellScripts"'+(new-object net.webclient).DownloadString('c:\dell\TSSv2Collect_offline.ps1'));
``` 
5. The rest will run as normal





