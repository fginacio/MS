# MS
Repository for MS products

TSSv2Collector:

TSSv2
TSSv2: Windows PowerShell based Troubleshshooting script (TSS) toolset

This is the Windows PowerShell based equivalent for the CMD based TSS toolset.

For Downlaods please use official Microsoft sites:

https://aka.ms/getTSS
https://cesdiagtools.blob.core.windows.net/windows/TSSv2.zip
Note: https://cesdiagtools.blob.core.windows.net/windows/TSSv2.ver will always reflect latest version number

This script simplify the log collection with only 3 collection options.

    +===============================================+
    |  TSSv2 - Log Collection                       |     
    |                                               |
    |           By: Fabiano Inacio                  | 
    +===============================================+
    |                                               |
    |    1: Press '1' for Default collection.       |
    |    2: Press '2' for Cluster collection.       |
    |    3: Press '3' for HyperV collection.        |
    |    Q: Press 'Q' for Exit.                     |
    +===============================================+
    

### Usage
Copy the below powershell code and paste into PowerShell
```Powershell
Echo TSSv2Collect;[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-Expression('$module="TSSv2Collect"; $repo="PowershellScripts"'+(new-object net.webclient).DownloadString('https://raw.githubusercontent.com/fginacio/MS/main/TSSv2Collect.ps1'))
``` 

-------------------------------------------------------------------------------------------------------------------------------------------------

### How To Use TSSv2Collect_Offline

1. Download the TSSv2 from this link <https://aka.ms/getTSS>;
2. On server were you need make a collection, save the TSSv2.zip at c:\Dell\ folder;
3. Download the TSSv2Collect_Offline.ps1 from this link <https://raw.githubusercontent.com/fginacio/MS/main/TSSv2Collect_Offline.ps1> and save at c:\Dell\ folder;
4. Run the copied code
```Powershell
Echo TSSv2Collect_Offline;[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-Expression('$module="TSSv2Collect_Offline"; $repo="PowershellScripts"'+(new-object net.webclient).DownloadString('c:\dell\TSSv2Collect_offline.ps1'));
``` 
5. The rest will run as normal





