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
    
 ======
 Usage
 ======
 
Copy the below powershell code and paste into PowerShell

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-Expression('$module="ToolBox";$repo="PowershellScripts"'+(new-object net.webclient).DownloadString('https://raw.githubusercontent.com/fginacio/MS/main/TSSv2Collect1_2.ps1'));Invoke-TSSv2Collector



