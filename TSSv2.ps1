<#
.SYNOPSIS
   Collect traces for Windows (ADS/CRM/DND/INT/NET/PRF/SHA/SPS/UEX/VSOD) and Netsh(packet capture)/Procmon/PerfMon/PSR/Video/SysMon/WPR/xPerf/TTD asf.

.DESCRIPTION
   TSS is a universal tool for troubleshooting Windows issues, it can collect ETW/WPP traces for Windows components, and in parallel collect a whole suite of more data.
   i.e. Netsh(packet capture)/Procmon/PerfMon/PSR/Video/SysMon/WPR/xPerf/TTD... can be taken all at the same time.
   This script supports -StartAutoLogger for ETW traces and in addition to this, BootLogging of various tools,
   including BootTrace(WPR), persistent=yes(Netsh) and /BootLogging(Procmon).

   Run 'Get-Help .\TSS.ps1 -full' for more detail.
   Run '.\TSS.ps1 -Find <keyword>' for detailed information about specific <keyword>

   USAGE SUMMARY:
   Script accepts data collection start actions: -Start/-StartAutologger/-StartDiag/-CollectLog 
   and uses -Stop to stop data collection or stops automatically by trigger with -WaitEvent option supplied.

   a) Start multiple traces, for exmple, UEX_RDS and ADS_Kerb trace, you should use this option if you know exactly what to trace:
      PS> .\TSS.ps1 -UEX_RDS -ADS_Kerb

   b) Start traces for PKI Client scenario to collect ADS basic data:
      PS> .\TSS.ps1 -Scenario ADS_Basic

   c) Start traces for Auth scenario to collect broad set of AUTH data:
      PS> .\TSS.ps1 -Scenario ADS_Auth

   d) Start traces for ADCS (cert authority) service and full AUTH data (recommended way to get full set of data from ADCS):
      PS> .\TSS.ps1 -Scenario ADS_Auth -CustomParams ADS_PKIADCS -ADS_ADCS -netsh

   e) Start traces and WPR/Netsh(ppsacket capturing)/Procmon at the same time:
      PS> .\TSS.ps1 -UEX_RDS -ADS_Auth -WPR General -Netsh -Procmon

   f) Collect WMI, WinRM, Task Scheduler, Print, Setup logs:
      PS> .\TSS.ps1 -CollectLog UEX_WMI,UEX_WinRM,UEX_Sched,UEX_Print
	  PS> .\TSS.ps1 -CollectLog DND_SetupReport

   Stop all traces including WPR/Netsh/Procmon/PSR:
      PS> .\TSS.ps1 -Stop

   StartAutoLogger for persistent/boot ETW traces and WPR(BootTrace), Netsh(persistent=yes) and Procmon(BootLogging):
      PS> .\TSS.ps1 -StartAutoLogger -UEX_RDS -WPR General -Netsh -Procmon
      PS> Restart-Computer
      PS> .\TSS.ps1 -Stop  # Stop all AutoLogger sessions and settings

   Collect just logs for each component:
      PS> .\TSS.ps1 -CollectLog PRF_IME,UEX_Print,BasicLog
	  PS> .\TSS.ps1 -CollectLog DND_SetupReport

   Display built-in Help Menu
      PS> .\TSS.ps1 -Help

   Find any help for keyword
      PS> .\TSS.ps1 -Find <keyword>
	  
.NOTES  
   Authors    : Ryutaro Hayashi (ryhayash@microsoft.com), Milan Milosavljevic (milanmil@microsoft.com), WalterE
   Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2) - it fails on older OS with PS v2.0
   Version    : see $global:TssVerDate - run .\TSS -ver

.LINK
	Download:  https://aka.ms/getTSS / https://aka.ms/getTSSlite -or- https://cesdiagtools.blob.core.windows.net/windows/TSSv2.zip
	Public KB: https://aka.ms/TSSv2 -or- https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-troubleshooters/introduction-to-troubleshootingscript-toolset-tssv2
	TSS https://internal.support.services.microsoft.com/en-us/help/4619187
	ADS https://internal.support.services.microsoft.com/en-us/help/4619196
	NET https://internal.support.services.microsoft.com/en-US/help/4648588
	DND https://internal.support.services.microsoft.com/en-us/help/4643331
	SHA https://internal.support.services.microsoft.com/en-us/help/5009525
	PRF https://internal.support.services.microsoft.com/en-us/help/5009898
	UEX https://internal.support.services.microsoft.com/en-us/help/5013201

.PARAMETER Start
Starting UEX_RDS trace and WRP/Netsh(packet capturing)/Procmon/PSR depending on options.

.PARAMETER StartAutoLogger
Set AutoLogger for persistent/boot ETW traces and WRP/Netsh(packet capturing)/Procmon.

.PARAMETER StartNoWait
Use to start <xxx> (ex. .\TSS.ps1 -StartNoWait -UEX_RDS) and fall back to prompt
Don't wait and the script returns immediately after starting traces.
You will need to stop tracing with: .\TSS.ps1 -Stop

.PARAMETER Stop
Stop all active ETW traces and WRP/Netsh(packet capturing)/Procmon/PSR. If traces are running as autologger/persistent mode, -Stop also removes the autologger settings.
Also this deletes AutoLogger settings if exist.

.PARAMETER RemoveAutoLogger
Delete all AutoLogger settings. 
Note this does not cancel WRP(BootTrace)/Netsh(persistent=yes)/Procmon(BootLogging). 
These are stopped manually after restarting the system.

.PARAMETER CollectLog
Collect logs for each component:
   PS> .\TSS.ps1 -CollectLog DND_SETUPReport

.PARAMETER WaitEvent 
Monitoring - see '.\TSS.ps1 -Help' and then select 8 = Monitoring feature

.PARAMETER Scenario
Run a predefined compbination of Component tracing and tools
See -ListSupportedScenarioTrace for a list of supported Scenario Tracing

.PARAMETER WPR
Start Windows Performance Recorder profile tracing, i.e. -WPR General
If used with -StartAutoLogger (i.e. -StartAutoLogger -WPR General), WPR General BootTrace is enabled.

.PARAMETER Netsh
Start Netsh (packet capturing) session. If used with -StartAutoLogger(i.e. -StartAutoLogger -Netsh), Netsh is started with 'Persisten=yes'.

.PARAMETER NetshScenario
(ex. .\TSS.ps1 -UEX_RDS -NetshScenario InternetClient_dbg)
Start Netsh (packet capturing) session with scenario trace. If used with -StartAutoLogger (i.e. -StartAutoLogger -NetshScenario InternetClient_dbg), Netsh is started with 'Persistent=yes'.

.PARAMETER Procmon
Start Procmon. If used with -StartAutoLogger(i.e. -StartAutoLogger -Procmon), BootLogging is enabled.

.PARAMETER PerfMon
Enable traces and Performance Monitor log.

.PARAMETER PerfIntervalSec
Use with -PerfMon (ex. .\TSS.ps1 -PerfMon -PerfInvervalSec(second))
Specify log interval for Performance Monitor log.

.PARAMETER Compress
Log folder('MSLOG' folder on desktop) is compressed after gathering logs.

.PARAMETER Delete
Use with -Compress. If -Delete, log foder will be deleted after compressing log folder is completed.

.PARAMETER Verbose
This script will run with verbose messages.

.PARAMETER Find
Find keyword in TSS help texts that include the specific search keyword
It also works with regular expressions like "reg.*path" or '|' operator "keyword1|keyword2"

.PARAMETER ListETWProviders <component/scenario>
List all ETW provider GUIDs for specific TSS component-/scenario-name

.PARAMETER FindGUID
List TSS component-names that include the specific ETW provider GUID

.PARAMETER Help
Display built-in Help Menu

.PARAMETER List
List all supported traces in this script

.PARAMETER ListSupportedCommands
List supported Command-Tools

.PARAMETER ListSupportedControls
List supported Control options

.PARAMETER ListSupportedNetshScenario
List supported NETSH scenarios on this computer

.PARAMETER ListSupportedNoOptions
List supported No* options

.PARAMETER ListSupportedSDP
List supported SDP reports

.PARAMETER ListSupportedScenarioTrace
List supported Scenario Tracing

.PARAMETER ListSupportedTrace
List supported component tracing switches and commands

.PARAMETER SDP
Collect SDP/MSDT reports (.e. .\TSS.ps1 -SDP NET)
See -ListSupportedSDP for a list of supported SDP reports

.PARAMETER Mini
Suppress Collecting some of per default defined logs i.e.in NET_*scenarios

.PARAMETER Mode
 [for data collection] Run script in "Basic","Advanced","Full","Verbose","Hang","Restart","GetFarmdata","Swarm","Kube","Permission" mode. Restart will restart associated service

.PARAMETER Traceinfo
   PS>.\TSS -TraceInfo all               // Show all trace info
   PS>.\TSS -TraceInfo <component-name>  // Show all trace info for component-name , i.e. UEX_Print
   PS>.\TSS -TraceInfo <scenario-name>   // Show all trace info for scenario-name , i.e. NET_Capture
   PS>.\TSS -TraceInfo <command>         // Show all trace info other than ETW trace, i.e. Procmon

.PARAMETER Update
 can be used together with -UpdMode Online|Lite	# deprecated |Quick|Full|Force
Update script with latest version. '-UpdMode Online' or '-UpdMode Full' will download full package, 'Quick' will do a differential update, 'Force' will force update even latest version seems installed

.PARAMETER Version
Displays TSS dated version number 

.OUTPUTS
By default, all log files are stored in 'C:\MS_DATA' folder (= "$global:LogFolder"). Location can be changed by -LogFolderPath

.EXAMPLE
.\TSS.ps1 -UEX_RDS -Scenario ADS_Auth
Start UEX_RDS trace and Scenario ADS_Auth

.EXAMPLE
.\TSS.ps1 -UEX_RDS -Scenario ADS_Auth -StartNoWait
Start trace but the script returns immediately. You can stop the traces with '.\s.ps1 -Stop' later.

.EXAMPLE
.\TSS.ps1 -UEX_RDS -WPR General -Procmon
Collect UEX_RDS trace, WPR profle General and Procmon at the same time.

.EXAMPLE
.\TSS.ps1 -UEX_RDS -PerfMon General
start trace and collect Performance Monitor 'General' log at the same time.

.EXAMPLE
.\TSS.ps1 -UEX_RDS -WPR General -Procmon -PSR
Collect traces, PSR and other tools at the same time.

.EXAMPLE
.\TSS.ps1 -Stop
Stop traces. You can use -Stop for stopping ETW traces, WPR General, Netsh and Procmon.
If you have a concern on some traces are still running, just run this command.

.EXAMPLE
.\TSS.ps1 -StartAutoLogger -UEX_RDS 
Enable AutoLogger setting for persistent/boot UEX_RDS trace

.\TSS.ps1 -StartAutoLogger -UEX_RDS -WPR General
Enable AutoLogger for persistent/boot UEX_RDS trace and WPR General BootTrace 

.EXAMPLE
.\TSS.ps1 -StartAutoLogger -UEX_RDS -WPR General -Netsh -Procmon
Enable AutoLoggers. After restart of the system, you can stop AutoLogger session with '.\TSS.ps1 -Stop'.

.EXAMPLE
.\TSS.ps1 -RemoveAutoLogger
After enable AutoLogger with '-StartAutoLogger' but in case you want to cancel the AutoLogger, use this option to delete the AutoLogger settings.

.EXAMPLE
.\TSS.ps1 -update
Update TSS script with latest version.

.EXAMPLE
.\TSS.ps1 -version
Displays TSS dated version number 
#>

#Requires -Version 3

#region ### All switches - same as in TSS.ps1 for enabling PS auto-complete #2023-04-18
[CmdletBinding(DefaultParameterSetName='Start')]
Param(
	[Parameter(ParameterSetName='Start', Position=0)]
	[Switch]$Start,
	[Parameter(ParameterSetName='StartAutoLogger', Position=0)]
	[Switch]$StartAutoLogger,
	[Parameter(ParameterSetName='StartDiag', Position=0)]
	[String[]]$StartDiag,
	[Parameter(ParameterSetName='Start')]
	[Switch]$StartNoWait,	# do not wait at stage: Press ANY-Key to stop
	[Parameter(ParameterSetName='Stop', Position=0)]
	[Switch]$Stop,
	[Switch]$StopAutologger, # For compatibility.
	[Parameter(ParameterSetName='RemoveAutoLogger', Position=0)]
	[Switch]$RemoveAutoLogger,
	[Parameter(ParameterSetName='Find', Position=0)] 
	#[ValidateNotNullorEmpty()]
	[String]$Find,	# -> ProcessFindKeyword
	[Parameter(ParameterSetName='ListETWProviders', Position=0)]
	[String]$ListETWProviders,
	[Parameter(ParameterSetName='FindGUID', Position=0)]
	[String]$FindGUID,
	[Parameter(ParameterSetName='Help', Position=0)]
	[Switch]$Help,
	[Parameter(ParameterSetName='CollectLog', Position=0)]
	[String[]]$CollectLog,
	[Parameter(ParameterSetName='List', Position=0)]
	[Switch]$List,
	[Parameter(ParameterSetName='List')]
	[Parameter(ParameterSetName='ListSupportedCommands')]
	[Parameter(ParameterSetName='ListSupportedControls')]
	[Parameter(ParameterSetName='ListSupportedDiag')]
	[Parameter(ParameterSetName='ListSupportedLog')]
	[Parameter(ParameterSetName='ListSupportedNetshScenario')]
	[Parameter(ParameterSetName='ListSupportedNoOptions')]
	[Parameter(ParameterSetName='ListSupportedPerfCounter')]
	[Parameter(ParameterSetName='ListSupportedScenarioTrace')]
	[Parameter(ParameterSetName='ListSupportedSDP')]
	[Parameter(ParameterSetName='ListSupportedTrace')]
	[Parameter(ParameterSetName='ListSupportedWPRScenario')]
	[Parameter(ParameterSetName='ListSupportedXperfProfile')]
	[Switch]$ExportGUIcsv,
	[Parameter(ParameterSetName='ListSupportedCommands', Position=0)]
	[Switch]$ListSupportedCommands,
	[Parameter(ParameterSetName='ListSupportedControls', Position=0)]
	[Switch]$ListSupportedControls,
	[Parameter(ParameterSetName='ListSupportedDiag', Position=0)]
	[Switch]$ListSupportedDiag,
	[Parameter(ParameterSetName='ListSupportedLog', Position=0)]
	[Switch]$ListSupportedLog,
	[Parameter(ParameterSetName='ListSupportedNetshScenario', Position=0)]
	[Switch]$ListSupportedNetshScenario,
	[Parameter(ParameterSetName='ListSupportedNoOptions', Position=0)]
	[Switch]$ListSupportedNoOptions,
	[Parameter(ParameterSetName='ListSupportedPerfCounter', Position=0)]
	[Switch]$ListSupportedPerfCounter,
	[Parameter(ParameterSetName='ListSupportedScenarioTrace', Position=0)]
	[Switch]$ListSupportedScenarioTrace,
	[Parameter(ParameterSetName='ListSupportedSDP', Position=0)]
	[Switch]$ListSupportedSDP,
	[Parameter(ParameterSetName='ListSupportedTrace', Position=0)]
	[Switch]$ListSupportedTrace,
	[Parameter(ParameterSetName='ListSupportedWPRScenario', Position=0)]
	[Switch]$ListSupportedWPRScenario,
	[Parameter(ParameterSetName='ListSupportedXperfProfile', Position=0)]
	[Switch]$ListSupportedXperfProfile,
	[Parameter(ParameterSetName='Set', Position=0)]
	[String]$Set,
	[Parameter(ParameterSetName='Unset', Position=0)]
	[String]$Unset,
	[Parameter(ParameterSetName='Status', Position=0)]
	[Switch]$Status,
	[Parameter(ParameterSetName='TraceInfo', Position=0, HelpMessage='Choose one from: all|switch-name|command|scenario')]
	[ValidateNotNullOrEmpty()]
	[String]$TraceInfo,
	[Parameter(ParameterSetName='Version', Position=0)]
	[Switch]$Version,  		# This will show current TSS script version

#region ### All POD Trace provider component-names
#region ----- ADS POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_ADCS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Basic,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_AccountLockout,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_ESR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Auth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_ADDS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_ADsam,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_BadPwd,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_LDAPsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_LockOut,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_DFSR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_EESummitDemo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_GPedit,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_GPmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_GPsvc, 
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Perf,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_UserInfo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_PKICLIENT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_NGC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Bio,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_LSA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_NtLmCredSSP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Kerb,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_KDC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Netlogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Profile,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_SAM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_SSL,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_CryptNcryptDpapi,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_CryptoPrimitives,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_EFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_WebAuth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_SmartCard,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_CredprovAuthui,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Appx,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_kernel,			# deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_NTKernelLogger,	# deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_ShellRoaming,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_CDP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_WinHTTP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_CEPCES,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_IIS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_GPO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_TEST,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_W32Time,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_WinLAPS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_OCSP,
#endregion ----- ADS POD providers -----

#region ----- INT POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$INT_MSMQ,
#endregion ----- CRM POD providers -----

#region ----- CRM POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$CRM_Platform,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$CRM_IISdump,
#endregion ----- CRM POD providers -----

#region ----- Sharepoint SPS POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SPS_ULS,	#Unified Logging Service
#endregion ----- CRM POD providers -----

#region ----- DND POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_AudioETW,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_AudioWPR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_CBS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_CodeIntegrity,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_PNP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_Servicing,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_TPM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_WU,
#endregion ----- DND POD providers -----

#region ----- NET POD providers ----- 
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_TestMe,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_AfdTcpFull,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_AfdTcpBasic,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_AppLocker,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Auth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_BFE,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_BGP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_BITS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Bluetooth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_BranchCache,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_CAPI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_COM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Container,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_CSC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DAcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DAmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DAsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DCLocator,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DHCPcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DHCPsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DNScli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DNSsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Docker,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_EFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Firewall,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_FltMgr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_FSRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_GeoLocation,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_HNS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_HTTP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_HttpSys,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_HypVmBus,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_HypVmms,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_HypVmWp,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_ICS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_IPAM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_IPhlpSvc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_IPsec,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_iSCSI,				#Deprecated: moved to SHA_
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_KernelIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_LBFO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_LDAPcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_LDAPsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_LLTDIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_LLDP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_MBAM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_MBN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_MDM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_MFAext,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Miracast,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_MUX,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NCA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NCHA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NCSI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NDIS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NDIScap,	#packetCapture
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NDISwan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Netlogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NetProfM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Netsetup,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NetworkUX,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NFC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NFScli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NFSsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NLB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NPS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NTFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_OLE32,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_OpenSSH,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Outlook,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_PCI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_PerfLib,			#Deprecated: moved to PRF_
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_PnP,				#Deprecated: Please use DND
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_PortProxy,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_PrintSvc,			#Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Proxy,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_QoS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Quic,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RadioManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RAmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RAS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RasMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RDMA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RNDIS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsAuth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsAuthMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsAudio,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsBroker,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsCore,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDclient,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDclientMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsH,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsHMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsPrintSpool,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRAIL,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDGW,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDGWMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDMS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDMSMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDPCLIP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDPDR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsUsrLogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsUsrLogonMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsVIP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsWRKSPC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RDScommon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RDScli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RDSsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RPC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SCCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SdnNC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SMB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SmbCA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SMBcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SMBsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SMBcluster,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_fskm,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_fsum,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_dns,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_fr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_nbt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_tcp,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DFSmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_dfsn,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_srv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_smbhash,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_sr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_rpcxdr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SCM, # Deprecated, please use PRF
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_sec,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SNMP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SSTP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SQLcheck,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_TAPI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_TaskSch,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_VMswitch,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_VPN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WebClient,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WebIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WinInet,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WFP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WinNAT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Winlogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Winsock,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WinRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WIP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Wlan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WmbClass,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WNV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WSman,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WWAN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Workfolders,
#endregion ----- NET POD providers -----

#region ----- PRF POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Alarm,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_AppX,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Calc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Camera,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Clipboard,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Cortana,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_DM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_DWM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Font,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_IME,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_ImmersiveUI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Media,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_NLS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Perflib,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Photo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_RADAR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Search,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Shell,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Shutdown,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_SCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Speech,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_StartMenu,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Store,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Sysmain,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_SystemSettings,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_UWP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_XAML,
#endregion ----- PRF POD providers -----

#region ----- SEC POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SEC_Defender,
#endregion ----- SEC POD providers -----

#region ----- SHA POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_ATAPort,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_CDROM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_CSVFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_CSVspace,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_Dedup,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_FSRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_HyperV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_ISCSI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_MPIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_MsCluster,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_msDSM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_NFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_ShieldedVM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_ReFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_Storage,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_StorageReplica,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_StorageSense,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_StorageSpace,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_Storport,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_Storsvc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_USB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VDS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VHDMP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VmConfig,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VML,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VMM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VSS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_WSB,
#endregion ----- SHA POD providers -----

#region ----- UEX POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Alarm,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_AppCompat,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_AppID,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_AppV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_AppX, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Auth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Calc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Camera, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_CldFlt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_ClipBoard,  # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_CloudSync,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_COM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_ContactSupport,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Cortana, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_CRYPT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_DeviceStore,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_DM, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_DSC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_DWM, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_ESENT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_EVT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_EventLog,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Font, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_FSLogix,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Fusion,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_IME, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_ImmersiveUI, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_LicenseManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Logon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_LSA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_MDAG,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Media, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_MMC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_MMCSS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_MSRA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Nls, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Photo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Print,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_PrintEx,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_QuickAssist,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_RDS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_RDWebRTC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_RestartManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Search, #Deprecated: Please use PRF_Search
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_TSched,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_SCM, # Deprecated, please use PRF
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_ServerManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Shell, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Shutdown, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Speech, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_StartMenu, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Store, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_SystemSettings, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Task,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Telemetry,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_UEV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_UserDataAccess,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_VAN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WER,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Win32k,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WinRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WMI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WMIBase,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WMIAdvanced,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WMIActivity,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WMIBridge,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WPN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WSC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WVD,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_XAML, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_PowerShell,
#endregion ----- UEX POD providers -----

#region ----- DEV POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DEV_TEST1,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DEV_TEST2,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DEV_TEST3,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DEV_TEST4,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DEV_TEST5,
#endregion ----- DEV POD providers -----

#region ----- CustomETL providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$WIN_CustomETL,
#endregion ----- CustomETL providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$WIN_kernel,

#endregion ### All POD Trace provider component-names

#region ### Command/Tool switches
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String[]]$CustomETL,
	[Parameter(ParameterSetName='Start')]
	[Switch]$Fiddler,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$GPresult,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$Handle,
	[Parameter(ParameterSetName='Start')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$LiveKD,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$Netsh,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String[]]$NetshScenario,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='PerfTCP')]
	[ValidateSet("Client", "Server")]
	[String]$PerfTCP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='PerfTCP')]
	[String]$PerfTCPAddr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='PerfTCP')]
	[Int]$Duration,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='PerfTCP')]
	[Int]$BufferLength,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='PerfSMB')]
	[String]$PerfSMB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='PerfSMB')]
	[String]$PerfSMBFileSize,
	[Parameter(ParameterSetName='Start')]
	[Int]$NumFiles,
	[Parameter(ParameterSetName='Start')]
	[String]$PerfMon,
	[Parameter(ParameterSetName='Start')]
	[String]$PerfMonLong,
	[Parameter(ParameterSetName='Start')]
	[Switch]$PktMon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$PoolMon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$Procmon,
	[Parameter(ParameterSetName='Start')]
	[Switch]$PSR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String[]]$Radar,
	[Parameter(ParameterSetName='Start')]
	[Switch]$RASdiag,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(Mandatory=$False,HelpMessage='Choose one technology from: Apps|CRMbase|Cluster|S2D|SCCM|CTS|DA|Dom|DPM|HyperV|Net|Perf|Print|RDS|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|SUVP|VSS|Mini|Nano|Remote|Repro|RFL|All')]
	[ValidateSet("Apps","CRMbase","Net","DA","Dom","DPM","CTS","Print","HyperV","Setup","Perf","Cluster","S2D","SCCM","RDS","Remote","SQLbase","SQLconn","SQLmsdtc","SQLsetup","SUVP","VSS","mini","nano","Repro","RFL","All")]
	[String[]]$SDP,
	[ValidateSet("noNetadapters","skipBPA","skipHang","skipNetview","skipSddc","skipTS","skipHVreplica","skipCsvSMB")]
	[Parameter(Mandatory=$False,HelpMessage='Choose technologies you want to skip from: noNetadapters|skipBPA|skipHang|skipNetview|skipSddc|skipTS|skipHVreplica|skipCsvSMB')]
	[String[]]$SkipSDPList,
	[Parameter(ParameterSetName='Start')]
	[Switch]$SysMon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[String[]]$TTD,
	[Parameter(ParameterSetName='Start')]
	[Switch]$Video,
	[Parameter(ParameterSetName='Start')]
	[Switch]$WFPdiag,
	[Parameter(ParameterSetName='Start')]
	[Switch]$WireShark,
	[ValidateSet("Storage","Cluster","DCOM","RPC","MDM","Perf","RDMS","RDSPub","SCM")]
	[Parameter(Mandatory=$False,HelpMessage='Specify additional WMI providers to trace in comma separated list: Storage|Cluster|DCOM|RPC|MDM|Perf|RDMS|RDSPub|SCM')]
	[String[]]$WMIProvList,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("BootGeneral", "General", "CPU", 'Device', 'Memory', 'Network', 'Registry', 'Storage', 'Wait', 'SQL', 'Graphic', 'Xaml', 'VSOD_CPU', 'VSOD_Leak')]
	[String]$WPR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("General", "CPU", "Disk", 'Memory', "Network", "Pool", "PoolNPP", "Registry", "SMB2", "SBSL", "SBSLboot", "Leak")]
	[String]$Xperf,
#endregion ### Command/Tool switches

#region ### Control switches
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$BasicLog,
	[Switch]$CreateBatFile,
	[Parameter(ParameterSetName='Start')]
	#[Parameter(ParameterSetName='StartAutoLogger')]
	[Array]$CustomParams,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='CollectLog')]
	[Int]$DefenderDurInMin,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[string]$EtlOptions,	#  circular|newfile:<ETLMaxSize>:<ETLNumberToKeep>:<ETLFileMax>
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Int]$EvtDaysBack = 30,		# used for Eventlog conversion to csv and txt
	[Parameter(ParameterSetName='Start')]
	#[Parameter(ParameterSetName='StartAutoLogger')]
	[string]$ExternalScript,
	[Parameter(ParameterSetName='Start')]
	[Int]$PerfIntervalSec,
	[Parameter(ParameterSetName='Start')]
	[Int]$PerfLongIntervalMin,
	[Parameter(ParameterSetName='Start')]
	[Int]$PerfMonMaxMB,
	[string]$PerfMonCNF,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[String]$LogFolderPath,
	[Switch]$Merge,
	[Switch]$Mini,			# This will skip some data collections, see in Tss_NET.psm1
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Parameter(ParameterSetName='ListETWProviders')]
	[ValidateSet("Basic","Medium","Advanced","Full","Verbose","VerboseEx","Hang","Restart","GetFarmdata","Swarm","Kube","Permission","traceMS","Server","Client","WinPE")]
	[Parameter(Mandatory=$False,HelpMessage='Choose script mode from: Basic|Medium|Advanced|Full|Verbose|VerboseEx|Hang|Restart|Swarm|Kube|GetFarmdata|Permission|traceMS|Server|Client|WinPE')]
	[String]$Mode,			# Run script in special mode, actual meaning depends on POD module (.psm1) implementation for this $global:Mode setting
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[Int]$ProcmonAltitude,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$ProcmonFilter,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[String]$ProcmonPath,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Switch]$RemoteRun,		# use for TSS remote execution, renamed from switch name $Remote to avoid AmbiguousParameter
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[string[]]$Scenario,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[Int]$TTDMaxFile,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[ValidateSet("Full","Ring","Onlaunch")]
	[String]$TTDMode,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[String]$TTDOptions,	# '<Option string>' in single quotes
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[String]$TTDPath,
	[Switch]$Update,	# This will update current TSS script version to latest from GitHub
	[ValidateSet("Online","Quick","Full","Force","Lite")]
	[Parameter(Mandatory=$False,HelpMessage='Choose update mode from: Online|Lite')]
	[String]$UpdMode = "Online",  	
	[Parameter(ParameterSetName='Start')]
	[String]$WaitEvent,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Switch]$xray = $True,	# Run always (for Telemetry), unless -noXray 
	[Switch]$beta = $False,	# hidden switch; set to $False = normal Production mode, $True = Testing/newFeature mode enabled
	[Switch]$Assist,		# Accessibility Mode
	[Switch]$noAdminChk,	# skip Admin check, which verifies elevated Admin rights
	[Switch]$noArgCheck,	# do not validate input command-line arguments
	[Switch]$noAsk,			# do not ask about good/failing scenario text input before compressing data
	[Switch]$noCab,			# Same as noZip. This will skip Compress phase. This switch is for having a comaptibility with TSSv1.
	[Switch]$noClearCache,	# do not clear DNS,NetBios,Kerberos,DFS chaches at start
	[Switch]$noCrash,		# do not run Crash after reboot again when using 'TSS -stop -noCrash'
	[Switch]$noEventConvert,# do not convert Eventlogs to .CSV or .TXT format
	[Switch]$noExpire,		# allow TSS script to run even if its version is older then 30 days
	[Switch]$noFiddler,		# do not start Fiddler
	[Switch]$noGPresult,	# do not run GPresult, used to override setting in preconfigured TS scenarios
	[Switch]$noHandle,		# do not collect Handle.exe
	[Switch]$noHang,		# do not wait forever when data collection seems to hang 
	[Switch]$noLiveKD,		# do not capture LiveKD
	[Switch]$noNetsh,		# do not run Netsh, used to override setting in preconfigured TS scenarios
	[Switch]$noPerfMon,		# do not run PerfMon, used to override setting in preconfigured TS scenarios
	[Switch]$noPktMon,		# do not start PktMon
	[Switch]$noPoolMon,		# do not run PoolMon at start and stop
	[Switch]$noPrereqC,		# do not run PreRequisiteCheckInStage1/2() and PreRequisiteCheckForStart()
	[Switch]$noProcmon,		# do not run Procmon, used to override setting in preconfigured TS scenarios
	[Switch]$noQuickEdit,	# do not try to disable Quick Edit Mode
	[Switch]$noRASdiag,		# do not start RASdiag
	[Switch]$noRecording,	# do not ask about consent for performing PSR or Video recording, and do not start these recordings
	[Switch]$noRepro,		# skip stage waiting for Reproduce the issue
	[Switch]$noRestart,		# do not restart associated service
	[Switch]$noSDP,			# do not gather SDP report, i.e. when using script in scheduled tasks
	[Switch]$noSound,		# do not play attention sound
	[Switch]$noSysMon,		# do not start SysMon
	[Switch]$noTTD,			# do not start Time Travel Debugging (TTD)
	[Switch]$noVersionChk,	# skip online TSS version check 
	[Switch]$noWFPdiag,		# do not start WFPdiag
	[Switch]$noWireShark,	# do not start WireShark
	[Switch]$noWPR,			# do not run WPR, used to override setting in preconfigured TS scenarios
	[Switch]$noXperf,		# do not run xPerf, used to override setting in preconfigured TS scenarios
	[Switch]$noXray,		# do not start xray troubleshooter
	[Switch]$noZip,			# This will skip Compress phase
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Switch]$noUpdate,		# do not AutoUpdate from cesdiagtools.blob.core.windows.net
	[Parameter(ParameterSetName='Start')]
	[Switch]$noPSR,
	[Parameter(ParameterSetName='Start')]
	[Switch]$noVideo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='NetshScenario')]
	[Switch]$noPacket,		# prevent packets from being captured with Netsh (only ETW traces in the ScenarioName will be captured)
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Switch]$noBasicLog,
	[Switch]$DebugMode,
	[Switch]$VerboseMode,
	[Switch]$AcceptEula,
	[Switch]$AddDescription,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Int]$NetshMaxSizeMB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$NetshOptions,	# '<Option string>'
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$WPROptions,	# '<Option string>'
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Int]$XperfMaxFileMB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$XperfOptions,	# '<Option string>'
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Int]$XperfPIDs,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$XperfTag,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SkipPdbGen,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[String]$CommonTask,
	[Switch]$EnableCOMDebug,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Switch]$NewSession,
	[Switch]$Discard,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Switch]$CollectComponentLog,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[String[]]$ProcDump,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Switch]$ProcDumpAppCrash,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[String]$ProcDumpInterval,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[ValidateSet("Start","Stop","Both")]
	[String]$ProcDumpOption,	#="Both" #we# removed, as it would not obey setting in config.cfg
	[String]$InputlogPath,
	[Parameter(ParameterSetName='Start')]
	[Int]$StopWaitTimeInSec,
	[Parameter(ParameterSetName='Start')]
	[Int]$CheckIntInSec,	#poll Interval (for -WaitEvent)
	[Parameter(ParameterSetName='Start')]
	[Int]$HighCPUTimeInSec,
	[Parameter(ParameterSetName='Start')]
	[Int]$HighMemUsageInSec,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Switch]$Crash,
	[Parameter(ParameterSetName='Start')]
	[ValidateSet("Full", "Kernel","active","automatic","mini")]
	[String]$CrashMode,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Info","Warning","Error")]
	[String]$ETWlevel,		# in code $TraceLevel
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$ETWflags,		# currently used for 'NT Kernel Logger'
	[Parameter(ParameterSetName='Start')]
	[String[]]$RemoteHosts,
	[Parameter(ParameterSetName='Start')]
	[String]$RemoteLogFolder,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='CollectLog')]
	[String[]]$Servers,
	[String]$StartTime,
	[String]$EndTime,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Switch]$CollectDump,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[String[]]$CollectEventLog,
	[Parameter(ParameterSetName='Start')]
	[Int]$MaxEvents,

	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$v,				# more verbose logging for ADS_Auth
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[string]$containerId,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[switch]$slowlogon,		# for ADS_Auth
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[switch]$noISECheck
#endregion ### Control switches
)
#endregion ### All switches

#region --- Define Variables 
	# Dated version of TSS script 
	$global:TssVerDate = "2023.06.20.0"	# Plz. update if releasing a new POD module version TssVerDate<POD>
	$csvDelimiter=","
	$Script:TssReleaseServer = "cesdiagtools.blob.core.windows.net"
	$global:v = $v	# verbose
	$global:containerId = $containerId
	$global:WMIProvList = $WMIProvList
	$global:slowlogon = $slowlogon
	$global:Servers = $Servers		# used i.e. for SharePoint Farm
	if ($StartTime){$global:SPSStartTime = $StartTime}
	if ($EndTime) {$global:SPSEndTime = $EndTime}
	if ($Merge) {$global:SPSmerge = $Merge}
#endregion --- Define Variables

# **Kernel provider needs to run its own ETW session with name 'NT Kernel Logger'
#If($global:BoundParameters.ContainsKey('ETWflags')){
If($ETWflags){
	$EtwTraceFlags = $ETWflags
}
	if (![string]::IsNullOrEmpty($EtwTraceFlags)){
		$TraceFlags = $EtwTraceFlags
	}else{
		$TraceFlags = "0x0000000000000001"
	}
$WIN_KernelProviders = @(
	'{9E814AAD-3204-11D2-9A82-006008A86939}!kernel!'+$TraceFlags+'!0xFF'	# Windows Kernel Trace 'NT Kernel Logger' / logman query providers "Windows Kernel Trace"
)

# ToDo: Define Variable defaults if not configured in tss_config
## -> FwConfigParameters

$TraceSwitches = [Ordered]@{

#region ### All POD descriptions
#region ----- ADS POD description -----
	'ADS_TEST' = 'ADS TEST'
	'ADS_Basic' = 'ADS Basic (CryptoDPAPI,CryptoPrimitives,EFS,KERB,NtLmCredSSP,KDC,SSL,WebAuth,SmartCard,CredprovAuthui,NGC,Bio,LSA) component ETW tracing'
	'ADS_Auth' = 'ADS Auth (CryptoDPAPI,KERB,NtLmCredSSP,SSL,WebAuth,SmartCard,CredprovAuthui,NGC,Bio,LSA) component ETW tracing'
	'ADS_AccountLockout' = 'ADS AccountLockout, KERB,NtLmCredSSP,KDC,SSL,LSA ETL log(s), Security EventLog component ETW tracing'
	'ADS_ESR' = 'ADS ESR (WebAuthP,ShellRoaming,CDP,WinHTTP,SSL) component ETW tracing'
	'ADS_ADDS' = 'ADDS core (Active Directory core) tracing'
	'ADS_ADsam' = 'ADsam (Active Directory SAM) component ETW tracing'
	'ADS_ADCS' = 'PKI Server / Certification Authority component ETW tracing'
	'ADS_BadPwd' = 'BadPassword component ETW tracing'
	'ADS_Bio' = 'ADS Bio component ETW tracing'
	'ADS_CDP' = 'ADS CDP component ETW tracing'
	'ADS_CEPCES' = 'ADS CEPCES component ETW tracing'
	'ADS_CredprovAuthui' = 'ADS CredprovAuthui component ETW tracing'
	'ADS_CryptNcryptDpapi' = 'ADS Crypto DPAPI component ETW tracing'
	'ADS_CryptoPrimitives' = 'ADS Crypto Primitives component ETW tracing'
	'ADS_DFSR' = 'DFS-R (replication) component ETW tracing'
    'ADS_EESummitDemo' = 'EE summit 2023 demo; do not use it for data collection'
	'ADS_EFS' = 'ADS EFS component ETW tracing'
	'ADS_GPedit' = 'ADS Group Policy Editor (GPedit) component ETW tracing'
	'ADS_GPmgmt' = 'ADS Group Policy Management (GPmgmt) component ETW tracing'
	'ADS_GPO' = 'ADS GPO GroupPolicy component ETW tracing'
	'ADS_GPsvc' = 'ADS GPsvc (Group Policy Service) component ETW tracing'
	'ADS_IIS' = 'ADS IIS component ETW tracing'
	'ADS_KDC' = 'ADS KDC component ETW tracing'
	'ADS_Kerb' = 'ADS KERB component ETW tracing'
	'ADS_LDAPsrv' = 'LDAP server NTDSA component ETW tracing'
	'ADS_LockOut' = 'Account LockOut component ETW tracing'
	'ADS_LSA' = 'ADS LSA component ETW tracing'
	'ADS_Netlogon' = 'Netlogon component ETW tracing'
	'ADS_NGC' = 'ADS NGC component ETW tracing'
	'ADS_NTKernelLogger' = 'Kernel Logger component ETW tracing'
	'ADS_NtLmCredSSP' = 'ADS NTLM CredSSP component ETW tracing'
	'ADS_OCSP' = 'ADS Online Certificate Status Protocol component ETW tracing'
	'ADS_Perf' = 'Collect ADperf Data using script tss_ADPerfDataCollection.ps1'
	'ADS_PKICLIENT' = 'PKI Client / CertEnroll / EFS Scenario component ETW tracing'
	'ADS_Profile' = 'ADS Profile component ETW tracing'
	'ADS_SAM' = 'ADS SAM component ETW tracing'
	'ADS_ShellRoaming' = 'ADS ShellRoaming component ETW tracing'
	'ADS_SmartCard' = 'ADS SmartCard component ETW tracing'
	'ADS_SSL' = 'ADS SSL / TLS component ETW tracing'
	'ADS_UserInfo' = 'ADS User info component ETW tracing'
	'ADS_WebAuth' = 'ADS WebAuth component ETW tracing'
	'ADS_Appx' = 'ADS WebAuth component ETW tracing'
	'ADS_kernel' = 'deprecated: use WIN_kernel ETW tracing'
	'ADS_WinHTTP' = 'ADS WinHTTP component ETW tracing'
	'ADS_W32Time' = 'ADS Windows Time component ETW tracing'
	'ADS_WinLAPS' = 'ADS Local Administrator Password Solution (LAPSv2) component ETW tracing'
#endregion ----- ADS POD description -----

#region ----- INT POD description -----
	'INT_MSMQ' = 'Biztalk Integration MSMQ tracing'
#endregion ----- INT POD description -----

#region ----- CRM POD description -----
	'CRM_Platform' = 'Dynamics CRM Platform Collector tracing'
	'CRM_IISdump ' = 'Dynamics CRM IIS (CRMAppPool) crash or hang memory dump collection'
#endregion ----- CRM POD description -----

#region ----- NET POD description -----
	'NET_TestMe' = 'NET TestMe tracing - for Testing purpose only'
	'NET_802Dot1x' = 'NET 802Dot1x scenario tracing, (use only with -Scenario NET_802Dot1x)'
	'NET_AfdTcpFull' = 'Afd/TcpIp/NetIO full component ETW tracing'
	'NET_AfdTcpBasic' = 'Afd/TcpIp/NetIO basic component ETW tracing'
	'NET_AppLocker' = 'AppLocker component ETW tracing'
	'NET_Auth' = 'NET AUTH tracing (ADS_Auth providers)'
	'NET_BFE' = 'Base Filtering Engine (BFE) component ETW tracing'
	'NET_BGP' = 'Boarder Gateway Protocol (BGP) component ETW tracing'
	'NET_BITS' = 'Background Intelligent Transfer Service (BITS) component ETW tracing'
	'NET_Bluetooth' = 'Bluetooth component ETW tracing'
	'NET_BranchCache' = 'BrancheCache component ETW tracing'
 	'NET_CAPI' = 'CAPI component ETW tracing'
	'NET_COM' = 'COM/DCOM/WinRT/PRC component tracing. -EnableCOMDebug will enable further debug logging'
	'NET_Container' = 'ALL_ Docker/Container tracing; -Mode <Swarm|Kube>'
	'NET_CSC' = 'Client Side Caching (CSC) tracing (see NET_SMBcli)'
	'NET_DAcli' = 'Direct Access client component ETW tracing'
	'NET_DAmgmt' = 'Direct Access management component ETW tracing'
	'NET_DAsrv' = 'Direct Access server component ETW tracing'
	'NET_DCLocator' = 'ADS_ Domain Controller Locator component ETW tracing'
	'NET_DFSsrv' = 'DFS-N server component ETW tracing'
	'NET_DHCPcli' = 'DHCP client component ETW tracing'
	'NET_DHCPsrv' = 'DHCP server component ETW tracing'
	'NET_DNScli' = 'DNS client component ETW tracing'
	'NET_DNSsrv' = 'DNS server component ETW tracing'
	'NET_Docker' = 'ALL_ Docker/Container component ETW tracing'
	'NET_EFS' = 'ALL_ Encrypted File System (EFS) component ETW tracing'
	'NET_Firewall' = 'Firewall component ETW tracing'
	'NET_FltMgr' = 'ALL_ Filter Manager component ETW tracing'
	'NET_FSRM' = 'File Server Resource Manager (FSRM) component ETW tracing'
	'NET_FWmgr' = 'Firewall manager component ETW tracing'
	'NET_GeoLocation' = 'BSSID GPS Geolocation tracing on WiFi or Cellular network when changing location/timezones, Orion DB'
	'NET_HNS' = 'ALL_ Host Networking Service (HNS) component ETW tracing'
	'NET_HTTP' = 'WinINet/WinHTTP component ETW tracing'
	'NET_HttpSys' = 'WinInet/HttpSys component ETW tracing'
	'NET_HypVM' = 'NET_ Hyper-V VirtualMachine component ETW tracing'
	'NET_ICS' = 'Internet Connection Sharing (ICS) component ETW tracing'
	'NET_IIS' = 'ALL_ Internet Information Server (IIS) component ETW tracing'
	'NET_IPAM' = 'IP Address Management (IPAM) component ETW tracing'
	'NET_IPhlpSvc' = 'IPhelper Service component ETW tracing'
	'NET_IPsec' = 'IPsec component ETW tracing'
	'NET_iSCSI' = 'Deprecated: Please use SHA_iSCSI component ETW tracing'
	'NET_KernelIO' = 'ALL_ KernelIO component ETW tracing'
	'NET_LBFO' = 'Load Balacing/Failover (LBFO) component ETW tracing'
	'NET_LDAPcli' = 'LDAP client tracing; edit tss_config to specify LDAPcliProcess'
	'NET_LDAPsrv' = 'LDAP server tracing (Logging from NTDSA) - full'
	'NET_LLTDIO' = 'Link-Layer Topology Discovery Mapper I/O (LLTDIO) Driver component ETW tracing'
	'NET_LLDP' = 'Link-Layer DiscoveryProtocol (LLDP) component ETW tracing'
	'NET_MBAM' = 'Microsoft BitLocker Administration and Monitoring (MBAM) component ETW tracing'
	'NET_MBN' = 'Mobile Broadband (MBN) and Wireless Wide Area Network (WWAN) component ETW tracing'
	'NET_MFAext' = 'ALL_ Multi Factor Authentication extension (MFAext) component ETW tracing'
	'NET_Miracast' = 'Miracast component ETW tracing'
	'NET_MUX' = 'ALL_ MUX component ETW tracing'
	'NET_NCA' = 'Network Connectivity Assistant (NCA) component ETW tracing'
	'NET_NCHA' = 'ALL_ Network Controller (NCHA) component ETW tracing'
	'NET_NCSI' = 'Network Connectivity Status Indicator (NCSI/NLA) component ETW tracing, prefer using -Scenario NET_NCSI'
	'NET_NDIS' = 'Network Driver Interface Specification (NDIS) component ETW tracing'
	'NET_NDIScap' = 'Network packetcapture'
	'NET_NDISwan' = 'NDISwan component ETW tracing'
	'NET_NetworkUX' = 'ALL_ NetworkUX component ETW tracing'
	'NET_Netlogon' = 'Netlogon component ETW tracing'
	'NET_NetProfM' = 'Network Profile Manager (network list service) component ETW tracing'
	'NET_Netsetup' = 'NetSetup component ETW tracing'
	'NET_NFC' = 'Near Field Communication (NFC) component ETW tracing'
	'NET_NFScli' = 'Network File System (NFS) client component ETW tracing'
	'NET_NFSsrv' = 'Network File System (NFS) server component ETW tracing'
	'NET_NLB' = 'Network Load Balancing (NLB) server component ETW tracing'
	'NET_NPS' = 'Network Policy Server (NPS) incl. EapHost component ETW tracing'
	'NET_NTFS' = 'ALL_ NTFS component ETW tracing'
	'NET_OLE32' = 'OLE32 component ETW tracing'
	'NET_OpenSSH' = 'OpenSSH component ETW tracing'
	'NET_Outlook' = 'Outlook component ETW tracing'
	'NET_PCI' = 'collect NET PCI info'
	'NET_PerfLib' = 'Deprecated: Please use PRF_PerfLib component ETW tracing'
	'NET_PnP' = 'Deprecated: Please use DND_PnP (Plug and Play) component ETW tracing'
	'NET_PortProxy' = 'PortProxy component ETW tracing'
	'NET_PrintSvc' = 'Deprecated: Please use UEX_Print tracing (PrintTrace.cmd)'
	'NET_Proxy' = 'Proxy tracing (AfdTcpBasic,NCSI,NDIS,WebIO,Winsock)'
	'NET_Quic' = 'Microsoft-Quic (QUIC 1.0) component ETW tracing'
	'NET_QoS' = 'Quality of Service (QoS) component ETW tracing'
	'NET_RadioManager' = 'RadioManager component ETW tracing'
	'NET_RAmgmt' = 'RemoteAccess management component ETW tracing'
	'NET_RAS' = 'Remote Access Server (RAS) component ETW tracing'
	'NET_RasMan' = 'Remote Access Connection Manager (RasMan) component ETW tracing'
	'NET_RDMA' = 'Remote Direct Memory Access (RDMA) component ETW tracing'
	'NET_RNDIS' = 'Remote NDIS (RNDIS) component ETW tracing'
	'NET_RDScli' = 'RDS Remote Desktop Service Client (RdsCommon,RdsRDclientRdsRDclientMan,RdsWRKSPC) component ETW tracing'
	'NET_RDScommon' = 'RDS common (RDSH,RdsAuth,RdsAuthMan,RdsCore) component ETW tracing'
	'NET_RDSsrv' = 'RDS Remote Desktop Service Server (RdsCommon,RdsHMan,...) component ETW tracing'
	'NET_RdsAudio' = 'RDS Rd-RDAUDIO component ETW tracing'
	'NET_RdsAuth' = 'RDS Rd-AUTH component ETW tracing'
	'NET_RdsAuthMan' = 'RDS Rd-MAN-AUTH component ETW tracing'
	'NET_RdsBroker' = 'RDS Rd-RDS_Broker component ETW tracing'
	'NET_RdsCore' = 'RDS Rd-RDPCORE component ETW tracing'
	'NET_RdsH' = 'RDS Rd-RDSH component ETW tracing'
	'NET_RdsHMan' = 'RDS Rd-MAN-RDSH component ETW tracing'
	'NET_RdsPrintSpool' = 'RDS Rd-PRNTSPOOL component ETW tracing'
	'NET_RdsRAIL' = 'RDS Rd-RAIL component ETW tracing'
	'NET_RdsRDclient' = 'RDS Rd-RDCLIENT component ETW tracing'
	'NET_RdsRDclientMan' = 'RDS Rd-MAN-RDCLIENT component ETW tracing'
	'NET_RdsRDGW' = 'RDS Rd-RDGW component ETW tracing'
	'NET_RdsRDGWMan' = 'RDS Rd-MAN-RDGW component ETW tracing'
	'NET_RdsRDMS' = 'RDS Rd-RDMS component ETW tracing'
	'NET_RdsRDMSMan' = 'RDS Rd-MAN-RDMS component ETW tracing'
	'NET_RdsRDPCLIP' = 'RDS Rd-RDPCLIP component ETW tracing'
	'NET_RdsRDPDR' = 'RDS Rd-RDPDR component ETW tracing'
	'NET_RdsUsrLogon' = 'RDS Rd-USRLOGON component ETW tracing'
	'NET_RdsUsrLogonMan' = 'RDS Rd-MAN-USRLOGON component ETW tracing'
	'NET_RdsVIP' = 'RDS Rd-VIP component ETW tracing'
	'NET_RdsWRKSPC' = 'RDS Rd-WRKSPC component ETW tracing'
	'NET_RPC' = 'RPC (Remote Procedure Call) component ETW tracing'
	'NET_SCCM' = 'ALL_ System Center Configuration Manager (SCCM) logging'
	'NET_SCM' = 'Deprecated: Please use PRF_SCM component ETW tracing'
	'NET_SdnNC' = 'Deprecated: Please use SdnDiagnostics tools at https://www.powershellgallery.com/packages/SdnDiagnostics'
	'NET_SMB' = 'SMB client (SMBcli) and server (SMBsrv) component component ETW tracing'
	'NET_SmbCA' = 'SMB Direct component component ETW tracing'
	'NET_SMBcli' = 'SMB client component (dns,fr,fskm,fsum,rpcxdr,sec,tcp) component ETW tracing'
	'NET_SMBsrv' = 'SMB server component (srv,smbhash,sr,dfsn,SMBcluster) component ETW tracing'
	'NET_SMBsrvBinding' = 'collect SMB LanmanServer bindings (only -CollectLog)'
	'NET_SMBcluster' = 'SMB server cluster component (csvfs,csvflt,csvvbus,csvnflt) component ETW tracing'
	'NET_fskm' = 'SMB (t.cmd) fskm (File Service Kernel-Mode) component ETW tracing (included in NET_SMBcli)'
	'NET_fsum' = 'SMB (t.cmd) fsum (File Service User-Mode) component ETW tracing (included in NET_SMBcli)'
	'NET_dns' = 'SMB (t.cmd) dnsApi component ETW tracing (included in NET_SMBcli)' 
	'NET_fr' = 'SMB (t.cmd) fr (Folder Replication) component ETW tracing (included in NET_SMBcli)' 
	'NET_nbt' = 'SMB (t.cmd) nbt (NetBIOS over TCP) component ETW tracing (included in NET_SMBcli)' 
	'NET_tcp' = 'SMB (t.cmd) tcp component ETW tracing (included in NET_SMBcli)'
	'NET_DFSmgmt' = 'DFSmgmt (DFS management) console component ETW tracing'
	'NET_dfsn' = 'DFS-N (namespace) component ETW tracing (included in NET_SMBsrv)'
	'NET_srv' = 'SMB (t.cmd) server (srv,srv2,srvnet,witness) component ETW tracing (included in NET_SMBsrv)'
	'NET_smbhash' = 'SMB (t.cmd) smbhash component ETW tracing (included in NET_SMBsrv)'
	'NET_sr' = 'SMB (t.cmd) sr volume replication component ETW tracing (included in NET_SMBsrv)'
	'NET_rpcxdr' = 'NFS (t.cmd) rpcxdr component ETW tracing (included in NET_SMBcli/NFScli)' 
	'NET_sec' = 'SMB (t.cmd) security component ETW tracing (included in NET_SMBcli/srv)'
	'NET_SNMP' = 'SNMP (Simple Network Management Protocol) component ETW tracing'
	'NET_SSTP' = 'SSTP (Secure Socket Tunneling Protocol) component ETW tracing'
	'NET_SQLcheck' = 'SQL Connectivity Settings Check (SQLchck.exe)'
	'NET_TAPI' = 'Telephony API (TAPI) component ETW tracing' 
	'NET_TaskSch' = 'UEX_ TaskScheduler component ETW tracing'
	'NET_VMswitch' = 'VMswitch component ETW tracing'
	'NET_VPN' = 'Virtual Private Network (VPN) component ETW tracing'
	'NET_WCM' = 'Windows Connection Manager (WCM) component ETW tracing'
	'NET_WebClient' = 'WebClient with SMBcli tracing. To restart service use -Mode Restart'
	'NET_WebIO' = 'WebIO/Winhttp/WinInet component ETW tracing'
	'NET_WinInet' = 'WinInet component ETW tracing'
	'NET_WFP' = 'Windows Filtering Platform (WFP) component ETW tracing' 
	'NET_WinNAT' = 'Windows Network Access Translation (WinNAT) component ETW tracing'
	'NET_Winlogon' = 'ADS_ Winlogon component ETW tracing'
	'NET_Winsock' = 'Winsock component ETW tracing'
	'NET_WinRM' = 'Windows Remote Management (WinRM) component ETW tracing'
	'NET_WIP' = 'Windows Information Protection (WIP) component ETW tracing'
	'NET_Wlan' = 'Wireless Local Area Network (WLAN) component ETW tracing'
	'NET_WmbClass' = 'WWAN/MBN WmbClass component ETW tracing'
	'NET_WNV' = 'ALL_ Windows Network Virtualization (WNV) component ETW tracing'
	'NET_WSman' = 'WSman component ETW tracing'
	'NET_WWAN' = 'Wireless Wide Area Network (WWAN ) = MBN component ETW tracing'
	'NET_Workfolders' = 'Workfolders component ETW tracing'
#endregion ----- NET POD description -----

#region ----- DND POD description -----
	'DND_AudioETW' = 'Audio ETW tracing + logs'
	'DND_AudioWPR' = 'Audio WPR trace + logs (only -CollectLog)'
	'DND_CodeIntegrity' = 'CodeIntegrity ETW tracing'
	'DND_PNP' = 'Plug and Play (PnP) component ETW tracing'
	'DND_Servicing' = 'CBS, PNP, WU ETW tracing, DISM + servicing logs'
	'DND_SETUP' = 'Collect deploy, setup, WU logs (only -CollectLog)'
	'DND_SETUPreport' = 'Collect Setup Report (only -CollectLog)'
	'DND_TPM' = 'Trusted Platform Module (TPM) ETW tracing + logs'
	'DND_WU' = 'Windows Update (WU) ETW tracing'
	'DND_WUlogs' = 'Collect Windows Update logs (only -CollectLog)'
#endregion ----- DND POD description -----

#region ----- PRF POD description -----
	'PRF_Alarm' = 'Alarm app component ETW tracing'
	'PRF_AppX' = 'AppX component ETW tracing'
	'PRF_Calc' = 'Calculator app component ETW tracing'
	'PRF_Camera' = 'Camera component ETW tracing'
	'PRF_ClipBoard' = 'Clip board component ETW tracing'
	'PRF_Cortana' = 'Cortana component ETW tracing'
	'PRF_DM' = 'Device Management(InstallService/EnterpriseManagement/CSP) component ETW tracing'
	'PRF_DWM' = 'DWM(Desktop Window Manager) component ETW tracing'
	'PRF_Font' = 'Font component ETW tracing'
	'PRF_IME' = 'IME and input component ETW tracing'
	'PRF_ImmersiveUI' = 'ImmersiveUI component ETW tracing'
	'PRF_Media' = 'Media Player component ETW tracing'
	'PRF_Nls' = 'Collect NLS tracing (only -CollectLog)'
	'PRF_Perflib' = 'Perflib component ETW tracing'
	'PRF_Photo' = 'Photo app component ETW tracing'
	'PRF_RADAR' = 'RADAR (RdrLeakDiag) component ETW tracing'
	'PRF_Search' = 'Windows search and search client(tquery.dll) component ETW tracing'
	'PRF_SCM' = 'SCM (Service Control Manager) ETW tracing'
	'PRF_Shell' = 'Shell(explorer.exe) component ETW tracing'
	'PRF_Shutdown' = 'Shutdown component ETW tracing'
	'PRF_Speech' = 'Speech app component ETW tracing'
	'PRF_StartMenu' = 'StartMenu(ShellExperienctHost/StartMenuExperienctHost) component ETW tracing'
	'PRF_Store' = 'Store app component ETW tracing'
	'PRF_Sysmain' = 'Sysmain (Readyboost, Superfetch) component ETW tracing'
	'PRF_SystemSettings' = 'SystemSettings component ETW tracing'
#	'PRF_UWP' = 'Universal Windows Platform (UWP) AppX,COM,Shell tracing (only -Scenario)'
	'PRF_XAML' = 'XAML and dcomp component ETW tracing'
#endregion ----- PRF POD description -----

#region ----- SEC POD description -----
	'SEC_DefenderGet' = 'Collect Defender Get-Logs (only -CollectLog)'
	'SEC_DefenderFull' = 'Collect Full Defender tracing using MDEClientAnalyzer.ps1 (only -CollectLog)'
#endregion ----- SEC POD description -----

#region ----- SHA POD description -----
	'SHA_ATAPort' = 'ATA(IDE) Port component ETW tracing'
	'SHA_CDROM' = 'CDROM, DVD, UDFS component ETW tracing'
	'SHA_CSVFS' = 'SHA CSVFS component ETW tracing'
	'SHA_CSVspace' = 'CSVspace component ETW tracing'
	'SHA_Dedup' = 'Deduplication component ETW tracing'
	'SHA_FSRM' = 'FSRM (File Server Resource Manager) component ETW tracing'
	'SHA_HyperV' = 'Hyper-V component ETW tracing'
	'SHA_HypVmBus' = 'SHA_ Hyper-V VmBus component ETW tracing'
	'SHA_HypVmms' = 'SHA_ Hyper-V Vmms (Virtual Management Service)component ETW tracing'
	'SHA_HypVmWp' = 'SHA_ Hyper-V VmWp (Virtual Machine Worker Process) component ETW tracing'
	'SHA_ISCSI' = 'iSCSI component ETW tracing'
	'SHA_MPIO' = 'Multipath I/O (MPIO) component ETW tracing'
	'SHA_msDSM' = 'Microsoft Device Specific Module (msDSM) component ETW tracing'
	'SHA_MsCluster' = 'SHA MS FailoverClustering component ETW tracing'
	'SHA_NFS' = 'NFS component ETW tracing'
	'SHA_ReFS' = 'ReFS FileSystem component ETW tracing'
	'SHA_SDDC' = 'collect HA/Cluster PrivateCloud.DiagnosticInfo infos'
	'SHA_ShieldedVM' = 'SHA_ ShieldedVM component ETW tracing'
	'SHA_SMS' = 'Storage Migration Service Helper per GetSmsLogs.psm1, run it against both the Orchestrator node and the transfer destination node'
	'SHA_Storage' = 'aka SAN shotgun component ETW tracing'
	'SHA_StorageSense' = 'StorageSense component ETW tracing'
	'SHA_StorageReplica' = 'Storage replica component ETW tracing'
	'SHA_StorageSpace' = 'Storage space component ETW tracing'
	'SHA_Storport' = 'Storport component ETW tracing'
	'SHA_Storsvc' = 'Storsvc component ETW tracing'
	'SHA_USB' = 'USB component ETW tracing'
	'SHA_VDS' = 'Virtual Disk Service (VDS) component ETW tracing'
	'SHA_VHDMP' = 'Virtual disk and VHDMP driver component ETW tracing'
	'SHA_VmConfig' = 'SHA_ Virtual Machine Config component ETW tracing'
	'SHA_VML' = 'SHA_ Virtual Machine LiveMigration (VML) component ETW tracing; use -Mode verbose to restart the Hyper-V service and get FRUTI log'
	'SHA_VMM' = 'SHA_ Virtual Machine Manager (VMM) component ETW tracing'
	'SHA_VSS' = 'VSS component ETW tracing'
	'SHA_WSB' = 'Windows Server Backup (WSB) component ETW tracing'
#endregion ----- SHA POD description -----

#region ----- Sharepoint SPS POD description -----
	'SPS_ULS' = 'Sharepoint ULS collection [-startTime "01/25/2023 11:30" -endTime "01/26/2023 14:30" [-Servers "server1","server2"]] | [-Mode <Medium|Verbose|VerboseEx>] [-Merge]'
#endregion ----- INT POD description -----

#region ----- UEX POD description -----
	'UEX_Alarm' = 'Deprecated: Please use PRF_Alarm tracing'
	'UEX_AppCompat' = 'AppCompat and UAC component ETW tracing'
	'UEX_AppID' = 'AppID component ETW tracing'
	'UEX_AppV' = 'App-V tracing (Application Virtualization) component ETW tracing'
	'UEX_AppX' = 'Deprecated: Please use PRF_AppX tracing'
	'UEX_Auth' = 'Authentication component ETW tracing'
	'UEX_AVDActivation' = 'MSRD: AVD Core + Activation data collection + Diagnostics report'
	'UEX_AVDCore' = 'MSRD: AVD Core data collection + Diagnostics report'
	'UEX_AVDDiag' = 'MSRD: AVD Diagnostics report only'
	'UEX_AVDHCI' = 'MSRD: AVD Core + Azure Stack HCI data collection + Diagnostics report'
	'UEX_AVDIME' = 'MSRD: AVD Core + IME data collection + Diagnostics report'
	'UEX_AVDMSIXAA' = 'MSRD: AVD Core + MSIX App Attach data collection + Diagnostics report'
	'UEX_AVDMSRA' = 'MSRD: AVD Core + Remote Assistance data collection + Diagnostics report'
	'UEX_AVDProfiles' = 'MSRD: AVD Core + Profiles data collection + Diagnostics report'
	'UEX_AVDSCard' = 'MSRD: AVD Core + Smart Card data collection + Diagnostics report'
	'UEX_AVDTeams' = 'MSRD: AVD Core + Teams data collection + Diagnostics report'
	'UEX_Calc' = 'Deprecated: Please use PRF_Calc tracing'
	'UEX_Camera' = 'Deprecated: Please use PRF_Camera tracing'
	'UEX_CldFlt' = 'cldflt (driver for clould file) component ETW tracing'
	'UEX_ClipBoard' = 'Deprecated: Please use PRF_ClipBoard tracing'
	'UEX_CloudSync' = 'CloudSync component ETW tracing'
	'UEX_COM' = 'COM/DCOM/WinRT/PRC component ETW tracing. -EnableCOMDebug will enable further debug logging'
	'UEX_ContactSupport' = 'ContactSupport app component ETW tracing'
	'UEX_Cortana' = 'Deprecated: Please use PRF_Cortana tracing'
	'UEX_CRYPT' = 'Crypt component ETW tracing'
	'UEX_DeviceStore' = 'Device Store component ETW tracing'
	'UEX_DM' = 'Deprecated: Please use PRF_DM tracing'
	'UEX_DSC' = 'Collect DSC Data using script DSC-Collect.ps1'
	'UEX_DWM' = 'Deprecated: Please use PRF_DWM tracing'
	'UEX_ESENT' = 'ESENT component ETW tracing'
	'UEX_EventLog' = 'EventLog component ETW tracing'
	'UEX_EVT' = 'Collect EventLog Data using script Evt-Collect.ps1'
	'UEX_Font' = 'Deprecated: Please use PRF_Font tracing'
	'UEX_FSLogix' = 'FSLogix component ETW tracing'
	'UEX_Fusion' = 'Collect Fusion Logs'
	'UEX_IME' = 'Deprecated: Please use PRF_IME tracing'
	'UEX_ImmersiveUI' = 'Deprecated: Please use PRF_ImmersiveUI tracing'
	'UEX_LicenseManager' = 'License manager component ETW tracing'
	'UEX_Logon' = 'Winlogon/LogonUI/Credential provider/LockApp/AssignedAccess component ETW tracing'
	'UEX_LSA' = 'Lsass component ETW tracing'
	'UEX_MDAG' = 'MDAG components ETW tracing'
	'UEX_Media' = 'Deprecated: Please use PRF_Media tracing'
	'UEX_MMC' = 'Multimedia Class (MMC) component ETW tracing'
	'UEX_MMCSS' = 'Multimedia Class Scheduler Service (MMCSS) component ETW tracing'
	'UEX_MSRA' = 'Remote Assistance (MSRA) component ETW tracing'
	'UEX_Nls' = 'Deprecated: Please use PRF_Nls tracing'
	'UEX_Photo' = 'Deprecated: Please use PRF_Photo tracing'
	'UEX_PowerShell' = 'PowerShell component ETW tracing, Configuration collect'
	'UEX_Print' = 'Print component ETW tracing (PrintTrace.cmd)'
	'UEX_PrintEx' = 'Collect Print tracing using script Print-Collect.ps1'
	'UEX_QuickAssist' = 'QuickAssist app component ETW tracing'
	'UEX_RDS' = 'RDS component ETW tracing'
	'UEX_RDWebRTC' = 'RD Web RTC component ETW tracing'
	'UEX_RestartManager' = 'Restart Manager component ETW tracing'
	'UEX_Sched' = 'Task Scheduler'
	'UEX_Search' = 'Deprecated: Please use PRF_Search tracing'
	'UEX_TSched' = 'Collect Task Scheduler Data using script Sched-Collect.ps1'
	'UEX_SCM' = 'Deprecated: Please use PRF_SCM component ETW tracing'
	'UEX_ServerManager' = 'Server manager(ServerManager.exe) component ETW tracing'
	'UEX_Shell' = 'Deprecated: Please use PRF_Shell tracing'
	'UEX_Shutdown' = 'Deprecated: Please use PRF_Shutdown tracing'
	'UEX_Speech' = 'Deprecated: Please use PRF_Speech tracing'
	'UEX_StartMenu' = 'Deprecated: Please use PRF_StartMenu tracing'
	'UEX_Store' = 'Deprecated: Please use PRF_Store tracing'
	'UEX_SystemSettings' = 'Deprecated: Please use PRF_SystemSettings tracing'
	'UEX_Telemetry' = 'Telemetry components ETW tracing'
	'UEX_Task' = 'Task schedure/UBPM component ETW tracing'
	'UEX_UEV' = 'UE-V component ETW tracing'
	'UEX_UserDataAccess' = 'UserDataAccess component ETW tracing'
	'UEX_VAN' = 'View Available Network component ETW tracing'
	'UEX_WER' = 'Windows Error Reporting component ETW tracing'
	'UEX_Win32k' = 'Win32k component ETW tracing'
	'UEX_WinRM' = 'Windows Remote Management (WinRM) component ETW tracing'
	'UEX_WMI' = 'Windows Management Instrumentation (WMI winmgmt) component ETW tracing. This does not contain WMI provider trace.' # This is going to be decommissioned
	'UEX_WMIBase' = 'Windows Management Instrumentation (WMI winmgmt) component ETW tracing. This is just basic tracing. Optional comma separated list: [-WMIProvList <[Cluster],[Storage],[DCOM],[RPC],[MDM],[Perf],[RDMS],[RDSPub]>]'
	'UEX_WMIAdvanced' = 'Advanced Windows Management Instrumentation (WMI winmgmt) component ETW tracing. Optional comma separated list: [-WMIProvList <[Cluster],[Storage],[DCOM],[RPC],[MDM],[Perf],[RDMS],[RDSPub]>]'
	'UEX_WMIActivity' = 'Deprecated: Please use UEX_WMIBase instead'
	'UEX_WMIBridge' = 'Deprecated: Please use -UEX_WMIBase or -UEX_WMIAdvanced -WMIProvList MDM instead'
	'UEX_WPN' = 'Windows Platform Notification (WPN) component ETW tracing'
	'UEX_WSC' = 'Windows Security Center (WSC) component ETW tracing'
	'UEX_WVD' = 'Windows Virtual Desktop (WVD/AVD) component ETW tracing'
	'UEX_XAML' = 'Deprecated: Please use PRF_XAML tracing'

#endregion ----- UEX POD description -----

#region ----- DEV POD description -----
	'DEV_TEST1' = 'DEV TEST1 component component ETW tracing'
	'DEV_TEST2' = 'DEV TEST2 component component ETW tracing'
	'DEV_TEST3' = 'DEV TEST3 component component ETW tracing'
	'DEV_TEST3Full' = 'DEV TEST3Full component component ETW tracing'
	'DEV_TEST4' = 'DEV TEST4 component component ETW tracing'
	'DEV_TEST5' = 'DEV TEST5 component component ETW tracing'
#endregion ----- DEV POD description -----
#region ----- WIN POD / CustomETL description -----
	'WIN_kernel' = 'Windows Kernel Trace (NT Kernel Logger)'
	'WIN_CustomETL' = 'user provided component ETW tracing; -CustomETL holds the list of comma separated, single quoted {GUID} and/or Provider-Names'
#endregion ----- WIN POD / CustomETL description -----

}
#endregion ### All POD descriptions

# Type 2 Command list (Commands that take arg with "Start|Stop|Both")
$Type2CommandSwitches = @{
	'GPresult' = '<Start|Stop|Both> Run GPresult and collect auditing and security info at Start|Stop|Both time(s) of repro'
	'Handle' = '<Start|Stop|Both> Collect SysInternals Handle output using Handle.exe at Start|Stop|Both time(s) of repro'
	'LiveKD' = '<Start|Stop|Both> Capture (SysInternals or built-in) live kernel dump at Start|Stop|Both time(s) of repro'
	'PoolMon' = '<Start|Stop|Both> Collect pool memory usage using PoolMon.exe at Start|Stop|Both of time(s) repro'
}

# This is used only for help message
$CommandSwitches = @{
	'Fiddler' = 'Collect Fiddler trace; requires Fiddler to be installed'
	'Netsh' = 'Netsh (Packet capture)'
	'NetshScenario' = 'Netsh client scenario trace + Packet capture'
	'PerfMon' = 'Performance Monitor with short interval'
	'PerfMonLong' = 'Performance Monitor with long interval'
	'PerfTCP' = 'Performance for TCP protocol, uses ntttcp.exe and requires tss command run on both source and dest machines'
	'PerfSMB' = 'Performance for SMB protocol, uses Robocopy and requires tss command run on client, with write access to a specified target share'
	'PktMon' = 'PktMon (Packet Monitor) for RS5+'
	'ProcDump' = 'Capture user dump (SysInternals ProcDump.exe)'
	'ProcMon' = 'Process Monitor (SysInternals Procmon.exe)'
	'PSR' = 'Problem Steps Recorder'
	'Radar' = 'Radar leak diag (rdrleakdiag.exe)'
	'RASdiag' = 'Netsh (RAS)'
	'SDP' = 'Collect speciality Support Diagnostic Platform data'
	'SysMon' = 'System Monitor (SysInternals SysMon.exe) [def: sysmonConfig.xml in \config folder]'
	'TTD' = 'Collect Time Travel Debugging (TTD) (TTT/iDNA); note: TSS_TTD.zip is only needed for downlevel OS prior to Win10/Server 2019 or on Server CORE'
	'Video' = 'Capture Video, use VLC Media Player for viewing; be sure that your Display settings uses a standard Display resolution'
	'WFPdiag' = 'Netsh (wfp)'
	'WPR' = 'Windows Performance Recorder (wpr.exe) - supported with Win2012R2+'
	'WireShark' = 'WireShark (Packet capture), requires WireShark to be installed'
	'Xperf' = 'Alternate command-line tool for WPR (Windows Performance Recorder)'
	'xray' = 'Run xray Diagnostics to scan for known issues'
}
	#'Crash' = 'Force Memory dump using NotMyFault; specify Full|Kernel'
$CommandSwitches += $Type2CommandSwitches	# | Sort-Object

# This list is used for LiteMode, as it does not ship with following executables
$ExternalCommandList = @{
	'Crash' = 'NotMyfaultc.exe'
	'ExecAction' = 'ExecAction.exe' #=Fiddler
	'Handle' = 'Handle.exe'
	'LiveKD' = 'LiveKD.exe'	# note: there is also a PS built-in command in modern OS
	'PoolMon' = 'PoolMon.exe'
	'ProcDump' = 'ProcDump.exe'
	'ProcMon' = 'Procmon.exe'
	'SysMon' = 'SysMon.exe'
	'Video' = 'RecorderCommandLine.exe'
	'WireShark' = "$env:ProgramFiles\Wireshark\dumpcap.exe"
	'Xperf' = 'Xperf.exe'
}
#	'TTD' = 'TTTracer.exe'
#	'PktMon' = 'PktMon.exe'
#	'Radar' = 'rdrleakdiag.exe'
If (($global:OSVersion.Build -lt 17763) -or $global:IsServerCore){
	$ExternalCommandList += @{
			'TTD' = 'TTTracer.exe'	# note: applies to downlevel OS and SrvCore; Win10 RS5+ ships built-in TTD
	}
}

# This is used only for help message
$SDPspecialties = @{
	'Apps' = 'Inbox-Apps-Diagnostic Report'
	'CRMbase' = 'Dynamics CRM Server Baseline Data Collection Diagnostic'
	'Net' = 'Network Report'
	'DA' = 'Direct Access Report'
	'Dom' = 'Domains/Active Directory Report'
	'DPM' = 'Data Protection Manager (DPM) Report'
	'CTS' = 'CTS Report'
	'Print' = 'Printing Report'
	'HyperV' = 'Hyper-V Report'
	'Setup' = 'Setup Report'
	'Perf' = 'Performance Report'
	'Cluster' = 'Windows Failover Cluster Diagnostic Report'
	'S2D' = 'S2D Report'
	'SCCM' = 'SCCM Report'
	'RDS' = 'Remote Desktop Services'
	'SQLbase' = 'SQL Basic Report'
	'SQLconn' = 'SQL Connectivity Report'
	'SQLmsdtc' = 'SQL msdtc Report'
	'SQLsetup' = 'SQL setup Report'
	'SUVP' = 'SUVP Report'
	'VSS' = 'VSS Report'
	'mini' = 'minimal SDP'
	'nano' = 'nano SDP'
	'Repro' = 'Repro (for testing)'
	'RFL' = 'Recommended Fix List (RFL)'
	'All' = 'All Technologies Report'
}

# This is used only for help message
$WPRprofiles = @{
	'BootGeneral' = 'all generic events (only GeneralProfile), may be used with -StartAutologger, you can add profiles as necessary with -WPROptions.'
	'CPU' = 'events on CPU usage (GeneralProfile+CPU)'
	'Device' = 'events related to device (CPU+FileIO+Minifilter+Power+Registry)'
	'General' = 'all generic events (GeneralProfile+CPU+DiskIO+FileIO+Network+Handle+Registry+Minifilter, context switches for wait analysis)'
	'Graphic' = 'events related to graphic (GeneralProfile+CPU+GPU+DesktopComposition+Power+Registry+Video)'
	'Memory' = 'events on memory allocation (GeneralProfile+VirtualAllocation)'
	'Network' = 'events on networking (GeneralProfile+CPU+DiskIO+FileIO+Minifilter+Network)'
	'Registry' = 'events on registry I/O such as registry access, creation and deletion (GeneralProfile+CPU+Registry)'
	'SQL' = 'events on memory allocation and networking (GeneralProfile+CPU+Minifilter+Network+VirtualAllocation)'
	'Storage' = 'events on Disk I/O (GeneralProfile+CPU+DiskIO+FileIO+Minifilter+Network)'
	'Wait' = 'events on CPU usage and context switch (GeneralProfile+CPU+DiskIO+FileIO+Minifilter+Network)'
	'Xaml' = 'events related to Xaml (GeneralProfile+CPU+GPU+DesktopComposition+XAMLActivity+XAMLAppResponsiveness+Video)'
	'VSOD_CPU' = 'events on CPU usage, Disk I/O, File I/O (GeneralProfile+CPU+DiskIO+FileIO)' 
	'VSOD_Leak' = 'events on CPU usage, Heap, VirtualAllocation (GeneralProfile+CPU+Heap+VirtualAllocation)' 
}

# This is used only for help message
$XperfProfiles = @{
	'CPU' = "-on PROC_THREAD+Latency+LOADER+Profile+interrupt+dpc+DISPATCHER+CSwitch+Power -stackWalk CSwitch+Profile+ReadyThread <Params>"
	'Disk' = "-on PROC_THREAD+LOADER+Profile+interrupt+dpc+DISK_IO+DISK_IO_INIT+filename+FILE_IO+FILE_IO_INIT+flt_io_init+flt_io+flt_fastio+flt_io_failure -stackwalk profile+DiskReadInit+DiskWriteInit+DiskFlushInit+FileRead+FileWrite+FileCreate+FileDelete+minifilterpreopinit+minifilterpostopinit <Params>"
	'General' = "-on Base+Latency+CSwitch+PROC_THREAD+LOADER+Profile+interrupt+dpc+DISPATCHER+NETWORKTRACE+FileIO+Power+DISK_IO+DISK_IO_INIT+filename+FILE_IO+FILE_IO_INIT+flt_io_init+flt_io+flt_fastio+flt_io_failure+VIRT_ALLOC+POOL+REGISTRY+DRIVERS -stackWalk CSwitch+Profile+ReadyThread+ThreadCreate+SyscallEnter+DiskReadInit+DiskWriteInit+DiskFlushInit+FileRead+FileWrite+FileCreate+FileDelete+minifilterpreopinit+minifilterpostopinit+PoolAlloc+PoolAllocSession+PoolFree+PoolFreeSession+VirtualAlloc+VirtualFree <Params>"
	'Leak' = "-on PROC_THREAD+LOADER+VIRT_ALLOC -stackwalk VirtualAlloc+VirtualFree <Params> -start HeapSession -heap -pids <PID> -stackwalk HeapAlloc+HeapRealloc"
	'Memory' = "-on Base+CSwitch+POOL -stackwalk Profile+PoolAlloc+PoolAllocSession+PoolFree+PoolFreeSession+VirtualAlloc <Params>"
	'Network' = "-on Base+Latency+DISPATCHER+NETWORKTRACE+FileIO+DRIVERS -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile+SyscallEnter <Params>"
	'Pool' = "-on Base+CSwitch+VIRT_ALLOC+POOL -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession+VirtualAlloc -PoolTag <PoolTag> <Params>"
	'PoolNPP' = "-on Base+CSwitch+LOADER+VIRT_ALLOC+POOL+PROC_THREAD -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession+VirtualAlloc -PoolTag <PoolTag> <Params>"
	'Registry' = "-on Base+REGISTRY+PROC_THREAD+NETWORKTRACE -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile+SyscallEnter <Params>"
	'SBSL' = "-on Base+Latency+DISPATCHER+REGISTRY+NETWORKTRACE+FileIO -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile -BufferSize 1024 -start UserTrace -on `"Microsoft-Windows-Shell-Core+Microsoft-Windows-Wininit+Microsoft-Windows-Folder Redirection+Microsoft-Windows-User Profiles Service+Microsoft-Windows-GroupPolicy+Microsoft-Windows-Winlogon+Microsoft-Windows-Security-Kerberos+Microsoft-Windows-User Profiles General+e5ba83f6-07d0-46b1-8bc7-7e669a1d31dc+63b530f8-29c9-4880-a5b4-b8179096e7b8+2f07e2ee-15db-40f1-90ef-9d7ba282188a`" <Params>"
	'SBSLboot' = "-on Base+Latency+DISPATCHER+REGISTRY+NETWORKTRACE+FileIO -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile <Params>"
	'SMB2' = "-on Base+Latency+DISPATCHER+NETWORKTRACE+FILE_IO+FILE_IO_INIT+DRIVERS <Params> -stackwalk Profile+CSwitch+ReadyThread -start SMB2 -on d3bce2d2-92c9-44c7-befe-a27a96d413e9:::'stack'"
}

$NoCommandOptions = @{
	'noCrash' = 'do not run Crash after reboot again when using .\TSS.ps1 -stop -noCrash'
	'noFiddler' = 'do not start Fiddler'
	'noGPresult' = 'do not run GPresult, used to override setting in preconfigured TS scenarios'
	'noHandle' = 'do not run Handle at start,stop or both'
	'noLiveKD' = 'do not capture LiveKD (live kernel dump)'
	'noNetsh' = 'do not run NetSh, which might be preconfigured in some TS scenarios'
	'noPerfMon' = 'do not run PerfMon, which might be preconfigured in some TS scenarios'
	'noPktMon' = 'do not start PktMon'
	'noPoolMon' = 'do not run PoolMon at start and stop'
	'noProcmon' = 'do not run Procmon, the Procmon is an UI tool. Therefore this option is helpful if you want to prevent UI tool from showing up like a case on server core'
	'noPSR' = 'do not run PSR, like same as -noProcmon and -noVideo, this is helpful for the scenario where you dont want to show any UI tools'
	'noRadar' = 'do not run Radar leak diag (rdrleakdiag.exe)'
	'noRASdiag' = 'do not start RASdiag'
	'noSDP' = 'do not gather SDP report, i.e. when using script in scheduled tasks'
	'noSysMon' = 'do not start SysMon'
	'noTTD' = 'do not start Time Travel Debugging (TTD)'
	'noVideo' = 'do not run Video, like same as -noProcmon and -noPSR, this is helpful for the scenario where you dont want to show any UI tools'
	'noWFPdiag' = 'do not start WFPdiag'
	'noWPR' = 'do not run WPR, which might be preconfigured in some TS scenarios'
	'noWireShark' = 'do not start WireShark'
	'noXperf' = 'do not run Xperf, which might be preconfigured in some TS scenarios'
	'noXray' = 'do not start xray diagnostics troubleshooter, but use xray to check for missing cumulative updates'
}
$NoControlOptions = @{
	'noAdminChk' = 'skip Admin check, which verifies elevated Admin rights'
	'noArgCheck' = 'do not validate input command-line arguments'
	'noAsk' = 'do not ask about good/failing scenario text input before compressing data'
	'noBasiclog' = 'do not collect mini basic log that is collected by default'
	'noClearCache' = 'do not clear DNS,NetBios,Kerberos,DFS chaches at start'
	'noEventConvert' = 'do not convert Eventlogs to .CSV or .TXT format'
	'noExpire' = 'allow TSS script to run even if its version is older than 30 days'
	'noHang' = 'do not wait forever when data collection seems to hang '
	'noISECheck' = 'allows TSS script to run in ISE environmet; noISECheck should be used ONLY during development; do NOT use noISECheck on production machines'
	'noPacket' = 'prevent packets from being captured with Netsh, only ETW traces in the ScenarioName will be captured'
	'noPrereqC' = 'do not run prerequisite check'
	'noQuickEdit' = 'do not try to disable Quick Edit Mode'
	'noRecording' = 'do not ask about consent for performing PSR or Video recording, and do not start these recordings'
	'noRepro' = 'skip stage waiting for Reproduce the issue'
	'noRestart' = 'do not restart associated Windows service'
	'noSound' = 'do not play attention sound'
	'noUpdate' = 'do not update with latest online TSS version on cesdiagtools.blob.core.windows.net, no AutoUpdate'
	'noVersionChk' = 'skip online TSS version check'
	'noZip' = 'do not compress/zip trace data'
}
$NoOptions = $NoCommandOptions + $NoControlOptions 

# Create global variables for noSwitches
$NoCommandOptionsList = ($NoCommandOptions.Keys | Sort-Object)
$NoControlOptionsList = ($NoControlOptions.Keys | Sort-Object)
$noOptionsList = ($NoOptions.Keys | Sort-Object)

#region --- ControlSwitches
$ControlSwitchesList = @{
	'AcceptEula' = 'do not ask at first run to accept Disclaimer (useful for -RemoteRun execution), but please read the EULA once!'
	'AddDescription' = 'will ask user to add a brief description of the repro issue. The name of resulting zip file will include such description.'
	'Assist' = 'Accessibility Mode'
	'BasicLog' = 'collect full basic log (by default mini basic log is always collected).'
	'BufferLength' = '<N> - PerfTCP: specify an Int value for length of buffer in kilobytes (default is 128K)'
	'CollectComponentLog' = 'use with -Scenario. By default, component collect functions are not called in case of -Scenario trace. This switch enables the collect functions to be called.'
	'CollectDump' = 'collect system dump (memory.dmp) after stopping all traces. -CollectDump can be used with -Start and -Stop.'
	'CollectEventLog' = '<Eventlog[]> collect specified event logs. Wild card * can be used for the event log name.'
	'Crash' = 'trigger system crash (memory dump) at stop of repro, or after all events are signaled in case used with -WaitEvent, Caution: this switch will force a memory.dump and system will reboot, open files will not be saved.'
	'CrashMode' = '<Full|Kernel> - choose the Memory.dmp dump type (TSS will use \BINx64\kdbgctrl.exe). For dedicated dump files, see Kb4475681 Batch file for configuring Dedicated memory dump settings.'
	'CustomETL' = '<custom ETL trace provider(s)> - add a comma separated list of single quoted {GUID} and/or Provider-Name(s).'
	'DebugMode' = 'run TSS script with debug mode; useful when troubleshooting TSS itself.'
	'VerboseMode' = 'show more verbose/informational output while processing TSS functions'
	'Discard' = 'used to discard a collected dataset at phase -Stop. *Stop- or *Collect-functions will not run. xray and psSDP will be skipped.'
	'Duration' = '<N> - PerfTCP: specify an Int value for number of seconds for each test (default is 60 seconds)'
	'EnableCOMDebug' = 'used by UEX module to turn on COM debug mode'
	'ETWlevel' = '<Info|Warning|Error> - Event Trace Level, default =0xFF'
	'ETWflags' = '<hexNr> - Event Trace Flags for -WIN_kernel trace, default =0x0000000000000001, see Logman query providers "Windows Kernel Trace"'
	'EtlOptions' = '<circular|newfile>:<ETLMaxSizeMB>:<ETLNumberToKeep>:<ETLFileMax> - set options passed to logman command, default for circular ETLMaxSize=1024, default for newfile ETLMaxSize=512, -StartAutologger only supports -ETLOptions circular:<ETLMaxSize>:<ETLNumberToKeep>:<ETLFileMax>, but ETLNumberToKeep wont be honored'
	'EvtDaysBack' = '<N> - Convert Eventlogs only for last N days; default: 30 days; also applies to SDP report; Note: Security Eventlog will be skipped'
	'InputlogPath' = '<path to log folder for diagnostic> - used with -StartDiag; specify a log path to be diagnosed'
	'LogFolderPath' = '<Drive:\path to log folder> - use a different log folder for resulting output data, instead of default location (C:\MS_DATA); useful when C: has low free disk-space'
	'MaxEvents' = '<N> - will investigate last N number of events with same EventID (default=1) for -WaitEvent Evt:<EventID>:<Eventlog Name>'
	'Merge' = 'Merge mode for SPS Unified Logging Service (ULS)'
	'Mini' = 'collect only minimal data, skip noPSR, noSDP, noVideo, noXray, noZip, noBasicLog'
	'Mode' = '<Basic|Medium|Advanced|Full|Verbose|VerboseEx|Hang|Restart|Swarm|Kube|GetFarmdata|Permission|traceMS> - [for data collection] run script in Basic, Medium, Advanced, Full or Verbose(Ex) mode. Restart will restart associated service.'
	'NumFiles' = 'Number of files to use in various tools. (Ex: PerfSMB tests)'
	'ProcmonAltitude' = '<N> - specify an Int value for ProcmonAltitude (default=385200), use `fltmc instances` to show filter driver Altitude, use a lower number than the suspected specific driver; value 45100 will show you virtually everything.'
	'PerfMonCNF' = '<[[hh:]mm:]ss> - Create a New File when the specified time has elapsed or when the max size <PerfMonMaxMB> is exceeded.'
	'PerfMonMaxMB' = '<N> - specify an Int value for maximum Perfmon Log size in MB, default=2048'
	'PerfSMBFileSize' = '<size>, where File <size> is <n>[K|M|G|b], Default 1M'
	'PerfTCPAddr' = '<IP Address>'
	'RemoteRun' = 'use when TSS is being executed on a remote host, i.e. via psExec or in PS Azure Serial Console, or with PS remoting; this will inhibit PSR, Video recording, starting TssClock and opening Explorer with final results. In such case also consider -AcceptEula'
	'RemoteHosts' = '<host01,host02> - specify comma separated list of remote hostnames or FQDN or IP-addr, which will be signaled after a stop condition is met.'
	'RemoteLogFolder' = '<\\Server01\share> - optional remote shared folder name where resulting log files of all remote hosts should be copied to.'
	'RemoveAutoLogger' = 'Delete AutoLogger settings. This option can be used when AutoLogger is enabled, but you want to discard the setting.'
	'Servers' = '<host01,host02> - specify comma separated list of server names'
	'SkipSDPList' = '<noNetadapters,skipBPA,skipHang,skipNetview,skipSddc,skipTS,skipHVreplica,skipCsvSMB> - avoid some SDP steps by using -SkipSDPList comma separated list of parameters'
    'WMIProvList' = '<Storage,Cluster,DCOM,RPC,MDM,Perf,RDMS,RDSPub,SCM> add additional providers in comma separated list'
	'Status' = 'show Status of TSS. You can show what traces/tools are running and also this shows what AutoLoggers are enabled on the system.' 
	'StartTime' = '<date time> - Example: "01/15/2023 20:30"'
	'EndTime' = '<date time> - Example: "01/15/2023 22:30"'
	'StopWaitTimeInSec' = '<N> - time to wait in seconds after all -WaitEvent events are signaled, in case you want to wait for an additional amount of seconds before stopping all traces.'
	'HighCPUTimeInSec' = '<N> - time duration in seconds to probe for high CPU (default=10 sec)'
	'HighMemUsageInSec' = '<N> - time duration in seconds to probe for high Memory consumption (default=10 sec)'
	'CheckIntInSec' = '<N> - poll interval in seconds to wait until testing again for a stop trigger condition.'
	'Update' = 'online update of TSS scripts' 
	'Version' = 'show current version of TSS and *.psm1 modules'
	'WaitEvent' = 'monitor for the specified event/stop-trigger and if it is signaled, traces will be stopped automatically.'
	'v' = 'used in ADS_Auth for more verbose logging'
	'containerId' = '<containerID> - used in ADS_Auth for Container tracing'
	'slowlogon' = 'used in ADS_Auth for slow logon WPR tracing'
}
$DataCollectionParameters = @(
	'Start',
	'StartAutoLogger',
	'StartDiag'
	'StartNoWait'
	'Stop'
	'CollectLog'
	'SDP'
	'xray'
	'CollectEventLog'
	'RemoveAutoLogger'
)
$ControlSwitches = @(
	'beta'
	'CommonTask'
	'Compress'
	'CreateBatFile'
	'CustomParams'
	'Delete'
	'DefenderDurInMin'
	'ExternalScript'
	'Help'
	'List'
	'ListSupportedCommands'
	'ListSupportedControls'
	'ListSupportedDiag'
	'ListSupportedLog'
	'ListSupportedNetshScenario'
	'ListSupportedNoOptions'
	'ListSupportedPerfCounter'
	'ListSupportedScenarioTrace'
	'ListSupportedSDP'
	'ListSupportedWPRScenario'
	'ListSupportedXperfProfile'
	'NetshOptions'
	'NetshMaxSizeMB'
	'NewSession'
	'PerfIntervalSec'
	'PerfLongIntervalMin'
	'PerfMonMaxMB'
	'ProcDumpOption'
	'ProcDumpInterval'
	'ProcDumpAppCrash'
	'ProcmonFilter'
	'ProcmonPath'
	'Scenario'
	'Set'
	'Unset'
	'SkipPdbGen'
	'TTDMode'
	'TTDMaxFile'
	'TTDOptions'
	'TTDPath'
	'WPROptions'
	'XperfMaxFileMB'
	'XperfOptions'
	'XperfPIDs'
	'XperfTag'
)
$ControlSwitches += $DataCollectionParameters
$ControlSwitches += ($ControlSwitchesList.Keys) + $noOptionsList
#endregion --- ControlSwitches

# Log size definition for commands(Not ETW)
# Some of data will be updated in CalculateLogSize().
$LogSizeInGB = @{
	'Crash' = 8
	'Fiddler' = 2
	'Perf' = 1
	'Procmon' = 3
	'Video' = 1
	'PSR' = 0.1
	'Netsh' = ($NetshLogSize / 1024)
	'NetshScenario' = ($NetshLogSize / 1024) + 1	#we# was '+ 4' -but, Why +4?
	'WFPdiag' = 16   # 16 traces x 1GB
	'RASdiag' = 14   # 14 traces x 1GB
	'PktMon' = 2
	'SysMon' = 1
	'WPR' = 10		# rough estimate
	'Xperf' =  10
	'TTD' =  5
	'LiveKD' = 3
	'ProcDump' = 1
	'WireShark' = 2
	'SDP' = 0.2
	'xray' = 0.1
	'Radar' = 0.5
}

$ETWSessionCountForCommand = @{
	'Netsh' = '2'			# NetTrace-XXX-XXX x 1, NetCfgTrace x 1
	'NetshScenario' = '2'	# NetTrace-XXX-XXX x 1, NetCfgTrace x 1
	'RASdiag' = '14'		# RASdiag spawns 14 ETW sessions
	'WFPdiag' = '1'			# wfpdiag x 1
	'PktMon' = '1'			# PktMon x 1
	'ProcMon' = '1'			# PROCMON TRACE x 1
	'WPR' = '1'				# WPR_initiated_WprApp_WPR System Collector x 1, WPR_initiated_WprApp_WPR Event Collector x 1
	'xPerf' = '1'			# NT Kernel Logger x 1
}

$StartPriority = @{
	'LiveKD' = 1
	'Video' = 1
	'PSR' = 1
	'GPresult' = 2
	'Handle' = 2
	'PoolMon' = 2
	'ProcDump' = 2
	'SysMon' = 2
	'ETW' = 5
	'Perf' = 6
	'WPR' = 6
	'Xperf' = 6
	'RASdiag' = 6
	'WireShark' = 6
	'Fiddler' = 6
	'Radar' = 6
	'Netsh' = 7
	'PktMon' = 7
	'WFPdiag' = 8
	'Procmon' = 8
	'TTD' = 10
	'PerfTCP' = 99
	'PerfSMB' = 99
}

$StopPriority = @{
	'PerfSMB' = 1
	'PerfTCP' = 1
	'TTD' = 1
	'Procmon' = 3
	'WFPdiag' = 3
	'Netsh' = 4
	'WireShark' = 4
	'PktMon' = 4
	'Fiddler' = 4
	'RASdiag' = 5
	'WPR' = 5
	'Xperf' = 5
	'Perf' = 5
	'Radar' = 5
	'ETW' = 6
	'SysMon' = 9
	'ProcDump' = 9
	'GPresult' = 9
	'Handle' = 9
	'PoolMon' = 9
	'PSR' = 10
	'Video' = 10
	'LiveKD' = 10
}

# Used for -Set and -Unset
#ToDo: add CrashMode
$SupportedSetOptions = [Ordered]@{
	'WER' = 'Enable WER (Windows Error Reporting) setting'
}

$LogTypes = @(
	'ETW'
	'Command'
	'Perf'
	'Custom'
)

$TraceStatus = @{
	'Success' = 0
	'Running' = 1
	'AutoLoggerRunning' = 2
	'Started' = 3
	'Stopped' = 4
	'ErrorInStart' = 5
	'ErrorInStop' = 6
	'NotSupported' = 7
	'NoStopFunction' = 8
}

$global:LogLevel = @{
	'Normal' = 0
	'Info' = 1
	'Warning' = 2
	'Error' = 3
	'Debug' = 4
	'ErrorLogFileOnly' = 5
	'WarnLogFileOnly' = 6
	'InfoLogFileOnly' = 7
}


#region common global functions used by POD modules
#------------------------------------------------------------------
#							 FUNCTIONS 
#------------------------------------------------------------------
Function global:EnterFunc([String]$FunctionName){
	LogMessage $LogLevel.Debug "---> Enter $FunctionName" "Cyan"
}

Function global:EndFunc([String]$FunctionName){
	LogMessage $LogLevel.Debug "<--- End $FunctionName" "Cyan"
}

Function global:LogMessage{
	Param(
		[ValidateNotNullOrEmpty()]
		[Int]$Level,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[ValidateNotNullOrEmpty()]
		[String]$Color,
		[Switch]$LogMsg=$False,
		[Switch]$noDate
	)

	If($Null -eq $Level){
		$Level = $LogLevel.Normal
	}

	If(($Level -eq $LogLevel.Debug) -and !($DebugMode.IsPresent)){
	   Return # Early return. This is LogMessage $LogLevel.Debug but DebugMode switch is not set.
	}

	Switch($Level){
		'0'{ # Normal
			$MessageColor = 'White'
			$LogConsole = $True
			$LogMessage = $Message
		}
		'1'{ # Info / Normal console message
			$MessageColor = 'Yellow'
			$LogConsole = $True
			$LogMessage = $Message  # Simple message
		}
		'2'{ # Warning
			$Levelstr = 'WARNING'
			$MessageColor = 'Magenta'
			$LogConsole = $True
		}
		'3'{ # Error
			$Levelstr = 'ERROR'
			$MessageColor = 'Red'
			$LogConsole = $True
		}
		'4'{ # Debug
			$Levelstr = 'DEBUG'
			$MessageColor = 'Green'
			If($DebugMode.IsPresent){
				$LogConsole = $True
			}Else{
				$LogConsole = $False
			}
		}
		'5'{ # ErrorLogFileOnly
			$Levelstr = 'ERROR'
			$LogConsole = $False
		}
		'6'{ # WarnLogFileOnly
			$Levelstr = 'WARNING'
			$LogConsole = $False
		}
		'7'{ # InfoLogFileOnly / Normal LogFile message
			$Levelstr = 'INFO'
			$LogMessage = $Message  # Simple message
			$LogConsole = $False
		}
	}

	# If color is specifed, overwrite it.
	If($Null -ne $Color -and $Color.Length -ne 0){
		$MessageColor = $Color
	}

	$Index = 1
	# In case of Warning/Error/Debug, add a function name and a line number to message.
	If($Level -eq $LogLevel.Warning -or $Level -eq $LogLevel.Error -or $Level -eq $LogLevel.Debug -or $Level -eq $LogLevel.ErrorLogFileOnly -or $Level -eq $LogLevel.WarnLogFileOnly -or $Level -eq $LogLevel.InfoLogFileOnly){
		$CallStack = Get-PSCallStack
		$CallerInfo = $CallStack[$Index]
		$2ndCallerInfo = $CallStack[$Index+1]
		$3rdCallerInfo = $CallStack[$Index+2]

		# LogMessage() is called from wrapper function like LogInfo() and EnterFunc(). In this case, we show caller of the wrapper function.
		If($CallerInfo.FunctionName -notlike "*LogException" -and ($CallerInfo.FunctionName -like "global:Log*" -or $CallerInfo.FunctionName -like "*EnterFunc" -or $CallerInfo.FunctionName -like "*EndFunc")){
			$CallerInfo = $2ndCallerInfo # Set actual function name calling LogInfo/LogWarn/LogError
			If($CallerInfo.FunctionName -like "*LogException"){
				$CallerInfo = $3rdCallerInfo
			}
		}
		$FuncName = $CallerInfo.FunctionName.Replace("global:","")
		If($FuncName -eq "<ScriptBlock>"){
			$FuncName = "Main"
		}

		# If this is from POD module, add the module name in front of the function name.
		If($CallerInfo.ScriptName -notlike "*$($global:ScriptName)"){ # ScriptName = 'TSS.ps1'
			$FuncName = (((Split-path $CallerInfo.ScriptName -leaf) -replace "TSSv2_","") + ":" + $FuncName)
		}
		$LogMessage = ((Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + ' [' + $FuncName + '(' + $CallerInfo.ScriptLineNumber + ')]'+ " $Levelstr" + ": " + $Message)
	}Else{
		if($noDate){
			$LogMessage = $Message
		}else{
			$LogMessage = (Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $Message
		}
		
	}

	If($LogConsole){ #we# may need additional check for '-and !(running in Azure serial Console)' ? (#675)
		Write-Host $LogMessage -ForegroundColor $MessageColor
	}

	# In case of error, warning, ErrorLogFileOnly, WarnLogFileOnly and InfoLogFileOnly, we log the message to error log file.
	If(![String]::IsNullOrEmpty($global:LogFolder) -and $LogMsg){
		If(!(Test-Path -Path $global:LogFolder)){
			FwCreateLogFolder $global:LogFolder
		}
		If($Null -ne $global:ErrorLogFile){
			If(!(Test-Path $global:ErrorLogFile)){
				New-Item $global:ErrorLogFile -type file -Force | Out-Null
			}
			$LogMessage | Out-File -Append $global:ErrorLogFile
		}Else{
			Write-Host "ErrorLogFile is not initalized."
		}
	}
}

Function global:LogInfo{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color,
		[Switch]$noDate
	)
	#if ($noDate) {[String]$noDateSwitch = "-noDate"}else{[String]$noDateSwitch = $Null}
	If([string]::IsNullOrEmpty($Color)){
		if ($noDate) {
			LogMessage $Loglevel.info $Message -noDate
		}else{
			LogMessage $Loglevel.info $Message
		}
	}Else{
		if ($noDate) {
			LogMessage $Loglevel.info $Message $Color -noDate
		}else{
			LogMessage $Loglevel.info $Message $Color
		}
		#_# Accessibility Mode -Assist
		if ($global:ParameterArray -Contains 'Assist') { Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak("$Message") }
	}
}

Function global:LogWarn{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.Warning $Message -LogMsg
	}Else{
		LogMessage $Loglevel.Warning $Message $Color -LogMsg
	}
}

Function global:LogError{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.Error $Message -LogMsg
	}Else{
		LogMessage $Loglevel.Error $Message $Color -LogMsg
	}
}

Function global:LogDebug{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.Debug $Message
	}Else{
		LogMessage $Loglevel.Debug $Message $Color
	}
}

Function global:LogInfoFile {
	#we# to write additional info to $global:ErrorLogFile
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] 	# color is just optional.
		[String]$Color,
		[Switch]$ShowMsg,			# write on-screen/transaction log
		[Switch]$noDate
	)
	
	#if ($noDate) {[String]$noDateSwitch = "-noDate"}else{[String]$noDateSwitch = $Null}
	# In case of -Status, we won't log message to log file to prevent log folder from being created.
	If($Status.IsPresent){
		Return # Early return 
	}
	If([string]::IsNullOrEmpty($Color)){
		if ($noDate) {
			LogMessage $Loglevel.InfoLogFileOnly $Message -LogMsg -noDate
		}else{
			LogMessage $Loglevel.InfoLogFileOnly $Message -LogMsg
		}
		If($ShowMsg -and $VerboseMode){
			if ($noDate) {
				LogMessage $Loglevel.info $Message -noDate
			}else{
				LogMessage $Loglevel.info $Message
			}
		}else{
			Write-Host '.' -NoNewline	#show some progress in PS window if logging is done only in Logfile
		}
	}Else{
		LogMessage $Loglevel.InfoLogFileOnly $Message $Color -LogMsg -noDate
		If($ShowMsg -and $VerboseMode){
			if ($noDate) {
				LogMessage $Loglevel.info $Message $Color -noDate
			}else{
				LogMessage $Loglevel.info $Message $Color
			}
		}else{
			Write-Host '.' -NoNewline	#show some progress in PS window if logging is done only in Logfile
		}
	}
}

Function global:LogWarnFile {
	#we# to write additional warning to $global:ErrorLogFile
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.WarnLogFileOnly $Message -LogMsg
	}Else{
		LogMessage $Loglevel.WarnLogFileOnly $Message $Color -LogMsg
	}
}

Function global:LogErrorFile {
	#we# to write additional error to $global:ErrorLogFile
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.ErrorLogFileOnly $Message -LogMsg
	}Else{
		LogMessage $Loglevel.ErrorLogFileOnly $Message $Color -LogMsg
	}
}

Function global:LogException{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.ErrorRecord]$ErrObj,
		[Bool]$fErrorLogFileOnly
	)
	$ErrorCode = "0x" + [Convert]::ToString($ErrObj.Exception.HResult,16)
	$ExternalException = [System.ComponentModel.Win32Exception]$ErrObj.Exception.HResult
	$ErrorMessage = $Message + "`n" `
		+ "Command/Function: " + $ErrObj.CategoryInfo.Activity + " failed with $ErrorCode => " + $ExternalException.Message + "`n" `
		+ $ErrObj.CategoryInfo.Reason + ": " + $ErrObj.Exception.Message + "`n" `
		+ "ScriptStack:" + "`n" `
		+ $ErrObj.ScriptStackTrace
	If($fErrorLogFileOnly){
		LogErrorFile $ErrorMessage
	}Else{
		LogError $ErrorMessage
	}
}

Function global:LogExceptionFile{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.ErrorRecord]$ErrObj
	)
	$ErrorCode = "0x" + [Convert]::ToString($ErrObj.Exception.HResult,16)
	$ExternalException = [System.ComponentModel.Win32Exception]$ErrObj.Exception.HResult
	$ErrorMessage = $Message + "`n" `
		+ "Command/Function: " + $ErrObj.CategoryInfo.Activity + " failed with $ErrorCode => " + $ExternalException.Message + "`n" `
		+ $ErrObj.CategoryInfo.Reason + ": " + $ErrObj.Exception.Message + "`n" `
		+ "ScriptStack:" + "`n" `
		+ $ErrObj.ScriptStackTrace
	LogErrorFile $ErrorMessage
}

Function global:FwIsElevated{
	$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent();
	$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity);
	$administratorRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator;
	return $currentPrincipal.IsInRole($administratorRole);
}

Function global:FwIsSupportedOSVersion{
	[OutputType([Bool])]
	Param(
		[parameter(Mandatory=$true)]
		[AllowNull()]
		[Hashtable]$SupportedOSVersion
	)
	EnterFunc $MyInvocation.MyCommand.Name

	[Version]$Global:OSVersion = [environment]::OSVersion.Version
	[Bool]$fResult = $False

	If($Null -eq $OSVersion){
		$fResult = $True 
		$SupportVersionStr = 'Any'
	}Else{
		$SupportVersionStr = $SupportedOSVersion.OS.ToString() + "." + $SupportedOSVersion.Build.ToString()
	}
	LogDebug ("Current OS = " + $OSVersion.Major + "." + $OSVersion.Build + "   Supported OS = " + $SupportVersionStr)

	If($OSVersion.Major -ge $SupportedOSVersion.OS -and $OSVersion.Build -ge $SupportedOSVersion.Build){
		$fResult =  $True
	}
	If($fResult){
		LogDebug ('This command is supported.')
	}Else{
		LogDebug ('Warning: This command not supported.')
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function global:FwResolveDesktopPath{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name

	$DesktopPath = [Environment]::GetFolderPath('Desktop')
	# What we are doing here is that when the script is run from non administrative user 
	# and PowerShell prompt is launched with 'Run as Administrator', profile path of the administrator
	# is obtained. But desktop path used for log path must be under current user's desktop path.
	# So we will check explorer's owner user to know the actual user name and build log folder path using it.
	$CurrentSessionID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
	$Explorer = Get-Process -name 'Explorer' -ErrorAction Ignore | Where-Object {$_.SessionId -eq $CurrentSessionID}
	If($Null -eq $Explorer){
		LogWarn "Unable to find explorer.exe. Returning with $DesktopPath"
		return $DesktopPath
	}
	$EnvVariables = $Explorer[0].startinfo.environmentvariables
	$Owner = ($EnvVariables | Where-Object {$_.NAME -eq 'USERNAME'}).Value
	$LogonUser = ($EnvVariables | Where-Object {$_.NAME -eq 'USERDOMAIN'}).Value

	# This is case where the shell is not explorer.exe. In this case, simply use path obtained by GetFolderPath('Desktop')
	If($Null -eq $Owner){
		LogWarn "Unable to retrieve logon user info. Use `'$DesktopPath`' for desktop path."
		return $DesktopPath
	}

	# There are two possible desktop paths
	$DesktopCandidate = "C:\users\$LogonUser\Desktop"
	$DesktopCandidate2 = "C:\users\$LogonUser.$UserDomain\Desktop"

	If(Test-Path -Path $DesktopCandidate2){ # like C:\Users\ryhayash.FAREAST\desktop
		$DesktopPath = "$DesktopCandidate2"
	}ElseIf(Test-Path -Path $DesktopCandidate){ 
		$DesktopPath = "$DesktopCandidate"
	}Else{ # This is folder redirection scenario
		$DesktopPath = "C:\temp\MSLOG"
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($DesktopPath)")
	return $DesktopPath
}

Function global:FwRunAdminCheck{
	EnterFunc $MyInvocation.MyCommand.Name
	If($Host.Name -match "ISE Host"){
		If(!($noISECheck)){
			LogInfo "Exiting on ISE Host. Please run in Admin PowerShell window. (PowerShell_ISE is not supported)" "Magenta"
			CleanUpandExit
		}
	}
	If(!(FwIsElevated)){
		LogInfo "This script needs to run from elevated Admin PowerShell window (Don't use an ISE window!)." "Red"
		If(!$noAsk.IsPresent){
			# Issue#373 - TSS hang in ISE
			$Answer = FwRead-Host-YN -Message "Do you want to re-run TSS from elevated PowerShell? (timeout=10s)" -Choices 'yn' -TimeOut 10
			#CHOICE /T 10 /C yn /D y /M " Do you want to re-run TSS from elevated PowerShell?"
			If(!$Answer){
				LogInfoFile "=== User declined to run TSS from elevated PowerShell ==="
				LogInfo "Run script from elevated Admin PowerShell window (Don't use an ISE window!)." "Red"
				CleanUpandExit
			}
		}
		$cmdline = $Script:TSScommandline.Replace($MyInvocation.InvocationName,$MyInvocation.MyCommand.Path)
		Start-Process "PowerShell.exe" -ArgumentList " -noExit $cmdline" -Verb runAs	#fix #355
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetProductTypeFromReg{
	switch ((Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\ProductOptions).ProductType)
	{
	  "WinNT"	 { return "WinNT"}
	  "ServerNT" { return "ServerNT"}
	  "LanmanNT" { return "LanmanNT"}
	  Default	 {"EmptyProductType"}
	}
}

Function global:RunCommands{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogPrefix,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String[]]$CmdletArray,
		[parameter(Mandatory=$false)]
		[Bool]$ThrowException=$false,
		[parameter(Mandatory=$false)]
		[Bool]$ShowMessage=$True,
		[parameter(Mandatory=$False)]
		[Bool]$ShowError=$False
	)
	EnterFunc $MyInvocation.MyCommand.Name
	ForEach($CommandLine in $CmdletArray){
		# Get file name of output file. This is used later to add command header line.
		$HasOutFile = $CommandLine -like "*Out-File*"
		If($HasOutFile){
			$OutputFile = $Null
			$Token = $CommandLine -split ' '
			$OutputFileCandidate = $Token[$Token.count-1] # Last token should be output file.
			#If($OutputFileCandidate -like '*.txt*' -or $OutputFileCandidate -like '*.log*'){
			If($OutputFileCandidate -match '\.txt' -or $OutputFileCandidate -match '\.log'){
				$OutputFile = $OutputFileCandidate
				#$OutputFile= $OutputFile -replace ('^"','')
			}
		}
		$tmpMsg = $CommandLine -replace "\|.*Out-File.*$",""
		$tmpMsg = $tmpMsg -replace "\| Out-Null.*$",""
		$tmpMsg = $tmpMsg -replace "\-ErrorAction Stop",""
		$tmpMsg = $tmpMsg -replace "\-ErrorAction SilentlyContinue",""
		$tmpMsg = $tmpMsg -replace "\-ErrorAction Ignore",""
		$tmpMsg = $tmpMsg -replace "cmd /r ",""
		$CmdlineForDisplayMessage = $tmpMsg -replace "2>&1",""

		# In case of reg.exe, see if it is available can be run.
		$cmd = ($CommandLine -split ' ')[0]
		If($cmd -eq 'reg' -or $cmd -eq 'reg.exe'){
			If(!$global:RegAvailable){
				LogInfoFile "Skipping running `'$CommandLine`' as reg command is not available on this system." -ShowMsg
				Continue
			}
		}

		Try{
			If($ShowMessage){
				LogInfoFile ("[$LogPrefix] Running $CmdlineForDisplayMessage") -ShowMsg
			}
			If($DebugMode.IsPresent){
				LogDebug "Running $CommandLine"
			}
			# There are some cases where Invoke-Expression does not reset $LASTEXITCODE and $LASTEXITCODE has old error value. 
			# Hence we initialize the $LASTEXITCODE(PowerShell managed value) if it has error before running command.
			If($Null -ne $global:LASTEXITCODE -and $global:LASTEXITCODE -ne 0){
				$global:LASTEXITCODE = 0
			}
			# Add a header if there is an output file.
			If($Null -ne $OutputFile){
				Write-Output "======================================" | Out-File -Append $OutputFile
				Write-Output "$((Get-Date).ToString("yyyyMMdd HH:mm:ss.fff")) : $CmdlineForDisplayMessage" | Out-File -Append $OutputFile
				Write-Output "======================================" | Out-File -Append $OutputFile
			}
			# Run actual command here.
			# We redirect all streams to temporary error file as some commands output an error to warning stream(3) and others are to error stream(2).
			Invoke-Expression -Command $CommandLine -ErrorAction Stop *> $TempCommandErrorFile
			
			# if LASTEXITCODE=-2147023446 -> (Error=0x800705aa) = ERROR_NO_SYSTEM_RESOURCES -> get REG hive and logman
			If($Null -ne $global:LASTEXITCODE -and $global:LASTEXITCODE -eq "-2147023446") {
				FwGetLogmanInfo _RunCommands_
				FwGetRegHives _RunCommands_
				LogInfo "[ERROR-Info] Error 0x800705aa can happen if MaxETWSessionCount >=55 , try HKLM\SYSTEM\CurrentControlSet\Control\WMI\EtwMaxLoggers=128 (decimal, DWORD) and reboot" "Magenta" -noDate
			}

			If($Null -ne $global:LASTEXITCODE -and $global:LASTEXITCODE -ne 0){
				LogInfoFile "LASTEXITCODE=$global:LASTEXITCODE for Command: $CommandLine"
			}
			# It is possible $LASTEXITCODE becomes null in some sucessful case, so perform null check and examine error code.
			If($Null -ne $global:LASTEXITCODE -and $global:LASTEXITCODE -ne 0 -and $global:LASTEXITCODE -ne -2){ # procdump may exit with 0xfffffffe = -2
				LogInfoFile "[RunCommands] LASTEXITCODE=$global:LASTEXITCODE for Command: $CommandLine"
				$Message = "An error happened during running `'$CommandLine` " + '(Error=0x' + [Convert]::ToString($global:LASTEXITCODE,16) + ')'
				LogErrorFile $Message
				If(Test-Path -Path $TempCommandErrorFile){
					# Always log error to error file.
					Get-Content $TempCommandErrorFile -ErrorAction Ignore | Out-File -Append $global:ErrorLogFile
					# If -ShowError:$True, show the error to console.
					If($ShowError -or $DebugMode.IsPresent){
						LogInfo ($Message) "Red" -noDate
						Write-Host "---------- ERROR MESSAGE ----------"
						Get-Content $TempCommandErrorFile -ErrorAction Ignore
						Write-Host "-----------------------------------"
					}
				}
				Remove-Item $TempCommandErrorFile -Force -ErrorAction Ignore | Out-Null

				If($DebugMode.IsPresent){
					Read-Host ("[DBG - hit ENTER to continue] Error happened in Runcommands. See above error message")
				}
				If($ThrowException){
					Throw($Message)
				}
			}Else{
				Remove-Item $TempCommandErrorFile -Force -ErrorAction Ignore | Out-Null
			}
		}Catch{
			If($DebugMode.IsPresent){
				Read-Host ("[DBG - hit ENTER to continue] Exception in Runcommands")
			}
			If($ThrowException){
				Throw $_   # Leave the error handling to upper function.
			}Else{
				$Message = "An error happened in Invoke-Expression with $CommandLine"
				LogException ($Message) $_ $fLogFileOnly
				If($ShowError){
						Write-Host ("ERROR: $Message") -ForegroundColor Red
						Write-Host ('---------- ERROR MESSAGE ----------')
						$_
						Write-Host ('-----------------------------------')
				}
				Continue
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwCreateFolder{
	<#
	.SYNOPSIS
		Creates Folder on the given path and handles various problems that might occur during that operation.
	.DESCRIPTION
		The Function will check if the folder on the given path exists and if it does NOT exist it will create it.
		global:FwCreateFolder expects 1 parameter: $Path
	.EXAMPLE
		
	.NOTES
		Date:   01.04.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Path
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if (!(Test-Path $Path)){
		Try{
			New-Item -ItemType directory -Path $Path | Out-Null
		}Catch{
			LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
			return
		}
		if (!(Test-Path $Path))
		{
			LogInfo ("New log folder " + $Path + " is NOT created! Something went wrong!")
		}
		else
		{
			LogDebug ("New log folder " + $Path + " created")
		}
	}
	else
	{
		LogDebug ("[FwCreateFolder] this Folder already exists: $Path")
		LogInfoFile ("[FwCreateFolder] this Folder already exists: $Path") "Cyan"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwNew-TemporaryFolder {
	 <#
	.SYNOPSIS
	 Creates a temporary subfolder underneath $RelativeFolder 
	.DESCRIPTION
	 Creates a temporary subfolder underneath $RelativeFolder; if parameter $RelativeFolder is empty it creates the folder in $Env:temp.
	 This is useful for temporary folders, i.e. needed for $LogTTD 
	.EXAMPLE
	 FwNew-TemporaryFolder -RelativeFolder "$global:LogFolder" - which typically resolves to "C:\MS_DATA"
	.PARAMETER RelativeFolder
	 The full path to the top folder for the new temporary subfolder.
	 #>
	Param(
		$RelativeFolder = $Env:temp
	)
	# Make a new folder based upon a TempFileName
	$T="$($RelativeFolder)\tmp$([convert]::tostring((get-random 65535),16).padleft(4,'0')).tmp"
	New-Item -ItemType Directory -Path $T
}

Function global:FwCreateLogFolder{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[string]$LogFolder
	)
	$CallStack = Get-PSCallStack
	$CallerInfo = $CallStack[1]
	If($CallerInfo.FunctionName -eq '<ScriptBlock>'){
		 $FuncName = 'Main'
	}Else{
		$FuncName = $CallerInfo.FunctionName
	}
	EnterFunc ("$($MyInvocation.MyCommand.Name)" + "(Caller - $($FuncName):$($CallerInfo.ScriptLineNumber))")
	If(!(test-path -Path $LogFolder)){
		#LogInfo ".. creating log folder $LogFolder" "Gray" # LogInfoFile would fail as $LogFolder does not exist
		New-Item $LogFolder -ItemType Directory -ErrorAction Stop | Out-Null
		LogDebug ".. created log folder $LogFolder" "Gray"
	}Else{
		LogDebug ("$LogFolder already exist.")
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwCopyFiles{
	<#
	.SYNOPSIS
		The function copies Source to Destination defined in [System.Collections.Generic.List[Object]]$SourceDestinationPaths
		Destination Folder will be created if it does not exit already.

	.DESCRIPTION
		The function copies Source to Destination defined in [System.Collections.Generic.List[Object]]$SourceDestinationPaths
		If source member containes * character, the function will copy all files that match critieria to the destination folder (folder path).
		If source file does not contain * character, the function will simply copy source file (file path) to destination (file path).

		global:FwCopyFiles expects 1 parameter: [System.Collections.Generic.List[Object]]$SourceDestinationPaths
		FwCopyFiles $SourceDestinationPaths

	.EXAMPLE
	Case 1: Copy a single-set of * files
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths.add(@("C:\Temp\*", "$LogFolderforDEV_TEST1"))
		FwCopyFiles $SourceDestinationPaths

	Case 2: Copy a single file
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths.add(@("C:\temp\single-file.txt", "$LogFolderforDEV_TEST1"))
		FwCopyFiles $SourceDestinationPaths

	# Case 3: Copy multi sets of files
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths = @(
			@("C:\temp\*", "$LogFolderforDEV_TEST1"),
			@("C:\temp2\one-single-case3.txt", "$LogFolderforDEV_TEST1")
		)
		FwCopyFiles $SourceDestinationPaths
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[Object]]$SourceDestinationPaths,
		[Bool]$ShowMessage=$True
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($SourceDestinationPaths.Count -eq 0){
		LogWarn "No file name to copy passed."
		Return
	}

	foreach ($item in $SourceDestinationPaths){
		If($item.gettype().BaseType.Name -ne "Array"){
			LogWarn "To be Copied source and destination files need to be passed as array but `'$item`' isn't an array"
			continue
		}
		#$SrcFilename = Split-Path $item[0] -Leaf
		$SrcFoldername = Split-Path $item[0]
		$DestFoldername = Split-Path $item[1]
		if(!(Test-Path $DestFoldername)){
			FwCreateFolder $DestFoldername
		}
		Try{
			if (($item[0].ToCharArray()) -contains '*'){ #wildcard copy
					if (!((Test-Path $SrcFoldername) -and (Test-Path $item[1]))){
						if (!(Test-Path $SrcFoldername)) {
							LogInfoFile "Skipping copying files as folder `'$SrcFoldername`' does not exist."
							continue
						}
						if (!(Test-Path $item[1])) {
							LogInfoFile "Skipping copying files as file `'$($item[1])`' does not exist."
							continue
						}
					}
					If($ShowMessage){LogInfo "Copying $($item[0]) to $($item[1])"}
					Copy-Item -Path $item[0] -Destination $item[1] -Recurse -Force 2>&1 | Out-Null
					#Get-ChildItem -Path $item[1] -Filter $SrcFilename | Rename-Item -NewName {$global:LogPrefix + $_.Name}
			}else{
					if (!((Test-Path $item[0]) -and (Test-Path $SrcFoldername))){
						if (!(Test-Path $item[0])) {
							LogInfoFile "Skipping copying files as file `'$($item[0])`' does not exist."
							continue
						}
						if (!(Test-Path $SrcFoldername)) {
							LogInfoFile "Skipping copying files as folder `'$SrcFoldername`' does not exist."
							continue
						}
					}
					If($ShowMessage){LogInfo "Copying $($item[0]) to $($item[1])"}
					Copy-Item -Path $item[0] -Destination $item[1] -Force 2>&1 | Out-Null
			}
		}Catch{
			$Message = "Failed to copy $($item[0])"
			LogWarn $Message
			LogException $Message $_ $fLogFileOnly
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetDSregCmd {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	If( !$global:IsServerCore -and ($global:OSVersion.Build -gt 14393)){ # Commands from Windows 10 RS2+
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'DSregcmd /status' at $TssPhase" -ShowMsg
		if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "DSregCmd" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_DSregCmd.txt"}
		$Commands += @(
			"dsregcmd.exe /status -ErrorAction Ignore | Out-File -Append $outFile"	#ToDo: need to ignore error msg
			"dsregcmd.exe /status /debug /all -ErrorAction Ignore | Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}else{ LogInfoFile "Note: dsregcmd.exe is not available in downlevel OS or on SrvCORE"}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetOperatingSystemInfo{
	<#
	.SYNOPSIS
		Collect Operating System info from the monitored machines and returns it to the caller.
	.DESCRIPTION
		Collect Operating System info from the monitored machines and stores it in global:FwBuildInfo variable
	.EXAMPLE
		Framework always runs this function at start and sets global:OperatingSystemInfo
	.NOTES
		Date:   20.04.2021
	#>
	EnterFunc $MyInvocation.MyCommand.Name
	# OperatingSystem info 
	$OSInfo = New-Object System.Collections.Generic.Dictionary"[String,String]"
	$OSInfo.Add("ProductName",(Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ProductName)
	$OSInfo.Add("OSVersion", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentMajorVersionNumber)
	$OSInfo.Add("CurrentVersion", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion)
	$OSInfo.Add("ReleaseId", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ReleaseId)
	$OSInfo.Add("BuildLabEx", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").BuildLabEx  )
	$OSInfo.Add("CurrentBuildHex", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentBuild)
	EndFunc ($MyInvocation.MyCommand.Name + "($OSInfo)")
	return $OSInfo
}

Function global:FwGetBuildInfo {
	EnterFunc ($MyInvocation.MyCommand.Name)
	$outFile = $PrefixTime + "BuildInfo.txt"
	FwGetOperatingSystemInfo | Out-File -Append $outFile
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FWgetFltMcInfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name)
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Collecting FltMc Information" -ShowMsg
	$Commands = @(
		"fltmc instances	| Out-File -Append $PrefixTime`Fltmc_instances.txt"
		"fltmc filters		| Out-File -Append $PrefixTime`Fltmc_filters.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
function global:FWgetDriverQuery {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name)
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Collecting Driverquery Information" -ShowMsg
	$Commands = @(
		"driverquery /FO csv /v	| Out-File -Append $PrefixTime`Driverquery.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetHotfix {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'Get-Hotfix'" -ShowMsg
	$outFile = $PrefixTime + "Hotfixes.txt"
	Get-Hotfix | Out-File -Append $outFile -Encoding ascii -Width 200
	EndFunc $MyInvocation.MyCommand.Name
}
Function global:FwGet-TimeStamp {
	return "$(Get-Date -format "yyyyMMdd_HHmmss_ffff")"
}

Function global:FwWrite-Log {
	# PURPOSE: Writes script information to a log file and to the screen when -Verbose is set or argument -Tee is passed.
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$LogFilePath,
		[string]$text, 
		[switch]$tee = $false, 
		[string]$foreColor = $null
	)
	EnterFunc ($MyInvocation.MyCommand.Name)
	#$LogFilePath = "$script:dataPath\$script:logName"
	$foreColors = "Black","Blue","Cyan","DarkBlue","DarkCyan","DarkGray","DarkGreen","DarkMagenta","DarkRed","DarkYellow","Gray","Green","Magenta","Red","White","Yellow"

	# check the log file, create if missing
	$isPath = Test-Path $LogFilePath
	if (!$isPath) {
		"$(FwGet-TimeStamp): Log started" | Out-File $LogFilePath -Force
		"$(FwGet-TimeStamp): Local log file path: $($LogFilePath)" | Out-File $LogFilePath -Force
		Write-Verbose "Local log file path: $($LogFilePath)"
	}
	# write to log
	"$(FwGet-TimeStamp): $text" | Out-File $LogFilePath -Append
	# write text verbosely
	Write-Verbose $text
	if ($tee) {
		# make sure the foreground color is valid
		if ($foreColors -contains $foreColor -and $foreColor)
		{
			Write-Host -ForegroundColor $foreColor $text
		}else{
			Write-Host $text
		}		
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetLogmanInfo {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	$outFile = $PrefixTime + "LogmanInfo" + $TssPhase + ".txt"
	$ETWSessionList = logman.exe -ets 
	$ETWSessionListCount = $ETWSessionList.Count
	try {$ETWSessionList| Out-String | out-file $outFile; $TotProvCnt=$($ETWSessionListCount -5); "`n $(Get-Date -format `"yyyyMMdd_HHmmss_ffff`") : Total # of ETW Sessions: " + $TotProvCnt| Out-File -Append $outFile; if ($TotProvCnt -gt 55) {write-host -ForegroundColor red "[ERROR]: This data collection exceeds 55 ETL Trace Sessions, stop unnecessary ones.`nTo do so, stop current TSS, run 'logman.exe -ets', then: Logman.exe stop -ets -n 'name of unrelated ETL session', then restart TSS"} } 
	catch {Throw $error[0].Exception.Message; exit 1}
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'logman.exe -ets' at $TssPhase - Total#: $TotProvCnt"
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetPowerCfg {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Collecting Power Configuration settings at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "PowerConfig" + $TssPhase + ".txt"
	$Commands = @(
		"PowerCfg.exe /list 2>&1	| Out-File -Append $outFile"
		"PowerCfg.exe /qh 2>&1		| Out-File -Append $outFile"
		"PowerCfg.exe /a 2>&1		| Out-File -Append $outFile"	# fails on SrvCore
		)
	if (!$IsServerSKU) {
		$Commands += @(
			"PowerCfg.exe /sleepstudy /duration 14 /output $PrefixTime`Powercfg-sleepstudy.html 2>&1"
		)
	}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	$PowerKeys = @(
		('HKLM:System\CurrentControlSet\Control\Power', "$PrefixTime`Reg_Power.txt"),
		('HKLM:System\CurrentControlSet\Control\Session Manager\Power', "$PrefixTime`Reg_SessMgr_Power.txt")
	)
	FwExportRegistry $LogPrefix $PowerKeys
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetSrvWkstaInfo {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Collecting IP/Server/Workstation infos at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "IP_Srv_Wks_Info" + $TssPhase + ".txt"
	"*** Note: All IPconfig info and DNS cache info was moved to IPconfig_Info" | Out-File -Append $outFile
	"		  All Arp info was moved to Arp_Info" | Out-File -Append $outFile
	"		  All SMB Server/Workstation info was moved to SMB_Server_Info/SMB_Workstation_Info" | Out-File -Append $outFile
	"		  All Netstat info was moved to NetStat_Info `n" | Out-File -Append $outFile
	FwGetArp $TssPhase
	FwGetIPconfig $TssPhase
	FwGetNetstat $TssPhase
	FwGetSMBserverInfo $TssPhase
	FwGetSMBclientInfo $TssPhase
	EndFunc $MyInvocation.MyCommand.Name
}
Function global:FwGetNetLbfoTeam {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "Collecting LBFO info" -ShowMsg
	$outFile = $PrefixTime + "LBFo_Info" + $TssPhase + ".txt"
	$Commands = @(
		"Get-NetLbfoTeam		| Out-File -Append $outFile"
		"Get-NetLbfoTeamMember	| Out-File -Append $outFile"
		"Get-NetLbfoTeamNic		| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}	
Function global:FwGetArp {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "Collecting Arp info" -ShowMsg
	$outFile = $PrefixTime + "Arp_Info" + $TssPhase + ".txt"
	$Commands = @(
		"arp -a -v 							| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}	
Function global:FwGetIPconfig {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "Collecting IPconfig info" -ShowMsg
	$outFile = $PrefixTime + "IPconfig_Info" + $TssPhase + ".txt"
	$Commands = @(
		"IPCONFIG /ALL 						| Out-File -Append $outFile"
		"netsh interface IP show config 	| Out-File -Append $outFile"
		"netsh interface IPv4 show int 		| Out-File -Append $outFile"
		"netsh interface IPv4 show subint 	| Out-File -Append $outFile"
		"netsh interface ipv4 show offload	| Out-File -Append $outFile"
		"netsh interface tcp show global	| Out-File -Append $outFile"
		"Route Print 						| Out-File -Append $outFile"
		"IPCONFIG /DisplayDNS 				| Out-File -Append $outFile"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
Function global:FwGetNetstat {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "Collecting Netstat info" -ShowMsg
	$outFile = $PrefixTime + "NetStat_Info" + $TssPhase + ".txt"
	$Commands = @(
		"NETSTAT -anob 						| Out-File -Append $outFile"
		"NETSTAT -r 						| Out-File -Append $outFile"
		"NETSTAT -es 						| Out-File -Append $outFile"
		"NETSTAT -nato		 				| Out-File -Append $outFile"
		"NETSTAT -nato -p tcp 				| Out-File -Append $outFile"
		)
		If($global:OSVersion.Build -gt 9600){ $Commands += @( "NETSTAT -anoq | Out-File -Append $outFile") }
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetSMBserverInfo {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	$LMServerStatus = (Get-Service -Name "LanmanServer").status
	if ($LMServerStatus -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
		LogInfoFile "Collecting SMB server NET * info" -ShowMsg
		$outFile = $PrefixTime + "SMB_Server_Net_Info" + $TssPhase + ".txt"
		$Commands = @(
			"NET CONFIG SERVER 					| Out-File -Append $outFile"
			"NET ACCOUNTS 						| Out-File -Append $outFile"
			"NET SESSION 						| Out-File -Append $outFile"
			"NET SHARE	 						| Out-File -Append $outFile"
			"NET FILES	 						| Out-File -Append $outFile"
			)
			if ($global:ProductType -ne "LanmanNT") {
				$Commands += @(	"NET USER | Out-File -Append $outFile")
			}else{ LogInfo "[$($MyInvocation.MyCommand.Name)] ProductType: $global:ProductType - skip NET USER on BDC or PDC" "Gray" }
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		LogInfoFile "Collecting SMB server PScmdlet info"
		$outFile = $PrefixTime + "SMB_Server_PScmdlet_Info" + $TssPhase + ".txt"
		$Commands = @(
			"Get-SmbShare | select Name,FolderEnumerationMode,Path,ShareState,ScopeName,CachingMode,LeasingMode,ContinuouslyAvailable,CATimeout,AvailabilityType |ft -auto | Out-File -Width 999 -Append $outFile"
			"Get-SmbShare | select Name,EncryptData,SecurityDescriptor,Description,Scoped,ConcurrentUserLimit,CurrentUsers,Volume |ft -auto |Out-String -Width 999 | Out-File -Append $outFile"
			"Get-SmbServerConfiguration			| Out-File -Append $outFile"
			"Get-SmbServerNetworkInterface		| Out-File -Append $outFile"
			#"Get-SmbOpenFile 					| Out-File -Append -Width 999 $outFile"
			"Get-SmbOpenFile | select FileId,SessionId,Path,ShareRelativePath,ClientComputername,ClientUserName,Permissions | ft * | Out-File -Append -Width 999 $outFile"
			"Get-SmbSession						| Out-File -Append $outFile"
			"Get-SmbWitnessClient				| Out-File -Append $outFile"
		)
		if ($global:OSVersion.Build -lt 9200) {
			$Commands += @(
			"NET FILES | Out-File -Append $outFile"
			)
		}
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}else{ LogInfo "[$($MyInvocation.MyCommand.Name)] [FAIL] Service LanmanServer is not started" }
	EndFunc $MyInvocation.MyCommand.Name
}
Function global:FwGetSMBclientInfo {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "Collecting SMB Client/Workstation info" -ShowMsg
	
	$wkstaStatus = (Get-Service -Name "LanmanWorkstation").status
	if ($wkstaStatus -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
		$outFile = $PrefixTime + "SMB_Client_Info" + $TssPhase + ".txt"
		$Commands = @(
			"NET USE 						| Out-File -Append $outFile"
			"NET CONFIG workstation			| Out-File -Append $outFile"
			"NET STATISTICS Workstation 	| Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False		
		$outFile = $PrefixTime + "SMB_Client_PScmdlets_Info" + $TssPhase + ".txt"
		$Commands = @(
			"Get-SmbConnection 				| Out-File -Width 999 -Append $outFile"
			"Get-SmbConnection | fl *		| Out-File -Append $outFile"
			"Get-SmbMapping 				| Out-File -Append $outFile"
			"Get-SmbClientConfiguration		| Out-File -Append $outFile"
			"Get-SmbClientNetworkInterface	| Out-File -Width 999 -Append $outFile"
			"Get-SmbMultichannelConnection	| Out-File -Width 999 -Append $outFile"
			"Get-SmbMultichannelConstraint	| Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False	
	}else{ LogInfo "[$($MyInvocation.MyCommand.Name)] [FAIL] LanmanWorkstation is not started" }
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportRegKey{
	<#
	.SYNOPSIS
		Exports registry key in TXT or REG formats
	.DESCRIPTION
		global:FwExportRegKey expects 3 parameters: $RegistryKey, $ExportFile, and $ExportFormat
	.EXAMPLE
		to export key and its subkey "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" in "C:\reg exportTXT.txt" using "TXT" format call:
		global:FwExportRegKey "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" "C:\Dev\reg exportTXT.txt" "TXT"
	.EXAMPLE
		to export key and its subkey "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" in "C:\reg exportREG.reg" using "REG" format call:
		global:FwExportRegKey "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" "C:\Dev\reg exportREG.reg" "REG"
	.NOTES
		Date:   01.04.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryKey,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ExportFile,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ExportFormat
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if(Test-Path Registry::"$RegistryKey") {
		If($ExportFormat -like "TXT"){
				$CommandLine = "reg query `"$RegistryKey`" /s > `"$ExportFile`" 2>&1 | Out-Null"
			}
		elseif($ExportFormat -like "REG"){
				$CommandLine = "reg export `"$RegistryKey`" `"$ExportFile`" /y 2>&1 | Out-Null"
			}
		else {
			LogException ("Not support export format $ExportFormant") $_ $fLogFileOnly
			return
			}
		
		LogDebug ("Running $CommandLine")
		Try{
			Invoke-Expression $CommandLine
		}Catch{
			LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
			Continue
		}
	}else{ "Key $RegistryKey does not exist"  > $ExportFile 2>&1 }
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportRegistry{
	<#
	.SYNOPSIS
		Exports registry key to log file(s) by using REG QUERY or REG EXPORT (-RealExport $true)
	.DESCRIPTION
		If $RegKeysAndLogfileArray(2nd argument) has a set of reg key and log file like 
		below example of Case 1, this function exports multiple keys to each corresponding log file.

		If the array does not have file and just an array of reg keys, this function requires 
		$Logfile(3rd argument) and exports all keys into the single file specified by $LogFile (Case 2).
		FwExportRegToOneFile() function has the same functionality.
	.PARAMETER RealExport
		If you need to export large key structures like HKLM\SOFTWARE it's way faster if you append
		the parameter -RealExport $true to the function call. This will use REG EXPORT then, instead of REG QUERY
		-RealExport will overwrite any existing file. See Case 4.
	.PARAMETER noRecursive
		this switch will not run recursive REG QUERY command

	.EXAMPLE
		There are multiple ways to use this function.
	Case 1: Export multiple registry keys to each corresponding log file.
		$RegKeys = @(
			('HKLM:System\CurrentControlSet\Control\CrashControl', "$LogFolder\_Reg_CrashControl.txt"),
			('HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management', "$LogFolder\_Reg_MemoryManagement.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug', "$LogFolder\_Reg_AeDebug.txt")
		)
		FwExportRegistry "MyLogPrefix" $RegKeys

	Case 2: Export single or multiple registry keys to a single file. But better way for this usage is to use FwExportRegToOneFile().
		$RegKeys = @(
			'HKLM:System\CurrentControlSet\Control\CrashControl',
			'HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management',
			'HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug'
		)
		FwExportRegistry "MyLogPrefix" $RegKeys "$LogFolder\_Reg_Recovery.txt"
			
	Case 3: Export multiple registry keys and a property to each corresponding log file.
		$RegKeys = @(
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'BuildLab', "$PrefixTime`Reg_BuildInfo.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'BuildLabEx', "$PrefixTime`Reg_BuildInfo.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'UBR', "$PrefixTime`Reg_BuildInfo.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'ProductName', "$PrefixTime`Reg_BuildInfo.txt"),
			('HKLM:Software\Microsoft\Windows\CurrentVersion\AppModel', 'Version', "$PrefixTime`Reg_AppModelVersion.txt")
		)
		FwExportRegistry "MyLogPrefix" $RegKeys

	Case 4: Use "reg export" instead "reg query". -RealExport will overwrite any existing file
		$RegKeys = @(
			('HKLM:System\CurrentControlSet\Control\CrashControl', "$LogFolder\_Reg_CrashControl.txt"),
			('HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management', "$LogFolder\_Reg_MemoryManagement.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug', "$LogFolder\_Reg_AeDebug.txt")
		)
		FwExportRegistry "MyLogPrefix" $RegKeys -RealExport $true

	.NOTES
		Date:   30.11.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogPrefix,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Array]$RegKeysAndLogfileArray,
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String]$LogFile=$Null,
		[Bool]$ShowMessage=$True,
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[Bool]$RealExport,
		[Switch]$noRecursive
	)
	EnterFunc $MyInvocation.MyCommand.Name
	ForEach($RegKeyAndLogFile in $RegKeysAndLogfileArray){
		If($RegKeyAndLogFile.Count -eq 3){		# Case#3 for exporting to multiple files and properties.
			$ExportKey = $RegKeyAndLogFile[0]	# Reg key
			$Property = $RegKeyAndLogFile[1]	# Property name
			$OutFile = $RegKeyAndLogFile[2]		# Output file name
			$ExportProperty = $true
		}ElseIf($RegKeyAndLogFile.Count -eq 2){ # Case#1 for exporting to multiple files.
			$ExportKey = $RegKeyAndLogFile[0]	# Reg key
			$OutFile = $RegKeyAndLogFile[1]		# Output file name
		}ElseIf($RegKeyAndLogFile.Count -eq 1){ # Case#2 for exporting to one file(always use $LogFile).
			$ExportKey = $RegKeyAndLogFile
			$OutFile = $LogFile
		}
		LogDebug "Exporting Reg=$ExportKey LogFile=$LogFile"

		If(!(Test-Path -Path $ExportKey)){
		   LogInfoFile "[$($MyInvocation.MyCommand.Name)] Registry Key `'$ExportKey`' does not exist."
			"[WARNING] Registry Key `"$ExportKey`" does not exist." | Out-File -Append $OutFile	#we# report to file
			Continue
		}
		$ConvExportKey = Convert-Path -Path $ExportKey

		# RunCommands takes care of header added to a log file. So we don't add a header here.
		If ($ExportProperty -eq $true) {
			$regEntry = Get-ItemProperty -Path "$ExportKey" | Select-Object -ExpandProperty $Property -ErrorAction Ignore
			If($regEntry){
				$Commands = @("REG QUERY `"$ConvExportKey`" /v `"$Property`" | Out-File -Append $OutFile")
			}else{LogInfoFile "Registry Property $ExportKey\$Property does not exist."; Continue}
		}Else{
			$Commands = @(
				if ($RealExport) {
					"REG EXPORT `"$ConvExportKey`" `"$OutFile`" /y 2>&1 | Out-Null"
				}else{
					If($noRecursive){
						"REG QUERY `"$ConvExportKey`" | Out-File -Append $OutFile"
					}else{
						"REG QUERY `"$ConvExportKey`" /s | Out-File -Append $OutFile"
					}
				}
			)
		}
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$ShowMessage

		# We keep below code for the export using Get-ChildItem for a while just in case of future use.
		#Try{
		#	$Key = Get-Item $ExportKey -ErrorAction Stop
		#}Catch{
		#	LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
		#	Continue
		#}
		#
		#Write-Output("[" + $Key.Name + "]") | Out-File -Append $LogFile
		#ForEach($Property in $Key.Property){
		#	Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
		#}
		#
		#Try{
		#	$ChildKeys = Get-ChildItem $ExportKey -Recurse -ErrorAction Stop
		#}Catch{
		#	LogException ("Error: An exception happens in Get-ChildItem $RegistryKey.") $_ $fLogFileOnly
		#	Continue 
		#}
		#
		#ForEach($ChildKey in $ChildKeys){
		#	Write-Output("[" + $ChildKey.Name + "]") | Out-File -Append $LogFile
		#	Try{
		#		$Key = Get-Item $ChildKey.PSPath -ErrorAction Stop
		#	}Catch{
		#		LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
		#		Continue
		#	}
		#	ForEach($Property in $Key.Property){
		#		Try{
		#			Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
		#		}Catch{
		#			LogException ("Error: An exception happens in Write-Output $Key.") $_ $fLogFileOnly
		#		}
		#	}
		#}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportRegToOneFile{
	<#
	.SYNOPSIS
		Exports registry key to a single log file by using REG QUERY
	.DESCRIPTION
		This is a wrapper function for FwExportRegistry. Requires $Logfile(3rd argument). 
		Exports all reg keys into the single file specified by $LogFile.
	.PARAMETER noRecursive
		this switch will not run recursive REG QUERY command
	.EXAMPLE
		$RegKeys = @(
			'HKLM:System\CurrentControlSet\Control\CrashControl',
			'HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management',
			'HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug'
		)
		FwExportRegToOneFile "TEST" $RegKeys "$LogFolder\_Reg_Recovery.txt"
	.NOTES
		Date:   27.07.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogPrefix,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Array]$RegistryKeys,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogFile,
		[Bool]$ShowMessage=$False,
		[Switch]$noRecursive=$False
	)
	EnterFunc $MyInvocation.MyCommand.Name
	FwExportRegistry $LogPrefix $RegistryKeys -LogFile $LogFile -ShowMessage:$ShowMessage -noRecursive:$noRecursive
	
	# We keep below code for the export using Get-ChildItem for a while just in case of future use.
	#ForEach($RegistryKey in $RegistryKeys){
	#	If(!(Test-Path -Path $RegistryKey)){
	#		LogWarnFile ("$RegistryKey does not exist.")
	#		Continue
	#	}
	#	If($ShowMessage){
	#		LogInfo ("[$LogPrefix] Exporting $RegistryKey")
	#	}
	#	Try{
	#		$Key = Get-Item $RegistryKey -ErrorAction Stop
	#	}Catch{
	#		LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
	#		Continue
	#	}
	#   
	#	Write-Output("[" + $Key.Name + "]") | Out-File -Append $LogFile
	#	ForEach($Property in $Key.Property){
	#		Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
	#	}
	#
	#	Try{
	#		$ChildKeys = Get-ChildItem $RegistryKey -Recurse -ErrorAction Stop
	#	}Catch{
	#		LogException ("Error: An exception happens in Get-ChildItem $RegistryKey.") $_ $fLogFileOnly
	#		Return # This is critical and return.
	#	}
	#
	#	ForEach($ChildKey in $ChildKeys){
	#		Write-Output("[" + $ChildKey.Name + "]") | Out-File -Append $LogFile
	#		Try{
	#			$Key = Get-Item $ChildKey.PSPath -ErrorAction Stop
	#		}Catch{
	#			LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
	#			Continue
	#		}
	#		ForEach($Property in $Key.Property){
	#			Try{
	#				Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
	#			}Catch{
	#				LogException ("Error: An exception happens in Write-Output $Key.") $_ $fLogFileOnly
	#			}
	#		}
	#	}
	#}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwAddRegValue{
	<#
	.SYNOPSIS
		Adds new reg value to the registry key
	.DESCRIPTION
		global:FwAddRegValue expects 4 parameters: $RegistryKey, $RegistryValue, $RegistryValueType (https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types) and $RegistryValueData
	.EXAMPLE
		to create new "my test" REG_DWORD value 0x1 in "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" call:
		global:FwAddRegValue "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" "my test" "REG_DWORD" "0x1"
	.NOTES
		Date:   01.04.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryKey,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryValue,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryValueType,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryValueData,
		[parameter(Mandatory=$false)]
		[Bool]$BootRequired = $False
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$CommandLine = "REG add `"$RegistryKey`" /v `"$RegistryValue`" /t $RegistryValueType /d $RegistryValueData /f 2>&1 | Out-Null"
	LogInfoFile ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
		if ($BootRequired -eq $true) { LogWarn "This key $RegistryKey will require a reboot once for proper data collection!" "Cyan" }
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwDeleteRegValue{
	<#
	.SYNOPSIS
		Deletes reg value from the registry key
	.DESCRIPTION
		global:FwDeleteRegValue expects 2 parameters: $RegistryKey and $RegistryValue
	.EXAMPLE
		to delete value "my test" from "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" call:
		global:FwDeleteRegValue "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" "my test"
	.NOTES
		Date:   01.04.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryKey,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryValue
	)
	EnterFunc $MyInvocation.MyCommand.Name
   
	$CommandLine = "REG delete `"$RegistryKey`" /v `"$RegistryValue`" /f 2>&1 | Out-Null"
	LogInfoFile ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-RegistryValue {
	<#
	.SYNOPSIS
		Fetsches reg value from the registry key
	.DESCRIPTION
		FwGet-RegistryValue expects 2 parameters: $Path and $Value
	.EXAMPLE
	# Ex: FwGet-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath
	#>
	Param(
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$Path,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$Value
	)

	if (Test-Path -path $Path) {
		return Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Ignore
	}
	else {
		return $false
	}
}

function FwSetRegAcl{
	<# #we# currently not used
	.SYNOPSIS
		Set Registry Permission
	.DESCRIPTION
		Set Registry Permission for User/Group
	.EXAMPLE
		Ex#1 Add a permission
		 FwSetRegAcl 'HKLM:System\CurrentControlSet\Services\Procmon24\Instances\Process Monitor 24 Instance' 'Add' 'Everyone' 'Readkey' 'None' 'None' 'Allow'
		Ex#2 Overwrite an exiting permission
		 FwSetRegAcl 'HKLM:System\CurrentControlSet\Services\Procmon24\Instances\Process Monitor 24 Instance' 'Overwrite' 'Everyone' 'ReadPermissions' 'None' 'None' 'Allow'
	#>
	Param(
		[String]$RegKey,	# ex: 'HKLM:System\CurrentControlSet\Services\Procmon24\Instances\Process Monitor 24 Instance'
		[ValidateSet("Add","Overwrite")]
		[String]$Mode,
		[String]$idRef1,	# ex: "HOSTNAME\username" or "Everyone"
		#[ValidateSet("ChangePermissions","CreateLink","CreateSubKey","Delete","EnumerateSubKeys","ExecuteKey","FullControl","Notify","QueryValues","ReadKey","ReadPermissions","SetValue","TakeOwnership","WriteKey")]
		[String[]]$regRights1,
		[ValidateSet("None","ContainerInherit","ObjectInherit")]
		[String]$inhFlags1,
		[ValidateSet("None","ContainerInherit","ObjectInherit")]
		[String]$prFlags1,
		[ValidateSet("Allow","Deny")]
		[String]$acType1
	)
	$acl = Get-Acl $RegKey #'HKLM:System\CurrentControlSet\Services\Procmon24\Instances\Process Monitor 24 Instance'
	LogInfo "===========================" -noDate
	LogInfo "Current ACL for '$RegKey'" -noDate
	LogInfo "===========================" -noDate
	$acl.Access

	#create the identity by creating an System.Security.Principal.NTAccount object 
	$idRef = [System.Security.Principal.NTAccount]($idRef1)

	#https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.registryrights?redirectedfrom=MSDN&view=netframework-4.8
	#create a System.Security.AccessControl.RegistryRights object using one of the rights <ChangePermissions|CreateLink|CreateSubKey|Delete|EnumerateSubKeys|ExecuteKey|FullControl|Notify|QueryValues|ReadKey|ReadPermissions|SetValue|TakeOwnership|WriteKey>
	$regRights = [System.Security.AccessControl.RegistryRights]::$regRights1

	# define the inheritance and propagation flags. <None|ContainerInherit|ObjectInherit>
	$inhFlags = [System.Security.AccessControl.InheritanceFlags]::$inhFlags1
	$prFlags = [System.Security.AccessControl.PropagationFlags]::$prFlags1

	#set the access control type enum <Allow|Deny>
	$acType = [System.Security.AccessControl.AccessControlType]::$acType1

	#create the RegistryAccessRule object 
	$rule = New-Object System.Security.AccessControl.RegistryAccessRule ($idRef, $regRights, $inhFlags, $prFlags, $acType)

	switch($Mode){
		"Add" {
			#Adding the ACL
			$acl.AddAccessRule($rule)}
		"Overwrite" {
			#Overwriting an Existing ACL
			$acl.SetAccessRule($rule)}
	}

	#Assigning the ACL
	$acl | Set-Acl -Path $RegKey #'HKLM:System\CurrentControlSet\Services\Procmon24\Instances\Process Monitor 24 Instance'
	LogInfo "===========================" -noDate
	LogInfo "Modified ACL:" -noDate
	LogInfo "===========================" -noDate
	$acl.Access
}

Function global:FwTestRegistryValue($key,$name){
	<#
	.SYNOPSIS
		Test, if a reg value exists for reg.name $name under the registry key $key
	.DESCRIPTION
		returns $True if $name exists
	.EXAMPLE
		FwTestRegistryValue "HKCU:\Software\Sysinternals\Process Monitor" "Logfile"
	#>
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		if(Get-Member -InputObject (Get-ItemProperty -Path $key) -Name $name -ErrorAction SilentlyContinue) 
		{
			LogInfoFile ("[$($MyInvocation.MyCommand.Name)] RegCheck is True: $key\$name")
			return $true
		}
	}Catch{
			LogException ("Error: An exception happens in Get-ItemProperty -Path $key.") $_ $fLogFileOnly
			LogWarn "[$($MyInvocation.MyCommand.Name)] reg value $key '$name' does not exist"
			Continue
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($false)")
	return $false
}

function global:FwAddRegItem {
	<#
	.SYNOPSIS
		Adds new Registry item(s) to the global list of registry keys (or non-recursive list) to be collected
	.DESCRIPTION
		Adds new Registry item(s) to the list of registry keys to be collected at Collect Phase ($global:RegKeysModules array)
		Parameter TssPhase is optional. FW will use _Start_ or _Stop_, depending on phase of datacollection.
		Individual RegKeysModules are defined in <_POD.psm1> specific #region Registry Keys modules as $global:KeysXXX
	.EXAMPLE
		global:FWaddRegItem @("Tcp", "Rpc")
	.EXAMPLE
		global:FWaddRegItem @("Tcp", "Rpc") -noRecursive
	#>
	Param(
		[Parameter(Mandatory=$True)]
		[String[]]$AddToRegKeyModules,	# which Reg module(s) to add to $global:RegKeysModules, i.e @("Tcp") or @("Tcp", "Rpc")
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,		# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[Switch]$noRecursive						# add item to non-recursive list
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] adding Registry item(s): $AddToRegKeyModules at $TssPhase" -ShowMsg
	If($noRecursive){
		$global:RegKeysModulesNoRecursive += $AddToRegKeyModules
		LogDebug "___ after FWaddRegItem, no-recursive list: $global:RegKeysModulesNoRecursive"
	}
	else {
		$global:RegKeysModules += $AddToRegKeyModules
		LogDebug "___ after FWaddRegItem, recursive list: $global:RegKeysModules"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetRegList {
	<# 
	.SYNOPSIS 
		Bulk collection of Registry keys at Collect Phase
	.DESCRIPTION
		It will process FwExportRegToOneFile for each RegKey module at phase TssPhase.
		You can add Registry keys to this list using function FWaddRegItem
	.EXAMPLE
		FWgetRegList _Stop_
	#>
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if ($TssPhase -eq '_Stop_') { global:FWaddRegItem "KIRMyKnobs" $TssPhase }
	#($global:RegKeysModules,$global:RegKeysModulesNoRecursive) | ForEach-Object {
		if ($global:RegKeysModules.count -gt 0){
			LogInfoFile "[$($MyInvocation.MyCommand.Name)] Processing Registry output Logs at $($TssPhase)" -ShowMsg
			LogInfoFile "___ RegKeysModules before: $global:RegKeysModules"
			$RegKeysSum = $global:RegKeysModules |Sort-Object -Unique
			LogInfoFile "___ UniqueRegList at $TssPhase : $RegKeysSum"
			foreach ($module in $RegKeysSum) {	# dynamic variables
				Set-Variable -Name ("Keys"  + $module) -scope Global
				$Keys = Get-Variable -Scope Global -Name ("Keys" + $module) -ValueOnly
				LogDebug "___ at $TssPhase : RegModule_short = $module - RegModuleName = Keys$module -- RegModuleValue = $Keys" #we# 
				$KeyFileName = $PrefixTime + "Reg_" + $module + $TssPhase +".txt"
				LogInfoFile "___ resulting Keys $module : $Keys"
				LogDebug "___ Reg KeyFileName: $KeyFileName"
				$duration = Measure-Command {
				 ($Keys) | ForEach-Object { FwExportRegToOneFile $LogPrefix $_ $KeyFileName -ShowMessage:$False}
				}
				LogInfoFile "___ [$duration FwExportRegToOneFile]: $module"
			}
			LogInfoFile "___ done all RegKeysModules: $RegKeysSum"
		}
		if ($global:RegKeysModulesNoRecursive.count -gt 0){
			LogInfoFile "[$($MyInvocation.MyCommand.Name)] Processing Non-Recursive Registry output Logs at $($TssPhase)" -ShowMsg
			LogInfoFile "___ RegKeysModulesNoRecursive before: $global:RegKeysModulesNoRecursive"
			$RegKeysSum = $global:RegKeysModulesNoRecursive |Sort-Object -Unique
			LogInfoFile "___ Non-Recursive UniqueRegList at $TssPhase : $RegKeysSum"
			foreach ($module in $RegKeysSum) {	# dynamic variables
				Set-Variable -Name ("Keys"  + $module) -scope Global
				$Keys = Get-Variable -Scope Global -Name ("Keys" + $module) -ValueOnly
				LogDebug "___ at $TssPhase : RegModule_short = $module - RegModuleName = Keys$module -- RegModuleValue = $Keys" #we# 
				$KeyFileName = $PrefixTime + "Reg_" + $module + $TssPhase +".txt"
				LogInfoFile "___ resulting Keys $module : $Keys"
				LogDebug "___ Reg KeyFileName: $KeyFileName"
				$duration = Measure-Command {
				 ($Keys) | ForEach-Object { FwExportRegToOneFile $LogPrefix $_ $KeyFileName -ShowMessage:$False -noRecursive}
				}
				LogInfoFile "___ [$duration FwExportRegToOneFile]: $module"
			}
			LogInfoFile "___ done all RegKeysModulesNoRecursive: $RegKeysSum"
		}
	#}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwEventLogsSet{
	<#
	.SYNOPSIS
		Set Event Log parameters for a single Event Log
	.DESCRIPTION
		FwEventLogsSet expects 5 parameters: $LogName, $Enabled (true or false), $retention (true or false), $quiet (true or false) and $MaxSize in Bytes (e.g. 102400000 is 100 MB)
	.EXAMPLE
		to execute this command: wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:true /rt:false /q:true /ms:102400000
		you need to call: FwEventLogsSet "Microsoft-Windows-CAPI2/Operational" true false true 102400000
	.EXAMPLE 
		to execute this command: wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:false
		you need to call: FwEventLogsSet Microsoft-Windows-Kerberos/Operational", "true", "", "", ""

	.NOTES
		Date:   01.04.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogName,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Enabled,  # true or false
		[parameter(Mandatory=$false)]
		[String]$retention,  # true or false
		[parameter(Mandatory=$false)]
		[String]$quiet,  # true or false
		[parameter(Mandatory=$false)]
		[String]$MaxSize   # in Bytes, e.g. 102400000 is 100 MB
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$rt = ""
	$q = ""
	$ms = ""

	If(!([string]::IsNullOrEmpty($retention))){
		$rt= " /rt:$retention"
	}

	If(!([string]::IsNullOrEmpty($quiet))){
		$q= " /q:$quiet"
	}

	If(!([string]::IsNullOrEmpty($MaxSize))){
		$ms = " /ms:$MaxSize"
	}

	$CommandLine = "wevtutil set-log $LogName /enabled:$Enabled$rt$q$ms 2>&1 | Out-Null"
	LogDebug ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwEventLogClear{
	<#
	.SYNOPSIS
		Clears single Event Log
	.DESCRIPTION
		global:FwEventLogClear expects 1 parameter: $LogName
	.EXAMPLE
		to execute this command: wevtutil.exe clear-log "Microsoft-Windows-CAPI2/Operational"
		you need to call: global:FwEventLogsClear "Microsoft-Windows-CAPI2/Operational"
	.NOTES
		Date:   01.04.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogName
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$CommandLine = "wevtutil clear-log $LogName 2>&1 | Out-Null"
	LogDebug ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportSingleEventLog{
	<# 
	.SYNOPSIS
		Exports single Event Log in evtx format
	.DESCRIPTION
		global:FwExportSingleEventLog expects 3 parameters: $LogName, $FileName and $Overwrite (true or false)
	.EXAMPLE
		to execute this command: wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" "c:\Capi2_Oper.evtx" /overwrite:true
		you need to call: global:FwExportSingleEventLog "Microsoft-Windows-CAPI2/Operational" "c:\Capi2_Oper.evtx" "true"
	.NOTES
		Date:   01.04.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogName,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FileName,
		[parameter(Mandatory=$false)]
		[String]$Overwrite
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If([string]::IsNullOrEmpty($Overwrite)){
		$CommandLine = "wevtutil export-log $LogName $FileName 2>&1 | Out-Null"
	}
	else
	{
		$CommandLine = "wevtutil export-log $LogName $FileName /overwrite:$Overwrite 2>&1 | Out-Null" 
	}
	LogDebug ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function global:FwExportEventLog{
	#we# ToDo: - better consolidate FwExportSingleEventLog and FwExportEventLog into one function
	#		   - currently Get-Winevent produces different results on Win11 and Srv2022, maybe related to bug #35871962 - Problems with PowerShell EventLogReader command ..
	<# .SYNOPSIS
		Exports one or more EventLogs in evtx format and calls FwExportEventLogWithTXTFormat (unless -noEventConvert)
	.DESCRIPTION
		global:FwExportEventLog expects 2 mandatory parameters: $EventLogArray and 2 optional parameters $ExportFolder, $NoExportWithText
	.EXAMPLE
		FwExportEventLog @("Microsoft-Windows-NTFS/Operational","Microsoft-Windows-NTFS/WHC") $global:LogFolder
	#>
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[Array]$EventLogArray,
		[Parameter(Mandatory=$False)]
		[ValidateNotNullOrEmpty()]
		[String]$ExportFolder = $global:LogFolder, #we# add default
		[Parameter(Mandatory=$False)]
		[Switch]$NoExportWithText,
		[Parameter(Mandatory=$False)]
		[Int]$DaysBack=0
	)
	EnterFunc $MyInvocation.MyCommand.Name
	# By default, use $EvtDaysBack(script parameter). But if $DaysBack is passed, use it.
	If($DaysBack -eq 0){
		$DaysBack = $EvtDaysBack 
	}
	$EventLogs = @()
	ForEach($EventLogCandidate in $EventLogArray){
		$EventObject = $Null
		$EventObject = Get-Winevent -ListLog $EventLogCandidate -ErrorAction Ignore
		If($Null -ne $EventObject){
			LogDebug ("Adding $EventLogCandidate to export list")
			$EventLogs +=$EventLogCandidate
		}Else{
			LogDebug ("[EventLog] $EventLogCandidate does not exist or `'Get-Winevent -ListLog`' failed.")
			LogInfoFile "[EventLog] $EventLogCandidate does not exist or `'Get-Winevent -ListLog`' failed."
		}
	}
	ForEach($EventLog in $EventLogs){
		$EventLogFileName = $EventLog -replace "/","-" -replace " ","-" 	#we# fix space in EvtLog
		If(Test-Path -Path "$ExportFolder\$env:computerName-$EventLogFileName.evtx"){
			LogInfo "[EventLog] $env:computerName-$EventLogFileName.evtx already exist. Skipping exporting the event log." "Gray"
			Continue
		}
		$Commands =@(
			"wevtutil epl `"$EventLog`" `"$ExportFolder\$env:computerName-$EventLogFileName.evtx`"",
			"wevtutil al `"$ExportFolder\$env:computerName-$EventLogFileName.evtx`" /l:en-us"
		)
		LogInfo "[EventLog] Exporting $EventLog"
		RunCommands "FwExportEventLog" $Commands -ThrowException:$False -ShowMessage:$False -ShowError:$True
		If(!$NoExportWithText){
			If(!($global:BoundParameters.ContainsKey('noEventConvert'))){
				if (($EventLog -ne "Security") -and ($DaysBack -ne 0)) {	# part1 of issue #510, skipping Security Eventlog as it takes usually a very long time
					# Export event log with text format
					FwExportEventLogWithTXTFormat $EventLog $ExportFolder -DaysBack $DaysBack
				}
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportEventLogWithTXTFormat{
	<#
	.SYNOPSIS
		Export event log with text format
	.DESCRIPTION
		global:FwExportEventLogWithTXTFormat expects 2 parameters: $EventLogName, $ExportFolder
		This function is also called from FwExportEventLog.
	.PARAMETER EventLogName
	 Event log name to be converted to txt file.
	.PARAMETER ExportFolder
	 Folder name converted event log is stored.
	.EXAMPLE
		To export event with text format:
		global:FwExportEventLogWithTXTFormat "Microsoft-Windows-TWinUI/Operational" "$global:LogFolder\XXX"
	.NOTES
		Date:   21.04.2021
	#>
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $EventLogName,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $ExportFolder,
		[Parameter(Mandatory=$False)]
		[Int]$DaysBack=0
	)
	EnterFunc $MyInvocation.MyCommand.Name

	# By default, use $EvtDaysBack(script parameter). But if $DaysBack is passed, respect the passed $DaysBack and use it.
	If($DaysBack -eq 0){
		$DaysBack = $EvtDaysBack 
	}
	# Use below logic based on https://github.com/shared-internal-tools/WindowsCSSToolsDevRep/issues/64
	$ExportLogName = $EventLogName -replace "/","-" -replace " ","-"  # #we# # XXX/Operational => XXX-Operational
	$EventTXTFile	= "$ExportFolder\$env:computerName-$ExportLogName" + ".txt"
	$tmpEventFile	= "$ExportFolder\$env:computerName-$ExportLogName" + ".csv"
	$EventLogDaysBack = (get-date).AddDays(-$DaysBack)	#we# part2 of issue #510
	$Command = "Get-WinEvent -Oldest -FilterHashTable @{LogName = `"$EventLogName`";StartTime = `"$EventLogDaysBack`";} -ErrorAction Ignore | Select-Object LevelDisplayName,TimeCreated,ProviderName,ID,UserId,Message | Export-Csv -path $tmpEventFile -UseCulture -NoTypeInformation -Encoding utf8"
	#we# $Command = "Get-WinEvent -Oldest -LogName `"$EventLogName`" -ErrorAction Ignore | Select-Object LevelDisplayName,TimeCreated,ProviderName,ID,UserId,Message | Export-Csv -path $tmpEventFile -UseCulture -NoTypeInformation -Encoding utf8"
	Try{
		LogInfoFile "[EventLog] Converting $EventLogName to *.txt format (last $DaysBack days)." -ShowMsg
		$durationCSV = Measure-Command { RunCommands "FwExportEventLogWithTXTFormat" $Command -ThrowException:$True -ShowMessage:$False -ShowError:$True }
	}Catch{
		LogException "Error happened in Get-WinEvent for $EventLogName" $_
		Return
	}

	$durationTXT = Measure-Command {
		# $tmpEventFile is csv. Hence remove comma and double quotes
		$tmp = $(Get-Content "$tmpEventFile") -replace ('^"','')
		$tmp = $tmp -replace ('","',"`t") # replace comma with tab space.
		$tmp = $tmp -replace ('",,"',"") # This happens in Security event log
		$tmp = $tmp -replace ('"$',"") # double quotes at line end.
		$tmp | Out-File -FilePath $EventTXTFile
		#Remove-Item $tmpEventFile -ErrorAction Ignore
	}

	LogInfoFile "[EventLog] Converting last $DaysBack days of $EventLogName event log to text format has completed. Duration .CSV: $durationCSV - Duration .TXT: $durationTXT"
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwSetEventLog{
	<#
	.SYNOPSIS
		Set a event log property and enable the event log, used for non-classic (System,Application,Security,Setup) Eventlogs (see below #we# ADO #259)
	.DESCRIPTION
		Sets a event log property such as eventlog size and enable the event log.
		global:FwSetEventLog expects 3 parameters: $EventLogName(Mandatory), $EvtxLogSize(Optional), $ClearLog(Optional)
		This function changes a event log settings but before changing them, it preserves the previous setting. 
		If you need to restore the setting, you can use FwResetEventLog to set the setting back to the previous setting.
	.PARAMETER EventLogName
		Array of the event log name that setting to be changed.
	.PARAMETER EvtxLogSize
		Maxmum size in byte of event log to be set. EvtxLogSize is also configurable through config parameter '_EvtxLogSize'.
	.PARAMETER ClearLog
		Exports eventlog to "$LogFolder\SavedEventLog" folder and then clear the event log before enabling the event log.
	.EXAMPLE
		FwSetEventLog "Microsoft-Windows-CAPI2/Operational" -EvtxLogSize:102400000 -ClearLog
			 or
		$global:EvtLogsPowerShell = @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
		FwSetEventLog $global:EvtLogsPowerShell
	.NOTES
		Date:   07.09.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[String[]]$EventLogNames,
		[parameter(Mandatory=$false)]
		[Int]$EvtxLogSize=0,  # Max eventlog size in byte with Integer
		[parameter(Mandatory=$false)]
		[Switch]$ClearLog=$False
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$SavedLogFolder = "$global:LogFolder\SavedEventLog"
	ForEach ($EventLogName in $EventLogNames){
		If(Test-Path -PathType Container "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$EventLogName"){ #we# ADO #259
			Try{
				$logDetails = Get-LogProperties -Name $EventLogName -ErrorAction Stop
			}Catch{
				$ErrorMessage = '[FwSetEventLog] An Exception happened in Get-LogProperties.' + 'HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + 'Exception=' + $_.CategoryInfo.Reason + ' Eventlog=' + $EventLogName
				LogException $ErrorMessage $_ $fLogFileOnly
				Throw($ErrorMessage)
			}
			
			# Before enabling and changing the log settings, we remember all previous settings by copying registry.
			Try {
				# Save registry key for this event log.
				If(!(Test-Path "$global:TSSRegKey\EventLog")){
					RunCommands "FwSetEventLog" "New-Item -Path `"$global:TSSRegKey\EventLog`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
				}
				
				If(Test-Path -PathType Container "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$EventLogName"){
					RunCommands "FwSetEventLog" "Copy-Item -Path `"HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$EventLogName`" -Destination `"$global:TSSRegKey\EventLog`" -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
				}Else{
					LogInfoFile "[FwSetEventLog] Registry for $EventLogName was not found." -ShowMsg
				}
				
				# If the log is enabled, we disable it first since some of changes will get error if the log is enabled.
				If($logDetails.Enabled){
					# Currently the event log is already enabled. In this case, we disable it first and enable it later.
					$logDetails.Enabled = $False
					LogInfoFile "[FwSetEventLog] Disabling $EventLogName as it has been already enabled." -ShowMsg
					Set-LogProperties -LogDetails $logDetails -Force -ErrorAction Stop | Out-Null
			
					# In case of Analytic log and if it's already enabled, we save it to 'SavedEventLog' folder before making change
					If($logDetails.Type -eq "Analytic" -or $logDetails.Type -eq "Debug"){
						# Save the log and clear it.
						$EventProperty = Get-Winevent -ListLog $EventLogName
						$EventLogFileName = Split-Path $EventProperty.LogFilePath -Leaf
						If(Test-Path -Path "C:\Windows\System32\Winevt\Logs\$EventLogFileName"){
							FwCreateLogFolder $SavedLogFolder
							LogInfoFile "[FwSetEventLog] Saving previously enabled analytic log to $SavedLogFolder" -ShowMsg
							Copy-Item "C:\Windows\System32\Winevt\Logs\$EventLogFileName" $SavedLogFolder
						}Else{
							Write-Host "C:\Windows\System32\Winevt\Logs\$EventLogFileName"
						}
					}
				}
			
				# First if $ClearLog is specified, save the log and clear it.
				If($ClearLog){
					if (!(Test-PAth $SavedLogFolder)) {FwCreateLogFolder $SavedLogFolder}
					$tmpStr = $EventLogName.Replace('/','-')
					$SavedEventLogName = ($tmpStr.Replace(' ','-') + '.evtx')
					# Save the log and clear it.
					If(!(Test-Path $global:LogFolder\SavedEventLog\$SavedEventLogName)){ #we# skip saving same EventLog multiple times
						LogInfoFile "[FwSetEventLog] Saving and clearing $EventLogName"
						$Commands = @(
							"wevtutil epl $EventLogName $SavedLogFolder\$SavedEventLogName 2>&1 | Out-Null",
							"wevtutil clear-log $EventLogName"
						)
						RunCommands "FwSetEventLog" $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
					}
				}
			
				# If event log size(_EvtxLogSize) is set through tss_config file, use it(default is 100MB).
				If(!([string]::IsNullOrEmpty($global:FwEvtxLogSize))){ 
					$EvtxLogSize = $global:FwEvtxLogSize
				}
			
				# Setting log size
				If($EvtxLogSize -ne 0){
					# $EvtxLogSize should be larger than 1028KB.
					If($EvtxLogSize -lt 1052672){
						$DefaultMinLogSize = 1028*1024
						LogInfoFile "Specified size($EvtxLogSize) is too small and set it with $DefaultMinLogSize(default minimum size)" -ShowMsg
						$EvtxLogSize = $DefaultMinLogSize
					}
					$logDetails.MaxLogSize = $EvtxLogSize
					$EvtxLogSizeinKB = [Math]::Floor($EvtxLogSize/1024)
					LogInfoFile "[FwSetEventLog] Setting EvtxLogSize to $EvtxLogSize($($EvtxLogSizeinKB)KB) for $EventLogName" -ShowMsg
					Set-LogProperties -LogDetails $logDetails -Force -ErrorAction Stop | Out-Null
				}
			
				# Enabling the log.
				LogInfoFile "[FwSetEventLog] Enabling $EventLogName" -ShowMsg
				$logDetails.Enabled = $True
				Set-LogProperties -LogDetails $logDetails -Force -ErrorAction Stop | Out-Null
			} Catch {
				$ErrorMessage = '[FwSetEventLog] ERROR: Encountered an error during changing event log ' + $EventLogName
				LogException $ErrorMessage $_ $fLogFileOnly
				Throw($ErrorMessage)
			}
		}else{LogInfoFile "[FwSetEventLog] Registry for $EventLogName was not found." "Magenta" -ShowMsg}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwResetEventLog{
	<#
	.SYNOPSIS
		Restore event log setting by using previously saved data by FwSetEventLog().
	.DESCRIPTION
		Restores event log settings that was changed previously by FwSetEventLog()
		global:FwResetEventLog expects 1 parameters: $EventLogName(Mandatory).
		FwSetEventLog() saves previous event log setting to under "HKCU:\Software\Microsoft\TSSv2\EventLog" registry.
		This function restores the settings by using the registry. If there is no registry, this function returns immediately.
	.PARAMETER EventLogName
		Array of event log name.
	.EXAMPLE
		FwResetEventLog "Microsoft-Windows-CAPI2/Operational"
			or
		$global:EvtLogsPowerShell = @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
		FwResetEventLog $global:EvtLogsPowerShell
	.NOTES
		Date:   07.09.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[String[]]$EventLogNames
	)
	EnterFunc $MyInvocation.MyCommand.Name
	ForEach ($EventLogName in $EventLogNames){
		LogDebug ("Restoring event log setting for $EventLogName")
		Try{
			$regKey = Get-Item "$global:TSSRegKey\EventLog\$EventLogName" -ErrorAction Stop 
		}Catch{
			# It seems no change was made when SetEventLog. So just return.
			LogWarn "FwResetEventLog was called but there was no saved setting data for $EventLogName."
			Return
		}
		
		Try{
			$logDetails = Get-LogProperties -Name $EventLogName -ErrorAction Stop
		}Catch{
			$ErrorMessage = '[ResetEventLog] An exception happened in Get-LogProperties.'  + 'HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + 'Exception=' + $_.CategoryInfo.Reason + ' Eventlog=' + $EventLogName
			LogException $ErrorMessage $_ $fLogFileOnly
			Throw($ErrorMessage)
		}
		
		# If the log is enabled, we disable it first since some of changes will get error if the log is enabled.
		If($logDetails.Enabled){
			$logDetails.Enabled = $False
			LogInfoFile "[FwResetEventLog] Disabling $EventLogName."
			Set-LogProperties -LogDetails $logDetails -Force -ErrorAction Stop | Out-Null
		}
		
		# Get values in registry that were previously saved by FwSetEventLog()
		$Enabled = $regKey.GetValue("Enabled")
		$MaxLogSize = $regKey.GetValue("MaxSize")

		# Disable log here as the log is originally disabled.
		# If the log is originally enabled, we don't re-enable it here, as log export might happen later and that could fail if we enable log here.
		# Therefore, the logs that is originally enabled are enabled after all data collections are completed, which means we re-enable log if $Script:DataCollectionCompleted=$True.
		If(!$Enabled -or ($Enabled -and $Script:DataCollectionCompleted)){
			Try{
				LogInfoFile "[FwResetEventLog] Restoring setting of $EventLogName with Enabled=$Enabled and MaxSize=$MaxLogSize"
				
				# Restoring log size.
				$logDetails.MaxLogSize = $MaxLogSize
				Set-LogProperties -LogDetails $logDetails -Force | Out-Null
				
				# Enable or Disable the log depending on previous setting.
				$logDetails.Enabled = $Enabled
				If($Enabled){
					LogInfoFile "Re-enabling $EventLogName as it was previously enabled."
				}
				Set-LogProperties -LogDetails $logDetails -Force | Out-Null
				
				# Remove the registry only for this event log.
				Remove-Item -Path "$global:TSSRegKey\EventLog\$EventLogName" -Recurse -ErrorAction Ignore | Out-Null 
			}Catch{
				$ErrorMessage = '[ResetEventLog] ERROR: Encountered an error during restoring event log. Eventlog=' + $EventLogName + ' Command=' + $_.CategoryInfo.Activity + ' HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + ' Exception=' + $_.CategoryInfo.Reason
				LogException $ErrorMessage $_ $fLogFileOnly
				Throw($ErrorMessage)
			}
		}Else{
			LogInfoFile "[FwResetEventLog] $EventLogName will be reset to Enabled=$Enabled and MaxSize=$MaxLogSize later"
		}
	}
	# If there is no entry under 'EventLog' registry, delete the top 'TSS' registry
	If($Null -eq (get-childitem "$global:TSSRegKey\EventLog")){
		Remove-Item -Path "$global:TSSRegKey\EventLog" -Recurse -ErrorAction Ignore | Out-Null #we# commented in order to keep EulaAccepted, but now EULA is in "HKCU:Software\Microsoft\CESDiagnosticTools"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwResetAllEventLogs{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Getting list of event logs to reset."
	$EventLogNames = Get-ChildItem "$global:TSSRegKey\EventLog" -ErrorAction Ignore
	If($EventLogNames.count -eq 0){
		LogDebug "No event log in $global:TSSRegKey"
	}Else{
		LogInfoFile "Resetting below event logs." -ShowMsg
		ForEach($EventLogName in $EventLogNames){
			LogInfoFile "  - $($EventLogName.PSChildName)" -ShowMsg
		}
		global:FwResetEventLog $EventLogNames.PSChildName
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwAddEvtLog {
	<#
	.SYNOPSIS
		Adds new Event Log to the list of Event Logs to be collected
	.DESCRIPTION
		Adds new Event Log item to the list of Event Logs to be collected at TssPhase
	.EXAMPLE
		FWaddEvtLog @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
		POD/module specific groups of EvtLogs can be defined in <_POD.psm1> #region groups of Eventlogs
	#>
	Param(
		[Parameter(Mandatory=$True)]
		[String[]]$AddToEvtLogNames,# which Evt name(s) to add to $global:EvtLogNames
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase	# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] adding Eventlog(s) $AddToEvtLogNames at $TssPhase" -ShowMsg
	$global:EvtLogNames += $AddToEvtLogNames
	#LogInfoFile "___ after global:FWaddEvtLog, list: $global:EvtLogNames"
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetEvtLogList {
	<# 
	.SYNOPSIS 
		Bulk Collecting Eventlogs at Collect Phase
	.DESCRIPTION
		You can add Eventlogs to this list using function FWaddEvtLog
	.EXAMPLE
		FwGetEvtLogList _Stop_
	#>
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if ($global:EvtLogNames.count -gt 0){
		LogInfo "[$($MyInvocation.MyCommand.Name)] Processing Eventlogs at $TssPhase"
		LogInfoFile "Eventlog List at $TssPhase : $global:EvtLogNames"
		$global:EvtLogNames = $global:EvtLogNames |Sort-Object -Unique
		LogInfoFile "___ UniqueEvtList at $TssPhase : $global:EvtLogNames"
		FwExportEventLog $global:EvtLogNames $global:LogFolder
		LogInfoFile "___ done all Eventlog collections"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwEvtLogDetails{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $LogName,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $LogFolderPath
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile ("[EventLog] Collecting the details for the " + $LogName + " log") -ShowMsg
	$Commands = @(
		"wevtutil gl `"$LogName`" | Out-File -Append  $LogFolderPath\EventLogs.txt",
		"wevtutil gli `"$LogName`" | Out-File -Append  $LogFolderPath\EventLogs.txt"
	)
	RunCommands "FwEvtLogDetails" $Commands -ThrowException:$False -ShowMessage:$True
	"" | Out-File -Append "$LogFolderPath\EventLogs.txt"

	If($logname -ne "ForwardedEvents"){
		Try{
			LogInfoFile ("[EventLog] Running Get-WinEvent -Logname $LogName -MaxEvents 1 -Oldest") -ShowMsg
			$evt = (Get-WinEvent -Logname $LogName -MaxEvents 1 -Oldest -ErrorAction Stop)
			"Oldest " + $evt.TimeCreated + " (" + $evt.RecordID + ")" | Out-File -Append "$LogFolderPath\EventLogs.txt"
			LogInfoFile ("[EventLog] Running Get-WinEvent -Logname $LogName -MaxEvents 1") -ShowMsg
			$evt = (Get-WinEvent -Logname $LogName -MaxEvents 1 -ErrorAction Stop)
			"Newest " + $evt.TimeCreated + " (" + $evt.RecordID + ")" | Out-File -Append "$LogFolderPath\EventLogs.txt"
			"" | Out-File -Append "$LogFolderPath\EventLogs.txt"
		}Catch{
			LogErrorFile ("An error happend during getting event log for $LogName")
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

#region --- FwBasicLog functions & common helper functions
function global:FwClearCaches {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] deleting DNS, NetBIOS, Kerberos and DFS caches at $TssPhase" -ShowMsg
	$Commands = @(
		"IPconfig /flushDNS"
		"NBTstat -RR"
		"$($env:windir)\system32\KLIST.exe purge -li 0x3e7"
		"$($env:windir)\system32\KLIST.exe purge"
	)
	if (Test-Path $DFSutilPath) {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'DFSutil.exe /PKTflush' at $TssPhase" -ShowMsg
		$Commands += "DFSutil.exe /PKTflush"
	}else{LogWarn "[$($MyInvocation.MyCommand.Name)] 'DFSutil.exe' not found in PATH"}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwCopyWindirTracing { 
	Param(
		[Parameter(Mandatory=$True)]
		[String]$ToLogSubFolder
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] copying '$Env:SystemRoot\tracing' $ToLogSubFolder logs" -ShowMsg
	$Commands = @(
		"xcopy /s/e/i/q/y $Env:SystemRoot\tracing $global:LogFolder\$ToLogSubFolder"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwDoCrash {
	EnterFunc $MyInvocation.MyCommand.Name
	If($global:BoundParameters.ContainsKey('Crash') -and !$global:BoundParameters.ContainsKey('noCrash')){
		if (!$noCrash.IsPresent) {
			$Script:IsCrashInProgress = $True
			$NotMyFault = Get-Command $global:NotMyFaultPath -ErrorAction Ignore
			If($Null -eq $NotMyFault){
				LogError "$global:NotMyFaultPath not found."
				Return
			}
			LogInfo "[$($MyInvocation.MyCommand.Name)] ##### forcing a memory dump/crash now using '$global:NotMyFaultPath /crash' #####" "Magenta"
			LogInfo "[$($MyInvocation.MyCommand.Name)] Please run command '$DirScript\TSS.ps1 -stop -noCrash' after reboot and collect $env:SystemRoot\memory.dmp." "Magenta"
			$Commands = @(
				"$global:NotMyFaultPath /AcceptEula /crash 0x07"
			)
			Close-Transcript -ShowMsg
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetCertsInfo { 
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,	# _Start_ or _Stop_
		[String]$CertMode,						# optional mode: Full or Basic
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Get certificates and credentials with CertUtil.exe at $TssPhase  ...may take some minutes" -ShowMsg
	LogInfo "`n[$($MyInvocation.MyCommand.Name)] certutil.exe can take some time in big environments, please wait..." "Cyan"

	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Credman" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Credman.txt"}
	"===== $(Get-Date) : List available credentials: cmdkey.exe /list " | Out-File -Append $outFile
	logLine $outFile
	$Commands = @(
		"$Sys32\cmdkey.exe /list | Out-File -Append $outFile"
		"$Sys32\certutil.exe -v -silent -enterprise -store NTAuth | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_NTAuth-store.txt"
		"$Sys32\certutil.exe -v -silent -enterprise -store root | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-Root-AD-store.txt"
		"$Sys32\certutil.exe -v -silent -store root | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-Root-Registry-store.txt"
		"$Sys32\certutil.exe -v -silent -store CA | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-CA-Registry-store.txt"
	)
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Cert_machine-store" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Cert_machine-store.txt"}
	"======== certutil.exe might take some minutes ... =============================================" | Out-File -Append $outFile
	$Commands += @("$Sys32\certutil.exe -v -silent -store my | Out-File -Append $outFile")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	if ( $CertMode -ieq "Full") {
		$Commands = @(
			"$Sys32\certutil.exe -v -silent -user -store my | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_user-store.txt"
			"$Sys32\certutil.exe -v -silent -scinfo | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_ScInfo.txt"
			"$Sys32\certutil.exe -tpminfo | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_TpmInfo.txt"
			"$Sys32\certutil.exe -v -silent -user -store my 'Microsoft Smart Card Key Storage Provider' | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_My_SmartCard.txt"
			"$Sys32\certutil.exe -v -silent -user -key -csp 'Microsoft Passport Key Storage Provider' | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_MPassportKey.txt"
			"$Sys32\certutil.exe -v -silent -store 'Homegroup Machine Certificates' | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Homegroup-Machine-Store.txt"
			"$Sys32\certutil.exe -v -silent -enterprise -store CA | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-CA-AD-store.txt"
			"$Sys32\certutil.exe -v -silent store authroot | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-ThirdParty-store.txt"
			"$Sys32\certutil.exe -v -silent -store -grouppolicy root | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-GP-Root-Store.txt"
			"$Sys32\certutil.exe -v -silent -store -grouppolicy CA | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-GP-CA-Store.txt"
			"$Sys32\wevtutil.exe query-events Application `"/q:*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll']]]`" | Out-File -Append $global:LogFolder\$($LogPrefix)CertificateServicesClientLog.xml"
			"$Sys32\certutil.exe -policycache `"$global:LogFolder\$($LogPrefix)CertificateServicesClientLog.xml`" | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_ReadableClientLog.txt"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		#wevtutil.exe  query-events Application "/q:*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll']]]" > "$global:LogFolder\$($LogPrefix)CertificateServicesClientLog.xml" 2>&1 | Out-Null
		#certutil.exe  -policycache "$global:LogFolder\$($LogPrefix)CertificateServicesClientLog.xml" > "$global:LogFolder\$($LogPrefix)Cert_ReadableClientLog.txt" 2>&1 | Out-Null
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwCheckAuthenticodeSignature{
	Param(
	[Parameter(Mandatory=$False)]
	[String]$TssPhase = $pathToCheck,				# 
	[Parameter(Mandatory=$False)]
	[String]$resultOutputDir						# resulting output folder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	If($resultOutputDir){
		if (test-path $resultOutputDir -ErrorAction SilentlyContinue) {
			$issuerInfo = "$resultOutputDir\issuerInfo.txt"
		}else{
			$issuerInfo = "$global:LogFolder\issuerInfo.txt"
		}
	}else{$issuerInfo = "$global:LogFolder\issuerInfo.txt"}
	If ($pathToCheck) {
		if (Test-Path -path $pathToCheck -ErrorAction SilentlyContinue) {
			$AuthenticodeSig = (Get-AuthenticodeSignature -FilePath $pathToCheck)
			$cert = $AuthenticodeSig.SignerCertificate
			$FileInfo = (get-command $pathToCheck).FileVersionInfo			
			$issuer = $cert.Issuer
			#OS is older than 2016 and some built-in processes will not be signed
			if (($OSBuild -lt 14393) -and (!$AuthenticodeSig.SignerCertificate)) {
				if (($FileInfo.CompanyName -eq "Microsoft Corporation")) {
					return
				}else{
					Write-Error "Script execution terminated because a process or script that does not have any signature was detected" | Out-File $issuerInfo -append
					$pathToCheck | Out-File $issuerInfo -append
					$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
					$cert | Format-List * | Out-File $issuerInfo -append
					[Environment]::Exit(1)
				}
			}
			#check if valid
			if ($AuthenticodeSig.Status -ne "Valid") {
				Write-Error "Script execution terminated because a process or script that does not have a valid Signature was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}
			#check issuer
			if (($issuer -ne "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Development PCA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")) {
				Write-Error "Script execution terminated because a process or script that is not Microsoft signed was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}	
			if ($AuthenticodeSig.IsOSBinary -ne "True") {
				#If revocation is offline then test below will fail
				$IsOnline = (Get-NetConnectionProfile).IPv4Connectivity -like "*Internet*"
				if ($IsOnline) {
					$IsWindowsSystemComponent = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.10.3.6" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable OsCertWarnVar -ErrorVariable OsCertErrVar)
					$IsMicrosoftPublisher = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.76.8.1" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable MsPublisherWarnVar -ErrorVariable MsPublisherErrVar)
					if (($IsWindowsSystemComponent -eq $False) -and ($IsMicrosoftPublisher -eq $False)) {
						#Defender AV and some OS processes will have an old signature if older version is installed
						#Ignore if cert is OK and only signature is old
						if (($OsCertWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($MsPublisherWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($OsCertWarnVar -like "*CERT_TRUST_IS_OFFLINE_REVOCATION*") -or ($MsPublisherWarnVar -like "CERT_TRUST_IS_OFFLINE_REVOCATION")) {
							return
						}
						Write-Error "Script execution terminated because the process or script certificate failed trust check" | Out-File $issuerInfo -append
						$pathToCheck | Out-File $issuerInfo -append
						$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
						$cert | Format-List * | Out-File $issuerInfo -append
						[Environment]::Exit(1)
					}
				}
			}
		}else{
			Write-Error ("Path " + $pathToCheck + " was not found") | Out-File $issuerInfo -append
		}
	}
}

function global:FwCheck-Command-verified($checkCommand) {
	#gets path of command and check signature
	$command = Get-Command $CheckCommand -ErrorAction SilentlyContinue
	FwCheckAuthenticodeSignature $command.path
}

function global:FwGetDFScache {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if (Test-Path $DFSutilPath) {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'DFSutil.exe' commands at $TssPhase" -ShowMsg
		$outFile = $PrefixTime + "DFScache" + $TssPhase + ".txt"
		$Commands = @(
			"DFSutil.exe /PKTinfo | Out-File -Append $outFile"
			"DFSutil.exe /SPCinfo | Out-File -Append $outFile"
			"DFSutil.exe /displayMupCache | Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}else{LogWarn "[$($MyInvocation.MyCommand.Name)] 'DFSutil.exe' not found in PATH"}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetEnv {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Get Environment settings" -ShowMsg
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Env" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Env.txt"}
	(Get-ChildItem env:*).GetEnumerator() | Sort-Object Name | Out-File -FilePath $outFile -Append -Encoding ascii -Width 200
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetGPresultAS { 
	# - GPresult, Auditing and Security - hint consider 'gpresult /r /v /scope computer|user'
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:noGPresult -ne $true) {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'AuditPol', 'SecEdit', 'GPresult /h /v' at $TssPhase" -ShowMsg
		LogInfo "`n[$($MyInvocation.MyCommand.Name)] GPresult can take some time in big environments, please wait..." "Cyan"
		$Commands = @(
			"AuditPol.exe /get /category:* | Out-File -Append $global:LogFolder\$($LogPrefix)AuditPol$TssPhase.txt"
			"SecEdit /export /cfg $global:LogFolder\$($LogPrefix)SecEdit$TssPhase.txt"
			"GPresult.exe /h $global:LogFolder\$($LogPrefix)GPresult-H$TssPhase.htm /f"
			"GPresult.exe /v | Out-File $global:LogFolder\$($LogPrefix)GPresult-V_$env:username`_$TssPhase.txt"
			"GPresult.exe /r | Out-File $global:LogFolder\$($LogPrefix)GPresult-R_$env:username`_$TssPhase.txt"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		LogInfoFile " *** [Hint] GPO lookup: https://gpsearch.azurewebsites.net/" "Cyan" -ShowMsg
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetKlist {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'KLIST.exe' at $TssPhase" -ShowMsg
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "kList_Tickets" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_kList_Tickets.txt"}
	$Commands = @(
		"$($env:windir)\system32\KLIST.exe 				| Out-File -Append $outFile"
		"$($env:windir)\system32\KLIST.exe -li 0x3e7 	| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
	
function global:FwGetMsInfo32 {
	<# 
	.SYNOPSIS 
		 collects MsInfo32 in .nfo and/or .txt format; use FwWaitForProcess to wait for background process completion
	#>
	Param(
		[Parameter(Mandatory=$False)]
		[String[]]$Formats=@("nfo","txt"),					# default is .nfo and .txt format, use "txt" to collect only msinfo.txt,
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder									# optional subfolder-name
	)
	EnterFunc $MyInvocation.MyCommand.Name
	# instead of msinfo32.exe consider PS command: Get-ComputerInfo
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Collecting MsInfo32 in '$Formats' format(s) at $TssPhase" -ShowMsg
	$ExeFile = "msinfo32.exe"
	if (test-path (join-path ([Environment]::GetFolderPath("System")) $ExeFile)){
			$MsInfo32Path = (join-path ([Environment]::GetFolderPath("System")) $ExeFile)
	}
	ForEach($Format in $Formats){
		if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "msinfo32.$Format"}else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_msinfo32.$Format"}
		if ($Format -match "txt"){
			$ArgumentList = " /report `"$outFile`""
			LogInfo ".. starting msinfo32.exe $ArgumentList"
			$global:msinfo32TXT = Start-Process -FilePath 'msinfo32' -ArgumentList $ArgumentList -PassThru
		}
		if ($Format -match "nfo"){
			$ArgumentList = " /nfo `"$outFile`""
			LogInfo ".. starting msinfo32.exe $ArgumentList"
			$global:msinfo32NFO = Start-Process -FilePath 'msinfo32' -ArgumentList $ArgumentList -PassThru
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetNltestDomInfo {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if ((Get-CimInstance win32_computersystem).partofdomain -eq $true) {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] NLTEST Domain information at $TssPhase - Please be patient..." -ShowMsg
		LogInfo "`n[$($MyInvocation.MyCommand.Name)] NLTEST can take some time in big environments, please wait..." "Cyan"
		if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "NLTEST_DomInfo" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_NLTEST_DomInfo.txt"}
		$Commands = @(
			"nltest /dsgetsite 						| Out-File -Append $outFile"
			"nltest /dsgetdc: /kdc /force 			| Out-File -Append $outFile"
			"nltest /dclist: 						| Out-File -Append $outFile"
			"nltest /trusted_domains 				| Out-File -Append $outFile"
			"nltest /domain_trusts /ALL_TRUSTS /V 	| Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}else{
	  LogInfo "[$($MyInvocation.MyCommand.Name)] This machine is not domain-joined; at $TssPhase"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetPoolmon {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,	# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if ($global:noPoolMon -ne $True) {
		if (Test-Path $global:PoolmonPath) {
			LogInfoFile "[$($MyInvocation.MyCommand.Name)] running Poolmon.exe at $TssPhase" -ShowMsg
			if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Poolmon" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Poolmon.txt"}
			get-date | Out-File $outFile -Encoding ascii
			$Commands = @(
				"Poolmon.exe -t -b -r -n $outFile"
			)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}else{LogWarn "[$($MyInvocation.MyCommand.Name)] 'Poolmon.exe' not found in PATH"}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetProxyInfo {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Collecting Proxy settings 'winhttp show proxy' and Reg. settings at $TssPhase" -ShowMsg
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Proxy" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Proxy.txt"}
	$Commands = @(
		"netsh winhttp show proxy 					| Out-File -Append $outFile"
		"bitsadmin /util /getieproxy localsystem 	| Out-File -Append $outFile"
		"bitsadmin /util /getieproxy networkservice | Out-File -Append $outFile"
		"bitsadmin /util /getieproxy localservice 	| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwAddRegItem @("Proxy") $TssPhase
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:GetOwnerCim{
	Param( $prc )
	EnterFunc $MyInvocation.MyCommand.Name
	$ret = Invoke-CimMethod -InputObject $prc -MethodName GetOwner
	EndFunc ($MyInvocation.MyCommand.Name + "$($ret.Domain)" + "\" + "$($ret.User)")
	return ($ret.Domain + "\" + $ret.User)
}

Function global:GetOwnerWmi{
	Param( $prc )
	EnterFunc $MyInvocation.MyCommand.Name
	$ret = $prc.GetOwner()
	EndFunc ($MyInvocation.MyCommand.Name + "$($ret.Domain)" + "\" + "$($ret.User)")
	return ($ret.Domain + "\" + $ret.User)
}

Function global:FwListProcsAndSvcs {
	<# .SYNOPSIS
		The function will list running processes, services and FilesVersions in $global:LogFolder or under \$Subfolder
		P1: TssPhase
		P2: output subfolder
	#>
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if ([string]::IsNullOrEmpty($Subfolder)) { $outDir = $global:LogFolder}else{ $outDir = $global:LogFolder + "\" + $Subfolder }
	$proc = FwExecWMIQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, SessionId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath from Win32_Process"
	if ($PSVersionTable.psversion.ToString() -ge "3.0") {
		$StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
		$Owner = @{N="User";E={(GetOwnerCim($_))}}
	}else{
		$StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
		$Owner = @{N="User";E={(GetOwnerWmi($_))}}
	}
	# Processes
	if ($proc) {
		LogInfoFile "[ListProcsAndSvcs] Collecting processes details" -ShowMsg
		$proc | Sort-Object Name |
		Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name, @{e={$_.SessionId};n="Session"},
		@{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
		@{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
		@{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, $Owner, CommandLine |
		Out-String -Width 500 | Out-File -FilePath ($outDir + "\" + $global:LogPrefix + "Processes_overview$global:TssPhase.txt")
		# FilesVersions
		LogInfoFile "[ListProcsAndSvcs] Retrieving file version of running binaries" -ShowMsg
		$binlist = $proc | Group-Object -Property ExecutablePath
		foreach ($file in $binlist) {
			if ($file.Name) {
				FwFileVersion -Filepath ($file.name) | Out-File -FilePath ($outDir + "\" + $global:LogPrefix + "FilesVersions$global:TssPhase.csv") -Append
			}
		}
		# Services
		LogInfoFile "[ListProcsAndSvcs] Collecting services details" -ShowMsg
		$svc = FwExecWMIQuery -NameSpace "root\cimv2" -Query "select ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"
		if ($svc) {
			$svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
			Out-String -Width 400 | Out-File -FilePath ($outDir + "\" + $global:LogPrefix + "Services_overview$global:TssPhase.txt")
		}
		EndFunc ($MyInvocation.MyCommand.Name + "($true)")
		return $true  | Out-Null
	}else{
		EndFunc ($MyInvocation.MyCommand.Name + "($false)")
		return $false | Out-Null
	}
}

function global:FwGetQwinsta {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Collecting QWinSta status at $TssPhase" -ShowMsg
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "QWinSta" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_QWinSta.txt"}
	$Commands = @(
		"$Sys32\QWINSTA.exe | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetRegHives {
	Param(
#	   [Parameter(Mandatory=$False)]
#	   [String]$HiveList,
		[Parameter(Mandatory=$False)]
		[String]$TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if (-not (Test-Path "$PrefixTime`RegHive_Software.hiv")) {
		LogInfoFile "___ FwGetRegHives at $TssPhase"
		$Commands = @(
			"REG SAVE HKLM\SOFTWARE $PrefixTime`RegHive_Software.hiv /Y"
			"REG SAVE HKLM\SYSTEM $PrefixTime`RegHive_System.hiv /Y"
			"REG SAVE HKCU\SOFTWARE $PrefixTime`RegHive_Software_User.hiv /Y"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwRestartInOwnSvc {
	<# .SYNOPSIS
		The function will stop and restart a service in its own svchost
		Escpecially useful on downlevel OS, which start many services in a single svchost
	#>
	Param(
		[Parameter(Mandatory=$True)]
		[String]$ServiceName
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] restarting $ServiceName service in own svchost"
	$Commands = @(
		"Stop-Service -Name $ServiceName -Force"
		"SC config $ServiceName type= own"
		"Start-Service -Name $ServiceName"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetSrvSKU {
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		$IsServerSKU = (Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop).Caption -like "*Server*"
	}Catch{
		LogException "An exception happened in Get-CimInstance for CIM_OperatingSystem" $_ $fLogFileOnly
		$IsServerSKU = $False
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($IsServerSKU)")
	Return $IsServerSKU
}

function global:FwGetSrvRole {
	EnterFunc $MyInvocation.MyCommand.Name
	# get Windows Feature and Role
	If($IsServerSKU){
		$Commands = @(
			"Get-WindowsFeature -ErrorAction Stop | Out-File -Append $PrefixTime`Roles_Features_All.txt"
		)
		RunCommands "GetSrvRole" $Commands -ThrowException:$False -ShowMessage:$False
		Get-WindowsFeature | Where-Object {$_.installed -eq $true} | Out-File -Append $PrefixTime`Roles_Features_Installed.txt
	}else{
		If($OSBuild -ge 9200) {
			Get-WindowsOptionalFeature -Online | Format-Table -AutoSize | Out-File -Append $PrefixTime`Roles_Features_Optional.txt
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetSVC {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'SC.exe queryex type= all state= all' at $TssPhase" -ShowMsg
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Services" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Services.txt"}
	SC.exe queryex type= all state= all | out-file $outFile
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetSVCactive {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'NET START' at $TssPhase" -ShowMsg
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "ServicesActive" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_ServicesActive.txt"}
	NET START | out-file $outFile
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetSysInfo {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,		# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'systeminfo.exe' at $TssPhase" -ShowMsg
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "SystemInfo" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_SystemInfo.txt"}
	systeminfo.exe | out-file $outFile
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetTaskList {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'Tasklist.exe /FO csv /svc' at $TssPhase" -ShowMsg
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Tasklist" + $TssPhase }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Tasklist"}
	$outFileTXT = $outFile + ".txt"
	$outFileCSV = $outFile + ".csv"
	$outFileM = $PrefixTime + "Tasklist-M" + $TssPhase + ".txt"
	$Commands = @(
		"Tasklist.exe /FO csv /svc	| Out-File -Append $outFileCSV"
		"Tasklist.exe /svc 			| Out-File -Append $outFileTXT"
		"Tasklist.exe /v 			| Out-File -Append $outFileTXT"
	)
	RunCommands "TaskList" $Commands -ThrowException:$False -ShowMessage:$False
	if ($TssPhase -eq "_Stop_") {Tasklist.exe /M | Out-File -Append $outFileM}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetWhoAmI {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Collecting 'WhoAmI.exe -all' info at $TssPhase" -ShowMsg
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "WhoAmI" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_WhoAmI.txt"}
	$Commands = @(
		"whoami.exe -all | Out-File -Append $outFile"
	)
	RunCommands "WhoAmI" $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-SummaryVbsLog{
	Param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[Switch]$FullBasic,		# select -FullBasic to collect Full Basic data
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if (!$global:IsLiteMode) { 
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] running SummaryReliability.vbs" -ShowMsg
		if ([string]::IsNullOrEmpty($BasicLogFolder)) {$BasicLogFolder = $global:LogFolder }
		if ([string]::IsNullOrEmpty($Subfolder)) { $DestFolder = $BasicLogFolder}else{ $DestFolder = $global:LogFolder + "\"  + $Subfolder}
		If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
		$LogPrefix = $B_mode + "BasicLog-SummaryVbsLog"
		If (Test-Path -Path "$Scriptfolder\psSDP\Diag\global\SummaryReliability.vbs") {
			Try {
				LogInfo "[$LogPrefix] .. running SummaryReliability.vbs"
				Push-Location -Path $DestFolder
				$CommandToExecute = "cscript.exe //e:vbscript $Scriptfolder\psSDP\Diag\global\SummaryReliability.vbs /sdp"
				Invoke-Expression -Command $CommandToExecute | Out-Null
			} Catch {
				LogException "An Exception happend in SummaryReliability.vbs" $_
			}
			Pop-Location
			#cd "$PSScriptRoot"
		}Else{ LogInfo "[$LogPrefix] SummaryReliability.vbs not found - skipping"}
	}else{ LogInfo "Skipping FwGet-SummaryVbsLog in Lite mode"}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-OSversion-Build{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[BasicLog] Obtaining OS version with build number" # Note: #!# LogInfoFile would fail at this stage as $LogFolder does not exist
	$OutFile = $BasicLogFolder + "\OSVersion-Build.txt"
	$OSVersionReg = Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows NT\CurrentVersion'
	If($OperatingSystemInfo.OSVersion -ge 10){
		'OS Version: ' + $OSVersionReg.ReleaseID + '(OS Build ' + $OSVersionReg.CurrentMajorVersionNumber + '.' + $OSVersionReg.CurrentMinorVersionNumber + '.' + $OSVersionReg.CurrentBuildNumber + '.' + $OSVersionReg.UBR + ')' | Out-File -Append $OutFile
	}Else{
		'OS Version: ' + $OSVersionReg.CurrentVersion + '.' + $OSVersionReg.CurrentBuild | Out-File -Append $OutFile
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-basic-system-info{
	Param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[Switch]$FullBasic		# select -FullBasic to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
	$LogPrefix = $B_mode + "BasicLog-System"

	#------ Basic ------#
	LogInfo "[$LogPrefix] Obtaining system basic info using WMI"
	Get-CimInstance -Class Win32_Environment | Where-Object { $_.SystemVariable -eq 'True' } | Format-List Name,VariableValue | Out-File -Append $BasicLogFolder\Environment_SYSTEM.txt
	$Commands = @(
		# Basic
		"Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop | fl * | Out-File -Append $BasicLogFolder\OS_info.txt"
		"Get-CimInstance -Class CIM_ComputerSystem -ErrorAction Stop | fl * | Out-File -Append $BasicLogFolder\Computer_info.txt"
		# Hotfix
		"Get-HotFix | Sort-Object -Property InstalledOn | Out-File -Append $BasicLogFolder\hotfixes.txt"
		# User and profile
		"Whoami /user 2>&1 | Out-File -Append  $BasicLogFolder\Whoami.txt"
		"Get-CimInstance -Class Win32_UserProfile -ErrorAction Stop | Out-File -Append $BasicLogFolder\Win32_UserProfile.txt"
		"Get-ChildItem `'HKLM:Software\Microsoft\Windows NT\CurrentVersion\ProfileList`' -Recurse | Out-File -Append $BasicLogFolder\_Reg_Profilelist.txt"
		# Powercfg
		"PowerCfg.exe /list 2>&1 | Out-File -Append $BasicLogFolder\powercfg.txt"
		"PowerCfg.exe /a 2>&1 | Out-File -Append $BasicLogFolder\powercfg.txt"
		"PowerCfg.exe /qh 2>&1 | Out-File -Append $BasicLogFolder\powercfg.txt"
		# BCDEdit
		"bcdedit.exe /enum 2>&1 | Out-File -Append $BasicLogFolder\Bcdedit.txt"
		"bcdedit.exe /enum all 2>&1 | Out-File -Append $BasicLogFolder\Bcdedit-all.txt"
		"bcdedit.exe /enum all /v 2>&1 | Out-File -Append $BasicLogFolder\Bcdedit-all-v.txt"
		# Environment variables
		"Get-ChildItem env:| fl | Out-File -Append $BasicLogFolder\Environment_User.txt"
	)
	if ($FullBasic) {
		$Commands += @(
			# Basic
			"Get-CimInstance -Class CIM_Processor -ErrorAction Stop | fl * | Out-File -Append $BasicLogFolder\CPU_info.txt"
			# WER
			"Get-ChildItem `'HKLM:Software\Microsoft\Windows\Windows Error Reporting`' -Recurse | Out-File -Append $BasicLogFolder\_Reg_WER.txt"
			"Get-ItemProperty `'HKLM:System\CurrentControlSet\Control\CrashControl`' | Out-File -Append $BasicLogFolder\_Reg_Dump.txt"
			"Copy-Item `'C:\ProgramData\Microsoft\Windows\WER`' $BasicLogFolder -Recurse -ErrorAction SilentlyContinue"
			# KIR
			"Copy-Item `'C:\ProgramData\Microsoft\Windows\OneSettings\FeatureConfig.json`' $BasicLogFolder -Recurse -ErrorAction SilentlyContinue"
			"Copy-Item `'C:\ProgramData\Microsoft\Windows\OneSettings\FeatureConfig.bak.json`' $BasicLogFolder -Recurse -ErrorAction SilentlyContinue"
			"Get-Item `'C:\ProgramData\Microsoft\Windows\OneSettings\FeatureConfig.*`' | Select-Object FullName,LastWriteTime | Out-File -Append $BasicLogFolder\FeatureConfig_time.txt"
		)
	}
	# TPM
	If($global:OSVersion.Build -gt 9600){
		 $TPMObj = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -class win32_tpm -ErrorAction Ignore
		If($Null -ne $TPMObj){
			$Commands += "Get-Tpm -ErrorAction Ignore | Out-File -Append $BasicLogFolder\TPM.txt"
		}Else{
			Write-Output "TPM is not supported on this system." | Out-File -Append "$BasicLogFolder\TPM.txt"
		}
	}Else{
		$Commands += "Get-Tpm -ErrorAction Ignore | Out-File -Append $BasicLogFolder\TPM.txt"
	}
	# Windows feature
	FwGetSrvRole
	# CoreInfo
	$CoreInfoCommand = Get-Command "CoreInfo.exe" -ErrorAction Ignore
	If($Null -ne $CoreInfoCommand){
		$Commands += "CoreInfo.exe /AcceptEula | Out-File -Append $BasicLogFolder\CoreInfo.txt"
	}else{ LogInfoFile " CoreInfo.exe not found"}
	# Windows 10 Defender
	If($OperatingSystemInfo.OSVersion -ge 10){
		$Commands += @(
			"Get-MpComputerStatus -ErrorAction Stop | Out-File -Append $BasicLogFolder\WindowsDefender.txt",
			"Get-MpPreference -ErrorAction Stop | Out-File -Append $BasicLogFolder\WindowsDefender.txt"
		)
	}
	if ($FullBasic) {
		FwGetDSregCmd -Subfolder $script:BasicSubFolder
		# Process info, services info and file version
		FwListProcsAndSvcs -Subfolder $script:BasicSubFolder
		# Driver info
		$Commands += @("driverquery /v | Out-File $BasicLogFolder\driverinfo.txt")
	}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True
	# Product info
	Write-Output "===== 32bit applications =====" | Out-File "$BasicLogFolder\Installed_products.txt"
	Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File -Append "$BasicLogFolder\Installed_Products.txt"
	Write-Output "`n===== 64bit applications =====" | Out-File -Append "$BasicLogFolder\Installed_products.txt"
	Get-ItemProperty "HKLM:Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File -Append "$BasicLogFolder\Installed_Products.txt"
	# Tasklist
	LogInfo "[$LogPrefix] Creating process list..."
	$Processes = Get-Process
	Write-Output(' ID		 ProcessName') | Out-File -Append "$BasicLogFolder\tasklist.txt"
	Write-Output('---------------------------') | Out-File -Append "$BasicLogFolder\tasklist.txt"
	ForEach($Process in $Processes){
		$PID16 = '0x' + [Convert]::ToString($Process.ID,16)
		Write-Output(($Process.ID).ToString() + '(' + $PID16 + ')	'  + $Process.ProcessName) | Out-File -Append "$BasicLogFolder\tasklist.txt"
	}
	Write-Output('=========================================================================') | Out-File -Append "$BasicLogFolder\tasklist.txt"
	tasklist /svc 2>&1 | Out-File -Append "$BasicLogFolder\tasklist.txt"
	LogInfoFile "[$LogPrefix] Running tasklist -v" -ShowMsg
	tasklist /v 2>&1 | Out-File -Append "$BasicLogFolder\tasklist-v.txt"
	# .NET version
	If(test-path -path "HKLM:Software\Microsoft\NET Framework Setup\NDP\v4\Full"){
		$Full = Get-ItemProperty "HKLM:Software\Microsoft\NET Framework Setup\NDP\v4\Full"
		Write-Output(".NET version: $($Full.Version)") | Out-File -Append "$BasicLogFolder\DotNet-Version.txt"
		Write-Output("") | Out-File -Append "$BasicLogFolder\DotNet-Version.txt"
	}
	FwExportRegToOneFile $LogPrefix 'HKLM:Software\Microsoft\NET Framework Setup\NDP' "$BasicLogFolder\DotNet-Version.txt"
	# Installed .NET KB
	$DotNetVersions = Get-ChildItem HKLM:\Software\WOW6432Node\Microsoft\Updates | Where-Object {$_.name -like "*.NET Framework*"}
	ForEach($Version in $DotNetVersions){ 
		$Updates = Get-ChildItem $Version.PSPath
		$Version.PSChildName | Out-File -Append "$BasicLogFolder\Installed_DotNetKB.txt"
		ForEach ($Update in $Updates){
			$Update.PSChildName | Out-File -Append "$BasicLogFolder\Installed_DotNetKB.txt"
		}
	}
	# MSinfo32
	if ($FullBasic) {
		FwGetMsInfo32 "nfo" -Subfolder $BasicSubFolder
	}
	# Basic registry keys
	LogInfo "[$LogPrefix] Exporting registry hives"
	FwGetRegHives _Stop_
	LogInfo "[$LogPrefix] Exporting recovery registry keys"
	$RecoveryKeys = @(
		('HKLM:System\CurrentControlSet\Control\CrashControl', "$BasicLogFolder\_Reg_CrashControl.txt"),
		('HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management', "$BasicLogFolder\_Reg_MemoryManagement.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug', "$BasicLogFolder\_Reg_AeDebug.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Option', "$BasicLogFolder\_Reg_ImageFileExecutionOption.txt"),
		('HKLM:System\CurrentControlSet\Control\Session Manager\Power', "$BasicLogFolder\_Reg_Power.txt")
	)
	FwExportRegistry $LogPrefix $RecoveryKeys
	# RunOnce
	if ($FullBasic) {
		$StartupKeys = @(
			"HKCU:Software\Microsoft\Windows\CurrentVersion\Run"
			"HKCU:Software\Microsoft\Windows\CurrentVersion\Runonce"
			"HKCU:Software\Microsoft\Windows\CurrentVersion\RunonceEx"
			"HKCU:Software\Microsoft\Windows\CurrentVersion\RunServices"
			"HKCU:Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\policies\Explorer\Run"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\Run"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\Runonce"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\RunonceEx"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\RunServices"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
		)
		FwExportRegToOneFile $LogPrefix $StartupKeys "$BasicLogFolder\_Reg_RunOnce.txt"
		$WinlogonKeys = @(
			'HKCU:Software\Microsoft\Windows NT\CurrentVersion'
			'HKCU:Software\Microsoft\Windows NT\CurrentVersion\Windows'
			'HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
			'HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
		)
		FwExportRegToOneFile $LogPrefix $WinlogonKeys "$BasicLogFolder\_Reg_Winlogon.txt"
		# Installed product
		If(FwIsElevated){
			LogInfo "[$LogPrefix] Getting installed product info"
			$UninstallKey = 'HKLM:Software\Microsoft\Windows\CurrentVersion\Uninstall'
			$Registries = Get-ChildItem $UninstallKey | Get-ItemProperty
			"Install date`tVersion`t`tProdcut Name" | Out-File -Append "$BasicLogFolder\Installed_Product.txt"
			ForEach($Registry in $Registries){
				If(($Null -ne $Registry.InstallSource -and $Registry.InstallSource -ne '') -and (Test-Path -Path $Registry.InstallSource)){
				   $Registry.InstallDate + "`t" + $Registry.Version + "`t" + $Registry.DisplayName | Out-File -Append "$BasicLogFolder\Installed_Product.txt"
				}
			}
		}
		# Group policy
		LogInfo "[$LogPrefix] Obtaining group policy"
		$Commands = @(
			"gpresult /h $BasicLogFolder\Policy_gpresult.html"
			"gpresult /z | Out-File $BasicLogFolder\Policy_gpresult-z.txt"
			"Secedit.exe /export /cfg $BasicLogFolder\Policy_secedit.txt"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True
	}
	#Policy keys
	$PoliciesKeys = @(
		'HKCU:Software\Policies'
		'HKLM:Software\Policies'
		'HKCU:Software\Microsoft\Windows\CurrentVersion\Policies'
		'HKLM:Software\Microsoft\Windows\CurrentVersion\Policies'
	)
	FwExportRegToOneFile $LogPrefix $PoliciesKeys "$BasicLogFolder\_Reg_Policy.txt"

	# Eventlog
	$EventLogs = Get-WinEvent -ListLog * -ErrorAction Ignore
	LogInfo ("[$LogPrefix] Exporting " + $EventLogs.Count + " event logs")
	ForEach($EventLog in $EventLogs){
		#we# if ($FullBasic -or $BasicEvtLogs -contains $EventLog.LogName){	#we# issue#405
		if ($FullBasic){	#we# issue#405
			$tmpStr = $EventLog.LogName.Replace('/','-')
			$EventLogName = ($tmpStr.Replace(' ','-') + '.evtx')
			wevtutil epl $EventLog.LogName "$EventLogFolder\$EventLogName" 2>&1 | Out-Null
		}
	}
	# Proxy
	$Commands = @(
		"REG EXPORT `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`" $BasicLogFolder\_Reg_HKCU_Internet_Settings.txt",
		"netsh winhttp show proxy 2>> $global:ErrorLogFile | Out-File -Append $BasicLogFolder\WinHTTP_Proxy.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$True -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-basic-setup-info{
	Param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[Switch]$FullBasic		# select -FullBasic to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
	$LogPrefix = $B_mode + "BasicLog-Setup"

	#------ Setup ------#
	LogInfo ("[$LogPrefix] Copying setup files")
	$ServicingFiles = @(
		"C:\Windows\INF\Setupapi.*"
		"C:\Windows\Logs\CBS\*.Log"
		"C:\Windows\Logs\DISM\*"
		"C:\Windows\logs\DPX\setupact.log"
		"C:\Windows\logs\CBS\CheckSUR.log"
		"C:\Windows\SoftwareDistribution\ReportingEvents.log"
		"C:\Windows\servicing\Sessions.xml"
		"C:\Windows\servicing\Sessions\*.*"
		"C:\Windows\winsxs\reboot.xml"
		"C:\Windows\Setup\State\State.ini"
		"C:\Windows\Panther\setup*.log"
		"C:\Windows\system32\sysprep\Unattend.xml"
	)
	if ($FullBasic) {
		$ServicingFiles += @(	
			"C:\Windows\winsxs\pending.xml"
			"C:\Windows\winsxs\pending.xml.bad"
			"C:\Windows\winsxs\poqexec.log"
			"C:\Windows\system32\driverstore\drvindex.dat"
			"C:\Windows\system32\driverstore\INFCACHE.1"
			"C:\Windows\system32\driverstore\infpub.dat"
			"C:\Windows\system32\driverstore\infstor.dat"
			"C:\Windows\system32\driverstore\infstrng.dat"
		)
	}
	$CopyCmds = @()
	ForEach($ServicingFile in $ServicingFiles){
		If(Test-Path -Path $ServicingFile){
			$CopyCmd = "Copy-Item $ServicingFile $SetupLogFolder -ErrorAction SilentlyContinue"
			$CopyCmds += $CopyCmd
		}
	}
	If(Test-Path -Path "C:\Windows\system32\sysprep\Panther"){
		$CopyCmds += "Copy-Item C:\Windows\system32\sysprep\Panther $SetupLogFolder\Panther -Recurse"
	}
	RunCommands $LogPrefix $CopyCmds -ThrowException:$False -ShowMessage:$True

	LogInfo ("[$LogPrefix] Exporting setup registry keys and getting package info")
	#reg save "HKLM\COMPONENTS" "$SetupLogFolder\COMPONENT.HIV"
	reg save "HKLM\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" "$SetupLogFolder\Component Based Servicing.HIV" 2>&1 | Out-Null
	FwExportRegToOneFile $LogPrefix "HKLM:System\CurrentControlSet\services\TrustedInstaller" "$BasicLogFolder\_Reg_TrustedInstaller.txt"
	FwExportRegToOneFile $LogPrefix "HKLM:Software\Microsoft\Windows\CurrentVersion\Setup\State" "$BasicLogFolder\_Reg_State.txt"
	dism /online /get-packages 2>&1| Out-File "$SetupLogFolder\dism-get-package.txt"
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-basic-networking-info{
	Param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[Switch]$FullBasic		# select -FullBasic to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
	$LogPrefix = $B_mode + "BasicLog-NET"
	#------- Networking --------#
	# TCP/IP
	LogInfo ("[$LogPrefix] Gathering networking info")
	$Commands = @(
		# NIC
		"Get-NetAdapter -IncludeHidden -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
		# COM/DCOM/RPC
		"netsh rpc show int 2>&1 | Out-File -Append $BasicLogFolder\Net_rpcinfo.txt"
		"netsh rpc show settings 2>&1 | Out-File -Append $BasicLogFolder\Net_rpcinfo.txt"
		"netsh rpc filter show filter 2>&1 | Out-File -Append $BasicLogFolder\Net_rpcinfo.txt"
	)
	if ($FullBasic) {
		$Commands += @(
			"Get-NetIPAddress -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetIPInterface -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetIPConfiguration -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetIPv4Protocol -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetIPv6Protocol  -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetOffloadGlobalSetting -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetPrefixPolicy -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetRoute -IncludeAllCompartments -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetTCPConnection -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetTransportFilter -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetTCPSetting -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetUDPEndpoint -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetUDPSetting -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			# Firewall
			"Show-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
			"Get-NetIPsecMainModeSA -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
			"Get-NetIPsecQuickModeSA -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
			"Get-NetFirewallProfile -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
			"Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_Get-NetFirewallRule.txt"
			"netsh advfirewall show allprofiles 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show allprofiles state 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show currentprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show domainprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show global 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show privateprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show publicprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show store 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"Copy-Item C:\Windows\System32\LogFiles\Firewall\pfirewall.log $BasicLogFolder\Net_Firewall_pfirewall.log -ErrorAction SilentlyContinue"
			# SMB
			"Get-SmbOpenFile -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
			"Get-SmbSession -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
			"Get-SmbWitnessClient -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
			#NIC
			"Get-NetAdapterAdvancedProperty -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterBinding -AllBindings -IncludeHidden -ErrorAction Stop | select Name, InterfaceDescription, DisplayName, ComponentID, Enabled | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterChecksumOffload -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterEncapsulatedPacketTaskOffload -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterHardwareInfo -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterIPsecOffload -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterLso -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterPowerManagement -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterQos -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterRdma -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterRsc -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterRss -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterSriov -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterSriovVf -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterStatistics -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterVmq -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterVmqQueue -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterVPort -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
		)
	}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True
	FwGetNetLbfoTeam $TssPhase
	FwGetArp $TssPhase
	FwGetIPconfig $TssPhase
	FwGetSMBclientInfo $TssPhase
	FwGetSMBserverInfo $TssPhase
	FwGetNetstat $TssPhase

	# Gathering Basic Registries
	FwAddRegItem @("Tcp","Rpc","Ole") _Stop_
	if ($FullBasic) {
		FwAddRegItem @("SMB","SMBSrv","Ole") _Stop_
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-basic-UEX-info{
	Param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[Switch]$FullBasic		# select -FullBasic to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
	$LogPrefix = $B_mode + "BasicLog-UEX"
	#------- UEX --------#
	LogInfo ("[$LogPrefix] Gathering UEX info")

	$Commands = @(
		"schtasks.exe /query /FO CSV /v | Out-File -Append $BasicLogFolder\schtasks_query.csv"
		"schtasks.exe /query /v | Out-File -Append $BasicLogFolder\schtasks_query.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True
	If(($OperatingSystemInfo.OSVersion -eq 10) -and !($global:IsServerCore)){
		LogInfo ("[$LogPrefix] Gathering MDM info")
		If($OSBuild -le 14393){
			$MDMCmdLine = "MdmDiagnosticsTool.exe $BasicLogFolder\MdmDiagnosticsTool.xml | Out-Null"
		}Else{
			$MDMCmdLine = "MdmDiagnosticsTool.exe -out $BasicLogFolder\MDM  | Out-Null"
		}
		RunCommands $LogPrefix $MDMCmdLine -ThrowException:$False -ShowMessage:$True
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-basic-Storage-info{
	Param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[Switch]$FullBasic		# select -FullBasic to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
	$LogPrefix = $B_mode + "BasicLog-SHA"
	#------- Storage --------#
	LogInfo ("[$LogPrefix] Gathering Storage info")
	$Commands = @(
		"fltmc | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
		"fltmc Filters | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
		"fltmc Instances | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
		"fltmc Volumes | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
		"vssadmin list volumes | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
		"vssadmin list writers | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
		"vssadmin list providers | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
		"vssadmin list shadows | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}
#end region --- FwBasicLog functions  & common helper functions

Function global:FwCollect_BasicLog{
	<#
	.SYNOPSIS
		The function collects basic logs, likely applicable for many different tracing scenarios
	.DESCRIPTION
		The function collects basic logs, likely applicable for many different tracing scenarios. 
		The list of logs is hardcoded.
	.NOTES
		Date:   19.04.2021, #we# 2021-12-05
	#>
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$False)]
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[Switch]$Full			# select -Full to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = 'Full-BasicLog'
	LogInfo "[$LogPrefix] .. running Full BasicLog" "Gray"
	If([string]::IsNullOrEmpty($Stage)){
		$script:BasicSubFolder = "BasicLog$LogSuffix"
	}Else{
		$script:BasicSubFolder = "BasicLog$LogSuffix-$Stage"
	}
	$BasicLogFolder = $global:LogFolder + "\" + $script:BasicSubFolder
	$EventLogFolder = "$BasicLogFolder\EventLogs"
	$SetupLogFolder = "$BasicLogFolder\DnD-Setup"
	Try{
		FwCreateLogFolder $BasicLogFolder
		FwCreateLogFolder $EventLogFolder
		FwCreateLogFolder $SetupLogFolder
	}Catch{
		LogError ("Unable to create log folder. " + $_.Exception.Message)
		Return
	}

	Try{
		$IsServerSKU = (Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop).Caption -like "*Server*"
	}Catch{
		LogErrorFile ("Get-CimInstance for CIM_OperatingSystem failed.`n" + 'Command=' + $_.CategoryInfo.Activity + ' HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + ' Exception=' + $_.CategoryInfo.Reason + ' Message=' + $_.Exception.Message)
		$IsServerSKU = $False
	}

	FwGet-OSversion-Build
	FwGet-SummaryVbsLog -FullBasic
	FwGet-basic-system-info -FullBasic
	FWaddEvtLog @("System", "Application")	#we# issue#405
	FwGet-basic-setup-info -FullBasic
	FwGet-basic-networking-info -FullBasic
	FwGet-basic-UEX-info -FullBasic
	FwGet-basic-Storage-info -FullBasic
	FWgetRegList $global:TssPhase
	FWgetEvtLogList $global:TssPhase

	if ($FullBasic) {
		FwWaitForProcess $global:msinfo32NFO 300
		#LogInfo ("[BasicLog] msinfo32 completed.")
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwCollect_MiniBasicLog{
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$False)]
		[String]$Stage=$Null
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = 'Mini-BasicLog'
	LogDebug "[$LogPrefix] .. running Mini BasicLog" "Gray"
	If([string]::IsNullOrEmpty($Stage)){
		$script:BasicSubFolder = "BasicLog_Mini$LogSuffix"
	}Else{
		$script:BasicSubFolder = "BasicLog_Mini$LogSuffix-$Stage"
	}
	$BasicLogFolder = $global:LogFolder + "\" + $script:BasicSubFolder
	$SetupLogFolder = "$BasicLogFolder\DnD-Setup"
	Try{
		FwCreateLogFolder $BasicLogFolder
		FwCreateLogFolder $SetupLogFolder
	}Catch{
		LogError ("Unable to create log folder. " + $_.Exception.Message)
		Return
	}

	FwGet-OSversion-Build
	FwGet-SummaryVbsLog
	FwGet-basic-system-info 
	FWaddEvtLog @("System", "Application") #we# issue#405
	FwGet-basic-setup-info
	FwGet-basic-networking-info
	FwGet-basic-UEX-info
	FwGet-basic-Storage-info
	FwGetGPresultAS
	FWgetRegList $global:TssPhase
	FWgetEvtLogList $global:TssPhase
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetHandle {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if (Test-Path $HandlePath) {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] Collecting Handle output at $TssPhase" -ShowMsg
		if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Handle" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Handle.txt"}
		$Commands = @(
			"handle.exe -a /AcceptEula | Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
	}
}

function global:FwGetNetAdapter {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] dump NetAdapter info with PowerShell commands at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "NetAdapter" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_NetAdapter.txt"}
	"Get-NetAdapter","Get-NetIPAddress","Get-NetIPConfiguration" | ForEach-Object { 
		$Commands = @("$_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	#we# ToDo: 	if "!_HypHost!" equ "1" (  Get-VMNetworkAdapter * | fl | Out-file $global:LogFolder\$($LogPrefix)PsCommand_NetAdapter_!mode!.txt -Append -Encoding ascii )
	if ($global:InvocationLine -match "HypHost") { Get-VMNetworkAdapter * | Format-List | Out-file $global:LogFolder\$($LogPrefix)PsCommand_NetAdapter$TssPhase.txt -Append -Encoding ascii }
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetVMNetAdapter {
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)]  dump VMNetworkAdapter info with PowerShell commands at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "VMNetworkAdapter" + $TssPhase + ".txt" }else{ $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_VMNetworkAdapter.txt"}
	$Commands = @(
		"Get-NetAdapter -includehidden | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	if (Test-Path $env:windir\System32\virtmgmt.msc) {
		"=== PowerShell Get-VMNetworkAdapter -VMName * ft Name,VMName,IPAddresses,MacAddress,AdapterId,SwitchName,SwitchId,VMQueue,VmqUsage,Status -AutoSize Out-String -Width 4096" >> $outFile
		Get-VMNetworkAdapter -VMName * | Format-Table Name,VMName,IPAddresses,MacAddress,AdapterId,SwitchName,SwitchId,VMQueue,VmqUsage,Status -AutoSize |Out-String -Width 4096 | Out-File -Append $outFile
	}else{LogInfo "[$($MyInvocation.MyCommand.Name)] [Info] This machine is not hosting Hyper-V VMs"}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwFileVersion {
	# return detailed VersionInfo, ex: C:\WINDOWS\system32\wbem\wbemcore.dll,10.0.17763.1999,20210608 20:32:26,Microsoft Corporation,Windows Management Instrumentation
	Param(
	  [string] $FilePath
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "[FwFileVersion] Getting file version of $FilePath"
	if (Test-Path -Path $FilePath) {
		Try{
			$fileobj = Get-item $FilePath -ErrorAction Stop
			$filever = $fileobj.VersionInfo.FileMajorPart.ToString() + "." + $fileobj.VersionInfo.FileMinorPart.ToString() + "." + $fileobj.VersionInfo.FileBuildPart.ToString() + "." + $fileobj.VersionInfo.FilePrivatepart.ToString()
			$FilePath + "," + $filever + "," + $fileobj.CreationTime.ToString("yyyyMMdd HH:mm:ss") + "," + $fileobj.VersionInfo.CompanyName + "," + $fileobj.VersionInfo.FileDescription
		}Catch{
			# Do nothing
		}
	}Else{
		LogDebug ("[FwFileVersion] $FilePath not found.")
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwFindPIDforSvcOrProc{
	#Find PID for Process or Service or package name
	#Return $ProcID
	Param(
		[String[]]$PIDorSvcOrProc
	)
	EnterFunc ($MyInvocation.MyCommand.Name + "($PIDorSvcOrProc)")
	LogDebug "PIDorSvcOrProc: $PIDorSvcOrProc"
	ForEach($Target in $PIDorSvcOrProc){
		# Check if passed string for -PIDorSvcOrProc is PID, .exe name or service name.
		$fFound = $False
		$fProcess = $False
		$fService = $False
		$fPID = $False
		$fAppX = $False
		If(([int]::TryParse($Target,[ref]$Null))){
			Try{
				$Process = Get-Process -Id $Target -ErrorAction Stop
			}Catch{
				$ErrorMessage = "Invalid PID $Target was specified for -PIDorSvcOrProc. Check the PID."
				LogInfo $ErrorMessage -noDate
				Throw ($ErrorMessage)
			}
			$ProcID = $Process.Id
			$fFound = $True
			LogInfo "Found target process $($Process.Name) with PID $ProcID" "Green" -ShowMsg
		}
		# Process or service name case
		If(!$fFound){
			If($Target.Contains('.exe')){
				Try{
					$ProcName = $Target.Replace('.exe','')
					$Processes = Get-Process -IncludeUserName -Name $ProcName -ErrorAction Stop
					##Write-Host ("Found target process(es) $ProcName with PID $($Process.Id)")
				}Catch{
					$ErrorMessage = "$Target is not running or invalid process name."
					LogInfo $ErrorMessage -noDate
					Throw ($ErrorMessage)
				}
				If($Processes.Count -gt 1){
					LogInfo "Found mutiple processes with name $ProcName below." -noDate
					LogInfo "-----------------------------------------" -noDate
					ForEach($Process in $Processes){
						LogInfo ("- " + $Process.Name +"(PID:" + $Process.Id + " User:" + $Process.UserName + ")") -noDate
					}
					LogInfo "-----------------------------------------" -noDate
					LogInfo "Please select your desired PID" "cyan" -noDate
					Try{
						FwPlaySound
						$SpecifiedPID = Read-Host "Enter PID of process you want to monitor"
						$Process = Get-Process -Id $SpecifiedPID -ErrorAction Stop
					}Catch{
						$ErrorMessage = "Invalid PID `'$SpecifiedPID`' was specified. Please enter correct PID."
						LogError $ErrorMessage
						Throw ($ErrorMessage)
					}
					$ProcID = $SpecifiedPID
				}Else{
					$Process = $Processes
					$ProcID = $Processes.Id
				}
				$fPID = $True
				LogInfo "Conversion of process name $($Process.name) to PID was successful and target process $($Process.name) was found with PID $ProcID" "Green"
				$fProcess = $True
				$fFound = $True
			}Else{ # Service name or package name case
				Try{
					$Service = Get-CimInstance -Class win32_service -ErrorAction Stop | Where-Object {$_.Name -eq $Target}
				}Catch{
					$ErrorMessage = "Error happened during running Get-CimInstance -Class win32_service"
					Write-Host $ErrorMessage
					Throw ($ErrorMessage)
				}
				If ($Null -ne $Service){
					If($Null -eq $Service.ProcessID){
						$ProcID = $Null
					}Else{
						$ProcID = $Service.ProcessID
					}
					$fService = $True
					$fFound = $True
					LogInfo "Target service $($Service.Name) was found with PID $($Service.ProcessID)." "Green"
				}
				# Search as a package name
				If(!$fFound){
					$AppXApps = Get-AppxPackage -Name $Target
					If ($AppXApps.count -eq 1){
						$fAppX = $True
						$fFound = $True
						Write-Host "Found AppX package for $($AppXApps.Name)"
					}ElseIf($AppXApps.count -gt 1){
						$ErrorMessage = "We see multiple packages that have name of $Target. Please specify accurate package name."
						Write-Host $ErrorMessage
						Throw ($ErrorMessage)
					}
				}
			}
		}
		If(!$fFound){
			$ErrorMessage = "Unable to find target process/service/package($Target)"
			LogInfo $ErrorMessage "Magenta" -noDate
			Throw ($ErrorMessage)
		}
	}
	Return $ProcID
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportFileVerToCsv {
	# return detailed VersionInfo, ex: "C:\WINDOWS\SysWOW64\win32k.sys","10.0.17763.1 (WinBuild.160101.0800)","9/15/2018 9:13:04 AM","320000","Microsoft Corporation","Full/Desktop Multi-User Win32 Driver"
	Param(
		[string] $WindirSubFolder,
		[string[]] $FileExts,			# List of one or more file extensions
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if ([string]::IsNullOrEmpty($Subfolder)) { $PrefixOut = $PrefixTime }else{ $PrefixOut = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_"}
	ForEach($FileExt in $FileExts){
		LogDebug "[FwExportFileVerToCsv] Getting file version of $Env:Windir\$WindirSubFolder\*.$FileExt" "Gray"
		Get-ChildItem -Path ($Env:Windir + "\" + $WindirSubFolder) -Filter *.$FileExt -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
			[pscustomobject]@{
				Name = $_.FullName;
				Version = $_.VersionInfo.FileVersion;
				DateModified = $_.LastWriteTime;
				Length = $_.length;
				CompanyName = $_.VersionInfo.CompanyName;
				FileDescription = $_.VersionInfo.FileDescription;
			}
		} | export-csv -notypeinformation -path "$($PrefixOut + "FileVersions_" + $WindirSubFolder + "_" + $FileExt + ".csv")"
		LogInfoFile "[FwExportFileVerToCsv] ... finished for $WindirSubFolder\*.$FileExt" "Gray"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

If($global:ParameterArray -notcontains 'noQuickEdit'){ 
	# This function disables quick edit mode. If the mode is enabled, 
	#  console output would hang when key input or strings are selected. 
	# So disable the quick edit mode during running script and re-enable it after script is finished.
	$QuickEditCode=@"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

public static class DisableConsoleQuickEdit
{
	const uint ENABLE_QUICK_EDIT = 0x0040;

	// STD_INPUT_HANDLE (DWORD): -10 is the standard input device.
	const int STD_INPUT_HANDLE = -10;

	[DllImport("kernel32.dll", SetLastError = true)]
	static extern IntPtr GetStdHandle(int nStdHandle);

	[DllImport("kernel32.dll")]
	static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

	[DllImport("kernel32.dll")]
	static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

	public static bool SetQuickEdit(bool SetEnabled)
	{

		IntPtr consoleHandle = GetStdHandle(STD_INPUT_HANDLE);

		// get current console mode
		uint consoleMode;
		if (!GetConsoleMode(consoleHandle, out consoleMode))
		{
			// ERROR: Unable to get console mode.
			return false;
		}

		// Clear the quick edit bit in the mode flags
		if (SetEnabled)
		{
			consoleMode &= ~ENABLE_QUICK_EDIT;
		}
		else
		{
			consoleMode |= ENABLE_QUICK_EDIT;
		}

		// set the new mode
		if (!SetConsoleMode(consoleHandle, consoleMode))
		{
			// ERROR: Unable to set console mode
			return false;
		}

		return true;
	}
}
"@
	Try{
		$QuickEditMode = add-type -TypeDefinition $QuickEditCode -Language CSharp -ErrorAction Stop
		# Keep disabled when DebugMode for better debugging.
		If(!$DebugMode.IsPresent){
			$fQuickEditCodeExist = $True
		}
	}Catch{
		$fQuickEditCodeExist = $False
	}
}

$FindServicePIDCode=@'
using System;
using System.ServiceProcess;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;

namespace MSDATA {
  public static class FindService {

	public static void Main(){
	  //Console.WriteLine("Hello world!");
	}

	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
	public struct SERVICE_STATUS_PROCESS {
	  public int serviceType;
	  public int currentState;
	  public int controlsAccepted;
	  public int win32ExitCode;
	  public int serviceSpecificExitCode;
	  public int checkPoint;
	  public int waitHint;
	  public int processID;
	  public int serviceFlags;
	}

	[DllImport("advapi32.dll")]
	public static extern bool QueryServiceStatusEx(IntPtr serviceHandle, int infoLevel, IntPtr buffer, int bufferSize, out int bytesNeeded);

	public static int FindServicePid(string SvcName) {
	  //Console.WriteLine("Hello world!");
	  ServiceController sc = new ServiceController(SvcName);
	  if (sc == null) {
		return -1;
	  }
				  
	  IntPtr zero = IntPtr.Zero;
	  int SC_STATUS_PROCESS_INFO = 0;
	  int ERROR_INSUFFICIENT_BUFFER = 0;

	  Int32 dwBytesNeeded;
	  System.IntPtr hs = sc.ServiceHandle.DangerousGetHandle();

	  // Call once to figure the size of the output buffer.
	  QueryServiceStatusEx(hs, SC_STATUS_PROCESS_INFO, zero, 0, out dwBytesNeeded);
	  if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER) {
		// Allocate required buffer and call again.
		zero = Marshal.AllocHGlobal((int)dwBytesNeeded);

		if (QueryServiceStatusEx(hs, SC_STATUS_PROCESS_INFO, zero, dwBytesNeeded, out dwBytesNeeded)) {
		  SERVICE_STATUS_PROCESS ssp = (SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(zero, typeof(SERVICE_STATUS_PROCESS));
		  return (int)ssp.processID;
		}
	  }
	  return -1;
	}
  }
}
'@

Try{
	$FindServiceObject = 'MSDATA.FindService' -as [type]
	If($Null -eq $FindServiceObject){
		If($Host.Version.Major -ge 7){
			add-type -TypeDefinition $FindServicePIDCode -Language CSharp -ReferencedAssemblies 'System.ServiceProcess.ServiceController','netstandard','System.ComponentModel.Primitives' -ErrorAction Stop
		}Else{
			add-type -TypeDefinition $FindServicePIDCode -Language CSharp -ReferencedAssemblies 'System.ServiceProcess' -ErrorAction Stop
		}
	}
}Catch [System.InvalidOperationException]{
	LogInfoFile "InvalidOperationException happened in Add-Type for FindServicePID but this is ignorable and continue."
}Catch{
	$_
	LogInfo "Unable to add C# code for finding service PID" "Magenta"
}

Function global:FindServicePid {
	Param(
		[String]$SvcName
	)

	Try{
		$pidsvc = [MSDATA.FindService]::FindServicePid($SvcName)
		LogInfo "[FindServicePid] Found PID for $SvcName(PID:$pidsvc)."
		Return $pidsvc
	}Catch{
		LogException "Error happened in FindServicePid()." $_ $fLogFileOnly
	}

	# Fall back to WMI way.
	LogInfo "[FindServicePid] Searching PID for $SvcName using WMI."
	$Service = Get-CimInstance -Class win32_service -ErrorAction Ignore | Where-Object {$_.Name -eq $SvcName}
	If($Null -eq $Service){
		LogError "Unable to find PID for $SvcName. Check if the service is running."
		Return $null
	}Else{
		Return $Service.ProcessID
	}
}

$UserDumpCode=@'
using System;
using System.Runtime.InteropServices;

namespace MSDATA
{
	public static class UserDump
	{
		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessID);
		[DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
		public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

		private enum MINIDUMP_TYPE
		{
			MiniDumpNormal = 0x00000000,
			MiniDumpWithDataSegs = 0x00000001,
			MiniDumpWithFullMemory = 0x00000002,
			MiniDumpWithHandleData = 0x00000004,
			MiniDumpFilterMemory = 0x00000008,
			MiniDumpScanMemory = 0x00000010,
			MiniDumpWithUnloadedModules = 0x00000020,
			MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
			MiniDumpFilterModulePaths = 0x00000080,
			MiniDumpWithProcessThreadData = 0x00000100,
			MiniDumpWithPrivateReadWriteMemory = 0x00000200,
			MiniDumpWithoutOptionalData = 0x00000400,
			MiniDumpWithFullMemoryInfo = 0x00000800,
			MiniDumpWithThreadInfo = 0x00001000,
			MiniDumpWithCodeSegs = 0x00002000
		};

		public static bool GenerateUserDump(uint ProcessID, string dumpFileName)
		{
			System.IO.FileStream fileStream = System.IO.File.OpenWrite(dumpFileName);

			if (fileStream == null)
			{
				return false;
			}

			// 0x1F0FFF = PROCESS_ALL_ACCESS
			IntPtr ProcessHandle = OpenProcess(0x1F0FFF, false, ProcessID);

			// #commenting out next 4 lines for PowerShell 7 issue #856
			// if(ProcessHandle == null)	// error CS0472
			// {
			// 	return false;
			// }

			MINIDUMP_TYPE Flags =
				MINIDUMP_TYPE.MiniDumpWithFullMemory |
				MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo |
				MINIDUMP_TYPE.MiniDumpWithHandleData |
				MINIDUMP_TYPE.MiniDumpWithUnloadedModules |
				MINIDUMP_TYPE.MiniDumpWithThreadInfo;

			bool Result = MiniDumpWriteDump(ProcessHandle,
								 ProcessID,
								 fileStream.SafeFileHandle,
								 (uint)Flags,
								 IntPtr.Zero,
								 IntPtr.Zero,
								 IntPtr.Zero);

			fileStream.Close();
			return Result;
		}
	}
}
'@
Try{
	$UserDumpObject = 'MSDATA.UserDump' -as [type]
	If($Null -eq $UserDumpObject){
		add-type -TypeDefinition $UserDumpCode -Language CSharp
	}
}Catch{
	LogInfoFile "Unable to add C# code for Collecting user dump."
}

Function global:FwCaptureUserDump{
	Param(
		[String] $Name,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $DumpFolder,
		[Bool] $IsService = $False,
		[long] $ProcPID
	)
	EnterFunc $MyInvocation.MyCommand.Name

	if (-not $global:ProcDump) {	#we# skip section if $global:ProcDump has been built at Start phase
		$global:ProcDump = "Procdump.exe"
		$ProcDumpCommand = Get-Command "Procdump.exe" -ErrorAction Ignore
	  if ($Null -ne $ProcDumpCommand) {
		  # For -Start, retrieve ProcDumpInterval from BoundParameters[] or config.cfg. For -Stop, $ProcDumpInterval are set in ReadParameterFromTSSReg().
		  If(!$Stop.IsPresent){
			  #$ProcDumpInterval = $global:BoundParameters['ProcDumpInterval']
			  If(!([string]::IsNullOrEmpty($global:BoundParameters['ProcDumpInterval']))){
					$ProcDumpInterval = $global:BoundParameters['ProcDumpInterval']
					LogDebug "[ProcDump] set ProcDumpInterval $global:ProcDumpInterval by CMDline"
			  }elseif (!([string]::IsNullOrEmpty($global:ProcDumpInterval))){
					LogDebug "[ProcDump] set ProcDumpInterval $global:ProcDumpInterval by config.cfg"
			  }else{
					LogDebug "[ProcDump] set default ProcDumpInterval $global:ProcDumpInterval in FwCaptureUserDump"
			  }
			  LogDebug "[FwCaptureUserDump] ProcDumpInterval (N:sec): $global:ProcDumpInterval -global $global:ProcDumpInterval" "cyan"
		  }
		  If(($Null -ne $global:ProcDumpInterval) -or ($Null -ne $ProcDumpInterval)){
			  $Token = $ProcDumpInterval -split ":"
			  If($Token.Count -ne 2){
				  LogWarn "Invalid ProcDumpInterval($ProcDumpInterval) was passed."
			  }Else{
				  $script:NumDumps = $Token[0]
				  $script:DmpIntervalInSec = $Token[1]
				  $IntervalOption = "-s $script:DmpIntervalInSec -n $script:NumDumps"
				  LogInfoFile "[FwCaptureUserDump] [$global:TssPhase] ProcDump Interval in seconds: $script:DmpIntervalInSec - Number of dumps: $script:NumDumps - ProcDumpOption: $ProcDumpOption"
			  }
		  }
		  $global:ProcDump = "Procdump.exe $IntervalOption -AcceptEula -ma"
	  }else{
		$global:ProcDump = "Missing"
		LogWarn ("The ProcDump tool is not available'.")
	  }
	}

	if ($ProcPID) {
		$IsService = $false
		$ProcessObject = Get-Process -Id $ProcPID -ErrorAction Ignore
		If($Null -eq $ProcessObject){
			LogError "Unable to find the process with PID $ProcPID"
			Return
		}
	}else{
		If($IsService){
			Try{
				$PIDSvc = FindServicePid $Name
				If(-not $PIDSvc) {
					LogWarn "Cannot find the PID for the process running the service $Name. The service may not be running or the name could be incorrect."
					Return
				}
				$ProcessObject = Get-Process -Id $PIDSvc -ErrorAction Stop
			}Catch{
				LogError "An error happened during getting PID for `'$Name`' service."
				Return
			}
		}Else{
			Try{
				$Name = $Name -replace "\.exe",""
				# warn if process is lsass.exe
				if ($Name -like "*lsass*") {
					LogWarn "Procdump on lsass may fail with Access Denied, see https://mikesblogs.net/access-denied-when-running-procdump/ + https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs" "Magenta"
					# also: https://www.osgwiki.com/wiki/ApWiki#Capturing_LSASS.exe_Time_Travel_Trace_.28PPL.29
				}
				$ProcessObject = Get-Process -Name $Name -ErrorAction Stop
			}Catch{
				LogError "The process $Name.exe is not running."
				Return
			}
		}
	}

	ForEach($Proc in $ProcessObject){
		If($IsService){
			$DumpFileName = "$DumpFolder\$($Proc.ProcessName).exe_$($Name)$global:TssPhase.dmp"
			$Message = "[UserDump] [$global:TssPhase] Capturing $script:NumDumps user dump(s) for $($Proc.ProcessName) ($Name) service in intervals of $script:DmpIntervalInSec seconds at $ProcDumpOption"
		}Else{
			$DumpFileName = "$DumpFolder\$($Proc.ProcessName).exe_$($Proc.Id)$global:TssPhase.dmp"
			$Message = "[UserDump] [$global:TssPhase] Capturing $script:NumDumps user dump(s) for $($Proc.ProcessName).exe ($($Proc.Id)) in intervals of $script:DmpIntervalInSec seconds at $ProcDumpOption"
		}
		if (!($ProcDumpAppCrash.IsPresent)){LogInfo $Message}

		if ($global:ProcDump -ne "Missing") {
			if (!($ProcDumpAppCrash.IsPresent)){
				$Command = "$global:ProcDump $($Proc.ID) `"$DumpFileName`""
			}else{
				LogInfo "[FwCaptureUserDump] will wait for an App exception: Procdump.exe -ma -e $($Proc.Id)" "Cyan"
				$Command = "Start-Process -WindowStyle Minimized -FilePath `"procdump.exe`" -ArgumentList `"-ma -e -AcceptEula $($Proc.ID) $DumpFileName`""
			}
			Try {
				RunCommands "UserDump" $Command -ThrowException:$True -ShowMessage:$True
			}Catch{
				#LogError "Failed to run $global:ProcDump (for $($Proc.ProcessName) Pid: $($Proc.ID))"
				#Write-Error $_
				$ErrorMessage = "Failed to run $global:ProcDump (for $($Proc.ProcessName) Pid: $($Proc.ID))"
				LogException $ErrorMessage $_ -fErrorLogFileOnly:$True
				If ($($Proc.ProcessName) -like "*lsass*" ){
					LogInfo "Please check the following" "Magenta"
					LogInfo "1. Is the SeDebugPrivilege privilege given to the user on the machine (WhoAmI /priv)? If not, enable it." "Magenta"
					LogInfo "2. Is LSASS running as PPL? If yes, set reg key HKLM\System\CCS\Control\Lsa\RunAsPPL=0 " "Magenta"
					LogInfo "3. Does Windows Defender have Real-Time protection enabled? If yes, disable this option temporarily." "Magenta"
					LogInfo "4. Do you have 3rd party AntiVirus blocking process dumps+. If yes, disable or remove 3rd party AV." "Magenta"
					LogInfoFile "Ad 4.: TTD and ProcDump requirements, see https://www.osgwiki.com/wiki/TTD_FAQ_and_Troubleshooting#Known_Issues_and_Incompatibilities"
				}
			}
		}else{
			Try {
				$Result = [MSDATA.UserDump]::GenerateUserDump($Proc.ID, $DumpFileName)
			}Catch{
				LogError "Failed to run GenerateUserDump($Proc.ID)"
				Write-Error $_
			}
			If(!$Result){
				If($IsService){
					LogError ("Failed to capture process dump for $($Name) service")
				}Else{
					LogError ("Failed to capture process dump for $($Proc.ProcessName)")
				}
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExecWMIQuery {
	[OutputType([Object])]
	Param(
		[string] $NameSpace,
		[string] $Query
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile ("[ExecWMIQuery] Executing query " + $Query) -ShowMsg
	Try{
		if ($PSVersionTable.psversion.ToString() -ge "3.0") {
			$Obj = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Stop
		}else{
			$Obj = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Stop
		}
	}Catch{
		LogException ("An error happened during running $Query") $_ $fLogFileOnly
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $Obj
}

Function global:FwGetCertStore{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$Store
	)
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		LogInfo ("[Cert] Getting Cert:\LocalMachine\$Store")
		$certlist = Get-ChildItem ("Cert:\LocalMachine\$Store") -ErrorAction Stop
	}Catch{
		LogError ("An error happened during retriving $Store")
		Return
	}
	
	ForEach($cert in $certlist) {
		$EKU = ""
		ForEach($item in $cert.EnhancedKeyUsageList){
			if ($item.FriendlyName) {
				$EKU += $item.FriendlyName + " / "
			}else{
				$EKU += $item.ObjectId + " / "
			}
		}
		$row = $Global:tbcert.NewRow()
		
		ForEach($ext in $cert.Extensions){
			if ($ext.oid.value -eq "2.5.29.14") {
				$row.SubjectKeyIdentifier = $ext.SubjectKeyIdentifier.ToLower()
			}
			if (($ext.oid.value -eq "2.5.29.35") -or ($ext.oid.value -eq "2.5.29.1")) { 
				$asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
				$aki = $asn.Format($true).ToString().Replace(" ","")
				$aki = (($aki -split '\n')[0]).Replace("KeyID=","").Trim()
				$row.AuthorityKeyIdentifier = $aki
			}
		}
		if($EKU){
			$EKU = $eku.Substring(0, $eku.Length-3)
		}
		$row.Store = $store
		$row.Thumbprint = $cert.Thumbprint.ToLower()
		$row.Subject = $cert.Subject
		$row.Issuer = $cert.Issuer
		$row.NotAfter = $cert.NotAfter
		$row.EnhancedKeyUsage = $EKU
		$row.SerialNumber = $cert.SerialNumber.ToLower()
		$Global:tbcert.Rows.Add($row)
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwInvokeUnicodeTool($ToolString) {
	# Switch output encoding to unicode and then back to the default for tools
	# that output to the command line as unicode.
	$oldEncoding = [console]::OutputEncoding
	[console]::OutputEncoding = [Text.Encoding]::Unicode
	Invoke-Expression $ToolString
	[console]::OutputEncoding = $oldEncoding
}

Function global:FwCleanUpandExit{
	CleanUpandExit
}

Function global:FwPlaySound{
	If($OSBuild -ge 9600 -and $global:ParameterArray -notcontains 'noSound'){
		LogDebug "Playing sound."
		rundll32.exe cmdext.dll,MessageBeepStub
	}
}

Function global:FwTest-TCPport{ # original name: Test-PSOnePort
  <#
	  .SYNOPSIS
	  Tests a network port on a remote computer

	  .DESCRIPTION
	  Tests whether a port on a remote computer is responding.

	  .EXAMPLE
	  FwTest-TCPport -ComputerName 127.0.0.1 -Port 4000 -Timeout 1000 
	  Tests whether port 4000 on the local computer is responding, 
	  and waits a maximum of 1000 milliseconds

	  .EXAMPLE
	  FwTest-TCPport -ComputerName 127.0.0.1 -Port 4000 -Timeout 1000 -Count 30 -Delay 2000
	  Tests 30 times whether port 4000 on the local computer is responding, 
	  and waits a maximum of 1000 milliseconds inbetween each test

	  .EXAMPLE
	  FwTest-TCPport -ComputerName 127.0.0.1 -Port 4000 -Timeout 1000 -Count 0 -Delay 2000 -ExitOnSuccess
	  Continuously tests whether port 4000 on the local computer is responding, 
	  waits a maximum of 1000 milliseconds inbetween each test, 
	  and exits as soon as the port is responding

	  .LINK
	  https://powershell.one/tricks/network/porttest
  #>
  Param(
	[Parameter(Mandatory=$True)]
	[string]$ComputerName,
	# port number to test
	[Parameter(Mandatory=$True)]
	[int]$Port,
	# timeout in milliseconds
	[int]$Timeout = 500,
	# number of tries. A value of 0 indicates countinuous testing
	[int][ValidateRange(0,1000)]
	$Count = 1,
	# delay (in milliseconds) inbetween continuous tests
	$Delay = 2000,
	# when enabled, function returns as soon as port is available
	[Switch]$ExitOnSuccess
  )
  EnterFunc $MyInvocation.MyCommand.Name
  $ok = $false
  $c = 0
  $isOnline = $false
  $continuous = $Count -eq 0 -or $Count -gt 1
  try {
	do
	{
	  $c++
	  if ($c -gt $Count -and !$continuous) { 
		# count exceeded
		break
	  }
	  $start = Get-Date
	  $tcpobject = [system.Net.Sockets.TcpClient]::new()
	  $connect = $tcpobject.BeginConnect($computername,$port,$null,$null) 
	  $wait = $connect.AsyncWaitHandle.WaitOne($timeout,$false) 
	  if(!$wait) { 
		# no response from port
		$tcpobject.Close()
		$tcpobject.Dispose()
		Write-Verbose "Port $Port is not responding..."
		if ($continuous) { Write-Host '.' -NoNewline }
	  }else{ 
		try { 
		  # port is reachable
		  if ($continuous) { Write-Host '!' -NoNewline }
		  [void]$tcpobject.EndConnect($connect)
		  $tcpobject.Close()
		  $tcpobject.Dispose()
		  $isOnline = $true
		  if ($ExitOnSuccess)
		  {
			$ok = $true
			$delay = 0
		  }
		}
		catch { 
		  # access to port restricted
		  throw "You do not have permission to contact port $Port."
		} 
	  } 
	  $stop = Get-Date
	  $timeUsed = ($stop - $start).TotalMilliseconds
	  $currentDelay = $Delay - $timeUsed
	  if ($currentDelay -gt 100)
	  {
		Start-Sleep -Milliseconds $currentDelay
	  }
	} until ($ok)
  }
  finally {
	# dispose objects to free memory
	if ($tcpobject)
	{
	  $tcpobject.Close()
	  $tcpobject.Dispose()
	}
  }
  if ($continuous) { Write-Host ' '}
  EndFunc ($MyInvocation.MyCommand.Name + "($isOnline)")
  return $isOnline
}

Function global:FwSetMCF { 
	#[disable|enable] MulticastForwarding - workaround for bug# 25929912 / 26000155 Rs5 fix 20.08C, Rs1=won't fix, KB4558063
	Param(
		[ValidateSet("disable","enable")]
		[Parameter(Mandatory=$True)]
		[String]$MCFstate
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:OSVersion.Build -le 17763) { # add Srv2012; 2023-01-17 replaced 14393
		try {
			$RAsvcStatus = (get-Service -Name "RemoteAccess" -ErrorAction Ignore).Status 
			$RaMgmtSvc = (get-Service -Name "RaMgmtSvc" -ErrorAction Ignore).Status
		}
		catch { }
		if (($RAsvcStatus -eq [System.ServiceProcess.ServiceControllerStatus]::Running) -or ($RaMgmtSvc -eq [System.ServiceProcess.ServiceControllerStatus]::Running)) {
			LogInfoFile "[$($MyInvocation.MyCommand.Name)] ** On (OS -le Srv2019) RemoteAccess: netsh interface ipv4 set global multicastforwarding=$MCFstate"
			$Commands = @(
				"netsh interface ipv4 set global multicastforwarding=$MCFstate"
			)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}else{LogInfoFile "[$($MyInvocation.MyCommand.Name)] Service 'RemoteAccess' Status = $RAsvcStatus , 'RaMgmtSvc' Status = $RaMgmtSvc"}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwTestConnWebSite{
	# Purpose: check internet connectivity to WebSite
	# Results: True = machine has internet connectivity, False = no internet connectivity
		#_#$checkConn = Test-NetConnection -ComputerName $WebSite -CommonTCPPort HTTP -InformationLevel "Quiet"
	Param(
		[string]$WebSite = $Script:TssReleaseServer
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$checkConn =$False
	if ($WebSite) {
		try {
			$checkConn = FwTest-TCPport -ComputerName $WebSite -Port 80 -Timeout 900 
			LogInfoFile "[FwTestConnWebSite] WebSite to test is: $WebSite - checkConn: $checkConn" "Gray" -ShowMsg
			}
		catch { LogInfoFile "[FwTestConnWebSite] WebSite to test is: $WebSite - checkConn: $checkConn" "Magenta" -ShowMsg}
	}else{ LogError "[FwTestConnWebSite] WebSite to test is: NULL "}
	EndFunc ($MyInvocation.MyCommand.Name + "($checkConn)")
	return $checkConn
}

Function global:FwToggleProgressPreference(){
	# Purpose: temporarily change $ProgressPreference
	Param(
		[ValidateSet("disable","enable")]
		[Parameter(Mandatory=$True)]
		[String]$ProgPrefState
	)
	if ($ProgPrefState -eq "disable"){
		# temporarily save $ProgressPreference
		$global:OriginalProgressPreference = $Global:ProgressPreference
		$Global:ProgressPreference = 'SilentlyContinue'
	}
	if ($ProgPrefState -eq "enable"){
		# reset $ProgressPreference
		$Global:ProgressPreference = $global:OriginalProgressPreference
	}
}

Function global:FwAuditPolSet {
	Param(
		[Parameter(Mandatory=$True)]
		[string]$AuditComponent,		# i.e. "Firewall"
		[Parameter(Mandatory=$True)]
		[string[]]$AuditSettingsList	# Example: @('"Filtering Platform Packet Drop","Filtering Platform Connection"') # for GUIDS see adtapi.h
	)
	EnterFunc $MyInvocation.MyCommand.Name
	#Note1: use /r to get a csv-formatted table: AuditPol /get /category:* /r | ConvertFrom-Csv | Format-Table 'Policy Target',Subcategory,'Inclusion Setting'
	#Note2: auditing categories are localized. On non-English systems the command using "names" fails, so lets use GUIDs in $AuditSettingsList
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Backup current AuditPol settings to $PrefixCn`AuditPol_backup.csv"
	$Commands = @("AuditPol /backup /file:$PrefixCn`AuditPol_backup.csv")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Enabling $AuditComponent related Events in Security Eventlog via AuditPol.exe" -ShowMsg
	$Commands += @(
		"AuditPol.exe /get /category:* | Out-File -Append $global:LogFolder\$($LogPrefix)AuditPol$TssPhase.txt"
		"AuditPol.exe /set /SubCategory:$AuditSettingsList  /success:enable /failure:enable"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
Function global:FwAuditPolUnSet {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Restoring original AuditPol settings from $PrefixCn`AuditPol_backup.csv" -ShowMsg
	$Commands = @(
		"AuditPol.exe /restore /file:$PrefixCn`AuditPol_backup.csv"
		"AuditPol.exe /get /category:* | Out-File -Append $global:LogFolder\$($LogPrefix)AuditPol$TssPhase.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwCopyMemoryDump {
	# .SYNOPSIS will copy Memory.dmp to dataset
	# $DaysBack controls how old the dump file to collect is
	Param(
		[Int]$DaysBack = 0
	)	
	EnterFunc "$($MyInvocation.MyCommand.Name) - DaysBack=$DaysBack"
	$SystemDumpFileName = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\CrashControl" -ErrorAction Ignore).DumpFile
	If($Null -eq $SystemDumpFileName){
		LogInfoFile "[FwCopyMemoryDump] `'DumpFile`' does not exist in `'HKLM:\System\CurrentControlSet\Control\CrashControl`'."
		Return
	}

	If(!(Test-Path -Path $SystemDumpFileName)){
		LogInfoFile "[FwCopyMemoryDump] `'$SystemDumpFileName`' does not exist."
		Return
	}

	$DumpFile = Get-Item $SystemDumpFileName -ErrorAction Ignore
	If($DumpFile -and ($DaysBack -ne 0)){
		$DumpFileSize = ($DumpFile.Length / 1GB).ToString("0.0")
		$TimeSpan = (Get-Date) - ($DumpFile.LastWriteTime)  # Current time - LastWriteTime
		LogInfo "Found dump file $SystemDumpFileName aged $($TimeSpan.Days) days, size=$DumpFileSize GB" "Cyan"
		LogDebug "DumpFile=$SystemDumpFileName TimeSpanDays=$($TimeSpan.Days) DaysBack=$DaysBack"
		If($TimeSpan.Days -gt $DaysBack){
			LogInfo "[FwCopyMemoryDump] Found `'$SystemDumpFileName`' but the last write time of the file is more than $DaysBack days ago($($TimeSpan.Days)). Skipping copying the file."  "Cyan"
			Return
		}
	}
	
	$Answer = FwRead-Host-YN -Message "Found memory dump($SystemDumpFileName with $($DumpFileSize)GB). Do you want to copy it to log folder? (timeout=10s)" -Choices "yn" -Timeout 10 -Default 'y'
	If($Answer){
		Try{
			LogInfo "Copying $SystemDumpFileName to $global:LogFolder"
			Copy-Item $SystemDumpFileName $global:LogFolder -ErrorAction Stop
		}Catch{
			LogError "Failed to copy memory.dmp. See $global:ErrorLogFile for detail."
			LogExceptionFile "Failed to copy memory.dmp to log folder." $_
		}
	}else{ LogInfoFile "=== User declined to copy Memory.dmp to log folder ==="}
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion common functions used by POD module

#region script functions

#region Common utilities
[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

function global:ShowEULAPopup($mode)
{
	$EULA = New-Object -TypeName System.Windows.Forms.Form
	$richTextBox1 = New-Object System.Windows.Forms.RichTextBox
	$btnAcknowledge = New-Object System.Windows.Forms.Button
	$btnCancel = New-Object System.Windows.Forms.Button

	$EULA.SuspendLayout()
	$EULA.Name = "EULA"
	$EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"

	$richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
	$richTextBox1.Location = New-Object System.Drawing.Point(12,12)
	$richTextBox1.Name = "richTextBox1"
	$richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
	$richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
	$richTextBox1.TabIndex = 0
	$richTextBox1.ReadOnly=$True
	$richTextBox1.Add_LinkClicked({Start-Process -FilePath $_.LinkText})
	$richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1 
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard 
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
	$richTextBox1.BackColor = [System.Drawing.Color]::White
	$btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
	$btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
	$btnAcknowledge.Name = "btnAcknowledge";
	$btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
	$btnAcknowledge.TabIndex = 1
	$btnAcknowledge.Text = "Accept"
	$btnAcknowledge.UseVisualStyleBackColor = $True
	$btnAcknowledge.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::Yes})

	$btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
	$btnCancel.Location = New-Object System.Drawing.Point(669, 415)
	$btnCancel.Name = "btnCancel"
	$btnCancel.Size = New-Object System.Drawing.Size(119, 23)
	$btnCancel.TabIndex = 2
	if($mode -ne 0)
	{
		$btnCancel.Text = "Close"
	}
	else
	{
		$btnCancel.Text = "Decline"
	}
	$btnCancel.UseVisualStyleBackColor = $True
	$btnCancel.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::No})

	$EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
	$EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
	$EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
	$EULA.Controls.Add($btnCancel)
	$EULA.Controls.Add($richTextBox1)
	if($mode -ne 0)
	{
		$EULA.AcceptButton=$btnCancel
	}
	else
	{
		$EULA.Controls.Add($btnAcknowledge)
		$EULA.AcceptButton=$btnAcknowledge
		$EULA.CancelButton=$btnCancel
	}
	$EULA.ResumeLayout($false)
	$EULA.Size = New-Object System.Drawing.Size(800, 650)

	Return ($EULA.ShowDialog())
}

function global:ShowEULAIfNeeded($toolName, $mode)
{
	$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
	$eulaAccepted = "No"
	$eulaValue = $toolName + " EULA Accepted"
	if(Test-Path $eulaRegPath)
	{
		$eulaRegKey = Get-Item $eulaRegPath
		$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
	}
	else
	{
		$eulaRegKey = New-Item $eulaRegPath
	}
	if($mode -eq 2) # silent accept
	{
		$eulaAccepted = "Yes"
	   		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
	}
	else
	{
		if($eulaAccepted -eq "No")
		{
			$eulaAccepted = ShowEULAPopup($mode)
			if($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes)
			{
					$eulaAccepted = "Yes"
					$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}

Function InsertArrayIntoArray($Array, $insertAfter, $valueToInsert){  
	$index = 0
	$insertPoint = -1

	#find the index of value before insertion
	#ryhayash: IndexOf is not case sensitive. So change logic to get index.
	#$insertPoint = $Array.IndexOf($insertAfter)
	If($insertAfter -is [int]){
		$insertPoint = $insertAfter
	}Else{
		ForEach($Element in $Array){
			If($Element -eq $insertAfter){
				$insertPoint = $index
			}
			$index++
		}
	}

	If($insertPoint -lt 0){
		LogDebug "[$valueToInsert] Unable to find insert point for $insertAfter(InsertPoint=$insertPoint). Adding the parameter to the head of the array." "Red"
	}Else{
		LogDebug "[$valueToInsert] InsertPoint=$insertPoint($insertAfter)"
	}

	#split the array into two parts
	#slice into a new array
	$newArray = @()
	If($insertPoint -eq 0){
		$secondHalf = $Array
		foreach ($insert in $valueToInsert){
			$newArray+=$insert
		}
	}Else{
		$firstHalf = $Array[0..$insertPoint]
		$secondHalf = $Array[($insertPoint +1)..$Array.Length]
		foreach ($first in $firsthalf){
			$newArray+=$first
		}
	}
	If($insertPoint -ne 0){
		foreach ($insert in $valueToInsert){
			$newArray+=$insert
		}
	}
	foreach ($second in $secondHalf){
		$newArray+=$second
	}

	return $newArray
	#returning this new array means you can assign it over the old array
}

Function RemoveItemFromArray($Array, $Item){
	EnterFunc $MyInvocation.MyCommand.Name
	$newArray = @()
	ForEach($Element in $Array){
		If($Element -ne $Item){
			$newArray += $Element
		}Else{
			LogDebug "Removing $Item."
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
	return $newArray
}

Function SearchTTTracer{
	[OutputType([String])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$Script:TTDFullPath = $Null
	$fFound = $False
	# First, seach path specified with '-TTDPath'
	$TTDPath = $global:BoundParameters['TTDPath']
	If(![string]::IsNullOrEmpty($TTDPath)){
		$Script:TTDFullPath = Join-Path -Path $TTDPath "TTTracer.exe"
		If(!(Test-Path -path $Script:TTDFullPath)){
			# Seach a bit more as TTDPath might have been specified with upper folder.
			$TTTracers = Get-ChildItem $TTDPath 'TTTracer.exe' -Recurse -ErrorAction Ignore
			If($Global:ProcArch -eq 'x64'){
			   $PathWithArch = ".*(amd64|x64)\\.*TTTracer.exe"
			}Else{
			   $PathWithArch = ".*x86\\.*TTTracer.exe"
			}
			
			ForEach($TTTracer in $TTTracers){
				If($TTTracer.FullName -like "*downlevel*" -or $TTTracer.FullName -like "*wow64*"){
					LogDebug "Skipping $($TTTracer.FullName)"
					Continue
				}
				If($TTTracer.FullName -match $PathWithArch){
					LogDebug "Use $($TTTracer.FullName)"
					$Script:TTDFullPath = $TTTracer.FullName
					$Script:UsePartnerTTD = $True
					$fFound = $True
					Break
				}Else{
					LogDebug "Skipping $($TTTracer.FullName)"
					Continue
				}
			}
		}Else{
			$Script:UsePartnerTTD = $True
			$fFound = $True
		}
	}Else{ # Search TTD shipped with TSS_TTD.zip. If not exist, try to search built-in TTD.
		If($Global:ProcArch -eq 'x64'){
			If($global:OSVersion.Build -lt 17763){
				$Script:TTDFullPath = Join-Path -Path ".\BINx64\downlevel" "TTTracer.exe"
			}Else{
				$Script:TTDFullPath = Join-Path -Path ".\BINx64" "TTTracer.exe"
			}
		}ElseIf($Global:ProcArch -eq 'x86'){
			If($global:OSVersion.Build -lt 17763){
				$Script:TTDFullPath = Join-Path -Path ".\BINx86\downlevel" "TTTracer.exe"
			}Else{
				$Script:TTDFullPath = Join-Path -Path ".\BINx86" "TTTracer.exe"
			}
		}
		If(Test-Path -path $Script:TTDFullPath){
			$Script:UsePartnerTTD = $True
			$fFound = $True
			LogInfoFile "Using PartnerTTD from TSS_TTD"
		}Else{ # Finally search built-in TTD (Win10/RS5+), but not in SrvCORE edition
			$BuiltInTTDPath = "C:\Windows\System32\TTTracer.exe"
			If(Test-Path -path $BuiltInTTDPath){
				$Script:TTDFullPath = $BuiltInTTDPath
				$Script:UsePartnerTTD = $False
				$fFound = $True
				LogInfoFile "Using built-in $BuiltInTTDPath"
			}Else{
				$fFound = $False
				LogInfoFile "Could not find TTD for this OS: $global:OSVersion"
			}
		}
	}
	If(!$fFound){
		$Script:TTDFullPath = $Null
		LogInfoFile "Could not find TTD for this OS: $global:OSVersion"
	}
	LogDebug "TTD path = $Script:TTDFullPath"
	EndFunc ($MyInvocation.MyCommand.Name + "($Script:TTDFullPath)")
	Return $Script:TTDFullPath
}

Function Close-Transcript{
	Param(
	[Parameter(Mandatory=$False)]
	[Switch]$ShowMsg=$False
	)
	Try{
		if ($ShowMsg) { LogInfo "Stopping transcript" }
		Stop-Transcript -ErrorAction Ignore | Out-Null
	}Catch{
		$Error.RemoveAt(0)
	}
}

Function CleanUpandExit{
	$CallStack = Get-PSCallStack
	$CallerInfo = $CallStack[1]
	If($CallerInfo.FunctionName -eq '<ScriptBlock>'){
		 $FuncName = 'Main'
	}Else{
		$FuncName = $CallerInfo.FunctionName
	}
	EnterFunc ("$($MyInvocation.MyCommand.Name)" + "(Caller - $($FuncName):$($CallerInfo.ScriptLineNumber))")
	#Run only once
	If(!$script:fCleanUpDidRun){
		# Removing temporary files and registries used in this script.
		If($Null -ne $TempCommandErrorFile -and (Test-Path -Path $TempCommandErrorFile)){
			Remove-Item $TempCommandErrorFile -Force | Out-Null
		}

		# Delete outstanding job
		$TSSv2Job = Get-Job -Name "TSSv2-*"
		If($Null -ne $TSSv2Job){
			$TSSv2Job | Remove-Job
		}

		# Restoring DisableRegistryTools to original value. We do this if original value is other than 0(regedit is disabled by administrator).
		If((IsStart) -or $Stop.IsPresent -or !([string]::IsNullOrEmpty($CollectLog)) -or !([string]::IsNullOrEmpty($StartDiag))){
			If($global:OriginalDisableRegistryTools -gt 0){
				LogInfo "Restoring `'DisableRegistryTools`' to $global:OriginalDisableRegistryTools"
				ToggleRegToolsVal $global:OriginalDisableRegistryTools
			}
		}

		# Restore Quick Edit mode
		If($fQuickEditCodeExist){
			[DisableConsoleQuickEdit]::SetQuickEdit($False) | Out-Null
		}

		# Stop TSS Clock if left running
		If($Stop.IsPresent -or ((IsStart) -and !($StartNoWait.IsPresent))){
			StopTSSClock -NoLogg
		}

		# Stop console logging.
		Close-Transcript
		If($Null -ne $global:LogFolder -and ($Error.Count -ne 0 -and (Test-Path -Path $global:LogFolder)) -and !$Script:fCompressDone){
			$Error | Out-File -FilePath $global:ErrorVariableFile
		}
		EndFunc $MyInvocation.MyCommand.Name
		LogDebug "Exiting script..." "Gray"
	}
	$script:fCleanUpDidRun = $True
	Exit
}

Function ToggleRegToolsVal($TmpVal){
	EnterFunc $MyInvocation.MyCommand.Name
	$DisableRegistryTools = (Get-ItemProperty -ErrorAction Ignore -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System).DisableRegistryTools
	LogDebug "DisableRegistryTools is setting to $TmpVal from $DisableRegistryTools"
	Set-ItemProperty -ErrorAction Ignore -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableRegistryTools -Value $TmpVal
	EndFunc $MyInvocation.MyCommand.Name
}

Function GetETWSessionByLogman{
		# Return: Nr. of ETW sessions found by 'logman.exe -ets'
	[OutputType([String[]])]
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc $MyInvocation.MyCommand.Name

	$ETWSessionList = logman.exe -ets | Out-String	#_#
	$SessionCount = 0
	$RunningSessionList = @()
	$LineNumber = 0

	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$LineNumber++
		# Skip first 3 lines
		If($LineNumber -le 3){
			Continue
		}
		$TraceSessionName = ($Line -Split '\s+')[0]
		$TraceType = ($Line -Split '\s+')[1]
		# Skip line with null string, like '----*' and if first string is space(' ').
		If($TraceSessionName -eq ''){
			Continue
		}ElseIf($TraceSessionName -like '----*'){
			Continue
		}ElseIf($TraceSessionName.Substring(0,1) -eq ' '){
			Continue
		}

		# Also skip line that does not have 2nd token.
		If([string]::IsNullOrEmpty($TraceType)){
			Continue
		}
		$SessionCount++
		$RunningSessionList += $TraceSessionName
	}
	LogDebug "Returning $($RunningSessionList.Count) sessions."
	LogInfoFile "[GetETWSessionByLogman] No. of ETW sessions at $TssPhase : $($RunningSessionList.Count)"
	EndFunc $MyInvocation.MyCommand.Name
	Return $RunningSessionList
}
Function GetETWSessionByPS{
	Param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($global:OSVersion.Build -gt 9600){
		$EtwTraceSessionCount = $(Get-EtwTraceSession * | select Name).count
		LogInfoFile "[Get-EtwTraceSession] No. of ETW sessions at $TssPhase : $EtwTraceSessionCount"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ConvertScenarioTraceNametoTraceName{
	[OutputType([String])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ScenarioTraceName
	)
	If(!($ScenarioTraceName.ToLower().Contains('scenario'))){
		Return $Null
	}
	$TraceName = $ScenarioTraceName -replace ".*Scenario_",""  # TSS_NET_BITSScenario_NET_BITSTrace => NET_BITSTrace
	$TraceName = $TraceName -replace "Trace$",""		  # NET_BITSTrace => NET_BITS
	LogDebug "Returning with $TraceName"
	Return $TraceName
}

Function HasScenarioCommandTypeTrace{
	[OutputType([Bool])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ScenarioName
	)
	# Load all properties with log type and create an array for the list of commands
	$CommandProperties = Get-Variable "*Property" -ValueOnly -ErrorAction Ignore | Where-Object {$_.LogType -eq "Command"}
	$Commandlist = @()
	ForEach($CommandProperty in $CommandProperties){
		$Commandlist += $CommandProperty.Name
	}
	$CommandList += 'NetshScenario'

	# See if the scenario has a trace with command type(WPR, Netsh, Perf, etc).
	$ScenarioDefinition = "$ScenarioName" + "_ETWTracingSwitchesStatus"
	$TracesInScenario = Get-Variable $ScenarioDefinition -ValueOnly -ErrorAction Ignore
	ForEach($Key in $TracesInScenario.Keys){
		$Command = ($Key -split ' ')[0]
		If($CommandList -contains $Command){
			LogDebug "$ScenarioName has $Command command."
			Return $True
		}
	}
	Return $False
}

Function IsStart{
	#[OutputType([Bool])]	#Note: OutputType is not known in PSv2 , (default in 2008-R2) #we# commenting line as of 2022-10-10
	Param( )
	$CallStack = Get-PSCallStack
	$CallerInfo = $CallStack[1]
	If($CallerInfo.FunctionName -eq '<ScriptBlock>'){
		 $FuncName = 'Main'
	}Else{
		$FuncName = $CallerInfo.FunctionName
	}
	EnterFunc ("$($MyInvocation.MyCommand.Name)" + "(Caller - $($FuncName):$($CallerInfo.ScriptLineNumber))")

	If($Null -eq $global:ParameterArray -or $global:ParameterArray.Count -eq 0){
		LogError "IsStart() was called but ParameterArray is not initialized yet."
		Return $False
	}

	$fStart = $False
	Switch($global:ParameterArray[0]){
		'start'				{$fStart = $True}
		'StartAutoLogger'	{$fStart = $True}
		'CollectLog'		{$fStart = $True}
		'StartDiag'			{$fStart = $True}
		'SDP'				{$fStart = $True}
		'stop'{}
		'RemoveAutoLogger'{}
		'set'{}
		'unset'{}
		'help'{}
		'TraceInfo'{}
		'Find'{}
		'FindGUID'{}
		'status'{}
		'List'{}
		'ListETWProviders'{}
		'ListSupportedCommands'{}
		'ListSupportedControls'{}
		'ListSupportedDiag'{}
		'ListSupportedLog'{}
		'ListSupportedNetshScenario'{}
		'ListSupportedNoOptions'{}
		'ListSupportedPerfCounter'{}
		'ListSupportedScenarioTrace'{}
		'ListSupportedSDP'{}
		'ListSupportedTrace'{}
		'ListSupportedWPRScenario'{}
		'ListSupportedXperfProfile'{}
		'Version'{}
		'update'{}
		'xray'{}
		default{
			$fStart = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fStart)")
	Return $fStart
}

Function IsTraceOrDataCollection{
	[OutputType([Bool])]
	$CallStack = Get-PSCallStack
	$CallerInfo = $CallStack[1]
	If($CallerInfo.FunctionName -eq '<ScriptBlock>'){
		 $FuncName = 'Main'
	}Else{
		$FuncName = $CallerInfo.FunctionName
	}
	EnterFunc ("$($MyInvocation.MyCommand.Name)" + "(Caller - $($FuncName):$($CallerInfo.ScriptLineNumber))")

	$Result = $False
	If($Null -eq $global:BoundParameters -or $global:BoundParameters.Count -eq 0){
		LogWarn "BoundParameters[] is not initialized yet."
		Return $False
	}

#	$DataCollectionParameters = @(
#		'Start',
#		'StartAutoLogger',
#		'StartDiag'
#		'StartNoWait'
#		'Stop'
#		'CollectLog'
#		'CollectEventLog'
#		'SDP'
#		'xray'
#		'RemoveAutoLogger'
#	)
	ForEach($key in $global:BoundParameters.Keys){
		If($key -in $DataCollectionParameters){
			$Result = $True
			Break 
		}
	}
	LogDebug "Returning with $Result"
	EndFunc ($MyInvocation.MyCommand.Name + "($Result)")
	Return $Result
}

Function IsServerCore{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$IsServerCore = $False
	If(!(Test-Path -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Server")){
		Return $IsServerCore  # Early return as this is Client SKU.
	}
	# Issue#374 - PSR report is not recorded on DC
	$ServerGuiShell = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels" -ErrorAction Ignore)."Server-Gui-Shell"
	If($ServerGuiShell -eq 1){
		$IsServerCore = $False
		If(!($Version -or $Update)) {LogInfoFile "[$($MyInvocation.MyCommand.Name)] IsServerCore: $IsServerCore - ServerGuiShell: $ServerGuiShell"}
	}else{
		$ServerCore = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels" -ErrorAction Ignore).ServerCore
		If($ServerCore -eq 1){
			$IsServerCore = $True
			If(!($Version -or $Update)) {LogInfoFile "[$($MyInvocation.MyCommand.Name)] IsServerCore: $IsServerCore"}
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($IsServerCore)")
	Return $IsServerCore
}

Function IsDefaultProcmonAltitude{
	#Note: a better test might be to check if desired Altitude does not match current value
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$FltDrvList = FltMc.exe filters| Out-String
	##'Filter Name'     'Num Instances'    Altitude    Frame
	$DefaultProcmonAltitude ="385200"
	$IsDefaultProcmonAltitude = $False
	ForEach($Line in ($FltDrvList -split "`r`n")){
		$Token = $Line -Split '\s+'
		LogDebug "Token: $Token"
		If(($Token[0] -eq "Procmon24") -and ($Token[2].Contains($DefaultProcmonAltitude))){	#  385200 40000
			LogInfo " $Token" -noDate
			LogWarn "Standard Altitude $DefaultProcmonAltitude for Procmon24 has been detected. A reboot will be required for changing ProcmonAltitude($ProcmonAltitude)" "Magenta"
			LogInfo "Please reboot and then use TSS switch -ProcmonAltitude $ProcmonAltitude" "Cyan" 
			$IsDefaultProcmonAltitude = $True
			Break
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($IsDefaultProcmonAltitude)")
	Return $IsDefaultProcmonAltitude
}

Function SaveToTSSReg{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegValue,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object]$RegData
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If(!(Test-Path $global:TSSParamRegKey)){
		LogInfoFile "Saving all parameters to $global:TSSParamRegKey" "Gray" -ShowMsg
		RunCommands "SaveToTSSReg" "New-Item -Path `"$global:TSSParamRegKey`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
	}

	$TSSReg = Get-ItemProperty -Path  $global:TSSParamRegKey
	Switch ($RegData.GetType()){
		'int'{
			$PropertyType = "DWord"
		}
		'string[]'{
			$RegData = $RegData -join ','
			$PropertyType = "String"
		}
		'System.Object[]'{
			$RegData = $RegData -join ','
			$PropertyType = "String"
		}
		default{
			$PropertyType = "String"
		}
	}

	LogInfoFile "Saving $RegValue($RegData) type=$($RegData.GetType()) to $($global:TSSParamRegKey)"
	LogDebug "Saving -Name $RegValue -Value $RegData"
	If($Null -ne $TSSReg.$RegValue){ # Overwrite the value
		Set-ItemProperty -Path $global:TSSParamRegKey -Name $RegValue -Value $RegData
	}Else{
		New-ItemProperty -Path $global:TSSParamRegKey -Name $RegValue -Value $RegData -PropertyType $PropertyType | Out-Null
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwRead-Host-YN{
	<#
	.SYNOPSIS
	 Displays message and reads user input (y or n) from console.
	.DESCRIPTION
	 Reads input from console using choice.exe if script runs on PowerShell or command prompt. In case of ISE, use Read-Host to read user input as ISE does not support interactive command(choice.exe).
	.EXAMPLE
	 1) FwRead-Host-YN -Message "Test messages" # Ask yes/no question without timeout
	 2) FwRead-Host-YN -Message "Test messages" -Timeout 10				 # Ask yes/no question with 10 second timeout
	 3) FwRead-Host-YN -Message "Test messages" -Choices "y"				# Request to input 'y' without timeout
	 4) FwRead-Host-YN -Message "Test messages" -Choices "yn"			   # Same as 1). Ask yes/no question without timeout
	 5) FwRead-Host-YN -Message "Test messages" -Choices "yn" -Timeout 10   # Same as 2). Ask yes/no question with 10 second timeout
	.PARAMETER Message
	 Mandatory option. String message that is displayed.
	.PARAMETER Choices
	 Optional parameter. Currently only 'yn' or 'y' is supported(default is 'yn'). For 'yn', user will be asked yes/no question. For 'y', requests user to input only 'y'.
	.PARAMETER Timeout
	 Optional parameter. Time out value in seconds. By default, there is no timeout and wait for user input permanently.
	 NOTE: This works only if script runs on PowerShell or command prompt. In case of ISE, -Timeout is simply ignored and does not work as ISE does not support choice.exe and Read-Host that does not have timeout feature is used.
	#>
	[OutputType([Bool])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[ValidateNotNullOrEmpty()]
		[ValidateSet("y","yn")] # Currently only 'y' and 'yn' are supported.
		[String]$Choices="yn",
		[Int]$TimeOut=0,
		[String]$Default="y"
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$Answer = $True
	If($global:IsISE -or $global:IsRemoteHost){ # In case of ISE, use Read-Host
		If($Choices -eq "yn"){
			$Message = $Message + " [Y/N]"
		}ElseIf($Choices -eq "y"){
			$Message = $Message + " [Y]"
		}
		$UserInput = Read-Host $Message
		If(![String]::IsNullOrEmpty($UserInput) -and $UserInput.Substring(0,1) -eq 'n'){
			$Answer = $False
		}ElseIf([String]::IsNullOrEmpty($UserInput)){
			LogInfo "RETURN key entered. Take it as 'yes'."
		}
	}Else{
		$Argument = "/C $Choices /M `"$Message`""
		If($TimeOut -gt 0){
			$Argument = $Argument + " /T $TimeOut /D " + $Default
		}
		$Proc = Start-Process -FilePath "Choice" -ArgumentList $Argument -PassThru -Wait -NoNewWindow
		If($Proc.ExitCode -eq 2) { # 'n' case
			$Answer = $False
			#LogInfoFile "[User provided answer:] $Answer"
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($Answer)")
	Return $Answer
}

Function global:FwDisplayPopUp{
	<#
	.SYNOPSIS
	  Displays a notification popup window for N seconds
	.DESCRIPTION
	  Function will display a PopUp window with [OK] button for duration of N seconds with title "TSS PowerShell ..." and closes after N seconds, then TSS script continues and requests input from user
	.EXAMPLE
	  FwDisplayPopUp 5 "[Topic is DFS]"
	#>
	Param(
		[parameter(Mandatory=$false)]
		[int]$Timer = 30,	# default time to display PopUp
		[parameter(Mandatory=$false)]
		[String]$Topic
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$newobject = New-Object -ComObject Wscript.Shell
	#ToDo: place window .TopMost = $true
	$PopUpWin = $newobject.popup("$Topic - Click OK and then Please answer TSS question ",$Timer ," TSS PowerShell window has a question for you! ($Timer sec display) ",0)
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwWaitForProcess{
	<#
	.SYNOPSIS
	  Wait for a background process to complete and terminate process if Timeout (in seconds) expired
	  Returns $True, if process is running more than $pTimeout seconds. This could be used as custom StopCondition trigger
	.DESCRIPTION
	  Wait for a background process to complete and terminate process if Timeout (in seconds) expired
	  i.e. msinfo32.exe is a background process 
	  FwWaitForProcess expects 2 parameters:
	   P1 =$ProcObj is process object that had been started i.e. with "$myNotepad = Start-Process -FilePath 'notepad' -PassThru"
	   P2 = $pTimeout is the timeout in seconds 
	.EXAMPLE
	  FwWaitForProcess $myNotepad 60
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object]$ProcObj,		# background process
		[parameter(Mandatory=$true)]
		[int]$pTimeout			# timeout in seconds
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($Null -ne $ProcObj){
		$TargetProc = Get-Process -Id $ProcObj.Id -ErrorAction SilentlyContinue
		If($Null -ne $TargetProc){
			Try{
				Loginfo "[FwWaitForProcess] Waiting $pTimeout seconds for $($ProcObj.Name) with ID $($ProcObj.Id) to be completed."
				Wait-Process -id $ProcObj.Id -Timeout $pTimeout -ErrorAction Stop
				Return ($Result = $False)
			}Catch{
				Loginfo "[FwWaitForProcess] $($ProcObj.Name) is running more than $pTimeout seconds, so stopping the process." "Magenta"
				$TargetProc.kill()
				Return ($Result = $True)
			}
		}
	}else{ LogInfoFile "[FwWaitForProcess] missing parameter for process object"}
	EndFunc $MyInvocation.MyCommand.Name
	EndFunc ($MyInvocation.MyCommand.Name + "($Result)")
}

function global:FwIsNumeric ($Value) {
	# validate if $Value is a valid Numeric number (like PID or EventID)
	return $Value -match "^[\d\.]+$"
}

function global:FwValidateInteger{
	# validate if the value of an input argument is of type [Int]
	# expects two parameters
	#  1. actual Value
	#  2. [optional] Name of argument to validate
	Param(
		$variableValue,		# actual Value
		$variableName		# Name of argument to validate
		)
	EnterFunc $MyInvocation.MyCommand.Name
	[int]$Initvalue = 0; $read = $variableValue; if( ![int]::TryParse( $read, [ref]$Initvalue ) ) { $script:fBailOut=$True; Write-Host -ForegroundColor Red "Argument '$read' ($variableName) is not of type [Int]. Please supply a valid argument for '$variableName'."}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwValidatePidOrProcessOrService{
	# validate if given PID,Process.exe or Service name is running
	Param(
		[string[]]$PID_or_Process_Or_Service	# PID|ProcessName.exe|Service-Name
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$Tokens = $PID_or_Process_Or_Service -split ','
	ForEach($Token in $Tokens) {
		LogDebug "Validation of ProcName/PID/SVC: $Token "
		# case of PID
		If (FwIsNumeric $Token){
			LogDebug "checking PID: $Token "
			If (Get-Process -Id $Token -ErrorAction SilentlyContinue) {	Write-host -ForegroundColor Green "[Validate Arg] PID $Token exists"}else{$script:fBailOut=$True; Write-host -ForegroundColor Red "[Validate Arg] PID $Token does NOT exist. Please specify a valid Process PID"}
			Return
		}
		# case of Process name with .exe
		If ($Token -match ".exe"){ 
			$ProcName = $Token.Replace('.exe','')
			LogDebug "checking ProcName: $ProcName "
			If ($MyProc = Get-Process -Name $ProcName -ErrorAction SilentlyContinue) {Write-host -ForegroundColor Green "[Validate Arg] Process $Token (PID: $($MyProc.Id)) exists."}else{$script:fBailOut=$True; Write-host -ForegroundColor Red "[Validate Arg] Process $Token does NOT exist. Please specify a valid Process name"}
		}
		Else{ # case of Service name 
			LogDebug "checking Service name: $Token "
			If ($MySvc = Get-Service -Name $Token -ErrorAction SilentlyContinue) {Write-host -ForegroundColor Green "[Validate Arg] Service $Token exists (Status: $($MySvc.Status))"}else{$script:fBailOut=$True; Write-host -ForegroundColor Red "[Validate Arg] Could not find a Service with name $Token. `n*** Please enter a valid Service name. ***"}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function ValidateColonSeparatedOptions{
	# validate if Option input arguments match type 
	# 3 expected input arguments are in form of "a:b:c" "String:Int:Int" "MyOpt:MyVal1:myVal2"
	Param(
		[string]$ColonSeparatedOptions,			# actual input string: "a:b:c"
		[string]$ColonSeparatedExpectedTypes,	# argument types: "String:Int:Int"
		[string]$ColonSeparatedParamNames		# argument names: "MyOpt:MyVal1:myVal2" 
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$TokensOption = $ColonSeparatedOptions -split ':'
	LogDebug "ColonSeparatedOptions:	   $TokensOption"
	$TokensExpectedType = $ColonSeparatedExpectedTypes -split ':'
	LogDebug "ColonSeparatedExpectedTypes: $TokensExpectedType" 
	$TokensParamNames = $ColonSeparatedParamNames -split ':'
	LogDebug "ColonSeparatedParamNames:	$TokensParamNames"
	$i=-1
	ForEach($Token in $TokensOption){
		$i+=1
		if($($TokensExpectedType[$i]) -match "int") {
			FwValidateInteger $Token $TokensParamNames[$i]
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function ValidateCmdLineInputArgs{
	# Exit early if Input arguments are invalid # (#707)
	EnterFunc $MyInvocation.MyCommand.Name
	If($global:ParameterArray -notcontains 'noArgCheck'){
		LogDebug "we will exit early if Input arguments are invalid" # (#707)
		# check ETLOptions
		If($global:BoundParameters.ContainsKey('ETLOptions')){
			ValidateColonSeparatedOptions $ETLOptions "String:Int:Int:Int" "circular|newfile:ETLMaxSizeMB:ETLNumberToKeep:ETLFileMax" 
		}
		# check ProcDumpInterval
		If($global:BoundParameters.ContainsKey('ProcDumpInterval')){
			if ($ProcDumpInterval -match ":00") {$script:fBailOut=$True; Write-host -ForegroundColor Red "[Validate Arg] ProcDumpInterval cannot be '00' seconds. Please specify a valid Interval "}
			ValidateColonSeparatedOptions $ProcDumpInterval "Int:Int" "Number_of_dumps:Interval_in_seconds" 
		}
		# check ProcDump
		If($global:BoundParameters.ContainsKey('ProcDump')){
			FwValidatePidOrProcessOrService $ProcDump
		}
		# check Radar
		If($global:BoundParameters.ContainsKey('Radar')){
			FwValidatePidOrProcessOrService $Radar
		}
		# check TTD
		If(($global:BoundParameters.ContainsKey('TTD')) -and !($TTDMode -eq "onLaunch") -and !($ScenarioName -eq 'NET_WebCliTTD')){
			FwValidatePidOrProcessOrService $TTD
		}
		# check options for -WaitEvent <Evt|LogFile|PortLoc|PortDest|NoNetConn|Svc|Process|Share|SMB|HTTP|RDP|WINRM|LDAP|RegData|RegValue|RegKey|File|Time|HNSL2Tunnel|StopCondition|HighCPU|HighMemory|Signal|ATQ>
		If($global:BoundParameters.ContainsKey('WaitEvent')){
			$WaitOptions = $WaitEvent -split ':'
			$WaitType = ($WaitEvent -split ':')[0]
			Switch($WaitType){
				#'Evt'		{ ValidateColonSeparatedOptions $WaitEvent "String:Int:String:Int:Int" "Evt:EventID:Eventlog_name:CheckIntInSec:StopWaitTimeInSec"}	# EventID/EventID would be string!
				'Evt'		{ ValidateColonSeparatedOptions $WaitEvent "String:String:String:Int:Int" "Evt:EventID:Eventlog_name:CheckIntInSec:StopWaitTimeInSec"}	# workaround for issue #906
				#'LogFile'	{ if ($($WaitOptions.count) -lt 4){ Write-host "LogFile expects two arguments: 'Path_to_LogFile':'Search_string'" "Magenta"}; ValidateColonSeparatedOptions $WaitEvent "String:String:String" "LogFile:Path_to_LogFile:Search_string"}
				'PortLoc'	{ ValidateColonSeparatedOptions $WaitEvent "String:Int" "PortLoc:Port_number"}
				'PortDest'	{ ValidateColonSeparatedOptions $WaitEvent "String:String:Int" "PortDest:RemoteHost:Port_number"}
				'Process'	{ FwValidatePidOrProcessOrService $($WaitOptions[1] + ".exe")}
				'Time'		{ ValidateColonSeparatedOptions $WaitEvent "String:Int:String" "Time:number_of_Sec/Min:Sec"}
				'StopEvt'	{ ValidateColonSeparatedOptions $WaitEvent "String:Int:String" "StopEvt:EventID:Eventlog_name"}
				'HighCPU'	{ ValidateColonSeparatedOptions $WaitEvent "String:Int" "HighCPU:CpuThreshold"}
				'HighMemory'{ ValidateColonSeparatedOptions $WaitEvent "String:Int" "HighMemory:MemoryThreshold"}
				default		{ # Do nothing
							}
			}
		}
		# bail out with hints if at least one check failed
		If($script:fBailOut) {
			LogInfo "[$($MyInvocation.MyCommand.Name)] Your TSS input arguments are invalid. Please double-check and run again with proper command-line arguments." "Magenta"
			CleanupAndExit
		}
	}else{ LogInfo "Skipping ValidateCmdLineInputArgs() as -noArgCheck was specified." "Gray"}
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion common functions used by POD module

Function DisplayDataUploadRequestInError{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message
	)
	$CallStack = Get-PSCallStack
	$CallerInfo = $CallStack[1]
	If($CallerInfo.FunctionName -eq '<ScriptBlock>'){
		 $FuncName = 'Main'
	}Else{
		$FuncName = $CallerInfo.FunctionName
	}
	EnterFunc ("$($MyInvocation.MyCommand.Name)" + "(Caller - $($FuncName):$($CallerInfo.ScriptLineNumber))")
	LogInfo "ERROR: $Message" "Red"
	LogInfo "==> Please send below log files (best send the compressed content of $global:LogFolder) to our upload site (MS workspace)." "Cyan"
	LogInfo "	- All log files in $global:LogFolder" "Yellow"
	LogInfo "	 - $global:TranscriptLogFile" "Yellow"
	LogInfo "	 - $global:ErrorLogFile" "Yellow"
	LogInfo "	 - $global:ErrorVariableFile" "Yellow"
	LogInfo "Please run .\$($global:ScriptName) -stop -noBasiclog -noXray, before you start a new TSS run." "Cyan"
	EndFunc $MyInvocation.MyCommand.Name
}

Function IsLiteMode{
	[OutputType([Bool])]
	$NumExecutable = (Get-ChildItem "$global:ScriptFolder\BIN\" -Name "*.exe" -ErrorAction Ignore).count 
	$NumExecutable += (Get-ChildItem "$global:ScriptFolder\BINx86\" -Name "*.exe" -ErrorAction Ignore).count
	$NumExecutable += (Get-ChildItem "$global:ScriptFolder\BINx64\" -Name "*.exe" -ErrorAction Ignore).count
	LogDebug "The number of executables in \BIN*\ folders is $NumExecutable"
	If($NumExecutable -lt 30){	#we# replaced 20 with 30
		Return $True
	}Else{
		Return $False
	}
}

Function global:FwIsOsCommandAvailable{
	# This function verifies if OS-Built-in command exists.
	# It returns True, if command $OsCommand exists, otherwise False
	[OutputType([Bool])]
	Param(
		[parameter(Mandatory=$false)]
		[String]$OsCommand
	)	
	EnterFunc $MyInvocation.MyCommand.Name
	$Result = $False
	$ApplicationInfo = Get-Command $OsCommand -ErrorAction Ignore
	If(!$ApplicationInfo) {LogWarn "OS built-in command '$OsCommand' does not exist on this system!" "Magenta"}else{$Result = $True}
	# special check for Reg.exe, which might have been replaced on some systems with a non-MS *.exe
	If(($Null -ne $ApplicationInfo) -and ($OsCommand -eq "Reg.exe")){
		$CompanyName = $ApplicationInfo.FileVersionInfo.CompanyName
		If($CompanyName -like "*Microsoft*"){
			Reg.exe query HKLM | Out-Null
			If($LASTEXITCODE -eq 0){
				$Result = $True
			}
		}
	}
	EndFunc "$($MyInvocation.MyCommand.Name) returning with $Result"
	Return $Result
}

Function global:FwIsCollectFunctionAvailable{
	# This function verifies if Collect...Log functions exist.	#_# workitem #267
	# It returns True, if function exists, otherwise False
	EnterFunc $MyInvocation.MyCommand.Name
	$CumResult = $True
	ForEach($CompName in $CollectLog){
		If ($CompName -NotMatch "BasicLog"){ #fix #267
			$ApplicationInfo = Get-Command ("Collect" + $CompName + "Log") -CommandType Function -ErrorAction Ignore
			If($ApplicationInfo) {$CumResult = ($CumResult -and $True)}else{ LogError " CollectLog function '$CompName' is not defined!" "Red";$CumResult = $False}
		}
	}
	EndFunc "$($MyInvocation.MyCommand.Name) returning with $CumResult"
	Return $CumResult
}

#endregion Common utilities

#region FW Core functions
Function CreateETWTraceProperties{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[Object]]$TraceDefinitionArray
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If($TraceDefinitionArray.Count -eq 0 -or $Null -eq $TraceDefinitionArray){
		Throw '$TraceDefinitionList is null.'
	}

	# Normal case
	Try{
		LogDebug ('Adding traces to PropertyArray')
		ForEach($TraceDefinition in $TraceDefinitionArray)
		{
			$TraceName = $TraceDefinition.Name + 'Trace'
			If([string]::IsNullOrEmpty($TraceDefinition.MultipleETLFiles)){
				$TraceDefinition.MultipleETLFiles = 'no'
			}
			$TraceProperty = @{
				Name = $TraceDefinition.Name
				TraceName = $ScriptPrefix + '_' + $TraceDefinition.Name + 'Trace'
				LogType = 'ETW'
				CommandName = 'logman.exe'
				Providers = $TraceDefinition.Provider  # this is the good moment to report duplicate guids in err log
				LogFileName = "`"$global:LogFolder\$LogPrefix$TraceName.etl`""
				StartOption = $Null
				StopOption = $Null
				PreStartFunc = $TraceDefinition.Name + 'PreStart'
				StartFunc = $Null
				StopFunc = $Null
				PostStopFunc = $TraceDefinition.Name + 'PostStop'
				DiagFunc = 'Run' + $TraceDefinition.Name + 'Diag'
				DetectionFunc = $Null
				AutoLogger =  @{
					AutoLoggerEnabled = $False
					AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\$TraceName-AutoLogger.etl`""
					AutoLoggerSessionName = $AutoLoggerPrefix + $ScriptPrefix + '_' + $TraceName
					AutoLoggerStartOption = $Null
					AutoLoggerStopOption = $Null
					AutoLoggerKey = $AutoLoggerBaseKey + $ScriptPrefix + '_' + $TraceName
				}
				Wait = $Null
				SupportedOSVersion = $Null # Any OSes
				Status = $TraceStatus.Success
				MultipleETLFiles = $TraceDefinition.MultipleETLFiles
				StartPriority = $StartPriority.ETW
				StopPriority = $StopPriority.ETW
				WindowStyle = $Null
			}
			#LogDebug ($TraceProperty.Name)
			$script:ETWPropertyList.Add($TraceProperty)  
		}
	}Catch{
		Throw ('An error happened during creating property for ' + $TraceDefinition.Name)
	}

	If($script:ETWPropertyList.Count -eq 0){
		Throw ('Failed to create ETWPropertyList. ETWPropertyList.Count is 0. Maybe bad entry in $TraceDefinitionList caused this.')
	}
	LogDebug ('Returning ' + $script:ETWPropertyList.Count  + ' properties.')
	EndFunc $MyInvocation.MyCommand.Name
}

Function AddTraceToLogCollector{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$TraceName
	)
	EnterFunc ($MyInvocation.MyCommand.Name + ' with ' + $TraceName)

	If($TraceName -like "*Scenario_*"){ # Scenario case
		$Token = $TraceName -split ("Scenario_")
		$TraceObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq $Token[1]}
		If($Null -ne $TraceObject){
			LogDebug "Creating a trace name for $TraceName"
			$TraceObject = CreateTraceObjectforScenarioTrace ($TraceName + 'Trace')
			If($Null -ne $TraceObject){
				LogDebug "New object for scnario trace $TraceName was created."
			}Else{
				LogError "Failed to create trace object for $TraceName"
			}
		}
	}Else{ # Normal case
		$TraceObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq $TraceName}
	}
	if($TraceName -ne "Debug"){ #Debug is switch
		if($Null -eq $TraceObject){
			Throw 'Trace ' + $TraceName + ' is not registered in trace catalog.'
		}

		# Version check
		If($Null -ne $TraceObject.SupportedOSVersion){
			If(!(FwIsSupportedOSVersion $TraceObject.SupportedOSVersion)){
				$ErrorMessage = $TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupportedOSVersion.OS + ' Build ' + $TraceObject.SupportedOSVersion.Build + '].'
				LogError $ErrorMessage
				CleanUpandExit # Early return as non supported option is specified.
			}
		}

		# Duplication check
		$tmpObject = $LogCollector | Where-Object{$_.TraceName -eq $TraceObject.TraceName}
		If($Null -ne $tmpObject){
			LogInfo "ERROR: Tried to start trace for $($TraceObject.TraceName) twice. Usually this happens when a scenario trace and a normal trace that is contained in the scenario are started at the same time. Please check what traces are contained in the scenario with below command." "Red"
			LogInfo "=> .\$($global:ScriptName) -TraceInfo <ScenarioName>" "Yellow"
			CleanUpandExit
		}
		LogDebug "Adding $($TraceObject.TraceName) to trace list"
		$LogCollector.Add($TraceObject)
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return
}

Function DumpCollection{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object[]]$Collection
	)
	EnterFunc $MyInvocation.MyCommand.Name

	LogDebug '--------------------------------------------------'
	ForEach($TraceObject in $Collection){
	   LogDebug ('Name              : ' + $TraceObject.Name)
	   LogDebug ('TraceName         : ' + $TraceObject.TraceName)
	   LogDebug ('LogType           : ' + $TraceObject.LogType)
	   LogDebug ('CommandName       : ' + $TraceObject.CommandName)
	   If($Null -eq $TraceObject.Providers){
		   $ProviderProp = ''
	   }Else{
		   $ProviderProp = $TraceObject.Providers[0] + '...  --> ' + $TraceObject.Providers.Count + ' providers'
	   }
	   LogDebug ('Providers         : ' + $ProviderProp)
	   LogDebug ('LogFileName       : ' + $TraceObject.LogFileName)
	   LogDebug ('StartOption       : ' + $TraceObject.StartOption)
	   LogDebug ('StopOption        : ' + $TraceObject.StopOption)
	   LogDebug ('PreStartFunc      : ' + $TraceObject.PreStartFunc)
	   LogDebug ('StartFunc         : ' + $TraceObject.StartFunc)
	   LogDebug ('StopFunc          : ' + $TraceObject.StopFunc)
	   LogDebug ('PostStopFunc      : ' + $TraceObject.PostStopFunc)
	   LogDebug ('DetectionFunc     : ' + $TraceObject.DetectionFunc)
	   LogDebug ('AutoLogger        : ' + $TraceObject.AutoLogger)
	   If($Null -ne $TraceObject.AutoLogger){
		   LogDebug (' - AutoLoggerEnabled     : ' + $TraceObject.AutoLogger.AutoLoggerEnabled)
		   LogDebug (' - AutoLoggerLogFileName : ' + $TraceObject.AutoLogger.AutoLoggerLogFileName)
		   LogDebug (' - AutoLoggerSessionName : ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
		   LogDebug (' - AutoLoggerStartOption : ' + $TraceObject.AutoLogger.AutoLoggerStartOption)
		   LogDebug (' - AutoLoggerStopOption  : ' + $TraceObject.AutoLogger.AutoLoggerStopOption)
		   LogDebug (' - AutoLoggerKey         : ' + $TraceObject.AutoLogger.AutoLoggerKey)
	   }
	   LogDebug ('Wait                         : ' + $TraceObject.Wait)
	   If($Null -ne $TraceObject.SupportedOSVersion){
		   $OSver = $TraceObject.SupportedOSVersion.OS
		   $Build = $TraceObject.SupportedOSVersion.Build
		   $OSVersionStr = 'Windows ' + $OSver + ' Build ' + $Build
	   }Else{
			$OSVersionStr = ''
	   }
	   LogDebug ('SupportedOSVersion: ' + $OSVersionStr)
	   LogDebug ('Status            : ' + $TraceObject.Status)
	   LogDebug ('MultipleETLFiles  : ' + $TraceObject.MultipleETLFiles)
	   LogDebug ('StartPriority     : ' + $TraceObject.StartPriority)
	   LogDebug ('StopPriority      : ' + $TraceObject.StopPriority)
	   LogDebug ('WindowStyle       : ' + $TraceObject.WindowStyle)
	   LogDebug '--------------------------------------------------'
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DumpTraceObject{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object[]]$Collection
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($Null -eq $Collection){
		LogError "Passed trace object list is null."
		return
	}
	ForEach($TraceObject in $Collection){
		If($Collection.Count -gt 1){
			Write-Host '--------------------------------------------------'
		}
		Write-Host "Name			 : $($TraceObject.Name)"
		Write-Host "TraceName		: $($TraceObject.TraceName)"
		Write-Host "LogType		  : $($TraceObject.LogType)"
		Write-Host "CommandName	  : $($TraceObject.CommandName)"
		Write-Host "Provider		 :"
		If($Null -eq $TraceObject.Providers){
			Write-Host "   => No provider"
		}Else{
			ForEach($Provider in $TraceObject.Providers){
				Write-Host "   $Provider"
			}
		}
		Write-Host "LogFileName	  : $($TraceObject.LogFileName)"
		Write-Host "StartOption	  : $($TraceObject.StartOption)"
		Write-Host "StopOption	   : $($TraceObject.StopOption)"
		Write-Host "PreStartFunc	 : $($TraceObject.PreStartFunc)"
		Write-Host "StartFunc		: $($TraceObject.StartFunc)"
		Write-Host "StopFunc		 : $($TraceObject.StopFunc)"
		Write-Host "PostStopFunc	 : $($TraceObject.PostStopFunc)"
		Write-Host "DetectionFunc	: $($TraceObject.DetectionFunc)"
		Write-Host "AutoLogger	   :"
		If($Null -ne $TraceObject.AutoLogger){
			Write-Host "  - AutoLoggerEnabled	 : $($TraceObject.AutoLogger.AutoLoggerEnabled)"
			Write-Host "  - AutoLoggerLogFileName : $($TraceObject.AutoLogger.AutoLoggerLogFileName)"
			Write-Host "  - AutoLoggerSessionName : $($TraceObject.AutoLogger.AutoLoggerSessionName)"
			Write-Host "  - AutoLoggerStartOption : $($TraceObject.AutoLogger.AutoLoggerStartOption)"
			Write-Host "  - AutoLoggerStopOption  : $($TraceObject.AutoLogger.AutoLoggerStopOption)"
			Write-Host "  - AutoLoggerKey		 : $($TraceObject.AutoLogger.AutoLoggerKey)"
		}
		Write-Host "Wait			: $($TraceObject.Wait)"
		If($Null -ne $TraceObject.SupportedOSVersion){
			$OSver = $TraceObject.SupportedOSVersion.OS
			$Build = $TraceObject.SupportedOSVersion.Build
			$OSVersionStr = 'Windows ' + $OSver + ' Build ' + $Build
		}Else{
			 $OSVersionStr = ''
		}
		Write-Host "SupportedOSVersion: $($OSVersionStr)"
		Write-Host "Status			: $($TraceObject.Status)"
		Write-Host "MultipleETLFiles  : $($TraceObject.MultipleETLFiles)"
		Write-Host "StartPriority	 : $($TraceObject.StartPriority)"
		Write-Host "StopPriority	  : $($TraceObject.StopPriority)"
		Write-Host "WindowStyle	   : $($TraceObject.WindowStyle)"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function InspectProperty{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Hashtable]$Property
	)
	#EnterFunc $MyInvocation.MyCommand.Name
	# Name
	If($Null -eq $Property.Name -or $Property.Name -eq ''){
		Throw 'ERROR: Object name is null.'
	}

	# TraceName
	If($Null -eq $Property.TraceName -or $Property.TraceName -eq ''){
		Throw 'ERROR: TraceName is null.'
	}

	# LogType
	ForEach($LogType in $script:LogTypes){
		If($Property.LogType -eq $LogType){
			$fResult = $True
			Break
		} 
	}
	If(!$fResult){
		Throw 'ERROR: unknown log type: ' + $Property.LogType
	}

	Switch($Property.LogType){
		# ETW must have:
		#   - providers
		#   - AutoLogger
		#   - AutoLoggerLogFileName/AutoLoggerSessionName
		'ETW' {
			If($Null -eq $Property.Providers){
				Throw 'ERROR: Log type is ' + $Property.LogType + ' but there are no providers.'
			}
			If($Null -eq $Property.AutoLogger){
				Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLogger is no set.'
			}Else{
				If($Null -eq $Property.AutoLogger.AutoLoggerLogFileName){
					Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerLogFileName is not specified in this property.'
				}
				If($Null -eq $Property.AutoLogger.AutoLoggerSessionName){
					Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerSessionName is not specified in this property.'
				}
			}
		}
		# Command must have:
		#   - CommandName
		#   - StartOption/StopOption
		#   - If AutoLogger is supported:
		#	   - must have AutoLoggerLogFileName/AutoLoggerStartOption/AutoLoggerStopOption
		'Command' {
			If($Null -eq $Property.CommandName){
				Throw 'ERROR: Log type is ' + $Property.LogType + " but 'CommandName' is not specified in this property."
			}
			If($Property.LogType -eq 'Command' -and ($Null -eq $Property.StartOption -or $Null -eq $Property.StopOption)){
				Throw 'ERROR: Log type is ' + $Property.LogType + ' but StartOption/StopOption is not specified in this property.'
			}
			If([string]::IsNullOrEmpty($Property.StopTimeOutInSec)){
				Throw "ERROR: Command type property must have StopTimeOutInSec but it is null"
			}
			If($Null -ne $Property.AutoLogger){
				If($Null -eq $Property.AutoLogger.AutoLoggerLogFileName){
					Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerLogFileName is not specified in this property.'
				}
				If($Null -eq $Property.AutoLogger.AutoLoggerStartOption){
					Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerStartOption is not specified in this property.'
				}
				If($Null -eq $Property.AutoLogger.AutoLoggerStopOption){
					Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerStopOption is not specified in this property.'
				}
			}
		}
		'Custom' {
			If($Null -ne $Property.StartFunc){
				Try{
					Get-Command $Property.StartFunc -ErrorAction Stop | Out-Null
				}Catch{
					Throw 'ERROR: ' + $Property.StartFunc + ' is not implemented in this script.'
				}
			}
			If($Null -ne $Property.StopFunc){
				Try{
					Get-Command $Property.StopFunc -ErrorAction Stop | Out-Null
				}Catch{
					Throw 'ERROR: ' + $Property.StopFunc + ' is not implemented in this script.'
				}
			}
			If($Null -ne $Property.DetectionFunc){
				Try{
					Get-Command $Property.DetectionFunc -ErrorAction Stop | Out-Null
				}Catch{
					Throw 'ERROR: ' + $Property.DetectionFunc + ' is not implemented in this script.'
				}
			}

			If($Null -eq $Property.Status){
				Throw('ERROR: Status is not initialized.')
			}
			# No additonal tests needed for Custom object
			Return
		}
	}

	# LogFileName
	If($Null -eq $Property.LogFileName){
		Throw 'ERROR: LogFileName must be specified.'
	}

	If($Null -eq $Property.Status){
		Throw('ERROR: Status is not initialized.')
	}
	#EndFunc $MyInvocation.MyCommand.Name	
}

Function ValidateCollection{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object[]]$Collection
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$ErrorCount=0

	ForEach($TraceObject in $Collection){
		# Name
		If($Null -eq $TraceObject.Name -or $TraceObject.Name -eq '')
		{
			Throw "[$($TraceObject.Name)] ERROR: Name is null."
			$ErrorCount++
		}
		# LogType
		$fValidLogType = $False
		ForEach($LogType in $LogTypes){
			If($TraceObject.LogType -eq $LogType){
				$fValidLogType = $True
				Break
			} 
		}
		If(!$fValidLogType){
			Throw "[$($TraceObject.Name)] ERROR: unknown log type: $($TraceObject.LogType)"
		}

		# LogFileName/Providers/AutoLogger/AutoLoggerLogFileName/AutoLoggerSessionName
		# => These may be null in some cases. We don't check them.

		# Command
		If($TraceObject.LogType -eq 'Command' -and $Null -eq $TraceObject.CommandName){
			Throw "[$($TraceObject.Name)] ERROR: Log type is Commad but 'CommandName' is not specified in this TraceObject."
		}
	}

	# For custom object
	If($Null -ne $TraceObject.StartFunc){
		Try{
			Get-Command $TraceObject.StartFunc -ErrorAction Stop | Out-Null
		}Catch{
			Throw "[$($TraceObject.Name)] ERROR: $($TraceObject.StartFunc) is not implemented in this script."
		}
	}
	If($Null -ne $TraceObject.StopFunc){
		Try{
			Get-Command $TraceObject.StopFunc -ErrorAction Stop | Out-Null
		}Catch{
			Throw "[$($TraceObject.Name)] ERROR: $($TraceObject.StopFunc) is not implemented in this script."
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function GetExistingTraceSession{
	[OutputType("System.Collections.Generic.List[PSObject]")]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	If($GlobalTraceCatalog.Count -eq 0){
		LogInfo 'No traces in GlobalTraceCatalog.' "Red"
		CleanUpandExit
	}
	Try{
		ValidateCollection $GlobalTraceCatalog
	}Catch{
		LogException "An exception happened in ValidateCollection" $_
		CleanUpandExit
	}

	$RunningTraces = New-Object 'System.Collections.Generic.List[PSObject]'
	$Script:RunningScenarioTraceList = New-Object 'System.Collections.Generic.List[PSObject]'
	$ETWSessionList = logman.exe -ets | Out-String	#_#
	GetETWSessionByPS [GetExistingTraceSession]
	$CurrentSessinID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
	$Processes = Get-Process | Where-Object{$_.SessionID -eq $CurrentSessinID}

	ForEach($TraceObject in $GlobalTraceCatalog){
		Switch($TraceObject.LogType) {
			'ETW' {
				#LogDebug "Checking existing session of $($TraceObject.TraceName)"
				ForEach($Line in ($ETWSessionList -split "`r`n")){
						$Token = $Line -Split '\s+' #we# this will detect 'NT Kernel Logger' as 'NT'
						$TraceName = $Token[0] -replace ("Trace.*","Trace")
						if((($TraceName -eq "NT") -and ($TraceObject.Name -eq "WIN_Kernel")) -or ($TraceName -eq $TraceObject.TraceName)){
						#If($TraceName -eq $TraceObject.TraceName){
							LogDebug "Found running trace session($TraceName)." "Yellow"
							$TraceObject.Status = $TraceStatus.Running
							$RunningTraces.Add($TraceObject)
							Break
						}ElseIf($TraceName -like ("*Scenario_" + $TraceObject.Name + "Trace*")){ # Scenario trace
							$NewTraceObject = CreateTraceObjectforScenarioTrace $TraceName
							If($Null -ne $NewTraceObject){
								LogDebug "Found running scenario trace session $($NewTraceObject.TraceName)" "Yellow"
								$NewTraceObject.Status = $TraceStatus.Running
								$RunningTraces.Add($NewTraceObject)
							}Else{
								LogError "Failed to create trace object for $TraceName"
							}
						}ElseIf($TraceName -like ("*Scenario_METL_$($TraceObject.Name)_*")){ # METL in Scenario trace
							$NewTraceObject = CreateTraceObjectforMultiETLTrace $TraceName
							If($Null -ne $NewTraceObject){
								LogDebug "Found running METL in scenario trace session $($NewTraceObject.TraceName)" "Yellow"
								$NewTraceObject.Status = $TraceStatus.Running
								$RunningTraces.Add($NewTraceObject)
							}Else{
								LogError "Failed to create trace object for $TraceName"
							}
						}
					}
			}
			'Command' {
				LogDebug ("[$($TraceObject.LogType)] Checking if $($TraceObject.Name) is still enabled.")
				Switch($TraceObject.Name) {
					'WPR' {
						ForEach($Line in ($ETWSessionList -split "`r`n")){
							$Token = $Line -Split '\s+'
							If($Token[0] -eq 'WPR_initiated_WprApp_WPR' -or $Token[0] -eq 'WPR_initiated_WprApp_boottr_WPR'){
								LogDebug "Found existing $($TraceObject.Name) session." "Yellow"
								$TraceObject.Status = $TraceStatus.Running
								$RunningTraces.Add($TraceObject)
								FwGetLogmanInfo _WPR_
								Break
							}
						}
					}
					'Xperf' {
						# We use a log file for xperf to see if the xperf is actively running.
						$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
						$LogFolderInReg = $RegValue.LogFolder
						If(![String]::IsNullOrEmpty($LogFolderInReg)){
							$XperfFileName = "$LogFolderInReg\xperf.etl"
							If(Test-Path -Path $XperfFileName){
								LogDebug "Found existing $($TraceObject.Name) session." "Yellow"
								$TraceObject.Status = $TraceStatus.Running
								$RunningTraces.Add($TraceObject)
								FwGetLogmanInfo _Xperf_
								Break
							}
						}
					}
					'Netsh' {
						$NetshSessionName = 'NetTrace'
						ForEach($Line in ($ETWSessionList -split "`r`n")){
							$Token = $Line -Split '\s+'							
							If($Token[0].Contains($NetshSessionName)){
								$TraceObject.Status = $TraceStatus.Running
								$RunningTraces.Add($TraceObject)
								LogInfoFile ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
								FwGetLogmanInfo _NetSh_
								Break
							}
						}
					}
					'Procmon' {
						$ProcmonProcess = Get-Process -name "Procmon*" -ErrorAction Ignore
						$FilterDriverList = fltmc | Out-String
						ForEach($Line in ($FilterDriverList -split "`r`n")){ # Get line
							# Split line by space and token[0] is driver name and token[1] is the number of instance.
							$Token = $Line -Split '\s+' 
							If([String]$Token[0] -like "Procmon*"){
								If($Token[1] -ne "0"){
									If((($Null -ne $ProcmonProcess) -and ($global:ParameterArray -contains 'Start' -or $Status.IsPresent -or $Stop.IsPresent)) -or $script:StopAutologger){
										LogDebug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
										$TraceObject.Status = $TraceStatus.Running
										$RunningTraces.Add($TraceObject)
										FwGetLogmanInfo _ProcMon_
										break
									}
								}
							}
						}
					}
					'PSR' {
						$PSRProcess = $Processes | Where-Object{$_.Name.ToLower() -eq 'psr'}
						If($PSRProcess.Count -ne 0){
							$TraceObject.Status = $TraceStatus.Running
							$RunningTraces.Add($TraceObject)
							LogDebug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
						}
					}
					'Video' {
						$VideoProcess = $Processes | Where-Object{$_.Name.ToLower() -eq 'recordercommandline'}
						If($VideoProcess.Count -ne 0){
							$TraceObject.Status = $TraceStatus.Running
							$RunningTraces.Add($TraceObject)
							LogDebug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
						}
					}
				}
			}
			'Perf' {
				LogDebug ("[$($TraceObject.LogType)] Checking if $($TraceObject.Name) is still enabled.")
				$datacollectorset = new-object -COM Pla.DataCollectorSet
				Try{  
					$datacollectorset.Query($TraceObject.Name, $env:computername)
				}Catch{
					# If 'Perf' is not running, exception happens and this is actually not error. So just log it if -DebugMode.
					$Error.RemoveAt(0)
					LogDebug ('INFO: An Exception happened in Pla.DataCollectorSet.Query for ' + $TraceObject.Name)
					Break
				}
			
				#Status ReturnCodes: 0=stopped 1=running 2=compiling 3=Pending (legacy OS prior Vista) 4=unknown (usually AutoLogger)
				If($datacollectorset.Status -ne 1){
					LogDebug ('PerfMon status is ' + $datacollectorset.Status)
					Break
				}
				$TraceObject.Status = $TraceStatus.Running
				$RunningTraces.Add($TraceObject)
				LogDebug ('Found existing ' + $TraceObject.Name + ' session.')
				FwGetLogmanInfo _PerfMon_
			}
			'Custom' {
				LogDebug ("[$($TraceObject.LogType)] Checking if $($TraceObject.Name) is still enabled.")
				If($Null -ne $TraceObject.DetectionFunc){
					$fResult = & $TraceObject.DetectionFunc
					If($fResult){
						$TraceObject.Status = $TraceStatus.Running
						$RunningTraces.Add($TraceObject)
						LogDebug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
						FwGetLogmanInfo _Custom_
					}
				}Else{
					LogDebug ($TraceObject.Name + ' does not have detection function.')
				}
			}
			Default {
				LogInfo ('Unknown log name ' + $TraceObject.LogType) "Red"
			}
		}
	}

	$RunningMultiETLTraceList = GetRunningMultiETLTrace
	ForEach($RunningMultiETLTraceObject in $RunningMultiETLTraceList){
		LogDebug ('Found running multi elt file trace ' + $RunningMultiETLTraceObject.TraceName) "Yellow"
		$RunningTraces.Add($RunningMultiETLTraceObject)
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $RunningTraces
}

Function GetRunningMultiETLTrace{
	[OutputType("System.Collections.Generic.List[PSObject]")]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name

	$RunningMultiETLTraceList = New-Object 'System.Collections.Generic.List[PSObject]'
	$ETWSessionList = logman.exe -ets | Out-String
	GetETWSessionByPS [GetRunningMultiETLTrace]
	
	# To detect multi etl file trace, we check output of "$Sys32\logman.exe -ets" again and if found the multi etl trace,
	# create trace object and add it to $RunningTraces
	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$Token = $Line -Split '\s+'
		If($Token[0] -like ($ScriptPrefix + '_METL_' + "*Trace")){
			# Create a new trace property and object
			$FullTraceName = $Token[0] -replace ("Trace.*","Trace")
			$TraceObject = CreateTraceObjectforMultiETLTrace $FullTraceName
			If($Null -ne $TraceObject){
				LogDebug "Trace object for $($TraceObject.TraceName) was created." "Yellow"
				$TraceObject.Status = $TraceStatus.Running
				$RunningMultiETLTraceList.Add($TraceObject)
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $RunningMultiETLTraceList
}

Function GetRunningScenarioTrace{
	[OutputType("System.Collections.Generic.List[PSObject]")]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$RunningScenarioObjectList = New-Object 'System.Collections.Generic.List[PSObject]'
	$TraceListInScenario = New-Object 'System.Collections.Generic.List[PSObject]'
	$ETWSessionList = logman.exe -ets | Out-String
	GetETWSessionByPS [GetRunningScenarioTrace]
	
	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$Token = $Line -Split '\s+'

		If($Token[0] -like ("*Scenario_*")){ # Scenario trace
			# Example: $ScenarioName="ADS_Auth" $FullTraceName="TSS_ADS_AuthScenario_ADS_XXXTrace" $TraceName=ADS_XXXTrace
			$ScenarioToken = $Token[0] -Split 'Scenario_' # TSS_ADS_AuthScenario_ADS_XXXTrace => TSS_ADS_Auth , ADS_XXXTrace
			$ScenarioName = $ScenarioToken[0] -replace (($ScriptPrefix + '_'),'') # TSS_ADS_Auth => ADS_Auth
			$FullTraceName = $Token[0] -replace ("Trace.*","Trace") # TSS_ADS_AuthScenario_ADS_XXXTraceXXX => TSS_ADS_AuthScenario_ADS_XXXTrace
			If($ScenarioToken[1].contains("METL")){
				$Temp = $ScenarioToken[1] -Split '_'   
				$TraceName = ($Temp[1] + '_' + $Temp[2] + 'Trace') # METL_NET_AfdTcpBasic_NetIoBasicTrace => NET_AfdTcpBasicTrace
			}Else{
				$TraceName = $ScenarioToken[1] -replace ("Trace.*","Trace") # ADS_XXXTraceXXX => ADS_XXXTrace
			}
			LogDebug "TraceName = $TraceName(Original name=$FullTraceName)"
			$ScenarioObject = $RunningScenarioObjectList | Where-Object{$_.ScenarioName -eq $ScenarioName}
			If($Null -eq $ScenarioObject){
				$TraceListInScenario = New-Object 'System.Collections.Generic.List[PSObject]'
				$TraceObject = $GlobalTraceCatalog | Where-Object{$_.TraceName -like ("*" + $TraceName)}
				If($Null -eq $TraceObject){
					LogDebug "Searching " + $TraceName + " failed."
					continue
				}
				$NewTraceObject = $TraceObject.psobject.copy() # Create new object for scenario trace
				$NewTraceObject.TraceName = $FullTraceName
				LogDebug "Adding $($NewTraceObject.TraceName) to $ScenarioName"
				$TraceListInScenario.Add($NewTraceObject)
				$ScenarioProperty = @{
					ScenarioName = $ScenarioName
					TraceListInScenario = $TraceListInScenario
				}
				LogDebug "Creating object for $ScenarioName"
				$RunningScenarioObject = New-Object PSObject -Property $ScenarioProperty
				$RunningScenarioObjectList.Add($RunningScenarioObject)
			}Else{
				$TraceObject = $GlobalTraceCatalog | Where-Object{$_.TraceName -like ("*" + $TraceName)}
				If($Null -eq $TraceObject){
					LogDebug "Searching $($ScenarioToken[1]) failed."
				}
				$NewTraceObject = $TraceObject.psobject.copy() # Create new object for scenario trace
				$NewTraceObject.TraceName = $FullTraceName	#we# RCA unclear for: Exception setting "TraceName": "The property 'TraceName' cannot be found on this object. Verify that the property exists and can be set."
				LogDebug "Adding $($NewTraceObject.TraceName) to $($ScenarioObject.ScenarioName)"
				$ScenarioObject.TraceListInScenario.Add($NewTraceObject)
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $RunningScenarioObjectList
}

Function GetEnabledAutoLoggerSession{
<#
.SYNOPSIS
Get all enabled AutoLogger traces

.DESCRIPTION
Process of detecting enabled AutoLogger settings:
1. Search registry keys that has our sign ($Scriptprefix) from 'HKLM\System\CurrentControlSet\Control\WMI\AutoLogger'
2. Firstly we will see if the key name has '_.*Scenario_.*' to get enabled AutoLogger for scenario trace.
3. Scondly ,search with '_METL_.*' to get enabled AutoLogger for multiple etl file trace.
4. After that, search normal ETW trace with '$ScriptPrefix_' which is currently 'TSS_'.
5. In the step 2-4, we found all types of ETW traces enabled by this script. After that, we will find
   AutoLogger entries for other support tools like WPR, Netsh and Procmon.
6. Return list of trace object that is enabled for AutoLogger.

.OUTPUTS
List of trace object that is enabled for AutoLogger.
Type: System.Collections.Generic.List[PSObject]

.NOTES
This function does not throw exception. In case of error, this function returns $Null.
#>
	[OutputType("System.Collections.Generic.List[PSObject]")]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$EnabledAutoLoggerTraces = New-Object 'System.Collections.Generic.List[PSObject]'

	# Get enabled AutoLogger traces for normal ETW, scneario trace and multiple etl trace.
	Try{
		$AutoLoggerRegArray = Get-ChildItem -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\AutoLogger
	}Catch{
		LogException ("Exception happened when accessing to HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\AutoLogger") $_ $fLogFileOnly
		Return $Null
	}
	
	ForEach($AutoLoggerReg in $AutoLoggerRegArray){
		$TraceObject = $Null
		If(($AutoLoggerReg.PSChildName) -match ($ScriptPrifix + '_.*Scenario_.*')){
			# Scenario trace case
			$TraceObject = CreateTraceObjectforScenarioTrace $AutoLoggerReg.PSChildName
		}ElseIf(($AutoLoggerReg.PSChildName) -match ($ScriptPrifix + '_METL_.*')){
			# Multiple ETL file trace case or single trace with '!' provider format.
			$TraceObject = CreateTraceObjectforMultiETLTrace $AutoLoggerReg.PSChildName
		}ElseIf(($AutoLoggerReg.PSChildName).contains($ScriptPrifix + '_')){
			# Normal ETW case
			$TraceObject = $GlobalTraceCatalog | Where-Object{$_.TraceName -eq $AutoLoggerReg.PSChildName}
			If($Null -ne $TraceObject.AutoLogger.AutoLoggerKey){
				$RegValue = $Null
				$RegValue = Get-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction Ignore
				If($Null -eq $RegValue){
					LogDebug ($TraceObject.Name + " does not have AutoLogger start registry(" + $TraceObject.AutoLogger.AutoLoggerKey + "\Start)") 
					Continue
				}
			}Else{
				Continue
			}
		}

		If($Null -ne $TraceObject){
			# Update AutoLoggerEnabled
			Try{
				$RegStartValue = Get-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction Stop
			}Catch{
				# We cannot use stream as this function returns object. So this is error but just logs with debugmode.
				LogDebug ($TraceObject.Name + " does not have AutoLogger start registry(" + $TraceObject.AutoLogger.AutoLoggerKey + "\Start)") 
				Continue
			}
			If($RegStartValue.Start -eq 1){
				$TraceObject.AutoLogger.AutoLoggerEnabled = $True
			}Else{
				$TraceObject.AutoLogger.AutoLoggerEnabled = $False
			}
			
			# Upadate AutoLoggerLogFileName
			If(!$StartAutoLogger.IsPresent){
				Try{
					$RegFileNameValue = Get-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'FileName' -ErrorAction Stop
				}Catch{
					# We cannot use stream as this function returns object. So this is error but just logs with debugmode.
					LogDebug ($TraceObject.TraceName + " does not have FileName registry") 
				}
				If($Null -ne $RegFileNameValue.FileName){
					$TraceObject.AutoLogger.AutoLoggerLogFileName = $RegFileNameValue.FileName
				}
			}

			If($TraceObject.AutoLogger.AutoLoggerEnabled){
				LogDebug ("AutoLogger for $($TraceObject.AutoLogger.AutoLoggerSessionName) is enabled.") "Yellow"
				$EnabledAutoLoggerTraces.Add($TraceObject)
				Continue
			}
		}
	}

	# Search AutoLogger entries for other all support tools(ex WPR, Netsh and Procmon).
	$CommandTraces = $GlobalTraceCatalog | Where-Object {$_.LogType -ne 'ETW'}
	ForEach($TraceObject in $CommandTraces){
		
		# This object does not support AutoLogger.
		If($Null -eq $TraceObject.AutoLogger){
			#LogDebug ('Skipping ' + $TraceObject.Name + ' as this does not support AutoLogger.')
			Continue
		}
		# This has AutoLogger but it is not enabled.
		If(!(Test-Path -Path $TraceObject.AutoLogger.AutoLoggerKey)){
			LogDebug ('Skipping ' + $TraceObject.Name + ' as AutoLogger is not enabled.')
			Continue
		}
	
		# Check start value.
		$RegValue = $Null
		$RegValue = Get-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction Ignore
		If($Null -eq $RegValue){
			# We cannot use stream as this function returns object. So this is error but just logs with debugmode.
			LogDebug ($TraceObject.Name + " does not have AutoLogger start registry(" + $TraceObject.AutoLogger.AutoLoggerKey + "\Start)") 
			Continue
		}
	
		# Now this object has start value so check it.
		# Procmon is tricky and if it is 0 or 3, which means BootLogging enabled.
		If($TraceObject.Name -eq 'Procmon' -and ($RegValue.Start -eq 3 -or $RegValue.Start -eq 0)){
			LogDebug ('AutoLogger for ' + $TraceObject.Name + ' is enabled.') "Yellow"
			$TraceObject.AutoLogger.AutoLoggerEnabled = $True
			$EnabledAutoLoggerTraces.Add($TraceObject)
			Continue
		}
	
		If($RegValue.Start -eq 1){
			LogDebug ('AutoLogger for ' + $TraceObject.Name + ' is enabled.') "Yellow"
			$TraceObject.AutoLogger.AutoLoggerEnabled = $True
			$EnabledAutoLoggerTraces.Add($TraceObject)
		}Else{
			$TraceObject.AutoLogger.AutoLoggerEnabled = $False
		}
	}

	# Show found traces in case of debugmode.
	If($DebugMode.IsPresent){
		LogDebug ("===============	 ENABLED AutoLogger TRACE	 ===============")
		ForEach($TraceObject in $EnabledAutoLoggerTraces){
			LogDebug ("  - " + $TraceObject.AutoLogger.AutoLoggerSessionName)
		}
		LogDebug ("===============================================================")
		If($EnabledAutoLoggerTraces.Count -ne 0){
			DumpCollection $EnabledAutoLoggerTraces
		}
		#Read-Host ("[DBG - hit ENTER to continue] [End of GetEnabledAutoLoggerSession] ==>")
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $EnabledAutoLoggerTraces
}

Function CreateTraceObjectforScenarioTrace{
	[OutputType([Object])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ScenarioTraceName
	)
	EnterFunc "$($MyInvocation.MyCommand.Name) with $ScenarioTraceName"
	If(!($ScenarioTraceName.contains('Scenario_'))){
		LogDebug "$ScenarioTraceName is not a scenario trace" "Yellow"
		Return $Null
	}
	$tmpTraceName = $ScenarioTraceName -replace (".*Scenario_","") # TSS_testScenario_DEV_TEST1Trace => DEV_TEST1Trace
	$TraceName = $tmpTraceName -replace ("Trace","") # DEV_TEST1Trace => DEV_TEST1
	If($TraceName.Contains("METL")){ 
		$TraceName = $TraceName -replace ("METL_","") # METL_DEV_TEST2_CertCli => # DEV_TEST2_CertCli
		$Token = $TraceName -split ('_')
		$TraceName = $Token[0] + '_' + $Token[1]
	}
	$TraceObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq $TraceName}
	If($Null -ne $TraceObject){
		$NewTraceObject = $TraceObject.psobject.copy() # Create new object for scenario trace
		$NewTraceObject.TraceName = $ScenarioTraceName
		$NewTraceObject.AutoLogger = $Null
		$NewTraceObject.AutoLogger = @{
			AutoLoggerEnabled  = $False
			AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\$($NewTraceObject.TraceName)-AutoLogger.etl`""
			AutoLoggerSessionName = $AutoLoggerPrefix + $NewTraceObject.TraceName
			AutoLoggerStartOption = $Null
			AutoLoggerStopOption = $Null
			AutoLoggerKey = $AutoLoggerBaseKey + $NewTraceObject.TraceName
		}
		LogDebug "Trace object for $($NewTraceObject.TraceName) was created."
	}Else{
		LogError "Unable to find $TraceName from global trace catalog"
		Return $Null
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $NewTraceObject
}

Function CreateTraceObjectforMultiETLTrace{
	[OutputType([Object])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$MultiETLTraceName
	)
	EnterFunc "$($MyInvocation.MyCommand.Name) with $MultiETLTraceName"
	If(!($MultiETLTraceName.contains('_METL_'))){
		LogDebug "$MultiETLTraceName is not a METL trace" "Yellow"
		Return $Null
	}

	# Convert METL name to original normal trace name in order to retrieve trace object from global catalog later.
	$TraceName = $Null
	$tmpTraceName = $MultiETLTraceName -replace ".*METL_","TSS_" # TSS_METL_NET_TEST3_CertCliTrace => TSS_NET_TEST3_CertCliTrace
	$Token = $tmpTraceName -split "_"
	For($i=0; $i -lt $Token.Length-1; $i++){
		If($i -ne 0){
			$TraceName = $TraceName + '_'
		}
		$TraceName = $TraceName + $Token[$i]  # TSS_NET_TEST3_CertCliTrace => TSS_NET_TEST3
	}
	$TraceName = $TraceName + 'Trace'  # TSS_NET_TEST3 => TSS_NET_TEST3Trace(Original trace name)

	# Get trace object for METL from catalog
	$TraceObject = $GlobalTraceCatalog | Where-Object{$TraceName -eq $_.TraceName}
	If($Null -ne $TraceObject){
		If($Null -ne $TraceObject.Count -and $TraceObject.Length -gt 1){
			LogError "$($TraceObject.Length) trace names are found in Global catalog.(Found trace names: $($TraceObject.TraceName)"
			Return $Null
		}
		# Original trace object taken from catalog is different from METL trace. So copy it and modify properties to create object for METL
		$NewTraceObject = $TraceObject.psobject.copy() # Create new object for METL trace
		$NewTraceObject.TraceName = $MultiETLTraceName
		$NewTraceObject.MultipleETLFiles = 'yes'
		# Inner object for AutoLogger is not copied. Hence create new one and set it to the new trace object.
		$NewTraceObject.AutoLogger = $Null
		$NewTraceObject.AutoLogger = @{
			AutoLoggerEnabled  = $False
			AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\$($NewTraceObject.TraceName)-AutoLogger.etl`""
			AutoLoggerSessionName = $AutoLoggerPrefix + $NewTraceObject.TraceName
			AutoLoggerStartOption = $Null
			AutoLoggerStopOption = $Null
			AutoLoggerKey = $AutoLoggerBaseKey + $NewTraceObject.TraceName
		}
		LogDebug "Trace object for $($NewTraceObject.TraceName) was created."
	}Else{
		LogError "Unable to find $TraceName from global trace catalog(METL name: $MultiETLTraceName)"
		Return $Null
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $NewTraceObject
}

Function ConvertToLocalPerfCounterName{
	[OutputType([Array])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String[]]$PerfCounterList
	)
	EnterFunc $MyInvocation.MyCommand.Name

	if (!(FwTestRegistryValue "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Perflib\009" "Counter")) {
		LogWarn "English Reg. 'Counter' not found."}
	else {
		$EnglishCounterName = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Perflib\009" -name 'Counter' | Select-Object -ExpandProperty counter
	}
	if (!(FwTestRegistryValue "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage" "Counter")) {
		LogWarn "Localized Reg. 'Counter' not found."}
	else {
		$LocalCounterName = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage" -name 'Counter' | Select-Object -ExpandProperty counter
	}
	
	$LoopCount = 0
	$PerfHashList = @{}
	ForEach($CounterData in @($EnglishCounterName,$LocalCounterName)){
		$CounterDataHash = @{}
		$i = 0
		# Creating hashtable that has counter id and counter name
		ForEach($line in ($CounterData -split "`r`n")){
			If($i -eq 0){
				$id = $line
				$i++
			}ElseIf($i -eq 1){
				$CounterName = $line
				# Issue#385 - '-Perfmon ALL' fails on Win11 in ConvertToLocalPerfCounterName
				If(!$CounterDataHash.ContainsKey($id)){
					#LogDebug ("Adding $id($CounterName)")
					$CounterDataHash.Add($id,$CounterName)
					$i = 0
				}
			}
		}

		If($LoopCount -eq 0){
			$PerfHashList.add("en-US",$CounterDataHash)
		}ElseIf($LoopCount -eq 1){
			$PerfHashList.add("Local",$CounterDataHash)
		}
		$LoopCount++
	}
	
	$EnlishCounterHash = $PerfHashList["en-US"]
	$LocalCounterHash = $PerfHashList["Local"]
	
	$LocalizedCounterSetNameArray = @()

	ForEach($EnglishCounterName in $PerfCounterList){
		$IsNonInstanceType = $False
		# Case for # Case for '<CounterName>(*)\*'
		If($EnglishCounterName.contains("(*)\*")){ 
			$EnglishCounterName = $EnglishCounterName -replace '^\\','' # Remove first '\'.
			$EnglishCounterName = $EnglishCounterName -replace '\(\*\)\\\*',''
		# Case for '<CounterName>\*'
		}ElseIf($EnglishCounterName.contains("\*")){
			$EnglishCounterName = $EnglishCounterName -replace '^\\','' # Remove first '\'.
			$EnglishCounterName = $EnglishCounterName -replace '\\\*',''
			$IsNonInstanceType = $True
		}Else{
			LogWarn ("Invalid counter set name($EnglishCounterName) is passed.")
			Continue
		}
	
		# Now search counter id conrresponding to the counter name and get localized counter name using the id.
		Foreach ($CounterID in $EnlishCounterHash.Keys){
			$EnglishCounterNameInRegistry = $EnlishCounterHash[$CounterID]
			If($EnglishCounterName -eq $EnglishCounterNameInRegistry){
				If($Null -ne $LocalCounterHash[$CounterID]){
					# Converting to localized counter name using counter id.
					#LogDebug ("Adding " + $LocalCounterHash[$CounterID] + " to counter array")
					If($IsNonInstanceType){
						$LocalizedCounterSetNameArray += "\" + $LocalCounterHash[$CounterID] + "\*"
					}Else{
						$LocalizedCounterSetNameArray += "\" + $LocalCounterHash[$CounterID] + "(*)\*"
					}
				}Else{
					# This case, we don't have local counter(this might be a bug) and simply set english counter name to local counter array.
					LogDebug ("Adding English name of " + $EnglishCounterNameInRegistry + " to counter array")
					If($IsNonInstanceType){
						$LocalizedCounterSetNameArray += "\" + $EnlishCounterHash[$CounterID] + "\*"
					}Else{
						$LocalizedCounterSetNameArray += "\" + $EnlishCounterHash[$CounterID] + "(*)\*"
					}
				}
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $LocalizedCounterSetNameArray
}

Function RunPreparation{
	EnterFunc $MyInvocation.MyCommand.Name

	If($global:ParameterArray -notcontains 'Stop'){
		# validate consistency of cmd-line input arguments (#707)
		#if ($Global:beta){
			ValidateCmdLineInputArgs
		#}
		
		# Running dummy trace for -Netsh and -NetshScenario to avoid missing packet sniff in very first Netsh run
		If($global:ParameterArray -Contains 'netsh' -or $global:ParameterArray -Contains 'netshscenario'){
			If(!($global:ParameterArray -Contains 'noNetsh')){
				LogDebug "Running dummy netsh"
				FwSetMCF disable
				$DummyNetshFile = "$env:temp\packetcapture_dummy.etl"
				LogInfoFile "[RunPreparation] Running dummy 'netsh trace start capture=yes scenario=NDIS capturetype=physical traceFile=$DummyNetshFile"
				$Commands = @(
					"netsh trace start capture=yes scenario=NDIS capturetype=physical traceFile=$DummyNetshFile correlation=no $Script:NetshTraceReport maxSize=1 fileMode=circular overwrite=yes",
					"netsh trace stop"
				)
				RunCommands "netsh" $Commands -ThrowException:$False -ShowMessage:$False
				FwSetMCF enable
				$DummyNetshFileFull = (Get-Item -LiteralPath $DummyNetshFile -ErrorAction Ignore).FullName 	#we# needed for short folder names like C:\Users\walte~1.abc\AppData\Local\Temp
				If(![String]::IsNullOrEmpty($DummyNetshFileFull)) {
					If(test-path -Path $DummyNetshFileFull){
						LogInfoFile "[RunPreparation] Removing dummy 'netsh trace' $DummyNetshFileFull"
						Remove-Item -Force -Path $DummyNetshFileFull -ErrorAction Ignore | Out-Null
					}
				}
				If(!$Status){LogInfoFile "Setting up Netsh parameters." -ShowMsg}
				FixUpNetshProperty
			}else{
				LogInfoFile "skip Setting up Netsh, because of -noNetsh switch"
			}
		}
		
		# For -PerfMon, but not -noPerfMon
		If($global:BoundParameters.ContainsKey('PerfMon')){
			If(!($global:BoundParameters.ContainsKey('noPerfMon'))){
				If(!$Status){LogInfoFile "Setting up PerfMon($($global:BoundParameters['PerfMon'])) parameters." -ShowMsg}
				FixUpPerfMonProperty 'PerfMon'
			}else{
				LogInfoFile "skip Setting up PerfMon, because of -noPerfmon switch"
			}
		}
		# For -PerfMonLong
		If($global:BoundParameters.ContainsKey('PerfMonLong')){
			If(!($global:BoundParameters.ContainsKey('noPerfMon'))){
				If(!$Status){LogInfoFile "Setting up PerfMonLong($($global:BoundParameters['PerfMonLong'])) parameters." -ShowMsg}
				FixUpPerfMonProperty 'PerfMonLong'
			}else{
				LogInfoFile "skip Setting up PerfMonLong, because of -noPerfmon switch"
			}
		}

		# For -PerfSMB we want to add packet capture
		If($global:BoundParameters.ContainsKey('PerfSMB')){
			if (PerfSMBPrerequisites)
			{
				LogInfo "PerfSMB prerequisites passed" "Green"
				$global:BoundParameters['Netsh'] = $True
				FixUpNetshProperty
				$noRepro = $True                										 # Don't wait for repro
			}
			else
			{
				LogError "PerfSMB prerequisites failed"
				CleanUpAndExit
			}
		}
		
		# For -Crash
		If($global:ParameterArray -Contains 'Crash'){
			If($global:ParameterArray -notcontains 'noCrash'){
				If ($CrashMode){
					If(!$Status){LogInfo "Setting up memory dump type (CrashMode)."}
					FixUpCrashProperty
				}
			}else{
				LogInfoFile "skip Setting up Crash, because of -noCrash switch"
			}
		}
		
		# For -WPR
		If($global:ParameterArray -Contains 'WPR'){
			If($global:ParameterArray -notcontains 'noWPR'){
				If(!$Status){LogInfoFile "Setting up WPR parameters." -ShowMsg}
				FixUpWPRProperty
			}else{
				LogInfoFile "skip Setting up WPR, because of -noWPR switch"
			}
		}
		
<#		# For PSR
		If($global:ParameterArray -Contains 'PSR'){
			If($global:ParameterArray -notcontains 'noPSR'){
				LogInfo "Setting up PSR parameters."
				FixUpPSRProperty
			}else{
			LogInfoFile "skip Setting up PSR, because of -noPSR or -noRecording switch"
			}
		}
#>
		
		# For -Xperf
		If($global:ParameterArray -Contains 'Xperf'){
			If($global:ParameterArray -notcontains 'noXperf'){
				If(!$Status){LogInfoFile "Setting up Xperf parameters." -ShowMsg}
				FixUpXperfProperty
			}else{
				LogInfoFile "skip Setting up Xperf, because of -noXperf switch"
			}
		}
	}

	# Fiddler
	If($global:ParameterArray -Contains 'Fiddler'){
		FixUpFiddlerProperty
	}

	# For -Procmon, fix up property to find path for Procmon.exe
	If($global:ParameterArray -Contains 'Procmon'){
		If($global:ParameterArray -notcontains 'noProcmon'){
			If(!$Status){LogInfoFile "Setting up Procmon parameters." -ShowMsg}
			FixUpProcmonProperty
		}else{
			LogInfoFile "skip Setting up Procmon, because of -noProcmon switch"
		}
	}

	<# 
	Autual process starts here:
	1. CreateETWTraceProperties creates trace properties for ETW trace automatically based on $TraceDefinitionList.
	2. Created trace properties are added to $GlobalPropertyList which has all properties including other traces like WRP and Netsh.
	3. Create trace objects based on $GlobalPropertyList 
	4. Created TraceObjects are added to $GlobalTraceCatalog
	5. Check argmuents and pick up TraceObjects specified in command line parameter and add them to $LogCollector(Generic.List)
	6. StartTraces() starts all traces in $LogCollector(not $GlobalTraceCatalog). 
	#>

	# Creating properties for ETW trace and add them to ETWPropertyList
	if ((IsTraceOrDataCollection) -or $FindGUID -or $TraceInfo -or $Status){ # added for #875 #we#fix -Status# 
		Try{
			LogDebug ('Creating properties for ETW and adding them to GlobalPropertyList.')
			CreateETWTraceProperties $TraceDefinitionList  # This will add created property to $script:ETWPropertyList
		}Catch{
			LogException ("An exception happened in CreateETWTraceProperties.") $_
			CleanUpandExit # Trace peroperty has invalid value and this is critical. So exits here.
		}

		ForEach($RequestedTraceName in $global:ParameterArray){   #milantodo this is where we need handle new params
			If($TraceSwitches.Contains($RequestedTraceName)){  #TraceSwitches correspond to scenarios
				 $ETWTrace = $TraceDefinitionList | Where-Object {$_.Name -eq $RequestedTraceName}
				If($Null -eq $ETWTrace){
					LogInfo ($RequestedTraceName + ' is not registered in our trace list.') "Red"
					CleanUpandExit
				}
				Continue 
			}
		}
	}

	# Creating all properties and add them to $GlobalPropertyList
	LogDebug ("Adding $($script:ETWPropertyList.count) ETW properties and $($CommandPropertyList.Count) command properties to GlobalTraceCatalog.")
	$AllProperties = $script:ETWPropertyList + $CommandPropertyList
	ForEach($TraceProperty in $AllProperties){
		Try{
			InspectProperty $TraceProperty
		}Catch{
			LogInfo ('ERROR: an error happens during inspecting property for ' + $TraceProperty.Name) "Red"
			Write-Host ($_.Exception.Message) -ForegroundColor Red
			LogInfo '---------- Error propery ----------' -noDate
			$TraceProperty | Format-Table
			LogInfo '-----------------------------------' -noDate
			CleanUpandExit # This is critical and exiting.
		}
		# Creating TraceObject from TraceProperty and add it to GlobalTraceCatalog.
		$TraceObject = New-Object PSObject -Property $TraceProperty
		$GlobalTraceCatalog.Add($TraceObject)
	}

	LogDebug ('Setting $fPreparationCompleted to true.')
	$script:fPreparationCompleted = $True

	#If($DebugMode.IsPresent){
	#	LogDebug ("======================	 GLOBAL TRACE CATALOG	 =======================")
	#	ForEach($TraceObject in $GlobalTraceCatalog){
	#		LogDebug ("Name: " + $TraceObject.Name + " TraceName: " + $TraceObject.TraceName)
	#	}
	#	LogDebug ("===========================================================================")
	#}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StartTraces{
	EnterFunc $MyInvocation.MyCommand.Name
	$global:TssPhase = "_Start_"

	# Run pre-start function for scenario trace and start TSS Clock.
	If($Scenario.Count -ne 0){
		ForEach($ScenarioName in $Scenario){
			RunFunction ($ScenarioName + 'ScenarioPreStart')
		}
		# Issue#334 - Clock should start on each Scenario
		StartTSSClock
	}

	# List used for multi etl file trace
	$CreatedMETLTraceList = New-Object 'System.Collections.Generic.List[PSObject]'
	$RemoveTraceList = New-Object 'System.Collections.Generic.List[PSObject]'

	ForEach($TraceObject in $LogCollector)
	{
		# Run pre-start function for a component.
		$ComponentPreStartFunc = $TraceObject.Name + 'PreStart'
		Try{
			RunFunction $ComponentPreStartFunc -ThrowException:$True
		}Catch{
			LogWarn "[$($TraceObject.Name)] Error happens in pre-start function($ComponentPreStartFunc). Skipping this trace."
			LogException ("An error happened in " + $ComponentPreStartFunc) $_ $fLogFileOnly
			$TraceObject.Status = $TraceStatus.ErrorInStart
			Continue
		}

		Switch($TraceObject.LogType){
			'ETW' {
				If($StartAutoLogger.IsPresent){
					$TraceName = $TraceObject.AutoLogger.AutoLoggerSessionName
				}Else{
					if ($TraceObject.TraceName -match "WIN_kernel") {$TraceObject.TraceName = 'NT Kernel Logger'}
					$TraceName = $TraceObject.TraceName
				}
				LogDebug "Enter [ETW] section in StartTraces. Starting `"$TraceName`""
				$EtwTraceLevel = $global:BoundParameters['ETWlevel']
				if (![string]::IsNullOrEmpty($EtwTraceLevel)){
					switch($EtwTraceLevel){
						'Info'		{$HexTraceLevel ="0x07"}
						'Warning'	{$HexTraceLevel ="0x03"}
						'Error'		{$HexTraceLevel ="0x01"}
					}
					$TraceLevel = $HexTraceLevel
				}else{
					$TraceLevel = "0xff"
				}
				if($TraceObject.MultipleETLFiles -eq 'yes'){
					#add code for multiple etl files
					LogDebug "[$($TraceObject.Name)] Enter multiple file condition"
					$RemoveTraceList.Add($TraceObject)
					$i=0
					LogInfo "[ETW] starting all ETW traces ..."	
					ForEach($Provider in $TraceObject.Providers){
						#get etl file guid and name from Provider
						if ($Provider -like "*!*"){
							$temp = $Provider.Split('!')
							$SingleTraceGUID = $temp[0] # Trace GUID
							$ETLName = $temp[1] # etl name
							If(![string]::IsNullOrEmpty($Scenario)){
								$TraceName = $ScriptPrefix + '_' + $Scenario + 'Scenario_METL_' + $TraceObject.Name + '_' + $ETLName + 'Trace'
							}Else{
								$TraceName = $ScriptPrefix + '_METL_' + $TraceObject.Name + '_' + $ETLName + 'Trace'
							}
							If($StartAutoLogger.IsPresent){
								If(![string]::IsNullOrEmpty($Scenario)){
									$SingleTraceName = $AutoLoggerPrefix + $ScriptPrefix + '_' + $Scenario + 'Scenario_METL_' + $TraceObject.Name + '_' + $ETLName + 'Trace'
								}Else{
									$SingleTraceName = $AutoLoggerPrefix + $ScriptPrefix + '_METL_' + $TraceObject.Name + '_' + $ETLName + 'Trace'
								}
							}Else{
								$SingleTraceName = $TraceName
							}
							#support for custom flags in etl
							$SingleTraceFlags = $temp[2] # Trace flag
							if ([string]::IsNullOrEmpty($SingleTraceFlags))
							{
								$SingleTraceFlags = "0xffffffffffffffff"
							}
							$SingleTraceLevel  = $temp[3] # Trace level
							if ([string]::IsNullOrEmpty($SingleTraceLevel)){
								$SingleTraceLevel = $TraceLevel
							}
							LogDebug "ETLMode=$Script:ETLmode | GUID=$SingleTraceGUID | TraceName=$SingleTraceName | TraceFlag=$SingleTraceFlags | TraceLevel=$SingleTraceLevel"

							$CreatedMETLTraceObject = $CreatedMETLTraceList | Where-Object{$_.TraceName -eq $TraceName}
							If($Null -eq $CreatedMETLTraceObject){
								$ShouldCreate = $True
								# Create trace object and add it to LogCollector
								$METLTraceObject = CreateTraceObjectforMultiETLTrace $TraceName
								If($Null -ne $METLTraceObject){
									LogDebug "Adding $($METLTraceObject.TraceName) to CreatedMETLTraceList"
									$CreatedMETLTraceList.Add($METLTraceObject)
								}Else{
									Throw "Failed to create trace object for $TraceName"
								}
							}Else{
								$ShouldCreate = $False
							}

							#If($DebugMode.IsPresent){
							#	Read-Host ("[DBG - hit ENTER to continue] [before starting logman create for multifile mode] ==>")
							#}
							If($StartAutoLogger.IsPresent){
								$AutoLoggerFileName = $SingleTraceName -replace ('autosession\\','')
								$etlLogPath= ($TraceObject.LogFileName).Substring(0, ($TraceObject.LogFileName).LastIndexOf("\")+1) + $LogPrefix + $AutoLoggerFileName + '-AutoLogger.etl"'
							}Else{
								$etlLogPath= ($TraceObject.LogFileName).Substring(0, ($TraceObject.LogFileName).LastIndexOf("\")+1) + $LogPrefix + $SingleTraceName + '.etl"'
							}

							Write-Progress -Activity ('Adding ' + $SingleTraceGUID + ' ' + $SingleTraceName + ' to ' + $TraceName) -Status 'Progress:' -PercentComplete ($i/$TraceObject.Providers.count*100)

							if ($Script:ETLmode -eq "circular"){
								Start-Sleep -Milliseconds 200
								If($ShouldCreate){
									LogInfoFile "Creating ETW component $SingleTraceName with $SingleTraceGUID $SingleTraceFlags $SingleTraceLevel"
									LogInfoFile "[ETW] logman create trace $SingleTraceName -ow -o $($etlLogPath) -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -nb 16 16 -bs 1024 -mode $Script:ETLmode -f bincirc -max $Script:ETLMaxSize -ets"	
									#LogInfo "[ETW] starting ETW traces ..."								
									RunCommands "ETW" "Logman.exe create trace $SingleTraceName -ow -o $($etlLogPath) -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -nb 16 16 -bs 1024 -mode $Script:ETLmode -f bincirc -max $Script:ETLMaxSize -ets" -ThrowException:$True -ShowMessage:$False -ShowError:$True
									#_#ToDo:? if LASTEXITCODE=-2147023446
								}Else{
									LogInfoFile "  Adding to ETW component $SingleTraceName GUID $SingleTraceGUID $SingleTraceFlags $SingleTraceLevel"
									RunCommands "ETW" "Logman.exe update trace $SingleTraceName -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -ets" -ThrowException:$False -ShowMessage:$False -ShowError:$True
								}
							}
							elseif($Script:ETLmode -eq "newfile"){
								$a = "`"$($etlLogPath.Substring(1, $etlLogPath.Length-6))_%d.etl`""
								Start-Sleep -Milliseconds 200
								If($ShouldCreate){
									LogInfoFile "Creating ETW component $SingleTraceName $SingleTraceFlags $SingleTraceLevel"
									LogInfoFile "[ETW] logman create trace $SingleTraceName -ow -o $a -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -nb 16 16 -bs 1024 -mode $Script:ETLmode -max $Script:ETLMaxSize -ets"
									#LogInfo "[ETW] starting ETW traces ..."	
									RunCommands "ETW" "Logman.exe create trace $SingleTraceName -ow -o $a -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -nb 16 16 -bs 1024 -mode $Script:ETLmode -max $Script:ETLMaxSize -ets" -ThrowException:$True -ShowMessage:$False -ShowError:$True
								}Else{
									LogInfoFile "  Adding to ETW component $SingleTraceName GUID $SingleTraceGUID $SingleTraceFlags $SingleTraceLevel"
									RunCommands "ETW" "Logman.exe update trace $SingleTraceName -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -ets" -ThrowException:$True -ShowMessage:$False -ShowError:$True
								}
							}else{
								# we should never get here
								Throw ("Invalid ETLOptions! ETLMode must contain either circular or newfile")
							}
							$i++
						}
					}
					Write-Progress -Activity 'Updating providers' -Status 'Progress:' -Completed
				}
				#elseif ([string]::IsNullOrEmpty($TraceObject.Providers)) #milanmil210527
				#{
				#	 Write-Progress -Activity 'ETW tracing is not configured for this data collection' -Status 'Progress:' -Completed
				#}  #milanmil210527

				else{
					# case for normal trace 
					LogDebug ("ETLMode=$Script:ETLmode  | LogFileName=" + $TraceObject.LogFileName)

					# This throws an exception and will be handled in main
					if ($Script:ETLmode -eq "circular"){
						Start-Sleep -Milliseconds 200
						LogInfoFile "Creating $Script:ETLmode ETW component `"$TraceName`""
						LogInfoFile "[ETW] logman create trace `"$TraceName`" -ow -o $($TraceObject.LogFileName) -mode $Script:ETLmode -bs 64 -f bincirc -max $Script:ETLMaxSize -ft 60 -ets"
						#LogInfo "[ETW] starting ETW traces ..."	
						RunCommands "ETW" "Logman.exe create trace `"$TraceName`" -ow -o $($TraceObject.LogFileName) -mode $Script:ETLmode -bs 64 -f bincirc -max $Script:ETLMaxSize -ft 60 -ets" -ThrowException:$True -ShowMessage:$False -ShowError:$True
					}
					elseif($Script:ETLmode -eq "newfile"){
						$a = "`"$(($TraceObject.LogFileName).Substring(1, ($TraceObject.LogFileName).Length-6))_%d.etl`""
						Start-Sleep -Milliseconds 200
						LogInfoFile "Creating $Script:ETLmode ETW component `"$TraceName`""
						LogInfoFile "[ETW] logman create trace `"$TraceName`" -ow -o $a -mode $Script:ETLmode -bs 64 -max $Script:ETLMaxSize -ft 60 -ets"
						LogInfo "[ETW] starting ETW traces ..."	
						RunCommands "ETW" "Logman.exe create trace `"$TraceName`" -ow -o $a -mode $Script:ETLmode -bs 64 -max $Script:ETLMaxSize -ft 60 -ets" -ThrowException:$True -ShowMessage:$False -ShowError:$True
					}else{
					# we should never get here
					   Throw ("Invalid ETLOptions! ETLMode must contain either circular or newfile")
					}

					# Adding all providers to the trace session
					$i=0
					ForEach($Provider in $TraceObject.Providers){
						if ($Provider -like "*!*"){	# Single etl file + multi flags/levels
							$temp = $Provider.Split('!')
							$SingleTraceGUID = $temp[0]
							$SingleTraceName = $temp[1]  # this will be ignored in this run as we trace all in a same file, however it is mandatory in case custom flags is required
							If($StartAutoLogger.IsPresent){
								If(![string]::IsNullOrEmpty($Scenario)){
									$SingleTraceName = $AutoLoggerPrefix + $ScriptPrefix + '_' + $Scenario + 'Scenario_METL_' + $TraceObject.Name + '_' + $temp[1] + 'Trace'
								}Else{
									$SingleTraceName = $AutoLoggerPrefix + $ScriptPrefix + '_METL_' + $TraceObject.Name + '_' + $temp[1] + 'Trace'
								}
							}Else{
								If(![string]::IsNullOrEmpty($Scenario)){
									$SingleTraceName = $ScriptPrefix + '_' + $Scenario + 'Scenario_METL_' + $TraceObject.Name + '_' + $temp[1] + 'Trace'
								}Else{
									$SingleTraceName = $ScriptPrefix + '_METL_' + $TraceObject.Name + '_' + $temp[1] + 'Trace'
								}
							}
							#support for custom flags in etl
							$SingleTraceFlags = $temp[2]
							if ([string]::IsNullOrEmpty($SingleTraceFlags)){
								$SingleTraceFlags = "0xffffffffffffffff"
							}
							$SingleTraceLevel = $temp[3]
							if ([string]::IsNullOrEmpty($SingleTraceLevel)){
								$SingleTraceLevel = $TraceLevel
							}
							LogDebug ("ETLMode=$Script:ETLmode | GUID=$SingleTraceGUID | TraceName=$SingleTraceName | TraceFlag=$SingleTraceFlags | TraceLevel=$SingleTraceLevel")
							$etlLogPath= ($TraceObject.LogFileName).Substring(0, ($TraceObject.LogFileName).LastIndexOf("\")+1) + $LogPrefix + $SingleTraceName + '.etl"'  
							Write-Progress -Activity ('Adding ' + $SingleTraceGUID + ' to ' + $TraceName) -Status 'Progress:' -PercentComplete ($i/$TraceObject.Providers.count*100)
							LogInfoFile "  Adding to ETW `"$TraceName`" GUID $SingleTraceGUID $SingleTraceFlags $SingleTraceLevel"
							RunCommands "ETW" "Logman.exe update trace `"$TraceName`" -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -ets" -ThrowException:$False -ShowMessage:$False
							# logman update trace command is same for circular and newfile modes
						}else{ # Normal case
							$SingleTraceFlags = "0xffffffffffffffff"
							$SingleTraceLevel = $TraceLevel
							Write-Progress -Activity ('Adding ' + $Provider + ' to ' + $TraceName) -Status 'Progress:' -PercentComplete ($i/$TraceObject.Providers.count*100)
							LogInfoFile "  Adding to ETW `"$TraceName`" GUID $Provider $SingleTraceFlags $SingleTraceLevel"
							RunCommands "ETW" "Logman.exe update trace `"$TraceName`" -p `"$Provider`" $SingleTraceFlags $SingleTraceLevel -ets" -ThrowException:$False -ShowMessage:$False
						}
						$i++
					}
					Write-Progress -Activity 'Updating providers' -Status 'Progress:' -Completed
				} 

				# If AutoLogger, update 'FileMax' and log folder
				If($StartAutoLogger.IsPresent -and $Null -ne $TraceObject.AutoLogger){
					If($TraceObject.MultipleETLFiles -eq 'yes'){
						$AutoLoggerTraceOjects = $CreatedMETLTraceList
					}Else{ # MultipleETLFiles='no'
						$AutoLoggerTraceOjects = $TraceObject
					}
					ForEach($AutoLoggerTraceOject in $AutoLoggerTraceOjects){
						LogDebug "Updating AutoLogger log path and FileMax for $($AutoLoggerTraceOject.TraceName)"
						If(Test-Path -Path $AutoLoggerTraceOject.AutoLogger.AutoLoggerKey){
							# Set maximum number of instances of the log file to $Script:ETLFileMax
							Try{
								New-ItemProperty -Path $AutoLoggerTraceOject.AutoLogger.AutoLoggerKey -Name 'FileMax' -PropertyType DWord -Value $Script:ETLFileMax -force -ErrorAction SilentlyContinue | Out-Null
							}Catch{
								LogWarn "Unable to update $($AutoLoggerTraceOject.AutoLogger.AutoLoggerKey)"
							}
						}Else{
							LogDebug "WARNING: $($AutoLoggerTraceOject.AutoLogger.AutoLoggerKey) does not exist."
						}

						Try{
							If($Script:ETLmode -eq "newfile"){
								# For future use.

								#$a = "`"$(($AutoLoggerTraceOject.AutoLogger.AutoLoggerLogFileName).Substring(1, $($AutoLoggerTraceOject.AutoLogger.AutoLoggerLogFileName).Length-6))_%d.etl`""
								#Start-Sleep -Milliseconds 200
								#LogInfo "Updating log file to $a"
								#RunCommands "ETW" "logman update trace $($AutoLoggerTraceOject.AutoLogger.AutoLoggerSessionName) -o $a" -ThrowException:$False -ShowMessage:$True
							}Else{ # Normal(circular) case
								LogInfoFile "Updating log file to $($AutoLoggerTraceOject.AutoLogger.AutoLoggerLogFileName)" -ShowMsg
								RunCommands "ETW" "Logman.exe update trace $($AutoLoggerTraceOject.AutoLogger.AutoLoggerSessionName) -o $($AutoLoggerTraceOject.AutoLogger.AutoLoggerLogFileName)" -ThrowException:$False -ShowMessage:$True
							}
						}Catch{
							LogWarn "Warning: unable to update logfolder for AutoLogger. Trace will continue with default location where this script is run."
						}
						$AutoLoggerTraceOject.Status = $TraceStatus.Started
					}
				}
				If($TraceObject.MultipleETLFiles -eq 'no'){
					$TraceObject.Status = $TraceStatus.Started
				}
			}
			'Perf' {
				LogDebug ('Enter [Perf] section in StartTraces. Starting ' + $TraceObject.TraceName)
				## check if the PerfMon datacollectorset was left over from a previous unsuccessful run 
				$datacollectorset = new-object -COM Pla.DataCollectorSet #we#
				Try{  
					$datacollectorset.Query($TraceObject.Name, $env:computername)
				}Catch{
					# If 'Perf' is not running, exception happens and this is actually not error. So just log it if -DebugMode.
					$Error.RemoveAt(0)
					LogDebug ('INFO: An Exception happened in Pla.DataCollectorSet.Query for ' + $TraceObject.Name)
					# Break
				}
				#Status ReturnCodes: 0=stopped 1=running 2=compiling 3=Pending (legacy OS prior Vista) 4=unknown (usually AutoLogger)
				If($datacollectorset.Status -eq 1){ # unlikely situation, as TSS would alredy show : Run TSS -stop
					LogDebug ('[StartTraces] PerfMon status is ' + $datacollectorset.Status)
					LogInfoFile ('[' + $TraceObject.Name + '] Running logman.exe stop + delete ' + $TraceObject.Name) -ShowMsg
					Logman.exe stop $TraceObject.Name | Out-Null
					Logman.exe delete $TraceObject.Name | Out-Null
				}
				If($datacollectorset.Status -eq 0){
					LogDebug ('StartTraces] PerfMon status is ' + $datacollectorset.Status)
					LogInfoFile ('[' + $TraceObject.Name + '] Running logman.exe delete ' + $TraceObject.Name) -ShowMsg
					Logman.exe delete $TraceObject.Name | Out-Null
				}
				
				Try{
					StartPerfMonLog  $TraceObject  # This may throw an exception.
				}Catch{
					LogInfoFile ('Error at [StartPerfMonLog] Enter [Perf] section in StartTraces. Starting ' + $TraceObject.TraceName)
					$TraceObject.Status = $TraceStatus.ErrorInStart
					$ErrorMessage = 'An exception happened during starting Performance Monitor log.'
					LogWarn "[$($TraceObject.TraceName)] $ErrorMessage `n -> Skipping this $($TraceObject.TraceName)trace."
					LogException $ErrorMessage $_ $fLogFileOnly
					# treat as non-Critical
					#we-commented# Throw ($ErrorMessage)
					Continue #we#
				}
				$TraceObject.Status = $TraceStatus.Started
			}
			'Command' {
				LogDebug ('Enter [Command] section in StartTraces. Start processing ' + $TraceObject.TraceName)

				# Supported version check
				If($Null -ne $TraceObject.SupportedOSVersion){
					If(!(FwIsSupportedOSVersion $TraceObject.SupportedOSVersion)){
						LogWarn ($TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupportedOSVersion.OS + ' Build ' + $TraceObject.SupportedOSVersion.Build + '] Skipping this trace.')
						$TraceObject.Status = $TraceStatus.NotSupported
						Break # This is not critical and continue another traces.
					}
				}

				# Check if the command exists.
				$CommName = Get-Command $TraceObject.CommandName -ErrorAction SilentlyContinue	#we# check if command exists, before testing Path, i.e. if psr.exe was removed from system
				#we# If(!(Test-Path -Path (Get-Command $TraceObject.CommandName).Path)){
				If($CommName){
					If(!(Test-Path -Path $CommName.Path)){
						LogWarn ('Warning: ' + $TraceObject.CommandName + ' not found. Skipping ' + $TraceObject.Name)
						$TraceObject.Status = $TraceStatus.ErrorInStart
						Break
					}
				}

				# Normal case.
				If(!$StartAutoLogger.IsPresent){ 
					LogInfoFile "[$($TraceObject.Name)] Running $($TraceObject.CommandName) $($TraceObject.Startoption) (Wait=$($TraceObject.Wait))" -ShowMsg
					If($TraceObject.Wait){
						$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.Startoption -RedirectStandardOutput $env:temp\StartProcess-output.txt -RedirectStandardError $env:temp\StartProcess-err.txt -PassThru -Wait
						If($Proccess.ExitCode -ne 0){
							Get-Content $env:temp\StartProcess-output.txt
							Get-Content $env:temp\StartProcess-err.txt
							Remove-Item $env:temp\StartProcess*
							$TraceObject.Status = $TraceStatus.ErrorInStart
							$ErrorMessage = ('An error happened in ' + $TraceObject.CommandName + ' (Error=0x' + [Convert]::ToString($Proccess.ExitCode,16) + ')')
							LogError $ErrorMessage
							Throw ($ErrorMessage)
						}
					}Else{
						If($TraceObject.WindowStyle -eq 'Minimized'){ # For trace with window minimized.
							$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.Startoption -WindowStyle Minimized
						}Else{
							$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.Startoption
						}
					}
					$TraceObject.Status = $TraceStatus.Started
				# AutoLogger case.
				}Else{ 
					# WPR -BootTrace does not support RS1 or earlier.
					If($TraceObject.Name -eq 'WPR'){
						LogDebug ('Enter [WPR] Current OS build=' + $OSBuild + ' WPR supported build=' + $WPRBootTraceSupportedVersion.Build)
						If($OSBuild -lt $WPRBootTraceSupportedVersion.Build){
							$TraceObject.Status = $TraceStatus.NotSupported
							Throw ($TraceObject.Name + ' -BootTrace is not supported on this OS. Supported Version is Windows ' + $WPRBootTraceSupportedVersion.OS  + ' Build ' + $WPRBootTraceSupportedVersion.Build + ' or later.')
						}
					}

					If($TraceObject.Name -eq 'Netsh'){
						LogDebug ('Enter [Netsh] Checking if there is running session.')
						$NetshSessionName = 'NetTrace'
						ForEach($Line in ($ETWSessionList -split "`r`n")){
							$Token = $Line -Split '\s+'
							If($Token[0].Contains($NetshSessionName)){
								$TraceObject.Status = $TraceStatus.ErrorInStart
								Throw ($TraceObject.Name + ' is already running.')
							}
						}
					}

					LogInfoFile ('[' + $TraceObject.Name + '] Running ' + $TraceObject.CommandName + ' ' + $TraceObject.AutoLogger.AutoLoggerStartOption) -ShowMsg
					If($TraceObject.Wait){
						$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.AutoLogger.AutoLoggerStartOption -RedirectStandardOutput $env:temp\StartProcess-output.txt -RedirectStandardError $env:temp\StartProcess-err.txt -PassThru -Wait
						If($Proccess.ExitCode -ne 0){
							$TraceObject.Status = $TraceStatus.ErrorInStart
							Get-Content $env:temp\StartProcess-output.txt
							Get-Content $env:temp\StartProcess-err.txt
							Remove-Item $env:temp\StartProcess*
							$ErrorMessage = ('An error happened in ' + $TraceObject.CommandName + ' (Error=0x' + [Convert]::ToString($Proccess.ExitCode,16) + ')')
							LogError $ErrorMessage
							Throw ($ErrorMessage)
						}
					}Else{
						$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.AutoLogger.AutoLoggerStartOption
						# Unfortunately we don't know if it starts without error as the process is stared as background process.
					}
					$TraceObject.Status = $TraceStatus.Started
				}
			}
			'Custom' {
				LogDebug ('Enter [Custom] section in StartTraces. Start processing ' + $TraceObject.TraceName)
				# Supported version check
				If($Null -ne $TraceObject.SupportedOSVersion){
					If(!(FwIsSupportedOSVersion $TraceObject.SupportedOSVersion)){
						$ErrorMessage = $TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupportedOSVersion.OS + ' Build ' + $TraceObject.SupportedOSVersion.Build + '].'
						LogError $ErrorMessage
						$TraceObject.Status = $TraceStatus.NotSupported
						Throw ($ErrorMessage) 
					}
				}
				# Check if the trace has pre-start function. If so, just call it.
				Try{
					RunFunction $TraceObject.StartFunc -ThrowException:$True
				}Catch{
					$TraceObject.Status = $TraceStatus.ErrorInStart
					Throw "[$($TraceObject.StartFunc)] ERROR: $($_.Exception.Message)"
				}
				$TraceObject.Status = $TraceStatus.Started
			}
			Default {
				$TraceObject.Status = $TraceStatus.ErrorInStart
				LogError ('Unknown log type ' + $TraceObject.LogType)
			}
		}
		# Run post-start function for a component.
		$ComponentPostStartFunc = $TraceObject.Name + 'PostStart'
		Try{
			RunFunction $ComponentPostStartFunc -ThrowException:$True
		}Catch{
			LogWarn "[$($TraceObject.Name)] Error happens in post-start function($ComponentPostStartFunc). Skipping this trace."
			LogException ("An error happened in " + $ComponentPostStartFunc) $_ $fLogFileOnly
			Continue
		}
	}

	If($CreatedMETLTraceList.Count -ne 0){
		ForEach($METLTraceObject in $CreatedMETLTraceList){
			LogDebug "Adding $($METLTraceObject.TraceName) to LogCollector" Yellow
			$LogCollector.Add($METLTraceObject)
		}
	}
	If($RemoveTraceList.Count -ne 0){
		ForEach($RemoveTraceObject in $RemoveTraceList){
			LogDebug "Removing $($RemoveTraceObject.TraceName) from LogCollector" Yellow
			$LogCollector.Remove($RemoveTraceObject) | Out-Null
		}
	}

	# Run pre-start function for scenario trace. #we# moved here
	ForEach($ScenarioName in $Scenario){
		RunFunction ($ScenarioName + 'ScenarioPostStart')
	}
	
loginfo "Start common start task"

	# Call common START task
	# Run collection of RegKey and Eventlogs before repro, defined by POD calls to FWaddRegItem and FWaddEvtLog _Start_
	if (($global:RegKeysModules.count -gt 0) -or ($global:RegKeysModulesNoRecursive.count -gt 0)) { FWgetRegList $global:TssPhase }
	if ($global:EvtLogNames.count -gt 0) { FWgetEvtLogList $global:TssPhase }
	#$Script:RunningScenarioObjectList = GetRunningScenarioTrace
	If(($Scenario.Count -ne 0) -and [string]::IsNullOrEmpty($CommonTask)){
		ForEach($ScenarioName in $Scenario){
			$ScenarioTraceSetName = "$($ScenarioName)_ETWTracingSwitchesStatus"
			$Scenario_ETWTracingSwitchesStatus = Get-Variable $ScenarioTraceSetName -ValueOnly -ErrorAction Ignore
			ForEach($Key in $Scenario_ETWTracingSwitchesStatus.Keys){
				$Token = $Null
				$ValueName = $Null
				If($Key.contains('CommonTask')){
					$Token = $Key -split ' '
					LogDebug "Setting `'$($Token[1])`' to TaskType"
					$TaskType = $Token[1]
					Switch($TaskType){
						'Full'{
							RunFunction "FwCollect_BasicLog" -Stage "Before-Repro" -ThrowException:$False
						}
						'Mini'{
							RunFunction "FwCollect_MiniBasicLog" -Stage "Before-Repro" -ThrowException:$False
						}
						Default {
							$PODCommonStartFunc = $TaskType + "_Start_Common_Tasks"
							RunFunction $PODCommonStartFunc -ThrowException:$False
						}
					}
				}
			}
		}
	}ElseIf(![string]::IsNullOrEmpty($CommonTask)){ # -Start/-StartAutoLogger + -CommonTask without scenario case
		Switch($CommonTask){
			'Full'{
				RunFunction "FwCollect_BasicLog" -Stage  "Before-Repro" -ThrowException:$False
			}
			'Mini'{
				RunFunction "FwCollect_MiniBasicLog" -Stage "Before-Repro" -ThrowException:$False
			}
			Default {
				$PODCommonStartFunc = $CommonTask + "_Start_Common_Tasks"
				RunFunction $PODCommonStartFunc -ThrowException:$False
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function SendStopEvent999{
	# Send a stop trigger 999 to RemoteHosts if -RemoteHosts was specified
	# In remoting, we record event 999 to remote host's System Eventlog
	Param(
		[parameter(Mandatory=$False)]
		[String]$additionalMsg=""
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If(($global:IsRemoting) -and $script:fEvent999Sent -ne $True){
		$RemoteHosts = $global:BoundParameters['RemoteHosts']
		LogInfo "[StopTraces] sending stop trigger to remote hosts: $RemoteHosts" "Cyan"
		$iHost=0
		ForEach($RemoteHost in $RemoteHosts){
			$iHost++
			$SendTimeStamp = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss.fffffff")
			Try{
				if ($WaitEvent -iMatch "Signal"){ #Send signal #519, ToDo/note: 'WAITFOR.exe /S <computer>' will likely fail with 'ERROR: Unable to send signal'
					if ($iHost -eq 1){
						LogInfo "$SendTimeStamp UTC: Sending stop signal notification $script:SignalString"
						WAITFOR.exe /SI $script:SignalString 2>&1
					}
				}
				# Write into remote EventLog; # Send actual event 999 to remote hosts.
				LogInfo "Writing event id $script:RemoteStopEventID into System Eventlog of $RemoteHost"
				Write-EventLog -LogName 'System' -EntryType Error -Source "EventLog" -EventId $script:RemoteStopEventID -Message "[$additionalMsg] This is StopMe Event ID: $script:RemoteStopEventID from script $($global:ScriptName) in order to stop data collection. Event was sent by user $Env:username on computer $Env:Computername at $SendTimeStamp UTC" -Category 1 -ComputerName $RemoteHost
			}Catch{
				LogException "Error happened in [SendStopEvent999] Write-EventLog to $RemoteHost" $_
				LogError "[Action] Please stop the script manually on all remote hosts with: .\$($global:ScriptName) -Stop"
			}
		}
		$script:fEvent999Sent=$True
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopTraces{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[PSObject]]$TraceCollection
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$global:TssPhase = "_Stop_"
	$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
	LogInfoFile "============== Entering TSS STOP Data collection: $TimeUTC UTC ======="
	# Change execution order based on 'StopPriority' in trace object
	$SortedLogCollector = $TraceCollection | Sort-Object -Property StopPriority
	
	# Remove and add trace object to original $TraceCollection with sorted order.
	ForEach($TraceObject in $SortedLogCollector){
		$TraceCollection.Remove($TraceObject) | Out-Null
		$TraceCollection.Add($TraceObject)
	}
	
	SendStopEvent999 -additionalMsg "in StopTraces"
	
	LogInfoFile "Stopping traces with below order (Time UTC $TimeUTC):" -ShowMsg
	$i=1
	ForEach($TraceObject in $TraceCollection){
		LogInfoFile ([String]::Format("  {0,-2} {1}", $i, $($TraceObject.TraceName))) -ShowMsg
		$i++
	}
	#Write-Host ' '

	# Get running ETW sessions
	$ETWSessionList = logman.exe -ets | Out-String
	GetETWSessionByPS [StopTraces]

	# Get running Scenario traces
	$Script:RunningScenarioObjectList = GetRunningScenarioTrace
	If($DebugMode.IsPresent){
		LogDebug ("Below traces will be stopped")
		LogDebug ("================	 RUNNING SCENARIOS AND TRACES	 ================")
		ForEach($TraceObject in $TraceCollection){
			#If(!($TraceObject.TraceName -like "*Scenario_*")){
				LogDebug ("  - " + $TraceObject.TraceName)
			#}
		}
		LogDebug ("=======================================================================")
		DumpCollection $TraceCollection
		Read-Host ("[DBG - hit ENTER to continue] [Before stopping traces] ==>")
	}

	# Get all processes running on current user session.
	$CurrentSessinID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
	$Processes = Get-Process | Where-Object{$_.SessionID -eq $CurrentSessinID}

	# Run pre-stop function for scenario trace.
	ForEach($ScenarioName in $Scenario){
		$ScenarioPreStopFunc = $ScenarioName + 'ScenarioPreStop'
		Try{
			RunFunction $ScenarioPreStopFunc -ThrowException:$True
		}Catch{
			LogException "An error happened in $ScenarioPreStopFunc but this is not critical and continue to stop traces." $_ $fLogFileOnly
		}
	}
	
	if ($TraceObject.LogType -eq 'ETW') {LogInfo "[ETW] Stopping all ETW traces ..."}
	ForEach($TraceObject in $TraceCollection){
		# Run pre-stop function for a component.
		$ComponentPreStopFunc = $TraceObject.Name + 'PreStop'
		Try{
			RunFunction $ComponentPreStopFunc -ThrowException:$True
		}Catch{
			LogWarn "[$($TraceObject.Name)] Error happens in pre-stop function($ComponentPreStopFunc). Skipping this trace."
			LogException ("An error happened in " + $ComponentPreStopFunc) $_ $fLogFileOnly
			Continue
		}

		Switch($TraceObject.LogType) {
			'ETW' {
				LogDebug "[ETW] Stopping $($TraceObject.TraceName)."
				Try{
					if ($TraceObject.TraceName -match "WIN_kernel") {
						$TraceObject.TraceName = 'NT Kernel Logger'
						LogInfoFile "[ETW] TraceName: 'NT Kernel Logger'" -ShowMsg
						}
					LogInfoFile "[ETW] logman stop `"$($TraceObject.TraceName)`" -ets"
					RunCommands "ETW" "Logman.exe stop `"$($TraceObject.TraceName)`" -ets" -ThrowException:$True -ShowMessage:$False -ShowError:$True
				}Catch{
					$ErrorInStoppingTrace = $True
				}

				# Retry stopping trace.
				If($ErrorInStoppingTrace){
					# Make sure the trace is really still running.
					$IsTraceRunning = $True
					Try{
						# If the trace is not running, 'logman <TraceName> -ets' throws an exception. In this case, we regard the trace stopped successfully.
						RunCommands "ETW" "Logman.exe $($TraceObject.TraceName) -ets" -ThrowException:$True -ShowMessage:$False -ShowError:$False
					}Catch{
						LogInfoFile "[ETW] $($TraceObject.TraceName) has already stopped." -ShowMsg
						$IsTraceRunning = $False # Looks like the trace is already stopped somehow. Set the flag to $False.
					}

					If($IsTraceRunning){
						# It is possible that the logman fails with some reason and trying the stop command might work. So sleep 3 seconds and try it again.
						LogWarn "Retrying to stop $($TraceObject.TraceName)"
						Start-Sleep -Seconds 3
						Try{
							RunCommands "ETW-2" "Logman.exe stop $($TraceObject.TraceName) -ets" -ThrowException:$True -ShowMessage:$True -ShowError:$True
						}Catch{
							LogException ("An error happened in `'Logman.exe stop $($TraceObject.TraceName)`'") $_
							$TraceObject.Status = $TraceStatus.ErrorInStop
							Continue
						}
						LogInfo "`'$($TraceObject.TraceName) `' was stopped successfully!" "Cyan"
					}
				}

				# Remove extension of .001(XXX-AutoLogger.etl.001 -> XXX-AutoLogger.etl
				If($script:StopAutologger){
					$001Files = Get-ChildItem $global:LogFolder | Where-Object {$_.Name -like "*-AutoLogger.etl.001" }
					ForEach($001File in $001Files){
						$NewName = $001File.FullName -Replace "\.etl\.001",".etl"
						LogDebug "Renaming $001File.Name to $NewName"
						Rename-Item $001File.FullName $NewName -ErrorAction Ignore
					}
				}

				# When we reach here, it means 'logman stop' was successful.
				$StoppedTraceList.Add($TraceObject)
				$TraceObject.Status = $TraceStatus.Stopped
				FwGetLogmanInfo _Stop_
				Break
			}
			'Command' {
				If($Null -ne $TraceObject.SupportedOSVersion){
					If(!(FwIsSupportedOSVersion $TraceObject.SupportedOSVersion)){
						LogInfo ($TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupportedOSVersion.OS + ' Build ' + $TraceObject.SupportedOSVersion.Build + ']')
						$TraceObject.Status = $TraceStatus.NotSupported
						Break
					}
				}
				LogDebug ('Enter [Command] section in StopTraces. Stopping ' + $TraceObject.Name)
				Try{
					Get-Command $TraceObject.CommandName -ErrorAction Stop | Out-Null
				}Catch{
					If($TraceObject.Name -eq 'Procmon' -and $TraceObject.AutoLogger.AutoLoggerEnabled -eq $True){
						LogDebug ('[Procmon] setting $fDonotDeleteProcmonReg to $True.')
						$script:fDonotDeleteProcmonReg = $True
					}
					LogError ($TraceObject.CommandName + ' not found. Please stop ' + $TraceObject.Name + ' manually.')
					$TraceObject.Status = $TraceStatus.ErrorInStop
					Break
				}

				$fFoundExistingSession = $False
				Switch($TraceObject.Name) {
					'WPR' {
						LogDebug ('Searching ' + $WPRSessionName + ' in CimInstances')
						ForEach($Line in ($ETWSessionList -split "`r`n")){
							$Token = $Line -Split '\s+'
							If($Token[0] -eq 'WPR_initiated_WprApp_WPR' -or $Token[0] -eq 'WPR_initiated_WprApp_boottr_WPR'){
								LogInfoFile "[WPR] Found existing $($TraceObject.Name) session ($Token[0])." "Yellow"
								$fFoundExistingSession = $True
								Break
							}
						}
					}
					'Xperf' {
						# We use a log file for xperf to see if the xperf is actively running.
						$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
						$LogFolderInReg = $RegValue.LogFolder
						If(![String]::IsNullOrEmpty($LogFolderInReg)){
							$XperfFileName = "$LogFolderInReg\xperf.etl"
							If(Test-Path -Path $XperfFileName){
								LogDebug ("[xperf] Found existing $($TraceObject.Name) session.")
								$fFoundExistingSession = $True
								Break
							}
						}
					}
				   'Netsh' {
						$NetshSessionName = 'NetTrace'
						ForEach($Line in ($ETWSessionList -split "`r`n")){
							$Token = $Line -Split '\s+'
							If($Token[0].Contains($NetshSessionName)){
								$fFoundExistingSession = $True
								LogInfoFile ('[Netsh] Found existing ' + $Token[0] + ' session.') -ShowMsg
								If($DebugMode.IsPresent){
									FwGetLogmanInfo _StopTraces_	# for #750
									FwGetRegHives _StopTraces_
								}
								FwGetLogmanInfo _NetSh_
								Break
							}
						}
					}
					'Procmon' {
						$Prcmon = $Processes | Where-Object{$_.Name.ToLower() -like 'Procmon*'}
						If($Prcmon.Count -ne 0){
							$fFoundExistingSession = $True
							LogDebug "[Procmon] Procmon is running as active session."
							Break
						}
						If($script:StopAutologger){
							If(Test-Path -Path $TraceObject.AutoLogger.AutoLoggerKey){
								Try{
									$Value = Get-Itemproperty -name 'Start' -path $TraceObject.AutoLogger.AutoLoggerKey -ErrorAction Ignore
								}Catch{
									LogDebug ('[Procmon] Start registry for Procmon does not exist. Skipping Procmon.')
									$fFoundExistingSession = $False 
									Break
								}
								# Start = 3 means this is first boot after BootLogging.
								If($NULL -ne $Value.Start -and ($Value.Start -eq 3 -or $Value.Start -eq 0)){
									LogDebug ('[Procmon] BootLogging detected.')
									$fFoundExistingSession = $True 
								}Else{
									LogDebug ('[Procmon] Start registry = ' + $Value.Start)
								}
							}
						}
					}
					'PSR' {
						$PSRProcess = $Processes | Where-Object{$_.Name.ToLower() -eq 'psr'}
						If($PSRProcess.Count -ne 0){
							$fFoundExistingSession = $True
							LogDebug ('[PSR] Found existing ' + $TraceObject.Name + ' session.')
						}
					}
					'Video' {
						$VideoProcess = $Processes | Where-Object{$_.Name.ToLower() -eq 'recordercommandline'}
						If($VideoProcess.Count -ne 0){
							$fFoundExistingSession = $True
							LogDebug ('[Video] Found existing ' + $TraceObject.Name + ' session.')
						}
					}
				}

				If(!$fFoundExistingSession){
					LogDebug ('Skipping stopping ' + $TraceObject.Name + ' as it is not running')
					Continue
				}

				# Normal case. Perform actual stop function here.
				If(!$script:StopAutologger){
					LogInfo "Stopping job $($TraceObject.Name)."
					LogInfoFile "[$($TraceObject.Name)] Running Stop-Command: $($TraceObject.CommandName) $($TraceObject.StopOption)" -ShowMsg
					Start-Job -Name ("TSSv2-" + $TraceObject.Name) -ScriptBlock {
						Start-Process -FilePath $Using:TraceObject.CommandName -ArgumentList $Using:TraceObject.StopOption -PassThru -wait
					} | Out-File -FilePath $global:ErrorLogFile -Append #we#| Out-Null
				# AutoLogger case.
				}Else{ 
					LogInfoFile ('[' + $TraceObject.Name + '] Running Stop-Command: ' + $TraceObject.CommandName + ' ' + $TraceObject.AutoLogger.AutoLoggerStopOption) -ShowMsg
					Start-Job -Name ("TSSv2-" + $TraceObject.Name) -ScriptBlock {
						Start-Process -FilePath $Using:TraceObject.CommandName -ArgumentList $Using:TraceObject.AutoLogger.AutoLoggerStopOption -PassThru -wait
					} | Out-Null

					If($TargetObject.Name -eq 'Procmon' -and $script:StopAutologger){
						Try{
							LogDebug ('Deleting Procmon registry keys')
							Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction Ignore
							Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Type'  -ErrorAction Ignore
						}Catch{
							# Do Nothing.
							LogWarn ('Failed to delete Procmon registry keys for ' + $TraceObject.AutoLogger.AutoLoggerKey)
						}
					}
				}
				$TraceObject.Status = $TraceStatus.Stopped
				$StoppedTraceList.Add($TraceObject)
			}
			'Perf' { #aka PerfMon
				LogDebug ('Enter [Perf] section in StopTraces. Name = ' + $TraceObject.Name)
				$datacollectorset = new-object -COM Pla.DataCollectorSet
				Try{
					$datacollectorset.Query($TraceObject.Name, $env:computername)
				}Catch{
					LogInfoFile ('Skipping stopping ' + $TraceObject.Name + ' as it is not running') -ShowMsg
					Break
				}

				#Status ReturnCodes: 0=stopped 1=running 2=compiling 3=queued (legacy OS) 4=unknown (usually AutoLogger)
				If($datacollectorset.Status -ne 1){
					LogDebug ('Skipping stopping ' + $TraceObject.Name + ' as it is not running')
					Break
				}
				LogInfoFile ('[' + $TraceObject.Name + '] Running logman.exe stop ' + $TraceObject.Name) -ShowMsg
				Logman.exe stop $TraceObject.Name | Out-Null
				If($LASTEXITCODE -ne 0){
					LogError ('[' + $TraceObject.Name + '] Failed to stop PerformanceMonitor log.')
					$TraceObject.Status = $TraceStatus.ErrorInStop
				}
				LogInfoFile ('[' + $TraceObject.Name + '] Running logman.exe delete ' + $TraceObject.Name) -ShowMsg
				Logman.exe delete $TraceObject.Name | Out-Null
				If($LASTEXITCODE -ne 0){
					LogError ('[' + $TraceObject.Name + '] Failed to delete Performance Monitor log.')
					$TraceObject.Status = $TraceStatus.ErrorInStop
				}Else{
					LogDebug ('[Perf] PerfMon was successfully stopped.')
					$TraceObject.Status = $TraceStatus.Stopped
					$StoppedTraceList.Add($TraceObject)
				}
			}
			'Custom' {
				LogDebug ('Enter [Custom] section in StopTraces. Name = ' + $TraceObject.Name)
				If($Null -ne $TraceObject.SupportedOSVersion){
					If(!(FwIsSupportedOSVersion $TraceObject.SupportedOSVersion)){
						LogDebug "$($TraceObject.Name) is not supported on this OS. Supported Version is [Windows $($TraceObject.SupportedOSVersion.OS) Build $($TraceObject.SupportedOSVersion.Build)]."
						$TraceObject.Status = $TraceStatus.NotSupported
						Break
					}
				}
				# Check if the trace has post-stop function. If so, just call it.
				Try{
					If($Null -ne $TraceObject.StopFunc){
						Try{
							$CustomStopFunc = $TraceObject.StopFunc
							RunFunction $CustomStopFunc -ThrowException:$True
							$fCustomStopFuncStarted = $True
						}Catch{
							LogWarn "Error happens in $CustomStopFunc. See error file $global:ErrorLogFile for detail."
							LogException ("An error happened in " + $CustomStopFunc) $_ $fLogFileOnly
						}
					}Else{
						$TraceObject.Status = $TraceStatus.NoStopFunction
					}
				}Catch{
					LogException ('[' + $TraceObject.Name + '] An error happened in stop function(' + $TraceObject.StopFunc + ').') $_
					$TraceObject.Status = $TraceStatus.ErrorInStop
					Continue
				}
				If($fCustomStopFuncStarted){
					$TraceObject.Status = $TraceStatus.Stopped
					$StoppedTraceList.Add($TraceObject)
				}
			}
			Default {
				LogError ('Unknown log type ' + $TraceObject.LogType)
			}
		}

		# For multiple etl trace, a post-stop function is associated with multiple etl traces 
		# and this causes the post-stop function to be run before stopping all associated METL traces.
		# To prevent this, we remember the metl traces and run a post-stop function for them later.
		If($TraceObject.TraceName -like "*_METL_*"){
			$TraceName = $DelayedExecutionList | Where-Object {$_ -eq $TraceObject.Name}
			If($Null -eq $TraceName){
				LogDebug "Adding $($TraceObject.Name) to DelayedExecutionList"
				$Script:DelayedExecutionList.Add($TraceObject.Name)
			}
			Continue
		}

		# Run post-stop function for a component. For Command type, stop process is executed asynchronously using PSJob. So we don't run post-stop function for command type at this point.
		If($TraceObject.LogType -ne 'Command'){
			$ComponentPostStopFunc = $TraceObject.Name + 'PostStop'
			Try{
				If(!$global:BoundParameters.ContainsKey('Discard')){
					RunFunction $ComponentPostStopFunc -ThrowException:$True
				}
			}Catch{
				LogWarn "Error happens in $ComponentPostStopFunc. See error file $global:ErrorLogFile for detail."
				LogException ("An error happened in " + $ComponentPostStopFunc) $_ $fLogFileOnly
			}
		}
	}

	If(!$global:BoundParameters.ContainsKey('Discard')){
		# Run post-stop function for type2(multiple etl) trace.
		ForEach($METLTraceName in $DelayedExecutionList){
			$ComponentPostStopFunc = $METLTraceName + 'PostStop'
			Try{
				RunFunction $ComponentPostStopFunc -ThrowException:$True
			}Catch{
				LogWarn "Error happens in $ComponentPostStopFunc. See error file $global:ErrorLogFile for detail."
				LogException ("An error happened in " + $ComponentPostStopFunc) $_ $fLogFileOnly
			}
		}

		# Run post-stop function for scenario trace that does have command type trace.
		ForEach($ScenarioName in $Scenario){ # When -StartNoWait, $Scenario is set in ReadParameterFromTSSReg().
			# Fix(#222)
			# If the scenario has command type trace like WPR and Netsh, the post-stop function for the scenario will be run after stopping all commands. #we# comment: this must not delay time-critical Post-Stop actions! better run your POD action in Collect...Log()
			If((HasScenarioCommandTypeTrace $ScenarioName)){
				If($DelayedExecutionListForScenario -notcontains $ScenarioName){
					LogInfoFile "Post-stop function for $ScenarioName will be run after stopping all command type traces." "Gray" -ShowMsg
					$Script:DelayedExecutionListForScenario.Add($ScenarioName)
				}
				Break
			}
			$ScenarioPostStopFunc = $ScenarioName + 'ScenarioPostStop'
			Try{
				RunFunction $ScenarioPostStopFunc -ThrowException:$True
			}Catch{
				LogWarn "Error happens in $ComponentPostStopFunc. See error file $global:ErrorLogFile for detail."
				LogException ("An error happened in " + $ScenarioPostStopFunc) $_ $fLogFileOnly
			}
			# create Zip file suffix based on scenario selcected #we#
			$script:LogZipFileSuffixScn += -join ($ScenarioName , "_")
		}
	}

	# Won't collect basic logs if we are in recovery process.
	If(!$Script:fInRecovery){
		#_# moved ----- begin _Stop_common_task block down after: data collection function for scenario. #161 /WalterE

		# We call component collect function in case of below conditions.
		# 1) There is a running scenario trace but -CollectComponentLog is specified
		# 2) There is no scenario trace
		If(!$global:BoundParameters.ContainsKey('Discard')){
			If(([String]::IsNullOrEmpty($Scenario)) -or (![String]::IsNullOrEmpty($Scenario) -and $Null -ne $global:BoundParameters['CollectComponentLog'])){
				# Now call component specific log function
				# The naming convention of the function is 'Collect' + $TraceObject.Name + 'Log'(ex. CollectRDSLog)
				ForEach($StoppedTrace in $StoppedTraceList){
				
					# Calling component callback function
					$ComponentSpecificFunc = 'Collect' + $StoppedTrace.Name + 'Log'
					Try{
							RunFunction $ComponentSpecificFunc -ThrowException:$True
					}Catch{
						LogWarn "Error happens in $ComponentSpecificFunc."
						LogException ("[$StoppedTrace] An error happened in " + $ComponentSpecificFunc) $_ $fLogFileOnly
					}
				
					# Diag function
					$ComponentDidagFunc = 'Run' + $StoppedTrace.Name + 'Diag'
					Try{
						RunFunction $ComponentDidagFunc -ThrowException:$True
					}Catch{
						LogWarn "Error happens in $ComponentDidagFunc."
						LogException ("An error happened in " + $ComponentDidagFunc) $_ $fLogFileOnly
					}
				}
			}

			# Run data collection function for scenario.
			ForEach($ScenarioName in $Scenario){
				LogDebug "Searching data collection function for $ScenarioName scenario."
				$ScenarioDataCollectionFunc = 'Collect' + $ScenarioName + 'ScenarioLog'
				Try{
					RunFunction $ScenarioDataCollectionFunc -ThrowException:$True
				}Catch{
					LogWarn "Error happens in $ScenarioDataCollectionFunc."
					LogException ("An error happened in " + $ScenarioDataCollectionFunc) $_ $fLogFileOnly
				}

				# Run diag function for scenario.
				$ScenarioDiagFunc = 'Run' + $ScenarioName + 'ScenarioDiag'
				Try{
					RunFunction $ScenarioDiagFunc -ThrowException:$True
				}Catch{
					LogWarn "Error happens in $ScenarioDiagFunc."
					LogException ("An error happened in " + $ScenarioDiagFunc) $_ $fLogFileOnly
				}
			}
		 
			# Call common STOP tasks
			If(($Scenario.Count -ne 0) -and [string]::IsNullOrEmpty($CommonTask)){
				[Bool]$Script:IsCommonTaskAlreadyRun = $False

				# In this case, we don't know what scenario of common task to call. Therefore retrieve the scenario name from running trace name.
				ForEach($ScenarioName in $Scenario){
					$ScenarioTraceSetName = "$($ScenarioName)_ETWTracingSwitchesStatus"
					$Scenario_ETWTracingSwitchesStatus = Get-Variable $ScenarioTraceSetName -ValueOnly -ErrorAction Ignore
					ForEach($Key in $Scenario_ETWTracingSwitchesStatus.Keys){
						$Token = $Null
						If($Key.contains('CommonTask')){
							$Token = $Key -split ' '
							LogDebug "Setting `'$($Token[1])`' to TaskType"
							$TaskType = $Token[1]
							Switch($TaskType){
								# For Full and Mini, add -RunOnce:$False as its possible the collect func is called previously on start.
								'Full'{
									RunFunction "FwCollect_BasicLog" -Stage  "After-Repro" -RunOnce:$False -ThrowException:$False
								}
								'Mini'{
									RunFunction "FwCollect_MiniBasicLog" -Stage "After-Repro" -RunOnce:$False -ThrowException:$False
								}
								Default {
									$PODCommonStopFunc = $TaskType + "_Stop_Common_Tasks"
									RunFunction $PODCommonStopFunc -ThrowException:$False
									[Bool]$Script:IsCommonTaskAlreadyRun = $True
								}
							}
						}
					}
				}
			}ElseIf(![string]::IsNullOrEmpty($CommonTask)){ # -Stop + -CommonTask case
				Switch($CommonTask){
					# For Full and Mini, add -RunOnce:$False as its possible the collect func is called previously on start.
					'Full'{
						RunFunction "FwCollect_BasicLog" -Stage  "After-Repro" -RunOnce:$False -ThrowException:$False 
					}
					'Mini'{
						RunFunction "FwCollect_MiniBasicLog" -Stage "After-Repro" -RunOnce:$False -ThrowException:$False
					}
					Default {
						$PODCommonStopFunc = $CommonTask + "_Stop_Common_Tasks"
						RunFunction $PODCommonStopFunc -ThrowException:$False
						[Bool]$Script:IsCommonTaskAlreadyRun = $True
					}
				}
			}
			if (!$Script:IsCommonTaskAlreadyRun){
				# We call full basic log only when -Basiclog is specified. Otherwise mini basic log(FwCollect_MiniBasicLog) is called.
				# It is possible FwCollect_BasicLog/FwCollect_MiniBasicLog will be run twice as it might be run as an above common task.
				# But RunFunction() can recognize if it has been already run or not. So the below basic log is run only when the common task is not Mini or Full.
				ProcessBasicLog $Script:IsCommonTaskAlreadyRun
			}
			#_#----- end _Stop_common_task
			
			If($global:ParameterArray -contains "noBasiclog" -and !$Script:IsCommonTaskAlreadyRun -and $global:ParameterArray -notcontains "mini"){
				# Run collection of RegKey and Eventlogs after repro, defined by POD calls to FWaddRegItem and FWaddEvtLog _Stop_
				if (($global:RegKeysModules.count -gt 0) -or ($global:RegKeysModulesNoRecursive.count -gt 0)) { FWgetRegList $global:TssPhase }
				if ($global:EvtLogNames.count -gt 0) { FWgetEvtLogList $global:TssPhase }
			}

			# Run xray Diagnostics to scan for known issues (no need to show EULA again)
			#_# If($global:ParameterArray -Contains 'xray' -and !$noXray.IsPresent){
			If($xray.IsPresent){ #we#
				If ($noXray){
					Processxray -skipDiags
				}else{
					Processxray
				}
			}
		}else{ LogInfoFile " Skip data-collection .. early exit because of -Discard switch" "Magenta" -ShowMsg}
	}

	$Jobs = Get-Job -Name "TSSv2-*"
	If($Jobs.Count -ne 0){
		LogInfo "Waiting for all running (job) commands below to be stopped."
		ForEach($Job in $Jobs){
			LogInfo "  - $($Job.Name)"
		}
	}

	# Start wating for jobs to be completed.
	$LoopCount = 0
	$CheckIntervalInSec = 1
	While($Jobs.Count -ne 0){
		$LoopCount++
		$Jobs = Get-Job -Name "TSSv2-*"
		If($Null -eq $Jobs){ # All job are finished and get out of while loop.
			Break
		}
		Write-Host '.' -NoNewline
		$IsDotDisplayed = $True
		Start-Sleep $CheckIntervalInSec

		ForEach($Job in $Jobs){
			$CommandName = $Job.Name -replace ("TSSv2-","")
			$TraceObject = $TraceCollection | Where-Object {$_.Name -eq $CommandName}
			$JobFinished = $False

			Switch($Job.State){
				'Completed'{
					If($IsDotDisplayed -eq $True){
						Write-Host ' '
					}
					LogInfo "Job $($Job.Name) is completed."
					Remove-Job $Job
					$TraceObject.Status = $TraceStatus.Stopped
					$JobFinished = $True
				}
				'Failed'{
					LogError ($Job.Name + ' failed.' + "`n" + $job.ChildJobs[0].JobStateInfo.Reason.Message)
					Remove-Job $Job
					$TraceObject.Status = $TraceStatus.ErrorInStop
					$JobFinished = $True
				}
				'Running'{
					# Get time out value from its property.
					If(![string]::IsNullOrEmpty($TraceObject.StopTimeoutInSec)){
						$JobTimeOutInSec = $TraceObject.StopTimeoutInSec
					}Else{
						$JobTimeOutInSec = 1800 # 30 minutes
					}

					# Calclate current elapsed time.
					$ElapsedTime = $LoopCount * $CheckIntervalInSec
					If($LoopCount -eq 31) {LogInfo "trying to stop job $($TraceObject.CommandName) since $ElapsedTime seconds (TimeOut=$JobTimeOutInSec sec)" "Gray"}

					# Check if it is timed out.
					If($ElapsedTime -ge $JobTimeOutInSec){
						LogError "Time out(Elapased time=$ElapsedTime TimeOut=$JobTimeOutInSec) happened. Unable to stop $($TraceObject.CommandName)."
						Stop-Job $Job
						Remove-Job $Job
						$TraceObject.Status = $TraceStatus.ErrorInStop
						$JobFinished = $True
					}
				}
				Default {
					LogWarn "$($Job.Name) is in $($Job.State). This is not normal and removing the job."
					Stop-Job $Job
					Remove-Job $Job
				}
			}
			$IsDotDisplayed = $False
			# If the job is finished regardless of the status(sucess or error), we call post-stop function for this object.
			If($JobFinished){
				 $CommandPostStopFunc = $TraceObject.Name + "PostStop"
				 Try{
					 RunFunction $CommandPostStopFunc -ThrowException:$True
				 }Catch{ # Show only warning message and log detail to error file.
					 LogWarn "An exception happens in $CommandPostStopFunc. See error file $global:ErrorLogFile for detail."
					 LogException ("An exception happened in " + $CommandPostStopFunc) $_ $fLogFileOnly
				 }
			}
		}
	}
	Write-Host ' '

	# Fix(#222)
	# Run post-stop function for the scenario that has command type trace.
	If($DelayedExecutionListForScenario.Count -ne 0){
		ForEach($ScenarioName in $DelayedExecutionListForScenario){
			$ScenarioPostStopFunc = $ScenarioName + 'ScenarioPostStop'
			Try{
				If(!$global:BoundParameters.ContainsKey('Discard')){
					RunFunction $ScenarioPostStopFunc -ThrowException:$True
				}
			}Catch{
				LogWarn "Error happens in $ScenarioPostStopFunc. See error file $global:ErrorLogFile for detail."
				LogException ("An error happened in " + $ScenarioPostStopFunc) $_ $fLogFileOnly
			}
		}
	}ElseIf($Scenario.Count -ne 0){
		ForEach($ScenarioName in $Scenario){
			$ScenarioPostStopFunc = $ScenarioName + 'ScenarioPostStop'
			Try{
				If(!$global:BoundParameters.ContainsKey('Discard')){
					RunFunction $ScenarioPostStopFunc -ThrowException:$True
				}
			}Catch{
				LogWarn "Error happens in $ScenarioPostStopFunc. See error file $global:ErrorLogFile for detail."
				LogException ("An error happened in " + $ScenarioPostStopFunc) $_ $fLogFileOnly
			}
			$script:LogZipFileSuffixScn += -join ($ScenarioName , "_")
		}
	}

	# Collect eventlogs(#564)
	If($global:BoundParameters.ContainsKey('CollectEventLog')){
		ProcessCollectEventLog
	}

	# Copy memory.dmp if -Crash is specifed in previous run and memory.dmp exists.(#518)
	If($global:BoundParameters.ContainsKey('CollectDump')){
		FwCopyMemoryDump
	}

	If($global:BoundParameters.ContainsKey('ETLOptions') -and !($global:BoundParameters.ContainsKey('StartAutologger'))){ # allow -EtlOption circular:<EtlMaxSizeMB> for autologger (#671)
		UnRegisterPurgeTask
	}

	# Remove script parameters in TSSRegKey.
	If(!$Script:IsCrashInProgress){
		RemoveParameterFromTSSReg
	}

	# Run psSDP here.
	If(!$Script:fInRecovery -and ($global:ParameterArray -Contains 'SDP' -and !($global:ParameterArray -Contains 'noSDP')) -and (!$global:BoundParameters.ContainsKey('Discard')) ){
		processSDP
	}

	$Script:DataCollectionCompleted = $True
	# Originally enabled debug/analytic log is re-enabled here.
	FwResetAllEventLogs

	# Trigger crash if -Crash is specified.
	FwDoCrash

	# Restoring HKLM\SOFTWARE\Microsoft\NetSh\1, if it was set previously		#_# 1=ipmontr.dll 2=ifmon.dll
	If(-not ($Null -eq $global:OriginalNetShRegistry1)){
		LogInfoFile "Restoring `'HKLM\SOFTWARE\Microsoft\NetSh\1`' to $global:OriginalNetShRegistry1" # 1="ipmontr.dll"
		Set-ItemProperty -ErrorAction Ignore -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh -Name 1 -value "ipmontr.dll" -Force
	}

	Write-Host ' '
	#LogInfo ($StoppedTraceList.Count.ToString() + ' trace(s) are stopped.')
	EndFunc $MyInvocation.MyCommand.Name
}

Function RemoveAutoLogger{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")
	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation
		}Catch{
			LogException "[RemoveAutoLogger] An exception happened in RunPreparation." $_
			CleanUpandExit
		}
	}

	$Count=0
	$EnabledAutoLoggerSessions = GetEnabledAutoLoggerSession
	ForEach($TraceObject in $EnabledAutoLoggerSessions){

		If($Null -eq $TraceObject.AutoLogger -or !$TraceObject.AutoLogger.AutoLoggerEnabled){
			Continue
		}

		LogDebug ('Processing deleting AutoLogger setting for ' + $TraceObject.Name)
		Try{
			Switch($TraceObject.LogType){
				'ETW' {
					LogInfoFile ('[ETW] Deleting ' + $TraceObject.AutoLogger.AutoLoggerSessionName)  -ShowMsg
					Logman.exe stop $TraceObject.Name -ets | Out-Null
					Logman.exe delete $TraceObject.AutoLogger.AutoLoggerSessionName | Out-Null
					If($LASTEXITCODE -ne 0){
						Throw('Error happens in Logman.exe delete ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
					}
				}
				'Command' {
					Switch($TraceObject.Name) {
						'WPR' {
							LogInfo ('[' + $TraceObject.Name + '] Canceling BootTrace.')
							wpr.exe -BootTrace -cancelboot
							 If($LASTEXITCODE -ne 0){
								 $ErrorMssage = 'Error happens in wpr.exe -BootTrace -cancelboot'
								 LogError$ErrorMssage 
								 Throw($ErrorMssage)
							 }
						}
						'Xperf' {
							LogInfo ('[' + $TraceObject.Name + '] Canceling BootTrace.')
							$XperfCommand = Get-Command $TraceObject.CommandName -ErrorAction Ignore
							If($Null -eq $XperfCommand){
								LogError "Unable to find $XperfPath"
								CleanUpandExit
							}
							$Command = "$($TraceObject.CommandName) -BootTrace off"
							RunCommands "Xperf" $Command -ThrowException:$True -ShowMessage:$True -ShowError:$True
						}
						'Netsh' {
							 netsh trace show status  | Out-Null
							 If($LASTEXITCODE -ne 0){
								 LogDebug ('[' + $MyInvocation.MyCommand.Name + '] Netsh is not running') 
								 Continue
							 }
							 LogInfoFile ('[' + $TraceObject.Name + '] Running ' + $TraceObject.CommandName + ' ' + $TraceObject.AutoLogger.AutoLoggerStopOption) -ShowMsg
							 Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.AutoLogger.AutoLoggerStopOption -PassThru -wait | Out-Null
						}
						'Procmon' {
							If($script:fDonotDeleteProcmonReg){
								Break
							}
							LogInfoFile ('[Procmon] Deleting Procmon registry keys(' + $TraceObject.AutoLogger.AutoLoggerKey + '\Start and Type)') -ShowMsg
							Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction SilentlyContinue
							Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Type' -ErrorAction SilentlyContinue
						}
					}
				}
			}
		}Catch{
			LogException ('An exception happens during deleting AutoLogger setting for ' + $TraceObject.Name) $_
			Continue
		}
		$Count++
	}

	If($Count -eq 0){
		LogInfo "No AutoLogger session was found."
	}

	# Unregister a purge task in task scheduler if it exists.
	UnRegisterPurgeTask

	# Remove script parameters in TSS registry as no longer needed.
	RemoveParameterFromTSSReg

	EndFunc $MyInvocation.MyCommand.Name
}

Function StartPerfMonLog{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object]$TraceObject
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ('Starting Performance Monitor log.')
	If($TraceObject.LogType -ne 'Perf' -or $TraceObject.Providers.Length -eq 0){
		$ErrorMessage = ('Invalid object(LogType:' + $TraceObject.LogType + ') was passed to StartPerfMonLog.')
		LogError $ErrorMessage
		Throw($ErrorMessage)
	}

	$PerfCounters = $Null
	ForEach($PerfCounter in $TraceObject.Providers){
		$PerfCounters += "`"" + $PerfCounter + "`""  + " "
	}
	
	If($TraceObject.Name -eq 'PerfMon'){
		$Interval = $Script:PerfMonInterval
	}ElseIf($TraceObject.Name -eq 'PerfMonLong'){
		$Interval = $Script:PerfMonLongInterval
	}

	If($PerfMonCNF) {$PerfCNF = "-cnf $PerfMonCNF"}else{$PerfCNF = "-f bincirc"}
	$Perfcmd = "Logman.exe create counter " + $TraceObject.Name + " -o `"" + $TraceObject.LogFileName + "`" -si $Interval -c $PerfCounters -max $PerfMonMaxMB $PerfCNF"
	LogInfoFile "[$($TraceObject.Name)] Running $Perfcmd" -ShowMsg
	Try{
		Invoke-Expression $Perfcmd -ErrorAction Stop | Out-Null
	}Catch{
		$ErrorMessage = ('An exception happened in Logman.exe create counter.')
		LogException ($ErrorMessage) $_ $fLogFileOnly
		Throw($ErrorMessage)
		FwGetRegHives _PerfError_stop_
	}

	Logman.exe start $TraceObject.Name  | Out-Null
	If($LASTEXITCODE -ne 0){
		$ErrorMessage = ('An error happened during starting ' + $TraceObject.Name + '(Error=' + [Convert]::ToString($LASTEXITCODE,16) + ')')
		LogError $ErrorMessage
		LogInfo "[ERROR-Info] Hint: On this error you can try to run your TSS command-line with additional switch -noPerfmon" "Magenta"
		Throw($ErrorMessage)
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CompressLogIfNeededAndShow{
	EnterFunc $MyInvocation.MyCommand.Name
	# Fix(#224)
	if (!($global:ParameterArray -contains 'noZip') -and !($global:ParameterArray -contains 'noCab')) {  # skip compressing results if -noZip or -noCab

		If(!$global:BoundParameters.ContainsKey('Discard')){
			# 1. In case of scenario trace, create Zip file suffix using the scenario name.
			If($Script:RunningScenarioObjectList.Count -ne 0){
				$script:LogZipFileSuffixScn = $Script:RunningScenarioObjectList.ScenarioName
				$script:LogZipFileSuffix = $script:LogZipFileSuffixScn
			}ElseIf(![String]::IsNullOrEmpty($Scenario)){ # Case for -StartNoWait + no trace in scenario
				$Token = $Scenario -split ','
				ForEach($ScenarioName in $Token){
					$script:LogZipFileSuffix = $ScenarioName + '_'
				}
				$script:LogZipFileSuffix = $script:LogZipFileSuffix  -replace "_$",""
			}

			# 2. In case of -AddDescription, ask user to input brief description and set it to $Description
			If($global:ParameterArray -Contains 'AddDescription' -and !($global:ParameterArray -Contains 'noAsk')){
				While($True){
					Write-Host ' '
					LogInfo "Enter a brief description of the issue (Press Enter when done)"
					Write-Host "Examples:"
					Write-Host "  - Good"
					Write-Host "  - Error case"
					Write-Host "  - Failing Repro"
					Write-Host '=> Special characters/symbols(#<>*_/\{}$+%`|=@\") are not allowed to use.'
					FwPlaySound
					$Description = Read-Host "Description"
					If($Description.Length -gt 40 -or $Description.Length -eq 0){
						LogInfo "Enter problem description within 40 characters"
					}ElseIf($Description -match '[#<>\*_\/\\\{\}\$\?\+%`\|=@"]'){
						LogInfo "Below symbols are not allowed. Please enter the description again." 
						LogInfo '=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\"' "Yellow"
					}Else{
						Break
					}
				}
				# Replace space(' ') with dash('-')
				$Description = $Description -replace (' ','-')
			}

			$LongZipFileName = (Split-Path $global:LogFolder -Leaf) + ".zip"

			# -Scenario case. Append scenario name.
			If(![string]::IsNullOrEmpty($script:LogZipFileSuffix)){ 
				$LongZipFileName = $LongZipFileName -Replace(".zip", "$script:LogZipFileSuffix.zip")
			# -CollectLog case. Append collected log component name.
			}ElseIf($global:ParameterArray -contains 'CollectLog'){
				$LogNames = $CollectLog -replace (",","-")
				$CollectLogDescription = "Log"
				ForEach($ComponentName in $CollectLog){
					$CollectLogDescription = $CollectLogDescription + '-' + $ComponentName
				}
				$LongZipFileName = $LongZipFileName -Replace(".zip", "$CollectLogDescription.zip")
			}

			# -xray case. Append xray_INFO or xray_ISSUES-FOUND
			If($global:ParameterArray -Contains 'xray'){
				$xrayInfoFile =  Get-ChildItem $global:LogFolder "xray_INFO*" -Recurse
				$xrayIssueFoundFile = Get-ChildItem $global:LogFolder "xray_ISSUES-FOUND*" -Recurse
				If($xrayInfoFile.Count -ne 0){
					$xrayDescription = "_xray_INFO"
				}
				If($xrayIssueFoundFile.Count -ne 0){
					$xrayDescription = "_xray_ISSUES-FOUND"
				}
				LogDebug "xrayInfoFile count = $($xrayInfoFile.Count) $xrayIssueFoundFile count = $($xrayIssueFoundFile.Count)"
				$LongZipFileName = $LongZipFileName -Replace(".zip", "$xrayDescription.zip")
			}

			# -AddDescription case. Append brief description of the issue.
			If($global:ParameterArray -Contains 'AddDescription' -and !($global:ParameterArray -Contains 'noAsk')){
				$LongZipFileName = $LongZipFileName -Replace(".zip", "-$Description.zip")
			}

			# 3. Create a full path of zip file
			$zipDestinationPath = (Split-Path $global:LogFolder -Parent) + "\" + $LongZipFileName
			LogDebug "LogZipFileSuffix = $script:LogZipFileSuffix"
			LogDebug "zipDestinationPath = $zipDestinationPath"

			# 4. If the created file path already exists(this could happen -stop without -AddDescription), rename the existing file.
			If(Test-Path $zipDestinationPath){
				# Case where destination zip file already exists.
				$DateSuffix = "$(Get-Date -f yyyy-MM-dd.HHmm.ss)"  
				$BackupZipPath = $zipDestinationPath -replace (".zip", "$DateSuffix.zip")
				LogInfo "Moving $zipDestinationPath to $BackupZipPath"
				Move-Item $zipDestinationPath $BackupZipPath -ErrorAction SilentlyContinue
			}
		}
		Write-Host ' '

		# 5. Before compressing log folder, close transcript.
		$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
		LogInfoFile "============== End of TSS Data collection: $TimeUTC UTC ============"
		Close-Transcript -ShowMsg

		# 6. Records all errors in $Error variable.
		If($Error.Count -ne 0){
			$Error | Out-File -FilePath $global:ErrorVariableFile
		}

		If(!$global:BoundParameters.ContainsKey('Discard')){
			# 7. Finally, compress log folder here.
			If(!$Script:StopInError){
				$ZipFileName = [System.IO.Path]::GetFileName($zipDestinationPath)
				LogInfo "Compressing $global:LogFolder folder(zip=$ZipFileName). This might take a while."
				Start-Sleep -s 5 #give some time for logging to complete before starting zip
				Try{
					Add-Type -Assembly 'System.IO.Compression.FileSystem'
					[System.IO.Compression.ZipFile]::CreateFromDirectory($global:LogFolder, $zipDestinationPath)
				}Catch{
					$ErrorMessage = 'An exception happened during compressing log folder' + "`n" + $_.Exception.Message
					LogWarn $ErrorMessage
					LogInfo "Please compress $global:LogFolder manually and send it to MS workspace upload site."
					LogException $ErrorMessage $_ $fLogFileOnly
					Return # Return here to prevent the deletion of source folder that is performed later.
				}
			}Else{
				LogInfo "Skipping compressing folder as an error happened in stop."
			}

			# 8. In case of Remoting, copy zip file to file share.
			If((IsStart) -and $global:IsRemoting -and $global:BoundParameters.ContainsKey('RemoteLogFolder')){
				$RemoteLogFolder = $global:BoundParameters['RemoteLogFolder']
				LogInfo "Copying $zipDestinationPath to $RemoteLogFolder"
				Try{
					Copy-Item $zipDestinationPath $RemoteLogFolder
				}Catch{
					LogError "Failed to copy $zipDestinationPath to $RemoteLogFolder"
				}
				$zipFileName = [System.IO.Path]::GetFileName($zipDestinationPath)
				$RemoteZiplogFileName = $RemoteLogFolder + "\" + $zipFileName
				If(Test-Path $RemoteZiplogFileName){
					LogInfo "==> Please send all zip files in $RemoteLogFolder to our upload site." "Cyan" -noDate
					$IsCopyToRemoteShareSucceeded = $True
				}Else{
					LogInfo "==> Please send $zipDestinationPath to our upload site." "Cyan" -noDate
				}
			}ElseIf($Script:StopInError){
				DisplayDataUploadRequestInError "ERROR(s) happened during stopping traces."
			}Else{
				LogInfo "==> Please send $zipDestinationPath to our MS upload site." "Cyan"
			}
		}
		# 9. Delete original log folder to save free space.
		If(!$Script:StopInError){
			LogDebug "Deleting $global:LogFolder"
			Try{
				Remove-Item $global:LogFolder -Recurse -Force -ErrorAction Stop | Out-Null
			}Catch{
				LogInfo "Please remove $global:LogFolder manually"
				$ErrorMessage = 'An exception happened during removing log folder' + "`n" + $_.Exception.Message
				LogException $ErrorMessage $_ $fLogFileOnly
			}
		}
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe (Split-Path $global:LogFolder -parent) }
		$Script:fCompressDone = $True
	}Else{
		If(!$global:BoundParameters.ContainsKey('Discard')){
			LogInfo "Logs were stored in $global:LogFolder"
			LogInfo "Please compress $global:LogFolder manually and send it to MS workspace upload site." "Cyan"
		}
		$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
		LogInfoFile "============== End of TSS Data collection: $TimeUTC UTC ============"
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe $global:LogFolder }
	}

	# 10. In case of remoting, also display remote share folder.
	If($IsCopyToRemoteShareSucceeded){
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe $RemoteLogFolder }
	}
	Write-Host ' '
	EndFunc $MyInvocation.MyCommand.Name
}

Function ShowTraceResult{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[PSObject]]$TraceObjectList,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Start','Stop')]
		[String]$FlagString,
		[Parameter(Mandatory=$True)]
		[Bool]$fAutoLogger
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Flag=$FlagString, fAutoLogger=$fAutoLogger"
	If($FlagString -eq 'Start'){
		$Status = $TraceStatus.Started
		If($fAutoLogger){
			$Message = 'Following AutoLogger session(s) were enabled:'
		}Else{
			$Message = 'Following trace(s) are started:'
		}
	}ElseIf($FlagString -eq 'Stop'){
		$Status = $TraceStatus.Stopped
		$Message = 'Following trace(s) are successfully stopped:'
	}

	Write-Host ' '
	LogInfo '********** RESULT **********' "Gray" -noDate
	$TraceObjects = $TraceObjectList | Where-Object{$_.Status -eq $Status}
	If($Null -ne $TraceObjects){
		LogInfo ($Message) -noDate
		ForEach($TraceObject in $TraceObjects){
			If(!$fAutoLogger){
				LogInfo ('	- ' + $TraceObject.TraceName) "Gray" -noDate
			}Else{
				LogInfo ('	- ' + $TraceObject.AutoLogger.AutoLoggerSessionName) "Gray" -noDate
			}
		}
	}Else{
		If($FlagString -eq 'Start'){
			LogInfo ('No traces are started.') -noDate
		}ElseIf($FlagString -eq 'Stop'){
			LogInfo ('No traces are stopped.') -noDate
		}
	}

	$ErrorTraces = $TraceObjectList | Where-Object{$_.Status -ne $Status -and $_.Status -ne $TraceStatus.NoStopFunction -and $_.Status -ne $TraceStatus.NotSupported}
	If($Null -ne $ErrorTraces){
		$Script:StopInError = $True # This will be used in CompressLogIfNeededAndShow()
		LogInfo ('[Error] The following trace(s) failed:')
		ForEach($TraceObject in $ErrorTraces){
			$StatusString = ($TraceStatus.GetEnumerator() | Where-Object {$_.Value -eq $TraceObject.Status}).Key
			If(!$fAutoLogger){
				LogInfo ('	- ' + $TraceObject.TraceName + "($StatusString)") "Red" -noDate
			}Else{
				LogInfo ('	- ' + $TraceObject.AutoLogger.AutoLoggerSessionName + "($StatusString)") "Red" -noDate
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function RunSetWer{
	EnterFunc $MyInvocation.MyCommand.Name
	$WERRegKey = "HKLM:Software\Microsoft\Windows\Windows Error Reporting\LocalDumps"
	FwPlaySound
	$DumpFolder = Read-Host -Prompt "Enter dump folder name"
	If(!(Test-Path -Path $DumpFolder -PathType Container)){
		Try{
			LogInfo ("Creating $DumpFolder.")
			New-Item $DumpFolder -ItemType Directory -ErrorAction Stop | Out-Null
		}Catch{
			LogException ("Unable to create $DumpFolder") $_
			CleanUpandExit
		}
	}

	If(!(Test-Path -Path $WERRegKey)){
		Try{
			LogInfo ("Creating $WERRegKey.")
			New-Item $WERRegKey -ErrorAction Stop | Out-Null
		}Catch{
			LogException ("Unable to create $WERRegKey") $_
			CleanUpandExit
		}
	}

	Try{
		LogInfo ("Setting `'DumpType`' to `'2`'.")
		Set-ItemProperty -Path $WERRegKey -Name 'DumpType' -value 2 -Type DWord -ErrorAction Stop | Out-Null
		LogInfo ("Setting `'DumpFolder`' to `'$DumpFolder`'")
		Set-ItemProperty -Path $WERRegKey -Name 'DumpFolder' -value $DumpFolder -Type ExpandString -ErrorAction Stop | Out-Null
	}Catch{
		LogException ("Unable to set DumpType or DumpFolder") $_
		CleanUpandExit
	}
	LogInfo "WER (Windows Error Reporting) settings are set properly." "Green"
	EndFunc $MyInvocation.MyCommand.Name
	CleanUpandExit
}

Function RunUnSetWer{
	EnterFunc $MyInvocation.MyCommand.Name
	$WERRegKey = "HKLM:Software\Microsoft\Windows\Windows Error Reporting\LocalDumps"
	If(Test-Path -Path $WERRegKey){
		Try{
			LogInfo ("Deleting $WERRegKey.")
			Remove-Item $WERRegKey -ErrorAction Stop | Out-Null
		}Catch{
			LogException ("Unable to delete $WERRegKey") $_
			CleanUpandExit
		}
	}Else{
			LogInfo ("INFO: `'$WERRegKey`' is already deleted.")
	}
	LogInfo "Disabling WER (Windows Error Reporting) settings is completed." "Cyan"
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessCollectLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("Started with -CollectLog $CollectLog")
	If([String]::IsNullOrEmpty($global:TssPhase)) { $global:TssPhase = "_Collect_" }
	LogInfoFile "======================== Start of Collect ========================"
	$RequestedLogs = $CollectLog -Split '\s+'
	$i=0

	# Run data collection and diag function for normal trace switch
	ForEach($RequestedLog in $RequestedLogs){
		$ComponentLogCollectionFunc = 'Collect' + $RequestedLog + 'Log'
		$Commandobj = Get-Command $ComponentLogCollectionFunc -CommandType Function -ErrorAction Ignore # Ignore exception
		If($Null -ne $Commandobj){
			Try{
				$i++
				If(!$global:BoundParameters.ContainsKey('Discard')){
					LogInfo ("Calling log collection function($ComponentLogCollectionFunc)") "green"
					& $ComponentLogCollectionFunc
				}
			}Catch{
				LogWarn ("Exception happened in $ComponentLogCollectionFunc.")
				LogException ("An error happened in $ComponentLogCollectionFunc") $_ $fLogFileOnly
				Continue
			}
		}Else{
			Continue
		}

		$ComponentDidagFunc = 'Run' + $RequestedLog + 'Diag'
		$Commandobj = Get-Command $ComponentDidagFunc -ErrorAction Ignore
		If($Null -ne $Commandobj){
			Try{

				# Call a function for diagnosis
				LogInfo ("Calling diag function($ComponentDidagFunc)") "green"
				& $ComponentDidagFunc
			}Catch{
				LogWarn ("Exception happened in $ComponentDidagFunc.")
				LogException ("An error happened in $ComponentDidagFunc") $_ $fLogFileOnly
				Continue
			}
		}Else{
			Continue
		}
	LogInfoFile "======================== End of Collect =========================="
	}

	# Run data collection and diag function for scenario trace
	ForEach($RequestedLog in $RequestedLogs){
		$ScenarioDataCollectionFunc = 'Collect' + $RequestedLog + 'ScenarioLog'
		$Commandobj = Get-Command $ScenarioDataCollectionFunc -CommandType Function -ErrorAction Ignore # Ignore exception
		If($Null -ne $Commandobj){
			Try{
				$i++
				If(!$global:BoundParameters.ContainsKey('Discard')){
					LogInfo ("Calling log collection function($ScenarioDataCollectionFunc)") "green"
					& $ScenarioDataCollectionFunc
				}
			}Catch{
				LogWarn ("Exception happened in $ScenarioDataCollectionFunc.")
				LogException ("An error happened in $ScenarioDataCollectionFunc") $_ $fLogFileOnly
				Continue
			}
		}Else{
			Continue
		}

		$ScenarioDiagFunc = 'Run' + $RequestedLog + 'ScenarioDiag'
		$Commandobj = Get-Command $ScenarioDiagFunc -ErrorAction Ignore
		If($Null -ne $Commandobj){
			Try{
				# Call a function for diagnosis
				LogInfo ("Calling diag function($ScenarioDiagFunc)") "green"
				& $ScenarioDiagFunc
			}Catch{
				LogWarn ("Exception happened in $ScenarioDiagFunc.")
				LogException ("An error happened in $ScenarioDiagFunc") $_ $fLogFileOnly
				Continue
			}
		}Else{
			Continue
		}
	}
	ProcessBasicLog $Script:IsCommonTaskAlreadyRun
	# Collect additional eventlogs if -CollectEventLog.
	If($global:BoundParameters.ContainsKey('CollectEventLog')){
		ProcessCollectEventLog
	}
	# Run xray #_# (always , as now [Switch]$xray = $True)
	#_# If($global:ParameterArray -contains 'xray' -and $global:ParameterArray -notcontains 'noXray'){
	If($xray.IsPresent){ #we#
		If ($noXray){
			Processxray -skipDiags
		}else{
			Processxray
		}
	}
	# Run psSDP
	If($global:ParameterArray -contains 'SDP' -and $global:ParameterArray -notcontains 'noSDP'){
		ProcessSDP
	}
	If($i -eq 0){
		Write-Host "Usage:"
		Write-Host ("  .\$($global:ScriptName) -CollectLog [ComponentName,ComponentName,...]")
		Write-Host ("  Example: .\$($global:ScriptName) -CollectLog UEX_FSLogix,UEX_Logon")
		Write-Host ' '
		Write-Host ("Run .\$($global:ScriptName) -ListSupportedLog to see supported log name")
	}
	CompressLogIfNeededAndShow
	CleanUpandExit
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStartDiag{
	EnterFunc $MyInvocation.MyCommand.Name
	If([String]::IsNullOrEmpty($global:TssPhase)) { $global:TssPhase = "_Diag_" }
	LogInfoFile "======================== Start of Diag ========================"
	$Count = 0
	ForEach($RequestedComponent in $StartDiag){
		$FuncName = 'Run' + $RequestedComponent + 'Diag'
		$CommandObj = Get-Command $FuncName -ErrorAction Ignore
		If($Null -ne $CommandObj){
			Try{
				LogInfo ("Calling diag function($FuncName)") "green"
				& $FuncName  # Calling function for log collection.
				$Count++
			}Catch{
				LogException ("Exception happened in $FuncName.") $_
				Return
			}
		}Else{
			LogDebug ("Diag function for $RequestedComponent($FuncName) is not implemented yet.")
		}

		# Diag for scenario
		$FuncName = 'Run' + $RequestedComponent + 'ScenarioDiag'
		$CommandObj = Get-Command $FuncName -ErrorAction Ignore
		If($Null -ne $CommandObj){
			Try{
				LogInfo ("Calling diag function for scenario($FuncName)") "green"
				& $FuncName  # Calling function for log collection.
				$Count++
			}Catch{
				LogException ("Exception happened in $FuncName.") $_
				Return
			}
		}Else{
			LogDebug ("Diag function for $RequestedComponent($FuncName) is not implemented yet.")
		}
	}

	If($Count -eq 0){
		Write-Host ("Please check component name you want to diagnose by running with -ListSupportedDiag. Then run again: .\$($global:ScriptName) -StartDiag <ComponentName>")
		Write-Host ("Example:")
		Write-Host ("PS> .\$($global:ScriptName) -ListSupportedDiag => Supported component name is listed.")
		Write-Host ("PS> .\$($global:ScriptName) -StartDiag <ComponentName>")
	}Else{
		If($xray.IsPresent){ #we#
			If ($noXray){
				Processxray -skipDiags
			}else{
				Processxray
			}
		}
		If($global:ParameterArray -contains 'SDP' -and $global:ParameterArray -notcontains 'noSDP'){
			ProcessSDP
		}
		CompressLogIfNeededAndShow
	}
	LogInfoFile "======================== End of Diag =========================="
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessTraceInfo{
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		RunPreparation # This creates global trace catalog
	}Catch{
		LogException "[ProcessTraceInfo] An exception happened in RunPreparation." $_
		CleanUpandExit
	}
	$TraceObjects = $Null
	Switch($TraceInfo){
		'all'{
			$TraceObjects = $GlobalTraceCatalog
		}
		'Command'{
			$TraceObjects = $GlobalTraceCatalog | Where-Object {$_.LogType -ne 'ETW'}
		}
		Default {
			# First, check if it is scenario name.
			$TracesInScenario = Get-Variable "$($TraceInfo)_ETWTracingSwitchesStatus" -ValueOnly -ErrorAction Ignore
			If($Null -ne $TracesInScenario){
				Write-Host "Scenario name:  $TraceInfo"
				Write-Host "  Trace switches:"
				ForEach($Key in $TracesInScenario.keys){
					Write-Host "	- $Key"
				}
				return
			}Else{
				$TraceObjects = $GlobalTraceCatalog | Where-Object {$_.Name -eq $TraceInfo}
			}
		}
	}
	If($Null -ne $TraceObjects){
		DumpTraceObject $TraceObjects
	}Else{
		Write-Host "Unable to find trace for `'$TraceInfo`'"
		Write-Host "Usage:"
		Write-Host "  .\$($global:ScriptName) -TraceInfo <ComponentName>|<ScenarioName>|all"
		Write-Host "   => Example: .\$($global:ScriptName) -TraceInfo ADS_BIO"
		Write-Host ' '
		Write-Host "  .\$($global:ScriptName) -TraceInfo all             // Show all trace info"
		Write-Host "  .\$($global:ScriptName) -TraceInfo <command>       // Show all trace info for Command, i.e. ProcDump"
		Write-Host "  .\$($global:ScriptName) -TraceInfo <ScenarioName>  // Show definition of scenario"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessFindKeyword{
	# calling ProcessHelp() with <keyword> or 0-9. Numbers 0-9 will invoke the corresponding Help-Menue items
	# It also works with regular expressions like "reg.*path"
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		ProcessHelp -SkipMenu -Ans $Find # This creates help-text files

	}Catch{
		LogException "[ProcessFindKeyword] An exception happened in ProcessHelp." $_
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListETWProviders{
	# input [string]$ListETWProviders
	EnterFunc $MyInvocation.MyCommand.Name
	# Load all trace providers defined in POD modules
	$ALLPODsProviderArray = Get-Variable -Name "*Providers"
	# Load all scenarios defined in POD modules
	$ScenarioTraceArray = Get-Variable "*_ETWTracingSwitchesStatus" -ErrorAction Ignore
	LogDebug " ---> Building List of all included components for ScenarioName: $ListETWProviders"
	# Scenarios	# first list all included components
	ForEach($ScenarioDefinition in $ScenarioTraceArray){
		$ScenarioName = $ScenarioDefinition.Name -replace ("_ETWTracingSwitchesStatus","")
		if ($ScenarioName -eq $ListETWProviders){
			if ($($ScenarioDefinition.Value.count) -gt 0) {
				Write-host "List of $($ScenarioDefinition.Value.count) components for ScenarioName: $ScenarioName"
				Write-host "======================================"
				$ScenarioDefinition.Value
			}
		}
	}
	LogDebug " ---> Building List of Provider GUIDs (Flags/Level) for ComponentName: $ListETWProviders"
	# Components
	$ProviderGUIDfound = $False

	ForEach($TraceProvider in $ALLPODsProviderArray){
		$TraceName = $TraceProvider.Name -replace ("Providers","")
		if ($TraceName -eq $ListETWProviders){
			if ($($TraceProvider.Value.count) -gt 0) {
				Write-host "`nList of $($TraceProvider.Value.count) Provider GUIDs (Flags/Level) for ComponentName: $TraceName"
				Write-host "=========================================================="
				$TraceProvider.Value
				$ProviderGUIDfound = $True
			}
		}
	}
	if (-not $ProviderGUIDfound) { Write-host "`n======================================`nThere is no such component name `"$ListETWProviders`". Please see Scenario included ETW tracing."}
	EndFunc $MyInvocation.MyCommand.Name
}
Function ProcessFindGUID{
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		RunPreparation # This creates global trace catalog
	}Catch{
		LogException "[ProcessFindGUID] An exception happened in RunPreparation." $_
		CleanUpandExit
	}
	$TraceObjectList = New-Object 'System.Collections.Generic.List[PSObject]'

	ForEach($TraceObject in $GlobalTraceCatalog){
		If($Null -eq $TraceObject.Providers){
			continue
		}
		ForEach($Provider in $TraceObject.Providers){
			If($Provider -match ".*$FindGUID.*"){
				$TraceObjectList.Add($TraceObject)
			}
		}
	}
	If($TraceObjectList.Count -ne 0){
		Write-Host "Below trace(s) contain `'$FindGUID`'."
		ForEach($TraceObject in $TraceObjectList){
			Write-Host "	- $($TraceObject.Name)"
		}
	}Else{
		Write-Host "No trace contains `'$FindGUID`'."
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CheckParameterCompatibility{
	EnterFunc $MyInvocation.MyCommand.Name
	If($Netsh.IsPresent -and ($Null -ne $NetshScenario)){
		$Message = 'ERROR: Cannot specify -Netsh and -NetshScenario at the same time.'
		LogInfo ($Message) "Red"
		Throw $Message
	}

	If(($global:ParameterArray -contains 'WPR') -and ($global:ParameterArray -contains 'Xperf')){
		$Message = 'ERROR: Cannot specify -WPR and -Xperf at the same time.'
		LogInfo ($Message) "Red" -noDate
		Throw $Message
	}

	If(($StartAutoLogger.IsPresent) -and ($global:BoundParameters.ContainsKey('WaitEvent'))){	# currently already disallowed by [Parameter(ParameterSetName='Start')] $WaitEvent
		$Message = "ERROR: We currently don't support combining -WaitEvent with -StartAutoLogger."
		LogInfo ($Message) "Red"
		Throw $Message
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CheckDeprecatedParam{
	EnterFunc $MyInvocation.MyCommand.Name
	$ALLPODsDeprecatedParamList = Get-Variable -Name "*_DeprecatedParamList" -ValueOnly
	If($ALLPODsDeprecatedParamList -eq $Null){
		LogDebug "No DeprecatedParamList"
		Return
	}
	$Commandline = $Script:TSScommandline
	# Remove script name and -NewSession
	$Commandline = $Commandline -replace "-NewSession",""  
	$Commandline = $Commandline -replace ".*\.ps1\' ",""  
	$FoundDeprecatedParams = @()
	ForEach($DeprecatedParamLists in $ALLPODsDeprecatedParamList){
		ForEach($DeprecatedParamProperty in $DeprecatedParamLists){
			LogDebug ("DeprecatedParamParam=" + $DeprecatedParamProperty.DeprecatedParam + " Type=" + $DeprecatedParamProperty.Type)
			#if ($global:ParameterArray -contains $DeprecatedParamProperty.DeprecatedParam){
			if ($Commandline -match $DeprecatedParamProperty.DeprecatedParam){
				If($DeprecatedParamProperty.Type -eq "Rename"){
					LogDebug ("Renaming " + $DeprecatedParamProperty.DeprecatedParam + " to " + $DeprecatedParamProperty.NewParam)
					# Replace deprecated param with new one.
					$Commandline = $Commandline -replace "$($DeprecatedParamProperty.DeprecatedParam)","$($DeprecatedParamProperty.NewParam)"
					$FoundDeprecatedParams += $DeprecatedParamProperty.DeprecatedParam
				}ElseIf($DeprecatedParamProperty.Type -eq "Obsolete"){
					LogDebug ("Removing " + $DeprecatedParamProperty.DeprecatedParam)
					# Just remove the obsoleted param.
					$Commandline = $Commandline -replace (" -" + $($DeprecatedParamProperty.DeprecatedParam)),""
					$FoundDeprecatedParams += $DeprecatedParamProperty.DeprecatedParam
				}
			}
		}
	}
	If($FoundDeprecatedParams.Count -gt 0){
		$DeprecatedParamsString = [String]$FoundDeprecatedParams -replace " ",","
		LogError "Deprecated parameter($DeprecatedParamsString) was passed. Run below command line instead."
		Write-Host -ForegroundColor Cyan "  PS> $($MyInvocation.ScriptName) $Commandline `n"
		Throw "Deprecated parameter"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function VersionInt($verString){
	EnterFunc $MyInvocation.MyCommand.Name
	$verSplit = $verString.Split([char]0x0a, [char]0x0d, '.')
	$vFull = 0; $i = 0; $vNum = 256 * 256 * 256
	while ($vNum -gt 0) { $vFull += [int] $verSplit[$i] * $vNum; $vNum = $vNum / 256; $i++ };
	EndFunc ($MyInvocation.MyCommand.Name + "($vFull)")
	return $vFull
}
Function CheckVersion ($verCurrent){	
  if (( -Not $noVersionChk.IsPresent) -or ($global:ParameterArray -notcontains 'noVersionChk')){
	# automated version checking. When launched, the script will warn if a newer version is available online and recommend to download it. 
	# Internet access is required and the repository to be reachable, for the version check to be successful. It will not automatically download the new version; this will be up to the user to do.
	EnterFunc $MyInvocation.MyCommand.Name
	#$TssReleaseServer = "cesdiagtools.blob.core.windows.net"
	Try{
		$checkConn = FwTestConnWebSite $Script:TssReleaseServer # FwTestConnWebSite could throw an exception
	}Catch{
		$checkConn = $False
	}
	if ( $checkConn -eq "True") {
		try
			{
				$WebClient = New-Object System.Net.WebClient
				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
				$verNew = $WebClient.DownloadString('https://cesdiagtools.blob.core.windows.net/windows/TSS.ver')
				$verNew = $verNew.TrimEnd([char]0x0a, [char]0x0d)
				[long] $lNew = VersionInt($verNew)
				[long] $lCur = VersionInt($verCurrent)
				if($lNew -gt $lCur) {
					Write-Host -ForegroundColor Magenta ("A newer version is available: v" + $verNew + " (you are currently on v"+$verCurrent+"). `n For best results, download and use the latest version from https://aka.ms/getTSS or https://aka.ms/getTSSlite")
					$Script:fUpToDate = $False
					$Script:TssVerOnline = $lNew 
				}
				else {
					LogInfo  ("You are running the latest version (v"+$verCurrent+")") "Green"
					$Script:fUpToDate = $True
				}
			}
		catch
			{
				LogInfo ("Unable to check TSS script version online... (local version: v"+$verCurrent+")" + $_) "Magenta" -noDate
				LogInfo "For best results, always use the latest version from https://aka.ms/getTSS" "Cyan" -noDate
			}
	}Else{
		LogInfo ("Unable to contact MS tools store: $Script:TssReleaseServer (local version: v" +$verCurrent+ ")") "Magenta" -noDate
		LogInfo "For best results, always use the latest version from https://aka.ms/getTSS" "Cyan" -noDate
	}
	EndFunc $MyInvocation.MyCommand.Name
  }else{ LogInfoFile "skipping online version check (-noVersionChk)" -ShowMsg}
}

Function CreateStartCommandforBatch{
	# currently not used
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[PSObject]]$TraceObjectList
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If($Null -eq $TraceObjectList){
		LogError"There is no trace in LogCollector."
		retrun
	}

	If($StartAutoLogger.IsPresent){
		$BatFileName = $StartAutoLoggerBatFileName
	}

	Try{
		$BatchFolder = Split-Path $BatFileName -Parent
		FwCreateLogFolder $BatchFolder
	}Catch{
		LogException("Unable to create $BatchFolder") $_
		CleanUpandExit
	}

	If(!$StartAutoLogger.IsPresent){
		If($LogFolderPath -eq ""){
			$LogFolder = $LogFolder -replace ".*\Desktop","%USERPROFILE%\Desktop"
		}
		Write-Output("MD $LogFolder") | Out-File $BatFileName -Encoding ascii -Append
	}Else{
		Write-Output("MD $AutoLoggerLogFolder") | Out-File $BatFileName -Encoding ascii -Append
	}

	ForEach($TraceObject in $TraceObjectList){
		Switch($TraceObject.LogType){
			'ETW' {
				If($StartAutoLogger.IsPresent){
					$TraceName = $TraceObject.AutoLogger.AutoLoggerSessionName
				}Else{	
					$TraceName = $TraceObject.TraceName
				}
				$LogFileName = $TraceObject.LogFileName -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."

				If($LogFolderPath -eq ""){
					$LogFileName = $LogFileName -replace ".*\Desktop","`"%USERPROFILE%\Desktop"
				}

				$Commandline = "Logman.exe create trace $TraceName -ow -o $LogFileName -mode Circular -bs 64 -f bincirc -max $Script:ETLMaxSize -ft 60 -ets"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
				
				ForEach($Provider in $TraceObject.Providers){
					$Commandline = "Logman.exe update trace $TraceName -p $Provider 0xffffffffffffffff 0xff -ets"
					LogInfo ("Adding `'$CommandLine`' to $BatFileName")
					Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
				}

				If($StartAutoLogger.IsPresent -and $Null -ne $TraceObject.AutoLogger){
					$Commandline = "Logman.exe update trace $TraceName -o $($TraceObject.AutoLogger.AutoLoggerLogFileName)"
					LogInfo ("Adding `'$CommandLine`' to $BatFileName")
					Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append

					$AutoLoggerKey = $TraceObject.AutoLogger.AutoLoggerKey -replace ":",""  # Convert "HKLM:" => "HKLM\"
					$Commandline = "REG ADD $AutoLoggerKey /V FileMax /T REG_DWORD /D $Script:ETLFileMax /F"
					LogInfo ("Adding `'$CommandLine`' to $BatFileName")
					Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
				}
			}
			'Perf' {
				ForEach($PerfCounter in $TraceObject.Providers){
					$AllCounters += "`"" + $PerfCounter + "`""  + " "
				}
				$LogFileName = $TraceObject.LogFileName -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."

				If($LogFolderPath -eq ""){
					$LogFileName = $LogFileName -replace ".*\Desktop","%USERPROFILE%\Desktop"
				}

				If($global:ParameterArray -contains 'PerfmonLong'){
					$PerflogInterval = $PerflogLongInterval
				}

				If($PerfMonCNF) {$PerfCNF = "-cnf $PerfMonCNF"}else{$PerfCNF = "-f bincirc"}
				$Commandline = "Logman.exe create counter " + $TraceObject.Name + " -o `"" + $LogFileName + "`" -si $PerflogInterval -c $AllCounters -max $PerfMonMaxMB $PerfCNF"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append

				$Commandline = "Logman.exe start $($TraceObject.Name)"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
			}
			'Command' {
				If(!$StartAutoLogger.IsPresent){
					$StartOptionWithoutSuffix = $($TraceObject.Startoption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."
				}Else{
					$StartOptionWithoutSuffix = $($TraceObject.AutoLogger.AutoLoggerStartOption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."
				}
				$CommandLine = "Start $($TraceObject.CommandName) $StartOptionWithoutSuffix"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
			}
			Default {
				LogWarn ("-CreateBatFile does not support command for $($TraceObject.TraceName)")
				Continue
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CreateStopCommandforBatch{
	# currently not used
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[PSObject]]$TraceObjectList
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If($StartAutoLogger.IsPresent){
		$BatFileName = $StopAutoLoggerBatFileName
	}Else{
		LogInfo ("Adding `'Pause`' to $BatFileName")
		Write-Output("") | Out-File $BatFileName -Encoding ascii -Append
		Write-Output("Pause") | Out-File $BatFileName -Encoding ascii -Append
		Write-Output("") | Out-File $BatFileName -Encoding ascii -Append
	}

	ForEach($TraceObject in $TraceObjectList){
		Switch($TraceObject.LogType){
			'ETW' {
				$CommandLine = "Logman.exe stop $($TraceObject.TraceName) -ets"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append

				If($StartAutoLogger.IsPresent){
					$CommandLine = "Logman.exe delete $($TraceObject.AutoLogger.AutoLoggerSessionName)"
					LogInfo ("Adding `'$CommandLine`' to $BatFileName")
					Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
				}
			}
			'Perf' {
				$CommandLine = "Logman.exe stop $($TraceObject.Name) & Logman.exe delete $($TraceObject.Name)"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
			}
			'Command' {
				If(!$StartAutoLogger.IsPresent){
					$StopOptionWithoutSuffix = $($TraceObject.StopOption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."

				}Else{
					$StopOptionWithoutSuffix = $($TraceObject.AutoLogger.AutoLoggerStopOption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."
				}
				$CommandLine = "$($TraceObject.CommandName) $StopOptionWithoutSuffix"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
			}
			Default {
				LogWarn ("-CreateBatFile does not support command for $($TraceObject.TraceName)")
				Continue
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpCrashProperty{
	EnterFunc $MyInvocation.MyCommand.Name
	if (!$global:IsLiteMode -and ($OSBuild -ge 9200)){
		$CrashMode = $global:BoundParameters['CrashMode']
		If($CrashMode -match "active|automatic|full|kernel|mini"){
			if (Test-Path $kdbgctrlPath) {
				LogInfo "[$($MyInvocation.MyCommand.Name)] running 'kdbgctrl.exe -sd $CrashMode' command"
				LogInfo "[$($MyInvocation.MyCommand.Name)] preparing system for '$CrashMode' memory dump."
				$outFile = $PrefixTime + "Set_DumpType.txt"
				$Commands = @("$kdbgctrlPath -sd $CrashMode | Out-File -Append $outFile")
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpNetshProperty{
	EnterFunc $MyInvocation.MyCommand.Name
		
	# Issue#321
	# Adjust parameter in case of Server Core
	If($global:IsServerCore){
		LogInfo "TSS is running on Server Core and adjusting netsh parameters"
		# SrvCORE does not work with trace scenario=InternetClient_dbg etc. Hence, replace original scenario name with 'InternetServer'
		If($global:BoundParameters.ContainsKey('NetshScenario')){
			$ScenarioNames = $global:BoundParameters['NetshScenario']
			$global:BoundParameters.Remove('NetshScenario') | Out-Null
			$global:BoundParameters.Add('NetshScenario','InternetServer')
		}
		
		# Remove provider
		If($global:BoundParameters.ContainsKey('NetshOptions')){
			$NetshOptions = $global:BoundParameters['NetshOptions']
			[System.Collections.ArrayList]$Token = $NetshOptions -split ' '
			While($Token -match "provider=*"){
				For($i=0;$i -lt $Token.Count;$i++){
					If($Token[$i] -like "provider=*"){
						$Token.Remove($Token[$i]) # Remove entry for 'Provider=XXX'
						Break
					}
				}
			}
			$AdjustedNetshOptions = $Token -join ' '
			$global:BoundParameters.Remove('NetshOptions') | Out-Null
			$global:BoundParameters.Add('NetshOptions',$AdjustedNetshOptions)
		}
	}

	# Initialize max log size for netsh with default value(2GB)
	$NetshMaxSizeMB = 2048

	# Update max log size fo Netsh if NetshMaxSizeMB is configured.
	If($global:BoundParameters.containskey('NetshMaxSizeMB')){
		$NetshMaxSizeMB = $global:BoundParameters['NetshMaxSizeMB']
	}Else{
		# See if max size is configured from tss_config.cfg
		$MaxSizeFromConfig = $FwConfigParameters['_NetshMaxSizeMB']
		If(![string]::IsNullOrEmpty($MaxSizeFromConfig)){
			LogDebug "Use NetshMaxSizeMB($MaxSizeFromConfig) configured in tss_config.cfg"
			$NetshMaxSizeMB = $MaxSizeFromConfig
		}
	}

	# Update $LogSizeInGB that is used in CalculateLogSize() later.
	LogDebug "NetshMaxSizeMB=$NetshMaxSizeMB MB"
	$LogSizeInGB.Netsh = $NetshMaxSizeMB / 1024
	$LogSizeInGB.NetshScenario = ($NetshMaxSizeMB / 1024) + 1	#we# was '+ 4' -but, Why +4?

	# Compose a log file name for netsh and add it to 'traceFile='
	If($global:BoundParameters.containskey('NetshScenario')){
		$NetshScenarioArray = $global:BoundParameters['NetshScenario']
		# dbg/wpp scenarios:
		$SupportedNetshScenarios = Get-ChildItem 'HKLM:System\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs\WPPTrace\HelperClasses'
		# normal scenarios: #we# [waltere] added
		$SupportedNetshScenarios += Get-ChildItem 'HKLM:System\CurrentControlSet\Control\NetTrace\Scenarios'
		#$RequestedScenarios = $NetshScenario -Split ','
		$i=0
		ForEach($RequestedScenario in $NetshScenarioArray){
			$fFound=$False
			ForEach($SupportedNetshScenario in $SupportedNetshScenarios){
				If($RequestedScenario.ToLower() -eq $SupportedNetshScenario.PSChildName.ToLower()){
					$fFound=$True
					If($i -eq 0){
						$SenarioString = $SupportedNetshScenario.PSChildName
					}Else{
						$SenarioString = $SenarioString + ',' + $SupportedNetshScenario.PSChildName
					}
				}
			}
			If(!$fFound){
				LogInfo "ERROR: Unable to find scenario `"$RequestedScenario`" for -NetshScenario. Supported scenarios for -NetshScenario are:" "Red"
				ForEach($SupportedNetshScenario in $SupportedNetshScenarios){
					Write-Host ("  - " + $SupportedNetshScenario.PSChildName)
				}
				CleanUpandExit
			}
			$i++
		}

		If(!$Status) {LogInfoFile "Scenario string for NetshScenario is $SenarioString" -ShowMsg}
		$SenarioStringForLog = $SenarioString.Replace(",","-")
		$NetshScenarioLogFile = "$global:LogFolder\$($LogPrefix)packetcapture-$SenarioStringForLog.etl" #we#[waltere] changed NetSH names for LogRaker
		$NetshProperty.LogFileName = $NetshScenarioLogFile
		$NetshProperty.AutoLogger.AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\$($LogPrefix)packetcapture-$SenarioStringForLog-AutoLogger.etl`""

		# Update secenario and log file name
		$NetshProperty.StartOption = $NetshProperty.StartOption + " scenario=$SenarioString traceFile=$($NetshProperty.LogFileName)"
		$NetshProperty.AutoLogger.AutoLoggerStartOption = $NetshProperty.AutoLogger.AutoLoggerStartOption + " scenario=$SenarioString traceFile=$($NetshProperty.AutoLogger.AutoLoggerLogFileName)"
	}Else{ # Non scenario trace case
		# Issue#362
		$NetshProperty.StartOption = $NetshProperty.StartOption + " traceFile=$($NetshProperty.LogFileName)"
		$NetshProperty.AutoLogger.AutoLoggerStartOption = $NetshProperty.AutoLogger.AutoLoggerStartOption + " traceFile=$($NetshProperty.AutoLogger.AutoLoggerLogFileName)"
	}

	# capture=yes/no
	If($global:BoundParameters.containskey('noPacket')){
		$Capture="capture=no"
	}Else{
		$Capture="capture=yes"
	}

	# Add capture=yes/no, report=yes/no and max log size
	$NetshProperty.StartOption = $NetshProperty.StartOption + " $Capture $Script:NetshTraceReport maxSize=$NetshMaxSizeMB"
	$NetshProperty.AutoLogger.AutoLoggerStartOption = $NetshProperty.AutoLogger.AutoLoggerStartOption + " $Capture $Script:NetshTraceReport maxSize=$NetshMaxSizeMB"

	# Add NetshOptions if it is configured
	$NetshOptions = $global:BoundParameters['NetshOptions']
	If(![string]::IsNullOrEmpty($NetshOptions)){
		# Issue#321 - Adjust netsh parameter for Windows Server 2012 or earlier
		If($OSBuild -le 9200){
			[System.Collections.ArrayList]$Token = $NetshOptions -split ' '
			For($i=0;$i -lt $Token.Count;$i++){
				If($Token[$i] -like "capturetype=*"){
					$Token.Remove($Token[$i]) # Remove entry for 'capturetype=XXX'
				}
			}
			$NetshOptions = $Token -join ' '
			$global:BoundParameters.Remove('NetshOptions') | Out-Null
			$global:BoundParameters.Add('NetshOptions',$NetshOptions)
			LogDebug "OSBuild=$OSBuild, NetshOptions=$NetshOptions"
		}
		$NetshProperty.StartOption = $NetshProperty.StartOption + " " + $NetshOptions
		$NetshProperty.AutoLogger.AutoLoggerStartOption = $NetshProperty.AutoLogger.AutoLoggerStartOption + " " + $NetshOptions
	}
	LogDebug "Netsh option = $($NetshProperty.StartOption)"
	LogDebug "Netsh AutoLogger option = $($NetshProperty.AutoLogger.AutoLoggerStartOption)"
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpWPRProperty{
	EnterFunc $MyInvocation.MyCommand.Name
	If($OSBuild -lt 17763){ #we# OS -ge 17763 (RS5) has built in WPR. -skipPdbGen is supported with OS -ge 19041 (2004+); \BIN\wpr.exe is supported with OS -ge 9600 (2012-R2)
		$WPRProperty.CommandName = "$PSScriptRoot\BIN\wpr.exe"
		If(!(Test-path -path $WPRProperty.CommandName)){
			LogError "$($WPRProperty.CommandName) not found. Exiting script."
			CleanUpAndExit
		}
	}

	$WPR = $global:BoundParameters['WPR']
	$WPROptions = $global:BoundParameters['WPROptions']
	$WPRLogFile = "$global:LogFolder\$($LogPrefix)WPR_$WPR.etl"
	$WPRProperty.LogFileName = "`"$WPRLogFile`""

	LogDebug "Updating WPR option with `'$WPR`' profile"
	Switch($WPR) {
		'BootGeneral' {
			$WPRProperty.StartOption = "-start GeneralProfile -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -filemode -recordTempTo $global:LogFolder"
		}
		'general' {
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start DiskIO -start FileIO -start Handle -Start Minifilter -start Network -Start Registry -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot DiskIO -addboot FileIO -addboot Minifilter -addboot Registry -addboot Network -filemode -recordTempTo $global:LogFolder"
		}
		'graphic' {
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -Start Registry -start Video -start GPU -Start DesktopComposition -start Power -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot Registry -addboot Video -addboot GPU -addboot DesktopComposition -addboot Power -filemode -recordTempTo $global:LogFolder"
		}
		'xaml' {
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start XAMLActivity -start XAMLAppResponsiveness -Start DesktopComposition -start Video -start GPU -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot XAMLActivity -addboot XAMLAppResponsiveness -addboot DesktopComposition -addboot Video -addboot GPU -filemode -recordTempTo $global:LogFolder"
		}
		'CPU' {
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -filemode -recordTempTo $global:LogFolder"
		}
		'memory' { 
			$WPRProperty.StartOption = "-start GeneralProfile -start VirtualAllocation -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot VirtualAllocation -filemode -recordTempTo $global:LogFolder"
		}
		'Registry' { 
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start Registry -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot Registry -filemode -recordTempTo $global:LogFolder"
		}
		'Storage' { 
			$WPRProperty.StartOption = "-start GeneralProfile  -start CPU -start DiskIO -start FileIO -start Minifilter -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot DiskIO -addboot FileIO -addboot Minifilter -filemode -recordTempTo $global:LogFolder"
		}
		'Wait' { 
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start DiskIO -start FileIO -start Network -start Minifilter -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot DiskIO -addboot FileIO -addboot Network -addboot Minifilter -filemode -recordTempTo $global:LogFolder"
		}
		'Network' { 
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start DiskIO -start FileIO -start Network -start Minifilter -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot DiskIO -addboot FileIO -addboot Network -addboot Minifilter -filemode -recordTempTo $global:LogFolder"
		}
		'SQL' { 
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start VirtualAllocation -start Network -start Minifilter -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot VirtualAllocation -addboot Network -addboot Minifilter -filemode -recordTempTo $global:LogFolder"
		}
		'Device' {
			$WPRProperty.StartOption = "-start CPU -start FileIO -Start Registry -start Power -start Minifilter -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot CPU -addboot FileIO -addboot Registry -addboot Power -addboot Minifilter -filemode -recordTempTo $global:LogFolder"
		}
		'VSOD_CPU' {
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start DiskIO -start FileIO -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot DiskIO -addboot FileIO -filemode -recordTempTo $global:LogFolder"
		}
		'VSOD_Leak' {
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start Heap -start VirtualAllocation -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot Heap -addboot VirtualAllocation -filemode -recordTempTo $global:LogFolder"
		}
		Default {
			ProcessListSupportedWPRScenario
			CleanUpandExit
		}
	}

	# If WPROptions is available, Just append option in $WPROptions to the tail end.
	If(![string]::IsNullOrEmpty($WPROptions)){ # Option from commmand line
		$WPRProperty.StartOption = $WPRProperty.StartOption + " " + $WPROptions
		$WPRProperty.AutoLogger.AutoLoggerStartOption = $WPRProperty.AutoLogger.AutoLoggerStartOption + " " + $WPROptions
	}

	If($global:ParameterArray -contains 'SkipPdbGen'){
		If($OSBuild -ge 19041){ # SkipPdbGen supports from Win10 2004
			$WPRProperty.StopOption = "-stop `"$WPRLogFile`" -skipPdbGen"
		}Else{
			LogInfo "-SkipPdbGen was specified but current OS does not support the option."
		}
	}Else{
		$WPRProperty.StopOption = "-stop `"$WPRLogFile`""
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpXperfProperty{
	EnterFunc $MyInvocation.MyCommand.Name

	# Load parameters
	$Xperf = $global:BoundParameters['Xperf']
	$XperfMaxFileMB = $global:BoundParameters['XperfMaxFileMB']
	$XperfTag = $global:BoundParameters['XperfTag']
	$XperfPIDs = $global:BoundParameters['XperfPIDs']
	$XperfOptions = $global:BoundParameters['XperfOptions']

	# AutoLogger for SMB2, SBSL and Leak is not supported at this point.
	If($StartAutoLogger.IsPresent -and ($Xperf -eq 'SMB2' -or $Xperf -eq 'SBSL' -or $Xperf -eq 'Leak')){
		LogError "AutoLogger for `'$Xperf`' is not supported."
		CleanUpandExit
	}

	# Set DisablePagingExecutive.
	$RegValues = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -ErrorAction Ignore
	If($RegValues.DisablePagingExecutive -ne 1){
		$Command = "REG ADD `"HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management`" -v DisablePagingExecutive -d 0x1 -t REG_DWORD -f"
		Runcommands "Xperf" $Command
	}

	# Add a profile name to log file name.
	$XperfLogFile = "$global:LogFolder\$($LogPrefix)Xperf_$Xperf.etl"
	$XperfProperty.LogFileName = $XperfLogFile

	LogDebug "Updating Xperf option with `'$Xperf`' profile"
	If([String]::IsNullOrEmpty($XperfMaxFileMB) -or $XperfMaxFileMB -eq 0){
		$XperfMaxFileMB = 2048
		If($Xperf -match "SBSL") {$XperfMaxFileMB = 16384} # issue #649
	}
	
	$XperfParams = "-BufferSize 1024 -MinBuffers 256 -MaxBuffers 1024 -MaxFile $XperfMaxFileMB -FileMode Circular -f $global:LogFolder\xperf.etl"

	# Set stop option
	$XperfProperty.StopOption = "-stop -d $($XperfProperty.LogFileName)"

	# Start option and stop option for SMB2, SBSL and Leak
	Switch($Xperf) {
		'CPU'	 {$XperfProperty.StartOption = "-on PROC_THREAD+Latency+LOADER+Profile+interrupt+dpc+DISPATCHER+CSwitch+Power -stackWalk CSwitch+Profile+ReadyThread $XperfParams"}
		'General' {$XperfProperty.StartOption = "-on Base+Latency+CSwitch+PROC_THREAD+LOADER+Profile+interrupt+dpc+DISPATCHER+NETWORKTRACE+FileIO+Power+DISK_IO+DISK_IO_INIT+filename+FILE_IO+FILE_IO_INIT+flt_io_init+flt_io+flt_fastio+flt_io_failure+VIRT_ALLOC+POOL+REGISTRY+DRIVERS -stackWalk CSwitch+Profile+ReadyThread+ThreadCreate+SyscallEnter+DiskReadInit+DiskWriteInit+DiskFlushInit+FileRead+FileWrite+FileCreate+FileDelete+minifilterpreopinit+minifilterpostopinit+PoolAlloc+PoolAllocSession+PoolFree+PoolFreeSession+VirtualAlloc+VirtualFree $XperfParams"}
		'Disk'	{$XperfProperty.StartOption = "-on PROC_THREAD+LOADER+Profile+interrupt+dpc+DISK_IO+DISK_IO_INIT+filename+FILE_IO+FILE_IO_INIT+flt_io_init+flt_io+flt_fastio+flt_io_failure -stackwalk profile+DiskReadInit+DiskWriteInit+DiskFlushInit+FileRead+FileWrite+FileCreate+FileDelete+minifilterpreopinit+minifilterpostopinit $XperfParams"}
		'Memory'  {$XperfProperty.StartOption = "-on Base+CSwitch+POOL -stackwalk Profile+PoolAlloc+PoolAllocSession+PoolFree+PoolFreeSession+VirtualAlloc $XperfParams"}
		'Network' {$XperfProperty.StartOption = "-on Base+Latency+DISPATCHER+NETWORKTRACE+FileIO+DRIVERS -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile+SyscallEnter $XperfParams"}
		'Pool'	{$XperfProperty.StartOption = "-on Base+CSwitch+VIRT_ALLOC+POOL -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession+VirtualAlloc -PoolTag $XperfTag $XperfParams"}
		'PoolNPP' {$XperfProperty.StartOption = "-on Base+CSwitch+LOADER+VIRT_ALLOC+POOL+PROC_THREAD -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession+VirtualAlloc -PoolTag $XperfTag $XperfParams"}
		'Registry'{$XperfProperty.StartOption = "-on Base+REGISTRY+PROC_THREAD+NETWORKTRACE -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile+SyscallEnter $XperfParams"}
		'SMB2'	{
			$XperfProperty.StartOption = "-on Base+Latency+DISPATCHER+NETWORKTRACE+FILE_IO+FILE_IO_INIT+DRIVERS $XperfParams -stackwalk Profile+CSwitch+ReadyThread -start SMB2 -on d3bce2d2-92c9-44c7-befe-a27a96d413e9:::'stack'"
			$XperfProperty.StopOption = "-stop -stop SMB2 -d $($XperfProperty.LogFileName)"
		}
		'SBSL'	{
			$XperfProperty.StartOption = "-on Base+Latency+DISPATCHER+REGISTRY+NETWORKTRACE+FileIO -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile -BufferSize 1024 -start UserTrace -on `"Microsoft-Windows-Shell-Core+Microsoft-Windows-Wininit+Microsoft-Windows-Folder Redirection+Microsoft-Windows-User Profiles Service+Microsoft-Windows-GroupPolicy+Microsoft-Windows-Winlogon+Microsoft-Windows-Security-Kerberos+Microsoft-Windows-User Profiles General+e5ba83f6-07d0-46b1-8bc7-7e669a1d31dc+63b530f8-29c9-4880-a5b4-b8179096e7b8+2f07e2ee-15db-40f1-90ef-9d7ba282188a`" $XperfParams"
			$XperfProperty.StopOption = "-stop -stop UserTrace -d $($XperfProperty.LogFileName)"
		}
		'SBSLboot'{$XperfProperty.StartOption = "-on Base+Latency+DISPATCHER+REGISTRY+NETWORKTRACE+FileIO -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile $XperfParams"}
		'Leak'	{
			$XperfProperty.StartOption = "-on PROC_THREAD+LOADER+VIRT_ALLOC -stackwalk VirtualAlloc+VirtualFree $XperfParams -start HeapSession -heap -pids $XperfPIDs -stackwalk HeapAlloc+HeapRealloc"
			$XperfProperty.StopOption = "-stop -stop HeapSession -d $($XperfProperty.LogFileName)"
		}
		Default {
			LogError "Unknown option $Xperf was specified."
			CleanUpandExit
		}
	}

	# Start option for AutoLogger
	$XperfProperty.AutoLogger.AutoLoggerStartOption = $XperfProperty.StartOption -replace "^-on","-BootTrace"

	# If XperfOptions is available, Just append option in XperfOptions to the tail end.
	If(![string]::IsNullOrEmpty($XperfOptions)){ # Option from commmand line
		$XperfProperty.StartOption = $XpefProperty.StartOption + " " + $XperfOptions
		$XperfProperty.AutoLogger.AutoLoggerStartOption = $XpefProperty.AutoLogger.AutoLoggerStartOption + " " + $XperfOptions
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpProcmonProperty{
	EnterFunc $MyInvocation.MyCommand.Name
	# Respect passed $ProcmonPath. It it is null, use default procmon path.
	$ProcmonCmdPath = $global:BoundParameters['ProcmonPath']
	If(![String]::IsNullOrEmpty($ProcmonCmdPath)){
		If(Test-Path "$ProcmonCmdPath\procmon.exe"){
			$ProcmonProperty.CommandName = "$ProcmonCmdPath\procmon.exe"
		}Else{
			LogError "Invalid ProcmonPath `'$ProcmonPath`' was passed."
			CleanUpandExit
		}
	}
	$ProcmonCommand = Get-Command $ProcmonProperty.CommandName -ErrorAction Ignore
	If($Null -eq $ProcmonCommand){
		LogErrorFile "Procmon.exe not found."  # Procmon will be removed from LogCollector later. So just log it to log file.
		Return
	}
	if(IsStart){
		# Check the version of Procmon.exe and add some switches accordingly.
		$ProcmonVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ProcmonCommand.Path).FileVersion
		LogDebug "Using $($ProcmonProperty.CommandName) with version $ProcmonVersion"
		If($Null -ne $ProcmonVersion -and $ProcmonVersion -gt 3.9){
			If(!([string]::IsNullOrEmpty($global:ProcmonRingBufferSize))){
				$RingBufferSize = $global:ProcmonRingBufferSize
			}Else{
				$RingBufferSize = 3096
			}
			$ProcmonProperty.StartOption = "/AcceptEula /RingBuffer /RingBufferSize $RingBufferSize /quiet /backingfile `"$ProcmonLogFile`""
			LogDebug "Procmon command line with buffer size: $($ProcmonProperty.StartOption)"
			$FlightRecorderMode = $True
			
			#is -ProcmonAltitude specified? 
			If($global:BoundParameters['ProcmonAltitude']){
				LogInfoFile " Will use specified ProcmonAltitude: $ProcmonAltitude "
				if(IsDefaultProcmonAltitude) {CleanupAndExit}
			}Else{
				$ProcmonAltitude = 385200	#default Procmon  alt.
			}
			$ProcmonProperty.StartOption = "/AcceptEula /RingBuffer /RingBufferSize $RingBufferSize /quiet /backingfile `"$ProcmonLogFile`" /Altitude $ProcmonAltitude"
			LogDebug "Procmon command line with Altitude: $($ProcmonProperty.StartOption)"
		}

		# See if Procmon filter specfied by -ProcmonFilter exists.
		$ProcmonFilter = $global:BoundParameters['ProcmonFilter']
		If(![String]::IsNullOrEmpty($ProcmonFilter)){
			# Case for $ProcmonFilter has an absolute path.
			If(!(Test-Path -Path $ProcmonFilter)){
				# If not found, this might be relative path. So search recursively from current directory($ScriptFolder).
				LogDebug "Searching for $ProcmonFilter."
				$ProcmonFilterFile = Get-ChildItem -File $ProcmonFilter -Recurse -ErrorAction Ignore
				If($Null -eq $ProcmonFilterFile){
					LogError "-ProcmonFilter is specified but the file `'$ProcmonFilter`' does not exist."
					CleanUpandExit
				}Else{
					# In case that Get-ChildItem found the filter file, the specified path in $ProcmonFilterFile might be different from actual file path. Hence update the $ProcmonFilter.
					$ProcmonFilter = $ProcmonFilterFile.FullName
					# copy ProcmonFilter to LogFolder
					Copy-Item -Path $ProcmonFilter -Destination $global:LogFolder 2>&1 | Out-Null
				}
			}
			LogInfoFile " Will use $ProcmonFilter for Procmon filter." -ShowMsg
			# Add filter to command line.
			If(Test-Path -Path $ProcmonFilter){
				$ProcmonProperty.StartOption = $ProcmonProperty.StartOption + " /LoadConfig `"$ProcmonFilter`""
				LogDebug "Procmon command line with filter: $($ProcmonProperty.StartOption)"
				If($FlightRecorderMode){
					LogInfoFile "Procmon filter is specified with flight recorder mode. In this case, flight recorder mode might be disabled." "Gray" -ShowMsg
				}
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpPerfMonProperty{
	Param(
		[String]$Type
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If(!$PerfMonMaxMB) {$Script:PerfMonMaxMB = 2048}
	If($Type -eq 'PerfMon'){
		$PerfProfile = $global:BoundParameters['PerfMon']
		If($global:BoundParameters.containskey('PerfIntervalSec')){
			$Script:PerfMonInterval = $global:BoundParameters['PerfIntervalSec']
		}
		$PerfMonProperty.TraceName = "PerfMon($PerfProfile) log"
		$PerfMonProperty.LogFileName = "$global:LogFolder\$($LogPrefix)PerfMon_$($PerfProfile)_$($Script:PerfMonInterval)sec_$($PerfMonMaxMB)MB.blg"
	}
	If($Type -eq 'PerfMonLong'){
		$PerfProfile = $global:BoundParameters['PerfMonLong']
		If($global:BoundParameters.containskey('PerfLongIntervalMin')){
			$Script:PerfMonLongInterval = ([Int]$global:BoundParameters['PerfLongIntervalMin'] * 60)
		}
		$PerfMonLongProperty.TraceName = "PerfMonLong($PerfProfile) log"
		$PerfMonLongProperty.LogFileName = "$global:LogFolder\$($LogPrefix)PerfMonLong_$($PerfProfile)_$($Script:PerfMonLongInterval)sec_$($PerfMonMaxMB)MB.blg"
	}
	$PerfCounterName = $PerfProfile + 'Counters'
	Try{
		$PerfCounters = Get-Variable -Name $PerfCounterName -ValueOnly -ErrorAction Stop
	}Catch{
		LogError "Invalid PerfMon counter name `'$PerfProfile`' was passed."
		LogInfo ("=> Please check supported counter name by running `'.\$($global:ScriptName) -ListSupportedPerfCounter`'") "Magenta"
		CleanUpandExit
	}
	$ConvertedCounterSet = ConvertToLocalPerfCounterName $PerfCounters
	If($ConvertedCounterSet.Count -gt 0){
		If($Type -eq 'PerfMon'){
			$PerfMonProperty.Providers = $ConvertedCounterSet
		}ElseIf($Type -eq 'PerfMonLong'){
			$PerfmonLongProperty.Providers = $ConvertedCounterSet
		}
	}Else{
		LogError "Failed to convert English counter name to local counter name."
		LogInfo " ..Collecting registry hives for troubleshooting this PerfMon issue"
		FwGetRegHives _Stop_
		LogInfo "=> Please check $global:ErrorLogFile" "Magenta"
		LogInfo "`nTo avoid this error, run TSS again with appended switch -noPerfmon" "Cyan"
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpFiddlerProperty{
	EnterFunc $MyInvocation.MyCommand.Name
	
	# Search fiddler path
	$FiddlerPaths = @("C:\Program Files\Fiddler", "C:\Program Files (x86)\Fiddler", "$env:userprofile\AppData\Local\Programs\Fiddler")
	ForEach($FiddlerPath in $FiddlerPaths){
		$IsFound = $False
		$FiddlerCommand = Join-Path $FiddlerPath 'ExecAction.exe'
		$Command = Get-Command $FiddlerCommand -ErrorAction Ignore
		If($Null -eq $Command){
			Continue
		}Else{
			$IsFound = $True
			Add-path $FiddlerPath
			$FiddlerProperty.CommandName = $FiddlerCommand
			break
		}
	}

	If(!$IsFound){
		LogError "Fiddler not found in below folders. Please download it from `'https://www.telerik.com/download/fiddler`' and install to one of below folders."
		ForEach($FiddlerPath in $FiddlerPaths){
			LogInfo "  - $FiddlerPath"
		}
		CleanUpAndExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ExportGUItoCsv{
	# will write a .csv file with headers: Key,Description; this is neeed for TSS-GUI
	# expects two parameters: GUIcsvFileName and CsvArray
	#  Ex: ExportGUItoCsv GUIcsvFileName CsvArray
	Param(
		[Parameter(Mandatory=$True)]
		$GUIcsvFileName,
		$CsvArray
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($ExportGUIcsv){
		# create dest folder 'TSSGUI' if it doesn't exist
		if(-not (Test-Path "$Scriptfolder\TSSGUI")){
			FwCreateFolder $Scriptfolder\TSSGUI
		}
		# user wants to export Key,Description into .csv file
		$outFile=$Scriptfolder +"\TSSGUI\" + $GUIcsvFileName +".csv"
		Write-Debug "____outFile= $outFile"
		$CsvArray | Select-Object Key,Description |Sort-Object Key |Export-Csv -Path $outFile -NoTypeInformation -Delimiter "$csvDelimiter" -Force -ErrorAction SilentlyContinue
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")

	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation # This creates GlobalTraceCatalog
		}Catch{
			LogException "[ProcessStart] An exception happened in RunPreparation" $_
			CleanUpandExit
		}
	}

	# At first we check if there are already running traces started by this script.
	$RunningTraces = $Null
	$RunningTraces = GetExistingTraceSession
	If($RunningTraces){
		LogWarn "Detected below existing trace(s)."
		ForEach($TraceObject in $RunningTraces){
			LogInfo "  - $($TraceObject.TraceName)" "Gray" -noDate
		}
		Write-Host ' '
		LogInfo "ERROR: Please stop above existing trace(s) with below command and then run again given TSS command-line." "Red"
		LogInfo "=> .\$($global:ScriptName) -Stop -noBasiclog -noXray" "Yellow"
		LogInfo "[Action] just in case this step did not help, please zip and upload the logfiles from $global:LogRoot folder. We will come back to you soon after analyzing the uploaded log files." "Cyan"
		CleanUpandExit
	}

	# Checking trace and command switches and add them to LogCollector.
	ForEach($RequestedTraceName in $global:BoundParameters.Keys){
		If($ControlSwitches -Contains $RequestedTraceName){  # additional params, like EtlOptions should be added to $ControlSwitches
			Continue # This is not switch for trace.
		}

		If($RequestedTraceName -eq 'NetshScenario'){
			$RequestedTraceName = 'Netsh' # NetshScenario uses Netsh object. So replace the name.
		}
		If($StartAutoLogger.IsPresent){
			# Only AutoLogger supported traces are added to LogCollector
			If($RequestedTraceName.Contains('Scenario')){
				$TraceName = ConvertScenarioTraceNametoTraceName $RequestedTraceName
				If($Null -ne $TraceName){
					$AutoLoggerTraceObject = $GlobalTraceCatalog | Where-Object{($Null -ne $_.AutoLogger) -and ($TraceName -eq $_.Name)}
					If($Null -ne $AutoLoggerTraceObject){
						AddTraceToLogCollector $RequestedTraceName
					}
				}Else{
					LogError "Unable to convert to a trace from `'$RequestedTraceName`'"
					CleanUpandExit
				}
			}Else{ # Normal Trace
				$AutoLoggerTraceObject =  $GlobalTraceCatalog | Where-Object{$Null -ne $_.AutoLogger -and ($RequestedTraceName -eq $_.Name)}
				If($Null -ne $AutoLoggerTraceObject){ # This trace has AutoLogger
					AddTraceToLogCollector $RequestedTraceName
				}Else{
					LogDebug "Skipping adding $RequestedTraceName to LogCollector"
				}
			}
		}Else{
			# If not AutoLogger, just add all traces which are specified in option.
			AddTraceToLogCollector $RequestedTraceName
		}
	}

	# Change execution order based on 'Priority' in trace object
	$SortedLogCollector = $LogCollector | Sort-Object -Property StartPriority
	
	# Remove and add trace object to original $LogCollector with sorted order.
	ForEach($TraceObject in $SortedLogCollector){
		$LogCollector.Remove($TraceObject) | Out-Null
		$LogCollector.Add($TraceObject)
	}

	# Now we have $LogCollector and check if it meets the requirements
	If($global:ParameterArray -notcontains 'noPrereqC'){
		PreRequisiteCheckForStart
	}Else{
		LogInfoFile "Skipping PreRequisiteCheckForStart() as -noPrereqC was specified." "Gray" -ShowMsg
	}

	# Store scenario name to TSS registry in case of -StartNoWait/-StartAutoLogger
	If(($global:ParameterArray -contains 'StartNoWait' -or $global:ParameterArray -contains 'StartAutoLogger') -and ($Scenario.Count -ne 0)){
		ForEach($ScenarioName in $Scenario){
			$ScenarioString = $ScenarioName + ','
		}
		$ScenarioString = $ScenarioString -replace ",$",""

		If(!(Test-Path $global:TSSParamRegKey)){
			RunCommands "ProcessStart" "New-Item -Path `"$global:TSSParamRegKey`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$True  -ShowError:$True
		}
		$ValueName = 'Scenario'
		$RegValues = Get-ItemProperty -Path  $global:TSSParamRegKey
		LogInfoFile "Saving scenario name(Scenario) to $global:TSSParamRegKey\$ValueName" -ShowMsg
		If($Null -ne $RegValues.$ValueName){ # Overwrite the value
			Set-ItemProperty -Path $global:TSSParamRegKey -Name $ValueName -Value $ScenarioString
		}Else{
			New-ItemProperty -Path $global:TSSParamRegKey -Name $ValueName -PropertyType String  -Value $ScenarioString | Out-Null
		}
	}

	If($DebugMode.IsPresent){
		LogDebug ("Prio TraceName")
		LogDebug "---- -------------------------"
		ForEach($TraceObject in $LogCollector){
			LogDebug (" $($TraceObject.StartPriority)  $($TraceObject.TraceName)")
		}
		LogDebug "---- -------------------------"
	}

	LogInfo "Processing below traces:" "Gray" -noDate
	ForEach($TraceObject in $LogCollector){
		If($StartAutoLogger.IsPresent -and $TraceObject.LogType -eq 'ETW'){
			LogInfo ('	- ' + $TraceObject.AutoLogger.AutoLoggerSessionName + ' with ' + $TraceObject.Providers.Count + ' providers') "Gray" -noDate
		}ElseIf($TraceObject.LogType -eq 'ETW'){	 
			LogInfo ('	- ' + $TraceObject.TraceName + ' with ' + $TraceObject.Providers.Count + ' providers') "Gray" -noDate
		}ElseIf($TraceObject.Name -eq 'WPR'){
			LogInfo "	- $($TraceObject.TraceName)($($global:BoundParameters['WPR']))" "Gray" -noDate
		}ElseIf($TraceObject.Name -eq 'PerfMon'){
			LogInfo "	- $($TraceObject.Name)($($global:BoundParameters['Perfmon']))" "Gray" -noDate
		}ElseIf($TraceObject.Name -eq 'PerfMonLong'){
			LogInfo "	- $($TraceObject.Name)($($global:BoundParameters['PerfmonLong']))" "Gray" -noDate
		}ElseIf($TraceObject.Name -eq 'Netsh'){
			If($global:ParameterArray -contains 'NetshScenario'){
				LogInfo "	- NetshScenario($($global:BoundParameters['NetshScenario']))" "Gray" -noDate
			}Else{
				LogInfo "	- Netsh(Packet capture)" "Gray" -noDate
			}
		}ElseIf($TraceObject.Name -eq 'Xperf'){
			LogInfo "	- $($TraceObject.Name)($($global:BoundParameters['Xperf']))" "Gray" -noDate
		}Else{
			LogInfo ('	- ' + $TraceObject.TraceName) "Gray" -noDate
		}
	}
	Write-Host ' '
	If($DebugMode.IsPresent){
		DumpCollection $LogCollector
		Read-Host ("[DBG - hit ENTER to continue] (Before StartTraces) ==>")
	}

	Try{
		FwCreateLogFolder $global:LogFolder
	}Catch{
		LogException ("Unable to create $global:LogFolder.") $_
		CleanUpandExit
	}

	### 
	### Finally we can start tracing here
	### 
	Try{
		StartTraces
	}Catch{
		$Script:fInRecovery = $True
		LogException ('An error happened in StartTraces') $_
		LogWarn "======================== Error in StartTraces =========================="
		LogWarn ('Starting recovery process...')

		# As some of detection functions rely on TSS registry, we save script parameters to TSS reg 
		# before running the detection functions called from GetExistingTraceSession.
		SaveParameterToTSSReg

		$RunningTraces = GetExistingTraceSession
		If($RunningTraces.Count -ne 0){
			StopTraces $RunningTraces
			If($StartAutoLogger.IsPresent){
				LogInfo 'Deleting AutoLogger settings if exists...' -noDate
				RemoveAutoLogger
			}
		}Else{
			LogInfo "There are no running traces. Exiting.."
		}
		DisplayDataUploadRequestInError "An error(s) happened during starting traces."
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe $global:logfolder }
		CleanUpandExit
	}

	# In case of -EtlOptions, register tss_Purgelog.ps1 to task scheduler.
	If($global:BoundParameters.ContainsKey('EtlOptions') -and !($global:BoundParameters.ContainsKey('StartAutologger'))){ # allow -EtlOption circular:<EtlMaxSizeMB> for autologger (#671)
		$EtlMode = ($EtlOptions -split ":")[0]
		If($EtlMode -eq 'newfile'){
			Try{
				RegisterPurgeTask
			}Catch{
				LogError "An error happend during registring purge task to task scheduler. ETL files will not be purged but continue to be captured."
				LogException "Error in RegisterPurgeTask" $_ $True
			}
		}
	}
	# -StartAutoLogger
	If($StartAutoLogger.IsPresent){
		ShowTraceResult $LogCollector 'Start' -fAutoLogger:$True
		LogInfo "The trace will be started from next boot=Restart (do not use 'Shutdown'). Run `'Restart-Computer`' to take the change effect."
		LogInfo "To stop data collection after boot, run: .\$($global:ScriptName) -Stop" "Cyan"
		If($Null -ne $ProcmonPath -and $ProcmonPath -ne ''){
			LogInfo ("==> Run `'" + ".\$($global:ScriptName) -Stop -ProcmonPath $ProcmonPath" + "`' to stop AutoLogger after next boot.") -noDate
		}
		SaveParameterToTSSReg
		CleanUpandExit
	# -Start and -StartNoWait
	}ElseIf($StartNoWait.IsPresent){
		If($global:BoundParameters.ContainsKey('Crash') -and !$global:BoundParameters.ContainsKey('noCrash')) {LogWarn "** Will Force Crash at stop: see KB969028 https://support.microsoft.com/en-US/help/969028" "Magenta" }
		Write-Host ' '
		LogInfo "Tracing has been started. You can now reproduce the issue and stop the trace by using -Stop switch." "Cyan" -noDate
		$StopMessage = "=> .\$($global:ScriptName) -Stop"
		If(![string]::IsNullOrEmpty($CommonTask)){
			$StopMessage = $StopMessage + " -CommonTask $CommonTask"
		}
		LogInfo $StopMessage "Yellow" -noDate
		# At the last, saving script parameters to TSS registry
		SaveParameterToTSSReg
		CleanUpandExit
	}
	# -Start
	Else{
		SaveParameterToTSSReg
		If(!([string]::IsNullOrEmpty($WaitEvent)) -or $FwIsMonitoringEnabledByConfigFile){
			Try{
				WaitForMultipleEvents
				If($script:FWRuleArray.Count -ne 0){
					ForEach($FWRule in $script:FWRuleArray){
						LogInfo "Disabling Firewall rule($($FWRule.Displayname)) setting as TSS enabled it temporary."
						$FWRule | Set-NetFirewallRule -Enabled False
					}
					$script:FWRuleArray = $Null
				}
				FwDoCrash	# if -Crash
			}Catch{
				$Script:fInRecovery = $True
				LogError 'An error happened in WaitForMultipleEvents'
				LogExceptionFile 'An error happened in WaitForMultipleEvents' $_
				LogInfoFile "======================== Error in Collect =========================="
				LogWarn "Starting recovery process..."
				$RunningTraces = GetExistingTraceSession
				If($RunningTraces.Count -ne 0){
					StopTraces $RunningTraces
					If($StartAutoLogger.IsPresent){
						LogInfo 'Deleting AutoLogger settings if exists...' -noDate
						RemoveAutoLogger
					}
				}Else{
					LogInfo "There are no running traces. Exiting.."
				}
				DisplayDataUploadRequestInError "An exception happened during waiting for event to be signaled."
				If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe $global:Logfolder }
				CleanUpandExit
			}
		}Else{
			If(!($noRepro -eq $True)){
				Write-Host ' '
				FwPlaySound
				$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
				LogInfoFile "============== Start of Repro: $TimeUTC UTC =========================="
				If($global:BoundParameters.ContainsKey('Crash') -and !$global:BoundParameters.ContainsKey('noCrash')) {LogWarn "** Will Force Crash at stop: see KB969028 https://support.microsoft.com/en-US/help/969028" "Cyan" }
				LogInfo		"============== Start of Repro: $TimeUTC UTC ==========================" "Green"
				# Issue#373 - TSS hang in ISE
				FwRead-Host-YN -Message "Reproduce the issue and enter 'Y' key AFTER finishing the repro (with window focus here)" -Choices 'y' | Out-Null  # no interest in answer
				$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
				LogInfoFile "============== End of Repro:   $TimeUTC UTC =========================="
				LogInfo		"============== End of Repro:   $TimeUTC UTC ==========================" "Green"
			}
		}
		StopTraces $LogCollector
		ShowTraceResult $LogCollector 'Stop' -fAutoLogger:$False
		CompressLogIfNeededAndShow
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStopAutoLogger{
	EnterFunc $MyInvocation.MyCommand.Name
	$script:StopAutologger = $True
	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")
	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation
		}Catch{
			LogException "[ProcessStopAutoLogger] An exception happened in RunPreparation" $_
			CleanUpandExit
		}
	}

	Try{
		FwCreateLogFolder $global:LogFolder
	}Catch{
		Write-Host ("Unable to create $global:Logfolder." + $_.Exception.Message)
		CleanUpandExit
	}

	Try{
		$RunningTraces = GetExistingTraceSession
		If($Null -eq $RunningTraces -or $RunningTraces.Count -eq 0){
			LogInfo "There are no running traces."
		}Else{
			StopTraces $RunningTraces
		}
		LogInfo "Deleting AutoLogger settings."
		RemoveAutoLogger
	}Catch{
		Write-Host ('ERROR: An exception happens in StopTraces: ' + $_.Exception.Message)
	}

	ProcessBasicLog $Script:IsCommonTaskAlreadyRun

	# Copy memory.dmp if -Crash is specifed in previous run and memory.dmp exists.(#518)
	If($global:BoundParameters.ContainsKey('CollectDump')){
		FwCopyMemoryDump
	}ElseIf($global:BoundParameters.ContainsKey('Crash')){
		FwCopyMemoryDump -DaysBack 2
	}

	# This the case where -StartAutoLogger is performed but -Stop is run without restart system. 
	# In this case, we don't show any result and simply exit.
	If($StoppedTraceList.Count -eq 0){
		CleanUpandExit 
	}

	ShowTraceResult $RunningTraces 'Stop' $True
	CompressLogIfNeededAndShow
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessBasicLog {
	Param(
		[Parameter(Mandatory=$False)]
		$Script:IsCommonTaskAlreadyRun = $False
	)
	EnterFunc $MyInvocation.MyCommand.Name
	# Collect BasicLog or MiniBasicLog
	If(($BasicLog.IsPresent) -or ($CollectLog -match "BasicLog")){ 
		RunFunction "FwCollect_BasicLog" -ThrowException:$False
	}Else{ # This is default behavior. Will call mini basic log.
		If($global:ParameterArray -notcontains "noBasiclog" -and !$Script:IsCommonTaskAlreadyRun){ #we# fix for #457
			RunFunction "FwCollect_MiniBasicLog" -ThrowException:$False
		}Else{
			LogInfoFile "Collecting basic log is skipped as -NoBasicLog was specified or common task is already run." "Gray" -ShowMsg
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStop{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")
	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation
		}Catch{
			LogException "[ProcessStop] An exception happened in RunPreparation" $_
			CleanUpandExit
		}
	}

	$EnabledAutoLoggerSessions = GetEnabledAutoLoggerSession
	If($Null -ne $EnabledAutoLoggerSessions){
		LogInfo "The following existing AutoLogger session was found:"
		ForEach($TraceObject in $EnabledAutoLoggerSessions){
			Write-Host ('	- ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
		}
		Write-Host ' '
		LogInfo "Stopping all autologger sessions."
		ProcessStopAutoLogger
		CleanUpandExit
	}

	$RunningTraces = GetExistingTraceSession
	If(($Null -ne $RunningTraces) -and ($RunningTraces.GetType()).Name -eq 'PSCustomObject'){
		$IsTraceObject = $True  # Case for $RunningTraces contaning single trace object
	}Else{
		$IsTraceObject = $False # Case for $RunningTraces contaning multiple trace objects
	}

	# Adding type 2 command manually since it is not a trace and cannot be detected. So add it manually.
	ForEach($Type2CommandSwitch in $Type2CommandSwitches){
		$Type2Command = $global:BoundParameters[$Type2CommandSwitch]
		If(![String]::IsNullOrEmpty($Type2Command) -and ($Type2Command -eq 'Both' -or $Type2Command -eq 'Stop')){
			$Type2CommandObject = $RunningTraces | Where-Object{$_.Name -eq $Type2CommandSwitch}
			If($Null -eq $Type2CommandObject){
				LogInfo "Adding $Type2CommandSwitch to list of running trace."
				$CommandObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq $Type2CommandSwitch}
				If($Null -eq $RunningTraces -or $IsTraceObject){
					$TraceObject = $RunningTraces
					$RunningTraces = New-Object 'System.Collections.Generic.List[Object]'
					If($IsTraceObject){
						$RunningTraces.Add($TraceObject)
					}
				}
				$RunningTraces.add($CommandObject)
			}
		}
	}

	If(($Null -ne $RunningTraces) -and ($RunningTraces.GetType()).Name -eq 'PSCustomObject'){
		$IsTraceObject = $True  # Case for $RunningTraces contaning single trace object
	}Else{
		$IsTraceObject = $False # Case for $RunningTraces contaning multiple trace objects
	}
	# Adding ProcDump manually since in case of ProcDump=stop + -StartNoWait, we cannot detect ProcDump and add it manually.
	If(![String]::IsNullOrEmpty($ProcDump) -and ($ProcDumpOption -eq 'Both' -or $ProcDumpOption -eq 'Stop')){
		$ProcDumpObject = $RunningTraces | Where-Object{$_.Name -eq 'ProcDump'}
		If($Null -eq $ProcDumpObject){
			LogInfo "Adding ProcDump to list of running trace."
			$ProcDumpObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq 'ProcDump'}

			If($Null -eq $RunningTraces -or $IsTraceObject){
				$TraceObject = $RunningTraces
				$RunningTraces = New-Object 'System.Collections.Generic.List[Object]'
				If($IsTraceObject){
					$RunningTraces.Add($TraceObject)
				}
			}
			$RunningTraces.add($ProcDumpObject)
		}
	}

	If($Null -eq $RunningTraces){
		LogInfo "No traces are running. Exiting."
		# Copy memory.dmp if -Crash is specifed in previous run and memory.dmp exists.(#518)
		If($global:BoundParameters.ContainsKey('CollectDump')){
			FwCopyMemoryDump
			CompressLogIfNeededAndShow
		}ElseIf($global:BoundParameters.ContainsKey('Crash')){
			FwCopyMemoryDump -DaysBack 2
			CompressLogIfNeededAndShow
		}
		RemoveParameterFromTSSReg
		CleanUpandExit
	}

	Try{
		FwCreateLogFolder $global:LogFolder
	}Catch{
		Write-Host ("Unable to create $global:Logfolder." + $_.Exception.Message)
		CleanUpandExit
	}

	Try{
		StopTraces $RunningTraces
	}Catch{
		LogError ('ERROR: An exception happened during stopping traces: ' + $_.Exception.Message)
	}
	ShowTraceResult $RunningTraces 'Stop' $False
	CompressLogIfNeededAndShow
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessSet{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("-Set is specifid with $Set")

	# Check if set function corresponding to the option exists or not
	If(!$SupportedSetOptions.Contains($Set)){
		LogInfo ('ERROR: -Set ' + $Set + ' is invalid.') "Red" -noDate
		LogInfo "Supported options are:" -noDate
		ForEach($Key in $SupportedSetOptions.Keys){
			Write-Host ("	o .\$($global:ScriptName) -Set " + $Key + "   /// " + $SupportedSetOptions[$Key])
		}
		CleanUpandExit
	}

	Try{
		$SetFuncName = "RunSet" + $Set
		Get-Command $SetFuncName -ErrorAction Stop | Out-Null
	}Catch{
		Write-Host ('ERROR: -Set ' + $Set + ' is invalid option. Possible option is:')
		CleanUpandExit
	}
	# Run set function
	LogDebug ("Calling $SetFuncName")
	& $SetFuncName
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessUnset{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("-Unset is specifid with $Unset")

	# Check if set function corresponding to the option exists or not
	If(!$SupportedSetOptions.Contains($Unset)){
		Write-Host ('ERROR: -Unset ' + $Unset + ' is invalid.') -ForegroundColor Red
		Write-Host ('Supported options are:')
		ForEach($Key in $SupportedSetOptions.Keys){
			Write-Host ("	o .\$($global:ScriptName) -Unset " + $Key)
		}
		CleanUpandExit
	}

	Try{
		$UnsetFuncName = "RunUnset" + $Unset
		Get-Command $UnsetFuncName -ErrorAction Stop | Out-Null
	}Catch{
		Write-Host ("ERROR: Unable to find a function for unsetting `'$Unset`'($UnsetFuncName)")
		CleanUpandExit
	}
	# Run set function
	LogDebug ("Calling $UnsetFuncName")
	& $UnsetFuncName
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStatus{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")
	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation
		}Catch{
			LogException "[ProcessStatus] An exception happened in RunPreparation" $_
			CleanUpandExit
		}
	}

	Write-Host ("Checking running traces.")
	$RunningScenarioObjectList = GetRunningScenarioTrace
	$RunningTraces = GetExistingTraceSession

	Write-Host ('Running scenario trace session:')
	If($Null -ne $RunningScenarioObjectList -or $RunningScenarioObjectList.Count -gt 0){
		ForEach($RunningScenarioObject in $RunningScenarioObjectList){
			Write-Host ' '
			Write-Host ("	" + $RunningScenarioObject.ScenarioName + " scenario:")
			$RunningScenarioObjec.TraceListInScenario
			ForEach($TraceObject in $RunningScenarioObject.TraceListInScenario){
				Write-Host ("	  - " + $TraceObject.TraceName + ' with ' + $TraceObject.Providers.Count + ' providers')
			}
		}
	}Else{
		Write-Host ("	There is no running scenario trace.")
	}
	Write-Host ' '
	# Checking running ETW traces and WPR/Procmon/Netsh/Perf. 
	Write-Host ('Running ETW trace session:')
	If($Null -ne $RunningTraces -or $RunningTraces.Count -gt 0){
		$etwCount=0
		ForEach($TraceObject in $RunningTraces){
			If($TraceObject.LogType -eq 'ETW'){
			   If($TraceObject.TraceName -like ("*Scenario_*Trace")){ # Scenario trace
				   continue
				}
				$etwCount++
				Write-Host ('	- ' + $TraceObject.TraceName + ' with ' + $TraceObject.Providers.Count + ' providers')
			}Else{
				$etwCount++
				Write-Host ('	- ' + $TraceObject.TraceName) # WPR/Procmon/Netsh/Perf
			}
		}
		If($etwCount -eq 0){
			Write-Host ("	There is no running session.")
		}
	}Else{
		Write-Host ("	There is no running session.")
	}
	Write-Host ' '

	# Checking if AutoLogger is enabled or not.
	Write-Host ('AutoLogger session enabled:')
	$EnabledAutoLoggerTraces = GetEnabledAutoLoggerSession # This updates $TraceObject.AutoLogger.AutoLoggerEnabled

	#If($EnabledAutoLoggerTraces -ne $Null){
	#	UpdateAutoLoggerPath $EnabledAutoLoggerTraces
	#}

	$AutoLoggerCount=0
	ForEach($TraceObject in $EnabledAutoLoggerTraces){
		Write-Host ('	- ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
		$AutoLoggerCount++
		If($DebugMode.IsPresent){
			DumpCollection $TraceObject
		}
	}

	If($AutoLoggerCount -eq 0){
		Write-Host ('	There is no AutoLogger session enabled.')
	}Else{
		Write-Host ('Found ' + $AutoLoggerCount.ToString() + ' AutoLogger session(s).')
	}
	Write-Host ' '
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessCreateBatFile{
	# currently not used
	EnterFunc $MyInvocation.MyCommand.Name

	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")
	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation
		}Catch{
			LogException "[ProcessCreateBatFile] An exception happened in RunPreparation" $_
			CleanUpandExit
		}
	}

	$TraceSwitcheCount=0
	# Checking trace and command switches and add them to LogCollector.
	ForEach($RequestedTraceName in $global:ParameterArray){
		If($ControlSwitches.Contains($RequestedTraceName)){
			Continue # This is not switch for trace.
		}ElseIf($TraceSwitches.Contains($RequestedTraceName)){
			$TraceSwitcheCount++
			Continue
		}
		If($RequestedTraceName -eq 'NetshScenario'){
			$RequestedTraceName = 'Netsh' # NetshScenario uses Netsh object. So replace the name.
		}
		If($StartAutoLogger.IsPresent){
			# Only AutoLogger supported traces are added to LogCollector
			$AllAutoLoggerSupportedTraces =  $GlobalTraceCatalog | Where-Object{$Null -ne $_.AutoLogger}
			If($Null -eq $AllAutoLoggerSupportedTraces){
				Continue
			}
			$AutoLoggerSupportedTrace = $AllAutoLoggerSupportedTraces | Where-Object{$_.Name -eq $RequestedTraceName}
			If($Null -ne $AutoLoggerSupportedTrace){ # This trace has AutoLogger
				AddTraceToLogCollector $RequestedTraceName
			}
		}Else{
			# If not AutoLogger, just add all traces which are specified in option.
			AddTraceToLogCollector $RequestedTraceName
		}
	}
	
	# Check collection
	If($LogCollector.Count -eq 0){
		LogError ('LogCollector is null.')
		CleanUpandExit
	}

	CreateStartCommandforBatch $LogCollector
	CreateStopCommandforBatch $LogCollector
	LogInfo ("Batch file was created on $BatFileName.")
	If(!$StartAutoLogger.IsPresent){
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe $global:LogFolder }
	}Else{
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe $AutoLoggerLogFolder }
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedCommands{
	EnterFunc $MyInvocation.MyCommand.Name
	[array]$CommandOptionsArray = @()
	Write-Host "`nSUPPORTED COMMANDS"
	Write-Host "=============================="
	Write-Host 'The following COMMANDS are supported:'
	ForEach($Key in ($CommandSwitches.Keys | Sort-Object -Unique)){
		$HelpForCOMMANDS += ([String]::Format("[Commands]  -{0,-20}{1}`n", $Key, $CommandSwitches[$Key]))
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$Key;Description=$CommandSwitches[$Key]}
			$CommandOptionsArray += $obj
		}
	}
	If(!$noMore.IsPresent){
		Write-Output $HelpForCOMMANDS | more
		ExportGUItoCsv "CommandOptions" $CommandOptionsArray
	}Else{
		ExportGUItoCsv "CommandOptions" $CommandOptionsArray
		Write-Host $HelpForCOMMANDS
	}
	Write-Host "Please use '.\$($global:ScriptName) -Find <CommandName>' for a quick overview of each individual command."  -ForegroundColor "Yellow"
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedControls{
	EnterFunc $MyInvocation.MyCommand.Name
	[array]$ControlOptionsArray = @()
	Write-Host "`nSUPPORTED ControlOptions"
	Write-Host "=============================="
	Write-Host 'The following ControlOptions are supported:'
	ForEach($Key in ($ControlSwitchesList.Keys | Sort-Object -Unique)){
		$HelpForCcontrols += ([String]::Format("[Controls]  -{0,-20}{1}`n", $Key, $ControlSwitchesList[$Key]))
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$Key;Description=$ControlSwitchesList[$Key]}
			$ControlOptionsArray += $obj
		}
	}
	ExportGUItoCsv "ControlOptions" $ControlOptionsArray
	Write-Host $HelpForCcontrols
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedTrace{
	Param(
		[parameter(Mandatory=$False)]
		[String]$PODName="ALL",
		[Switch]$noMore
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$Section1 = @"
`nSUPPORTED COMPONENT TRACE
=========================
The following component traces are supported:`n
"@
	[array]$SupportedComponentsArray = @()
	ForEach($Key in ($TraceSwitches.Keys | Sort-Object)){
		If([String]::IsNullorEmpty($PODName) -or $PODName -eq "ALL"){
			$HelpForTrace += ([String]::Format("[Component]  -{0,-25}{1}`n", $Key, $TraceSwitches[$Key]))
		}Else{
			If($Key -like ($PODName + "_*")){
				$HelpForTrace += ([String]::Format("  -{0,-25}{1}`n", $Key, $TraceSwitches[$Key]))
			}
		}
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$Key;Description=$TraceSwitches[$Key]}
			$SupportedComponentsArray += $obj
		}
	}
	# Show list of supported traces with paging by using native more command.
	$HelpForTrace = $Section1 + $HelpForTrace
	ExportGUItoCsv "ComponentsAll" $SupportedComponentsArray
	If(!$noMore.IsPresent){
		Write-Output $HelpForTrace | more
	}Else{
		Write-Host $HelpForTrace
	}

	#Write-Host ' '
	Write-Host "Usage:"
	Write-Host "  .\$($global:ScriptName) -<ComponentName> -<ComponentName>"
	Write-Host "  Example: .\$($global:ScriptName) -UEX_FSLogix -UEX_Logon" -ForegroundColor "Yellow"
	Write-Host ' '
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedLog{
	Param(
		[parameter(Mandatory=$False)]
		[String]$PODName="ALL"
	)
	EnterFunc $MyInvocation.MyCommand.Name
	Write-Host "`nSUPPORTED COMPONENT LOG COLLECTION"
	Write-Host "=================================="
	Write-Host ("The following COMPONENT Logs are supported for data collection:")
	[array]$SupportedCollectLogArray = @()
	$ScenarioCollectFunctions = @()
	$CollectFunctions = Get-Command "Collect*Log" -ErrorAction Ignore
	ForEach($CollectFunction in $CollectFunctions){
		$IsScenarioCollectFunction = $False
		If($PODName -ne "ALL"){
			If(!($CollectFunction.Name -like "Collect$PODName*")){
				Continue
			}
		}
		$ComponentName = $CollectFunction.Name -replace "^Collect",""
		$ComponentName = $ComponentName -replace "Log$",""
		If($ComponentName -like "*Scenario"){
			$ScenarioCollectFunctions += $ComponentName
			$IsScenarioCollectFunction = $True
		}Else{
			If($TraceSwitches.Contains($ComponentName)){
				Write-Host ([String]::Format("[-CollectLog]  {0,-25}- {1}", $ComponentName, $TraceSwitches[$ComponentName]))
			}Else{
				Write-Host ([String]::Format("[-CollectLog]  {0,-25}- no description", $ComponentName))
			}
			if($ExportGUIcsv){
				$obj = new-object PSObject -Property @{Key=$ComponentName;Description=$TraceSwitches[$ComponentName]}
				$SupportedCollectLogArray += $obj
			}
		}
	}
	ExportGUItoCsv "CollectLogComponents" $SupportedCollectLogArray
	
	If($ScenarioCollectFunctions.Count -ne 0){
		#[array]$SupportedScenarioCollectLogArray = @()
		Write-Host ("`nThe following SCENARIOS are supported for data collection:")
		ForEach($ScenarioCollectFunction in $ScenarioCollectFunctions){
			$ScenarioCollectFunction = $ScenarioCollectFunction -replace "Scenario$",""
			Write-Host ([String]::Format("[-CollectLog]  {0,-25}- log for {0} scenario",$ScenarioCollectFunction))
			#if($ExportGUIcsv){
			#	$obj = new-object PSObject -Property @{Key=$ScenarioCollectFunction;Description="log for $ScenarioCollectFunction scenario"}
			#	$SupportedScenarioCollectLogArray += $obj
			#}
		}
		#ExportGUItoCsv "CollectScenarioLogs" $SupportedScenarioCollectLogArray	
	}

	Write-Host ' '
	Write-Host "Usage:"
	Write-Host "  .\$($global:ScriptName) -CollectLog [ComponentName,ComponentName,...]"
	Write-Host "  Ex#1:   .\$($global:ScriptName) -CollectLog UEX_FSLogix,UEX_Logon" -ForegroundColor "Yellow"
	Write-Host "  Ex#2:   .\$($global:ScriptName) -CollectLog BasicLog" -ForegroundColor "Yellow"		# for Collecting System Basic logs"
	Write-Host ' '
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedNetshScenario{
	EnterFunc $MyInvocation.MyCommand.Name
	# dbg/wpp scenarios:
	$SupportedNetshScenarios = Get-ChildItem 'HKLM:System\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs\WPPTrace\HelperClasses'
	# normal scenarios: #we# [waltere] added
	$SupportedNetshScenarios += Get-ChildItem 'HKLM:System\CurrentControlSet\Control\NetTrace\Scenarios'
	[array]$NetShScenarioArray = @()
	Write-Host "`nSUPPORTED NETSH SCENARIO TRACE"
	Write-Host "=============================="
	Write-Host "Supported scenarios for -NetshScenario are:"
	ForEach($SupportedNetshScenario in $SupportedNetshScenarios){
		Write-Host ("  - " + $SupportedNetshScenario.PSChildName)
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$($SupportedNetshScenario.PSChildName)}
			$NetShScenarioArray += $obj
		}
	}
	ExportGUItoCsv "NetShScenarios" $NetShScenarioArray	
	Write-Host ' '
	Write-Host "Usage:"
	Write-Host "  .\$($global:ScriptName) -NetshScenario <ScenarioName>"
	Write-Host "  Example: .\$($global:ScriptName) -NetshScenario InternetClient_dbg" -ForegroundColor "Yellow"
	Write-Host ' '
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedNoOptions{
	EnterFunc $MyInvocation.MyCommand.Name
	[array]$NoCommandOptionsArray = @()
	Write-Host "`nSUPPORTED NoOptions for Commands/Tools"
	Write-Host "========================================"
	Write-Host "The following NoOptions for Commands/Tools are supported:"
	ForEach($Key in ($NoCommandOptionsList)){
		$HelpForNoCommandOptions += ([String]::Format("[NoOptions]  -{0,-20}{1}`n", $Key, $NoOptions[$Key]))
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$Key;Description=$NoOptions[$Key]}
			$NoCommandOptionsArray += $obj
		}
	}
	ExportGUItoCsv "NoCommandOptions" $NoCommandOptionsArray
	Write-Host $HelpForNoCommandOptions
	
	[array]$NoControlOptionsArray = @() # $null
	Write-Host "`nSUPPORTED NoOptions for optional Control switches"
	Write-Host "==================================================="
	Write-Host "The following NoOptions for optional Controls are supported:"
	ForEach($Key in ($NoControlOptionsList)){
		$HelpForNoControlOptions += ([String]::Format("[NoOptions]  -{0,-20}{1}`n", $Key, $NoOptions[$Key]))
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$Key;Description=$NoOptions[$Key]}
			$NoControlOptionsArray += $obj
		}
	}
	ExportGUItoCsv "NoControlOptions" $NoControlOptionsArray
	Write-Host $HelpForNoControlOptions
	EndFunc $MyInvocation.MyCommand.Name
}
<#
Function AddItemToArray{ #not used
	Param(
		[parameter(Mandatory=$True)]
		[array]$ArrayName,
		[String]$Key,
		[String]$KeyDecription
	)
	$script:ArrayName = $ArrayName
	$obj = new-object PSObject -Property @{Key=$Key;Description=$KeyDecription}
	[array]$script:ArrayName += $obj
}
#>

Function ProcessListSupportedPerfCounter{
	Param(
		[Parameter(Mandatory=$False)]
		[Switch]$AnswerYes	# True for building Help-Message
	)
	EnterFunc $MyInvocation.MyCommand.Name
	[array]$SupportedPerfArray = @()
	Write-Host "`nSUPPORTED PERFORMANCE MONITOR COUNTER"
	Write-Host "====================================="
	Write-Host "The following Performance counter set names are supported:"
	ForEach($key in ($SupportedPerfCounter.keys | Sort-Object)){
		$HelpForPerfCounter += ([String]::Format("[PerfMon]  {0,-20}{1}`n", $Key, $SupportedPerfCounter[$Key]))
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$Key;Description=$SupportedPerfCounter[$Key]}
			$SupportedPerfArray += $obj
		}
	}
	ExportGUItoCsv "PerfCounter" $SupportedPerfArray
	Write-Host $HelpForPerfCounter
	#Write-Host ' '
	Write-Host "Usage:"
	Write-Host "  .\$($global:ScriptName) -PerfMon <CounterSetName>"
	Write-Host "  Ex#1: Start Performance Monitor with general counters (CPU, Memory, Disk and etc) with 5 seconds interval"
	Write-Host "	   .\$($global:ScriptName) -PerfMon General -PerfIntervalSec 5" -ForegroundColor Yellow
	Write-Host "  Ex#2: Start Performance Monitor (Long) with SMB counters (SMB counters + general counters) with 11 minutes interval"
	Write-Host "	   .\$($global:ScriptName) -PerfMonLong SMB -PerfLongIntervalMin 11" -ForegroundColor Yellow
	Write-Host ' '

	if (!$AnswerYes){
		LogInfo "Do you want to see a detailed performance counter list for each counter set?" "Cyan"
		$Answer = FwRead-Host-YN -Message "Press Y for Yes, N for No (timeout=10s)" -Choices 'yn' -TimeOut 10 -Default N
		If($Answer){
			# Show detailed PerfMon counters only when -ListSupportedPerfCounter is specified.
			If($global:ParameterArray -contains "ListSupportedPerfCounter"){
				Write-Host ("Here is detailed performance counters for each counter set:")
				Write-Host ' '
				ForEach($key in $SupportedPerfCounter.keys){
					Write-Host ("$key")
					Write-Host ("------------------------------")
					$PerfCounters = Get-Variable -Name ($key + "Counters") -ValueOnly
					ForEach($PerfCounter in $PerfCounters){
						Write-Host ($PerfCounter)
					}
					Write-Host ' '
					Write-Host ' '
				}
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedDiag{
	Param(
		[parameter(Mandatory=$False)]
		[String]$PODName="ALL"
	)
	EnterFunc $MyInvocation.MyCommand.Name
	[array]$DiagComponentsArray = @()
	$ScenarioDiagFunctions = @()
	Write-Host "`nSUPPORTED COMPONENT TO DIAGNOSE"
	Write-Host "==============================="
	Write-Host ("Diag function for below components are supported:")
	$DiagFunctions = Get-Command "Run*Diag" -ErrorAction Ignore
	ForEach($DiagFunction in $DiagFunctions){
		If($PODName -ne "ALL"){
			If(!($DiagFunction.Name -like "Run$PODName*")){
				Continue
			}
		}
		$DiagFunctionName = $DiagFunction.Name -replace "^Run",""
		$DiagFunctionName = $DiagFunctionName -replace "Diag$",""
		If($DiagFunctionName -like "*Scenario"){
			$ScenarioDiagFunctions += $DiagFunctionName
		}Else{
			Write-Host ([String]::Format("[-StartDiag]   {0,-25}- Diagnostic module", $DiagFunctionName))
			if($ExportGUIcsv){
				$obj = new-object PSObject -Property @{Key=$DiagFunctionName;Description="Diagnostic module"}
				$DiagComponentsArray += $obj
			}
		}
	}
	ExportGUItoCsv "DiagComponents" $DiagComponentsArray

	If($ScenarioDiagFunctions.Count -ne 0){
		#[array]$DiagScenarioArray = @()	# no POD Diag scenario is defined so far
		Write-Host ' '
		Write-Host "Supported diag function for scenario trace:"
		ForEach($ScenarioDiagFunction in $ScenarioDiagFunctions){
			$ScenarioDiagFunction = $ScenarioDiagFunction -replace "Scenario$",""
			Write-Host ("	- $ScenarioDiagFunction")
			#if($ExportGUIcsv){
			#	$obj = new-object PSObject -Property @{Key=$ScenarioDiagFunction;Description=$ScenarioDiagFunction}
			#	$DiagScenarioArray += $obj
			#}
		}
		#ExportGUItoCsv "DiagScenarios" $DiagScenarioArray
	}
	Write-Host ' '
	Write-Host "Usage:"
	Write-Host "  .\$($global:ScriptName) -StartDiag [ComponentName,ComponentName,...]"
	Write-Host "  Example: .\$($global:ScriptName) -StartDiag UEX_WinRM" -ForegroundColor "Yellow"
	Write-Host ' '
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedScenarioTrace{
	Param(
		[parameter(Mandatory=$False)]
		[String]$PODName="ALL",
		[Switch]$noMore
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$Section1 = @"
`nSUPPORTED SCENARIO TRACE
========================
The following ScenarioNames are supported:`n
"@

	# 1. Gather all scenario traces.
	If([String]::IsNullorEmpty($PODName) -or $PODName -eq "ALL"){
		$ScenarioTraceArray = Get-Variable "*_ETWTracingSwitchesStatus" -ErrorAction Ignore
	}Else{
		$ScenarioTraceArray = Get-Variable ($PODName + "*_ETWTracingSwitchesStatus") -ErrorAction Ignore
	}

	# 2. If there is a decription for the scenario trace, display it. If not, dynamically load list of traces and show them.
	$ScenarioDescription = $Null
	[array]$SupportedScenariosArray = @()
	ForEach($ScenarioTrace in $ScenarioTraceArray){
		# Get a POD name and scenario name
		$Token = $ScenarioTrace.Name -split '_'
		$POD = $Token[0]
		$ScenarioName = ($ScenarioTrace.Name).replace("_ETWTracingSwitchesStatus","")

		# Check if the description for the scenario trace exists in POD scenario trace list(<POD>_ScenarioTraceList).
		$PODScenarioTraceList = Get-Variable ($POD + "_ScenarioTraceList") -ErrorAction Ignore
		If($Null -ne $PODScenarioTraceList){ # This is a case <POD>_ScenarioTraceList exists.
			If(($PODScenarioTraceList.Value).Contains($ScenarioName)){
				$ScenDescription = $($PODScenarioTraceList.Value[$ScenarioName])
				$ScenarioDescription = ($ScenarioDescription + ([String]::Format("  {0,-18} - collects {1}`n", $ScenarioName, $ScenDescription )) )
			}
		}Else{ # This is a case <POD>_ScenarioTraceList does not exist. In this case, we show the description by using the scenario definition(XXX_ETWTracingSwitchesStatus).
			$TracesInScenario = $ScenarioTrace.Value  # This is hashtable.
			$ScenDescription = $Null
			ForEach($TraceInScenario in $TracesInScenario.keys){
				$ScenDescription = $ScenDescription + $TraceInScenario + ', '
			}
			$ScenDescription = $ScenDescription -replace ", $","" # Remove ', ' at the end of string.
			$ScenarioDescription = $ScenarioDescription + ([String]::Format("  {0,-18} - collects {1}`n", $ScenarioName, $ScenDescription))
		}
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$ScenarioName;Description=$ScenDescription}
			$SupportedScenariosArray += $obj
		}
	}
	$HelpForScenarioTrace = $Section1 + $ScenarioDescription
	ExportGUItoCsv "ScenariosAll" $SupportedScenariosArray
	If(!$noMore.IsPresent){
		Write-Output $HelpForScenarioTrace | more
	}Else{
		Write-Host $HelpForScenarioTrace #-Wrap
	}
	Write-Host "Usage:"
	Write-Host "  .\$($global:ScriptName) -Scenario <ScenarioName>"
	Write-Host "  Example: .\$($global:ScriptName) -Scenario ADS_Auth" -ForegroundColor Yellow
	Write-Host ' '
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedSDP{
	EnterFunc $MyInvocation.MyCommand.Name
	[array]$SupportedSDPArray = @()
	Write-Host "`nSUPPORTED SDP (MSDT) report Options"
	Write-Host "==================================="
	Write-Host "Usage:"
	Write-Host "  .\$($global:ScriptName) -SDP <specialty> -SkipSDPList <comma-separated-params> "
	Write-Host "  Example: .\$($global:ScriptName) -SDP NET -SkipSDPList skipBPA,skipTS" -ForegroundColor Yellow
	Write-Host "   You can avoid some steps SDP component logs by using -SkipSDPList parameters (noNetadapters,skipBPA,skipHang,skipNetview,skipSddc,skipTS,skipHVreplica,skipCsvSMB)"
	Write-Host "   You can use a comma-separated list to combine more SDP reports, i.e. -SDP NET,Cluster.`n"

	Write-Host "The following SDP reports are supported:"
	ForEach($Key in ($SDPspecialties.Keys | Sort-Object)){
		$HelpForSDPspec += ([String]::Format("[SDP]  -SDP {0,-20}{1}`n", $Key, $SDPspecialties[$Key]))
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$Key;Description=$SDPspecialties[$Key]}
			$SupportedSDPArray += $obj
		}
	}
	ExportGUItoCsv "SDPoptions" $SupportedSDPArray
	Write-Host $HelpForSDPspec
	Write-Host ' '
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedWPRScenario{
	EnterFunc $MyInvocation.MyCommand.Name
	[array]$SupportedWPRArray = @()
	Write-Host "`nSUPPORTED WPR Options"
	Write-Host "======================="
	Write-Host "Usage:"
	Write-Host "  .\$($global:ScriptName) -WPR <WPRprofile> [-WPROptions <Option string> -SkipPdbGen]"
	Write-Host "  Example: .\$($global:ScriptName) -WPR General`n" -ForegroundColor Yellow
	
	Write-Host "The following WPR profiles are supported:"
	ForEach($Key in ($WPRprofiles.Keys | Sort-Object)){
		$HelpForWPRprofiles += ([String]::Format("[WPR]  -WPR {0,-14} : {1}`n", $Key, $WPRprofiles[$Key]))
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$Key;Description=$WPRprofiles[$Key]}
			$SupportedWPRArray += $obj
		}
	}
	ExportGUItoCsv "WPRprofiles" $SupportedWPRArray
	Write-Host $HelpForWPRprofiles
	Write-Host ' '
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedXperfProfile{
	EnterFunc $MyInvocation.MyCommand.Name
	[array]$SupportedXperfArray = @()
	Write-Host "`nSUPPORTED Xperf Profile Options"
	Write-Host "================================="
	Write-Host "Usage:"
	Write-Host "  .\$($global:ScriptName) -Xperf <Profile> [-XperfMaxFileMB <Size> -XperfOptions <Option string> -XperfPIDs <PID> -XperfTag <Pool Tag>]"
	Write-Host "  Example: .\$($global:ScriptName) -Xperf CPU`n" -ForegroundColor Yellow
	
	Write-Host "The following Xperf profiles are supported:"
	ForEach($Key in ($XperfProfiles.Keys | Sort-Object)){
		 $HelpForXperfProfiles += ([String]::Format("[Xperf]  -Xperf {0,-10} : {1}`n", $Key, $XperfProfiles[$Key]))
		if($ExportGUIcsv){
			$obj = new-object PSObject -Property @{Key=$Key;Description=$XperfProfiles[$Key]}
			$SupportedXperfArray += $obj
		}
	}
	ExportGUItoCsv "XperfProfiles" $SupportedXperfArray
	Write-Host $HelpForXperfProfiles
	Write-Host ' '
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessList{
	Param(
		[parameter(Mandatory=$False)]
		[String]$PODName
	)
	EnterFunc $MyInvocation.MyCommand.Name
	ProcessListSupportedCommands
	ProcessListSupportedControls
	ProcessListSupportedNoOptions
	ProcessListSupportedLog $PODName
	ProcessListSupportedDiag $PODName
	ProcessListSupportedNetshScenario
	ProcessListSupportedWPRScenario
	ProcessListSupportedXperfProfile
	ProcessListSupportedSDP
	ProcessListSupportedTrace $PODName
	ProcessListSupportedScenarioTrace $PODName
	ProcessListSupportedPerfCounter
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessSDP{
	EnterFunc $MyInvocation.MyCommand.Name
	#Sanity check: are OS commands available?
	$OsCommands = @("cmd.exe", "cscript.exe","reg.exe","ipconfig.exe")
	ForEach ($OsCommand in $OsCommands) {
		FwIsOsCommandAvailable $OsCommand | Out-Null
	}
	$SkipSDPList = $global:BoundParameters['SkipSDPList']
	$SDP = $global:BoundParameters['SDP'] # $SDP is string array
	If(![String]::IsNullOrEmpty($SkipSDPList)){
		ForEach($SkipOption in $SkipSDPList){
			$SkipOptionSwitchs = $SkipOptionSwitchs + '-' + $SkipOption + ' '
		}
		LogInfo "SkipOptionSwitchs:		 $SkipOptionSwitchs"
		LogInfoFile "Current ExecutionPolicy:   $(Get-ExecutionPolicy)"
		LogInfoFile "ErrorActionPreference:	 $ErrorActionPreference"
	}
	If([String]::IsNullOrEmpty($SDP)){
		LogWarn "SDP tech was not passed to ProcessSDP(). Returning."
		Return
	}
	If(Test-Path -Path "$Scriptfolder\psSDP\Get-psSDP.ps1"){
		Try{
			If($EvtDaysBack -ne 0) {$EvtDaysSwitch="-EvtDaysBack $EvtDaysBack"}else{$EvtDaysSwitch=""}
			If($Nozip) {$NoZipSwitch="-NoZip"}else{$NoZipSwitch=""}
			If($noISECheck) {$noISECheckSwitch="-noISECheck"}else{$noISECheckSwitch=""}
			If($Script:xrayCompleted -or $noXray) {$noXraySwitch="-skipxray"}else{$noXraySwitch=""}
			LogDebug "____EvtDaysBack $EvtDaysBack - EvtDaysSwitch: $EvtDaysSwitch"
			ForEach($SDPtech in $SDP){
				LogInfoFile "[psSDP] SDP($SDPtech) starting..." -ShowMsg
				$psSDPcmd = ".\Get-psSDP.ps1 $SDPtech -SkipEULA -skipQEdit -savePath $global:LogFolder $SkipOptionSwitchs $EvtDaysSwitch $NoZipSwitch $noXraySwitch $noISECheckSwitch"
				LogInfo "[psSDP] Running $psSDPcmd"
				Push-Location -Path "$Scriptfolder\psSDP"
				Invoke-Expression -Command $psSDPcmd
				Pop-Location 
			}
		}Catch{
			LogException "An Exception happend in Get-psSDP.ps1" $_
		}
		LogInfo "[psSDP] end of SDP data collection" "Gray"
		# Somehow after running psSDP, working directory is changed to log folder. So back to script root.
		Set-Location $PSScriptRoot
	}Else{
		LogWarn "[psSDP] unable to find Get-psSDP.ps1. Skipping psSDP." "Gray"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function Processxray{
	Param(
		[parameter(Mandatory=$False)]
		[Switch]$skipDiags		# if True, run only check for cumulative update
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If(Test-Path -Path "$Scriptfolder\xray\xray.ps1"){
		LogInfoFile "[xray] xray Diagnostics starting..." "Green" -ShowMsg
		Push-Location -Path "$Scriptfolder\xray"
		Try{
			If(!$skipDiags.IsPresent){
				LogInfoFile "[xray] Running xray.ps1 -Area * -DataPath $global:LogFolder -AcceptEULA" -ShowMsg
				.\xray.ps1 -Area * -DataPath $global:LogFolder -AcceptEULA
			} else{
				LogInfoFile "[xray] Running xray.ps1 for checking latest cumulative Windows updates" -ShowMsg
				.\xray.ps1 -Area * -DataPath $global:LogFolder -AcceptEULA -skipDiags
			}
		}Catch{
			LogException "Exception happened in xray.ps1" $_
		}
		Pop-Location 
		LogInfoFile "[xray] xray Diagnostics completed" -ShowMsg
		$Script:xrayCompleted = $True
	}Else{
		LogWarn "[xray] unable to find xray.ps1. Skipping xray." "Gray"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessCollectEventLog{
	EnterFunc $MyInvocation.MyCommand.Name
	If(!$global:BoundParameters.ContainsKey('CollectEventLog')){
		LogDebug "ProcessCollectEventLog is called but CollectEventLog is not specified. Returning."
		Return
	}
	$EventLogs = $global:BoundParameters['CollectEventLog']
	LogInfo "CollectEventLog = $EventLogs"
	$EventLogList = @()
	ForEach($EventLog in $EventLogs){
		$EventLogConfiguration = Get-winevent -ListLog $EventLog -ErrorAction Ignore
		If($Null -eq $EventLogConfiguration){
			Continue
		}Else{
			$EventLogList += $EventLogConfiguration.LogName
		}
		FwExportEventLog $EventLogList
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function UpdateTSS{
	EnterFunc $MyInvocation.MyCommand.Name
	If(Test-Path -Path "$Scriptfolder\scripts\tss_update-script.ps1"){
		LogInfo "[update] TSS update starting..." green
		Push-Location -Path ".\scripts"
		Try{
			.\tss_update-script.ps1 -tss_action update -UpdMode $UpdMode -verOnline $Script:TssVerOnline
		}Catch{
			LogException "Exception happened in tss_update-script.ps1" $_
		}
		Pop-Location 
		LogInfo "[update] TSS update procedure completed." green
	}Else{
		LogWarn "[update] unable to find tss_update-script.ps1" "Gray"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ReadConfigFile{
	EnterFunc $MyInvocation.MyCommand.Name
	If(!(Test-Path -Path $global:ConfigFile)){
		LogDebug ("Config file `'$global:ConfigFile`' does not exist.")
		Return
	}
	$Lines = Get-Content $global:ConfigFile
	ForEach($Line in $Lines){
		# Skip empty line
		If($Line.Length -eq 0){ 
			Continue
		}
		# Skip comment line and the line starting with space or tab.
		If($Line.Substring(0,1) -eq '@' -or $Line.Substring(0,1) -eq ' ' -or $Line.Substring(0,1) -eq "`t"){
			Continue
		}
		# In case the parameter is enabled but does not have a value like '_ErrorLimit=', skip it.
		$Token = $Line -split ('=')
		If($Token.Length -ne 2){ 
			LogWarn "Invalid line in tss_config file: $Line"
			Continue
		}
		# Remove double and single quote
		$Value = $Token[1] -Replace ("[`"`']")
		# Remove space at the end of value
		If($Value -match " *$"){
			$Value = $Value -replace " *$",""
		}
		Try{
			$script:FwConfigParameters.Add($Token[0], $Value)
		}Catch{
			LogException ("Exception happened in ParameterTalbe.Add() with $($Token[0])=$Value. Usually this happens when the same parameter is configured multiple times.") $_
			Return
		}
	}
	# If there is a parameter configured, copy the tss_config file to the log folder.
	If($FwConfigParameters.Count -eq 0){
		LogInfo "Config file (tss_config.cfg) exists but no parameter is configured." "Gray"
		Return
	}Else{
		Try{
			if($MyInvocation.BoundParameters.keys[0] -ne "SDP"){	# not command: TSS.ps1 -SDP
				LogDebug "Copying $global:ConfigFile to $global:LogFolder"
				Copy-Item $global:ConfigFile $global:LogFolder -ErrorAction Stop
				Copy-Item $global:ConfigFolder\tss_config.cfg_backup $global:LogFolder -ErrorAction Ignore	# copy backup file as well, if it exits
				Copy-Item $global:ConfigFolder\StopCondition.txt $global:LogFolder -ErrorAction Ignore	# copy custom  StopCondition file
			}
		}Catch{
			LogWarn "Failed to copy $global:ConfigFile to $global:LogFolder"
		}
	}
	# ToDo: add additional parameter name(s) in below list, whenever tss_config.cfg adds a new parameter
	#'_RunDown','_noClearCache','_noRestart','_collectEvtSec','_RunPS_BCstatus','_BITSLOG_RESET','_BITSLOG_RESTART','_SCCMdebug','_NetLogonFlag','_LDAPcliProcess','_LDAPcliFlags','_FltMgrFlags','_GPEditDebugLevel' | ForEach-Object {
	#	If(!([string]::IsNullOrEmpty($FwConfigParameters[$_]))){
	#		Set-Variable -Name ('$global:' + ($_).replace("_","")) -scope Global
	#		$ConfigVarName = ('$global:' + ($_).replace("_",""))
	#		$ConfigVarValue = $FwConfigParameters[$_]
	#		LogDebug "ConfigVarName: $ConfigVarName - ConfigVarValue: $ConfigVarValue"
	#	}
	#}

	# Set all configured parameters to global variable so that POD module can access them.
	# Example: _EvtxLogSize is set to $global:EvtxLogSize. 
	# Note: '_'(underscore) at the beginning of parameter is removed when config parameter is converted to global variable.
	ForEach($Key in $FwConfigParameters.Keys){
		$ConfigVarName = $Key -replace "^_",''
		[String]$ConfigVarValue = $FwConfigParameters[$Key]
		# Convert string boolean to real boolean
		If($ConfigVarValue -eq '$True'){
			[Bool]$ConfigVarValue = $True
		}ElseIf($ConfigVarValue -eq '$False'){
			[Bool]$ConfigVarValue = $False
		}
		# If the value is number string, convert it to int32.
		If([int]::TryParse($ConfigVarValue,[ref]$Null)){ # convert number string to int
			[int]$ConfigVarValue = $ConfigVarValue
		}
		Try{
			Set-Variable -Name $ConfigVarName -Value $ConfigVarValue -scope Global -ErrorAction Stop
		}Catch{
			LogWarn "Failed to set $ConfigVarName=$ConfigVarValue"
			Continue
		}
		$ConfigValue = Get-Variable -Name $ConfigVarName -Scope Global
		LogDebug ("ConfigVarName: $($ConfigValue.Name) = " + $ConfigValue.Value)
	}
	$Value = $FwConfigParameters['_EnableMonitoring']
	If(!([string]::IsNullOrEmpty($Value)) -and ($Value.Substring(0,1) -eq 'y')){
		$Value = $FwConfigParameters['_MonitorIntervalInSec']
		If(!([string]::IsNullOrEmpty($Value))){
			$script:FwMonitorIntervalInSec = $Value
		}
		# Count monitoring events
		$TestList = @("_PortLoc", "_PortDest", "_NoNetConn", "_SvcName", "_ShareName", "_DomainName", "_ProcessName", "_CommonTCPPort", "_RegDataKey", "_RegValueKey", "_RegKey", "_File", "_EventLogName", "_WaitTime", "_LogFile", "_CpuThreshold", "_MemoryThreshold")
		$ConfiguredTestCount = 0
		ForEach($TestName in $TestList){
			$Value = $FwConfigParameters[$TestName]
			If($Null -ne $Value){
				$ConfiguredTestCount++
			}
		}
		If($ConfiguredTestCount -gt 0){
			$script:FwIsMonitoringEnabledByConfigFile = $True
			LogDebug "IsMonitoring is set to True"
			LogDebug "Number of monitoring events = $ConfiguredTestCount"
		}
	}
	If(!([string]::IsNullOrEmpty($FwConfigParameters['_EvtxLogSize']))){
		$global:FwEvtxLogSize = $FwConfigParameters['_EvtxLogSize']	#we# changed to global in #
	}
	if (!($global:BoundParameters['ProcDumpOption'])) { #we#604
		$ProcDumpOptionFromConfig = $FwConfigParameters['_ProcDumpOption']
		If(![string]::IsNullOrEmpty($ProcDumpOptionFromConfig)){
			LogDebug "Use ProcDumpOption($ProcDumpOptionFromConfig) configured in tss_config.cfg"
			$script:ProcDumpOption = $ProcDumpOptionFromConfig
		}else{
			$script:ProcDumpOption="Both"		# default if not in config.cfg or in command-line
			LogDebug "Use ProcDumpOption($ProcDumpOption) - default configured in ReadConfigFile"
		}
	}else{ LogDebug "Use ProcDumpOption($ProcDumpOption) from command-line" }
	if (!($global:BoundParameters['ProcDumpInterval'])) { #we#604
		$ProcDumpIntervalFromConfig = $FwConfigParameters['_ProcDumpInterval']
		If(![string]::IsNullOrEmpty($ProcDumpIntervalFromConfig)){
			LogDebug "Use ProcDumpInterval($ProcDumpIntervalFromConfig) configured in tss_config.cfg"
			$script:ProcDumpInterval = $ProcDumpIntervalFromConfig
		}else{
			$script:ProcDumpInterval="3:10"	# default if not in config.cfg or in command-line
			LogDebug "Use ProcDumpInterval($script:ProcDumpInterval) - default configured in ReadConfigFile"
		}
	}else{ LogDebug "Use ProcDumpInterval($ProcDumpInterval) from command-line" }
	LogDebug "[ReadConfigFile] ProcDumpInterval $script:ProcDumpInterval / global: $global:ProcDumpInterval  - ProcDumpOption $ProcDumpOption / global: $global:ProcDumpOption"
	# ToDo: Define default switch options for PerfMon, PerfMonLong, WPR, Xperf ?
	EndFunc $MyInvocation.MyCommand.Name
}

Function ValidateIPAddress{
	[OutputType([Bool])]
	Param([string]$IpAddr)
	EnterFunc $MyInvocation.MyCommand.Name
	
	[int]$a, [int]$b, [int]$c, [int]$d = $IpAddr.Split(".")
	if (($a -ge 0) -and ($a -le 255) -and ($b -ge 0) -and ($b -le 255) -and ($c -ge 0) -and ($c -le 255) -and ($d -ge 0) -and ($d -le 255))
		{$fResult = $True;}
	else 
	{
		$fResult = $False
	}	
			
	# Reform IPAddr with the "integerized" octets.
	# This normalizes cases with extra digits like leading zeros.  (10.0.0.01 --> 10.0.0.1)
	$ModifiedIpAddr = "$a.$b.$c.$d"
	
    EndFunc "$($MyInvocation.MyCommand.Name) Return=$fResult"
    $ModifiedIpAddr, $fResult
}

Function ValidateUNCPath{
	[OutputType([Bool])]
	Param([string]$UNCPath)
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	$pattern = '^\\\\((?:[a-zA-Z0-9_-]+|(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))\\[a-zA-Z0-9_]+(\\[a-zA-Z0-9_]+)+$'

	if ($UNCPath -match $pattern){
		$ServerName = $matches[1]
		LogInfoFile "UNC Path format is valid"
		$fResult = $True
	}
	EndFunc "$($MyInvocation.MyCommand.Name) Return=$fResult"
	$ServerName, $fResult
}

Function ValidateConfigFile{
	EnterFunc $MyInvocation.MyCommand.Name
	# Validate parameters for monitoring
	If($global:IsRemoting){
		$Value = $FwConfigParameters['_WriteEventToHosts']
		If([string]::IsNullOrEmpty($Value)){
			Throw ("_WriteEventToHosts has to be specified when remoting is enabled.")
		}Else{
			# Test if remote registry and WMI is enabled as these are required for remoting.
			$RemoteHosts = $Value -split ','
			ForEach($RemoteHost in $RemoteHosts){
				$reg = $Null
				Try{
					$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $RemoteHost)
				}Catch{
					# Do nothing
				}
				If($Null -eq $reg){
					Throw "Remote Registry service is not started on $RemoteHost. Please start it and run again or remove `'$RemoteHost`' from _WriteEventToHosts."
				}
			}
		}
		# _RemoteLogFolder is optional but if it has a value, it should be remote share.
		$Value = $FwConfigParameters['_RemoteLogFolder']
		If(!([string]::IsNullOrEmpty($Value)) -and $Value.Substring(0,2) -ne '\\'){
			Throw "_RemoteLogFolder has to be remote share but current value is $Value"
		}
		# Test access for the remote share
		If(!([string]::IsNullOrEmpty($Value)) -and !(Test-Path -Path $Value)){
			Throw "Unable to access to `'$Value`'."
		}
	}
	# Validate parameters for monitoring
	If($FwIsMonitoringEnabledByConfigFile){
		# _PortDest => _PortDestServerName needs to be configured.
		$Value = $FwConfigParameters['_PortDest']
		If(![string]::IsNullOrEmpty($Value)){
			$PortDestServerName = $FwConfigParameters['_PortDestServerName']
			If([string]::IsNullOrEmpty($PortDestServerName)){
				Throw ("_PortDestServerName needs to be configured.")
			}
		}
		# _ProcessName => _ProcessName should not contain '.exe'.
		$Value = $FwConfigParameters['_ProcessName']
		If(![string]::IsNullOrEmpty($Value) -and $Value.contains('.exe')){
			Throw ("_ProcessName($Value) cannot take name with `'.exe`'.")
		}
		# _ShareName => _ShareServerName must be specified.
		$Value = $FwConfigParameters['_ShareName']
		If(![string]::IsNullOrEmpty($Value)){
			$ShareServerName = $FwConfigParameters['_ShareServerName']
			If([string]::IsNullOrEmpty($ShareServerName)){
				Throw ("_ShareServerName needs to be configured.")
			}
		}
		# _CommonTCPPort => it must be one of 'RDP', 'SMB', 'HTTP' and 'WINRM'
		$Value = $FwConfigParameters['_CommonTCPPort']
		If(![string]::IsNullOrEmpty($Value)){
			If(!(($Value -eq 'SMB') -or ($Value -eq 'HTTP') -or ($Value -eq 'RDP') -or ($Value -eq 'WINRM'))){
				Throw ("_CommonTCPPort($Value) must be one of 'RDP', 'SMB', 'HTTP' and 'WINRM'.")
			}Else{
				$CommonTCPPortServerName = $FwConfigParameters['_CommonTCPPortServerName']
				If([string]::IsNullOrEmpty($CommonTCPPortServerName)){
					Throw ("_CommonTCPPortServerName needs to be configured.")
				}
			}
		}
		# _RegDataKey => _RegDataValue and _RegDataExpectedData are required.
		$Value = $FwConfigParameters['_RegDataKey']
		If(![string]::IsNullOrEmpty($Value)){
			$RegDataValue = $FwConfigParameters['_RegDataValue']
			$RegDataExpectedData = $FwConfigParameters['_RegDataExpectedData']
			If([string]::IsNullOrEmpty($RegDataValue) -or [string]::IsNullOrEmpty($RegDataExpectedData)){
				Throw ("Both _RegDataValue and _RegDataExpectedData need to be configured.")
			}
		}
		# _RegValueKey => _RegValueValue is required.
		$Value = $FwConfigParameters['_RegValueKey']
		If(![string]::IsNullOrEmpty($Value)){
			$RegValueValue = $FwConfigParameters['_RegValueValue']
			If([string]::IsNullOrEmpty($RegValueValue)){
				Throw ("_RegValueValue needs to be configured.")
			}
		}
		# _EventlogName => _Stop_EventID is required.
		$Value = $FwConfigParameters['_EventlogName']
		If(![string]::IsNullOrEmpty($Value)){
			$StopEventID = $FwConfigParameters['_Stop_EventID']
			If([string]::IsNullOrEmpty($StopEventID)){
				Throw ("_Stop_EventID needs to be configured.")
			}
		}
		# _WaitTime => time should be number
		$Value = $FwConfigParameters['_WaitTime']
		If(![string]::IsNullOrEmpty($Value)){
			$Token = $Value -split ':'
			If(![int]::TryParse($Token[0],[ref]$Null)){
				Throw ("_WaitTime can take only number but `'$($Token[0])`' was specified.")
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ReadParameterFromTSSReg{
	EnterFunc $MyInvocation.MyCommand.Name
	If(!(Test-Path "$global:TSSParamRegKey")){
		LogInfoFile "[ReadParameterFromTSSReg] There are no parameter settings in TSS registry."
		Return $Null
	}Else{
		If(!$Status.IsPresent){ # In case of -Status, we don't want to show this message to make console log simple.
			LogInfoFile "Reading parameters from TSS registry." -ShowMsg
		}
		$ParamArray = Get-Item "$global:TSSParamRegKey" | Select-Object -ExpandProperty Property -ErrorAction Ignore
		$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
		ForEach($Param in $ParamArray){
			$Data = $RegValue.$Param

			# Convert string boolean to boolean
			If($Data -eq "True"){
				$Data = $True
			}ElseIf($Data -eq "False"){
				$Data = $False
			}
			# Load data as a string array if data has delimiter(,).
			If($Data.gettype().Name -eq 'String'){
				If($Data.contains(',')){
					$Data = $Data -split ','
				}
			}
			LogInfoFile ('  - $' + "$Param($(($Data.gettype()).Name)) = $Data")
			Set-Variable -Name $Param -Value $Data -Scope Script
			If(!($global:BoundParameters.ContainsKey($Param))){
				$global:BoundParameters.Add($Param,$Data)
			}
			If($global:ParameterArray -notcontains $Param){
				$global:ParameterArray += $Param
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function SaveParameterToTSSReg{
	EnterFunc $MyInvocation.MyCommand.Name
	# Save parameter to TSS registry
	ForEach($Key in $global:BoundParameters.Keys){
		If($Key -ne 'Start' -and $Key -ne 'StartAutoLogger' -and $Key -ne 'StartNoWait' -and  $Key -ne 'NewSession' -and $Key -ne 'DebugMode'){
			if($global:BoundParameters[$Key]) { SaveToTSSReg $Key $global:BoundParameters[$Key] }
		}
	}
	SaveToTSSReg 'LogFolder' $global:LogFolder
	EndFunc $MyInvocation.MyCommand.Name
}

Function RemoveParameterFromTSSReg{
	EnterFunc $MyInvocation.MyCommand.Name
	# Delete parameters saved in TSS registry
	If(Test-Path -Path $global:TSSParamRegKey){
		LogInfoFile "[TSS] Removing $global:TSSParamRegKey" "Gray" -ShowMsg
		Remove-Item $global:TSSParamRegKey -Force
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function Add-Path {
	<#
	.SYNOPSIS
	  Adds a Directory to the Current Path | Join-Path ?
	.DESCRIPTION
	  Add a directory to the current $ENV:path. This is useful for temporary changes to the path or, when run from your profile, for adjusting the path within your PowerShell prompt.
	.EXAMPLE
	  Add-Path -Directory "C:\Program Files\Notepad++"
	.PARAMETER Directory
	  The name of the directory to add to the current path.
	#>
	Param(
		[Parameter(
		 Mandatory=$True,
		 ValueFromPipeline=$True,
		 ValueFromPipelineByPropertyName=$True,
		 HelpMessage='What directory would you like to add?')]
		[Alias('dir')]
		[string[]]$Directory
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$Path = $env:PATH.Split(';')
	foreach ($dir in $Directory) {
		if ($Path -contains $dir) {
			LogInfoFile "$dir is already present in PATH."
		}else{
			if (-not (Test-Path $dir)) {
			LogInfoFile "$dir does not exist in the filesystem"
			}else{
				$Path += $dir
			}
		}
	}
	$env:PATH = [String]::Join(';', $Path)
	EndFunc $MyInvocation.MyCommand.Name
}

Function RunFunction{
	<#
	.SYNOPSIS
	 Runs a function passed through argument.
	.DESCRIPTION
	 Check if the passed function exists and if it is not called before, run the function.
	.EXAMPLE
	 RunFunction "CollectDev_TESTLog"
	 RunFunction "CollectDev_TESTLog" $RunOnce:$False  # Allows multiple execution.
	.PARAMETER FuncName
	 The name of the function to be executed.
	.PARAMETER RunOnce
	 Boolean to determine if the function is allowed to be executed more than onece.
	.PARAMETER ThrowException
	 Determines if an exception is thrown from this function.
	#>
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$True)]
		[String]$FuncName,
		[Parameter(Mandatory=$False)]
		[String]$ParamString,
		[Parameter(Mandatory=$False)]
		[Bool]$RunOnce = $True,
		[Parameter(Mandatory=$False)]
		[Bool]$ThrowException = $False
	)
	EnterFunc "$($MyInvocation.MyCommand.Name) with $FuncName"

	$Func = $Null
	$Func = Get-Command $FuncName -CommandType Function -ErrorAction Ignore # Ignore exception
	
	If($Null -ne $Func){
		$PreviouslyExecutedFunction = $Script:ExecutedFunctionList | Where-Object {$_ -eq $FuncName}
		If($Null -eq $PreviouslyExecutedFunction){
			LogDebug "Adding $FuncName to ExecutedFunctionList." "Yellow"
			$Script:ExecutedFunctionList.Add($FuncName)
		}Else{
			If($RunOnce){
				LogInfoFile "Skipping running $FuncName() as it is already run before."
				Return
			}
		}

		LogInfo "Calling $FuncName $ParamString" "Green"
		Try{
			If([string]::IsNullOrEmpty($ParamString)){
				& $FuncName
			}Else{
				& $FuncName $ParamString
			}
		}Catch{
			LogWarn "An error happened in $FuncName"
			LogException "An error happened in $FuncName" $_ $fLogFileOnly
			If($ThrowException){
				Throw $_.Exception.Message
			}
		}
	}Else{
		LogDebug "$FuncName was not found."
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function PreRequisiteCheckInStage1{
	EnterFunc $MyInvocation.MyCommand.Name

	# Issue#331 - Disallow starting more than one TSS instance at the same time.
	If($global:ParameterArray -contains 'Start' -or $global:ParameterArray -contains 'StartAutoLogger' -or $global:ParameterArray -contains 'Stop' -or $global:ParameterArray -contains 'CollectLog' -or $global:ParameterArray -contains 'StartDiag'){
		$TSSProcesses = Get-CimInstance Win32_Process | Where-Object {$_.Commandline -like "*$($global:ScriptName)*-NewSession*"}
		If($Null -ne $TSSProcesses){
			$MyPID = $PID  # $PID is built-in env value that has PID of this instance of PowerShell.exe.
			ForEach($TSSProcess in $TSSProcesses){
				If($MyPID -ne $TSSProcesses.ProcessId){
					LogInfo "ERROR: Currently another instance of TSS is running with PID $($TSSProcesses.ProcessId)." "Red"
					if (($global:ParameterArray -contains 'Stop')) {
						LogInfo "User initiated stop. Sending Stop Trigger (System EventID 999) to terminate current TSS data collection."
						Write-EventLog -LogName 'System' -EntryType Error -Source "EventLog" -EventId 999 -Message "This is user initiated StopMe Event ID: 999 from script TSS in order to stop data collection. Event was sent by user $Env:username on computer $Env:Computername" -Category 1 -ComputerName $Env:Computername
					}
					CleanupAndExit
				}
			}
		}
	}

	# First thing we need to check is 'Constrained Language Mode' as this prevents most .net types from being accessed and it is very critical for this script.
	# https://devblogs.microsoft.com/PowerShell/PowerShell-constrained-language-mode/
	$ConstrainedLanguageMode = $ExecutionContext.SessionState.LanguageMode
	$LockdownPolicy = $Env:__PSLockdownPolicy
	If($ConstrainedLanguageMode -ne 'FullLanguage'){
		If($Null -eq $LockdownPolicy){
			$fIsLockdownByEnvironmentVariable = $False
		}Else{
			$fIsLockdownByEnvironmentVariable = $True
		}
	
		LogInfo ("Current constrained language mode is `'" + $ConstrainedLanguageMode + "`' but this script must be run with `'FullLanguage`' mode.") "Red"
		Write-Host ('Please ask administrator why $ExecutionContext.SessionState.LanguageMode is set to ' + $ConstrainedLanguageMode + '.') -ForegroundColor Red
		Write-Host ' '
		If($fIsLockdownByEnvironmentVariable){
			Write-Host ("To fix this issue, remove `'__PSLockdownPolicy`' environment valuable.")
			Write-Host ' '
		}
		CleanUpandExit
	}

	# Elevation Check
	# This script needs to be run with administrative privilege except for -CollectLog.
	If(((IsStart) -or $global:BoundParameters.ContainsKey('Stop')) -and !$noAdminChk.IsPresent){
		FwRunAdminCheck
	}

	# Disabling quick edit mode as somethimes this causes the script stop working until enter key is pressed.
	If($fQuickEditCodeExist){
		[DisableConsoleQuickEdit]::SetQuickEdit($True) | Out-Null
	}

	# Validate tss script version - timebomb if older than 30 days, but exclude -Update
	If( !$Update.IsPresent){
		$TSSver = $global:TssVerDate.SubString(0,10)
		$dateTSSver = [DateTime]($TSSver)
		$DiffDate = ((Get-Date) - $dateTSSver )
		If($DiffDate.Days -gt 30){
			LogError "TSS script is outdated more than 30 days. Please -Update or download latest version: 'https://aka.ms/getTSS' or 'https://cesdiagtools.blob.core.windows.net/windows/TSS.zip'"
			If( !$noExpire.IsPresent){ CleanUpandExit }else{LogWarn "..allowing to continue by switch -noExpire = $noExpire"}
		}
	}

	# At this moment, we don't support multiple scenario traces.
	If($Scenario.Count -gt 1){
		LogInfo "Currently multiple scenarios ($Scenario) are not supported." "Red"
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function PreRequisiteCheckInStage2{
	<#
	.SYNOPSIS
	 Inspects traces to be started
	.DESCRIPTION
	 Make sure $LogCollector is not empty and number of traces to be started does not exceed system limitation which is currently 55 sessions.
	#>
	EnterFunc $MyInvocation.MyCommand.Name
	
	# In stage2, we have $global:ParameterArray and $LogFolderPath initialized

	# Parameter compatibility check
	Try{
		CheckParameterCompatibility
	}Catch{
		LogError "Detected compatibility error. Exiting..."
		CleanUpandExit
	}

	# Check if command line has deprecated parameters.
	Try{
		CheckDeprecatedParam
	}Catch{
		LogError "Detected deprecated parameter. Exiting..." "Gray"
		CleanUpandExit
	}

	# Check if reg.exe is disabled. If it is, temporary enable it by setting DisableRegistryTools=0.
	If((IsStart) -or $Stop.IsPresent -or ![string]::IsNullOrEmpty($CollectLog) -or ![string]::IsNullOrEmpty($StartDiag)){
		If($global:OriginalDisableRegistryTools -gt 0){
			LogInfo "Registry editing has been disabled by your administrator. Current value of Reg-Key DisableRegistryTools = $OriginalDisableRegistryTools" "Cyan"
			ToggleRegToolsVal 0
		}
		If((-not ($Null -eq $global:OriginalNetShRegistry1)) -and (IsStart) ){
			LogInfo "Registry key for NetSh.exe had been added by RSAT tools. Current value of Reg-Key HKLM\SOFTWARE\Microsoft\NetSh\1 = $OriginalNetShRegistry1 `n Reverting this setting temporarily to allow NetSh tracing." "Cyan"
			Remove-ItemProperty -ErrorAction Ignore -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh -Name 1 -Force
		}
	}

	# Validate script folder name
	#if (($global:ScriptFolder -match '\s' ) -or ($global:ScriptFolder -match '[()]') ) {
	#	write-host -ForegroundColor red "TSS script path contains spaces or brackets or exclamation mark. Please rename/correct the TSS path: '$ScriptFolder'"
	#	CleanUpAndExit
	#}

	# Log folder check. It must be other than profile in case of -StartAutoLogger.
	If($StartAutoLogger.IsPresent -and ![string]::IsNullOrEmpty($LogFolderPath)){
		if($LogFolderPath -like "C:\Users\*"){
			LogError "Setting log folder under profile($LogFolderPath) is not supported in case of -StartAutoLogger. Please specify somewhere other than profile(ex. -LogFolderPath D:\MS_DATA)."
			CleanUpAndExit
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function PreRequisiteCheckForStart{
	EnterFunc $MyInvocation.MyCommand.Name

	# Do admin check again as it is possible for traces to be started without -Start switch now.
	# In this case, admin check in PreRequisiteCheckInStage1 is passed and we need to run admin check at this timing again.
	If($global:ParameterArray -notcontains 'noAdminChk'){
		FwRunAdminCheck
	}

	# Running TSS on x64 system with x86 powershell.exe may fail later.(#591)
	If (![Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem){
		LogError "Windows PowerShell Workflow is not supported in a Windows PowerShell x86-based console. Open a Windows PowerShell x64-based console, and then try again."
		CleanUpandExit
	}

	If(!$StartAutoLogger.IsPresent -and ($global:ParameterArray -contains 'PSR' -or $global:ParameterArray -contains 'Video' -and $global:ParameterArray -notcontains 'noRecording')){
		FwPlaySound
		LogInfo "Note for this step:`n If you do not agree on Recording, the solution for your issue might be delayed a lot, because MS support engineer needs to match the time (hh:mm:ss) of your problem (error message) exactly with the time stamps in debug data." "Magenta" -noDate
		LogInfo "[Action-Privacy] We need your consent to allow Problem Step Recording and-or Screen-Video recording, please enter Y or N" "Cyan" -noDate
		# Issue#373 - TSS hang in ISE
		$Answer = FwRead-Host-YN -Message "Press Y for Yes = allow recording, N for No (timeout=20s)" -Choices 'yn' -TimeOut 20
		#CHOICE /T 20 /C yn /D y /M " Press Y for Yes = allow recording, N for No "
		If(!$Answer){
			LogInfoFile "=== User declined screen recording/video ==="
			LogInfo "Run script with -noPSR, -noVideo or -noRecording again if you don't want your session to be recorded" "Red" -noDate
			CleanUpandExit
		}
	}
	
	# PSR.exe might be missing on some systems
	If($global:ParameterArray -contains 'PSR'){
		$PSRCommand = Get-Command $PSRProperty.CommandName -ErrorAction Ignore
		If($Null -eq $PSRCommand){
			LogWarn "$($PSRProperty.CommandName) not found."
			$RemovePSR = $True
		}
		If($RemovePSR){
			LogInfoFile "Removing -PSR from parameter list and will continue without running ProblemStepRecorder." "Gray" -ShowMsg
			$global:ParameterArray = RemoveItemFromArray $global:ParameterArray "PSR"
			$TraceObject = $LogCollector | Where-Object {$_.Name -eq 'PSR'}
			If($Null -ne $TraceObject){
				$LogCollector.Remove($TraceObject) | Out-Null
			}
		}
	}
	# Video
	If($global:ParameterArray -contains 'Video'){
		LogInfoFile "Overview for Video - Current Caption/ScreenResolution:"	#  for Hyper-V VMs (in enhanced Mode?)
		(Get-CimInstance win32_videocontroller | select caption, CurrentHorizontalResolution, CurrentVerticalResolution) | Out-File -Append $global:ErrorLogFile 
		$ScreenRes = (Get-CimInstance -Class Win32_DesktopMonitor | Select-Object ScreenWidth,ScreenHeight)
		LogInfoFile "Screen Resolution (for Video): $($ScreenRes.ScreenWidth) x $($ScreenRes.ScreenHeight)"
		If(!(Test-Path "HKLM:\Software\Microsoft\NET Framework Setup\NDP\v3.5")){
			LogInfo "-Video requires .NET 3.5 but not installed on this system." "Magenta"
			LogInfo "To download .NET Framework 3.5:"
			LogInfo "  1. Go to https://www.microsoft.com/download/details.aspx?id=21"
			LogInfo "  2. Select language and click [Download] button then install it manually."
			$RemoveVideo = $True
		}
		$VideoCommand = Get-Command $VideoProperty.CommandName -ErrorAction Ignore
		If($Null -eq $VideoCommand){
			LogWarn "$($VideoProperty.CommandName) not found."
			$RemoveVideo = $True
		}
		If($RemoveVideo){
			LogInfoFile "Removing -Video from parameter list and will continue without recording video." "Gray" -ShowMsg
			$global:ParameterArray = RemoveItemFromArray $global:ParameterArray "Video"
			$TraceObject = $LogCollector | Where-Object {$_.Name -eq 'Video'}
			If($Null -ne $TraceObject){
				$LogCollector.Remove($TraceObject) | Out-Null
			}
		}
	}
	#TTD on downlevel OS
	If($global:ParameterArray -contains 'TTD' -and ($global:OSVersion.Build -lt 17763)){
		SearchTTTracer
		If(!$Script:TTDFullPath){
			LogDebug "TTDFullPath: $Script:TTDFullPath notfound"
			Write-Host -ForegroundColor Magenta "The command '-TTD $TTD' would require the TSS_TTD.zip, please ask Microsoft engineer to provide this package."
			Write-Host -ForegroundColor Red "In this TSS data collection, the TTD trace will NOT be recorded!"
			$Answer = FwRead-Host-YN -Message ". Do you want to continue anyways without TTD trace? (timeout=20s)" -Choices "yn" -Timeout 20 -Default 'n'
			If(!$Answer){
				LogInfo "Exiting script."
				CleanUpandExit
			}
		}		
	}

	# See if external commands exist. If not, remove the command from LogCollector.
	$RemovedExternalCommandList = New-Object 'System.Collections.Generic.List[Object]'
	ForEach($ExternalCommand in $ExternalCommandList.Keys){
		If($global:BoundParameters.ContainsKey($ExternalCommand)){
			$Command = Get-Command $ExternalCommandList[$ExternalCommand] -ErrorAction Ignore
			If($Null -eq $Command){
				$global:ParameterArray = RemoveItemFromArray $global:ParameterArray $ExternalCommand
				$global:BoundParameters.Remove($ExternalCommand) | Out-Null
				$TraceObject = $LogCollector | Where-Object {$_.Name -eq $ExternalCommand}
				If($Null -ne $TraceObject){
					$LogCollector.Remove($TraceObject) | Out-Null
					$RemovedExternalCommandList.Add($ExternalCommand)
				}
			}
		}
	}

	If($RemovedExternalCommandList.count -gt 0){
		If($global:IsLiteMode){
			LogInfo "You are using Lite version of TSS. Below log(s) will be not collected." "Magenta"
			LogInfo "Please download full version of TSS from 'https://aka.ms/getTSS' to collect all logs." "Magenta"
		}Else{
			LogInfo "Below command(s) is/are not available on this machine. TSS will not collect expected data/logs." "Magenta"
		}
		ForEach($RemovedExternalCommand in $RemovedExternalCommandList){
			LogInfo "  - $RemovedExternalCommand" "Magenta"
		}
	}

	# Xperf
	If($global:ParameterArray -contains 'Xperf'){
		$Xperf = $global:BoundParameters['Xperf']
		$XperfTag = $global:BoundParameters['XperfTag']
		$XperfPIDs = $global:BoundParameters['XperfPIDs']

		Switch($Xperf){
			'Pool' {
				If([String]::IsNullOrEmpty($XperfTag)){
					LogError "Xperf with Pool profile needs -XperfTag switch. Please run with `'-Xperf $Xperf -XperfTag <PoolTag>`'."
					LogInfo "Ex.: .\$($global:ScriptName) -Xperf Pool -XperfTag TcpE+AleE+AfdE+AfdX" "Yellow"
					CleanUpAndExit
				}
			}
			'PoolNPP' {
				If([String]::IsNullOrEmpty($XperfTag)){
					LogError "Xperf with PoolNPP profile needs -XperfTag switch. Please run with `'-Xperf $Xperf -XperfTag <PoolTag>`'."
					CleanUpAndExit
				}
			}
			'Leak' {
				If([String]::IsNullOrEmpty($XperfPIDs)){
					LogError "Xperf with Leak profile needs -XperfPIDs switch. Please run with `'-Xperf $Xperf -XperfPIDs <PID>`'."
					CleanUpAndExit
				}
			}
		}
	}

	# Sysmon
	If($global:BoundParameters.ContainsKey('SysMon')){

		# To see if sysmon was enabled by TSS, we check if 'Sysmon' service is running and also the 'sysmon' is stored in TSS reg.
		$SysMonService = Get-Service -Name "SysMon" -ErrorAction Ignore

		If($Null -ne $SysMonService){
			$RegValues = Get-ItemProperty -Path  $global:TSSParamRegKey -ErrorAction Ignore
			If($Null -eq $RegValues.SysMon){
				LogWarn "Detected running SysMon started from outside of TSS. TSS will NOT restart and stop the running SysMon."
				LogInfo "=> To stop running SysMon, run `'SysMon.exe -u -nobanner`' manually." "Cyan"
				If(!$noAsk.IsPresent){
					FwPlaySound
					$Answer = FwRead-Host-YN -Message "Do you want to continue? (timeout=20s)" -Choices 'yn' -TimeOut 20
					If(!$Answer){
						LogInfo "Exiting script."
						CleanUpandExit
					}
				}
				LogInfo "Removing -SysMon from script parameter."
				$global:ParameterArray = RemoveItemFromArray $global:ParameterArray 'SysMon'
				$global:BoundParameters.Remove('SysMon') | Out-Null
				# Remove SysMon from $LogCollector which is the list of traces to be collected.
				$TraceObject = $LogCollector | Where-Object {$_.Name -eq 'SysMon'}
				If($Null -ne $TraceObject){
					$LogCollector.Remove($TraceObject) | Out-Null
				}
			}
		}
	}

	# WaitEvent
	If($global:BoundParameters.ContainsKey('WaitEvent')){
		$Token = ($global:BoundParameters['WaitEvent']) -split ':'
		$EventType = $Token[0]
		Switch ($EventType){
			'LogFile' {
				$FileName = ($Token[1] + ':' + $Token[2])
				If(!(Test-Path -Path $FileName)){
					LogError "-WaitEvent was specified but passed file `'$FileName`' does not exist."
					CleanUpAndExit
				}
			}
		}
	}

	# Remoting
	If($global:IsRemoting){
		# Check if RemoteRegistry is running
		$SvcStatus = ((Get-Service 'RemoteRegistry' -ErrorAction Ignore).Status)
		If($SvcStatus -ne [System.ServiceProcess.ServiceControllerStatus]::Running){
			LogWarn "RemoteRegistry needs to be enabled for Remoting feature to work properly."
			FwPlaySound
			Write-Host ' '
			$Answer = FwRead-Host-YN -Message "Do you want to start 'RemoteRegistry' service now"
			If($Answer){ # Yes
				Try{
					Start-Service -Name "RemoteRegistry" -ErrorAction Stop
					LogInfo "RemoteRegistry service started."
				}Catch{
					LogError "Unable to start 'RemoteRegistry' service. Please check if the service is disabled by policy."
					CleanUpAndExit
				}
			}Else{ # No
				LogInfoFile "=== User declined to start 'RemoteRegistry' service ==="
				LogError "Enable 'RemoteRegistry' service manually and then run the script again."
				CleanUpAndExit
			}
		}

		# Check if Firewall rules for remoting are enabled.
		$FWRuleEnabled = $True
		$script:FWRuleArray = @()
		$RulesRemoteEventLogSvc = Get-NetFirewallRule -Name "RemoteEventLogSvc*" -ErrorAction Ignore
		ForEach($RuleRemoteEventLogSvc in $RulesRemoteEventLogSvc){
			If($RuleRemoteEventLogSvc.Enabled -eq "False"){
				$script:FWRuleArray += $RuleRemoteEventLogSvc
				$FWRuleEnabled = $False
			}
		}
		$RuleDCOMIN = Get-NetFirewallRule -Name "ComPlusNetworkAccess-DCOM-In" -ErrorAction Ignore
		If($Null -ne $RuleDCOMIN -and $RuleDCOMIN.Enabled -eq "False"){
			$script:FWRuleArray += $RuleDCOMIN
			$FWRuleEnabled = $False
		}

		If(!$FWRuleEnabled){
			LogWarn "Below Firewall rule(s) needs to be enabled for Remoting feature to work properly."
			ForEach($FWRule in $script:FWRuleArray){
				Write-Host "   - $($FWRule.DisplayName)"
			}
			FwPlaySound
			Write-Host ' '
			$Answer = FwRead-Host-YN -Message "Do you want to enable above firewall rules now"
			If($Answer){ # Yes
				ForEach($FWRule in $script:FWRuleArray){
					LogInfo "Enabling Firewall rule `'$($FWRule.DisplayName)`'"
					Try{
						$FWRule | Set-NetFirewallRule -Enabled True -ErrorAction Stop
					}Catch{
						LogError "Unable to enable Firewall rule. Remoting would not work on this system."
						CleanUpAndExit
					}
				}
			}Else{ # No
				LogInfoFile "=== User declined to enable above firewall rules ==="
				LogError "Enable above firewall rules manually and then run the script again."
				CleanUpAndExit
			}
		}

		$RemoteHosts = $global:BoundParameters['RemoteHosts']
		LogInfo "Testing if Write-EventLog work with specified remote hosts. This may take a while in case Firewall on remote host blocks the access."
		ForEach($RemoteHost in $RemoteHosts){
			Try{
				Write-EventLog -ComputerName $RemoteHost -LogName 'System' -EntryType Info -Source "Eventlog" -EventId 1 -Message "Test event from TSS ($Env:Computername)" -Category 1 -ErrorAction Stop
			}Catch{
				$Message = "Unable to write an event to $RemoteHost. Remoting would not work on specified remote hosts($RemoteHost)"
				LogError $Message
				LogException $Message $_ $True
				# Bail out(Reset enabled Firewall rules and exit). 
				If($script:FWRuleArray.Count -ne 0){
					ForEach($FWRule in $script:FWRuleArray){
						LogInfo "Disabling Firewall rule `'$($FWRule.DisplayName)`' setting as it was enabled temporary." "Gray"
						$FWRule | Set-NetFirewallRule -Enabled False
					}
					$script:FWRuleArray = $Null
				}
				CleanUpAndExit
			}
		}
	}

	# Check 1: Make sure $LogCollector is not empty.
	If($LogCollector.Count -eq 0){
		If($StartAutoLogger.IsPresent){
			LogInfo "ERROR: There are no traces that support AutoLogger in specified switch or scenario. Exiting." "Red"
		}Else{
			LogInfo 'ERROR: There are no traces to start. Please check switches you specified or scenario. Exiting.' "Red"
		}
		CleanUpandExit
	}

	# Check 2: Validate $LogCollector
	Try{
		ValidateCollection $LogCollector
	}Catch{
		LogException "An exception happened in ValidateCollection" $_
		CleanUpandExit
	}

	# Check 3: trace count. If it is more than 55 sessions, stop unnecessary sessions 
	#		  and see it gets less than 55 . It is still over 55 , show error and exit.
	If($LogCollector.count -ne 0){
		$ETWTracesObjectList = $LogCollector | Where-Object {$_.LogType -eq 'ETW'}
		If($Null -ne $ETWTracesObjectList -and $ETWTracesObjectList.count -ne 0){
			# Inspect the trace provider and count number of trace to be started.
			$TraceList = New-Object 'System.Collections.Generic.List[Object]'
			ForEach($ETWTracesObject in $ETWTracesObjectList){
				ForEach($Provider in $ETWTracesObject.Providers){
					If($Provider -like "*!*"){ # Multi etl
						$TraceFileName = ($Provider -split '!')[1]  # 2nd token is trace name
						$TraceName = $ETWTracesObject.Name + $TraceFileName
						$FoundTrace = $TraceList | Where-Object {$_ -eq $TraceName}
						If($Null -eq $FoundTrace){
							LogDebug "1(METL): Adding $TraceFileName in $($ETWTracesObject.Name) to TraceList"
							$TraceList.Add($TraceName)
						}
					}Else{ # Normal trace
						LogDebug "2(Normal): Adding $($ETWTracesObject.Name) to TraceList"
						$TraceList.Add($ETWTracesObject.Name)
						break
					}
				}
			}
		}Else{
			LogDebug "No ETW traces found."
		}

		$TSSTraceCount = $TraceList.Count

		# Add ETW session count for commands
		ForEach($Key in $ETWSessionCountForCommand.Keys){
			$CommandTraceObject = $Null
			$CommandTraceObject = $LogCollector | Where-Object {$_.Name -eq $Key}
			If($Null -ne $CommandTraceObject){
				LogDebug "3(Tool): Adding $Key with trace count ($($ETWSessionCountForCommand[$Key])) to TSSTraceCount"
				$TSSTraceCount += $ETWSessionCountForCommand[$Key]
			}
		}

		# Get number of existing trace sessions
		$EtwMaxLoggers = FwGet-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI" -Value EtwMaxLoggers
		If($EtwMaxLoggers){
			$MaxETWSessionCount = $EtwMaxLoggers
			LogInfoFile "Defined Registry Value: EtwMaxLoggers = $EtwMaxLoggers"
		}else{$MaxETWSessionCount = 55}
		#$MaxETWSessionCount = 55	#we# was 56, system wide max number of ETW Trace sessions, can be raised by registry HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\EtwMaxLoggers and reboot
		$RunningSessionList = $Null
		$RunningSessionList = GetETWSessionByLogman [PreRequisiteCheckInStage2]
		GetETWSessionByPS [PreRequisiteCheckInStage2]
		$SessionCount = $RunningSessionList.Count
		$TotalExpectedTraceCount = $SessionCount + $TSSTraceCount + 3	#we# +3, as Network scenarios often fail with error 1450 = ERROR_NO_SYSTEM_RESOURCES, as i.e. netsh needs an additional session
		LogInfoFile "No. of TSS trace sessions expected=$TSSTraceCount / Existing running sessions=$SessionCount"
		If($TotalExpectedTraceCount -gt $MaxETWSessionCount){
			LogInfo "Number of trace sessions ($TSSTraceCount for TSS plus $SessionCount for existing sessions) will exceed system wide max number of session ($MaxETWSessionCount). Trying to stop unnessessary running ETW sessions."
			# Stopping unnecessary sessions
			$DeletedTraceCount=0
			ForEach($RunningSession in $RunningSessionList){
				Write-Output "Running logman.exe -stop $RunningSession -ets" | Out-File -Append "$global:LogFolder\Stopped-ETWSessionList.txt"
				Write-Output "logman.exe -stop $RunningSession -ets" | Out-File -Append "$global:LogFolder\LogManStop.cmd"
				logman.exe -stop $RunningSession -ets | Out-File -Append "$global:LogFolder\Stopped-ETWSessionList.txt"
				If($LASTEXITCODE -eq 0){
					$DeletedTraceCount++
				}
			}
			LogWarn "$DeletedTraceCount traces have been stopped to create room to run TSS. See `'Stopped-ETWSessionList.txt`' in $global:LogFolder to see stopped traces."

			# Double check if we have enough space to run etw trace by TSS.
			$RunningSessionList = $Null
			$RunningSessionList = GetETWSessionByLogman [PreRequisiteCheckInStage2-2]
			GetETWSessionByPS [PreRequisiteCheckInStage2-2]
			$SessionCount = $RunningSessionList.Count
			$TotalExpectedTraceCount = $SessionCount + $TSSTraceCount + 3	#we# +3
			# If total number of session is still larger than $MaxETWSessionCount, show error message and exit.
			If($TotalExpectedTraceCount -gt $MaxETWSessionCount){
				LogError "Number of trace session($TSSTraceCount for TSS and $SessionCount for existing sessions) will be $TotalExpectedTraceCount and it exceeds system total maximum number of session($MaxETWSessionCount)."
				Write-Host "Please try manually run $global:LogFolder\LogManStop.cmd from elevated commpand prompt to reduce running ETW sessions. And then run TSS again."
				Write-Host "> $global:LogFolder\LogManStop.cmd" -ForegroundColor Yellow
				CleanUpAndExit
			}
		}

		# Check 4: Check if there is enough free space
		$LogDrive = $global:LogFolder.Substring(0, 1)
		LogDebug "Log drive is $LogDrive drive (Log folder = $global:LogFolder)"
		If($LogDrive -eq "\"){
			$FreeInMB = $Null # This is network drive and we won't calculate free size in this case.
		}Else{
			$Drive = Get-PSDrive $LogDrive
			$FreeInMB = [Math]::Ceiling(($Drive.Free / 1024 / 1024))
		}

		If($Null -ne $FreeInMB){
			$EstimatedLogSizeInMB = CalculateLogSize
			If($Null -ne $EstimatedLogSizeInMB){
				# Show calculated size and if it is larger than available space, ask user if he wants to continue.
				LogInfo ("Estimated overall max log size = " + [Math]::Ceiling($EstimatedLogSizeInMB / 1024) + "GB (Free size of $Drive drive = " + [Math]::Ceiling($FreeInMB / 1024) + "GB)`n") "Green"
				If($EstimatedLogSizeInMB -gt $FreeInMB){
					LogInfo ("$global:ScriptPrefix may consume " + $EstimatedLogSizeInMB / 1024 + "GB at the maximum but free size of $Drive drive is " + [Math]::Ceiling($FreeInMB / 1024) + "GB.") "Magenta"
					LogInfo ("You can change log folder using -LogFolderPath switch.") "Cyan"
					LogInfo ("Example: .\$($global:ScriptName) -Start -<TraceSwitch> -LogFolderPath D:\MS_DATA") "Cyan"
					FwPlaySound
					# Issue#373 - TSS hang in ISE
					$Answer = FwRead-Host-YN -Message "Do you want to continue Collecting data?" -Choices 'yn'
					#CHOICE /C yn /M " Do you want to continue Collecting data? "
					If(!$Answer) {
						LogInfo "Exiting script."
						CleanUpAndExit
					}
				}
			}
		}
	}Else{
		LogDebug "Logcollector is empty."
		Return
	}

	# Check 5: Validate script folder name
	#if (($global:ScriptFolder -match '\s' ) -or ($global:ScriptFolder -match '[()]') ) {
	#	write-host -ForegroundColor red "TSS script path contains spaces or brackets or exclamation mark. Please rename/correct the TSS path: '$ScriptFolder'"
	#	CleanUpAndExit
	#}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CalculateLogSize{
	[OutputType([Int])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name

	If($LogCollector.Count -eq 0){
		LogError "$LogCollector has not been initialized yet."
		Return $Null
	}

	# -WPR
	If($global:BoundParameters.ContainsKey('WPR')){
		LogInfo "WARNING: WPR might consume large amount of free disk space if you run for long term. Use -Xperf instead in case you need to limit disk usage." "Magenta"
		LogInfo "Ex: .\$($global:ScriptName) -Xperf General -XperfMaxFileMB 10240  # Limit log size to 10GB" "Yellow"

		# Below calculation is applicable for in-memory mode but we use it for file mode as well since we don't have formula for file mode.
		$MemorySizeInGB = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).Sum /1gb
		$LogSizeInGB.WPR = [Math]::Round(($MemorySizeInGB * 0.8), [MidpointRounding]::AwayFromZero)  # 80% of total amount of physical memory.(Issue#407)
	}

	# -Xperf
	If($global:BoundParameters.ContainsKey('XperfMaxFileMB')){
		$XperfMaxSizeInGB = [Math]::Round(($global:BoundParameters['XperfMaxFileMB'] / 1024), [MidpointRounding]::AwayFromZero)
		If([String]::IsNullOrEmpty($XperfMaxSizeInGB) -or $XperfMaxSizeInGB -le 0){
			$XperfMaxSizeInGB = 2
		}
		$LogSizeInGB.Xperf = $XperfMaxSizeInGB
	}else{ If($Xperf -match "SBSL") {$LogSizeInGB.Xperf = 16} }

	# -Crash (Full memory dump) #751
	If($global:BoundParameters.ContainsKey('crash')){
		$MemorySizeInGB = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).Sum /1gb
		$LogSizeInGB.crash = [Math]::Round(($MemorySizeInGB * 1.0), [MidpointRounding]::AwayFromZero)  # 100% of total amount of physical memory.
	}

	# -PerfMon
	If(($global:BoundParameters.ContainsKey('PerfMon')) -or ($global:BoundParameters.ContainsKey('PerfMonLong'))){
		$PerfMonMaxSizeInGB = [Math]::Round(($global:BoundParameters['PerfmonMaxMB'] / 1024), [MidpointRounding]::AwayFromZero)
		If([String]::IsNullOrEmpty($PerfMonMaxSizeInGB) -or $PerfMonMaxSizeInGB -le 0){
			$PerfMonMaxSizeInGB = 2
		}
		$LogSizeInGB.PerfMon = $PerfMonMaxSizeInGB
	}
	
	# Calculate estimated log size and if free size of log drive is not enough, show warning message
	$EstimatedLogSize = 0
	If($LogCollector.Count -ne 0){
		# 1. We calculate size of all ETW traces. It is calculated with 2GB per a trace.
		$ETWTraceObjects = $LogCollector | Where-Object {$_.LogType -eq 'ETW'}
		$EstimatedLogSizeInMB = $ETWTraceObjects.Count * $Script:ETLMaxSize # $Script:ETLMaxSize = 1024MB by default
		LogDebug ("Added " + [Math]::Ceiling($EstimatedLogSizeInMB / 1024) + "GB for ETW")

		# Caluculate size of multiple etl file trace.
		ForEach($TraceObject in $ETWTraceObjects){
			$ETLFileList = New-Object 'System.Collections.Generic.List[PSObject]'
			# Counting number of files in this trace provider list
			ForEach($TraceProvider in $TraceObject.Providers){
				$Token = $TraceProvider -split '!'
				If($Token.Count -gt 1){
					$EtlFile = $Token[1] # 2nd token is etl file name
					$EtlFileInFileList = $ETLFileList | Where-Object {$_ -eq $EtlFile}
					If($Null -eq $EtlFileInFileList){
						$ETLFileList.Add($EtlFile)
					}
				}
			}
			If($ETLFileList.Count -gt 1){
				# Multiple etl files case
				$EstimatedLogSizeInMB += (($ETLFileList.Count - 1) * $Script:ETLMaxSize)
				LogInfoFile ("Found multi etl files trace($($TraceObject.Name)). This trace contains $($ETLFileList.Count) files and adding " + (($($ETLFileList.Count)-1) * $Script:ETLMaxSize / 1024) + "GB")
				#LogDebug ("Found multi etl files trace($($TraceObject.Name)). This trace contains $($ETLFileList.Count) files and adding " + (($($ETLFileList.Count)-1) * $Script:ETLMaxSize / 1024) + "GB")
			}
		}

		# 2. Add log size for command switch
		ForEach($Key in $CommandSwitches.Keys){
			If($global:ParameterArray -Contains $Key){
				LogDebug "Adding $($LogSizeInGB.$Key)GB for $Key"
				$EstimatedLogSizeInMB += ($LogSizeInGB.$Key * 1024)
			}
		}
	}
	LogInfoFile ("Estimated longterm data Log size = " + [Math]::Ceiling($EstimatedLogSizeInMB / 1024) + "GB")
	EndFunc ($MyInvocation.MyCommand.Name + "($EstimatedLogSizeInMB)")
	Return $EstimatedLogSizeInMB
}

Function ProcessHelp{
	Param(
		[parameter(Mandatory=$False)]
		[String]$Ans,		# passed by ProcessFindKeyword
		[Switch]$SkipMenu	# skip display Help/Menue - for switch -Find <keyword>
	)
	EnterFunc $MyInvocation.MyCommand.Name
$HelpMessage = @"

[Help] Starting traces (-Start)
-------------------------------
[Help] Public KB: https://aka.ms/TSSv2 -or- https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-troubleshooters/introduction-to-troubleshootingscript-toolset-tssv2
[Help] Be sure you run TSS in a regular elevated/Admin PowerShell window. Running TSS in PowerShell ISE is not supported.

[Help] The verb -Start will start ETW component trace(s) or support tools such as -WPR. 
[Help] The verb [-Start] is optional, but it could be replaced by complementary start options.
[Help] Complementary start verbs are: -StartAutoLogger, -StartDiag, -StartNoWait, -CollectLog
[Help] Logs related to the traces are also automatically collected when stopping the data collection.

[Help] => ETW trace components + Support tools + Data collection + Diag system

[Syntax] Syntax in this help:
-----------------------------
[Syntax]  <placeholder>  means the string in <angle brackets> for placeholder needs to be substituted with an actual ScenarioName, trace-component, command or value
[Syntax]  [optional]     the keyword/value in [square brackets] is optional, i.e. [module:int] means the module and interval are optional, default values are used if [<xx>:<yy>] are omitted.
[Syntax]  '|'            means 'or', choose one of the available options
[Syntax]  ':'            is the separator character between two values
[Syntax]   example:  -PerfMon [General:10] means PerfMon CounterSetName= 'General' and Interval= '10' seconds, when omitted, the defaults kick in, so -PerfMon has same effects as -PerfMon General -PerfIntervalSec 10
[Syntax]   example:  [-StopWaitTimeInSec <N>] means that the argument -StopWaitTimeInSec is optional, but if specified then a value for <N> ='number of seconds' is mandatory

[ETW] ETW trace:
----------------
[ETW]   1. Enabling a scenario trace:
[ETW]     PS> .\$($global:ScriptName) -Scenario <ScenarioName>
[ETW]     * supported <ScenarioName>s are listed with '$($global:ScriptName) -ListSupportedScenarioTrace'

[ETW]   2. Enabling component traces:
[ETW]     PS> .\$($global:ScriptName) <-ComponentName> <-ComponentName> ...
[ETW]     * supported <-ComponentName>s is listed with '$($global:ScriptName) -ListSupportedTrace'

[ETW]   3. Starting traces with no-wait mode (-Start -StartNoWait + -Stop):
[ETW]     [-Start]
[ETW]      PS> .\$($global:ScriptName) -StartNoWait -Scenario <ScenarioName> 
[ETW]      Note: prompt returns immediately so you can log off or use i.e. 'Shutdown'
[ETW]     [-Stop]
[ETW]      PS> .\$($global:ScriptName) -Stop

[ETW]       To list all provider Guids of components and/or scenarios, use -ListETWProviders
[ETW]         PS> .\$($global:ScriptName) -ListETWProviders <component-/scenario-name>

[Tools] Support tools:
----------------------
[Tools] Starting support tools/commands (ProcMon, ProcDump, netsh, Performance Monitor (PerfMon), WPR, Radar, etc.)
[Tools] PS> .\$($global:ScriptName) -WPR <WPRprofile> -Procmon -Netsh|-NetshScenario <NetshScenario> -PerfMon <CounterSetName> -ProcDump <PID> -PktMon -SysMon -SDP <specialty> -xray -PSR -Video -TTD <PID[]|ProcessName[]|ServiceName[]>

[Commands] COMMANDS
-------------------
[Commands]  -Crash                      - force a Full|Kernel memory dump (at stop trigger) - Attention: system will reboot
[Crash]      + -CrashMode <Full|Kernel> - choose the Memory.dmp dump type (TSS will use \BINx64\kdbgctrl.exe)
[Defender]   + -DefenderDurInMin <Duration in min> - set duration of Defender run time (default DefenderDurInMin=5 minutes)
[Commands]  -Fiddler                    - collect Fiddler trace 
[Fiddler]    Enable the traffic decryption option by clicking Tools > Options.. > Tab: HTTPS > and ticking the [x] 'Decrypt HTTPS Traffic' box.
[Commands]  -GPresult <Start|Stop|Both> - Collect gpresult, auditing and security info on start, stop or both.
[Commands]  -Handle <Start|Stop|Both>   - Collect SysInternals Handle.exe output on phase start, stop or both.
[Commands]  -LiveKD <Start|Stop|Both>   - start SysInternals LiveKD -ml (live kernel dump). Start: the dump is taken on start of repro. Stop: the dump is taken on stop. Both: the dump is taken on both start and stop.
[Commands]  -Netsh                      - start network packet capturing
[Netsh]      + -NetshOptions '<Option string>' - specify additional options for Netsh, i.e. 'capturetype=both captureMultilayer=yes provider=Microsoft-Windows-PrimaryNetworkIcon provider={1701C7DC-045C-45C0-8CD6-4D42E3BBF387}'
[Netsh]      + -NetshMaxSizeMB <Int>    - max log size for netsh in MB (Ex.: -NetshMaxSizeMB 4096), default=2048
[Netsh]      + -noPacket                - prevent packets from being captured with Netsh (only ETW traces in the ScenarioName will be captured)

[Commands]  -NetshScenario <ScenarioName[]>  - start netsh scenario trace. Supported <ScenarioName>s are listed with -ListSupportedNetshScenario
[NetshScenario] + -NetshOptions '<Option string>' - specify additional options for NetshScenario, i.e. 'capturetype=both captureMultilayer=yes provider=Microsoft-Windows-PrimaryNetworkIcon provider={1701C7DC-045C-45C0-8CD6-4D42E3BBF387}'
[NetshScenario] + -NetshMaxSizeMB <Int> - max log size for netsh in MB (Ex.: -NetshMaxSizeMB 4096), default=2048
[NetshScenario] + -noPacket             - prevent packets from being captured with Netsh (only ETW traces in the ScenarioName will be captured)
[Commands]  -PerfMon <CounterSetName> [-PerfIntervalSec N] [-PerfMonMaxMB <N>] [-PerfMonCNF <[[hh:]mm:]ss>] - start Performance Monitor log, (default PerfIntervalSec=10). <CounterSetName>s can be listed with -ListSupportedPerfCounter
[PerfMon]     + -PerfIntervalSec <Interval in sec> - set interval for the PerfMon log(default is 10 seconds)
[PerfMon]     + -PerfMonMaxMB <N>       - specify an Int value for maximum Perfmon Log size in MB, default=2048
[PerfMon]     + -PerfMonCNF <[[hh:]mm:]ss> - Create a New File when the specified time has elapsed or when the max size <PerfMonMaxMB> is exceeded.
[Commands]  -PerfMonLong <CounterSetName> [-PerfLongIntervalMin N] [-PerfMonMaxMB <N>] [-PerfMonCNF <[[hh:]mm:]ss>] - start Performance Monitor log, (default PerfLongIntervalMin=10). <CounterSetName>s can be listed with -ListSupportedPerfCounter
[PerfMon]     + -PerfLongIntervalMin <Interval in min> - set interval for the PerfMonLong log(default is 10 minutes)
[Commands]  -PerfTCP <Client|Server> -PerfTCPAddr <Server IP address>
[PerfTCP]    Starts an Ntttcp test consisting of a single threaded TCP transfer, followed by a multithreaded transfer, followed by a latency test
[PerfTCP]    + -BufferLength   - Optional size of buffer in kilobytes (default is 128K)
[PerfTCP]    + -Duration       - Optional length of time in seconds of both single and multithreaded tests (default is 60)
[PerfTCP]
[PerfTCP]    REQUIREMENTS:
[PerfTCP]        1. TSS command to be run on both client and server machines.
[PerfTCP]        2. Add the following firewall rules to allow inbound connections for ntttcp.exe and latte.exe on the server
[PerfTCP]           The TSS tool MUST be located at C:\TSS
[PerfTCP]           netsh advfirewall firewall add rule program=C:\TSS\BINx64\ntttcp.exe name="ntttcp" protocol=any dir=in action=allow enable=yes profile=ANY
[PerfTCP]           netsh advfirewall firewall add rule program=C:\TSS\BINx64\latte.exe name="latte" protocol=any dir=in action=allow enable=yes profile=ANY
[PerfTCP]        3. Ensure both <PerfTCPAddr> and <Duration> values are the same on both machines
[PerfTCP]        4. IMPORTANT: Instruct customer to start on SERVER machine first and wait for prompt before starting command on CLIENT machine
[PerfTCP]
[PerfTCP]    The following example runs a singlethreadded test followed by a multithreaded test, Sending data to 10.0.0.1, with 64K buffers, for 2 minutes
[PerfTCP]    Ex: .\$($global:ScriptName) -PerfTCP Server -PerfTCPAddr 10.0.0.1 -BufferLength 64 -Duration 120
[PerfTCP]    Then wait for prompt: "At this time run the appropriate TSS command on the client machine (i.e. with -PerfTCP Client)"
[PerfTCP]    Ex: .\$($global:ScriptName) -PerfTCP Client -PerfTCPAddr 10.0.0.1 -BufferLength 64 -Duration 120
[PerfTCP]
[Commands]  -PerfSMB starts a Robocopy for performance testing SMB between client and server
[PerfSMB]    The TSS command is run on the client 
[PerfSMB]    .\$($global:ScriptName) -PerfSMB <UNC path to remote share directory> [-PerfSMBFileSize <size>] [-NumFiles <N>]
[PerfSMB]     <size> is <N>[K|M|G|b] (i.e. 1M meens 1 MegaByte)
[PerfSMB]    UNC path can be any valid UNC path to a remote share directory, including name or IP address
[PerfSMB]    Ex1: \\servername\sharename\dirname
[PerfSMB]    Ex2: \\10.0.0.1\sharename\dirname
[PerfSMB]    IMPORTANT: Customer MUST have write access to the share directory from the client machine.  
[PerfSMB]           It may be necessary to adjust permissions, or connect first via cmd prompt using credentials
[PerfSMB]
[PerfSMB]    Client optional parameters:
[PerfSMB]        -PerfSMBFileSize <size>, where <size> is <n>[K|M|G|b] , Default 1M
[PerfSMB]        -NumFiles <number of files to transfer>,  Default 10
[PerfSMB]    Example1: Server IP is 10.0.0.1, sharename is TestShare, dirname is TestDir, send 10 1MB files
[PerfSMB]        .\$($global:ScriptName) -PerfSMB \\10.0.0.1\TestShare\TestDir
[PerfSMB]    Example2: Server name is TestServer, sharename is TestShare, dirname is TestDir, send 1 1GB file
[PerfSMB]        .\$($global:ScriptName) -PerfSMB \\TestServer\TestShare\TestDir -PerfSMBFileSize 1G -NumFiles 1
[PerfSMB]
[PerfSMB]    -PerfSMB also collects a packet capture by default
[PerfSMB]
[Commands]  -PktMon                     - collect Packet Monitoring data (on RS5+ / Srv2019), PktMon:Drop will collect only dropped packets
[Commands]  -PoolMon <Start|Stop|Both>  - Collect PoolMon on start, stop or both.
[Commands]  -ProcDump <PID[]|ProcessName.exe[]|ServiceName[]> - capture user dump(s) of single item or comma separated list of items using SysInternals ProcDump.exe. By default, the dump is taken on start of repro and stop. Enter ProcessName(s) with .exe extension; 
[ProcDump]    you can change the timing and interval by specifying below -ProcDumpOption and -ProcDumpInterval
[ProcDump]    + -ProcDumpOption <Start|Stop|Both>  - Start: the dump is taken on start of repro. Stop: the dump is taken on stop. Both (default): the dump is taken on both start and stop.
[ProcDump]    + -ProcDumpInterval <N>:<Interval in sec> - Use this option when the dump needs to be captured repeatedly. N: =number of dumps, Int: =Interval in seconds; default=3:10
[ProcDump]    + -ProcDumpAppCrash       - will enable ProcDump -ma -e (Write a full dump when the process encounters an unhandled exception)
[ProcDump]     Example1: -ProcDump mstsc.exe,4321,TokenBroker,TermService -ProcDumpOption Stop -ProcDumpInterval 5:60
[ProcDump]     Example2: -ProcDump Excel.exe -ProcDumpAppCrash -WaitEvent Process:Excel
[Commands]  -ProcMon                    - start SysInternals Procmon.exe
[Procmon]     + -ProcmonAltitude <N> - specify a string value for ProcmonAltitude (default=385200), use 'fltmc instances' to show filter driver Altitude, use a lower number than the suspected specific driver; value 45100 will show you virtually everything. 
[Procmon]     + -ProcmonPath <folder path to Procmon.exe> - specify a path to Procmon.exe(by default, TSS uses built-in Procmon)
[Procmon]     + -ProcmonFilter <filter-file.pmc> - specify a config file for Procmon(ex. ProcmonConfiguration.pmc) located in \config folder
[Commands]  -PSR- start PSR(Problem Steps Recorder)
[Commands]  -Radar <PID[]|ProcessName[]|ServiceName[]> - collect leak diag info
[Radar]       Example: -Radar AppIDSvc
[Commands]  -RASDiag                    - collect trace: Netsh Ras diagnostics set trace enable
[Commands]  -SDP <SpecialityName[]>     - collect SDP(Support Diagnostic Package) for the specified speciality
[SDP]         + -SkipSDPList "<xxx>","<yyy>" - comma separated list of SDP modul names to skip, which appear to hang in your environment while running SDP report
[SDP]            Ex#1: -SDP Net -SkipSDPList noNetadapters,skipNetview
[SDP]            Ex#2: -SDP Cluster -SkipSDPList skipSddc,skipCsvSMB,skipTS
[SDP]          => <SpecialityName>: "Apps","CRMbase","CTS","Cluster","DA","Dom","DPM","HyperV","Net","Perf","Print","RDS","S2D","SCCM","Setup","SQLbase","SQLconn","SQLmsdtc","SQLsetup","SUVP","VSS","mini","nano","Repro","RFL","All"
[SDP]          => Skip SDP List: "noNetadapters","skipBPA","skipHang","skipNetview","skipSddc","skipTS","skipHVreplica","skipCsvSMB"
[Commands]  -SysMon                     - collect SysInternals System Monitor (SysMon) log [def: sysmonConfig.xml in 'config' folder]
[Commands]  -TTD <PID[]|ProcessName.exe[]|ServiceName[]> - start Time Travel Debugging (TTD) (TTT/iDNA) with default= -Full mode; Enter ProcessName(s) with .exe extension; single item(PID/name) or comma separated list of items
[TTD]         Note: downlevel OS before Win10 RS2 will require the TSS_TTD.zip package
[TTD]         + -TTDPath <Folder path to tttracer.exe> - specify folder path containing tttracer.exe (PartnerTTD); typically this switch is not needed, unless you want to force a specific path
[TTD]         + -TTDMode <Full|Ring|onLaunch> - Full = -dumpfull (=default), Ring = ring buffer mode, onLaunch = -onLaunch (requires TSS_TTD)
[TTD]         + -TTDMaxFile <size in MB> - Max log file size; operation depends on -TTDMode (Full: stops when max size is reached, Ring: keeps max size in ring buffer)
[TTD]         + -TTDOptions '<String of TTD options>' - use this option if you want to add any additional option for TTD (TTT/iDNA)
[Commands]  -Video                      - start video capturing (requires .NET 3.5 installed) - A picture might paint a thousand words, but a video can tell a story.
[Commands]  -WFPDiag                    - collect trace: netsh Wfp capture
[Commands]  -WireShark                  - start WireShark. Below parameters are configurable through tss_config.cfg file.
[WireShark]    WS_IF:                   Used for -i; Specify interface number (ex. _WS_IF=1)
[WireShark]    WS_Filter:               Used for -f; Filter for the interface (ex. _WS_Filter="port 443")
[WireShark]    WS_Snaplen:              Used for -s; Limit the amount of data for each frame. This is better performance and helpful for high load situation. (ex. _WS_Snaplen=128)
[WireShark]    WS_TraceBufferSizeInMB:  Used for -b FileSize (multiplied by 1024); Switch to next file after NUM MB. (ex. _WS_TraceBufferSizeInMB=512; default=512MB)
[WireShark]    WS_PurgeNrFilesToKeep:   Used for -b files; Replace after NUM files. (ex. _WS_PurgeNrFilesToKeep=20)
[WireShark]    WS_Options:              Any other options for -i; (ex. _WS_Options="-P")
[WireShark]   Example: for Collecting WireShark on interface 15 and 11, input when TSS prompts for a interface number: 15 -i 11 
[WireShark]   By default Wireshark starts dumpcap.exe  -i <all NICs> -B 1024 -n -t -w _WireShark-packetcapture.pcap -b files:10 -b filesize:524288
[Commands]  -WPR <WPRprofile>           - start a WPR profile trace. <WPRprofile> is one of 'General|BootGeneral|CPU|Device|Memory|Network|Registry|Storage|Wait|SQL|Graphic|Xaml|VSOD_CPU|VSOD_Leak'
[WPR]         + -SkipPdbGen             - Skip generating symbol files(PDB files)
[WPR]         + -WPROptions '<Option string>' - specify options for WPR.exe, i.e.: -WPROptions '-onoffproblemdescription "test description"'
[WPR]           Ex#1: .\$($global:ScriptName) -StartAutoLogger -WPR BootGeneral -WPROptions '-addboot CPU' - will cature WPR boot trace with profile General+CPU
[WPR]           Ex#2: .\$($global:ScriptName) -WPR BootGeneral -WPROptions '-Start CPU -start Network -start Minifilter' - will combine profile General+CPU+Network+Minifilter
[Commands]  -Xperf <Profile>            - start Xperf. <Profile> is one of 'General|CPU|Disk|Leak|Memory|Network|Pool|PoolNPP|Registry|SMB2|SBSL|SBSLboot'
[Xperf]       + -XperfMaxFileMB <Size>  - Specify max log size in MB(default 2048MB); default for SBSL* scenario=16384 (same for ADS_/NET_SBSL)
[Xperf]       + -XperfTag <Pool Tag>    - Specify PoolTag to be logged. This is used with 'Pool' or 'PoolNPP' profile. (ex. -Xperf Pool -XperfTag TcpE+AleE+AfdE+AfdX)
[Xperf]       + -XperfPIDs <PID>        - Specify ProcessID. This is used with 'Leak' profile. (ex. -Xperf Leak -XperfPIDs <PID>)
[Xperf]       + -XperfOptions <Option string> - Specify other option string for Xperf
[Commands]  -xray                       - start xray to diagnose a system for known issues
[Controls]  To list all COMMANDS Options, run .\$($global:ScriptName) -ListSupportedCommands

[Controls] CONTROLS
-------------------
[Controls]  -AcceptEula     - do not ask at first run to accept Disclaimer (useful for -RemoteRun execution)
[Controls]  -AddDescription <description> - add a brief description of the repro issue. The name of resulting zip file will include such description
[Controls]  -Assist         - Accessibility Mode
[Controls]  -BasicLog       - collect full basic log (by default mini basic log is always collected)
[Controls]  -CollectComponentLog - use with -Scenario. By default, component collect functions are not called in case of -Scenario trace. This switch enables the component collect functions to be called.
[Controls]  -CollectDump    - collect system dump (memory.dmp) after stopping all traces. -CollectDump can be used with -Start and -Stop.
[Controls]  -CollectEventLog <Eventlog[]>    - collect specified event logs. Wild card * can be used for the event log name.
[CollectEventLog] Ex.: -CollectEventLog Security,*Cred*  # collect security and all event logs that matches *Cred* like 'Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational'
[Controls]  -CommonTask <<POD>|Full|Mini> - run common tasks before starting and after stopping trace
[CommonTask]     <POD> : currently only 'NET' is available, collects additional info before starting and after stopping trace
[CommonTask]     Full  : full basic log is collected after stopping trace
[CommonTask]     Mini  : mini basic log is collected after stopping trace
[Controls]  -Crash          - trigger system crash with NotMyFault at stop of repro, or after all events are signaled in case used with -WaitEvent, Caution: this switch will force a memory.dump (Attention: system will reboot), open files won't save.
[Controls]  -CustomETL      - add custom ETL trace provider(s), ex: .\$($global:ScriptName) -WIN_CustomETL -CustomETL '{CBDA4DBF-8D5D-4F69-9578-BE14AA540D22}','Microsoft-Windows-PrimaryNetworkIcon' (comma separated list of single quoted '{GUID}' and/or 'Provider-Name')
[Controls]  -DebugMode      - run with debug mode for a developer
[Controls]  -VerboseMode    - show more verbose/informational output while processing TSS functions
[Controls]  -Discard        - used to discard a dataset at phase -Stop. *Stop- or *Collect-functions will not run. xray and psSDP will be skipped.
[Controls]  -EnableCOMDebug - used by UEX module to turn on COM debug mode
[Controls]  -ETLOptions <circular|newfile>:<ETLMaxSizeMB>:<ETLNumberToKeep>:<ETLFileMax> - set options passed to logman command, default for circular ETLMaxSize=1024, default for newfile ETLMaxSize=512, -StartAutologger only supports -ETLOptions circular:<ETLMaxSize>:<ETLNumberToKeep>:<ETLFileMax>, but ETLNumberToKeep won't be honored
[ETLOptions]  Ex.1: -ETLOptions newfile:2048:5  # run newfile logs with size of 2048 MB, keep only last 5 *.etl files; defaults for circular mode: circular:1024, for newfile mode: newfile:512:10 
[ETLOptions]  Ex.2: -StartAutologger -ETLOptions circular:4096 (Autologger will not obey :<ETLNumberToKeep> and it only accepts mode circular)
[ETLOptions]  Ex.3: -StartAutologger -ETLOptions circular:4096:10:3 (Autologger will not obey :<ETLNumberToKeep> and it only accepts mode circular and '3' as the number of autologger generations )
[Controls]  -ETWlevel <Info|Warning|Error> - set Event tracing Level, default =0xFF
[Controls]  -ETWflags <hexNr> - Event Trace Flags for -WIN_kernel trace, default =0x0000000000000001 (1=Process creations/deletions, .. see Logman query providers "Windows Kernel Trace")
[Controls]  -EvtDaysBack <N> - Convert Eventlogs only for last N days; default: 30 days; also applies to SDP report; Note: Security Eventlog will be skipped
[Controls]  -ExternalScript <path to external PS file> - run the specified PowerShell script before starting trace
[Controls]  -LogFolderPath <Drive:\path to log folder> - use a different log folder path for resulting output data, instead of default location (C:\MS_DATA); useful when drive C: is low on free disk-space
[Controls]  -MaxEvents <N>  - as an argument for '-WaitEvent Evt:..' will investigate last N number of events with same EventID (default=1)
[Controls]  -Mini           - collect only minimal data, skip noPSR, noSDP, noVideo, noXray, noZip, noBasicLog
[Controls]  -Mode <Basic|Medium|Advanced|Full|Verbose|VerboseEx|Hang|Restart|Swarm|Kube|GetFarmdata|Permission|traceMS> - [for data collection] run script in Basic, Medium, Advanced, Full or Verbose(Ex) mode. Restart will restart associated service.
[Controls]  -RemoteRun      - use when TSS is being executed on a remote host, i.e. via psExec or in PS Azure Serial Console, or with PS remoting; this will inhibit PSR, Video recording, starting TssClock and opening Explorer with final results. In such case also consider -AcceptEula
[Controls]  -StartNoWait    - do not wait and prompt will return immediately, this is useful for the scenario where a user needs to log off
[Controls]  -WaitEvent      - monitor for the specified event/stop-trigger and if it is signaled, traces will be stopped automatically
[WaitEvent]   run '.\$($global:ScriptName) -Find Monitoring' to see the usage
[Controls]  -Update         - update TSS package, can be used together with -UpdMode Online|Lite # deprecated: Quick|Full|Force|
[Update]      + -UpdMode <Online|Lite>  - 'Online' (=default), Lite = upd lite version # deprecated: or 'Full' will download full package, 'Quick' will do a differential update, 'Force' will force update even latest version seems installed
[Controls]  To list most common Control Options, run .\$($global:ScriptName) -ListSupportedControls
[Controls]   adding -ExportGUIcsv for -List* switches will export the help output to a CSV table (Key | Description) in the subfolder \TSSGUI
[Controls]  -v              - [Auth] used in ADS_Auth for more verbose logging
[Controls]  -containerId <containerID> - [Auth] used in ADS_Auth for Container tracing
[Controls]  -watchProcess <procName|PID> - [Auth] deprecated, was used in ADS_Auth to wait for process termination -- plz use -WaitEvent process <procName|PID>
[Controls]  -slowlogon      - [Auth] used in ADS_Auth for slow logon WPR tracing

[NoOptions] NoOPTIONs:
----------------------
[NoOptions]  Any given Command/Tool in predefined scenarios can be suppressed by specifying a corresponding no* option
[NoOptions]  To list all no* Options, run .\$($global:ScriptName) -ListSupportedNoOptions

[CollectLog] Starting a data collection (-CollectLog)
=====================================================
[CollectLog] If there is no need to capture Component traces and only data collection and/or system diagnosis need to be performed, use this option (-CollectLog).
[CollectLog] => Run data collection + system diagnostics

[CollectLog] PS> .\$($global:ScriptName) -CollectLog <ComponentName[]>
[CollectLog] * supported <ComponentName>s are listed with '$($global:ScriptName) -ListSupportedLog'

[CollectLog] CONTROLS accepted:
[CollectLog]   -AcceptEula  - do not ask at first run to accept Disclaimer
[CollectLog]   -LogFolderPath <Drive:\path to log folder>  - use the log folder instead of default location (C:\MS_DATA)
[CollectLog]   -DebugMode   - run with debug mode for a developer
[CollectLog]   -CollectEventLog <EventLog[]>   - collect event log. Run '.\$($global:ScriptName) -Find CollectEventLog' for detail.
[Controls]  To list all -CollectLog Options, run .\$($global:ScriptName) -ListSupportedLog

[CollectEventLog] Collect Windows Event logs (-CollectEventLog)
===============================================================
[CollectEventLog] Collect specified Event log(s). Wild card * can be used for the event log name.

[CollectEventLog] PS> .\$($global:ScriptName) -CollectEventLog <EventLog[]>
[CollectEventLog] Ex.: -CollectEventLog Security   # collect only security log
[CollectEventLog] Ex.: -CollectEventLog Security,*Cred*  # collect security and all event logs that matches *Cred* like 'Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational'

[CollectEventLog] CONTROLS accepted:
[CollectEventLog]   -AcceptEula  - do not ask at first run to accept Disclaimer
[CollectEventLog]   -LogFolderPath <Drive:\path to log folder>  - use the log folder instead of default location (C:\MS_DATA)
[CollectEventLog]   -DebugMode   - run with debug mode for a developer

[SDP] Collecting SDP reports (-SDP)
===================================
[SDP] If there is no need to capture Component traces and only SDP report needs to be run, use this option (-SDP). 
[SDP] -SDP can also be used with -Start, -CollectLog and -StartDiag.

[SDP] 1. Starting SDP
[SDP]    PS> .\$($global:ScriptName) -SDP <SpecialityName[]>
[SDP]    Ex#1: .\$($global:ScriptName) -SDP RDS
[SDP]    Ex#2: .\$($global:ScriptName) -SDP RDS,Setup
[SDP]    => SDP SpecialityName: Apps|CRMbase|CTS|Cluster|DA|Dom|DPM|HyperV|Net|Perf|Print|RDS|S2D|SCCM|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|SUVP|VSS|mini|nano|Repro|RFL|All

[SDP] CONTROLS accepted:
[SDP]    -SkipSDPList <SkipSDPList[]> - comma separated list of skipping stages in SDP report
[SDP]     Example: .\$($global:ScriptName) -SDP RDS -SkipSDPList skipBPA,skipTS
[SDP]      => Skip List SDP: noNetadapters|skipBPA|skipHang|skipNetview|skipSddc|skipTS|skipHVreplica|skipCsvSMB
[SDP]    -AcceptEula      - do not ask at first run to accept Disclaimer
[SDP]    -EvtDaysBack <N> - Convert Eventlogs only for last N days
[SDP]    -LogFolderPath <Drive:\path to log folder>  - use the log folder instead of default location(C:\MS_DATA)
[SDP]    -StartNoWait     - do not wait and prompt will return immediately, this is useful for the scenario where a user needs to log off
[SDP]    -BasicLog        - collect full basic log (by default mini basic log is always collected)

[SDP] 2. Starting SDP with -StartNoWait
[SDP]    With -StartNoWait at start of data collection, use -SDP when stopping trace (i.e. use $($global:ScriptName) -Stop -SDP)
[SDP]    PS> .\$($global:ScriptName) -StartNoWait -<ComponentName>
[SDP]    PS> .\$($global:ScriptName) -Stop -SDP <SpecialityName>

[SDP] 3. Starting SDP with AutoLogger (persistent/boot) scenario
[SDP]    Like same as -StartNoWait, use -SDP when stopping trace in case of AutoLogger.
[SDP]    PS> .\$($global:ScriptName) -StartAutoLogger -<ComponentName>
[SDP]    PS> Restart-Computer
[SDP]    PS> .\$($global:ScriptName) -Stop -SDP <SpecialityName>
[Controls]  To list all -SDP specialties, run .\$($global:ScriptName) -ListSupportedSDP

[StartDiag] Running a system diagnose (-StartDiag)
==================================================
[StartDiag] If there is no need to capture Component traces and collect data, but want to diagnose system, use this option.
[StartDiag] => Run system diagnostics only

[StartDiag] PS> .\$($global:ScriptName) -StartDiag <ComponentName[]> [-InputlogPath <path to log folder for diagnostic>]
[StartDiag]  * supported <ComponentName>s are listed with '$($global:ScriptName) -ListSupportedDiag'

[StartDiag] CONTROLS accepted:
[StartDiag]   -AcceptEula     - do not ask at first run to accept Disclaimer
[StartDiag]   -DebugMode      - run with debug mode for a developer
[StartDiag]   -InputlogPath <path to log folder for diagnostic> - specify a log path to be diagnosed (with -StartDiag)
[StartDiag]   -LogFolderPath <Drive:\path to log folder>  - use the log folder instead of default location (C:\MS_DATA)

[StartAutoLogger] Setting AutoLogger (-StartAutoLogger) for capturing issue at Boot Phase
=========================================================================================
[StartAutoLogger] -StartAutoLogger enables AutoLogger that is a feature to start capturing traces from early boot timing. 
[StartAutoLogger] This is helpful when the issue happens on the early stage of system boot. 
[StartAutoLogger] Note, a 'Shutdown' scenario (FastStart) may not contain boot phase at Power-on. Only 'Restart' will perform a typical boot phase. Therefor -StartAutoLogger should not be used for FastStart/Hibernation scenarios (instead use -StartNoWait)

[StartAutoLogger] 1. Enable a scenario trace + support tools with AutoLogger and stop the traces
[StartAutoLogger]    PS> .\$($global:ScriptName) -StartAutoLogger -Scenario <ScenarioName> -WPR <WPRprofile> -Procmon -Netsh|-NetshScenario <NetshScenario>
[StartAutoLogger]    PS> Restart-Computer               # to start traces from boot time
[StartAutoLogger]    PS> .\$($global:ScriptName) -Stop  # This stops all running traces and deletes AutoLogger settings

[StartAutoLogger] 2. Enable component traces + support tools with AutoLogger
[StartAutoLogger]    PS> .\$($global:ScriptName) -StartAutoLogger <-ComponentName> <-ComponentName> ...  -WPR <WPRprofile> -Procmon -Netsh|-NetshScenario <NetshScenario>
[StartAutoLogger]    PS> Restart-Computer               # to start traces from boot time
[StartAutoLogger]    PS> .\$($global:ScriptName) -Stop  # This stops all running traces and deletes AutoLogger settings

[StartAutoLogger] CONTROLS accepted:
[StartAutoLogger]   -AcceptEula    - do not ask at first run to accept Disclaimer
[StartAutoLogger]   -DebugMode     - run with debug mode for a developer
[StartAutoLogger]   -LogFolderPath <Drive:\path to log folder>  - use the log folder instead of default location (C:\MS_DATA)

[RemoveAutoLogger] Deleting AutoLogger settings (-RemoveAutoLogger)
===================================================================
[RemoveAutoLogger] Delete AutoLogger settings. This option can be used when AutoLogger is enabled, but you want to discard the setting.
[RemoveAutoLogger]    PS> .\$($global:ScriptName) -RemoveAutoLogger

[Status] Showing trace status (-Status)
=======================================
[Status] You can show what traces/tools are running and also this shows what AutoLoggers are enabled on the system.
[Status] PS> .\$($global:ScriptName) -Status

[Help] Displaying help message (-Help)
======================================
[Help] 1. Show the version of TSS
[Help]    PS> .\$($global:ScriptName) -version

[Help] 2. Show interactive help message menue
[Help]    PS> .\$($global:ScriptName) -Help
[Help]    Hint: use numbers 0-9 or keyword search for quick help

[Help] 3. List available parameters for each trace / scenario
[Help]    List available options for all or each technology area:
[Help]     PS> .\$($global:ScriptName) -List
[Help]    List all ETW provider GUIDs for components or scenarios
[Help]     PS> .\$($global:ScriptName) -ListETWProviders <component-/scenario-name>
[Help]    List available commands / support tools:
[Help]     PS> .\$($global:ScriptName) -ListSupportedCommands 
[Help]    List available components for Diag feature (-StartDiag):
[Help]     PS> .\$($global:ScriptName) -ListSupportedDiag
[Help]    List available components for data collection (-CollectLog):
[Help]     PS> .\$($global:ScriptName) -ListSupportedLog
[Help]    List available options for -NetshScenario switch (Netsh trace scenario=):
[Help]     PS> .\$($global:ScriptName) -ListSupportedNetshScenario
[Help]    List available noOptions:
[Help]     PS> .\$($global:ScriptName) -ListSupportedNoOptions
[Help]    List available performance counter set for -PerfMon and -PerfMonLong:
[Help]     PS> .\$($global:ScriptName) -ListSupportedPerfCounter
[Help]    List available predefined scenario traces:
[Help]     PS> .\$($global:ScriptName) -ListSupportedScenarioTrace
[Help]    List available specialty SDP reports:
[Help]     PS> .\$($global:ScriptName) -ListSupportedSDP
[Help]    List available components for ETW traces:
[Help]     PS> .\$($global:ScriptName) -ListSupportedTrace
[Help]    List available options/profiles for -WPR (Windows Performance Recorder):
[Help]     PS> .\$($global:ScriptName) -ListSupportedWPRScenario
[Help]    List available profiles for -Xperf:
[Help]     PS> .\$($global:ScriptName) -ListSupportedXperfProfile

[Help] 4. Show trace info for components (with providers) or scenarios
[Help]    PS> .\$($global:ScriptName) -TraceInfo <ComponentName>|<ScenarioName>|all
[Help]    * supported <ComponentName>s are listed with '$($global:ScriptName) -ListSupportedTrace'
[Help]    * supported <ScenarioName>s are listed with '$($global:ScriptName) -ListSupportedScenarioTrace'

[Help] 5. Find component names that have a passed GUID 
[Help]    PS> .\$($global:ScriptName) -FindGUID <GUID>
[Help]    Ex.: .\$($global:ScriptName) -FindGUID 1234  -- this will show trace name that contains a provider GUID with substring '1234'

[Help] 6. Find Provider GUIDs for component-name or scenario
[Help]    PS> .\$($global:ScriptName) -FindETWProvider <component-or-scenario>
[Help]    Ex.: .\$($global:ScriptName) -FindETWProvider NET_SMB 

[Help] 7. Search and find a keyword or RegEx in TSS help texts
[Help]    PS> .\$($global:ScriptName) -Find <keyword>
[Help]     Ex#1: .\$($global:ScriptName) -Find syntax             -- this will show all lines in TSS help which contain the keyword 'syntax'
[Help]     Ex#2: .\$($global:ScriptName) -Find "syntax|PS_error"  -- this will show all lines in TSS help which contain the keyword 'syntax' or 'PS_error'
[Help]    It also finds terms with regular expressions like in keyword 'reg.*path'; this would find i.e. terms 'Registry Path' or 'RegKeyPath'

[Scripts] Helper scripts and tools included in TSS.zip
========================================================
[Scripts] \scripts\tss_EventCreate.ps1 - create an Event log entry in [EvtLogName] with [Event ID]
[Scripts] \scripts\tss_SMB_Fix-SmbBindings.ps1 - useful for fixing corrupted SMB Bindings (LanmanServer/LanmanWorkstation/NetBT); see also -Collect NET_SMBsrvBinding
[Scripts] \BINx64\kdbgctrl.exe    - use switch -sd <dump type>  to Set kernel crash dump type Full|Kernel, i.e. kdbgctrl -sd Full
[Scripts] \BINx64\NTttcp.exe      - Performance tests: https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-bandwidth-testing
[Scripts] \BINx64\latte.exe       - Latency tests: https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-test-latency
[Scripts] \BINx64\notmyfaultc.exe - force a memory dump: https://learn.microsoft.com/es-es/sysinternals/downloads/notmyfault if TSS command-line includes -Crash

[PS_error] Help on unexpected PowerShell errors
===============================================
[PS_error] - run this command after a failure: .\$($global:ScriptName) -Stop -noBasiclog -noXray
[PS_error] - close open elevated PS window and start a new elevated PS window
[PS_error] - allow PS scripts running on your system with proper ExecutionPolicy
[PS_error]    If you encounter an error that running scripts is disabled, try 
[PS_error]    Method#1
[PS_error]      Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -force -Scope Process
[PS_error]    and verify with 'Get-ExecutionPolicy -List' that no ExecutionPolicy with higher precedence is blocking execution of this script.
[PS_error]    Then run '.\$($global:ScriptName) <with desired parameters>' again.

[PS_error]    Alternate Method#2a: if scripts are blocked by MachinePolicy, run in elevated PowerShell: 
[PS_error]      Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value RemoteSigned
[PS_error]      Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name EnableScripts  -Value 1 -Type DWord
[PS_error]    Alternate Method#2b: if scripts are blocked by UserPolicy, run in elevated PowerShell: 
[PS_error]      Set-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name ExecutionPolicy -Value RemoteSigned
[PS_error]      Set-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name EnableScripts  -Value 1 -Type DWord
     
[PS_error]    Note, Method#2a is only a workaround for Policy 'MachinePolicy - RemoteSigned', if you also see 'UserPolicy - RemoteSigned', please ask the domain admin for temporary GPO exemption.
[PS_error]    In rare situations you could try -ExecutionPolicy Bypass

[PS_error]    If your org. foreces by GPO PowerShell constrained language mode ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') please ask the domain admin for temporary GPO exemption.

[TssLite] Help on LiteMode
==========================
[TssLite] In case you have downloaded TSS LiteMode package (https://aka.ms/getTSSlite), some external tool based commands will not be collected.
[TssLite] This affects SysInternals and other utilities (Crash/Handle/Fiddler/PoolMon/ProcMon/ProcDump/SysMon/TTD(on downlevel OS)/Video/Xperf)

[PSremoting] Help on starting TSS remotely, using PowerShell remoting (PSremoting)
==================================================================================
[PSremoting] If you want to start a remote PowerShell session (or use Sysinternals PsExec) and run TSS commands silently there, please try the following approach; remember to append -AcceptEula for a very first remote execution in your user context:
[PSremoting] Prerequisite: expand TSS.zip package on remote computer i.e. on Server11 on local disk C:\TSS
[PSremoting]   Pre-Req: on the destination Computer "Server11" run: 'Enable-PSRemoting -Force', then you can continue with steps on your Admin Computer:
[PSremoting]   $RemoteComputer = "Server11"
[PSremoting]   New-PSSession -ComputerName $RemoteComputer
[PSremoting]   Enter-PSSession -ComputerName $RemoteComputer
[PSremoting]   cd C:\TSS
[PSremoting]   .\$($global:ScriptName) -SDP NET -AcceptEula -RemoteRun

[FAQ] Frequently asked Questions (see also public TSS KB)
===========================================================
[FAQ] Public KB: https://aka.ms/TSSv2 -or-  https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-troubleshooters/introduction-to-troubleshootingscript-toolset-tssv2
[FAQ] Issue cannot be repro'd when TSS runs?
[FAQ]  TSS basically only actively modifies some settings for troubleshooting purpose (at start, and resets them at stop):
[FAQ]   - starts a NetSH trace, so the NIC driver will be set to promiscuous mode
[FAQ]   - it runs on a server with RemoteAccess service enabled: netsh interface ipv4 set global multicastforwarding=Disable|Enable
[FAQ]   - clears all caches (NetBios, DNS, Kerberos, DFS) at start time, unless -noClearCache is specified
[FAQ]   - some scenarios activate additional EventLogs (and de-activate at stop)
[FAQ]   - enables ETW tracing and debug logging, this could change timing

[FAQ] Video recording *.wvm in TSS:
[FAQ]  If your resulting VideoRepro.wmv file covers only part of the screen, while recording plz. decrease your screen 'Display settings -> Display resolution' to a standard setting.
"@

$HelpMessageForMonitoring = @"

[Monitoring] Monitoring feature (-WaitEvent)
============================================
[Monitoring] TSS has a feature to monitor lots of events such as an event in Windows event log, shutdown of network port, creation/deletion of file and registry, and so on. Once the event is signaled, traces will be stopped automatically in time.
[Monitoring] If commandline contains -WaitEvent, the system will also monitor for the stop trigger 'System Event ID 999' 

[Monitoring] This feature is helpful when you can't reproduce the issue intentionally or immediately and need to wait for next occurrence. 
[Monitoring] In such case, this feature allows the script to wait for the repro event and stop traces automatically once the expected event happens (no manual human intervention needed).

[Monitoring] After all events are signaled, if you want to wait an additional amount of seconds before stopping traces, use '-StopWaitTimeInSec <N>' to create an additional delay at Stop.
[Monitoring] Note: Whenever item names include a space character, you need to enclose name in single quotes: '<item name>' 

[Monitoring] The monitoring is enabled by -WaitEvent switch. Please see below usage for detail of [Evt|PortLoc|PortDest|NoNetConn|Svc|Process|Share|SMB|HTTP|RDP|WINRM|LDAP|RegData|RegValue|RegKey|File|Time|HNSL2Tunnel|LogFile|StopCondition|HighCPU|HighMemory|Signal|ATQ], where <xxx> means any -<ComponentName>, -Scenario <ScenarioName>, or -<ToolName>.
[Monitoring] The default Poll/Monitoring interval (CheckIntInSec) is defined in \config\tss_Config.cfg with parameter _MonitorIntervalInSec; default is 5 seconds
[Monitoring]  for defining a shorter poll interval, use -CheckIntInSec <N> 

[Monitoring] 1. [Evt] Wait and stop traces when an event ID is recorded, optional with CheckIntInSec, StopWaitTimeInSec, StopEventData (Text or ErrorCode), EvtDataPartial (True|False), EvtDataOperator (OR|AND, def.: OR)
[Monitoring]    Separate multiple EventIDs with '/', Ex.: 30800/30809; <StopEventData> can be a string of slash (/) separated data
[Monitoring]    if arg #6 <StopEventData> is supplied, we look for exact full string match between <Data>...</Data> as seen in Event 'XML View', unless argument #7 = EvtDataPartial is set to True
[Monitoring]    [Syntax]  Eventlog Names that include a space need to be enclosed in single quotes '...'
[Monitoring]    [Controls] -MaxEvents <N> will investigate last N number of events with same EventID (default=1) seen within CheckIntInSec (default=5) period.
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent Evt:<EventID>:'<Eventlog Name>'[:<CheckIntInSec>:<StopWaitTimeInSec>:<StopEventData>:<EvtDataPartial True|False>:<OR|AND>] [-MaxEvents <N>]
[Monitoring]     Ex#1: .\$($global:ScriptName) -Scenario ADS_ACCOUNTLOCKOUT -WaitEvent Evt:4625:'Security':5:0:user1/user2:True:OR => monitors in intervals of 5 sec for partial(=True) string 'user1' OR 'user2' in Security EventID 4625 (waiting 0 sec after event is logged)
[Monitoring]     Ex#2: .\$($global:ScriptName) -Scenario ADS_ACCOUNTLOCKOUT -WaitEvent Evt:4625:'Security':5:2:user1/0xc000006a:False:AND => monitors in intervals of 5 sec for full (partial=False) string 'user1' AND error code '0xc000006a' in Security EventID 4625 (waiting 2 sec after event is logged)
[Monitoring]     Ex#3: .\$($global:ScriptName) -Scenario NET_NCSI -WaitEvent Evt:4042:'Microsoft-Windows-NCSI/Operational':0:0:6 => monitors constantly for exact data string '6' which translates for NCSI 'ActiveHttpProbeFailedButDnsSucceeded' in EventID 4042 
[Monitoring]     Ex#4: .\$($global:ScriptName) -Scenario NET_Capture -WaitEvent Evt:4227/4231:'System' => monitors constantly for EventID 4227 or 4231 in System EventLog (indicators of Port Exhaustion)

[Monitoring] 2. [PortLoc] Wait for a local network port to be closed / becoming unreachable
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent PortLoc:<Port number> [-StopWaitTimeInSec <N>]

[Monitoring] 3. [PortDest] Wait for a remote (not local) network port to be closed / becoming unreachable on remote host(s)
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent PortDest:'<RemoteHost1,Host2>':<Port number> [-StopWaitTimeInSec <N>]

[Monitoring] 4. [NoNetConn] Wait for Default Gateway (or optional <DestHost>) becoming unreachable
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent NoNetConn[:<DestHost>] [-StopWaitTimeInSec <N>]

[Monitoring] 5. [Svc] Wait for a windows service to be stopped or terminated unexpectedly
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent Svc:<Service name> [-StopWaitTimeInSec <N>]

[Monitoring] 6. [Process] Wait for a process to be stopped or terminated unexpectedly
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent Process:<Process name without .exe extension> [-StopWaitTimeInSec <N>]

[Monitoring] 7. [Share] Wait for a remote share to become inaccessible
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent Share:<ServerName>:<ShareName> [-StopWaitTimeInSec <N>]

[Monitoring] 8. [SMB|HTTP|RDP|WINRM] Wait for a common network port to be closed / becoming unreachable via protocol SMB|HTTP|RDP|WINRM on remote host(s)
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent <SMB|HTTP|RDP|WINRM>:'<RemoteHost1,Host2>' [-StopWaitTimeInSec <N>]

[Monitoring] 9. [LDAP] Wait for a domain controller to be inaccessible
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent LDAP:<Domain name> [-StopWaitTimeInSec <N>]

[Monitoring] 10. [RegData] Wait for the creation of registry data entry, or a change FROM (with :True) or TO (with [:False] = default) a specific data entry <ExpectedData>
[Monitoring]    Monitor for registry data change inTO a specific data entry <ExpectedData>
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent RegData:<RegKeyPath>:<RegValueName>:<ExpectedData> [-StopWaitTimeInSec <N>]
[Monitoring]    Monitor for registry data change FROM a specific data entry <ExpectedData> into any other value
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent RegData:<RegKeyPath>:<RegValueName>:<ExpectedData>:True [-StopWaitTimeInSec <N>]
[Monitoring]     Ex: .\$($global:ScriptName) -Start <xxx> -WaitEvent RegData:HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters:TcpTimedWaitDelay:0x1E 
[Monitoring]        will be signaled, once new data turns TO ExpectedData 0x1E; if you append as last parameter :True, then you monitor until actual data is no more 0x1E (ExpectedData)

[Monitoring]   Syntax for monitoring Registry items in 10.[RegData], 11.[RegValue], 12.[RegKey]
[Monitoring]    [Syntax]  registry path <RegKeyPath>          example: 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
[Monitoring]    [Syntax]  registry name <RegValueName>        example: TcpTimedWaitDelay
[Monitoring]    [Syntax]  registry data entry <ExpectedData>  example: 0x1E
[Monitoring]    [Syntax]  the last parameter can be set to :True = opposite behaviour; (no last parameter means default= :False)
[Monitoring]    [Syntax]  registry roots can be              HKLM:, HKCU:, HKCR: or HKU:
[Monitoring]    [Syntax]  registry paths or names that include a space need to be enclosed in single quotes '...'
  
[Monitoring] 11. [RegValue] Wait for the creation(:True)/removal([:False]) of registry value name
[Monitoring]    Monitor a registry value name to be created under <RegKeyPath>
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent RegValue:<RegKeyPath>:<RegValueName>:True [-StopWaitTimeInSec <N>]
[Monitoring]    Monitor a registry value name to be deleted under <RegKeyPath>
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent RegValue:<RegKeyPath>:<RegValueName> [-StopWaitTimeInSec <N>]
[Monitoring]     Ex: .\$($global:ScriptName) -Start <xxx> -WaitEvent RegValue:HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters:TcpTimedWaitDelay
[Monitoring]        will be signaled, 

[Monitoring] 12. [RegKey] Wait for the creation(:True)/removal([:False]) of registry key path
[Monitoring]    Monitor a registry key <RegKeyPath> to be created:
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent RegKey:<RegKeyPath>:True [-StopWaitTimeInSec <N>]
[Monitoring]     Ex1: .\$($global:ScriptName) -procmon -WaitEvent RegKey:'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services':True
[Monitoring]    Monitor a registry key <RegKeyPath> to be deleted:
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent RegKey:<RegKeyPath> [-StopWaitTimeInSec <N>]
[Monitoring]     Ex2: .\$($global:ScriptName) -procmon -WaitEvent RegKey:'HKLM:SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -StopWaitTimeInSec 11

[Monitoring] 13. [File] Wait for a creation or deletion of a specified '<FilePath>' 
[Monitoring]    Monitor a new File to be created:
[Monitoring]     Ex1: .\$($global:ScriptName) -Start <xxx> -WaitEvent File:'<FilePath>':True [-StopWaitTimeInSec <N>]
[Monitoring]    Monitor an existing File to be deleted:
[Monitoring]     Ex2: .\$($global:ScriptName) -Start <xxx> -WaitEvent File:'<FilePath>' [-StopWaitTimeInSec <N>]
[Monitoring]    Example: .\$($global:ScriptName) -Start -ADS_Kerb -WaitEvent File:'C:\temp\TestMe.txt'
   
[Monitoring] 14. [Time] Wait for time elapsed event
[Monitoring]    Time:<N> Wait until N minutes elapsed:
[Monitoring]     Ex1: .\$($global:ScriptName) -Start <xxx> -WaitEvent Time:<N>       => we wait N minutes and then stop data collection
[Monitoring]    Time:<N>:Sec Wait until N seconds elapsed:
[Monitoring]     Ex2: .\$($global:ScriptName) -Start <xxx> -WaitEvent Time:<N>:Sec   => we wait N seconds and then stop data collection

[Monitoring] 15. [HNSL2Tunnel] Wait for HNS L2Tunnel Network is gone (Get-HNSNetwork)
[Monitoring]     Ex: .\$($global:ScriptName) -Start <xxx> -WaitEvent HNSL2Tunnel [-StopWaitTimeInSec <N>]

[Monitoring] 16. [LogFile] Wait for specific message/error-string 'search-string' in LogFile 'Path\LogfileName.ext'; 'search-string' could be a Regular Expression, such as 'Access.*Denied' (including 'Access Denied' 'Access is Denied')
[Monitoring]     Ex1: .\$($global:ScriptName) -Start <xxx> -WaitEvent LogFile:'<Path\LogfileName.ext>':'<search-string>' [-StopWaitTimeInSec <N>]
[Monitoring]     Ex2: .\$($global:ScriptName) -Start <xxx> -WaitEvent LogFile:'C:\AppFolder\MyLogfileName.log':'Access.*Denied'

[Monitoring] 17. [StopCondition] wait for a customizable stop condition (script-block) to return $False
[Monitoring]     PS> .\$($global:ScriptName) -Start <xxx> -WaitEvent StopCondition [-StopWaitTimeInSec <N>]
[Monitoring]     The customizable stop condition needs to be defined in \config\StopCondition.txt file. Please see instructions and some examples inside the StopCondition.txt file

[Monitoring] 18. Wait for an event and trigger forced memory dump/crash after the event is signaled. Attention: system will reboot
[Monitoring]     Ex: .\$($global:ScriptName) -Start <xxx> -WaitEvent <EventType> -Crash

[Monitoring] 19. [HighCPU] Wait for highCPU time to occur. Once CPU time exceeds <CpuThreshold>% for a duration of <HighCPUtimeInSec> seconds (default=10 sec) we keep on Collecting data for a duration of <StopWaitTimeInSec> seconds (default=60 sec).
[Monitoring]     Note: for testing you can use SysInternals CPUstres tool (https://docs.microsoft.com/en-us/sysinternals/downloads/cpustres)
[Monitoring]     PS>  .\$($global:ScriptName) -Start <xxx> -WaitEvent HighCPU:<CpuThreshold> [-StopWaitTimeInSec <N>] [-HighCPUtimeInSec <N>]
[Monitoring]     Ex1: .\$($global:ScriptName) -Xperf CPU -WaitEvent HighCPU:80 -StopWaitTimeInSec 60 -HighCPUtimeInSec 20 (here we will stop recording 60 seconds after CPU consumption reached 80% average for 20 seconds)

[Monitoring] 20. [HighMemory] Wait for highMemory consumption to occur. Once Memory consumption exceeds <MemoryThreshold>% for a duration of <HighMemUsageInSec> seconds (default=10 sec) we keep on Collecting data for a duration of <StopWaitTimeInSec> seconds (default=60 sec).
[Monitoring]     PS>  .\$($global:ScriptName) -Start <xxx> -WaitEvent HighMemory:<MemoryThreshold> [-StopWaitTimeInSec <N>] [-HighMemUsageInSec <N>]
[Monitoring]     Ex1: .\$($global:ScriptName) -Xperf Memory -WaitEvent HighMemory:90 -StopWaitTimeInSec 60 -HighMemUsageInSec 15 (here we will stop recording 60 seconds after memory consumption reached 90% average for 15 seconds)

[Monitoring] 21. [Signal] Wait for a named signal sent by local OS built-in command 'WAITFOR.exe /SI <SignalString>' to occur. Once <SignalString> is received, we stop data collection.
[Monitoring]     Note: this curretly works only for local machine notifications
[Monitoring]     PS>  .\$($global:ScriptName) -Start <xxx> -WaitEvent Signal:<SignalString> [-StopWaitTimeInSec <N>]

[Monitoring] 22. [ATQ] Wait for (ADS) ATQ Thread Exhaustion on Domain Controller to occur.
[Monitoring]     PS>  .\$($global:ScriptName) -Start <xxx> -WaitEvent ATQ [-StopWaitTimeInSec <N>]

[Monitoring] See also:
[Monitoring] URL: https://github.com/shared-internal-tools/WindowsCSSToolsDevRep/wiki/Using-event-monitoring
[Monitoring] or section 'Monitoring' in internal KB https://internal.support.services.microsoft.com/en-us/help/4619187

[Remoting] Remoting (-RemoteHosts)
==================================
[Remoting] You can use the monitoring feature (-WaitEvent) on multiple remote hosts together with remoting feature -RemoteHosts (to be started on 'failing' system). 
[Remoting] Remoting is helpful when you collect data on a system using monitoring and want to wait until a stop condition is met. 
[Remoting] In this case, after the stop condition is met, remoting feature sends signal (event ID 999) to all remote hosts. And then simultanously, all running traces on the remote hosts are stopped automatically without user interaction.

[Remoting] Remoting can be enabled 1. from command line (-RemoteHosts) or 2. through config file (tss_config.cfg).
[Remoting] Note: Command-line parameters take precedence over config file params.

[Remoting]  -RemoteHosts <host01,host02>           - specify comma separated list of remote hosts, which will be signaled after a stop condition is met or TSS is stoppe manually.
[Remoting]  -RemoteLogfolder '<\\Server01\share>'  - optional remote share folder name where resulting log files of all remote hosts should be copied to.

[Remoting] 1. Enable remoting from command-line on the system which is expected to observe Event ID 1000
[Remoting]   To enable remoting, use -RemoteHosts switch to specify one or more remote hosts, on which TSS traces are/will be started manually with switch -WaitEvent and be stopped automatically after being signaled.
[Remoting]   Whenever you specify -RemoteHosts <host01,host02>, TSS will notify those remote hosts to stop data collection.
[Remoting]   Note: You can in addition specify a remote share folder (-RemoteLogfolder) where log files are copied to, after stopping trace. 
[Remoting]      -RemoteLogfolder is helpful if the number of remote hosts is large and you want to consolidate all logs to one folder.

[Remoting]  Example:
[Remoting]   PS> .\$($global:ScriptName) -Scenario NET_General -RemoteHosts PC01,PC02  # this line line will send a stop trigger to host PC01 and PC02 once you stop the data collection.
[Remoting]    Start below command on all remote hosts (cluster01, cluster02 and cluster03 in this example)
[Remoting]     PS> .\$($global:ScriptName) -SHA_MsCluster -WaitEvent StopEvt:1000:System -RemoteHosts cluster01,cluster02,cluster03 -RemoteLogfolder '\\cluster01\share'
[Remoting]   Note: besides the Event 1000, a remoting enabled system is also listening on System Event ID 999. This ID basically instructs remote system to stop data-collection. The system that experiences actual ID 1000 will send StopTrigger ID 999 to all other systems.

[Remoting] 2. (optional) Enable remoting through config file
[Remoting]    2a.) Edit 'tss_config.cfg' in TSS '\config\' folder and add below lines. Also copy your 'tss_config.cfg' file to TSS '\config\' folder on all remote hosts.
[Remoting]       _EnableRemoting=y
[Remoting]       _WriteEventToHosts=cluster01,cluster02,cluster03
[Remoting]       _RemoteLogFolder=\\cluster01\share  # This is optional parameter
[Remoting]       _EnableMonitoring=y
[Remoting]       _EventlogName="System"
[Remoting]       _Stop_EventID=1000
[Remoting]      Above settings mean that the script will wait until the event ID 1000 is recorded on one of the remote hosts (cluster01,cluster02,cluster03) and once the event happens on such remote host, 
[Remoting]      TSS will stop all traces running on all remote hosts, and copy all collected logs to '\\cluster01\share'. 
[Remoting]      So you don't need to logon to all remote hosts to gather the log files. The log files from all hosts will be copied there in the shared folder that is specified by '_RemoteLogFolder' parameter.

[Remoting]    2b.) Start a component or scenario trace on all remote hosts. The script will wait and does not fall back to command prompt until the event is recorded.
[Remoting]      Ex.: PS> .\$($global:ScriptName) -SHA_MsCluster -WaitEvent Evt:1000:System
[Remoting]    Once the event ID 1000 is recorded in the 'System' log on any of local or remote hosts, the trace running on all (remote) hosts will be stopped automatically and then all logs on all hosts will be saved in '\\cluster01\share'.
"@

if (!$SkipMenu.IsPresent){ # skip Help_Menue for -Find <keyword> # see ProcessFindKeyword
	Write-Host ' '
	Write-Host "TSS HELP MESSAGE (Version $global:TSSVerDate):"
	Write-Host "==========================================================================="
	Write-Host "Nr  Category	 Description"
	Write-Host "==========================================================================="
	Write-Host ([String]::Format("{0,2}","0") + "  Common	 Common general help message")
	Write-Host ([String]::Format("{0,2}","1") + "  ADS		All available options for Active Directory Service POD")
	Write-Host ([String]::Format("{0,2}","2") + "  CRM		All available options for Dynamics CRM")
	Write-Host ([String]::Format("{0,2}","3") + "  DND		All available options for Device and Deployment POD")
	Write-Host ([String]::Format("{0,2}","4") + "  INT		All available options for Biztalk Integration")	
	Write-Host ([String]::Format("{0,2}","5") + "  NET		All available options for Networking POD")
	Write-Host ([String]::Format("{0,2}","6") + "  PRF		All available options for Performance POD")
	Write-Host ([String]::Format("{0,2}","7") + "  SEC		All available options for Security POD")
	Write-Host ([String]::Format("{0,2}","8") + "  SHA		All available options for Storage and High Availability POD")
	Write-Host ([String]::Format("{0,2}","9") + "  SPS		All available options for SharePoint Server")
	Write-Host ([String]::Format("{0,2}","10") + "  UEX		All available options for User Experience POD")
	Write-Host ([String]::Format("{0,2}","11") + "  ALL		All available options for ALL PODs")
	Write-Host ([String]::Format("{0,2}","12") + "  Monitoring Show help message for Monitoring and Remoting feature")
	Write-Host ([String]::Format("{0,2}","13") + "  Config	 All available config parameters")
	Write-Host ([String]::Format("{0,2}"," ") + "  keyword	") -NoNewline -ForegroundColor Cyan; Write-Host ("Enter any search keyword to show all help lines that match the keyword")
	Write-Host ("---------------------------------------------------------------------------")
	Write-Host ("Select a number or enter any keyword ") -NoNewline -ForegroundColor Cyan
	$Ans = Read-Host "[0-13 or any keyword]"
	If([String]::IsNullOrEmpty($Ans)){
		$Ans = '0'
	}
}
	Switch($Ans){
		'0'{
			Write-output $HelpMessage | more
			Return
		}
		'1'{$PODName="ADS";$Pattern="ADS_"}
		'2'{$PODName="CRM";$Pattern="CRM_"}
		'3'{$PODName="DND";$Pattern="DND_"}
		'4'{$PODName="INT";$Pattern="INT_"}
		'5'{$PODName="NET";$Pattern="NET_"}
		'6'{$PODName="PRF";$Pattern="PRF_"}
		'7'{$PODName="SEC";$Pattern="SEC_"}
		'8'{$PODName="SHA";$Pattern="SHA_"}
		'9'{$PODName="SPS";$Pattern="SPS_"}
		'10'{$PODName="UEX";$Pattern="UEX_"}
		'11'{ProcessList;return}
		'12'{
			Write-Output $HelpMessageForMonitoring | more
			Return
		}
		'13'{
			Write-Host "See below for the detail on config parameters for TSS (\config\tss_config.cfg)."
			Write-Host "URL: https://github.com/shared-internal-tools/WindowsCSSToolsDevRep/wiki/Parameters-for-TSSv2-config-file"
			Write-Host "or section 'Parameters for TSS config file' in internal KB https://internal.support.services.microsoft.com/en-us/help/5027643"
			Write-Host "Note: Command-line parameters take precedence over config params"
			Return
		}
		default {$PODName="ALL";$Pattern="$Ans"}
	}

	# Create help messages, show Monitoring, Commands, Controls, NoOptions, CollectLog, Diag, NetshScenario, WPR, Xperf, PerfMon, SDP, Components and Scenarios
	Write-Host "...Creating help message..." -ForegroundColor Gray
	Write-Output $HelpMessage | Out-File -Append "$env:temp\TSS-help-General.txt"
	Write-Output $HelpMessageForMonitoring | Out-File -Append "$env:temp\TSS-help-Monitoring.txt"
	# All outputs from below functions go to information stream(6). So redirect them to standard output(1) by using '6>&1'
	ProcessListSupportedCommands 6>&1 | Out-File -Append "$env:temp\TSS-help-Commands.txt"
	ProcessListSupportedControls 6>&1 | Out-File -Width 500 -Append "$env:temp\TSS-help-Controls.txt"
	ProcessListSupportedNoOptions 6>&1 | Out-File -Append "$env:temp\TSS-help-NoOptions.txt"
	ProcessListSupportedLog 6>&1 | Out-File -Width 500 -Append "$env:temp\TSS-help-CollectLog.txt"
	ProcessListSupportedDiag 6>&1 | Out-File -Append "$env:temp\TSS-help-StartDiag.txt"
	ProcessListSupportedNetshScenario 6>&1 | Out-File -Append "$env:temp\TSS-help-NetshScenario.txt"
	ProcessListSupportedWPRScenario 6>&1 | Out-File -Append "$env:temp\TSS-help-WPR.txt"
	ProcessListSupportedXperfProfile 6>&1 | Out-File -Width 500 -Append "$env:temp\TSS-help-Xperf.txt"
	ProcessListSupportedPerfCounter -AnswerYes 6>&1 | Out-File -Append "$env:temp\TSS-help-PerfMon.txt"
	ProcessListSupportedSDP 6>&1 | Out-File -Append "$env:temp\TSS-help-SDP.txt"
	ProcessListSupportedTrace $PODName -noMore 6>&1 | Out-File -Width 500 -Append "$env:temp\TSS-help-Trace.txt"
	ProcessListSupportedScenarioTrace $PODName -noMore 6>&1 | Out-File -Width 500 -Append "$env:temp\TSS-help-Scenario.txt"

	Write-Host "...Searching help messages with keyword=""$Pattern"" ..." -ForegroundColor Gray
	$HelpFiles = @(
		"$env:temp\TSS-help-General.txt",
		"$env:temp\TSS-help-Monitoring.txt",
		"$env:temp\TSS-help-Commands.txt",
		"$env:temp\TSS-help-Controls.txt"
		"$env:temp\TSS-help-NoOptions.txt"
		"$env:temp\TSS-help-CollectLog.txt",
		"$env:temp\TSS-help-StartDiag.txt",
		"$env:temp\TSS-help-NetshScenario.txt",
		"$env:temp\TSS-help-WPR.txt",
		"$env:temp\TSS-help-Xperf.txt",
		"$env:temp\TSS-help-PerfMon.txt",
		"$env:temp\TSS-help-SDP.txt"
		"$env:temp\TSS-help-Trace.txt",
		"$env:temp\TSS-help-Scenario.txt"
	)

	$MatchInfoList = New-Object 'System.Collections.Generic.List[Object]'
	ForEach($HelpFile in $HelpFiles){
		$Lines = Select-String -Path $HelpFile -Pattern $Pattern
		$Category = $HelpFile -replace "^.*-help-",""
		$Category = $Category -replace "\.txt",""
		$MatchInfoObject = [PSCustomObject]@{
			Name	 = $Category
			MatchInfoArray = $Lines
		}
		$MatchInfoList.Add($MatchInfoObject)
	}

	If($($MatchInfoList.MatchInfoArray).count -eq 0) {
		Write-Host "Could not find any match for keyword ""$Ans""." -ForegroundColor cyan
		#Return		#we# don't return here, as long as there is no caching implemented for generated help-texts
	}
	# Show search result
	ForEach($MatchInfo in $MatchInfoList){
		If($($MatchInfo.MatchInfoArray).Count -ne 0){
			Switch($MatchInfo.Name){
				'Trace' {Write-Host " * Trace (-Start, -StartAutologger, -StartNowait):"}
				'General' {Write-Host " * General help:"}
				default {Write-Host (" -" + $MatchInfo.Name + ":")}
			}

			ForEach($MatchObject in $MatchInfo.MatchInfoArray){
				Write-Host $MatchObject.Line
			}
			Write-Host ' '
		}
	}
	Remove-Item -Force "$env:temp\TSS-help*" -ErrorAction Ignore | Out-Null
	EndFunc $MyInvocation.MyCommand.Name
}

Function RegisterPurgeTask{
	EnterFunc $MyInvocation.MyCommand.Name
	If($global:OSVersion.Build -gt 9200){	#_# Get-ScheduledTask is not supported on 2008-R2
		$TaskIntervalInMinute = 5 # 5 minutes interval by default
		$PurgeScriptName = "$global:ScriptsFolder\tss_Purgelog.ps1"
		If($StartAutologger.IsPresent){
			$PurgeTaskName = $Script:PurgeTaskNameForAutologger
			$Trigger = New-ScheduledTaskTrigger -AtStartup
		}Else{
			$PurgeTaskName = $Script:PurgeTaskName
			$Trigger = New-ScheduledTaskTrigger -once -at (get-date)
		}
		
		If(!(Test-Path -Path "$global:ScriptsFolder\tss_Purgelog.ps1")){
			Throw "tss_Purgelog.ps1 not found."
		}
		
		# Create purge task
		$Actions = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument "& $PurgeScriptName"
		$Principal = New-ScheduledTaskPrincipal -UserID 'SYSTEM' -RunLevel Highest
		$Settings = New-ScheduledTaskSettingsSet
		$task = New-ScheduledTask -Action $Actions -Principal $Principal -Trigger $Trigger -Settings $Settings
		LogInfo "Registering a task($PurgeTaskName) to purge log files."
		Register-ScheduledTask -TaskName $PurgeTaskName -InputObject $task -ErrorAction Ignore | Out-Null
		
		# Add repetition settings.
		$t = Get-ScheduledTask -TaskName $PurgeTaskName
		$t.Triggers.Repetition.Interval = ("PT" + $TaskIntervalInMinute + "M")
		Set-ScheduledTask -InputObject $t | Out-Null
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function UnRegisterPurgeTask{
	EnterFunc $MyInvocation.MyCommand.Name
	If($global:OSVersion.Build -gt 9200){	#_# Get-ScheduledTask is not supported on 2008-R2
		$TaskNames = @($Script:PurgeTaskName, $Script:PurgeTaskNameForAutologger)
		ForEach($TaskName in $TaskNames){
			$Task = $Null
			$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Ignore
			If($Null -ne $Task){
				LogInfo "Deleting `'$TaskName`' task."
				Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
			}
		}
		$PurgeLog = "C:\Windows\temp\$($env:COMPUTERNAME)__Log-PurgeTask.txt"
		If(Test-Path -Path $PurgeLog){
			Move-Item $PurgeLog $global:LogFolder -ErrorAction SilentlyContinue
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

#endregion FW Core functions

#region monitoring functions
Function Test_File{
	[OutputType([Bool])]
	Param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$True)]
		[String]$FilePath,
		[Parameter(Mandatory=$False)]
		[Bool]$SignalOnCreation = $False
	)
	LogDebug "Test_File with $FilePath is called($SignalOnCreation)."

	If(Test-Path $FilePath){
		If($SignalOnCreation){
			LogInfo "File $FilePath got created. Test_File is signaled." "Red"
			# copy new file 
			Copy-Item $FilePath -Destination $global:LogFolder
			Return $False # signaled.
		}Else{
			Return $True
		}
	}Else{
		If($SignalOnCreation){
			Return $True
		}Else{
			LogInfo "File $FilePath got removed. Test_File is signaled." "Red"
			Return $False # signaled
		}
	}
}

Function Test_RegData{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyRoot,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyPath,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$ValueName,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$ExpectedData,
		[Parameter(Mandatory=$False)]
		[Bool]$IsOpposite = $False
	)
	# HKU and HKCR by default do not exist as PSdrive
	if (!(Test-Path HKU:)){New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null} #bug 403
	if (!(Test-Path HKCR:)){New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null}

	$RegKeyPath = $KeyRoot + ":\" + $KeyPath
	$RegFullPath = $RegKeyPath + "\" + $ValueName # Used only for debug message
	LogDebug "Test_RegData for $RegFullPath with expected value $ExpectedData is called."

	$RegData = Get-ItemProperty $RegKeyPath -name $ValueName -ErrorAction Ignore
	If(($Null -ne $RegData) -and ($RegData.$ValueName -eq $ExpectedData)){
		If($IsOpposite){
			LogDebug "$ValueName is still $($RegData.$ValueName)"
			Return $True
		}Else{
			LogInfo "$ValueName becomes $ExpectedData. Test_Reg for $RegFullPath is signaled." "Red"
			Return $False # signaled (Expected data is set to the registry.
		}
	}Else{
		If($IsOpposite){
			LogInfo "$ValueName was changed to $($RegData.$ValueName). Test_Reg for $RegFullPath is signaled." "Red"
			Return $False # signaled
		}Else{
			LogDebug "`'$RegFullPath`' does not exist or value($($RegData.$ValueName)) is not expected value($ExpectedData) yet."
			Return $True
		}
	}
}

Function Test_RegValue{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyRoot,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyPath,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$ValueName,
		[Parameter(Mandatory=$False)]
		[Bool]$IsOpposite = $False
	)
	# HKU and HKCR by default do not exist as PSdrive
	if (!(Test-Path HKU:)){New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null} #bug 403
	if (!(Test-Path HKCR:)){New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null}

	$RegKeyPath = $KeyRoot + ":\" + $KeyPath
	$RegFullPath = $RegKeyPath + "\" + $ValueName # Used only for debug message
	LogDebug "Test_RegValue for `'$RegFullPath`' is called."

	# Check if key exists
	Try{
		$KeyObject = Get-ItemProperty -Path $RegKeyPath -ErrorAction Stop
	}Catch{
		If($IsOpposite){
			Return $True
		}Else{
			LogInfo "Key `'$RegKeyPath`' does not exist. Test_RegValue is signaled." "Red"
			Return $False # signaled. Key is aleady removed hence report as a signaled case.
		}
	}

	# Check if the value exists
	If($Null -eq $KeyObject.$ValueName){
		If($IsOpposite){
			Return $True
		}Else{
			LogInfo "Value `'$RegFullPath`' got removed. Test_RegValue is signaled." "Red"
			Return $False # signaled. Value got moved.
		}
	}Else{
		If($IsOpposite){
			LogInfo "Value `'$RegFullPath`' got created. Test_RegValue is signaled." "Red"
			Return $False # signaled. Value got created.
		}Else{
			Return $True
		}
	}
}

Function Test_RegKey{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyRoot,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyPath,
		[Parameter(Mandatory=$False)]
		[Bool]$IsOpposite = $False
	)
	# HKU and HKCR by default do not exist as PSdrive
	if (!(Test-Path HKU:)){New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null} #bug 403
	if (!(Test-Path HKCR:)){New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null}

	$RegKeyPath = $KeyRoot + ":\" + $KeyPath
	LogDebug "Test_RegKey for `'$RegKeyPath`' is called."

	# Check if key exists
	If(Test-Path $RegKeyPath){
		If($IsOpposite){
			LogInfo "Key `'$RegKeyPath`' got created. Test_RegKey is signaled." "Red"
			Return $False # signaled. Key was created hence report as a signaled case.
		}Else{
			Return $True
		}
	}Else{
		If($IsOpposite){
			Return $True
		}Else{
			LogInfo "Key `'$RegKeyPath`' got removed. Test_RegKey is signaled." "Red"
			Return $False # signaled. Key was removed hence report as a signaled case.
		}
	}
}

<# Need check with Walter for the purpose of this function
#Function Test_BCpercent {
#	# if MaxCacheSizeAsNumberOfBytes reaches 120% or 180% , checks performed in intervals of 5 minutes
#	$BCTestStatus =	& "$ScriptParentPath\tss_BCpercentRule.ps1" -Folderpath $Folderpath -BCpercentNr $BCpercent -NrOfDatFilesLimit $NrOfDatFilesLimit #-ErrorAction SilentlyContinue
#	if ("$BCTestStatus" -eq "False" ) {$Script:StopCondFound=0; LogInfo "Branch Cache test breached limit $BCpercent % or *.dat $NrOfDatFilesLimit, BCTestStatus result: $BCTestStatus "}
#	else { Write-Verbose "$(Get-date -Format G) | Result BCpercentRule: $BCTestStatus -- Script:StopCondFound $Script:StopCondFound -- CurrentActiveCacheSize: $((Get-BCDataCache).CurrentActiveCacheSize)" }
#}
#>

Function Test_PortLoc{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$PortLoc
	)
	LogDebug "Test_PortLoc with port $PortLoc is called."

	$Ports = $PortLoc -split '/'
	$Count = $Ports.Count
	ForEach($PortNumber in $Ports){
		$TcpTestStatus = Get-NetTCPConnection -State Listen -LocalPort $PortNumber -ErrorAction Ignore
		If(($Null -eq $TcpTestStatus) -or ($TcpTestStatus.TcpTestSucceeded -eq $False)){
			LogInfo "Test_PortLoc for $PortNumber is signaled." "Red"
			$Count--
		}
	}
	If($Count -eq 0){
		LogInfo "Test_PortLoc is signaled." "Red"
		Return $False # signaled.
	}Else{
		Return $True
	}
}

Function Test_PortDest{
	#we# consider FwTest-TCPport
	[OutputType([Bool])]
	Param(
		[ValidateNotNullOrEmpty()]
		[String[]]$ServerNames,
		[ValidateNotNullOrEmpty()]
		[String]$Port
	)
	LogDebug "Test_PortDest with port(s) $Port on Server(s) $ServerNames is called."
	$ServerList = $ServerNames -split ','
	$Ports = $Port -split '/'
	$PortCount = $Ports.Count
	$OkCnt=0
	ForEach($ServerName in $ServerList){
		ForEach($PortNumber in $Ports){
			$TcpTestStatus = Test-Netconnection -ComputerName $ServerName -Port $PortNumber -InformationLevel "Detailed" -ErrorAction Ignore -WarningAction SilentlyContinue
			If(($Null -eq $TcpTestStatus) -or ($TcpTestStatus.TcpTestSucceeded -eq $False)){
				LogInfo "Test_PortDest for port $PortNumber on $ServerName is signaled." "Red"
				$PortCount--
			}
		}
		If($PortCount -eq 0){
			LogInfo "Test_PortDest is signaled." "Red"
			Return $False # signaled.
		}Else{
			#Return $True
			$OkCnt++
		}
	}
	If($OkCnt -ge 1){Return $True}
}

Function Test_NoNetConn{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$False)]
		[String]$DestHost 	#Name or IP-address, if "DefaultGW" is supplied we test against Default Gateway
	)
	if ($DestHost -eq "DefaultGW") {
		$DefGWIP =(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty Nexthop)
		$PingTestStatus = Test-Connection $DefGWIP -Quiet -Count 1 -ErrorAction Ignore -WarningAction SilentlyContinue
	}else{
		if ([BOOL]($DestHost -as [IPADDRESS])){$DefGWIP =$DestHost}else{$DefGWIP =(Resolve-DnsName $DestHost -type A).IPAddress}
		$PingTestStatus = (test-NetConnection $DestHost -WarningAction SilentlyContinue).PingSucceeded
	}
	LogDebug "Test_NoNetConn on $DefGWIP) was called."
	If($Null -eq $PingTestStatus){
		LogError "ERROR: Something wrong happend in Test-Connection $DefGWIP. Return false so that monitor function to be exited."
		Return $False
	}
	If($PingTestStatus -eq $False){
		LogInfo "No Ping response from $DestHost ($DefGWIP). Test_NoNetConn is signaled." "Red"
		Return $False # signaled
	}Else{
		Return $True
	}
	Return $True
}

Function Test_Share{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$ServerName,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$ShareName
	)
	$SharePath = "\\$ServerName\$ShareName"
	LogDebug "Test_Share with $SharePath is called."

	# check if $ShareName is reachable via SMB
	If((Test-Path $SharePath)){
		Return $True
	}Else{
		LogInfo "Test_Share for unreachable $SharePath is signaled." "Red"
		Return $False # signaled
	}
} 

Function Test_LogFile{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$LogFilePath,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$SearchString
	)
	LogDebug "Test_LogFile for Search-string $SearchString exists in file $LogFilePath is called."
	If(Select-String -Path $LogFilePath -Pattern $SearchString){
		LogInfo " => please be sure that the Search-string (or RegEx) '$SearchString' in file '$LogFilePath' is not already existant at start of tracing." "Magenta"
	}
	# check if string $SearchString does not exist in Log file $LogFilePath
	If(!(Select-String -Path $LogFilePath -Pattern $SearchString)){
		Return $True
	}Else{ # $SearchString found!
		LogInfo "Test_LogFile for Search-string '$SearchString' in file '$LogFilePath' is signaled." "Red"
		# copy Log file
		LogInfoFile "[Test_LogFile] Copy monitored Log file $LogFilePath to TSS data folder"
		Copy-Item $LogFilePath -Destination $global:LogFolder
		Return $False # signaled
	}
}

Function Test_CommonTCPPort{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateSet("SMB", "HTTP", "RDP", "WINRM")]
		[String]$Protocol,
		[Parameter(Mandatory=$False)]
		[String[]]$ServerNames
	)
	$ServerList = $ServerNames -split ',' #.split("/")
	LogDebug "Test_CommonTCPPort with protocol $Protocol for Server(s) $ServerNames is called."
	$OkCnt=0
	foreach ($ServerName in $ServerList) {
		$TcpTestStatus = Test-NetConnection -ComputerName $ServerName -CommonTCPPort $Protocol -InformationLevel "Detailed" -ErrorAction Ignore -WarningAction SilentlyContinue
		If($Null -eq $TcpTestStatus){
			LogError "ERROR: Something wrong happend in Test-Netconnection. Return false so that monitor function to be exited."
			Return $False	# signaled on error
		}
		If(!($TcpTestStatus.TcpTestSucceeded)){
			LogInfo "$ServerName stopped listening on $Protocol. Test_CommonTCPPort is signaled." "Red"
			Return $False	# signaled
		}Else{
			#Return $True
			$OkCnt++
		}
	}
	If($OkCnt -ge 1){Return $True}
	Return $True
}

Function Test_LDAP{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[String]$DomainName
	)
	LogDebug "Test_LDAP with $DomainName is called."
	$TestStatus = nltest /DSGETDC:$DomainName /LDAPONLY | Out-Null
	If($LASTEXITCODE -ne 0 ){
		LogInfo "DC in Domain $DomainName is not reachable via /LDAPONLY, result: $TestStatus - LASTEXITCODE: $LASTEXITCODE" "Red"
		Return $False # signaled
	}
	Return $True
}

Function Test_HNSL2Tunnel{
	#[OutputType([Bool])]
	LogDebug "Test_HNSL2Tunnel gone is called."
	if (get-command Get-HNSNetwork -ErrorAction SilentlyContinue) {
		$HNSL2Tunnel = Get-HNSNetwork | Where-Object {($_.Type -eq "l2tunnel")}
		if ("$HNSL2Tunnel" -eq "$null" ) {
			LogInfo "L2Tunnel Network gone is signaled. Test_HNSL2Tunnel is signaled. Running data collection now for StopWaitTimeInSec=$StopWaitTimeInSec seconds" "Red"
			Return $False # signaled
		}
		Return $True
	}Else{ LogInfo "WARNING: There is no HNSL2Tunnel on this system" "Magenta"}
}

Function Test_Svc{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $SvcName
	)
	LogDebug "Test_Svc with $SvcName is called."

	# check if service status is Running  (not Stopped)
	$SvcStatus = ((Get-Service $SvcName -ErrorAction Ignore).Status)
	#_#if ($SvcStatus -ne "Running"){
	if ($SvcStatus -ne [System.ServiceProcess.ServiceControllerStatus]::Running){
		LogInfo "$SvcName stopped running: $SvcStatus. Test_Svc is signaled." "Red"
		Return $False # signaled
	}Else{
		Return $True
	}
} 

Function Test_Process{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $ProcessName
	)
	LogDebug "Test_Process with $ProcessName is called."

	# check if Process is running 
	$ProcessObject = Get-Process -Name $ProcessName -ErrorAction Ignore
	If($Null -eq $ProcessObject){
		LogInfo "$ProcessName is not running. Test_Process is signaled." "Red"
		Return $False # signaled
	}Else{
		Return $True
	}
}

Function Test_EventLog{
	<# Name: Test_EventLog [-EventIDs -EventlogName -CheckIntInSec -WaitTimeInSec -EventData -EvtDataPartial -EvtDataOperator]
	if you invoke from CMD:
	 PowerShell -noprofile "&{Invoke-Command -ScriptBlock {$EventID=30800;$SearchBackTime=60000;$EventlogName="Microsoft-Windows-SmbClient/Operational"; Get-WinEvent -LogName $EventlogName -FilterXPath "*[System[EventID=$EventID and TimeCreated[timediff(@SystemTime) <= $SearchBackTime]]]" -MaxEvents 5 -ErrorAction SilentlyContinue}}"
	 PowerShell -noprofile "&{Invoke-Command -ScriptBlock {Get-WinEvent -LogName "Microsoft-Windows-SmbClient/Operational"  -FilterXPath "*[System[EventID=30800]]" -MaxEvents 3 -ErrorAction SilentlyContinue }}"
	#Eventlogs location on disk: "C:\Windows\System32\winevt\Logs\Microsoft-Windows-SmbClient%4Operational.evtx"
	Example to delete Source
	 Get-CimInstance win32_nteventlogfile -Filter "logfilename='Microsoft-Windows-SmbClient/Operational'" | foreach {$_.sources}
	 Remove-Eventlog -Source "TSS"
	For Testing:
	 you can watch for 40961/40962 in "Microsoft-Windows-PowerShell/Operational", which is logged when starting a  new PoSh window
	.SYNOPSIS
	Purpose: Monitor Eventlogs for specific event and stop script; in combi with TSS: stop the script based on EventIDs in a non classic Eventlog
		The stop trigger condition is true if the EventID is found in specified Eventlog up to CheckIntInSec back in time, the control is given back to calling script.
		From CMD script you can invoke this PowerShell script by: PowerShell -noprofile -file "tss_EvtMon.ps1" -EventID 30800 -EventlogName "Microsoft-Windows-SmbClient/Connectivity" -EventData 0
		Multiple EventIDs are separated by '/', for example -EventID 40961/40962
		Multiple EventData strings are separated by '/', for example -EventData C:\Windows\System32\calc.exe/C:\Windows\System32\cmd.exe

	If you experience PS error '...is not digitally signed.' change Policy to RemoteSigned or Bypass by running the command:
	 Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
	 SYNTAX: MonitorEventLog -EventID 30800 -EventlogName "Microsoft-Windows-SmbClient/Connectivity" -EventData 'find-my-string'

	.DESCRIPTION
	The script will stop, once the specific details EventID(s) and Eventdata string(s) are all met.
	You need to run the script in Admin PowerShell window, if you want to monitor 'Security' Event Log
	You can append the -verbose parameter to see more details.
	When entering -EventData string, please enter the complete string as seen in Event 'XML View', for example 'C:\Windows\System32\calc.exe'
	 as seen in 'XML View' <Data Name="NewProcessName">C:\Windows\System32\calc.exe</Data> 
	In additin to any specific EventID, the script will also listen on EventID 999 in Application eventlog, and stop when it sees 999 sent by a remote system as a stop trigger.
	.PARAMETER EventIDs
		The Event ID wot watch for, separate multiple IDs with '/', Ex.: 30800/30809
	.PARAMETER CheckIntInSec
		Specify how often (time-interval in seconds) to search for given EventID(s)
	.PARAMETER EventlogName
		Specify name of Eventlog, i.e. "Microsoft-Windows-PowerShell/Operational" or "Microsoft-Windows-SmbClient/Operational"
	.PARAMETER WaitTimeInSec
		Force a wait time in seconds after an event is found,  this will instruct tss to stop x seconds later.
	.PARAMETER EventData
		Specify a complete string that is seen in Eventlog XML view <Data>"your complete string"</Data>
	.PARAMETER EvtDataPartial
		Specify a unique keyword that is part of the complete message, to allow search for partial event data message
		This does not require a full string between <Data> .. </Data>, partial match is ok
	.PARAMETER EvtDataOperator
		combine multiple EventData search terms by AND or OR operator (default = OR)
	.EXAMPLE
	 MonitorEventLog -EventID 30800 -EventlogName "Microsoft-Windows-SmbClient/Connectivity" -EventData 0
	.EXAMPLE
	 MonitorEventLog -EventID 4688/4689 -EventlogName "Security" -EventData C:\Windows\System32\calc.exe/C:\Windows\System32\cmd.exe -verbose
	 This will monitor for multiple EventIDs  4688 and 4689, checking if either string 'C:\Windows\System32\calc.exe' or 'C:\Windows\System32\cmd.exe' exist in given EventID(s) 
	.EXAMPLE
	 MonitorEventLog -EventID 40961/40962 -EventlogName "Microsoft-Windows-PowerShell/Operational" -EventData 0
	 This will monitor for multiple EventIDs 40961 and 40962 in Microsoft-Windows-PowerShell/Operational, will be triggered as soon as a new PowerShell window opens
	.EXAMPLE
	 MonitorEventLog -EventID 4624 -EventlogName "Security" -EventData "Contoso.com/User1" -EvtDataPartial -EvtDataOperator "AND"
	 This will monitor for EventID 4624 in Security eventlog, will be triggered as soon as a Logon attempt from "User1" in domain "Contoso.com" is logged, AND means both criteria must match; omitting -EvtDataOperator or choosing "OR" will fire if one criteria is found in EventID 4624
	.EXAMPLE
	  [Info] for testing it is sufficient to specify an existing "Source", i.e.
	  Write-EventLog -LogName "Application" -Source "Outlook" -EventID 59 -EntryType Information -Message "Test this EventID as stop trigger." -Category 1 -RawData 10,20 -ComputerName $Env:Computername
	  Note, you can also use the script tss_EventCreate.ps1 to fire such event.
	.OUTPUTS
	 Returns $True if the specified event is not recorded. Return $False if the event is recorded.
	#>
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True,Position=0,HelpMessage='Choose the EventID, or multiple separated by slash / ')]
		[string[]]$EventIDs, 		# separate multiple IDs with '/', Ex.: 30800/30809
		[Parameter(Mandatory=$False,Position=2,HelpMessage='Choose name of EventLog-File' )]
		[string]$EventlogName, 		# name of Eventlog, i.e. "Microsoft-Windows-PowerShell/Operational" #"Microsoft-Windows-SmbClient/Operational"
		[Parameter(Mandatory=$False,Position=3,HelpMessage='Choose the amount of time to search back in seconds ')]
		[Int32]$CheckIntInSec = 0,	# specify time-interval in seconds to search back, # how often in seconds should the evenlog file be scanned?
		[Parameter(Mandatory=$False,Position=4,HelpMessage='Choose Stop WaitTime in Sec')]
		[Int32]$WaitTimeInSec = 0,	# this specifis the forced wait time after an event is detected
		[Parameter(Mandatory=$False,Position=5,HelpMessage='optional: complete string in any EventData, or multiple separated by slash / ')]
		[string[]]$EventData = '0',	#'3221226599' # = STATUS_FILE_NOT_AVAILABLE / '3221225996' = STATUS_CONNECTION_DISCONNECTED / '0' = STATUS_SUCCESS
		[Parameter(Mandatory=$False,Position=6,HelpMessage='Search for keywords in event Message')]
		[Switch]$EvtDataPartial,	# allow search for partial event data message
		[Parameter(Mandatory=$False,Position=7,HelpMessage='choose operator for EventData: AND OR')]
		[string]$EvtDataOperator="OR",	# AND will fire only if both conditions are true
		[Parameter(Mandatory=$False,Position=8,HelpMessage='choose operator for EventData: AND OR')]
		[string]$EvtMaxEvents=1		# number of latest events with same EventID to investigate;
	)
	EnterFunc $MyInvocation.MyCommand.Name
	[Int32]$MaxEvents = $EvtMaxEvents	# Specifies the maximum number of events that Get-WinEvent returns.  
	[Int32]$SearchBackTime = 0 #amount of time in MilliSec to search back
	[string[]]$Event_ID_list=$EventIDs.split("/")
	[array]$xpaths= @()
	$EvtDataStrings = $EventData.split("/")
	[string]$EvtDataStrings_Or = $EventData.replace("/","|")  # default OR operator in partial EventData search
	[string[]]$EvtDataStrings_And = $EventData.Split("/")  # implement AND operator for multple partial EventData words

	If($CheckIntInSec -gt 0){
		LogDebug "Sleep $CheckIntInSec(CheckIntInSec) seconds."
		Start-Sleep -second $CheckIntInSec
	}

	# Check if the evenlog log name is valid.
	Try{
		$logDetails =  Get-WinEvent -ListLog $EventlogName -ErrorAction Stop
	}Catch{
		$PossibleEventLogNames = @()
		$Tokens = $EventlogName -split ' '
		ForEach($Token in $Tokens){
			LogInfo "$Token"
			$PossibleEventLogNames += Get-WinEvent -ListLog "*$Token*" -ErrorAction Ignore
		}
		$Tokens = $EventlogName -split '/'
		$PossibleEventLogNames += Get-WinEvent -ListLog "*$($Tokens[0])*" -ErrorAction Ignore
		If($PossibleEventLogNames.Count -ne 0){
			LogWarn "Unable to find `'$EventlogName`'"
			$PossibleEventLogNames = $PossibleEventLogNames | Get-Unique
			LogInfo "Possible correct Event log name would be following:"
			ForEach($PossibleEventLogName in $PossibleEventLogNames){
				$PossibleEventLogName
				Write-Host "   - $($PossibleEventLogName.LogName)"
			}
		}
		LogError "Unable to find `'$EventlogName`'. The name of the event log might not be valid."
		Throw $_ # Rethrow the exception to go into recovery process.
	}

	# Remove '-' and '/'. We will create a valuable this is the name for it.
	$tempName = $EventlogName -replace "-",""
	$EventlogNameForValuable = $tempName -replace "/",""
	$FwLastSearchStartTime = ($EventlogNameForValuable + $Event_ID_list[0])
	$CurrentTime = Get-Date

	$LastSearchTime = Get-Variable -Name $FwLastSearchStartTime -Scope Script -ValueOnly -ErrorAction Ignore
	If($Null -eq $LastSearchTime){
		New-Variable -Name $FwLastSearchStartTime -Scope Script -Value (Get-Date)
		$LastSearchTime = Get-Variable -Name $FwLastSearchStartTime -Scope Script -ValueOnly
		$TimeDiff = New-TimeSpan $script:FwScriptStartTime $CurrentTime
		LogDebug "Script start time			 : $script:FwScriptStartTime"
	}Else{
		$TimeDiff = New-TimeSpan $LastSearchTime $CurrentTime
	}

	$SearchBackTime = $TimeDiff.TotalSeconds * 1000 + 1000 # Interval sec from last search or script start time + 1 sec(buffer).

	# For debug log
	Set-Variable -Name $FwLastSearchStartTime -Scope Script -Value (Get-Date) # Update last search time. This is used when this function is called next time.
	$LastSearchTimeVariable = Get-Variable -Name $FwLastSearchStartTime -Scope Script # $LastSearchTimeVariable is used for just message only
	LogDebug "Eventlog name				 : $EventlogName"
	LogDebug "EventIDs					  : $Event_ID_list"
	LogDebug "Last search time variable name: $($LastSearchTimeVariable.Name)"
	LogDebug "Last search start time		: $LastSearchTime"
	LogDebug "Current time				  : $CurrentTime"
	LogDebug "SearchBackTime				: $SearchBackTime msec" # Search back time
	LogDebug "EvtDataStrings:"
	ForEach($EvtDataString in $EvtDataStrings){
		LogDebug "	- $EvtDataString"
	}
	if ($EvtDataStrings.count -gt 1){
		LogDebug "EvtDataOperator:	$EvtDataOperator"
		LogDebug "EvtDataStrings_Or:  $EvtDataStrings_Or"
		LogDebug "EvtDataStrings_And: count: $($EvtDataStrings_And.count) Search for: [1] $($EvtDataStrings_And[0]) AND [2] $($EvtDataStrings_And[1])"
	}else{
		LogDebug "Check for full Event data string: $EvtDataStrings"
	}
	
	foreach ($EventID in $Event_ID_list){
		if ($EvtDataPartial -and ($EvtDataStrings_And.count -gt 1)) {	# This does not require a full string between <data> .. </data>, partial match is ok;  #we#22.08.16# added: -and ($EvtDataStrings_And.count -gt 1)
			$xpath = 
@"
*[System[TimeCreated[timediff(@SystemTime) <= $SearchBackTime]]
[EventID=$EventID]]
"@
			$xpaths += $xpath
			LogDebug "---- EventID: $EventID - Xpath: `n$xpath"
		}Else{ # full match of 'EvtDataString'
			foreach($EvtDataString in $EvtDataStrings){
				if($EventData -ne '0'){
					LogDebug "EventData=$EvtDataString"
					$xpath = 
@"
*[System[TimeCreated[timediff(@SystemTime) <= $SearchBackTime]]
[EventID=$EventID]]
[EventData[Data='$EvtDataString']]
"@
				}Else{
					$xpath = 
@"
*[System[TimeCreated[timediff(@SystemTime) <= $SearchBackTime]]
[EventID=$EventID]]
"@
				}
				$xpaths += $xpath
			}
			LogDebug "---- EventID: $EventID - Xpath: `n$xpath"
		}
	}

	$IsFound = $False
	If($EvtDataPartial -and ($EvtDataOperator -ne "OR")){
		# Partial Event message and Operator = "AND"
		LogDebug "AND -- xpathCount: $($xpaths.count)"
		ForEach($xpath in $xpaths){
			LogDebug "1(Partial + AND): Get-WinEvent -LogName $EventlogName -MaxEvents $MaxEvents -FilterXPath $xpath -ErrorAction Ignore | Select-Object -Property Properties -ExpandProperty Properties with `'$EvtDataStrings_And`'"
			$Events = Get-WinEvent -LogName $EventlogName -MaxEvents $MaxEvents -FilterXPath $xpath -ErrorAction Ignore | Select-Object -Property Properties -ExpandProperty Properties
			If($Null -eq $Events){
				LogDebug "1: No event found."
			}
			ForEach($Event in $Events){
				LogDebug "1: Found event: $($Event.Value)"
				$Count = 0
				ForEach($EvtDataString in $EvtDataStrings_And){
					If([String]($Event.Value) -match $EvtDataString){
						$Count++
						LogDebug "1: Event message `"$($Event.Value)`" matches `'$EvtDataString`'(count=$Count/$($EvtDataStrings_And.count))"
						If($Count -eq $EvtDataStrings_And.Count){
							# Met all search keywords!
							If($WaitTimeInSec -ne 0){
								LogDebug "1: Wait for $WaitTimeInSec seconds."
								Start-Sleep -second $WaitTimeInSec
							}
							$IsFound = $True
						}
					}
				}
			}
		}
	}Else{
		LogDebug "Partial + OR/Full -- xpathCount: $($xpaths.count)"
		$Count = 0
		ForEach($xpath in $xpaths){
			# Partial Event message and Operator = "OR", or 'no Partial'
			If($EvtDataPartial -and ($EventData -ne 0) -and ($EvtDataStrings_And.count -gt 1)){ #we# added check for nr. of EvtDataStrings_And
				# search for partial string in EventData
				If(($EvtDataOperator -ieq "OR")){
					# Operator "OR", default
					LogDebug "2(Partial + OR): Get-WinEvent -LogName $EventlogName -MaxEvents $MaxEvents -FilterXPath $xpath -ErrorAction Ignore | Select-Object -Property Properties -ExpandProperty Properties with `'$EvtDataStrings_Or`'"
					$Events = Get-WinEvent -LogName $EventlogName -MaxEvents $MaxEvents -FilterXPath $xpath -ErrorAction Ignore | Select-Object -Property Properties -ExpandProperty Properties
					ForEach($Event in $Events){
						If([String]($Event.Value) -match $EvtDataStrings_Or){
							LogDebug "Found `"$($Event.Value)`""
							If($WaitTimeInSec -ne 0){
								LogDebug "2: Wait for $WaitTimeInSec seconds."
								Start-Sleep -second $WaitTimeInSec
							}
							$IsFound = $True # signaled.
						}
					}
				}
			}Else{
				# search for full string in EventData or only event id case(no event data search)
				$Message = "3(Full): Get-WinEvent -MaxEvents $MaxEvents -LogName $EventlogName -FilterXPath $xpath " # full match of 'EvtDataString'
				LogDebug $Message
				$EvtEntry = Get-WinEvent -MaxEvents $MaxEvents -LogName $EventlogName -FilterXPath $xpath -ErrorAction Ignore |Select-Object Message,Id,TimeCreated
				If($Null -eq $EvtEntry){
					LogDebug "3: Get-WinEvent returns ObjectNotFound"
				}Else{
					LogDebug ("Get-WinEvent returns $EvtEntry")
					If($WaitTimeInSec -ne 0){
						LogDebug "3: Wait for $WaitTimeInSec seconds."
						Start-Sleep -second $WaitTimeInSec
					}
					$Count++
				    LogDebug "EvtDataStrings_And.Count=$($EvtDataStrings_And.Count), HitCount=$Count"
					If($Count -ge $EvtDataStrings_And.Count){
					    $IsFound = $True # signaled.
					}
				}
			}
		}
	}
	EndFunc "$($MyInvocation.MyCommand.Name) with IsFound=$IsFound"
	If($IsFound){
		Return $False # signaled.
	}Else{
		Return $True
	}
}

Function WaitTime{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[Int] $WaitTime,
		[Parameter(Mandatory=$True)]
		[Bool] $Second
	)
	If($Second){
		 LogDebug "Wait for $WaitTime seconds"
		$WaitSeconds = $WaitTime
	}Else{
		$WaitSeconds = ($WaitTime * 60)
	}
	Start-Sleep -Seconds $WaitSeconds
	Return $False
}

Function WaitForSignal{
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $SignalString
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if (!$script:fAlreadyWaitedforSignalOnce){
		LogDebug "WAITFOR.exe $SignalString is called. Once $SignalString is received, signal event"
		$script:fAlreadyWaitedforSignalOnce =$True
		WAITFOR.exe $SignalString 2>&1
		If($LASTEXITCODE -eq 0){
			$Result = $False # = signaled
		}
		LogInfo "Named Signal ($SignalString) is received. Stopping tracing after StopWaitTimeInSec=$StopWaitTimeInSec seconds" "Red"
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $False
}

Function Test_StopCondition{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Test_StopCondition is called. If condition is met, signal event"
	if (Test-Path .\Config\StopCondition.txt){
		Try{
			$CondResult = Invoke-Command -ScriptBlock ([scriptblock]::Create((Get-Content ".\Config\StopCondition.txt")))
			if ($CondResult) {LogInfo "custom Test_StopCondition is met => signal event." "Red"}
			Return !($CondResult) # (-not $True) = False = signaled
		}Catch{ Throw $_ }
	}Else{ LogInfo "WARNING: The file .\Config\StopCondition.txt is missing" "Magenta"}
	EndFunc $MyInvocation.MyCommand.Name
}

Function Test_HighCPU{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$CpuThreshold
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Test_HighCPU with $CpuThreshold is called. If condition is met, signal event"
	If(([string]::IsNullOrEmpty($StopWaitTimeInSec)) -or ($StopWaitTimeInSec -eq 0)){ # define a minimum waitTime of 60 sec
		$StopWaitTimeInSec = 60
	}
	If(([string]::IsNullOrEmpty($HighCPUtimeInSec)) -or ($HighCPUtimeInSec -eq 0)){$HighCPUtimeInSec=10}
	$CPUValue = get-counter -Counter "\Processor Information(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples $HighCPUtimeInSec
	$HighCPUAvg = ($CPUValue.CounterSamples.CookedValue | Measure-Object -Average).Average
	if ($HighCPUAvg -gt $CpuThreshold) {
		LogInfo "'Total Processor Time' within $HighCPUtimeInSec sec is greater than $CpuThreshold`% (current Avg=$HighCPUAvg). Test_HighCPU is signaled. Running data collection now for StopWaitTimeInSec=$StopWaitTimeInSec seconds" "Red"
		Return $False # signaled
	}Else{
		Return $True
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function Test_HighMemory{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$MemoryThreshold
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Test_HighMemory with $MemoryThreshold is called. If condition is met, signal event"
	If(([string]::IsNullOrEmpty($StopWaitTimeInSec)) -or ($StopWaitTimeInSec -eq 0)){ # define a minimum waitTime of 60 sec
		$StopWaitTimeInSec = 60
	}
	If(([string]::IsNullOrEmpty($HighMemUsageInSec)) -or ($HighMemUsageInSec -eq 0)){$HighMemUsageInSec=10}
	$CommittedBytesInUse = get-counter -Counter "\Memory\% Committed Bytes In Use" -SampleInterval 1 -MaxSamples $HighMemUsageInSec
	$HighMemAvg = ($CommittedBytesInUse.CounterSamples.CookedValue | Measure-Object -Average).Average
	if ($HighMemAvg -gt $MemoryThreshold) {
		LogInfo "'Committed Bytes in Use' Percentage within $HighMemUsageInSec sec is greater than $MemoryThreshold`% (current Avg=$HighMemAvg). Test_HighMemory is signaled. Running data collection now for StopWaitTimeInSec=$StopWaitTimeInSec seconds" "Red"
		Return $False # signaled
	}Else{
		Return $True
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function Test_ATQ{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Test_ATQ is called. If condition is met, signal event"
	If(([string]::IsNullOrEmpty($StopWaitTimeInSec)) -or ($StopWaitTimeInSec -eq 0)){ # define a minimum waitTime of 60 sec
		$StopWaitTimeInSec = 60
	}
	$LdapAtqThreads = get-counter -counter "\DirectoryServices(NTDS)\ATQ Threads LDAP" -SampleInterval 5 -MaxSamples 1
	$OtherAtqThreads = Get-Counter -counter "\DirectoryServices(NTDS)\ATQ Threads Other" -SampleInterval 5 -MaxSamples 1
	$TotalAtqThreads = Get-Counter -counter "\DirectoryServices(NTDS)\ATQ Threads Total" -SampleInterval 5 -MaxSamples 1
	if ($LdapAtqThreads.CounterSamples.CookedValue + $OtherAtqThreads.CounterSamples.CookedValue -eq $TotalAtqThreads.CounterSamples.CookedValue) {
		LogInfo "ATQ Threads on DC are depleted. Test_ATQ is signaled. Running data collection now for StopWaitTimeInSec=$StopWaitTimeInSec seconds" "Red"
		Return $False # signaled
	}Else{
		Return $True
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function WaitForMultipleEvents{
	# .SYNOPSIS wait until a specific repro 'event' is hit
	EnterFunc $MyInvocation.MyCommand.Name

	###
	### Step 1: Display important global variables
	###
	LogInfo "Enter monitoring function with below parameters:"
	LogInfo "  - ErrorLimit = $global:ErrorLimit"
	LogInfo "  - IsRemoting = $global:IsRemoting"
	LogInfo "  - MonitorIntervalInSec = $FwMonitorIntervalInSec"
	LogInfo "  - IsMonitoringEnabledByConfigFile = $FwIsMonitoringEnabledByConfigFile"
	If($FwIsMonitoringEnabledByConfigFile -and [string]::IsNullOrEmpty($WaitEvent)){
		LogInfo "  => Using tss_config file to set up monitoring event"
	}Else{
		Write-Host "  => Using command line input ($WaitEvent) to set up monitoring event"
	}
	Write-Host ' '

	###
	### Step 2: Create test cases
	###
	$TestPropertyList = New-Object 'System.Collections.Generic.List[PSObject]'
	If($FwIsMonitoringEnabledByConfigFile -and [string]::IsNullOrEmpty($WaitEvent)){
		$TestCommandList = New-Object 'System.Collections.Generic.List[PSObject]'

		# Create test cases based on tss_config file
		ForEach($Key in $FwConfigParameters.keys){
			Switch($Key){
				'_PortLoc'{
					$LocalPortNumber = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($LocalPortNumber)){
						$TestCommand = "PortLoc:$LocalPortNumber"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_PortLoc=$LocalPortNumber)"
					}
				}
				'_PortDest'{
					$ServerName = $FwConfigParameters['_PortDestServerName']
					$PortNumber = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($ServerName) -and ![string]::IsNullOrEmpty($PortNumber)){
						$TestCommand = "PortDest:$ServerName" + ':' + $PortNumber
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_PortDest=$PortNumber / _PortDestServerName=$ServerName)"
					}
				}
				'_NoNetConn'{
					$DestHost = $FwConfigParameters['_noNetConnDestHost']
					If(![string]::IsNullOrEmpty($DestHost)){
						$TestCommand = "NoNetConn:$DestHost"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogInfo "NoNetConn Test will use IP of Default Gateway (_noNetConnDestHost=$DestHost)"
					}
				}
				'_SvcName'{
					$SvcName = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($SvcName)){
						$TestCommand = "Svc:$SvcName"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_SvcName=$SvcName)"
					}
				}
				'_ProcessName'{
					$ProcessName = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($ProcessName)){
						$TestCommand = "Process:$ProcessName"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_ProcessName=$ProcessName)"
					}
				}
				'_ShareName'{
					$ServerName = $FwConfigParameters['_ShareServerName']
					$ShareName = $FwConfigParameters[$Key] -Replace ("`"")
					If(![string]::IsNullOrEmpty($ServerName) -and ![string]::IsNullOrEmpty($ShareName)){
						$TestCommand = "Share:$ServerName" + ':' + $ShareName
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_ShareServerName=$ServerName _ShareName=$ShareName )"
					}
				}
				'_LogFile'{
					$LogFilePath = $FwConfigParameters['_LogFilePath']
					$SearchString = $FwConfigParameters[$Key] -Replace ("`"")
					If(![string]::IsNullOrEmpty($LogFilePath) -and ![string]::IsNullOrEmpty($SearchString)){
						$TestCommand = "LogFile:$LogFilePath" + ':' + $SearchString
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_LogFilePath=$LogFilePath  _SearchString=$SearchString)"
					}
				}
				'_DomainName'{
					$DomainName = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($DomainName)){
						$TestCommand = "LDAP:$DomainName"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_DomainName=$DomainName)"
					}
				}
				'_CommonTCPPort'{
					$ServerName = $FwConfigParameters['_CommonTCPPortServerName']
					$CommonTCPPort = $FwConfigParameters[$Key] -Replace ("`"")
					If(![string]::IsNullOrEmpty($CommonTCPPort) -and (($CommonTCPPort -eq 'SMB') -or ($CommonTCPPort -eq 'HTTP') -or ($CommonTCPPort -eq 'RDP') -or ($CommonTCPPort -eq 'WINRM'))){
						$TestCommand = ($CommonTCPPort + ":" + $ServerName)
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_CommonTCPPort=$CommonTCPPort)"
					}
				}
				'_RegDataKey'{
					# Expected format = RegData:$KeyRoot:$KeyPath:$ValueName:$ExpectedData => At least need 5 tokens
					$RegDataKey = $FwConfigParameters[$Key]
					$Token = $RegDataKey -split ('\\')
					Switch($Token[0]){
						'HKEY_LOCAL_MACHINE'{$RegKeyRoot = 'HKLM'}
						'HKEY_CURRENT_USER' {$RegKeyRoot = 'HKCU'}
						'HKEY_CLASSES_ROOT'{ $RegKeyRoot = 'HKCR'}
						'HKEY_USERS' {$KeyRoot = 'HKU'}
						'HKLM'{$RegKeyRoot = $Token[0]}
						'HKCU'{$RegKeyRoot = $Token[0]}
						'HKCR'{$RegKeyRoot = $Token[0]}
						'HKU' {$RegKeyRoot = $Token[0]}
						default{
							LogWarn "Skipping $Key as parameter is null or invalid(RootKey=$($Token[0]))"
							Break
						}
					}
					$RegDataKey = $RegDataKey -replace (($Token[0] + '\\'),'')
					$RegDataValue = $FwConfigParameters['_RegDataValue']
					$RegDataExpectedValue = $FwConfigParameters['_RegDataExpectedData']
					$RegDataIsChanged = $FwConfigParameters['_RegDataDetectIfChanged']
					If(![string]::IsNullOrEmpty($RegDataIsChanged) -and ($RegDataIsChanged.Substring(0,1) -eq 'y')){
						$IsOpposite = 'True'
					}Else{
						$IsOpposite = 'False'
					}
					$TestCommand = ("RegData:" + $RegKeyRoot + ":" + $RegDataKey + ":" + $RegDataValue + ":" + $RegDataExpectedValue + ":" + $IsOpposite)
					$TestCommandList.Add($TestCommand)
				}
				'_RegValueKey'{
					$RegValueKey = $FwConfigParameters[$Key]
					$Token = $RegValueKey -split ('\\')
					Switch($Token[0]){
						'HKEY_LOCAL_MACHINE'{$RegKeyRoot = 'HKLM'}
						'HKEY_CURRENT_USER' {$RegKeyRoot = 'HKCU'}
						'HKEY_CLASSES_ROOT' {$RegKeyRoot = 'HKCR'}
						'HKEY_USERS' {$KeyRoot = 'HKU'}
						'HKLM'{$RegKeyRoot = $Token[0]}
						'HKCU'{$RegKeyRoot = $Token[0]}
						'HKCR'{$RegKeyRoot = $Token[0]}
						'HKU' {$RegKeyRoot = $Token[0]}
						default{
							LogWarn "Skipping $Key as parameter is null or invalid(RootKey=$($Token[0]))"
							Break
						}
					}
					$RegValueKey = $RegValueKey -replace (($Token[0] + '\\'),'')
					$RegValueValue = $FwConfigParameters['_RegValueValue']
					$RegValueDetectIfValueCreated = $FwConfigParameters['_RegValueDetectIfValueCreated']
					If(![string]::IsNullOrEmpty($RegValueDetectIfValueCreated) -and ($RegValueDetectIfValueCreated.Substring(0,1) -eq 'y')){
						$IsOpposite = 'True'
					}Else{
						$IsOpposite = 'False'
					}
					$TestCommand = ("RegValue:" + $RegKeyRoot + ":" + $RegValueKey + ":" + $RegValueValue + ":" + $IsOpposite)
					$TestCommandList.Add($TestCommand)
				}
				'_RegKey'{
					$RegKey = $FwConfigParameters[$Key]
					$Token = $RegKey -split ('\\')
					Switch($Token[0]){
						'HKEY_LOCAL_MACHINE'{$RegKeyRoot = 'HKLM'}
						'HKEY_CURRENT_USER' {$RegKeyRoot = 'HKCU'}
						'HKEY_CLASSES_ROOT' {$RegKeyRoot = 'HKCR'}
						'HKEY_USERS' {$KeyRoot = 'HKU'}
						'HKLM'{$RegKeyRoot = $Token[0]}
						'HKCU'{$RegKeyRoot = $Token[0]}
						'HKCR'{$RegKeyRoot = $Token[0]}
						'HKU' {$RegKeyRoot = $Token[0]}
						default{
							LogWarn "Skipping $Key as parameter is null or invalid(RootKey=$($Token[0]))"
							Break
						}
					}
					$RegKey = $RegKey -replace (($Token[0] + '\\'),'')
					$RegKeyDetectIfValueCreated = $FwConfigParameters['_RegKeyDetectIfKeyCreated']
					If(![string]::IsNullOrEmpty($RegKeyDetectIfValueCreated) -and ($RegKeyDetectIfValueCreated.Substring(0,1) -eq 'y')){
						$IsOpposite = 'True'
					}Else{
						$IsOpposite = 'False'
					}
					$TestCommand = ("RegKey:" + $RegKeyRoot + ":" + $RegKey + ":" + $IsOpposite)
					$TestCommandList.Add($TestCommand)
				}
				'_File'{
					$File = $FwConfigParameters[$Key]
					$FileDetectIfFileCreated = $FwConfigParameters['_FileDetectIfFileCreated']
					If(![string]::IsNullOrEmpty($FileDetectIfFileCreated) -and ($FileDetectIfFileCreated.Substring(0,1) -eq 'y')){
						$IsOpposite = 'True'
					}Else{
						$IsOpposite = 'False'
					}
					$TestCommand = ("File:" + $File + ":" + $IsOpposite)
					$TestCommandList.Add($TestCommand)
				}
				'_EventlogName'{
					$EventLogName = $FwConfigParameters[$Key]
					$StopEventID = $FwConfigParameters['_Stop_EventID']
					$StopWaitTimeInSec = $FwConfigParameters['_Stop_WaitTimeInSec']
					$StopEventData = $FwConfigParameters['_Stop_EventData']
					If([string]::IsNullOrEmpty($CheckIntInSec)){
						$CheckIntInSec = 0
					}
					#If($global:BoundParameters.ContainsKey('CheckIntInSec'))
					#If(!$CheckIntInSec -gt 0){ #bound
					#	$CheckIntInSec = $FwConfigParameters['_CheckIntInSec']
					#}
					$EvtDataPartial = $FwConfigParameters['_EvtDataPartial']
					$EvtDataOperator = $FwConfigParameters['_EvtDataOperator']
					If([string]::IsNullOrEmpty($StopEventID)){
						LogWarn "`'_Stop_EventID' needs to be specified."
						LogError "Skipping eventlog test as _Stop_EventID is null"
						Break
					}
					If([string]::IsNullOrEmpty($StopWaitTimeInSec)){
						$StopWaitTimeInSec = 0
					}
					If([string]::IsNullOrEmpty($EvtDataPartial)){
						$EvtDataPartial = $True
					}Else{
						If($EvtDataPartial.Substring(0,1) -eq 'y'){
							$EvtDataPartial = $True
						}Else{
							$EvtDataPartial = $False
						}
					}
					If([string]::IsNullOrEmpty($StopEventData)){
						$EvtDataPartial = $False
						$StopEventData = '0'
					}
					If([string]::IsNullOrEmpty($EvtDataOperator)){
						$EvtDataOperator = 'OR'
					}ElseIf($EvtDataOperator -ne 'OR'){
							$EvtDataOperator = 'AND'
					}
					If(![string]::IsNullOrEmpty($EventLogName)){
						$TestCommand = "Evt:" + $StopEventID + ":" + $EventLogName + ":" + $CheckIntInSec + ":" + $StopWaitTimeInSec + ":" + $StopEventData + ":" + $EvtDataPartial + ":" + $EvtDataOperator
						$TestCommandList.Add($TestCommand)
					}Else{
						LogInfo "Skipping $Key as parameter is null or invalid"
					}
				}
				'_WaitTime'{
					$WaitTime = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($WaitTime)){
						$TestCommand = "Time:$WaitTime"
						$TestCommandList.Add($TestCommand)
					}
				}
				'_HighCPU'{
					$CpuThreshold = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($CpuThreshold)){
						$TestCommand = "HighCPU:$CpuThreshold"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_HighCPU=$CpuThreshold)"
					}
				}	
				'_HighMemory'{
					$MemoryThreshold = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($MemoryThreshold)){
						$TestCommand = "HighMemory:$MemoryThreshold"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_HighMemory=$MemoryThreshold)"
					}
				}
				'_WaitForSignal'{
					$SignalString = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($SignalString)){
						$TestCommand = "Signal:$SignalString"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_WaitForSignal=$SignalString)"
					}
				}
				Default{
					LogDebug ("Skipping $Key=" + $FwConfigParameters[$Key])
				}
			}
		}

		# Create a property for the test case and put it into $TestPropertyList
		ForEach($TestCommand in $TestCommandList){
			$TestProperty = CreateTestProperty $TestCommand
			If($Null -ne $TestProperty){
				LogDebug "Adding $($TestProperty.Function) to TestPropertyList."
				$TestPropertyList.Add($TestProperty)
			}Else{
				LogError "Error happend in CreateTestProperty with `'$TestCommand`'"
				Return
			}
		}
	}Else{ # Case for command line(-WaitEvent <xxx>)
		# Use condition passed from command line argument
		$TestProperty = CreateTestProperty $WaitEvent
		If($Null -ne $TestProperty){
			$TestPropertyList.Add($TestProperty)
		}Else{
			LogError "Error happend in CreateTestProperty with `'$WaitEvent`'"
			Return
		}
	}

	# If remote monitoring (but -WaitEvent is not Signal), add event monitor for event 999
	If(($global:IsRemoting) -or ($global:BoundParameters.ContainsKey('WaitEvent'))){ #we#575
		if (-not ($WaitEvent -iMatch "Signal")){
			$TestCommand = "StopEvt:$($script:RemoteStopEventID):System"
			$TestProperty999 = CreateTestProperty $TestCommand
			If($Null -eq $TestProperty999){
				LogError "Error happend in CreateTestProperty with `'$TestCommand`'"
				Return
			}
		}
	}

	LogInfo "Waiting for all below test cases to be signaled. (Poll/MonitorInterval: $FwMonitorIntervalInSec seconds)" "Green"
	ForEach($TestProperty in $TestPropertyList){
		LogInfo "  - $($TestProperty.TestName)"
	}
	If(($global:IsRemoting) -or ($global:BoundParameters.ContainsKey('WaitEvent'))){ #we#575
		if (-not ($WaitEvent -iMatch "Signal")){
			LogInfo "  - $($TestProperty999.TestName) - will stop as soon as being signaled"
		}
	}
	If(-not ($global:IsISE -or $global:IsRemoteHost)) {
		LogInfo "*** Attention: Do NOT LOG OFF until stop trigger is signaled (Lock-Screen is OK). ***" "Cyan"
		LogInfo "Want to stop manually?: Press CTRL-C, then Y[es] and later run .\$($global:ScriptName) -Stop" "Cyan"
		[console]::TreatControlCAsInput = $true			# for (#556)
	}

	###
	### Step 3: Perform all test cases and wait until all test cases to be signaled.
	###
	$StopCondFound = $False
	$signaledCount = 0
	While($StopCondFound -eq $False){
		For($i=0; $i -lt $TestPropertyList.Count; $i++){
			$TestProperty = $TestPropertyList[$i]
			$param = $TestProperty.Parameters
			### Test function is called here ###
			$Result = & $TestProperty.Function @param
			If(!$Result){
				# Remove test item since this has been signaled and no need to run again.
				$TestProperty.ErrorCount++
				If($TestProperty.ErrorCount -eq $global:ErrorLimit){
					LogInfo ("$($TestProperty.TestName) is signaled")
					$TestPropertyList.Remove($TestProperty) | Out-Null
					$signaledCount++
				}
				LogDebug "Error count of `'$($TestProperty.TestName)`' is $($TestProperty.ErrorCount)"
			}Else{
				LogDebug "Test result for `'$($TestProperty.TestName)`' is $Result"
			}
		}
		
		# Check System event 999 if remoting or -WaitEvent.
		If(($global:IsRemoting) -or ($global:BoundParameters.ContainsKey('WaitEvent'))){ #we#575
			if (-not ($WaitEvent -iMatch "Signal")){
				$param = $TestProperty999.Parameters
				$Result = & $TestProperty999.Function @param
				If(!$Result){
					LogInfo "Stop event $script:RemoteStopEventID was detected!! Will stop all running traces." "Red"
					Return
				}
			}
		}

		LogDebug "Remaining condition count=$($TestPropertyList.Count) / signaled condition count=$signaledCount"
		If($TestPropertyList.Count -eq 0){
			SendStopEvent999 -additionalMsg "in WaitForMultipleEvents"
			$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
			LogInfo "============== Repro condition HIT - STOP now $TimeUTC UTC ===========" "Green"
			LogInfo ("All -WaitEvent cases are siginaled! Will stop all active data collectors.")
			$StopCondFound = $True
		}Else{
			Write-Host '.' -NoNewline
			# allow CTRL-C to stop WaitEvent loop and terminate TSSclock as well (#556 )
			if ($Host.UI.RawUI.KeyAvailable -and (3 -eq [int]$Host.UI.RawUI.ReadKey("AllowCtrlC,IncludeKeyUp,NoEcho").Character))
			{
				Write-Host "You pressed CTRL-C. Do you want to terminate TSS [Y/N]?" -ForegroundColor Cyan
				$key = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
				if ($key.Character -eq "Y") { StopTSSClock -NoLogg; break; }
			}
			Start-Sleep -Second $FwMonitorIntervalInSec
		}
	}
	Write-Host ' '
	If($StopCondFound){
		# Wait StopWaitTimeInSec
		If($global:BoundParameters.ContainsKey('StopWaitTimeInSec')){ # Command line
			$StopWaitTimeInSec = $global:BoundParameters['StopWaitTimeInSec']
		}ElseIf($script:FwConfigParameters.ContainsKey('_Stop_WaitTimeInSec')){ # Config
			$StopWaitTimeInSec = $FwConfigParameters['_Stop_WaitTimeInSec']
		}Else{
			$StopWaitTimeInSec = 0 # Default
		}
		If($StopWaitTimeInSec -gt 0){
			LogInfo "Waiting addtional StopWaitTimeInSec=$StopWaitTimeInSec seconds."
			Start-Sleep -Seconds $StopWaitTimeInSec
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CreateTestProperty{
	[OutputType([System.Collections.Hashtable])]
	Param(
		[Parameter(Mandatory=$True)]
		[String]$TestParameter
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " with $TestParameter")
	$Token = $TestParameter -split (':')
	$TestType = $Token[0]
	Switch($TestType){
		'PortLoc'{ # Test_PortLoc -Port <PortNumber>
			If($Token.Length -ne 2){
				LogError ("Passed -WaitEvent parameter for PortLoc `'$TestParameter`' is invalid. See below usage.")
				LogError ("Example: -WaitEvent PortLoc:PortNumber => -WaitEvent PortLoc:3389")
				Return $Null
			}
			$TestParams = @{Port = $Token[1]}
			$TestName = "Local port(PortLoc)-unreachable Test ($TestParameter)"
			$TestFuncName = 'Test_PortLoc'
		}
		'PortDest'{ # Test_PortDest -ServerName [ServerName] -Port <PortNumber>
			If($Token.Length -ne 3){
				LogError ("Passed -WaitEvent parameter for PortDest `'$TestParameter`' is invalid. See below usage.")
				LogError ("Example: -WaitEvent PortDest:RemoteServer:PortNumber => -WaitEvent PortDest:RemoteServer:445")
				Return $Null
			}
			$TestParams = @{ServerName = $Token[1]; Port = $Token[2]}
			$TestName = "Remote port(PortDest)-unreachable Test ($TestParameter)"
			$TestFuncName = 'Test_PortDest'
		}
		'NoNetConn' { #Test_NoNetConn [<DestHost>]
			If($Token.Length -eq 1){
				$DestHost = 'DefaultGW'
			}ElseIf($Token.Length -eq 2){
				$DestHost = $Token[1]
			}ElseIf($Token.Length -gt 2){
				LogError ("Passed -WaitEvent parameter for NoNetConn Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$TestParams = @{DestHost = $DestHost}
			$TestName = "Network-unreachable Test ($TestParameter)"
			$TestFuncName = 'Test_NoNetConn'
		}
		'Svc'{ # Test_Svc -SvcName <ServiceName>
			If($Token.Length -ne 2){
				LogError ("Passed -WaitEvent parameter for Svc `'$TestParameter`' is invalid. See below usage.")
				LogError ("Example: -WaitEvent Svc:rpcss")
				Return $Null
			}
			$TestParams = @{SvcName = $Token[1]}
			$TestName = "Svc(Service)-stopped Test ($TestParameter)"
			$TestFuncName = 'Test_Svc'
		}
		'Share'{ # Test_Share -ServerName <ServerName> -ShareName <ShareName>
			If($Token.Length -ne 3){
				LogError ("Passed -WaitEvent parameter for Share `'$TestParameter`' is invalid. See below usage.")
				LogError ("Example: -WaitEvent share:TestServer:ShareName")
				Return $Null
			}
			$TestParams = @{ServerName = $Token[1]; ShareName = $Token[2]}
			$TestName = "Unreachable-File-Share Test ($TestParameter)"
			$TestFuncName = 'Test_Share'
		}
		'LogFile'{ # Test_LogFile -LogFilePath <LogFilePath> -SearchString <SearchString>
			# As separator is ':', LogFilePath is split into two tokens; need to combine them again.
			$LogFilePath = $Token[1] + ':' + $Token[2]
			$LogFilePath = $LogFilePath -replace ("`"",'') # remove double quote
			$LogFilePath = $LogFilePath -replace ("`'",'') # remove single
			If($Token.Length -le 3){
				Write-host "Token.Length: $($Token.Length) - LogFilePath $LogFilePath -  $($Token[0]) - [1+2] $($Token[1]) + $($Token[2]) = $LogFilePath - SearchSTring: $($Token[3])"
				LogError ("Passed -WaitEvent parameter for LogFile `'$TestParameter`' is invalid. See below usage.")
				LogInfo ("Example: -WaitEvent LogFile:'LogFilePath':'SearchString'")
				Return $Null
			}
			$TestParams = @{LogFilePath = $LogFilePath; SearchString = $Token[3]}
			$TestName = "Search-String in LogFile Test ($TestParameter)"
			$TestFuncName = 'Test_LogFile'
		}
		'Process'{ # Test_Process -ProcessName <ProcessName>
			If($Token.Length -ne 2){
				LogError ("Passed -WaitEvent parameter for Process stopped`'$TestParameter`' is invalid")
				LogError ("Example: -WaitEvent Process:Notepad  Note: Don`'t add `'.exe`' for the process name.")
				Return $Null
			}
			$TestParams = @{ProcessName = $Token[1]}
			$TestName = "Process-stopped Test ($TestParameter)"
			$TestFuncName = 'Test_Process'
		}
		'LDAP'{ # Test_LDAP -DomainName <DomainName>
			If($Token.Length -ne 2){
				LogError ("Passed -WaitEvent parameter for LDAP Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$TestParams = @{DomainName = $Token[1]}
			$TestName = "LDAP-Domain Test ($TestParameter)"
			$TestFuncName = 'Test_LDAP'
		}
		'SMB' { # Test_CommonTCPPort -Protocol SMB -ServerName <xxx,yyy>
			If($Token.Length -eq 1){
				$ServerNames = 'localhost'
			}ElseIf($Token.Length -eq 2){
				$ServerNames = $Token[1]
			}ElseIf($Token.Length -gt 2){
				LogError ("Passed -WaitEvent parameter for SMB Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$TestParams = @{Protocol = $Token[0]; ServerName=$ServerNames}
			$TestName = "SMB Test ($TestParameter)"
			$TestFuncName = 'Test_CommonTCPPort'
		}
		'HTTP' { # Test_CommonTCPPort -Protocol HTTP -ServerName <xxx>
			If($Token.Length -eq 1){
				$ServerNames = 'localhost'
			}ElseIf($Token.Length -eq 2){
				$ServerNames = $Token[1]
			}ElseIf($Token.Length -gt 2){
				LogError ("Passed -WaitEvent parameter for HTTP Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$TestParams = @{Protocol = $Token[0]; ServerName=$ServerNames}
			$TestName = "HTTP Test ($TestParameter)"
			$TestFuncName = 'Test_CommonTCPPort'
		}
		'RDP' { # Test_CommonTCPPort -Protocol RDP -ServerName <xxx>
			If($Token.Length -eq 1){
				$ServerNames = 'localhost'
			}ElseIf($Token.Length -eq 2){
				$ServerNames = $Token[1]
			}ElseIf($Token.Length -gt 2){
				LogError ("Passed -WaitEvent parameter for RDP Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$TestParams = @{Protocol = $Token[0]; ServerName=$ServerNames}
			$TestName = "RDP Test ($TestParameter)"
			$TestFuncName = 'Test_CommonTCPPort'
		}
		'WINRM' { # Test_CommonTCPPort -Protocol WINRM -ServerName <xxx>
			If($Token.Length -eq 1){
				$ServerNames = 'localhost'
			}ElseIf($Token.Length -eq 2){
				$ServerNames = $Token[1]
			}ElseIf($Token.Length -gt 2){
				LogError ("Passed -WaitEvent parameter for WINRM Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$TestParams = @{Protocol = $Token[0]; ServerName=$ServerNames}
			$TestName = "WINRM Test ($TestParameter)"
			$TestFuncName = 'Test_CommonTCPPort'
		}
		'RegData' { # [RegData] Test_RegData -RegPath <xxx>
			# Expected format = RegData:$KeyRoot:$KeyPath:$ValueName:$ExpectedData => At least need 5 tokens
			If($Token.Length -lt 5){
				LogError ("Passed -WaitEvent parameter for RegData test `'$TestParameter`' is invalid")
				LogError "Expected format is `'RegData:KeyRoot:KeyPath:ValueName:ExpectedData`' or `'RegData:KeyRoot:KeyPath:ValueName:ExpectedData:True`'"
				Return $Null
			}

			# Root key needs to be converted to PowerShell format
			Switch($Token[1]){
				'HKEY_LOCAL_MACHINE'{$KeyRoot = 'HKLM'}
				'HKEY_CURRENT_USER' {$KeyRoot = 'HKCU'}
				'HKEY_CLASSES_ROOT' {$KeyRoot = 'HKCR'}
				'HKEY_USERS' {$KeyRoot = 'HKU'}
				'HKLM'{$KeyRoot = $Token[1]}
				'HKCU'{$KeyRoot = $Token[1]}
				'HKCR'{$KeyRoot = $Token[1]}
				'HKU' {$KeyRoot = $Token[1]}
				default{
					$KeyRoot = $Token[1]
					LogError ("Invalid key root `'$KeyRoot`' was specified.")
					Return $Null
				}
			}
			# Remove backslash at first string from registy key path
			$KeyPath = $Token[2]
			$KeyPath = [regex]::replace($KeyPath, "^\\", '') # \aaa\bbb => aaa\bbb

			# 
			If(($Null -ne $Token[5]) -and $Token[5] -eq 'True'){
				$IsOpposite = $True
			}Else{
				$IsOpposite = $False
			}

			$TestParams = @{KeyRoot = $KeyRoot; KeyPath = $KeyPath ;ValueName=$Token[3]; ExpectedData =$Token[4]; IsOpposite = $IsOpposite}
			$TestName = "Registry-Data Test ($TestParameter)"
			$TestFuncName = 'Test_RegData'
		}
		'RegValue' { # [RegValue] Test_RegValue 
			# Expected format = RegValue:$KeyRoot:$KeyPath:$ValueName => At least need 4 tokens
			If($Token.Length -lt 4){
				LogError ("Passed -WaitEvent parameter for RegValue test `'$TestParameter`' is invalid")
				LogError "Expected format is RegValue:`'KeyRoot:KeyPath:ValueName`' or RegValue:`'KeyRoot:KeyPath:ValueName:True`'"
				LogInfo "Example: RegValue:`'HKLM:System\CurrentControlSet\Services\i8042prt\Parameters\OverrideKeyboardType`'"
				Return $Null
			}

			# Root key needs to be converted to PowerShell format
			Switch($Token[1]){
				'HKEY_LOCAL_MACHINE'{$KeyRoot = 'HKLM'}
				'HKEY_CURRENT_USER' {$KeyRoot = 'HKCU'}
				'HKEY_CLASSES_ROOT' {$KeyRoot = 'HKCR'}
				'HKEY_USERS' {$KeyRoot = 'HKU'}
				'HKLM'{$KeyRoot = $Token[1]}
				'HKCU'{$KeyRoot = $Token[1]}
				'HKCR'{$KeyRoot = $Token[1]}
				'HKU' {$KeyRoot = $Token[1]}
				default{
					$KeyRoot = $Token[1]
					LogError ("Invalid key root `'$KeyRoot`' was specified.")
					Return $Null
				}
			}
			# Remove backslash at first string from registy key path
			$KeyPath = $Token[2]
			$KeyPath = [regex]::replace($KeyPath, "^\\", '') # \aaa\bbb => aaa\bbb

			# 
			If(($Null -ne $Token[4]) -and $Token[4] -eq 'True'){
				$IsOpposite = $True
			}Else{
				$IsOpposite = $False
			}

			$TestParams = @{KeyRoot = $KeyRoot; KeyPath = $KeyPath ;ValueName=$Token[3]; IsOpposite = $IsOpposite}
			$TestName = "Registry-Value Test ($TestParameter)"
			$TestFuncName = 'Test_RegValue'
		}
		'RegKey' { # [RegKey] Test_RegKey -KeyRoot <xxx> -KeyPath <xxx>
			# Expected format is 'RegData:$KeyRoot:$KeyPath' => At least need 3 tokens
			If($Token.Length -lt 3){
				LogError ("Passed WaitEvent parameter for RegKey test `'$TestParameter`' is invalid")
				LogError "Expected format is `'RegKey:KeyRoot:KeyPath`' or `'RegData:KeyRoot:KeyPath:True`'"
				LogInfo "Example: 'RegKey:HKLM:System\CurrentControlSet\Services\i8042prt\Parameters`'"
				Return $Null
			}

			# Root key needs to be converted to PowerShell format
			Switch($Token[1]){
				'HKEY_LOCAL_MACHINE'{$KeyRoot = 'HKLM'}
				'HKEY_CURRENT_USER' {$KeyRoot = 'HKCU'}
				'HKEY_CLASSES_ROOT' {$KeyRoot = 'HKCR'}
				'HKEY_USERS' {$KeyRoot = 'HKU'}
				'HKLM'{$KeyRoot = $Token[1]}
				'HKCU'{$KeyRoot = $Token[1]}
				'HKCR'{$KeyRoot = $Token[1]}
				'HKU' {$KeyRoot = $Token[1]}
				default{
					$KeyRoot = $Token[1]
					LogError ("Invalid key root `'$KeyRoot`' was specified.")
					Return $Null
				}
			}
			# Remove backslash at first string from registy key path
			$KeyPath = $Token[2]
			$KeyPath = [regex]::replace($KeyPath, "^\\", '') # \aaa\bbb => aaa\bbb

			If(($Null -ne $Token[3]) -and $Token[3] -eq 'True'){
				$IsOpposite = $True
			}Else{
				$IsOpposite = $False
			}

			$TestParams = @{KeyRoot = $KeyRoot; KeyPath = $KeyPath; IsOpposite = $IsOpposite}
			$TestName = "Registry-Key Test ($TestParameter)"
			$TestFuncName = 'Test_RegKey'
		}
		'File' { # Test_File -FilePath <xxx>
			# Expected format is 'File:FilePath' => At least need 2 tokens
			If($Token.Length -lt 3){
				LogError ("Passed -WaitEvent parameter for File test `'$TestParameter`' is invalid")
				LogError "Expected format is `'File:FilePath`' or `'File:FilePath:True`'"
				LogInfo "Example: File:`"D:\data\test.txt`""
				Return $Null
			}
			# As separator is ':', file path is split into two tokens; need to combine them again.
			$FilePath = $Token[1] + ':' + $Token[2]
			$FilePath = $FilePath -replace ("`"",'') # remove double quote
			$FilePath = $FilePath -replace ("`'",'') # remove single

			If(($Null -ne $Token[3]) -and $Token[3] -eq 'True'){
				$SignalOnCreation = $True
			}Else{
				$SignalOnCreation = $False
			}

			$TestParams = @{FilePath = $FilePath; SignalOnCreation = $SignalOnCreation}
			$TestName = "File-exists Test ($TestParameter)"
			$TestFuncName = 'Test_File'
		}
		'BranchCache' {
			#ToDo:
		}
		'Evt' {
			If($Token.Length -lt 3){
				LogError ("Passed -WaitEvent parameter for Evt test `'$TestParameter`' is invalid")
				LogError ("Example: -WaitEvent Evt:100:System")
				Return $Null
			}
			If([string]::IsNullOrEmpty($Token[3])){
				$CheckIntInSec = 0
			}Else{
				$CheckIntInSec = $Token[3]
			}
			If([string]::IsNullOrEmpty($Token[4])){
				$WaitTimeInSec = 0
			}Else{
				$WaitTimeInSec = $Token[4]
			}
			If([string]::IsNullOrEmpty($Token[5])){
				$EventData = '0'
			}Else{
				$EventData = $Token[5] -replace ("`"","") # remove double quote
			}
			If([string]::IsNullOrEmpty($Token[6])){
				$EvtDataPartial = $True			#we#22.08.16# ToDo: only set if number of args > 6 (ex. Evt:4042:Microsoft-Windows-NCSI/Operational:0:0:6)?
			}Else{
				If($Token[6] -eq 'True'){
					$EvtDataPartial = $True
				}ElseIf($Token[6] -eq 'False'){
					$EvtDataPartial = $False
				}
			}
			If([string]::IsNullOrEmpty($Token[7])){
				$EvtDataOperator = "OR"
			}Else{
				$EvtDataOperator = $Token[7]
			}

			# make hardcoded '$MaxEvents = 1' configurable in Function Test_EventLog(#600)
			If($global:BoundParameters.ContainsKey('MaxEvents')){
				$EvtMaxEvents = $global:BoundParameters['MaxEvents']
			}Else{
				$EvtMaxEvents = 1  # default is 1
			}

			$TestParams = @{
				EventIDs = $Token[1]
				EventlogName = $Token[2]
				CheckIntInSec = $CheckIntInSec
				WaitTimeInSec = $WaitTimeInSec
				EventData = $EventData
				EvtDataPartial = $EvtDataPartial
				EvtDataOperator = $EvtDataOperator
				EvtMaxEvents = $EvtMaxEvents
			}
			$TestName = "Evt(Event) Test ($TestParameter)"
			$TestFuncName = 'Test_Eventlog'
		}
		'StopEvt'{
			$TestParams = @{
				EventIDs = $Token[1]
				EventlogName = $Token[2]
				CheckIntInSec = 0
				WaitTimeInSec = 0
				EventData = '0'
				EvtDataPartial = $False
				EvtDataOperator = "OR"
				EvtMaxEvents = 1
			}
			$TestName = "StopEvt Test for remoting ($TestParameter)"
			$TestFuncName = 'Test_Eventlog'
		}
		'Time'{
			$Second = $False
			If(![String]::IsNullOrEmpty($Token[2]) -and $Token[2] -like 'sec*'){
				$Second = $True
			}
			$TestParams = @{
				WaitTime = $Token[1]
				Second = $Second
			}
			$TestName = "Time(Wait timer) event ($TestParameter)"
			$TestFuncName = 'WaitTime'
		}
		'HNSL2Tunnel' {
			$TestName = "HNSL2Tunnel Test"
			$TestFuncName = 'Test_HNSL2Tunnel'
		}
		'StopCondition' {
			$TestName = "StopCondition Test"
			$TestFuncName = 'Test_StopCondition'
		}
		'HighCPU' {
			If($Token.Length -ne 2){
				LogError ("Passed -WaitEvent parameter for HighCPU `'$TestParameter`' is invalid. See below usage to test for CPU usage > 95%.")
				LogError ("Example: -WaitEvent HighCPU:CpuThreshold => -WaitEvent HighCPU:95")
				Return $Null
			}
			$TestParams = @{CpuThreshold = $Token[1]}
			$TestName = "HighCPU Test ($TestParameter)"
			$TestFuncName = 'Test_HighCPU'
		}
		'HighMemory' {
			If($Token.Length -ne 2){
				LogError ("Passed -WaitEvent parameter for HighMemory `'$TestParameter`' is invalid. See below usage to test for Memory usage > 95%.")
				LogError ("Example: -WaitEvent HighMemory:MemoryThreshold => -WaitEvent HighMemory:95")
				Return $Null
			}
			$TestParams = @{MemoryThreshold = $Token[1]}
			$TestName = "HighMemory Test ($TestParameter)"
			$TestFuncName = 'Test_HighMemory'
		}
		'Signal' {
			If($Token.Length -ne 2){
				LogError ("Passed -WaitEvent parameter for Signal `'$TestParameter`' is invalid. See below usage to wait for named Signal.")
				LogError ("Example: -WaitEvent Signal:SignalString => -WaitEvent Signal:Please_Stop")
				Return $Null
			}
			$TestParams = @{Signal = $Token[1]}
			$script:SignalString = $Token[1]
			$TestName = "Wait for Signal ($TestParameter)"
			$TestFuncName = 'WaitForSignal'
		}
		'ATQ' {
			$TestName = "ATQ Thread Exhaustion Test"
			$TestFuncName = 'Test_ATQ'
		}
		default {
			LogError ("Passed -WaitEvent parameter '$TestType' as a category is invalid. Any events will not be monitored and will stop active traces now.")
			Loginfo "Valid types are: [Evt|PortLoc|PortDest|NoNetConn|Svc|Process|Share|SMB|HTTP|RDP|WINRM|LDAP|RegData|RegValue|RegKey|File|Time|HNSL2Tunnel|LogFile|StopCondition|HighCPU|HighMemory|Signal|ATQ]" "cyan"
			Return $Null
		}
	}
	$TestProperty = @{
		TestName = $TestName
		Function = $TestFuncName
		Parameters = $TestParams
		ErrorCount = 0
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $TestProperty
}

Function SetupRemoting{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "IsRemoting is set to True"
	$global:IsRemoting = $True

	# RemoteHosts: if command line does not have '-RemoteHosts', get the remote hosts from config file and add them to $global:BoundParameters
	If(!($global:BoundParameters.ContainsKey('RemoteHosts'))){ # Case for remoting cofigured by config file
		$Data = $FwConfigParameters['_WriteEventToHosts']
		If($Null -ne $Data -and $Data.contains(',')){
			$Data = $Data -split ','  # Convert a comma separated string to string array.
		}
		$global:BoundParameters.Add('RemoteHosts',$Data)
	}

	# RemoteStopEventID: This is configurable only through config file.
	$Value = $FwConfigParameters['_Remote_Stop_EventID']
	If(!([string]::IsNullOrEmpty($Value))){
		LogDebug "RemoteStopEventID is set to $Value"
		$script:RemoteStopEventID = $Value
	}

	# RemoteLogFolder: if command line does not have '-RemoteLogFolder', get the remote hosts from config file and add it to $global:BoundParameters
	If(!($global:BoundParameters.ContainsKey('RemoteLogFolder'))){ # Case for remoting cofigured by config file
		$Value = $FwConfigParameters['_RemoteLogFolder']
		If(!([string]::IsNullOrEmpty($Value))){
			LogDebug "RemoteLogFolder is set to $Value"
			$global:BoundParameters.Add('RemoteLogFolder',$Value)
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion monitoring functions

#region FW functions for custom object
Function StartTTD{
	EnterFunc $MyInvocation.MyCommand.Name

	# Case with -TTDPath(Internal TTD)
	LogDebug ("Searching tttracer.exe")
	$TTTracerPath = SearchTTTracer
	If($Null -eq $TTTracerPath){
		Throw "Unable to find tttracer.exe."
	}

	LogInfo ("[TTD] Using $TTTracerPath")

	$TTD = $global:BoundParameters['TTD']
	$TTDMode = $global:BoundParameters['TTDMode']
	If($Null -eq $TTDMode){
		$TTDMode = 'Full' # By default TTDMode is 'Full'.
	}
	$TTDOptions = $global:BoundParameters['TTDOptions']
	$TTDMaxFile = $global:BoundParameters['TTDMaxFile']

	If($TTD.Count -ne 1 -and $TTDMode -eq 'onLaunch'){
		Throw "TTD with -onLaunch does not support starting multiple processes."
	}

	$IsInitialized = $False

	# Create temp LogTTD folder
	If(![string]::IsNullOrEmpty($LogFolderPath)){
		$Script:LogTTD = FwNew-TemporaryFolder -RelativeFolder $LogFolderPath
	}Else{
		$Script:LogTTD = FwNew-TemporaryFolder -RelativeFolder "$env:SystemDrive\MS_DATA\"
	}

	If(!(Test-Path $Script:LogTTD)){
		FwCreateLogFolder $Script:LogTTD
	}Else{
		LogDebug "$Script:LogTTD already exists."
		Get-ChildItem -Path $Script:LogTTD -Include * -File -Recurse | ForEach-Object { Remove-Item $_ -ErrorAction Ignore}
		Start-Sleep -s 5 #add some time for deletion to complete
	}
	
	ForEach($Target in $TTD){

		# Check if passed string for -TTD is PID, exe name or service name.
		$fFound = $False
		$fProcess = $False
		$fService = $False
		$fPID = $False
		$fAppX = $False

		If(([int]::TryParse($Target,[ref]$Null))){
			Try{
				 $Process = Get-Process -Id $Target -ErrorAction Stop
			}Catch{
				$ErrorMessage = "Invalid PID $Target was specified for -TTD. Check the PID."
				LogError $ErrorMessage
				Throw ($ErrorMessage)
			}
			$ProcID = $Process.Id
			$fFound = $True
			LogDebug ("Found target process with PID $ProcID")
		}
		# Process or service name case
		If(!$fFound){
			If($Target.Contains('.exe')){
				If($TTDMode -ne 'onLaunch'){
					Try{
						$ProcName = $Target.Replace('.exe','')
						$Processes = Get-Process -IncludeUserName -Name $ProcName -ErrorAction Stop
					}Catch{
						$ErrorMessage = "$Target is not running or invalid process name."
						LogError $ErrorMessage
						Throw ($ErrorMessage)
					}
					If($Processes.Count -gt 1){
						LogInfo "Found mutiple processes below."
						LogInfo "-----------------------------------------"
						ForEach($Process in $Processes){
							Write-Host ("- " + $Process.Name +"(PID:" + $Process.Id + " User:" + $Process.UserName + ")")
						}
						LogInfo "-----------------------------------------"
						Try{
							FwPlaySound
							$SpecifiedPID = Read-Host "Enter PID of process you want to attach"
							$Process = Get-Process -Id $SpecifiedPID -ErrorAction Stop
						}Catch{
							$ErrorMessage = "Invalid PID `'$SpecifiedPID`' was specified. Please enter correct PID."
							LogError $ErrorMessage
							Throw ($ErrorMessage)
						}
						$ProcID = $SpecifiedPID
					}Else{
						$Process = $Processes
						$ProcID = $Processes.Id
					}
					$fPID = $True
					LogDebug "Conversion of process name to PID was successful and target process was found with PID $ProcID"
				}Else{
					$fProcess = $True
				}
				$fFound = $True
			}Else{ # Service name or package name case
				Try{
					$Service = Get-CimInstance -Class win32_service -ErrorAction Stop | Where-Object {$_.Name -eq $Target}
				}Catch{
					$ErrorMessage = "Error happened during running Get-CimInstance -Class win32_service"
					LogError $ErrorMessage
					Throw ($ErrorMessage)
				}
				If ($Null -ne $Service){
					If($Null -eq $Service.ProcessID){
						$ProcID = $Null
					}Else{
						$ProcID = $Service.ProcessID
					}
					$fService = $True
					$fFound = $True
					LogDebug ("Target service " + $Service + " was found.")
				}
				# Search as a package name
				If($TTDMode -eq 'onLaunch' -and !$fFound){
					$AppXApps = Get-AppxPackage -Name $Target
					If ($AppXApps.count -eq 1){
						$fAppX = $True
						$fFound = $True
						LogDebug "Found AppX package for $($AppXApps.Name)"
					}ElseIf($AppXApps.count -gt 1){
						$ErrorMessage = "We see multiple packages that have name of $Target. Please specify accurate package name for -TTD."
						LogError $ErrorMessage
						Throw ($ErrorMessage)
					}
				}

				# At this point, we don't support onlaunch + Service/Appx with built-in TTD in Windows.
				If($TTDMode -eq 'onLaunch' -and !$Script:UsePartnerTTD){
					LogError "Built-in native TTTracer.exe with -onLaunch + Service or Appx is not supported yet."
					Throw ($ErrorMessage)
				}
			}
		}
		If(!$fFound){
			$ErrorMessage = "Unable to find target process/service/package($Target)"
			LogError $ErrorMessage
			Throw ($ErrorMessage)
		}

		# -onlaunch case
		If($TTDMode -eq 'onLaunch'){
			If($fService){
				$TTDArg = "/k $TTTracerPath -out `"$Script:LogTTD`" -onLaunch $Target"  # For a service
			}ElseIf($fProcess){
				$TTDArg = "/k $TTTracerPath -out `"$Script:LogTTD`" -onLaunch $Target -Parent *" # For a process
			}ElseIf($fAppX){
				$TTDArg = "/k $TTTracerPath -out `"$Script:LogTTD`" -onLaunch $Target -plm" # For an AppX
			}

			# Add MaxFile
			If($Null -ne $TTDMaxFile){
				$TTDArg = $TTDArg + " -MaxFile $TTDMaxFile"
			}

			# At the last, add other options.
			If($Null -ne $TTDOptions){
				$TTDArg = $TTDArg + " $TTDOptions"
			}

			$TTDcmd = "cmd.exe $TTDArg"
			LogInfo ("[TTD] Starting $TTDcmd")
			Try{
				Start-Process 'cmd.exe' -ArgumentList "/c $TTTracerPath -cleanup" -ErrorAction Stop
				Start-Sleep -Seconds 3
				Start-Process 'cmd.exe' -ArgumentList $TTDArg -ErrorAction Stop
			}Catch{
				$ErrorMessage = "An exception happened during starting `'TTTracer.exe -onLaunch`'. See error in command prompt open with another window."
				LogError $ErrorMessage
				Throw ($ErrorMessage)
			}
			Return
		}

		# -Attach case
		If($Null -eq $ProcID){
			$ErrorMessage = "Unable to find PID for $Target"
			LogError $ErrorMessage
			Throw ($ErrorMessage)
		}
		If($fService){
			LogInfo ("[TTD] Target service is `'" + $Service.Name + "`'(PID:$ProcID)")
		}Else{
			LogInfo ("[TTD] Target process is `'" + $Process.Name + ".exe`'(PID:$ProcID)")
		}

		# Create argument for TTD
		If(!$Script:UsePartnerTTD){
			$TTDArg =  "-out `"$Script:LogTTD`" -attach $ProcID"	# Built-in TTD
		}Else{
			$TTDArg =  "-out `"$Script:LogTTD`" -attach $ProcID"	# Partner Package --ToDo: need to verify, if -BG is needed as it fails on Win10 20H2 with 'Access is denied' (TonyGa) # removing -bg for now...
		}

		# Add MaxFile
		If($Null -ne $TTDMaxFile){
			$TTDArg = $TTDArg + " -MaxFile $TTDMaxFile"
		}

		# Add mode
		Switch($TTDMode){
			'Full' {$TTDArg = $TTDArg + " -Dumpfull"}
			'Ring' {$TTDArg = $TTDArg + " -Ring"}
		}

		# At the last, add other options.
		If($Null -ne $TTDOptions){
			$TTDArg = $TTDArg + " $TTDOptions"
		}

		$TTDcmd = "$TTTracerPath $TTDArg"
		# TTTracer.exe starts here. We use call operator(&) as TTD shows small window and we also would like to see every outputs as TTD is risky command.
		#& $TTTracerPath -out `"$LogFolder`" -attach $ProcID #& $TTTracerPath -bg -out `"$LogFolder`" -attach $ProcID
		Try{
			# TTTracer.exe starts here. We use call operator(&) as TTD shows small window and we also would like to see every outputs as TTD is risky command.
			#Start-Process 'cmd.exe' -ArgumentList $TTDArg -ErrorAction Stop
			If($Script:UsePartnerTTD){
				If(!$IsInitialized){
					Runcommands "TTD" "$TTTracerPath -initialize"
					Start-Sleep -Seconds 3
					$IsInitialized = $True
				}
			}
			LogInfo ("[TTD] Starting $TTDcmd")
			$TTDProc = Start-Process -FilePath $TTTracerPath -ArgumentList $TTDArg -RedirectStandardOutput "$global:Logfolder\TTD-output.txt" -RedirectStandardError "$global:Logfolder\TTD-err.txt" -PassThru -ErrorAction Stop
		}Catch{
			$ErrorMessage = "An exception happed during starting `'TTTracer.exe -onLaunch`'. See error in command prompt open with another window."
			LogError $ErrorMessage
			Throw ($ErrorMessage)
		}
	}
	
	#If($LASTEXITCODE -ne 0){
	#	$ErrorMessage = "An exception happed during starting `'$TTDcmd`'. See error in command prompt open with another window."
	#	LogError ($ErrorMessage)
	#	Throw ($ErrorMessage)
	#}
	Start-Sleep 1  # Wait for tttracer to be started.
	Try{
		# See if tttracer.exe is started or not.
		$TTDProc = Get-Process -Name "tttracer" -ErrorAction Stop
		LogInfo ("[TTD] TTTracer started successfully with PID:" + $TTDProc.Id)
		If($Script:UsePartnerTTD){
			LogInfo "[TTD] Note: Please start your repro steps AFTER TTD fully initialized and the tiny TTD window is seen on screen." "Cyan"
		}
	}Catch{
		LogInfo "If TTD .out file contains 'Error: Process with Id <ID> has shadow stack enabled' try setting HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\UserShadowStacksForceDisabled=1" "Cyan" # pending final sol. for ADO-PM #297
		$ErrorMessage = "Failed to start TTD. See above error message for detail."
		LogError $ErrorMessage
		Throw ($ErrorMessage)
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopTTD{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[TTD] Stopping TTD."
	$Script:TTDFullPath = $Null  # $Script:TTDFullPath is also used in TTDPostStop()
	$fDownLevel = $False

	# See if tttracer.exe is started or not.
	$TTDProcs = Get-Process -Name "tttracer" -ErrorAction Ignore
	If($Null -ne $TTDProcs){
		LogInfo "[TTD] Detected running TTTracer"
		If($TTDProcs.count -gt 1){
			# This is case for downlevel OS like WS2012R2
			# In this case, there are two tttracers, normal tttracer.exe and 'downlevel/tttracer.exe' are running.
			# If we see tttracer for downlevel, we have to use it to stop running tttracer.
			ForEach($TTDProc in $TTDProcs){
				If(($TTDProc.Path).contains("downlevel\tttracer.exe")){
					LogInfo ("[TTD] Detected downlevel TTTracer and will use the tttracer to stop trace.")
					$Script:TTDFullPath = $TTDProc.Path
					$fDownLevel = $True
					break
				}Else{
					$Script:TTDFullPath = $TTDProc.Path
				}
			}
		}ElseIf($TTDProcs.count -eq 1){
			$Script:TTDFullPath = $TTDProcs.Path
		}
	}Else{
		LogWarn "[TTD] TTTracer.exe is not running. Just clean up everything."
		$Script:TTDFullPath = SearchTTTracer
		If($Null -eq $Script:TTDFullPath){
			Throw "Unable to find tttracer.exe."
		}
	}

	If(!(Test-Path $Script:TTDFullPath)){
		Throw "Unable to find TTTracer.exe"
	}

	If($Script:TTDFullPath -eq "C:\Windows\System32\TTTracer.exe"){
		$Script:UsePartnerTTD = $False # Built-in TTD
	}Else{
		$Script:UsePartnerTTD = $True # Partner package
	}

	LogInfo "[TTD] Using $Script:TTDFullPath"
	Try{
		RunCommands "TTD" "$Script:TTDFullPath -stop all" -ThrowException:$True -ShowMessage:$True -ShowError:$True
	}Catch{
		Throw('ERROR: An error happened during stopping' + '(Error=0x' + [Convert]::ToString($LASTEXITCODE,16) + ')')
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectTTD{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	if ($noTTD -ne $True) 
	{ 
		$TTDProcObj = Get-Process -Name 'tttracer' -ErrorAction Ignore # we could use 'FwWaitForProcess $TTDProcObj <N>' later
		If($Null -ne $TTDProcObj){
			LogDebug "$($TTDProcObj.Path) is running" Yellow
			$fResult = $True
		}
	} 
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartWFPdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$WFPdiagLogfile = "$global:Logfolder\$LogPrefix" + "WFPdiag.cab"
	# We run native commands directly without using RunCommands() as it uses Invoke-Expression and the cmdlet does not work for wfpdiag.
	LogInfoFile "[WFPdiag] Running netsh wfp capture start file=$($WFPdiagProperty.LogFileName)" -ShowMsg
	netsh wfp capture start file=$($WFPdiagProperty.LogFileName)
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopWFPdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$WFPStopCommand = "netsh wfp capture stop"
	Try{
		RunCommands "WFPDiag" $WFPStopCommand -ThrowException:$True -ShowMessage:$True
	}Catch{
		$2ndWFPdiagStopCommand = "Logman.exe stop wfpdiag -ets"
		LogWarn "Error happened during running `'$WFPStopCommand`'. Try running `'$2ndWFPdiagStopCommand`' instead."
		RunCommands "WFPDiag" $2ndWFPdiagStopCommand -ThrowException:$True -ShowMessage:$True
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectWFPdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	$WFPdiagSessionName = "wfpdiag"

	$ETWSessionList = logman.exe -ets | Out-String
	GetETWSessionByPS [DetectWFPdiag]
	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$Token = $Line -Split '\s+'
		If($Token[0].Contains($WFPdiagSessionName)){
			LogDebug ('DetectWFPdiag detects running WFPdiag.')
			$fResult = $True
			Break
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartRASdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$RASdiagStartCommand = @(
		"Netsh Ras diagnostics set loglevel all",
		"Netsh Ras diagnostics set trace enable"
	)
	RunCommands "RASdiag" $RASdiagStartCommand -ThrowException:$True -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopRASdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$RASdiagStopCommand = @(
		"Netsh Ras diagnostics set trace disable",
		"xcopy /s/e/i/q/y $env:SystemRoot\tracing $global:LogFolder\tracing"
	)
	RunCommands "RASdiag" $RASdiagStopCommand -ThrowException:$True -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectRASdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	$RASdiagSessionName = "RRAS-EtwTracing"

	$ETWSessionList = logman.exe -ets | Out-String
	GetETWSessionByPS [DetectRASdiag]
	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$Token = $Line -Split '\s+'
		If($Token[0].Contains($RASdiagSessionName)){
			LogDebug ('DetectRASdiag detects running RASdiag.')
			$fResult = $True
			Break
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartPktMon{
	# Note 2023: There is a current PktMon single-session limitation - it may be needed first: to clear the filters “pktmon filter remove” and stop existing sessions “pktmon stop”.
	EnterFunc $MyInvocation.MyCommand.Name
	If(($global:BoundParameters.ContainsKey('noPktMon'))){
		LogInfoFile "skip Starting PktMon, because of -noPktMon switch"
		Return
	}
	If($OSBuild -lt 17763){
		LogInfoFile "PktMon is not implemented in downlevel OS"
		Return
	}
	# Sometimes pktmon is started with 'Flow packets only' type by OS. Hence we stop previous pktmon session just in case.
	RunCommands "PktMon" "PktMon.exe Stop --etw" -ThrowException:$False -ShowMessage:$False -ShowError:$False
	If($OSBuild -ge 19041){ # Above ver2004(20H1)
		$PktMonStartCommand = "PktMon Start --capture --pkt-size 128 -f $($PktMonProperty.LogFileName) -s 1024"
	}ElseIf($OSBuild -ge 18362){ # ver1903(19H1) and 1909(19H2)
		$PktMonStartCommand = "PktMon Start --etw --pkt-size 128 -f $($PktMonProperty.LogFileName) -s 1024"
	}ElseIf($OSBuild -ge 17763){ # ver1809(RS5)
		$PktMonStartCommand = "PktMon Start -c --type all"	#we# @2022-09-16
	}
	RunCommands "PktMon" $PktMonStartCommand -ThrowException:$True -ShowMessage:$True -ShowError:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopPktMon{
	EnterFunc $MyInvocation.MyCommand.Name

	#we# Issue#380 - PktMon is only supported on RS5+
	If($OSBuild -lt 17763){
		LogInfoFile "PktMon is not implemented in downlevel OS"
		Return
	}

	If(!($global:BoundParameters.ContainsKey('noPktMon'))){
		$PktOutFile= "$global:LogFolder\$($LogPrefix)PktMon.txt"	#fix issue #769
		$PktMonStopCommand = @(
			"PktMon.exe comp List 		| Out-File -Append $PktOutFile",
			"PktMon.exe comp List -a -i	| Out-File -Append $PktOutFile",
			"PktMon.exe comp counters 	| Out-File -Append $PktOutFile",
			"PktMon.exe Stop --etw		| Out-File -Append $PktOutFile",
			"PktMon.exe filter list		| Out-File -Append $PktOutFile"
		)
		If($OSBuild -ge 17763 -and $OSBuild -lt 18362){
			$PktMonStopCommand += "sc.exe stop pktmon"
		}
		RunCommands "PktMon" $PktMonStopCommand -ThrowException:$False -ShowMessage:$True
	}else{
		LogInfoFile "skip Stopping PktMon, because of -noPktMon switch"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectPktMon{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False

	# Use TSS reg to see if PktMon is enabled or not.(#404 ,#445)
	$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
	$PktMonInReg = $RegValue.PktMon
	If(![String]::IsNullOrEmpty($PktMonInReg)){
		$fResult = $True
	}

	<#
	#we# Issue#380 - PktMon is only supported on RS5+
	If($OSBuild -lt 17763){
		LogInfoFile "PktMon is not implemented in downlevel OS"
		Return $fResult
	}

	If($OSBuild -ge 18362){ # Above ver1903(19H1)
		# Issue#354 - Change the way to detect PktMon
		$Line = PktMon status | Select-String "Log file"
		If ($Line -ne $Null){
			$fResult = $True
		}
	}ElseIf($OSBuild -ge 17763){ # ver1809(RS5)
		# Issue#404
		#$Line = sc.exe query pktmon | Select-String "RUNNING"
		If (((Get-Service "PktMon" -ErrorAction SilentlyContinue).status) -eq [System.ServiceProcess.ServiceControllerStatus]::Running){
			$fResult = $True
		}
	}
	#>

	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartFiddler{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] starting Fiddler Logging, waiting to configure traffic decrypt" "Cyan"
	LogInfo "*** by default it will NOT decrypt the traffic, please enable `Decrypt HTTPS traffic` option." "Magenta" -noDate
	LogInfo " ** [INFO] to decrypt https, see https://fiddlerbook.com/fiddler/help/httpsdecryption.asp" "Cyan" -noDate
	LogInfo " ** [INFO]  Enable the traffic decryption option by clicking Tools > Options.. > HTTPS > and ticking the 'Decrypt HTTPS Traffic' box. Click OK, and accept the dialog to install certificates." "Cyan" -noDate

	# Run Fiddler.exe -ArgumentList
	LogInfoFile "[Fiddler] Running Fiddler.exe -noVersionCheck" -ShowMsg
	Start-Process "Fiddler.exe" -ArgumentList "-noVersionCheck"

	# Run ExecAction.exe start
	FwRead-Host-YN -Message "Please configure 'Decrypt HTTPS traffic' option, hit 'Y' to continue." -Choices 'y' | Out-Null  # no interest in answer
	RunCommands "Fiddler" "ExecAction.exe start" -ThrowException:$True -ShowMessage:$True -ShowError:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopFiddler{ #saves dump to $Env:USERPROFILE\Documents\Fiddler2\Captures\dump.saz
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = "Fiddler"
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. saving Fiddler dump" -ShowMsg
	$Commands = @(
		"ExecAction.exe dump"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$True -ShowMessage:$True -ShowError:$True
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. waiting 5 sec to save Fiddler dump" -ShowMsg
	Start-Sleep -Seconds 5
	$Commands = @(
		"xcopy /i/q/y $Env:USERPROFILE\Documents\Fiddler2\Captures\*.saz $DirRepro"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$True -ShowMessage:$True -ShowError:$True
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. stopping and closing Fiddler app" -ShowMsg
	$Commands = @(
		"ExecAction.exe stop"
		"ExecAction.exe quit"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$True -ShowMessage:$True -ShowError:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectFiddler{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	# Use TSS reg to see if Fiddler is enabled or not.
	$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
	$FiddlerInReg = $RegValue.Fiddler
	If(![String]::IsNullOrEmpty($FiddlerInReg)){
		$fResult = $True
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartSysMon{
	EnterFunc $MyInvocation.MyCommand.Name
	$UseConfigFile = $False
	$EvtxLogSize = 104857600  # 100MB by default
	$SysmonConfig = ".\Config\sysmonConfig.xml"
	
	If(Test-Path -Path $SysmonConfig){
		LogInfo "Found $SysmonConfig. SysMon will start using the config file."
		$UseConfigFile = $True
	}

	# Install SysMon service and start capturing events.
	Try{
		RunCommands "SysMon" "SysMon.exe -i -nobanner /AcceptEula" -ThrowException:$True -ShowMessage:$True
	}Catch{
		# Sometimes we get ERROR_SWAPERROR(0x3e7) but this is ignorable.
		If($LASTEXITCODE -ne 999){ 
			LogInfoFile "Got ERROR_SWAPERROR(0x3e7) during running `"SysMon.exe -i -nobanner /AcceptEula`" but this is ignorable and will continue."
		}Else{
			Throw $_  # This might be problematic error. Re-throw the exception.
		}
	}
	# If there is a config file, use it.
	If($UseConfigFile){
		RunCommands "SysMon" "SysMon.exe -c $SysmonConfig -nobanner" -ThrowException:$True -ShowMessage:$True
	}

	# If event log size(_EvtxLogSize) is specified in config, use it(default is 100MB).
	If(!([string]::IsNullOrEmpty($global:FwEvtxLogSize))){ 
		$EvtxLogSize = $global:FwEvtxLogSize
	}

	# Update log size
	LogInfo "Updating log size for Microsoft-Windows-Sysmon/Operational to $EvtxLogSize bytes"
	FwEventLogsSet "Microsoft-Windows-Sysmon/Operational" -Enabled:$True -Retention:$True -Quiet:$True -MaxSize:$EvtxLogSize
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopSysMon{
	EnterFunc $MyInvocation.MyCommand.Name

	If(!$global:BoundParameters.ContainsKey('Discard')){
		# Export event log first as SysMon.exe -u called later removes the eventlog.
		FwExportEventLog "Microsoft-Windows-Sysmon/Operational" $global:LogFolder -DaysBack 1
	}

	# Then uninstall Sysmon
	RunCommands "SySMon" "SysMon.exe -u -nobanner" -ThrowException:$True -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectSysMon{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False

	# To see if sysmon was enabled by TSS, we check if 'Sysmon' service is running and also the 'sysmon' is stored in TSS reg.
	$SysMonService = Get-Service -Name "sysmon" -ErrorAction Ignore
	If($Null -ne $SysMonService){
		$RegValues = Get-ItemProperty -Path  $global:TSSParamRegKey -ErrorAction Ignore
		If($Null -ne $RegValues.sysmon){
			$fResult = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartTSSClock{
	EnterFunc $MyInvocation.MyCommand.Name
	If($global:IsServerCore -or $global:IsRemoteHost -or $RemoteRun.IsPresent){
		LogDebug "This is sever core or remote session and will not start TSS Clock"
		Return
	}

	$TSSClockPath =  ".\Scripts\tss-clock.ps1"
	$TSSClockProcess = Get-CimInstance Win32_Process | Where-Object {$_.Commandline -like "*tss-clock*"}
	If($Null -eq $TSSClockProcess){
		If(Test-Path -Path $TSSClockPath){
			# See if we in the process of UEX_RDS, UEX_WVD, UEX_Win32k and PRF_DWM.
			$noTopMost = $False
			If($global:ParameterArray -like '*UEX_RDS' -or $global:ParameterArray -like '*UEX_WVD' -or $global:ParameterArray -like '*UEX_Win32k' -or $global:ParameterArray -like '*PRF_DWM'){
				$noTopMost = $True
			}

			# Show clock in background using Start-Process
			If($noTopMost){ # RDS case
				LogInfo "Starting TSS Clock without topmost."
				Start-Process "PowerShell.exe" ".\Scripts\tss-clock.ps1 -noTopMost" -noNewWindow
			}Else{ # Normal case
				LogInfoFile "Starting TSS Clock" -ShowMsg
				Start-Process "PowerShell.exe" ".\Scripts\tss-clock.ps1" -noNewWindow
			}
		}Else{
			LogDebug "$TSSClockPath does not exist."
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopTSSClock{
	Param(
	[Parameter(Mandatory=$False)]
	[Switch]$NoLogg
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$TSSClockProcesses = Get-CimInstance Win32_Process | Where-Object {$_.Commandline -like "*tss-clock*"}
	If($Null -ne $TSSClockProcesses){
		ForEach($TSSClockProcess in $TSSClockProcesses){
			if(!$NoLogg){LogInfoFile "Stopping TSS Clock (PID:$($TSSClockProcess.ProcessId))" "Gray" -ShowMsg}
			Stop-Process -Id $TSSClockProcess.ProcessId -ErrorAction Ignore
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StartLiveKD{
	EnterFunc $MyInvocation.MyCommand.Name
	$LiveKD = $global:BoundParameters['LiveKD']
	If($LiveKD -eq 'Start' -or $LiveKD -eq 'Both'){
		FwSetEventLog "Microsoft-Windows-Kernel-LiveDump/Analytic" -EvtxLogSize:102400000 -ClearLog  # 102400000
		if ($global:IsLiteMode -and ($OSBuild -ge 10240)){ #using OS-Built-in command: 
			Get-StorageDiagnosticInfo -StorageSubSystemFriendlyName (Get-StorageSubSystem).FriendlyName -IncludeLiveDump  -DestinationPath $global:LogFolder
		}else{
			$command = "$($LiveKDProperty.CommandName) -ml -o $global:LogFolder\$($LogPrefix)LiveDump-Start.dmp /AcceptEula"
			RunCommands "LiveKD" $command -ThrowException:$False -ShowMessage:$True -ShowError:$True
		}

		# In case of 'start', stop the Analytic log here.
		If($LiveKD -eq 'Start'){
			FwResetEventLog "Microsoft-Windows-Kernel-LiveDump/Analytic"
		}
	}

	# In case of StartNoWait, register the mode to TSS registry
	If(($LiveKD -ne 'Start') -and ($global:ParameterArray -contains 'StartNoWait' -or $global:ParameterArray -contains 'StartAutoLogger')){
		If(!(Test-Path $global:TSSParamRegKey)){
			RunCommands "LiveKD" "New-Item -Path `"$global:TSSParamRegKey`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$True  -ShowError:$True
		}
		# Save parameter to TSS registry
		SaveToTSSReg 'LiveKD' $LiveKD
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopLiveKD{
	EnterFunc $MyInvocation.MyCommand.Name

	If($Stop.IsPresent){
		# In case of -Stop, $LiveKD is set in ReadParameterFromTSSReg().
		If([String]::IsNullOrEmpty($LiveKD)){
			$LiveKD = "Both" # Set default value
		}
		# Remove 'LiveKD' registry in TSSRegKey.
		Remove-ItemProperty -Path $global:TSSParamRegKey -Name 'LiveKD' -ErrorAction SilentlyContinue  # Record to $Error
	}Else{ # Load from BoundParameters[]
		$LiveKD = $global:BoundParameters['LiveKD']
	}

	If($LiveKD -eq 'Start'){
		FwAddEvtLog "Microsoft-Windows-Kernel-LiveDump/Analytic"
		#we# LogDebug "Returning as $LiveKD is specified and nothing to do for stop."
		Return
	}
	If($LiveKD -eq 'Stop'){
		FwSetEventLog "Microsoft-Windows-Kernel-LiveDump/Analytic" -EvtxLogSize:102400000 -ClearLog  # 102400000
	}
	if ($global:IsLiteMode -and ($OSBuild -ge 10240)){ #using OS-Built-in command: 
		Get-StorageDiagnosticInfo -StorageSubSystemFriendlyName (Get-StorageSubSystem).FriendlyName -IncludeLiveDump  -DestinationPath $global:LogFolder
	}else{
		$command = "$($LiveKDProperty.CommandName) -ml -o $global:LogFolder\$($LogPrefix)LiveDump-Stop.dmp /AcceptEula"
		RunCommands "LiveKD" $command -ThrowException:$False -ShowMessage:$True -ShowError:$True
	}
	FwResetEventLog "Microsoft-Windows-Kernel-LiveDump/Analytic"
	# Add LiveDump log to $global:EvtLogNames using FwAddEvtLog so that it be picked up later in one of functions FwCollect_BasicLog, FwCollect_MiniBasicLog or Stop_Common_Tasks (which invoke_FwGetEvtLogList_ )
	FwAddEvtLog "Microsoft-Windows-Kernel-LiveDump/Analytic"
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectLiveKD{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False

	# Use TSS reg to see if LiveKD is enabled or not. For -Start, DetectLiveKD is called only to see if LiveKD is running.
	# But LiveKD is not a trace. So this function just returns with false in case of -Start.
	If($Status.IsPresent){
		$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
		$LiveKDInReg = $RegValue.LiveKD
		If(![String]::IsNullOrEmpty($LiveKDInReg) -and ($LiveKDInReg -eq 'Both' -or $LiveKDInReg -eq 'Stop')){
			$fResult = $True
		}
	}ElseIf($Stop.IsPresent){
		# In case of -Stop, $LiveKD is set in ReadParameterFromTSSReg().
		If(![String]::IsNullOrEmpty($LiveKD) -and ($LiveKD -eq 'Both' -or $LiveKD -eq 'Stop')){
			$fResult = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartGPresult{
	EnterFunc $MyInvocation.MyCommand.Name
	$GPresult = $global:BoundParameters['GPresult']
	If($GPresult -eq 'Start' -or $GPresult -eq 'Both'){
		FwGetGPresultAS
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopGPresult{
	EnterFunc $MyInvocation.MyCommand.Name
	$GPresult = $global:BoundParameters['GPresult']
	If($GPresult -eq 'Stop' -or $GPresult -eq 'Both'){
		FwGetGPresultAS
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectGPresult{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	If($Status.IsPresent){
		$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
		$GPresultInReg = $RegValue.GPresult
		If(![String]::IsNullOrEmpty($GPresultInReg) -and ($GPresultInReg -eq 'Both' -or $GPresultInReg -eq 'Stop')){
			$fResult = $True
		}
	}ElseIf($Stop.IsPresent){
		# In case of -Stop, $script:GPresult is set in ReadParameterFromTSSReg().
		If(![String]::IsNullOrEmpty($script:GPresult) -and ($script:GPresult -eq 'Both' -or $script:GPresult -eq 'Stop')){
			$fResult = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartPoolMon{
	EnterFunc $MyInvocation.MyCommand.Name
	$PoolMon = $global:BoundParameters['PoolMon']
	If($PoolMon -eq 'Start' -or $PoolMon -eq 'Both'){
		FwGetPoolmon
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopPoolMon{
	EnterFunc $MyInvocation.MyCommand.Name
	$PoolMon = $global:BoundParameters['PoolMon']
	If($PoolMon -eq 'Stop' -or $PoolMon -eq 'Both'){
		FwGetPoolmon
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectPoolMon{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	If($Status.IsPresent){
		$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
		$PoolMonInReg = $RegValue.PoolMon
		If(![String]::IsNullOrEmpty($PoolMonInReg) -and ($PoolMonInReg -eq 'Both' -or $PoolMonInReg -eq 'Stop')){
			$fResult = $True
		}
	}ElseIf($Stop.IsPresent){
		# In case of -Stop, $script:PoolMon is set in ReadParameterFromTSSReg().
		If(![String]::IsNullOrEmpty($script:PoolMon) -and ($script:PoolMon -eq 'Both' -or $script:PoolMon -eq 'Stop')){
			$fResult = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartHandle{
	EnterFunc $MyInvocation.MyCommand.Name
	$Handle = $global:BoundParameters['Handle']
	If($Handle -eq 'Start' -or $Handle -eq 'Both'){
		FwGetHandle
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopHandle{
	EnterFunc $MyInvocation.MyCommand.Name
	$Handle = $global:BoundParameters['Handle']
	If($Handle -eq 'Both' -or $Handle -eq 'Stop'){
		FwGetHandle
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectHandle{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	If($Status.IsPresent){
		$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
		$HandleInReg = $RegValue.Handle
		If(![String]::IsNullOrEmpty($HandleInReg) -and ($HandleInReg -eq 'Both' -or $HandleInReg -eq 'Stop')){
			$fResult = $True
		}
	}ElseIf($Stop.IsPresent){
		# In case of -Stop, $script:Handle is set in ReadParameterFromTSSReg().
		If(![String]::IsNullOrEmpty($script:Handle) -and ($script:Handle -eq 'Both' -or $script:Handle -eq 'Stop')){
			$fResult = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartPerfTCP{
	EnterFunc $MyInvocation.MyCommand.Name
	
    $ModifiedIpAddr, $fResult = ValidateIPAddress -IpAddr $PerfTCPAddr
    if (-not $fResult)
	{
		$ErrorMessage = $PerfTCPAddr + ' is an invalid IPv4 Address for PerfTCPAddr.  Please use W.X.Y.Z format'
		LogError $ErrorMessage 
		CleanUpAndExit
	}
	$PerfTCPAddr = $ModifiedIpAddr

	EndFunc $MyInvocation.MyCommand.Name
}

Function PerfTCPPostStart{
	EnterFunc $MyInvocation.MyCommand.Name
	# Set defaults if not provided on command line
	if (!($global:BoundParameters.ContainsKey('BufferLength'))){
		$BufferLength = 128 
		LogInfoFile "-Duration not specified so using default $BufferLength kilobytes"
	}
	if (!($global:BoundParameters.ContainsKey('Duration'))){
		$Duration = 60
		LogInfoFile "-Duration not specified so using default $Duration seconds"
	}
	$TwiceDuration = 2*$Duration
	# Build commands
	if ($PerfTCP -eq "Server"){
		$NtttcpSTThdCmd = $script:PerfTCPPath + " -r -m 1,*," + $PerfTCPAddr + " -p 5005 -l " + $BufferLength + "K -a 16 -t " + $Duration
		$NtttcpMultiThdCmd = $script:PerfTCPPath + " -r -m 8,*," + $PerfTCPAddr + " -p 5005 -l " + $BufferLength + "K -a 16 -t " + $Duration
		$LatTeCmd = $script:LatTePath + " -a " + $PerfTCPAddr + ":5005 -i 10010"		
	}else{ # client
		$NtttcpSTThdCmd = $script:PerfTCPPath + " -s -m 1,*," + $PerfTCPAddr + " -p 5005 -l " + $BufferLength + "K -a 4 -t " + $Duration
		$NtttcpMultiThdCmd = $script:PerfTCPPath + " -s -m 8,*," + $PerfTCPAddr + " -p 5005 -l " + $BufferLength + "K -a 4 -t " + $Duration
		$LatTeCmd = $script:LatTePath + " -c -a " + $PerfTCPAddr + ":5005 -i 10010"		
	}
	# Run commands
	if ($PerfTCP -eq "Server"){
		LogInfo "Now running multithreaded command for server: `n$ntttcpMultiThdCmd`n"
		LogInfo "`nAt this time run the appropriate TSS command on the source machine (i.e. with -PerfTCP Client)" "White"
		$outfile = $PrefixTime + "PerfTCP_ntttcp_srv_multi_results.txt"
		Invoke-Expression $NtttcpMultiThdCmd > $outfile
		LogInfo "`n`nNow running single threaded command for server: `n$ntttcpSTThdCmd`n`n"
		$outfile = $PrefixTime + "PerfTCP_ntttcp_srv_single_results.txt"
		Invoke-Expression $NtttcpSTThdCmd > $outfile
		LogInfo "`n`nNow running latency test for server: `n$LatTeCmd"
		$outfile = $PrefixTime + "PerfTCP_latency_srv_results.txt"
		Invoke-Expression $LatTeCmd > $outfile
	}else{ # client
		LogInfo "Now running multithreaded command for client: `n$ntttcpMultiThdCmd`n`n`n"
		LogInfo "Please wait $TwiceDuration seconds to complete`n`n"
		$outfile = $PrefixTime + "PerfTCP_ntttcp_cli_multi_results.txt"
		Invoke-Expression $NtttcpMultiThdCmd > $outfile
		LogInfo "`n`nNow running single threaded command for client: `n$ntttcpSTThdCmd`n`n"
		LogInfo "Please wait $TwiceDuration seconds to complete`n`n"
		$outfile = $PrefixTime + "PerfTCP_ntttcp_cli_single_results.txt"
		Invoke-Expression $NtttcpSTThdCmd > $outfile
		LogInfo "`n`nNow running latency test for client: `n$LatTeCmd"
		$outfile = $PrefixTime + "PerfTCP_latency_cli_results.txt"
		Invoke-Expression $LatTeCmd > $outfile
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopPerfTCP{
	EnterFunc $MyInvocation.MyCommand.Name
	EndFunc $MyInvocation.MyCommand.Name
}

Function PerfSMBPrerequisites {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "Checking prerequistites for PerfSMB"
	if (!($global:BoundParameters.ContainsKey('NumFiles'))){
		$NumFiles = $script:PerfSMBDfltNumFiles
		LogInfo "No -NumFiles parameter specified, so using default of $NumFiles"
	}
	if (!($global:BoundParameters.ContainsKey('PerfSMBFileSize'))){
		$PerfSMBFileSize = $script:PerfSMBDfltFileSize
	}
	# Check PermSMBFileSize to conform with proper syntax, and store size and unit
	[long]$size = $PerfSMBFileSize -replace "^(\d+).*", '$1'
	$unit = ($PerfSMBFileSize -replace "^\d+([KkMmGgBb])", '$1').ToUpper()
	if (!($global:BoundParameters.ContainsKey('PerfSMBFileSize'))){
		LogInfo "No -PerfSMBFileSize parameter specified, so using default of $size$unit"
	}
	$script:PerfSMBSize = $size
	if     ($unit -ieq 'K') {$size = $size * 1024}
	elseif ($unit -ieq 'M') {$size = $size * 1024 * 1024}
	elseif ($unit -ieq 'G') {$size = $size * 1024 * 1024 * 1024}
	elseif ($unit -ieq 'B') {}
	else{
		LogError "-PerfSMBFileSize parameter is invalid: $PerfSMBFileSize"
		LogError "Syntax must be <size>[K|M|G|B]"
		LogError "Example for 1GB file would be 1G"
		CleanupAndExit
	}
	$script:PerfSMBBytes = $size
	$script:PerfSMBUnit = $unit
    $ServerName, $fResult = (ValidateUNCPath $PerfSMB)
	if ($fResult){
		LogInfoFile "$PerfSMB is a valid UNC path"
	}else{
		$ErrorMessage = "$PerfSMB is not a valid UNC path`nPlease ensure it conforms to \\<servername_or_ip>\<sharename>\<directory>`nNote that it MUST contain at least one directory below the share root"
		LogError $ErrorMessage
		return $False
	}
	LogInfo "`n[PerfSMB] Checking if the target server $ServerName is reachable at TCP port 445..."
	$ServerReachable = Test-NetConnection -ComputerName $ServerName -CommonTCPPort SMB
	if ($ServerReachable.TcpTestSucceeded -eq $true){
		LogInfo "[Success] FileServer $ServerName is reachable" "Green"
	}else{
		$ErrorMessage = "FileServer $ServerName is unreachable`nEnsure firewall rules allow SMB access via port 445"
		LogError $ErrorMessage
		return $False
	} 
	LogInfo "[PerfSMB] Checking that the remote share $PerfSMB can be accessed..."
 	if (Test-Path -Path $PerfSMB){
		LogInfo "[Success] Remote share $PerfSMB is accessible" "Green"
	}else{
		LogError "Failed to get access to $PerfSMB"
		LogError "Either the share does not exist on the remote machine, or you do not have access to it"
		LogError "If it exists, first try accessing via Start->Run $SharePath and enter credentials"
		LogError "Then re-run this tss command"
		return $False
	}
	return $True
	EndFunc $MyInvocation.MyCommand.Name
}

Function StartPerfSMB{
	EnterFunc $MyInvocation.MyCommand.Name
	$bytes = $script:PerfSMBBytes  # This was already adjusted to bytes in PerfSMBPrerequisites
	if (!($global:BoundParameters.ContainsKey('NumFiles'))){
		$NumFiles = $script:PerfSMBDfltNumFiles
	}
	# Setup
	LogInfoFile "[PerfSMB] Creating the local $script:PerfSMBClientTmpDir temp folder"
	$CommandLine = "md " + $script:PerfSMBClientTmpDir
	Invoke-Expression $CommandLine | Out-Null
	LogInfoFile "[PerfSMB] Deleting any existing files under the local temp folder"
	Remove-Item -Path "$script:PerfSMBClientTmpDir\*" -Force -ErrorAction SilentlyContinue
	$Message = "[PerfSMB] Creating $NumFiles $script:PerfSMBSize$PerfSMBUnit" + " files in $script:PerfSMBClientTmpDir" + "..."
	LogInfo $Message
		
	# For large files WriteAllBytes has size limitations, and it's also slooooow.   
	# We will use diskspd for this case
	if ($bytes -gt 250000000){  # Big file is anything > 250MB
		LogInfoFile "Large file generation.  Using Dskspd"
		$PerfSMBFileSize = "-c" + $PerfSMBFileSize  # Fix for DiskSpd command
		LogInfo "[PerfSMB] Now writing $NumFiles files with size $script:PerfSMBSize$PerfSMBUnit and 8 threads to $PerfSMB\IO.dat. It might take a while depending on the connection speed..."
		$CommandLine = "diskspd.exe -b1M -d60 -o64 -t4 -r $PerfSMBFileSize $NumFiles $PerfSMB\IO.dat > $global:LogFolder\$($LogPrefix)_PerfSMB_writeremote.txt"
		Invoke-Expression $CommandLine | Out-Null
		LogInfo "[PerfSMB] Cleanup files in the remote directory..."
		Remove-Item -Path $PerfSMB"\*" -Force -ErrorAction SilentlyContinue
		LogInfo "[PerfSMB] Now reading a 1G file with 4 threads from $PerfSMB. It might take a while depending on the connection speed..."
		$CommandLine = "diskspd.exe -b1M -d60 -o64 -t4 -r $PerfSMBFileSize $PerfSMB\IO.dat > $global:LogFolder\$($LogPrefix)_PerfSMB_readremote.txt"
		Invoke-Expression $CommandLine | Out-Null
		LogInfo "[PerfSMB] Now writing a 1G file using 4 threads to local directory $script:PerfSMBClientTmpDir. It might take a while depending on the local disk performance..."
		$CommandLine = "diskspd.exe -b1M -d60 -o64 -t4 -r $PerfSMBFileSize $NumFiles $script:PerfSMBClientTmpDir\IO.dat > $global:LogFolder\$($LogPrefix)_PerfSMB_writelocal.txt"
		Invoke-Expression $CommandLine | Out-Null
		LogInfo "[PerfSMB] Cleanup files in the local directory..."
		Remove-Item -Path $script:PerfSMBClientTmpDir"\*" -Force -ErrorAction SilentlyContinue
		LogInfo "[PerfSMB] Now reading a 1G file with 4 threads from local directory $PerfSMBClientTmpDir. It might take a while depending on the local disk performance..."
		$CommandLine = "diskspd.exe -b1M -d60 -o64 -t4 -r $PerfSMBFileSize $PerfSMBClientTmpDir\IO.dat > $global:LogFolder\$($LogPrefix)_PerfSMB_readlocal.txt"
		Invoke-Expression $CommandLine | Out-Null
	}else{
		LogInfoFile "Normal file generation.  Using Robocopy"
		# Create the files
		for ($i = 1; $i -le $NumFiles; $i++){
			$FilePath = Join-Path -Path $script:PerfSMBClientTmpDir -ChildPath "TSSFile$i.txt"
			[System.IO.File]::WriteAllBytes($FilePath, @(0) * $bytes)
		}
		LogInfo "[PerfSMB] Now writing $NumFiles files with size $script:PerfSMBSize$PerfSMBUnit and 8 threads to $PerfSMB. It might take a while depending on the connection speed..."
		$CommandLine = "robocopy.exe $script:PerfSMBClientTmpDir $PerfSMB /NFL /IS /IM /R:3 /W:5 /MT /LOG:$global:LogFolder\$($LogPrefix)_PerfSMB_Robocopy.txt"
		Invoke-Expression $CommandLine | Out-Null
		LogInfo "[PerfSMB] Now doing an unbuffered Robocopy of $NumFiles files with size $script:PerfSMBSize$PerfSMBUnit and 8 threads to $PerfSMB..."
		$CommandLine = "robocopy.exe $script:PerfSMBClientTmpDir $PerfSMB /J /NFL /IS /IM /R:3 /W:5 /MT /LOG+:$global:LogFolder\$($LogPrefix)_PerfSMB_Robocopy.txt"
		Invoke-Expression $CommandLine | Out-Null
		LogInfo "[PerfSMB] Now reading $NumFiles files with size $script:PerfSMBSize$PerfSMBUnit and 8 threads from $PerfSMB to local directory..."
		$CommandLine = "robocopy.exe $PerfSMB $script:PerfSMBClientTmpDir /NFL /IS /IM /R:3 /W:5 /MT /LOG+:$global:LogFolder\$($LogPrefix)_PerfSMB_Robocopy.txt"
		Invoke-Expression $CommandLine | Out-Null
		LogInfo "[PerfSMB] Now doing an unbuffered Robocopy of $NumFiles files with size $script:PerfSMBSize$PerfSMBUnit and 8 threads from $PerfSMB to local directory..."
		$CommandLine = "robocopy.exe $PerfSMB $script:PerfSMBClientTmpDir /J /NFL /IS /IM /R:3 /W:5 /MT /LOG+:$global:LogFolder\$($LogPrefix)_PerfSMB_Robocopy.txt"
		Invoke-Expression $CommandLine | Out-Null
		LogInfo "[PerfSMB] Now writing $NumFiles files with size $script:PerfSMBSize$PerfSMBUnit and 1 thread to $PerfSMB..."
		$CommandLine = "robocopy.exe $script:PerfSMBClientTmpDir $PerfSMB /NFL /IS /IM /R:3 /W:5 /MT:1 /LOG+:$global:LogFolder\$($LogPrefix)_PerfSMB_Robocopy.txt"
		Invoke-Expression $CommandLine | Out-Null
		LogInfo "[PerfSMB] Now reading $NumFiles files with size $script:PerfSMBSize$PerfSMBUnit and 1 thread from $PerfSMB to local directory..."
		$CommandLine = "robocopy.exe $PerfSMB $script:PerfSMBClientTmpDir /NFL /IS /IM /R:3 /W:5 /MT:1 /LOG+:$global:LogFolder\$($LogPrefix)_PerfSMB_Robocopy.txt"
		Invoke-Expression $CommandLine | Out-Null
	}
	LogInfo "[PerfSMB] File copy tests have completed"
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopPerfSMB{
	EnterFunc $MyInvocation.MyCommand.Name
	$FullSharePath = $script:PerfSMBDL + ":\" + $script:PerfSMBSharePath
	if (!($script:PerfSMBKeepShare)){
		LogInfoFile "Deleting the test files from the $PerfSMB folder"
		$CommandLine = "rm " + $PerfSMB + "\*TSSFile*"
		Invoke-Expression $CommandLine
	}
	Write-Host "[PerfSMB] Cleanup files in the remote directory..."
	Get-ChildItem -Path $PerfSMB -Filter "TSSFile*" | Remove-Item -Force
	LogInfo "[PerfSMB] Cleanup files in the local directory..."
	Remove-Item -Path $script:PerfSMBClientTmpDir -Recurse -Force
	EndFunc $MyInvocation.MyCommand.Name
}

Function StartProcDump{
	EnterFunc $MyInvocation.MyCommand.Name
	$ProcDumpInterval = $global:BoundParameters['ProcDumpInterval'] # specified in command-line
	If(($Null -eq $ProcDumpInterval) -or ([string]::IsNullOrEmpty($ProcDumpInterval))) {
		$ProcDumpInterval = $script:ProcDumpInterval				# specified in config.cfg or default specified in ReadConfigFile
	}
	$ProcDumpOption = $global:BoundParameters['ProcDumpOption']		# specified in command-line
	If(($Null -eq $ProcDumpOption) -or ([string]::IsNullOrEmpty($ProcDumpOption))) {
		$ProcDumpOption = $script:ProcDumpOption					# specified in config.cfg or default specified in ReadConfigFile
	}
	if (!($ProcDumpAppCrash.IsPresent)){ LogInfo "[StartProcDump] ProcDumpOption $ProcDumpOption - ProcDumpInterval $ProcDumpInterval " "Gray"}
	# Capture user dump
	If($ProcDumpOption -eq 'Start' -or $ProcDumpOption -eq 'Both'){
		RunProcDump
	}
	# In case of StartNoWait, register the mode to TSSv2\Parameters registry
	If(!(Test-Path $global:TSSParamRegKey)){
		RunCommands "ProcDump" "New-Item -Path `"$global:TSSParamRegKey`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
	}
	# Saving parameters to TSS registry for -NoWaitstart and also so that -Status can detect procdump.
	SaveToTSSReg 'ProcDump' ($ProcDump -join ',') # $ProcDump is string array. Hence convert it to comma separated single string.
	SaveToTSSReg 'ProcDumpOption' $ProcDumpOption
	SaveToTSSReg 'ProcDumpInterval' $ProcDumpInterval	#we#604
	LogDebug "[StartProcDump] ProcDumpOption $ProcDumpOption / global: $global:ProcDumpOption - ProcDumpInterval $ProcDumpInterval / global: $global:ProcDumpInterval - Bound: $($global:BoundParameters['ProcDumpInterval'])"
	EndFunc $MyInvocation.MyCommand.Name
}

Function RunProcDump{
	EnterFunc $MyInvocation.MyCommand.Name
	$ProcDump = $global:BoundParameters['ProcDump']
	ForEach($Target in $ProcDump){
		$IsService = $Null
		If(!$Target.Contains('.exe')){
			$IsService = $True
		}
		Try{
			If([int]::TryParse($Target,[ref]$Null)){
				[int]$ProcID = $Target
				FwCaptureUserDump -ProcPID $ProcID -DumpFolder $global:LogFolder	# PID
			}ElseIf($IsService){
				FwCaptureUserDump "$Target" $global:LogFolder -IsService:$True 		# Service
			}Else{
				FwCaptureUserDump "$Target" $global:LogFolder -IsService:$False		# Process
			}
		}Catch{
			LogException "Error happened in FwCaptureUserDump" $_
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopProcDump{
	EnterFunc $MyInvocation.MyCommand.Name
	# In case of -Stop, $ProcDump, $ProcDumpOption and $ProcDumpInterval are set in ReadParameterFromTSSReg().
	LogDebug "[StopProcDump] ProcDumpOption: $ProcDumpOption - ProcDumpInterval: $ProcDumpInterval - global: $global:ProcDumpInterval"

	If($ProcDumpOption -eq 'Start'){
		# Do nothing
		LogDebug "Returning as `'$ProcDumpOption`' is specified and nothing to do for stop."
		Return
	}

	if (!($ProcDumpAppCrash.IsPresent)){
		# Capture user dump
		RunProcDump
	}else{LogDebug "Returning as -ProcDumpAppCrash is specified and nothing to do for stop."}
	EndFunc $MyInvocation.MyCommand.Name
}

<# Function DetectProcDump{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False

	If(!(Test-Path "$global:TSSParamRegKey")){
		LogDebug "[DetectProcDump] There are no parameter settings in TSS registry."
		$fResult = $False
	}else{
		$ParamArray = Get-Item "$global:TSSParamRegKey" | Select-Object -ExpandProperty Property -ErrorAction Ignore
		$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
		ForEach($Param in $ParamArray){
			$Data = $RegValue.$Param
			If($Param -eq 'Procdump'){
				LogDebug "Procdump is enabled with `'$Data`'"
				$fResult = $True
			}
		}
	}
	EndFunc "$($MyInvocation.MyCommand.Name) Return=$fResult"
	Return $fResult
}
#>
Function DetectToolName{
	# Detection routine from TSS registry entry
	[OutputType([Bool])]
	Param([String]$ToolName)
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	If(!(Test-Path "$global:TSSParamRegKey")){
		LogDebug "[DetectToolName] There are no parameter settings in TSS registry."
		$fResult = $False
	}else{
		$ParamArray = Get-Item "$global:TSSParamRegKey" | Select-Object -ExpandProperty Property -ErrorAction Ignore
		$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
		ForEach($Param in $ParamArray){
			$Data = $RegValue.$Param
			If($Param -eq "$ToolName"){
				LogDebug "$ToolName is enabled with `'$Data`'"
				$fResult = $True
			}
		}
	}
	EndFunc "$($MyInvocation.MyCommand.Name) Return=$fResult"
	Return $fResult
}
Function DetectProcDump{
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = (DetectToolName "ProcDump")
	EndFunc "$($MyInvocation.MyCommand.Name) Return=$fResult"
}
Function DetectRadar{
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = (DetectToolName "Radar")
	EndFunc "$($MyInvocation.MyCommand.Name) Return=$fResult"
}
Function StartRadar{
	EnterFunc $MyInvocation.MyCommand.Name
	$Radar = $global:BoundParameters['Radar']
	#FindPID for Service or Process, or see StartTTD
	$script:RadarPID = (FwFindPIDforSvcOrProc $Radar)
	$Commands = @("$Sys32\rdrleakdiag.exe -p $script:RadarPID -enable")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	# In case of StartNoWait, register the mode to TSSv2\Parameters registry
	If(!(Test-Path $global:TSSParamRegKey)){
		RunCommands "Radar" "New-Item -Path `"$global:TSSParamRegKey`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
	}
	# Saving parameters to TSS registry for -NoWaitstart and also so that -Status can detect Radar.
	SaveToTSSReg 'Radar' ($Radar -join ',') # $Radar is string array. Hence convert it to comma separated single string.
	SaveToTSSReg 'RadarPID' ($script:RadarPID)
	EndFunc $MyInvocation.MyCommand.Name
}
Function StopRadar{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "stopping RADAR: snap with PID=$script:RadarPID"
	$Commands = @("$Sys32\rdrleakdiag.exe -p $script:RadarPID -snap -nowatson -nocleanup")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

Function StartWireshark{
	EnterFunc $MyInvocation.MyCommand.Name

	# If parameters are set by tss_config file, respect them. Otherwise, set default value.
	If([String]::IsNullOrEmpty($global:WS_TraceBufferSizeInMB)){
		[int32]$WS_TraceBufferSizeInKB = (512 *1024)
	}else{
		[int32]$WS_TraceBufferSizeInKB =( [convert]::ToInt32($global:WS_TraceBufferSizeInMB) * 1024) #_# config value multiplied by 1024 (for MB instead of KB) #_# #294
	}
	If([String]::IsNullOrEmpty($global:WS_PurgeNrFilesToKeep)){
		$global:WS_PurgeNrFilesToKeep = 10
	}

	# Get interface number
	$IFNoArray = [System.Collections.ArrayList]@()
	If([String]::IsNullOrEmpty($global:WS_IF)){
		# Get IF dynamically
		$IFlist = & "C:\Program Files\Wireshark\dumpcap.exe" -D | Write-Output
		ForEach($Line in ($IFlist -split "`r`n")){
			$IFNoArray.add(($Line -split "\.")[0]) | Out-Null
		}
	}Else{ # Interface number is set from config or script parameter
		$IFNoArray.add($global:WS_IF) | Out-Null
	}

	# Create option string for -i(interface)
	If($IFNoArray.Count -gt 0){
		ForEach($IFNo in $IFNoArray){
			$iOptionString = $iOptionString + " -i $IFNo"
			If(![String]::IsNullOrEmpty($global:WS_Filter)){
				$iOptionString = $iOptionString + " -f `"$global:WS_Filter`""
			}
			If(![String]::IsNullOrEmpty($global:WS_Snaplen)){
				$iOptionString = $iOptionString + " -s $global:WS_Snaplen"
			}
			If(![String]::IsNullOrEmpty($global:WS_Options)){ # Other options for -i
				$iOptionString = $iOptionString + " $global:WS_Options"
			}
		}
	}Else{
		Throw "Unabled to find valid network interface."
	}

	# Add "C:\Program Files\Wireshark" to $PATH
	Add-path "C:\Program Files\Wireshark"

	$WSOptionString = "$iOptionString -B 1024 -n -t -w $($WireSharkProperty.LogFileName) -b files:$global:WS_PurgeNrFilesToKeep -b filesize:$WS_TraceBufferSizeInKB" #_# #294
	LogInfoFile "[WireShark] Running dumpcap.exe $WSOptionString" -ShowMsg
	Start-Process "dumpcap.exe" -ArgumentList $WSOptionString -RedirectStandardOutput "$global:LogFolder\WSStartProcess-output.txt" -RedirectStandardError "$global:LogFolder\WSStartProcess-err.txt" -NoNewWindow
	Start-Sleep -Seconds 2 # Wait for a few seconds to see if the dumpcap.exe exits with error.
	$Dumpcap = $Null
	$Dumpcap = Get-Process -Name "dumpcap" -ErrorAction Ignore
	If($Null -eq $Dumpcap){ # Error case
		$ErrorMessage = ('An error happened in dumpcap.exe (Error=0x' + [Convert]::ToString($Process.ExitCode,16) + ')')
		LogError $ErrorMessage
		Write-Host "-------------------- ERROR MESSAGE --------------------"
		Get-Content "$global:LogFolder\WSStartProcess-output.txt"
		Get-Content "$global:LogFolder\WSStartProcess-err.txt"
		Write-Host "-------------------------------------------------------"
		Remove-Item "$global:LogFolder\StartProcess*" -ErrorAction Ignore
		Throw $ErrorMessage
	}Else{ # Normal case
		LogInfo "[WireShark] WireShark(dumpcap.exe) started in background."
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopWireshark{
	EnterFunc $MyInvocation.MyCommand.Name
	RunCommands "WireShark" "taskkill /F /IM dumpcap.exe" -ShowMessage:$True -ShowError:$True -ThrowException:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectWireshark{
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	$WSProcObj = Get-Process -Name 'dumpcap' -ErrorAction Ignore
	If($Null -ne $WSProcObj){
		LogDebug "$($WSProcObj.Path) is running" Yellow
		$fResult = $True
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

#endregion FW functions for custom object

#region pre/post functions for the object with 'command' /tools type ( called by $TraceObject.PreStartFunc)
Function RadarPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	If(Test-Path "$Env:tmp\rdr*.tmp"){Remove-Item -Recurse -Force $Env:tmp\rdr*.tmp}
	#FOR /F "usebackq delims==" %%i IN (`dir /B %tmp%\rdr*.tmp`) DO RMdir %tmp%\%%i /s /Q
	EndFunc $MyInvocation.MyCommand.Name
}
Function RadarPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "Collecting RADAR leak snap" -ShowMsg
	Start-Sleep -Seconds 2
	LogInfo "copying '$env:tmp\rd*.tmp' to $DirRepro\Radar"
	&{Invoke-Command -ScriptBlock { try { Get-ChildItem  $env:tmp\rdr*.tmp | ForEach-Object { Copy-Item -Force -Recurse $_.FullName $DirRepro\Radar } } catch {Throw $error[0].Exception.Message; exit 1} }}
<#	
	::call :doCmd xcopy /s/e/i/q/y %tmp%\rd*.tmp !_DirRepro!\Radar
	call :logitem ... copying '%tmp%\rd*.tmp' with PowerShell
		PowerShell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass "&{Invoke-Command -ScriptBlock { try { Get-ChildItem  $env:tmp\rdr*.tmp | ForEach-Object { Copy-Item -Force -Recurse $_.FullName !_DirRepro!\Radar } } catch {Throw $error[0].Exception.Message; exit 1} }}"
		 if "!ERRORLEVEL!" neq "0" ( call :logOnlyItem .. ERROR: !ERRORLEVEL! - 'Copy-Item %tmp%\rd*.tmp with PowerShell' failed.)
	#>
	LogInfoFile "*** [Hint] RADAR decoding: Please refer to the following process on https://osgwiki.com/wiki/Running_RADAR_locally RadarDecoder.exe"
	LogInfoFile " ** Alternate tool: Debug Diagnostic Tool https://www.microsoft.com/en-us/download/details.aspx?id=58210"
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcmonPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	# In case of Procmon 3.8 or later, use flight recorder mode which is enabled by registry.
	$ProcmonCommand = Get-Command $ProcmonProperty.CommandName
	$ProcmonVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ProcmonCommand.Path).FileVersion
	If($Null -ne $ProcmonVersion -and $ProcmonVersion -gt 3.8){
		If(!([string]::IsNullOrEmpty($global:ProcmonRingBufferSize))){
			$RingBufferSize = $global:ProcmonRingBufferSize
		}Else{
			$RingBufferSize = 3096
		}
		LogDebug "Setting Procmon RingBufferSize registry to $RingBufferSize"
		Try{ 
			If(!(Test-Path "HKCU:Software\Sysinternals\Process Monitor")){
				New-Item -Path "HKCU:Software\Sysinternals\Process Monitor" -Force -ErrorAction Ignore | Out-Null
			}
			Set-ItemProperty -Path "HKCU:Software\Sysinternals\Process Monitor" -Name "FlightRecorder" -Value 1 -ErrorAction Stop
			Set-ItemProperty -Path "HKCU:Software\Sysinternals\Process Monitor" -Name "RingBufferSize" -Value $RingBufferSize -ErrorAction Stop

		}Catch{
			LogWarn "Failed to set ring buffer size. Procmon will run without flight recorder mode."
			LogException "Failed to set RingBufferSize registry." $_ -fErrorLogFileOnly:$True
		}
		if($ProcMonAltitude.isPresent -or $global:BoundParameters['ProcMonAltitude']){
				LogInfo "Setting ProcMon Altitude registry to value $ProcMonAltitude" "cyan"
				#Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\Procmon24" -Name "SupportedFeatures" -Value 3 -Type DWord
				#Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\Procmon24" -Name "Group" -Value "FSFilter Activity Monitor" -Type String
				#Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\Procmon24" -Name "Start" -Value 0 -Type DWord
				#Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\Procmon24" -Name "Type" -Value 1 -Type DWord
				#Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\Procmon24" -Name "ImagePath" -Value "System32\drivers\PROCMON24.SYS" -Type ExpandString
				#Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\Procmon24" -Name "DefaultInstance" -Value "Process Monitor 24 Instance" -Type String
				Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\Procmon24\Instances\Process Monitor 24 Instance" -Name "Altitude" -Value $ProcMonAltitude -Type String
				Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\Procmon24\Instances\Process Monitor 24 Instance" -Name "Flags" -Value 0 -Type DWord
		}
	}

	# Check pre-existing Procmon session. If there is running Procmon, stop it.
	$ProcmonProcess = Get-Process -Name 'Procmon*' -ErrorAction Ignore
	If($Null -ne $ProcmonProcess){
		# Trying to kill Procmon by using taskkill.exe.
		LogInfo "Currently Procmon.exe is running and stopping the process."
		RunCommands "Procmon" "TASKKILL.exe /F /IM Procmon.exe /T"
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function ProcmonPostStop{
	<#
	.SYNOPSIS
	This is a function to delete Procmon 'Logfile' registry.

	.DESCRIPTION
	After stopping Procmon, 'Logfile' is created with our log path and this causes Procmon 
	to be started using the log path next time when the Procmon is started manually. 
	To prevent this from occuring, we delete the registry after stoppping Procmon.

	.NOTES
	No parameters. Exception is not thrown.
	#>
	EnterFunc $MyInvocation.MyCommand.Name
#	If((Get-Item "HKCU:\Software\Sysinternals\Process Monitor" -ErrorAction Ignore).Property -contains "Logfile"){
	If(FwTestRegistryValue "HKCU:\Software\Sysinternals\Process Monitor" "Logfile"){
		Try{
			Remove-ItemProperty -Path "HKCU:\Software\Sysinternals\Process Monitor" -Name "Logfile" -ErrorAction Stop
		}Catch{
			LogException "Failed to delete registry in ProcmonPostStop" $_ -fErrorLogFileOnly:$True
		}
	}

	$ProcmonCommand = Get-Command $ProcmonProperty.CommandName
	$ProcmonVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ProcmonCommand.Path).FileVersion
	If($Null -ne $ProcmonVersion -and $ProcmonVersion -gt 3.8){
		LogDebug "Setting RingBufferSize registry back to 0"
		Try{
			Set-ItemProperty -Path "HKCU:Software\Sysinternals\Process Monitor" -Name "FlightRecorder" -Value 0 -ErrorAction Stop	#we# changed from HKCU:\
			Set-ItemProperty -Path "HKCU:Software\Sysinternals\Process Monitor" -Name "RingBufferSize" -Value 0 -ErrorAction Stop	#we# changed from HKCU:\
			if($ProcMonAltitude.isPresent -or $global:BoundParameters['ProcMonAltitude']){
				LogInfoFile "Resetting ProcMon Altitude registry back to default 385200"
				Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\Procmon24\Instances\Process Monitor 24 Instance" -Name "Altitude" -Value "385200" -Type String -ErrorAction Stop
			}
		}Catch{
			LogException "Failed to set RingBufferSize registry." $_ -fErrorLogFileOnly:$True
		}
	}

	# Check if the Procmon is really stopped. If not, kill it using taskkill.
	$ProcmonProcess = Get-Process -Name 'Procmon*' -ErrorAction Ignore
	If($Null -ne $ProcmonProcess){
		# Trying to kill Procmon by using taskkill.exe.
		LogWarn "Stopping Procmon.exe might have failed. Stopping the Procmon process forcibly using taskkill."
		RunCommands "Procmon" "TASKKILL.exe /F /IM Procmon.exe /T"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function WPRPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	# In rare case, WPR keeps working after stopping it. So we make sure if it was really stopped or not. If it is still running, cancel the WPR as this means something wrong happened.
	LogDebug "Checking if WRP is still running."
	$RunningTraces = GetExistingTraceSession
	$WPRObject = $RunningTraces | Where-Object {$_.Name -eq 'WPR'}
	If($Null -ne $WPRObject){
		#LogWarn "Stopping WRP failed at first attempt. Canceling the WPR. You might not see a log for WPR."
		LogWarn "Stopping WRP failed at first attempt. Retrying the WPR -Stop. You might not see a log for WPR."
		LogWarn "Retrying to Stop WRP $WPR"									#_we#
		WPR.EXE -Stop $WPRLogFile											#_we#
		WPR.EXE -Status | Out-File -FilePath $global:ErrorLogFile -Append 	#_we#
		wpr.exe -cancel | Out-File -FilePath $global:ErrorLogFile -Append	#_we#
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function DetectWPR{
	# WPR  - to detect WPR: logman.exe query -ets "WPR_initiated_WprApp_WPR System Collector" (or "WPR_initiated_WprApp_WPR Event Collector")
	#we# ToDo: we may need to check for a previous WPR run; Function DetectWPR
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	$WPRSessionName = "WPR_initiated"

	$ETWSessionList = logman.exe -ets | Out-String
	GetETWSessionByPS [DetectWPR]
	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$Token = $Line -Split '\s+'
		If($Token[0].Contains($WPRSessionName)){
			LogDebug ('DetectWPR detects running WPR.')
			$fResult = $True
			Break
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function XperfPostStop{
	EnterFunc $MyInvocation.MyCommand.Name

	$RegValue = Get-ItemProperty -Path  "$global:TSSParamRegKey" -ErrorAction Ignore
	$LogFolderInReg = $RegValue.LogFolder
	If(![String]::IsNullOrEmpty($LogFolderInReg)){
		$XperfFileName = "$LogFolderInReg\xperf.etl"
		If(Test-Path -Path $XperfFileName){
			Try{
				Remove-Item $XperfFileName -Force -ErrorAction Stop
			}Catch{
				LogWarn "Xperf might be still running. Please stop Xperf manually."
			}
		}
	}

	# In rare case, Xperf keeps running after stopping it. So we make sure if it was really stopped or not. If it is still running, Please stop Xperf manually
	LogDebug "Checking if Xperf is still running."
	$RunningTraces = GetExistingTraceSession
	$XperfObject = $RunningTraces | Where-Object {$_.Name -eq 'Xperf'}
	If($Null -ne $XperfObject){
		LogWarn "Stopping Xperf failed. Please stop Xperf manually."
	}

	# Set DisablePagingExecutive.
	$RegValues = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -ErrorAction Ignore
	If($RegValues.DisablePagingExecutive -eq 1){
		$Command = "Remove-ItemProperty -Path `"HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management`" -Name 'DisablePagingExecutive' -ErrorAction Ignore"
		Runcommands "Xperf" $Command
	}

	# Remove c:\kernel.etl
	If(Test-Path "C:\kernel.etl"){
		LogInfo "Removing C:\kernel.etl"
		Remove-Item -Path "C:\kernel.etl" -Force -ErrorAction Ignore
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function DetectXperf{
	# Xperf  - to detect Xperf: logman.exe query -ets "NT Kernel Logger" (before #546), we now use the existence of temporary log file 
	#we# ToDo: we may need to check for a previous Xperf run with logman.exe -ets
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	$XperfSessionName = "NT Kernel Logger"

	$ETWSessionList = logman.exe -ets | Out-String
	GetETWSessionByPS [DetectXperf]
	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$Token = $Line -Split '\s+'
		If($Token[0].Contains($XperfSessionName)){
			LogDebug ('DetectXperf detects running Xperf.')
			$fResult = $True
			Break
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

# PSR Problem Step Recorder
Function PSRPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	StartTSSClock

	# Check pre-existing PSR session. If there is running PSR session, just kill it.
	$PSRProcess = Get-Process -Name 'PSR' -ErrorAction Ignore
	If($Null -ne $PSRProcess){
		# Trying to kill psr by using taskkill.exe.
		LogInfoFile "Currently PSR.exe is running. Stopping the process and re-run the PSR from TSS." -ShowMsg
		RunCommands "PSR" "TASKKILL.exe /F /IM psr.exe /T"
	}
	If(!([string]::IsNullOrEmpty($global:PSRmaxsc))){
		$PSRmaxsc = $global:PSRmaxsc
	}Else{
		$global:PSRmaxsc = 100
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function PSRPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	StopTSSClock
	# Check if psr.exe is still running. If it is, kill the process using taskkill.exe.
	$PSRProcess = Get-Process -Name 'PSR' -ErrorAction Ignore
	If($Null -ne $PSRProcess){
		# Trying to kill psr by using taskkill.exe.
		LogInfo "PSR.exe is still running. Stopping the process with taskkill."
		RunCommands "PSR" "TASKKILL.exe /F /IM psr.exe /T"
		Start-Sleep 3
		# Double check if the PSR really stopped.
		$PSRProcess = $Null
		$PSRProcess = Get-Process -Name 'PSR' -ErrorAction Ignore
		If($Null -ne $PSRProcess){
			LogError "Unable to stop PSR.exe."
		}Else{
			LogWarn "Failed to stop PSR gracefully and it was killed forcibly. PSR log might not be saved correctly."
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

# Video
Function VideoPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	StartTSSClock
	#$ScreenRes = (Get-WmiObject -Class Win32_DesktopMonitor | Select-Object ScreenWidth,ScreenHeight)
	#LogInfoFile "Screen Resolution (for Video): $($ScreenRes.ScreenWidth) x $($ScreenRes.ScreenHeight)"
	EndFunc $MyInvocation.MyCommand.Name
}
Function VideoPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	StopTSSClock
	EndFunc $MyInvocation.MyCommand.Name
}

Function TTDPreStart{ #we# #532
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Accepting TTD/TTD EULA per registry"
	# if using \BIN64\TTTracer.exe from package TSS_TTD.zip
	Try{
		If(!(Test-Path "HKCU:.DEFAULT\Software\Microsoft\TTD")){ #HKCU\.DEFAULT\Software\Microsoft\TTD
			New-Item -Path "HKCU:.DEFAULT\Software\Microsoft\TTD" -Force -ErrorAction Ignore | Out-Null
		}
		If(!(Test-Path "HKCU:.DEFAULT\Software\Microsoft\TTT")){
			New-Item -Path "HKCU:.DEFAULT\Software\Microsoft\TTT" -Force -ErrorAction Ignore | Out-Null
		}
		Set-ItemProperty -Path "HKCU:.DEFAULT\Software\Microsoft\TTD" -Name "EULASigned" -Value 1 -ErrorAction Stop
		Set-ItemProperty -Path "HKCU:.DEFAULT\Software\Microsoft\TTT" -Name "EULASigned" -Value 1 -ErrorAction Stop

		If(!(Test-Path "HKLM:Software\Microsoft\TTD")){
			New-Item -Path "HKLM:Software\Microsoft\TTD" -Force -ErrorAction Ignore | Out-Null
		}
		If(!(Test-Path "HKLM:Software\Microsoft\TTT")){
			New-Item -Path "HKLM:Software\Microsoft\TTT" -Force -ErrorAction Ignore | Out-Null
		}
		Set-ItemProperty -Path "HKLM:Software\Microsoft\TTD" -Name "EULASigned" -Value 1 -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:Software\Microsoft\TTT" -Name "EULASigned" -Value 1 -ErrorAction Stop

	}Catch{
		LogWarn "Failed to set TTD EULASigned."
		LogException "Failed to set TTD EULASigned." $_ -fErrorLogFileOnly:$True
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function TTDPostStop{
	EnterFunc $MyInvocation.MyCommand.Name

	Start-Sleep -Seconds 10  # It seems like we have to wait several seconds after issuing '-stop all' for -delete and -cleanup to work properly.
	
	# $Script:TTDFullPath is initialized in StopTTD()
	RunCommands "TTD" "$Script:TTDFullPath -delete all" -ThrowException:$False -ShowMessage:$True -ShowError:$False
	Start-Sleep -Seconds 3
	RunCommands "TTD" "$Script:TTDFullPath -cleanup" -ThrowException:$False -ShowMessage:$True -ShowError:$False

	# As .run file is still being opened by the attached process, we cannot compress logfolder later.
	# To prevent this, TTSv2 saves the .run file to temporary folder tmp*.tmp when starting capturing and copy .run and related files to log folder after stopping it.
	LogInfo "Trying to Copy $Script:LogTTD\*.run,*.out,*.err logs to $global:LogFolder" "Gray"
	Get-ChildItem -Path "$Script:LogTTD\*" -Include *.run,*.out,*.err -Recurse | Copy-Item -Destination $global:Logfolder -force
	LogInfo " . Rename TTD $global:LogFolder\*.run* logs to $global:LogPrefix *" "Gray"
	Get-ChildItem -Path "$global:LogFolder" -Filter "*.run*" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	LogInfo " . Rename TTD $global:LogFolder\*.out logs to $global:LogPrefix *" "Gray"
	Get-ChildItem -Path "$global:LogFolder" -Filter "*.out" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	LogInfo " . Rename TTD $global:LogFolder\TTD*.txt logs to $global:LogPrefix *" "Gray"
	Get-ChildItem -Path "$global:LogFolder" -Filter "TTD*.txt" | Rename-Item -NewName {$global:LogPrefix + $_.Name}

	# Remove TTD services if TTD is partner package.
	If($Script:UsePartnerTTD){
		LogInfo "Unregistering TTD Services"
		$TTDFolder = Split-Path $Script:TTDFullPath -Parent
		$RemoveCommands = @(
			"$TTDFolder\TTDService.exe /unregserver",
			"$TTDFolder\wow64\TTDService.exe /unregserver"
		)
		RunCommands "TTD" $RemoveCommands -ThrowException:$False -ShowMessage:$True -ShowError:$False
	}

	# Kill command prompt if onLaunch as the cmd prompt remains even after stopping TTD in case of onLaunch
	$cmdProcs = Get-CimInstance Win32_Process -Filter "name = 'cmd.exe'" -ErrorAction Ignore | Where-Object {$_.CommandLine -like '*TTTracer.exe*onLaunch*'}
	ForEach($cmdProc in $cmdProcs){
		LogInfo "Killing command prompt for TTD(PID:$($cmdProc.ProcessId))"
		RunCommands "TTD" "Taskkill /PID $($cmdProc.ProcessId) /T"
	}
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion pre/post functions for the object with 'command' /tools type
<#----------------  FUNCTIONS END  ----------------#>
#endregion script functions


#region ### MAIN
#------------------------------------------------------------------
#								MAIN 
#------------------------------------------------------------------

$global:BoundParameters = $MyInvocation.BoundParameters

# If there is no option, add -Help switch to BoundParameters to show help message
If($global:BoundParameters.Count -eq 0){
	$global:BoundParameters.Add('Help',$True)
}

# Initialize ParameterArray
$global:ParameterArray = @()
ForEach($Key in $MyInvocation.BoundParameters.Keys){
	$global:ParameterArray += $Key
}

# Display script version
If((IsStart) -and ($global:BoundParameters.ContainsKey('NewSession') -or ($RemoteRun))){ #we# for #770
	LogInfoFile "TSS Script Version: $global:TssVerDate" "Cyan" -ShowMsg
}

# Add implicit -Start verb
If((IsStart) -and !$global:BoundParameters.ContainsKey('Start')){
	$global:BoundParameters.Add('Start',$True)
	$global:ParameterArray = InsertArrayIntoArray -Array $global:ParameterArray -insertAfter 0 -valueToInsert 'Start'
}

# Set $TSScommandline. This is used when new PowerShell session is created.
$Script:TSScommandline = $MyInvocation.Line

if (-not $RemoteRun){ # don't start a -NewSession if running in PSremoting (issue #770)
	# Start new PowerShell session to clear all pre-existing global variables and run on fresh environment.
	If($global:ParameterArray -notcontains 'NewSession' -and ((IsStart) -or $global:ParameterArray -contains 'StartAutoLogger' -or $global:ParameterArray -contains 'Stop' -or $global:ParameterArray -contains 'CollectLog' -or $global:ParameterArray -contains 'StartDiag')){
		If($Host.Name -match "ISE"){
			If($global:ParameterArray -contains 'StopAutologger'){
				LogError "-StopAutologger is no longer used. Please use '-Stop' instead to stop and delete autologger sessions."
				CleanUpAndExit
			}
			If($global:ParameterArray -contains 'noISEcheck'){
				LogWarn "TSS is running on PowerShell ISE. Global variables created in previous run might be reused and that may cause unexpected behavior. When you see value in tss_config file is updated but not reflected in the session, please relaunch the PowerShell ISE and run it again for workaround."
			}
		}Else{
			# To handle path having space, use &(call operator) to start new powershell session
			$CommandArg = $MyInvocation.Line -replace "^.*ps1.",""  # & 'C:\temp\TSS (1)\TSS.ps1' -Dev_TEST1 => -Dev_TEST1
			$CommandArg = $CommandArg -replace "-StopAutologger","-Stop"  # Replace -StopAutologger with -Stop as -StopAutologger is no longer used.
			$cmdline = "& '$($MyInvocation.MyCommand.Path)' $CommandArg -NewSession"

			# Replacing double quote(") with single quote(') - Issue#595
			$cmdline = $cmdline -replace "`"","`'"
			LogDebug "Starting a new PSSession."
			PowerShell.exe $cmdline
			Exit
		}
	}
}

# Deprecated parameter list. Property array of deprecated/obsoleted params.
#   DeprecatedParam: Parameters to be renamed or obsoleted in the future
#   Type           : Can take either 'Rename' or 'Obsolete'
#   NewParam       : Provide new parameter name for replacement only when Type=Rename. In case of Type='Obsolete', put null for the value.
#$FW_DeprecatedParamList = @(
#	@{DeprecatedParam='LogFolderName';Type='Rename';NewParam='LogFolderPath'}
#)

If(!$noPrereqC.IsPresent){
	PreRequisiteCheckInStage1
}Else{
	LogInfo "Skipping PreRequisiteCheckInStage1() as -noPrereqC was specified." "Gray"
}

#region EULA
# Show EULA if needed.
If($AcceptEULA.IsPresent){
	$eulaAccepted = ShowEULAIfNeeded "TSSv2" 2  # Silent accept mode.
}Else{
	$eulaAccepted = ShowEULAIfNeeded "TSSv2" 0  # Show EULA popup at first run.
}

if ($eulaAccepted -ne "Yes")
{
   LogInfo "EULA Declined"
   Exit
}
#endregion EULA

# Clear previous errors
If($Error.Count -ne 0){
	$PreviousError = $Error | ForEach-Object { $_ } # $PreviousError will be saved to log file after the initialization of $LogFolder is completed.
}
$Error.Clear()

# Containers Change
#region Containers 
#Entry point
if ($global:containerId -ne "") {
	LogInfo "TSS support for containers scenario is still in Beta phase and data collection might be incomplete!" "Cyan"
	$ContScriptfolder = Split-Path $MyInvocation.MyCommand.Path -Parent
	$modName = "TSSv2_CONTAINERS.psm1"
	$modPath = "$ContScriptfolder\$modName"
	Remove-Module $modName -ErrorAction Ignore
	Import-Module $modPath -DisableNameChecking

	$Command = ""
	ForEach ($Param in $global:BoundParameters.Keys){
 		if (($Command -eq "") -and ($Param -ne "containerId") -and ($Param -ne "Start")){
			$Command = "-$Param"
			if ($($global:BoundParameters[$Param]).GetType().Name -eq "String"){	
					$Command = $Command + " " + $global:BoundParameters[$Param]
			}
		}
		elseif (!($Param -eq "containerId") -and ($Param -ne "Start")){
			$Command = "$Command -$Param"
			if ($($global:BoundParameters[$Param]).GetType().Name -eq "String"){
				$Command = $Command + " " + $global:BoundParameters[$Param]
			}
		}
	}
	$StopCommand = $False
	ForEach ($Param in $global:BoundParameters.Keys){
 		if ($Param -eq "Stop"){
			$StopCommand = $True
		}
	}
	
	if ($StopCommand){
		LogInfo "Container Tracing is initiated using command: $($global:ScriptName) $Command"
		global:FWEnter-ContainerTracing -fwcontainerId $containerId -fwTSSStopCommandToExecInContainer $Command
	}else {
		if (!($Command -contains "StartNoWait")) {  # StartNoWait is mandatory for containers
			$Command = $Command + " -StartNoWait"
		}
		LogInfo "Container Tracing is initiated using command: $($global:ScriptName) $Command"
		global:FWEnter-ContainerTracing -fwcontainerId $containerId -fwTSSStartCommandToExecInContainer $Command
	}
	Exit
}
#endregion Containers

#
# region Global variables
#
$global:ScriptPrefix 	= 'TSS'
$global:ScriptName 		= $MyInvocation.MyCommand.Name
$global:ScriptFolder 	= Split-Path $MyInvocation.MyCommand.Path -Parent
$global:ScriptsFolder 	= $global:ScriptFolder + "\scripts"
$global:ConfigFolder	= $global:ScriptFolder + "\config"
$global:ConfigFile		= $global:ConfigFolder + "\tss_config.cfg"
$global:InvocationLine	= $($MyInvocation.Line) #we# to enable inspect in TSSv2_[POD].psm1
$global:IsRemoting		= $False
$global:ProcDump		= ""
$global:Radar			= ""
$global:OperatingSystemInfo = global:FwGetOperatingSystemInfo
$global:OSBuild			= [int]$global:OperatingSystemInfo.CurrentBuildHex
$global:OSVersion		= [environment]::OSVersion.Version # This is just for compatibility.
$global:OriginalDisableRegistryTools = (Get-ItemProperty -ErrorAction Ignore -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System).DisableRegistryTools
$global:OriginalNetShRegistry1 = (Get-ItemProperty -ErrorAction Ignore -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh).1	# see KB5023873 for Win11 - 1="ipmontr.dll"
$global:TSSRegKey		= "HKLM:Software\Microsoft\CESDiagnosticTools\TSSv2" # To support autologger and purge task, need to set params to under HKLM
$global:TSSParamRegKey = "$global:TSSRegKey\Parameters"
$global:IsServerCore	= IsServerCore
$global:IsServerSKU 	= FwGetSrvSKU
$global:IsISE 			= $Host.Name -match "ISE Host"
$global:IsRemoteHost 	= $Host.Name -match "RemoteHost"
$global:IsLiteMode		= IsLiteMode
$global:RegAvailable = $True
# below ProgressPreference should only be set if we are running in Azure Serial Console
If($RemoteRun.IsPresent) {$global:ProgressPreference = "SilentlyContinue"}else{$global:ProgressPreference = "Continue"} #we# test for P2: powershell ( serial console): "Win32 internal error "Access is denied" 0x5 occurred while reading the console output buffer. (#675) 

# Global variables previously (only defined) in _NET.psm1
$global:Sys32			= $Env:SystemRoot + "\system32"
$global:PoolmonPath 	= $global:ScriptFolder + "\Bin\Poolmon.exe"
$global:HandlePath 		= $global:ScriptFolder + "\Bin\Handle.exe"
$global:DirScript		= $global:ScriptFolder
$global:DirRepro		= $global:LogFolder
$global:RegKeysModules = @()
$global:RegKeysModulesNoRecursive = @()
$global:EvtLogNames = @()
# endregion Global variables
# Change current working directory and will access all tools with relative path.
Set-Location $global:ScriptFolder

# Make sure all *.ps1/.psm1 files are Unblocked 
Get-ChildItem -Recurse -Path $global:ScriptFolder\*.ps* | Unblock-File -Confirm:$false

# In case of stop, read parameters from TSS registry and set them to $global:BoundParameters
If($Stop.IsPresent -or $Status.IsPresent){
	ReadParameterFromTSSReg # This adds params to $global:BoundParameters
}

# Version check
If($PSVersionTable.PSVersion.Major -le 3){ #we# ($OSBuild -le 9200) { #we# OSver is lower then Win2012: #we# TSS should work with with Win7/2008R2 with updated PS version to v5
	LogInfo "This script is supported starting with Windows 8.1 or Windows Server 2012 R2 (PowerShell v4+)" "Cyan"
	Write-Host ("... running on OS: $global:OSVersion with PS version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) `n [Beta-phase] ...parts of the script may not work or throw errors running on older OS - NOT tested!") -ForegroundColor Magenta
	Write-Host "Please update your PowerShell version to version 5.1 or higher!" -ForegroundColor Red
	Write-Host "see https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/install/installing-windows-powershell?source=recommendations&view=powershell-5.1"
	Write-Host ' '
	if ($PSVersionTable.PSVersion.Major -le 2){
		Write-Host "Please update your PowerShell version first!" -ForegroundColor Red
		CleanUpandExit 
	}
}

# Global variables for sub Folder and data locations
$global:LogPrefix 		= $env:COMPUTERNAME + "_" + "$(Get-Date -f yyMMdd-HHmmss)_" 
$global:LogSuffix 		= "-$(Get-Date -f yyyy-MM-dd.HHmm.ss)"  

# Log sub folder
$LogSubFolder = 'TSS_' + $env:COMPUTERNAME + "_" + "$(Get-Date -f yyMMdd-HHmmss)_" 

	# in case of Collecting -SDP only, shorten subfolder to SDP_<specialty>
	#if (($MyInvocation.BoundParameters.keys[0] -eq "SDP") -and ($global:BoundParameters.Count -le 2)) { # need a better check for 'SDP only'
	if ($MyInvocation.BoundParameters.keys[0] -eq "SDP") {
		$SDPcombi = ([string]::Concat($SDP)).replace(',','_') # $SDP is string array
		$LogSubFolder = 'SDP_' + $SDPcombi
	}

# Log folders
# 1. If -LogFolderPath exists, set it to $global:LogFolder
# 2. Set default log foldername($global:LogRoot + $LogSubFolder)
# 3. If 'LogFolder' is saved in TSS registry, set it to $global:LogFolder
If(($global:BoundParameters.ContainsKey('Start') -or $global:BoundParameters.ContainsKey('CollectLog') -or ($MyInvocation.BoundParameters.keys[0] -eq "SDP")) -and $global:BoundParameters.ContainsKey('LogFolderPath')){
	$global:LogRoot = $LogFolderPath + "\"
	$global:LogFolder = $global:LogRoot + $LogSubFolder
}Else{ # Normal case
	$global:LogRoot = "$env:SystemDrive\MS_DATA\"
	$global:LogFolder = $global:LogRoot + $LogSubFolder

	# If 'LogFolder' exists in TSS reg, overwrite the $global:LogFolder with the LogFolder in reg.	# ToDo: could this potentially lead to re-use same folder for subsequent runs, if prev. run had error? - sometimes we observe two datasets (different time-stamps) in one folder!?
	If(Test-Path "$global:TSSParamRegKey"){
		$RegValues = Get-ItemProperty -Path  $global:TSSParamRegKey -ErrorAction SilentlyContinue
		If($Null -ne $RegValues){
			If($($RegValues.LogFolder)){	#_# fix to avoid LogFolder=''
				LogDebug "Found LogFolder in TSS reg. Set it to LogFolder"
				$global:LogRoot = Split-Path $($RegValues.LogFolder) -Parent
				$global:LogFolder = $RegValues.LogFolder
			}
		}
	}
}
If((IsTraceOrDataCollection)){
	LogInfo "LogFolder is set to `'$global:LogFolder`'" "Cyan"
}

# Error log
$global:ErrorLogFile = "$global:LogFolder\$($LogPrefix)_Log-Warn-Err-Info.txt"
$global:ErrorVariableFile = "$global:LogFolder\$($LogPrefix)_ErrorVariable.txt"
$global:TempCommandErrorFile = "$global:LogFolder\$($LogPrefix)Command-Error.txt" #"$env:TMP\TSS-Command-Error.txt"

# Output log - used for transcription
$global:TranscriptLogFile = "$global:LogFolder\$($LogPrefix)_Log-transcript.txt"

if($StartNoWait.IsPresent -or $StartAutoLogger.IsPresent){
	$global:TranscriptLogFile = "$global:LogFolder\$($LogPrefix)_LogStart.txt"
	$global:ErrorLogFile = "$global:LogFolder\$($LogPrefix)_LogStart-Warn-Err-Info.txt"
	$global:ErrorVariableFile = "$global:LogFolder\$($LogPrefix)_LogStart_ErrorVariable.txt"
}

if($Stop.IsPresent){
	$global:TranscriptLogFile = "$global:LogFolder\$($LogPrefix)_LogStop.txt"
	$global:ErrorLogFile = "$global:LogFolder\$($LogPrefix)_LogStop-Warn-Err-Info.txt"
	$global:ErrorVariableFile = "$global:LogFolder\$($LogPrefix)_LogStop_ErrorVariable.txt"
}

LogDebug ("============================	 Log files	 ============================")
LogDebug ("LogFolder			: $global:LogFolder")
LogDebug ("LogSubFolder		 : $LogSubFolder")
LogDebug ("ErrorLogFile		 : $global:ErrorLogFile")
LogDebug ("ErrorVariableFile	: $global:ErrorVariableFile")
LogDebug ("TempCommandErrorFile : $global:TempCommandErrorFile")
LogDebug ("TranscriptLogFile	: $global:TranscriptLogFile")
LogDebug ("===========================================================================")
	
#Create Log Folder if it does not exist
If((IsTraceOrDataCollection)){ #we# added $PreviousError
	Try{
		FwCreateLogFolder $global:LogFolder
		# Log previous errors
		If($Null -ne $PreviousError){
			$PreviousError | Out-File -FilePath "$global:LogFolder\$($LogPrefix)_Pre-start-ErrorVariable.txt"
		}
	}Catch{
		LogException "Unable to create log folder. " $_
	}
}

# Before starting logging, close existing session.
Close-Transcript

# Log console output only when script starts component trace or data collection
If((IsTraceOrDataCollection)){
	Try{
		LogInfoFile "Starting transcription: $TranscriptLogFile"
		Start-Transcript -Append -Path $TranscriptLogFile | Out-Null
			$CommandArg = $MyInvocation.Line -replace "^.*ps1.",""  # & 'C:\temp\TSS (1)\TSS.ps1' -Dev_TEST1 => -Dev_TEST1
			$CommandArg = $CommandArg -replace "-StopAutologger","-Stop"  # Replace -StopAutologger with -Stop as -StopAutologger is no longer used.
			$cmdline = "'$($MyInvocation.MyCommand.Path)' $CommandArg"
		LogInfoFile "Commandline: $cmdline " #$($MyInvocation.Line)" "Gray" # Log commandline first.
		LogInfoFile "Running Command: $($MyInvocation.Line)" "Gray" -ShowMsg
		# Log PS window type
		[string]$PSMode = ($ExecutionContext.SessionState.LanguageMode)
		If(($Host.Name -match "ISE") -or ($Host.Name -match "ServerRemoteHost")){
			LogInfoFile "$($global:ScriptName) v$global:TSSverDate script execution is attempted in 'PowerShell ISE' window or in PSremote ($($Host.Name));  PSMode: $PSMode; ErrorActionPreference: $ErrorActionPreference"
		}else{
			LogInfoFile "$($global:ScriptName) v$global:TSSverDate script execution is running in regular 'PowerShell' window ($($Host.Name)) PSMode: $PSMode; ErrorActionPreference: $ErrorActionPreference"
		}
		LogInfo "... running TSS v$global:TSSverDate on OS: $global:OSVersion with PS version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)" "Gray"
	}Catch{
		LogError ("Error happened in Start-Transcript")
	}
	If(!(FwIsOsCommandAvailable Reg.exe)){
		LogInfoFile "global:RegAvailable is set to false; Microsoft REG.EXE is not found on this system."
		$global:RegAvailable = $False
	}
}

#checking online for latest public version
if (( -Not $noVersionChk.IsPresent) -or ($global:ParameterArray -notcontains 'noVersionChk')){
	If (( -Not $noUpdate.IsPresent) -and ((IsStart) -or $StartAutoLogger.IsPresent -or ![string]::IsNullOrEmpty($StartDiag) -or ![string]::IsNullOrEmpty($CollectLog))) {
		LogInfoFile "Checking if a new version is available on https://aka.ms/getTSS" -ShowMsg
		CheckVersion($global:TssVerDate)
	}
}

#Auto-Update
If (( -Not $noUpdate.IsPresent) -and ($Script:fUpToDate -eq $False) -and ((IsStart) -or $StartAutoLogger.IsPresent -or ![string]::IsNullOrEmpty($StartDiag) -or ![string]::IsNullOrEmpty($CollectLog))) {
	LogInfo "[Auto-Update] We need your consent to allow auto update, please enter Y or N" "Cyan"
	$AuUpdateAns = FwRead-Host-YN -Message "Press Y (recommended) for Yes = allow update, N for No (timeout=30s)" -Choices 'yn' -TimeOut 30
	If(!$AuUpdateAns){
		LogInfoFile "=== User declined, answered Auto-Update with: N=$AuUpdateAns ===" "Magenta"
		LogInfo "** Hint: you can use the switch -noUpdate to avoid the [Auto-Update] **"  "Cyan"
	}else{
		UpdateTSS	# skip this step with -noUpdate
		LogInfo "`n ..exiting. please repeat your TSS command-line now with latest version in place." "Cyan"
		Exit
	}
}

#
# Set $global:EnableCOMDebug to use the value in TSSv2_UEX.psm1
If($EnableCOMDebug.IsPresent){
	$global:EnableCOMDebug = $EnableCOMDebug
}

#
# Set $global:StartAutoLogger to use the value in TSSv2_NET.psm1 and other modules
If($StartAutoLogger.IsPresent){
	$global:StartAutoLogger = $StartAutoLogger
}

#region CustomParams
# Get CustomParams
If($CustomParams.Count -eq 0){			
	LogDebug ("CustomParams input is not provided")
	$global:CustomParams = @()
}else{
	$global:CustomParams = $CustomParams
	LogInfo ("Custom Parameters: " + $CustomParams)
}
#endregion CustomParams

## bail out if running in MS prod domain
if(!($Mode -iMatch "traceMS")){
	if (($env:USERDNSDOMAIN -match "\.microsoft\.com") -and (IsTraceOrDataCollection)){
		Write-Host " .. running on Domain: $env:USERDNSDOMAIN"
		Write-Host -ForegroundColor Magenta "`n ..exiting, as testing TSS in microsoft.com domain may cause Security alerts. Please test TSS in Lab environment without CorpNet access and read 'Important Note' in internal KB5026874. `nIn case you need data from this MS domain joined machine, plz append: -Mode traceMS"
		Exit
	}
}

#region Executing external PS script and exiting
If([string]::IsNullOrEmpty($ExternalScript)) {			
	LogDebug "TSS started without providing external script"
}else{
	$ScriptPath = Split-Path $MyInvocation.InvocationName 
	$Command = $ScriptPath + "\" + $ExternalScript
	write-host ("Starting external script: " + $Command)
	& "$ScriptPath\$ExternalScript"
	CleanUpandExit
}
#endregion Executing external PS script

#region --- PerfMon Counters
# Global perf counter
$global:GeneralCounters = @(
	'\Process(*)\*'
	'\Process V2(*)\*'
	'\Processor(*)\*'
	'\Processor information(*)\*'
	'\Memory(*)\*'
	'\System(*)\*'
	'\PhysicalDisk(*)\*'
	'\LogicalDisk(*)\*'
)

$global:SMBCounters = @(
	$global:GeneralCounters
	'\Server(*)\*'
	'\Server Work Queues(*)\*'
	'\SMB Client Shares(*)\*'
	'\SMB Direct Connections(*)\*'
	'\SMB Server(*)\*'
	'\SMB Server Sessions(*)\*'
	'\SMB Server Shares(*)\*'
	'\Network Adapter(*)\*'
	'\Network Interface(*)\*'
	'\Network QoS Policy(*)\*'
	'\Paging File(*)\*'
	'\Redirector\*'
	'\RDMA Activity(*)\*'
	)

$global:NETCounters = @(
	$global:SMBCounters
	'\Browser\*'
	'\Cache\*'
	'\Thread(*)\*'
	'\Netlogon(*)\*'
	'\Objects\*'
	'\Terminal Services\*'
	'\.NET CLR Memory(*)\*'
	'\IP\*'
	'\UDP\*'
	'\UDPv4\*'
	'\TCPv4\*'
	'\IPv4\*'
	'\UDPv6\*'
	'\TCPv6\*'
	'\IPv6\*'
	'\WFPv4\*'
	'\WFPv6\*'
	'\ICMP\*'
	'\IPsec Driver\*'
	'\IPsec Connections\*'
	'\IPsec AuthIP IPv6\*'
	'\IPsec AuthIP IPv4\*'
	'\IPHTTPS Global(*)\*'
	'\IPHTTPS Session\*'
	'\DNS\*'
	'\DHCP Server\*'
	'\DHCP Server v6\*'
	'\DFS Namespace Service Referrals\*'
	'\Per Processor Network Activity Cycles(*)\*'
	'\Per Processor Network Interface Card Activity(*)\*'
	'\RaMgmtSvc\*'
	'\RAS Port(*)\*'
	'\RAS Total\*'
	'\WINS Server\*'
	'\NBT Connection(*)\*'
	)

$global:BCCounters = @(
	$global:NETCounters
	'\BranchCache\*' 
	'\BranchCache Kernel Mode\*' 
	'\Client Side Caching\*'
	)

$global:DCCounters = @(
	$global:NETCounters
	'\NTDS(*)\*' 
	'\Database(lsass)\*' 
	'\DirectoryServices(*)\*' 
	'\AD FS(*)\*'
	)

$global:SQLCounters = @(
	$global:NETCounters
	'\.NET CLR Exceptions(*)\*'
	'\.NET CLR Interop(*)\*'
	'\.NET CLR Jit(*)\*'
	'\.NET CLR Loading(*)\*'
	'\.NET CLR LocksAndThreads(*)\*'
	'\.NET CLR Remoting(*)\*'
	'\.NET CLR Security(*)\*'
	'\ACS/RSVP Service(Service)\*'
	'\Active Server Pages\*'
	'\AppleTalk(*)\*'
	'\ASP.NET\*'
	'\ASP.NET Applications(__Total__)\*'
	'\ASP.NET Apps Rds V1 Beta2(__Total__)\*'
	'\ASP.NET Rds V1 Beta2\*'
	'\Distributed Transaction Coordinator\*'
	'\FTP Service(_Total)\*'
	'\FTP Service(Default FTP Site)\*'
	'\Http Indexing Service\*'
	'\IAS Accounting Clients\*'
	'\IAS Accounting Server\*'
	'\IAS Authentication Clients\*'
	'\IAS Authentication Server\*'
	'\Indexing Service\*'
	'\Indexing Service Filter\*'
	'\Internet Information Services Global\*'
	'\Job Object\*'
	'\Job Object Details\*'
	'\LogicalDisk(_Total)\*'
	'\MacFile Server\*'
	'\Microsoft Gatherer\*'
	'\Microsoft Gatherer Projects(*)\*'
	'\Microsoft Search\*'
	'\Microsoft Search Catalogs(*)\*'
	'\Microsoft Search Indexer Catalogs(*)\*'
	'\MSSQL$*:Access Methods\*'
	'\MSSQL$*:Advanced Analytics(*)\*'
	'\MSSQL$*:Availability Replica(*)\*'
	'\MSSQL$*:Backup Device\*'
	'\MSSQL$*:Batch Resp Statistics(*)\*'
	'\MSSQL$*:Broker Activation\*'
	'\MSSQL$*:Broker Statistics\*'
	'\MSSQL$*:Broker TO Statistics\*'
	'\MSSQL$*:Broker/DBM Transport\*'
	'\MSSQL$*:Buffer Manager\*'
	'\MSSQL$*:Buffer Node(*)\*'
	'\MSSQL$*:Catalog Metadata(*)\*'
	'\MSSQL$*:CLR\*'
	'\MSSQL$*:Columnstore(*)\*'
	'\MSSQL$*:Cursor Manager by Type(*)\*'
	'\MSSQL$*:Cursor Manager Total\*'
	'\MSSQL$*:Database Mirroring(*)\*'
	'\MSSQL$*:Database Replica(*)\*'
	'\MSSQL$*:Databases(*)\*'
	'\MSSQL$*:Deprecated Features\*'
	'\MSSQL$*:Exec Statistics(*)\*'
	'\MSSQL$*:FileTable\*'
	'\MSSQL$*:General Statistics\*'
	'\MSSQL$*:Http Storage(*)\*'
	'\MSSQL$*:Latches\*'
	'\MSSQL$*:Locks(*)\*'
	'\MSSQL$*:Memory Broker Clerks(*)\*'
	'\MSSQL$*:Memory Manager\*'
	'\MSSQL$*:Memory Node(*)\*'
	'\MSSQL$*:Plan Cache(*)\*'
	'\MSSQL$*:Query Store(*)\*'
	'\MSSQL$*:Replication Agents(Distribution)\*'
	'\MSSQL$*:Replication Agents(Logreader)\*'
	'\MSSQL$*:Replication Agents(Merge)\*'
	'\MSSQL$*:Replication Agents(Queuereader)\*'
	'\MSSQL$*:Replication Agents(Snapshot)\*'
	'\MSSQL$*:Replication Dist.\*'
	'\MSSQL$*:Replication Logreader(*)\*'
	'\MSSQL$*:Replication Merge\*'
	'\MSSQL$*:Replication Snapshot\*'
	'\MSSQL$*:Resource Pool Stats(*)\*'
	'\MSSQL$*:SQL Errors(*)\*'
	'\MSSQL$*:SQL Statistics\*'
	'\MSSQL$*:Transactions\*'
	'\MSSQL$*:Transactions(*)\*'
	'\MSSQL$*:User Settable(User counter 1)\*'
	'\MSSQL$*:User Settable(User counter 10)\*'
	'\MSSQL$*:User Settable(User counter 2)\*'
	'\MSSQL$*:User Settable(User counter 3)\*'
	'\MSSQL$*:User Settable(User counter 4)\*'
	'\MSSQL$*:User Settable(User counter 5)\*'
	'\MSSQL$*:User Settable(User counter 6)\*'
	'\MSSQL$*:User Settable(User counter 7)\*'
	'\MSSQL$*:User Settable(User counter 8)\*'
	'\MSSQL$*:User Settable(User counter 9)\*'
	'\MSSQL$*:Wait Statistics(*)\*'
	'\MSSQL$*:Workload Group Stats(*)\*'
	'\NNTP Commands(*)\*'
	'\NNTP Commands(_Total)\*'
	'\NNTP Server(*)\*'
	'\NNTP Server(_Total)\*'
	'\Print Queue(_Total)\*'
	'\ProcessorPerformance\*'
	'\SMTP NTFS Store Driver(*)\*'
	'\SMTP NTFS Store Driver(_Total)\*'
	'\SMTP Server(*)\*'
	'\SMTP Server(_Total)\*'
	'\SQL Server 2016 SQL Server XTP Storage(*)\*'
	'\SQL Server 2016 SQL Server XTP Transaction Log(*)\*'
	'\SQL Server 2016 XTP Cursors(*)\*'
	'\SQL Server 2016 XTP Databases(*)\*'
	'\SQL Server 2016 XTP Garbage Collection(*)\*'
	'\SQL Server 2016 XTP IO Governor(*)\*'
	'\SQL Server 2016 XTP Phantom Processor(*)\*'
	'\SQL Server 2016 XTP Transactions(*)\*'
#	'\Telephony\*'
	'\Web Service(_Total)\*'
	'\Web Service(Administration Web Site)\*'
	'\Web Service(Default Web Site)\*'
	'\Windows Media Station Service\*'
	'\Windows Media Unicast Service\*'
	'\XTP Cursors(*)\*'
	'\XTP Garbage Collection(*)\*'
	'\XTP Phantom Processor(*)\*'
	'\XTP Transactions(*)\*'
	'\Hyper-V Virtual Machine Summary\*' 
	'\Hyper-V Virtual Network Adapter\*' 
	'\Hyper-V Virtual Storage Device\*' 
	'\Hyper-V Virtual Switch\*' 
	'\Hyper-V Virtual Switch Port\*' 
	'\Hyper-V VM IO APIC\*' 
	'\Hyper-V VM Remoting\*' 
	'\Hyper-V VM Save, Snapshot, and Restore\*' 
	'\Hyper-V VM Vid Driver\*' 
	'\Hyper-V VM Vid Message Queue\*' 
	'\Hyper-V VM Vid Numa Node\*' 
	'\Hyper-V VM Vid Partition\*' 
	'\Hyper-V VM worker Process Memory Manager\*' 
	'\SQLServerDatabase Replica\*'
	)
	
$global:HyperVCounters = @(
	$global:GeneralCounters
	'\Hyper-V Hypervisor Logical Processor(*)\*'
	'\Hyper-V Hypervisor Virtual Processor(*)\*'
	'\Hyper-V Hypervisor Root Virtual Processor(*)\*'
	'\Hyper-V Dynamic Memory Balancer(*)\*'
	'\Hyper-V Dynamic Memory VM(*)\*('
	'\Hyper-V Virtual IDE Controller (Emulated)(*)\*'
	'\Hyper-V Virtual Storage Device(*)\*'
	'\Hyper-V Hypervisor Partition(*)\*'
	'\Hyper-V Hypervisor Root Partition(*)\*'
	'\Hyper-V Legacy Network Adapter(*)\*'
	'\Hyper-V Virtual Network Adapter(*)\*'
	'\Hyper-V Virtual Switch(*)\*'
	'\Hyper-V Virtual Switch Port(*)\*'
	'\Hyper-V Virtual Switch Processor(*)\*'
	'\Hyper-V VM Vid Partition(*)\*'
	'\Hyper-V VM Vid Numa Node(*)\*'
	#'\Hyper-V Dynamic Memory Integration Service(*)\*'
	#'\Hyper-V Hypervisor(*)\*'
	#'\Hyper-V Replica VM(*)\*'
	#'\Hyper-V Virtual Machine Bus(*)\*'
	#'\Hyper-V Virtual Machine Health Summary(*)\*'
	#'\Hyper-V VM Remoting(*)\*'
	#'\Hyper-V VM Save, Snapshot, and Restore(*)\*'
)

$global:BIZCounters = @(
	$global:NETCounters
	'\BizTalk:Messaging(*)\*' 
	'\XLANG/s Orchestrations(*)\*' 
	'\Distributed Transaction Coordinator\*' 
	'\BizTalk:Message Agent(*)\*' 
	'\BizTalk:Message Box:General Counters(*)\*' 
	'\BizTalk:Message Box:Host Counters(*)\*' 
	'\.Net Data Provider for SqlServer(*)\*'
	)

$global:NCCounters = @(
	$global:NETCounters
	'\Cache\*' 
	'\.NET CLR LocksAndThreads(*)\*' 
	'\Network Controller\*'
	)

$global:ALLCounters = @(
	$global:SQLCounters
	'\NTDS(*)\*'
	'\Database(lsass)\*'
	'\DirectoryServices(*)\*'
	'\Cluster Storage Hybrid Disks(*)\*'
	'\Cluster CSV Volume Cache\*'
	'\HTTP Service Url Groups(*)\*'
	'\HTTP Service Request Queues(*)\*'
	'\GPU Engine\*'
	#_# '\Security System-Wide Statistics\*'	#we# see issue #383, reason for duplication of this counter on some 2022 Cluster nodes is unclear, no repro on 2019
	)
	If($OSBuild -lt 20348){	#383 do not add for Srv2022 or Win11
		$global:ALLCounters += '\Security System-Wide Statistics\*'
	}
#endregion --- PerfMon Counters

#region initialize variables
If((IsStart) -or $StartAutoLogger.IsPresent -or $Stop.IsPresent -or !([string]::IsNullOrEmpty($StartDiag)) -or !([string]::IsNullOrEmpty($CollectLog)) -or $SDP.IsPresent){
	if ([Environment]::Is64BitOperatingSystem -eq $True){
		$Global:ProcArch = 'x64'
	}else{
		$Global:ProcArch = 'x86'
	} # Binaries are supposed to be located in $global:ScriptFolder\BIN$Global:ProcArch or $global:ScriptFolder\BIN
	
	#add support for ARM (i.e. for Defender)
	[string]$arch = (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture
	if ($arch -like "ARM*") {
		$Global:ProcArch = 'ARM'
		$global:ARM = $true
	}

	# add TSS Binary folders (\BIN***, \BIN) to $Env:Path #we#
	foreach ($sub in @("bin$Global:ProcArch", "bin")){
		Add-path (Join-Path -Path $(Split-Path $MyInvocation.MyCommand.Path -Parent) -ChildPath $sub)
	}

	# Add $Env:WinDir\System32 if it is missing
	$CommandPaths = $Env:Path -split ';'
	If($CommandPaths -notcontains "$Env:WinDir\System32"){
		LogInfoFile "Adding $Env:WinDir\System32 to PATH"
		Add-path "$Env:WinDir\System32"
	}

	# Set-/Clear-Variables Mini/Beta/Mode #we# 
	if($Mini){
		Set-Variable -scope Global -name Mini -Value $true
	}else{
		if ($Global:Mini){
			Clear-Variable -scope Global -name Mini
		}
	}
	if($beta){
		Set-Variable -scope Global -name beta -Value $true
	}else{
		if ($Global:beta){
			Clear-Variable -scope Global -name beta
		}
	}
	if($Mode){
		Set-Variable -scope Global -name Mode -Value $Mode
	}else{
		if ($Global:Mode){
			Clear-Variable -scope Global -name Mode
		}
	}
	if($DefenderDurInMin){
		Set-Variable -scope Global -name DefenderDurInMin -Value $DefenderDurInMin
	}else{
		if ($Global:DefenderDurInMin){
			Clear-Variable -scope Global -name DefenderDurInMin
		}
	}
	
	# For -PerfTCP switch
	# Make sure we don't tell user to wait for repro twice.
	# We'll display our own message in post start function
	if ($PerfTCP)
	{
		$global:BoundParameters.Add("noRepro",$True)
		LogInfoFile "Adding -noRepro switch because cmd uses -PerfTCP tool"
	}
}
$global:BinArch			= "\Bin" + $global:ProcArch

# Global variables previously (only defined) in _NET.psm1
$global:NotMyFaultPath =  $global:ScriptFolder + $BinArch + "\NotMyfaultc.exe"
$global:DFSutilPath 	= $global:ScriptFolder + $BinArch + "\DFSutil.exe"
$global:kdbgctrlPath 	= $global:ScriptFolder + $BinArch + "\kdbgctrl.exe"
$global:PstatPath 		= $global:ScriptFolder + $BinArch + "\Pstat.exe"
$global:SpaceDBPath 	= $global:ScriptFolder + $BinArch + "\spacedb.exe"  #rvi
$global:PrefixCn = $global:LogFolder + "\" + $Env:Computername + "_"
$global:PrefixTime = $global:LogFolder + "\" + $global:LogPrefix

#
# Script/Local variables
#
$script:FwScriptStartTime = Get-Date
$script:FwMonitorIntervalInSec = 5 #we# _MonitorIntervalInSec is configurable in tss_config.cfg -or by variable: CheckIntInSec
if($CheckIntInSec -gt 0) {$script:FwMonitorIntervalInSec = $CheckIntInSec}
$global:ErrorLimit = 1
$script:FwIsMonitoringEnabledByConfigFile = $False
$script:RemoteStopEventID = 999	#we# _Remote_Stop_EventID is configurable in tss_config.cfg, as some customer use 999 for their app
$script:FwConfigParameters = @{}
$script:LogZipFileSuffix = '' # variables for descriptive $LogZipFile
$script:LogZipFileSuffixScn = ''
$Script:DataCollectionCompleted = $False
$Script:UsePartnerTTD = $False
$Script:fInRecovery = $False
$Script:fPreparationCompleted = $False
$script:StopAutologger = $False
$Script:PurgeTaskName = "TSSv2 Purge Task"
$Script:PurgeTaskNameForAutologger = "TSSv2 Purge Task for AutoLogger"
$Script:IsCrashInProgress = $False
$script:PerfTCPPath 	= $global:ScriptFolder + $BinArch + "\Ntttcp.exe" 
$script:LatTePath       = $global:ScriptFolder + $BinArch + "\latte.exe"
$script:PerfSMBDL = 'C'  
$script:PerfSMBSharePath = "tssShare"  
$script:PerfSMBKeepShare = $False
$script:PerfSMBClientTmpDir = $env:TEMP + "\TSSperfSMB"
$script:PerfSMBDfltNumFiles = 1
$script:PerfSMBDfltFileSize = "1M"
$script:PerfSMBBytes = $Null  # Used to store adjusted  PerfSMBFileSize string
$script:PerfSMBUnit =  $Null  # Used to store unit from PerfSMBFileSize string
$script:PerfSMBSize =  $Null  # For convenient print statement later

# Collections
$script:ETWPropertyList = New-Object 'System.Collections.Generic.List[Object]'
$CommandPropertyList = New-Object 'System.Collections.Generic.List[Object]'
$globalTraceCatalog = New-Object 'System.Collections.Generic.List[Object]'
$LogCollector = New-Object 'System.Collections.Generic.List[Object]'
$TraceDefinitionList = New-Object 'System.Collections.Generic.List[Object]'
$StoppedTraceList = New-Object 'System.Collections.Generic.List[Object]'
$script:RunningScenarioObjectList = New-Object 'System.Collections.Generic.List[Object]'
$Script:ExecutedFunctionList = New-Object 'System.Collections.Generic.List[Object]'
$Script:DelayedExecutionList = New-Object 'System.Collections.Generic.List[Object]'
$Script:DelayedExecutionListForScenario = New-Object 'System.Collections.Generic.List[Object]'
$Script:VerDate_MSRD = ((((Get-content -Path ".\scripts\MSRD-Collect\MSRD-Collect.ps1") | Where-Object {$_ -match "msrdVersion "}) -split " ")[2]).trim("""")


# Color settings
if (-not ($global:BoundParameters.ContainsKey('RemoteRun'))){ # for issue #770
	if (($Host.Name -match "ISE") -or ($Host.Name -match "ServerRemoteHost")){
		$Host.privatedata.ConsolePaneBackgroundColor = 'Black' # this works in PowerShell ISE only
		$Host.privatedata.ConsolePaneForegroundColor = 'Cyan'  # this works in PowerShell ISE only
	}else{
		$Host.privatedata.ProgressBackgroundColor = 'Black'
		$Host.privatedata.ProgressForegroundColor = 'Cyan'
		}
}

#
# ETL Tracing options
#
$Script:ETLMode = "circular" # other option is newfile
$Script:ETLMaxSize = "1024"  # for newfile we should use 500
$Script:ETLNumberToKeep = ""  # don't use it for circular mode, for newfile default is 10 and it can be provided.
$Script:ETLFileMax = "5"	# the default value is 5 as the number of generations for autologger
If($global:BoundParameters.ContainsKey('EtlOptions')){
	$EtlArgs = $EtlOptions.Split(":")
	$Script:ETLmode = $EtlArgs[0]
	if (($Script:ETLmode -ne "circular") -and ($Script:ETLmode -ne "newfile")){
		LogError "Invalid ETLOptions! ETLOption must contain either `'circular`' or `'newfile`'"
		CleanUpandExit
	}
	if (($Script:ETLmode -ne "circular") -and ($global:BoundParameters.ContainsKey('StartAutologger'))){
		LogError "Invalid ETLOptions! ETLOption must contain `'circular`' for -StartAutologger"
		CleanUpandExit
	}
	$Script:ETLMaxSize = $EtlArgs[1]
	$Script:ETLNumberToKeep = $EtlArgs[2]
		$Script:ETLFileMax = $EtlArgs[3]
	if(([string]::IsNullOrEmpty($Script:ETLNumberToKeep)) -and ($Script:ETLmode -eq "newfile") ){
			$Script:ETLNumberToKeep = "10" #default for newfile mode
		}
	if(([string]::IsNullOrEmpty($Script:ETLMaxSize)) -and ($Script:ETLmode -eq "newfile") ){
			$Script:ETLMaxSize = "512" #default for newfile mode
		}
	if([string]::IsNullOrEmpty($Script:ETLFileMax) ){
			$Script:ETLFileMax = "5" #default for autologger filemax
		}
	if($Script:ETLmode -eq "circular"){
			$Script:ETLNumberToKeep = "" #default for circular mode
		}
	if(([string]::IsNullOrEmpty($Script:ETLMaxSize)) -and ($Script:ETLmode -eq "circular") ){
			$Script:ETLMaxSize = "1024" #default for circular mode
		}
}

LogDebug ("============================== ETL Option ================================")
LogDebug ("ETLOptions: $EtlOptions")
LogDebug ("ETLMode=" + $Script:EtlMode + "   ETLMaxSizeMB=" + $Script:ETLMaxSize + "   ETLNumberToKeep=" + $Script:ETLNumberToKeep + "   ETLFileMax=" + $Script:ETLFileMax)
LogDebug ("==========================================================================")

# AutoLogger
$AutoLoggerLogFolder = $global:LogFolder
$AutoLoggerPrefix = 'autosession\'
$AutoLoggerBaseKey = 'HKLM:\System\CurrentControlSet\Control\WMI\AutoLogger\'

# Batch file
$BatFileName = "$global:LogFolder\TSSv2.cmd"
$StartAutoLoggerBatFileName = "$AutoLoggerLogFolder\StartAutoLogger.cmd"
$StopAutoLoggerBatFileName = "$AutoLoggerLogFolder\StopAutoLogger.cmd"

# Read-only variables
Set-Variable -Name 'fLogFileOnly' -Value $True -Option readonly

#endregion initialize variables

#region Loading all POD modules
LogDebug " ---> Loading all POD modules."
LogDebug "Note: If stuck here: Some security software like Cynet has capability to inhbit loading PS modules." "Magenta"
foreach($file in Get-ChildItem $Scriptfolder){
	$extension = [IO.Path]::GetExtension($file)
	if ($extension -eq ".psm1" ){
		$modName = ($file.Name).substring(0, ($file.Name).length - 5)
		$modPath = "$Scriptfolder\$($file.Name)"
		Remove-Module $modName -ErrorAction Ignore
		#LogDebug ("Remove module for $modName completed")
		Import-Module $modPath -DisableNameChecking
		#LogDebug ("Import module for $modPath completed")
	}
}
LogDebug " <--- Finished Loading all POD modules."
#endregion Loading all POD modules

# Early Exit if -CollectLog functions are not defined
If (!([string]::IsNullOrEmpty($CollectLog))) {
	If (!(FwIsCollectFunctionAvailable)){
		CleanUpandExit
	}
}

###
### Create trace properties and build trace list
###
If(!(IsStart)){
	# In case of not -Start, we add all traces to trace list to know what traces are currently running.
	$RequestedTraceList = $TraceSwitches.Keys
}

# For customETL
If($global:ParameterArray -Contains 'customETL'){
	$WIN_CustomETLProviders = @(
		$CustomETL	# List of user provided custom ETL providers, i.e. -CustomETL '{CBDA4DBF-8D5D-4F69-9578-BE14AA540D22}','Microsoft-Windows-PrimaryNetworkIcon'
	)
	LogInfoFile "Adding CustomETL providers: $CustomETL"
}

# Load all trace providers defined in POD modules
$ALLPODsProviderArray = Get-Variable -Name "*Providers"

LogDebug " ---> Building TraceDefinitionList"
if ((IsTraceOrDataCollection) -or $FindGUID -or $TraceInfo -or $Status){ # added for #875 #we#fix -Status#
	ForEach($TraceProvider in $ALLPODsProviderArray){
		$TraceName = $TraceProvider.Name -replace ("Providers","")
		$ETEfileList = New-Object 'System.Collections.Generic.List[Object]'
		#If(($TraceProvider.value[0]).contains('!')){				  milanmil210527 commented
		If(!([string]::IsNullOrEmpty($TraceProvider.value[0])) -and (($TraceProvider.value[0]).contains('!'))){ #milanmil210527 added
			# This is possible multiple etl file trace. So check if this has really multiple etl file
			ForEach($Provider in $TraceProvider.value){
				$Token = $Provider -split ('!')
				$ETLFile = $ETEfileList | Where-Object {$_ -eq $Token[1]}
				If($Null -eq $ETLFile){
					$ETEfileList.add($Token[1]) 
				}
			}
			If($ETEfileList.Count -gt 1){
				$TraceDefinitionList += @{Name = $TraceName; Provider = $TraceProvider.value; MultipleETLFiles = 'yes'}
			}Else{
				$TraceDefinitionList += @{Name = $TraceName; Provider = $TraceProvider.value}
			}
		}Else{
			$TraceDefinitionList += @{Name = $TraceName; Provider = $TraceProvider.value}
		}
	}
}
LogDebug " <--- done Building TraceDefinitionList"

<#
If($DebugMode.IsPresent){
	LogDebug "======================	 Trace Definition List	 ======================"
	ForEach($TraceDefinition in $TraceDefinitionList){
		Write-Host ($TraceDefinition.Name + " ") -NoNewline -ForegroundColor Green
	}
	Write-Host ' '
	LogDebug "==========================================================================="
}
#>

# Read tss_config.cfg file and validate parameters
If((IsStart) -or ($CollectLog)){ # enable tss_config parameters for -CollectLog
	Try{
		LogDebug "Reading tss_config.cfg file"
		ReadConfigFile
		ValidateConfigFile
		If($DebugMode.IsPresent){
			LogInfo "====================== CONFIG PARAMETERS ======================"
			ForEach($Key in $FwConfigParameters.Keys){
				LogInfo ("  - $Key=" + $FwConfigParameters[$Key])
			}
			LogInfo "==============================================================="
		}
	}Catch{
		LogException "Invalid parameter(s) is configured in tss_config.cfg" $_
		CleanUpAndExit
	}
}

# Setup remoting if enabled.
$EnableRemotingValue = $FwConfigParameters['_EnableRemoting']
If((![string]::IsNullOrEmpty($EnableRemotingValue) -and $EnableRemotingValue.Substring(0,1) -eq 'y') -or $global:BoundParameters.ContainsKey('RemoteHosts') -or ($global:BoundParameters.ContainsKey('WaitEvent') -and ( $WaitEvent -iMatch "Signal"))){ #we# added "Signal" for WAITFOR.exe #519
	SetupRemoting
}

$WPRLogFile = "$global:LogFolder\$($LogPrefix)WPR_$WPR.etl"
$WPRBootTraceSupportedVersion = @{OS=10;Build=15063} # BootTrace is supported from RS2+
$WPRAutLoggerKey = "$AutoLoggerBaseKey\WPR_initiated_WprApp_boottr_WPR Event Collector"

#region Tool/command Property
$WPRProperty = @{
	Name = 'WPR'
	TraceName = 'WPR'
	LogType = 'Command'
	CommandName = 'wpr.exe'
	Providers = $Null
	LogFileName = "`"$WPRLogFile`""
	StartOption = "-start GeneralProfile -start CPU -start DiskIO -start FileIO -Start Registry -FileMode -recordtempto $global:LogFolder"
	StopOption = "-stop $WPRLogFile"
	PreStartFunc = $Null
	PostStopFunc = $Null
	DetectionFunc = 'DetectWPR'
	StopTimeOutInSec = 1800 # 30 minutes
	AutoLogger = @{
		AutoLoggerEnabled = $False
		AutoLoggerLogFileName = "$AutoLoggerLogFolder\WPR-BootTrace$LogSuffix.etl"
		AutoLoggerSessionName = 'WPR(BootTrace)'
		AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot FileIO -addboot DiskIO -addboot Registry -filemode -recordtempto $AutoLoggerLogFolder"
		AutoLoggerStopOption = "-BootTrace -stopboot `"$AutoLoggerLogFolder\WPR-BootTrace$LogSuffix.etl`""
		AutoLoggerKey = "$AutoLoggerBaseKey" + "WPR_initiated_WprApp_boottr_WPR Event Collector"
	}
	Wait = $True
	#SupportedOSVersion = @{OS=10;Build=10240}
	SupportedOSVersion = @{OS=6;Build=9600}	#we# 2012-R2+   //Ws2012 9200 seems not supported! // ToDo: tssv1: 9600 does not support WPR, => should attempt trying Xperf
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.WPR
	StopPriority = $StopPriority.WPR
	WindowStyle = $Null
}

If($global:ParameterArray -contains "xperf"){
	$XperfLogFile = "$global:LogFolder\$($LogPrefix)Xperf-$Xperf.etl"
}Else{
	$XperfLogFile = "$global:LogFolder\$($LogPrefix)Xperf.etl"
}
$XperfProperty = @{
	Name = 'Xperf'
	TraceName = 'Xperf'
	LogType = 'Command'
	CommandName = "xperf.exe"
	Providers = $Null
	LogFileName = $XperfLogFile
	StartOption = "-on"  # This will set in FixUpXperfProperty later
	StopOption = "-stop -d $XperfLogFile"
	PreStartFunc = $Null
	PostStopFunc = $Null
	#DetectionFunc = 'DetectXperf'	#we# Todo
	StopTimeOutInSec = 1800 # 30 minutes
	AutoLogger = @{
		AutoLoggerEnabled = $False
		AutoLoggerLogFileName = "$AutoLoggerLogFolder\Xperf-BootTrace$LogSuffix.etl"
		AutoLoggerSessionName = 'Xperf(BootTrace)'
		AutoLoggerStartOption = "-BootTrace"
		AutoLoggerStopOption = "-stop -d $AutoLoggerLogFolder\Xperf-BootTrace$LogSuffix.etl"
		AutoLoggerKey = "HKLM:\System\CurrentControlSet\Control\WMI\GlobalLogger"
	}
	Wait = $True
	SupportedOSVersion = $Null #// 9600+? //Ws2012 9200 WPR seems not supported, but XPerf might...!
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Xperf
	StopPriority = $StopPriority.Xperf
	WindowStyle = $Null
}

# Netsh(Packet capturing)
$NetshLogFile = "$global:LogFolder\$($LogPrefix)Netsh_packetcapture.etl"
if ($OSBuild -le 9200) { $Script:NetshTraceReport ="report=no" }else{ $Script:NetshTraceReport ="report=disabled" }	#we#  preferred Report mode depends on OS

$NetshProperty = @{
	Name = 'Netsh'
	TraceName = 'Netsh'
	LogType = 'Command'
	CommandName = 'netsh.exe'
	Providers = $Null
	LogFileName = "`"$NetshLogFile`""
	StartOption = "trace start fileMode=circular"  # This will be updated in FixUpNetshProperty() later.
	StopOption = 'trace stop'
	PreStartFunc = $Null
	PostStopFunc = $Null
	StopTimeOutInSec = 600 # 10 minutes
	AutoLogger = @{
		AutoLoggerEnabled = $False
		AutoLoggerLogFileName = "$AutoLoggerLogFolder\$($LogPrefix)packetcapture-AutoLogger.etl"
		AutoLoggerSessionName = 'Netsh(persistent=yes)'
		AutoLoggerStartOption = "trace start persistent=yes fileMode=circular"
		AutoLoggerStopOption = 'trace stop'
		AutoLoggerKey = "$AutoLoggerBaseKey" + "-NetTrace-$env:UserDomain-$env:username"
	}
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Netsh
	StopPriority = $StopPriority.Netsh
	WindowStyle = $Null
}

If($OSBuild -eq 9600){ 
	$NetshProperty.AutoLogger.AutoLoggerKey = "$AutoLoggerBaseKey\NetTrace-$env:UserDomain-$env:username"
}

# Netsh WFPdiag
$WFPdiagLogfile = "$global:Logfolder\$LogPrefix" + "WFPdiag.cab"
$WFPdiagProperty = @{
	Name = 'WFPdiag'
	TraceName = 'Netsh WFPdiag'
	LogType = 'Custom'
	CommandName = $Null
	Providers = $Null
	LogFileName = "$global:Logfolder\$LogPrefix" + "WFPdiag.cab"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartWFPdiag'
	StopFunc = 'StopWFPdiag'
	PostStopFunc = $Null
	DetectionFunc = 'DetectWFPdiag'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.WFPdiag
	StopPriority = $StopPriority.WFPdiag
	WindowStyle = $Null
}

# Netsh RASdiag
$RASdiagProperty = @{
	Name = 'RASdiag'
	TraceName = 'Netsh RASdiag'
	LogType = 'Custom'
	CommandName = $Null
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartRASdiag'
	StopFunc = 'StopRASdiag'
	PostStopFunc = $Null
	DetectionFunc = 'DetectRASdiag'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.RASdiag
	StopPriority = $StopPriority.RASdiag
	WindowStyle = $Null
}

$PktMonProperty = @{
	Name = 'PktMon'
	TraceName = 'PktMon(Packet Monitor)'
	LogType = 'Custom'
	CommandName = $Null
	Providers = $Null
	LogFileName = "$global:Logfolder\$LogPrefix" + "PktMon.etl"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartPktMon'
	StopFunc = 'StopPktMon'
	PostStopFunc = $Null
	DetectionFunc = 'DetectPktMon'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = @{OS=10;Build=17763}
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.PktMon
	StopPriority = $StopPriority.PktMon
	WindowStyle = $Null
}

$FiddlerProperty = @{
	Name = 'Fiddler'
	TraceName = 'Fiddler'
	LogType = 'Custom'
	CommandName = "ExecAction.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartFiddler'
	StopFunc = 'StopFiddler'
	PostStopFunc = $Null
	DetectionFunc = 'DetectFiddler'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Fiddler
	StopPriority = $StopPriority.Fiddler
	WindowStyle = $Null
}

$SysMonProperty = @{
	Name = 'SysMon'
	TraceName = 'Sysmon(System Monitor)'
	LogType = 'Custom'
	CommandName = $Null
	Providers = $Null
	LogFileName = "$global:Logfolder\$env:computername-Microsoft-Windows-Sysmon-Operational.txt"  # This is just a place holder. This file will not be used.
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartSysMon'
	StopFunc = 'StopSysMon'
	PostStopFunc = $Null
	DetectionFunc = 'DetectSysMon'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.SysMon
	StopPriority = $StopPriority.SysMon
	WindowStyle = $Null
}

$ProcmonLogFile = "$global:LogFolder\$($LogPrefix)Procmon_$ProcmonAltitude.pml"
$fDonotDeleteProcmonReg = $False
$ProcmonProperty = @{
	Name = 'Procmon'
	TraceName = 'Procmon'
	LogType = 'Command'
	CommandName = "Procmon.exe"
	Providers = $Null
	LogFileName = "`"$ProcmonLogFile`""
	StartOption = "/AcceptEula /quiet /backingfile `"$ProcmonLogFile`""
	StopOption = '/AcceptEula /Terminate'
	PreStartFunc = $Null
	PostStopFunc = $Null
	StopTimeOutInSec = 900 # 15 minutes
	AutoLogger = @{
		AutoLoggerEnabled = $False
		AutoLoggerLogFileName = "$AutoLoggerLogFolder\Procmon-BootLogging.pml"
		AutoLoggerSessionName = 'Procmon(BootLogging)'
		AutoLoggerStartOption = '/AcceptEula /EnableBootLogging'
		AutoLoggerStopOption = "/AcceptEula /ConvertBootLog `"$AutoLoggerLogFolder\Procmon-BootLogging.pml`""
		AutoLoggerKey = 'HKLM:\System\CurrentControlSet\Services\Procmon24'
	}
	Wait = $False
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Procmon
	StopPriority = $StopPriority.Procmon
	WindowStyle = "Minimized"
}

$PSRProperty = @{
	Name = 'PSR'
	TraceName = 'PSR(Problem Steps Recorder)'
	LogType = 'Command'
	CommandName = 'psr.exe'
	Providers = $Null
	LogFileName = "`"$global:LogFolder\$($LogPrefix)PSR.zip`""
	StartOption = "/start /output `"$($global:LogFolder)\$($LogPrefix)PSR.zip`" /maxsc $global:PSRmaxsc /gui 0"
	StopOption = '/stop'
	PreStartFunc = 'PSRPrestart'
	StartFunc = $Null
	StopFunc = $Null
	PostStopFunc = 'PSRPostStop'
	DetectionFunc = $Null
	StopTimeOutInSec = 30
	AutoLogger = $Null
	Wait = $False
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.PSR
	StopPriority = $StopPriority.PSR
	WindowStyle = $Null
}

# Video
$wmvFile = "$global:LogFolder\$($LogPrefix)VideoRepro.wmv"
$VideoLogFile = "$global:LogFolder\$($LogPrefix)VideoRepro.log"
$VideoProperty = @{
	Name = 'Video'
	TraceName = 'Video recorder'
	LogType = 'Command'
	CommandName = 'RecorderCommandLine.exe'
	Providers = $Null
	LogFileName = $wmvFile
	StartOption = "-start -fullscreen -output $wmvFile -overwrite -log $VideoLogFile"
	StopOption = '-stop'
	PreStartFunc = $Null
	PostStopFunc = $Null
	AutoLogger = $Null
	Wait = $False
	StopTimeOutInSec = 30
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Video
	StopPriority = $StopPriority.Video
	WindowStyle = "Minimized"
}

$LiveKDProperty = @{
	Name = 'LiveKD'
	TraceName = 'LiveKD'
	LogType = 'Custom'
	CommandName = "Livekd.exe"
	Providers = $Null
	LogFileName = "$global:Logfolder\$($LogPrefix)liveKdDump.dmp"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartLiveKD'
	StopFunc = 'StopLiveKD'
	PostStopFunc = $Null
	DetectionFunc = 'DetectLiveKD'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.LiveKD
	StopPriority = $StopPriority.LiveKD
	WindowStyle = $Null
}

$GPresultProperty = @{
	Name = 'GPresult'
	TraceName = 'GPresult'
	LogType = 'Custom'
	CommandName = "GPresult.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartGPresult'
	StopFunc = 'StopGPresult'
	PostStopFunc = $Null
	DetectionFunc = 'DetectGPresult'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.GPresult
	StopPriority = $StopPriority.GPresult
	WindowStyle = $Null
}

$HandleProperty = @{
	Name = 'Handle'
	TraceName = 'Handle'
	LogType = 'Custom'
	CommandName = "Handle.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartHandle'
	StopFunc = 'StopHandle'
	PostStopFunc = $Null
	DetectionFunc = 'DetectHandle'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Handle
	StopPriority = $StopPriority.Handle
	WindowStyle = $Null
}

$PoolMonProperty = @{
	Name = 'PoolMon'
	TraceName = 'PoolMon'
	LogType = 'Custom'
	CommandName = "PoolMon.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartPoolMon'
	StopFunc = 'StopPoolMon'
	PostStopFunc = $Null
	DetectionFunc = 'DetectPoolMon'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.PoolMon
	StopPriority = $StopPriority.PoolMon
	WindowStyle = $Null
}

$ProcDumpProperty = @{
	Name = 'ProcDump'
	TraceName = 'ProcDump'
	LogType = 'Custom'
	CommandName = "ProcDump.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartProcDump'
	StopFunc = 'StopProcDump'
	PostStopFunc = $Null
	DetectionFunc = 'DetectProcDump'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.ProcDump
	StopPriority = $StopPriority.ProcDump
	WindowStyle = $Null
}

$RadarProperty = @{
	Name = 'Radar'
	TraceName = 'Radar'
	LogType = 'Custom'
	CommandName = "rdrleakdiag.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartRadar'
	StopFunc = 'StopRadar'
	PostStopFunc = $Null
	DetectionFunc = 'DetectRadar'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Radar
	StopPriority = $StopPriority.Radar
	WindowStyle = $Null
}

$WireSharkProperty = @{
	Name = 'WireShark'
	TraceName = 'WireShark'
	LogType = 'Custom'
	CommandName = "$env:ProgramFiles\Wireshark\dumpcap.exe"
	Providers = $Null
	LogFileName = "$global:Logfolder\$($LogPrefix)WireShark-packetcapture.pcap"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartWireShark'
	StopFunc = 'StopWireshark'
	PostStopFunc = $Null
	DetectionFunc = 'DetectWireshark'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.WireShark
	StopPriority = $StopPriority.WireShark
	WindowStyle = $Null
}

$PerfTCPProperty = @{
	Name = 'PerfTCP'
	TraceName = 'PerfTCP'
	LogType = 'Custom'
	CommandName = "Ntttcp.exe"
	Providers = $Null
	LogFileName = "$global:Logfolder\$($LogPrefix)PerfTCP.txt"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartPerfTCP'
	StopFunc = 'StopPerfTCP'
	PostStopFunc = $Null
	DetectionFunc = $Null
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.PerfTCP
	StopPriority = $StopPriority.PerfTCP
	WindowStyle = $Null
}

$PerfSMBProperty = @{
	Name = 'PerfSMB'
	TraceName = 'PerfSMB'
	LogType = 'Custom'
	CommandName = "Robocopy.exe"
	Providers = $Null
	LogFileName = "$global:Logfolder\$($LogPrefix)PerfSMB.txt"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartPerfSMB'
	StopFunc = 'StopPerfSMB'
	PostStopFunc = $Null
	DetectionFunc = $Null
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.PerfSMB
	StopPriority = $StopPriority.PerfSMB
	WindowStyle = $Null
}

# Performance Monitor log
$Script:PerfMonInterval = 10 # default 10 seconds

# PerfMon logs
$SupportedPerfCounter = @{
	'General'	= 'Basic CPU, Memory, Disk and process counters'
 	'ALL'		= 'General + SMB + NET + SQL + DC + Cluster counters'
	'BC'		= 'General + SMB + NET + BranchCache counters'
	'BIZ'		= 'General + SMB + NET + BIZ counters'
	'DC'		= 'General + SMB + NET + DomainController counters'
	'HyperV'	= 'General + HyperV counters'
	'NC'		= 'General + SMB + NET + Network Controller counters'
	'NET'		= 'General + SMB + NET counters'
	'SMB'		= 'General + SMB counters'
	'SQL'		= 'General + SMB + NET + SQL counters'
}

LogDebug " ---> Begin Preparing supported Perfcounter list"
$ALLPODsPerfCounter = Get-Variable -Name "*_SupportedPerfCounter" -ValueOnly
ForEach($PODPerfCounter in $ALLPODsPerfCounter){
	ForEach($Key in $PODPerfCounter.keys){
		$SupportedPerfCounter.Add($Key, $PODPerfCounter[$Key])
	}
}
LogDebug " <--- End Preparing supported Perfcounter list"

$PerfMonProperty = @{
	Name = 'PerfMon'
	TraceName = "PerfMon log with short interval"
	LogType = 'Perf'
	CommandName = 'logman.exe'
	Providers = $GeneralCounters
	LogFileName = "$global:LogFolder\$($LogPrefix)PerfMon_$($PerfMon)_$($PerflogInterval)sec_$($PerfMonMaxMB)MB.blg"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	PostStopFunc = $Null
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Perf
	StopPriority = $StopPriority.Perf
}

# Performance Monitor with long interval
$Script:PerfMonLongInterval = 10 * 60 # default 10 minutes
$PerfMonLongProperty = @{
	Name = 'PerfMonLong'
	TraceName = "PerfMon log with long interval"
	LogType = 'Perf'
	CommandName = 'logman.exe'
	Providers = $GeneralCounters
	LogFileName = "$global:LogFolder\$($LogPrefix)PerfMonLong_$($PerfMonLong)_$($PerflogLongInterval)sec_$($PerfMonMaxMB)MB.blg"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	PostStopFunc = $Null
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Perf
	StopPriority = $StopPriority.Perf
}

$TTDProperty = @{
	Name = 'TTD'
	TraceName = 'TTD trace'
	LogType = 'Custom'
	CommandName = $Null
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartTTD'
	StopFunc = 'StopTTD'
	PostStopFunc = $Null
	DetectionFunc = 'DetectTTD'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null # @{OS=10;Build=17763} # From RS5.
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.TTD
	StopPriority = $StopPriority.TTD
}

$CommandPropertyList = @(
	$FiddlerProperty
	$GPresultProperty
	$HandleProperty
	$LiveKDProperty
	$NetshProperty
	$PoolmonProperty
	$PerfMonProperty
	$PerfMonLongProperty
	$PerfTCPProperty
	$PerfSMBProperty
	$PktMonProperty
	$ProcDumpProperty
	$ProcmonProperty
	$PSRProperty
	$RadarProperty
	$RASdiagProperty
	$SysMonProperty
	$TTDProperty
	$VideoProperty
	$WFPdiagProperty
	$WireSharkProperty
	$WPRProperty
	$XperfProperty
)
#endregion Tool/command Property

#support for scenarios (simulating import parameters)
If($Scenario.Count -ne 0 -and (IsStart)){
	ForEach($ScenarioName in $Scenario){
		$myArrayToInsert = @()
		$ScenarioTraceSetName = "$($ScenarioName)_ETWTracingSwitchesStatus"
		$Scenario_ETWTracingSwitchesStatus = Get-Variable $ScenarioTraceSetName -ValueOnly -ErrorAction Ignore
		If($Null -eq $Scenario_ETWTracingSwitchesStatus){
			LogError "Invalid scenario name $ScenarioName was specified."
			Write-Host "=> Run `'.\$($global:ScriptName) -ListSupportedScenario`' to see available scenario names." -ForegroundColor Yellow
			Write-Host " and Please also run '.\$($global:ScriptName) -Stop' once after such error, in order to cleanup previous failed TSS attempts." -ForegroundColor  Cyan	#we# added to avoid Perfmon errors in next run
			CleanUpAndExit
		}

		$ETWTraceCountInScenario = 0
		LogInfoFile "Specified scenario $ScenarioName contains following traces and parameters:" "Gray" -ShowMsg
		ForEach($Key in $Scenario_ETWTracingSwitchesStatus.Keys){
			$Token = $Null
			$ValueName = $Null
			$OriginalCommand = $Null

			If($Key.contains(' ')){ # Parameter with option
				$Token = $Key -split ' '  # Example: 'WPR General' to WPR
				$Command = $Token[0]
				$OriginalCommand = $Key

				# Create NetshOptions for Netsh
				If(!$MyInvocation.BoundParameters.ContainsKey($Command)){
					# Netsh
					If(($Token[0] -eq 'Netsh')){
						# If there is 2nd token, that is NetshOptions and set it to BoundParameters.
						If($Token.Length -gt 2){
							$OptionString = $Null
							For($i=1;$i -lt $Token.Length;$i++){
								$OptionString += $Token[$i] + ' '
							}
							$OptionString = $OptionString -replace " $",""  # remove space at the end.
							If(!$global:BoundParameters.containskey('NetshOptions')){
								$global:BoundParameters.Add('NetshOptions',$OptionString)
							}Else{
								LogInfoFile "NetshOptions has already been set from command line. Using the command line option." -ShowMsg
							}
						}
						$global:BoundParameters.Add('Netsh',$True)
						LogInfoFile "   - $OriginalCommand" "Gray" -ShowMsg
						Continue
					}

					# Create NetshOptions for Netsh and WPROptions for WPR
					If(($Token[0] -eq 'NetshScenario') -or ($Token[0] -eq 'WPR')){
						# If 3rd token exists, it is netshoptions and set it to BoundParameters.
						If($Null -ne $Token[2]){
							$OptionString = $Null
							For($i=2;$i -lt $Token.Length;$i++){
								$OptionString += $Token[$i] + ' '
							}
							$OptionString = $OptionString -replace " $",""  # remove space at the end.
							If($Token[0] -eq 'NetshScenario'){
								$OptionName = 'NetshOptions'
							}ElseIf($Token[0] -eq 'WPR'){
								$OptionName = 'WPROptions'
							}
							If(!$global:BoundParameters.containskey($OptionName)){
								$global:BoundParameters.Add($OptionName,$OptionString)
							}Else{
								LogInfo "$OptionName has already been set from command line. Using the command line option."
							}
						}
					}

					# Other all options that take string, string array, integer are set to BoundParameters[].
					If(($Token[1]).contains(',')){
						$Parameter = $Token[1] -split ','
					}Else{
						$Parameter = $Token[1]
					}
					$global:BoundParameters.Add($Command,$Parameter)
				}Else{
					# In case that the same switch is specified by command line and scenario trace, we will respect command line.
					If(!$Status) {LogInfo "Sc.Tool: $Command was specified by both command line and scenario trace. Using `'$Command' in command line instead of scenario definition."}
					Continue # Skip adding to $myArrayToInsert
				}
			}Else{ # Parameter without option is set to BoundParameters[] here.
				$Command = $Key
				# Add only command type trace. ETW will be added later.
				If(!($MyInvocation.BoundParameters.ContainsKey($Command))){
					If($CommandSwitches.ContainsKey($Command)){
						$global:BoundParameters.Add($Command,$True)
					}
				}Else{
					# In case that the same switch is specified by command line and scenario trace, we will respect command line.
					If(!$Status) {LogInfo "Sc.NoOpt: $Command was specified by both command line and scenario trace. Using `'$Command' in command line instead of scenario definition."}
					Continue # Skip adding to $myArrayToInsert
				}
			}

			# Only when trace is '$True'(enabled), we add it to parameter.
			If($Scenario_ETWTracingSwitchesStatus[$Key]){
				# ETW: Add prefix to trace name so that framework recognize this trace is part of scenario. #bugbug we need to investigate ONLY ETW traces, not things like Commontask
				#_#ForEach($TraceProperty in $ETWPropertyList){ # better use ETWPropertyList for -Status, instead of TraceDefinitionList?
				ForEach($TraceProperty in $TraceDefinitionList){
					If($TraceProperty.Name -eq $Command){
						$ScenarioTraceName = $ScriptPrefix + '_' + $Scenario + "Scenario_" + $Command
						LogDebug "Renaming $Command to $ScenarioTraceName"

						# ETW is added here.
						$global:BoundParameters.Add($ScenarioTraceName,$True)
						$ETWTraceCountInScenario++
						break
					}
				}

				# Add command switches(netsh, WPR, Procmon and so on)
				If($ControlSwitches -Contains $Command){
					If(!($global:BoundParameters.ContainsKey($Command))){
						$global:BoundParameters.Add($Command,$True)
					}
				}Else{
					LogDebug "$Command is not added to ParameterArray."
				}
				If($Null -eq $OriginalCommand){
					LogInfoFile "   - $Command" "Gray" -ShowMsg
				}Else{
					LogInfoFile "   - $OriginalCommand" "Gray" -ShowMsg
				}
			}Else{
				LogDebug ("$Key in $ScenarioName scenario is disabled")
			}
		}
	}
}

# Converting $Mini to noSwitches.
If($global:BoundParameters.ContainsKey('Mini') -and !$global:BoundParameters.ContainsKey('Status')){
	$noSwitches = @(
		'noBasicLog'
		'noPSR'
		'noSDP'
		'noVideo'
		'noXray'
		'noZip'
	)
	LogInfo "Extracting `'Mini`' switch and adding the extracted parameters to ParameterArray"
	ForEach($noSwitch in $noSwitches){
		If(!($global:BoundParameters.ContainsKey($noSwitch))){
			LogDebug "Adding $noSwitch to BoundParameters"
			$global:BoundParameters.Add($noSwitch,$True)
		}Else{
			LogDebug "$noSwitch is already contained in BoundParameters. Skipping this switch."
		}
	}
}

<# Add switches in noSettingList to BoundParameters
If($global:BoundParameters.ContainsKey('noSettingList')){
	ForEach($Token in $global:BoundParameters['noSettingList']){
		If(!($global:BoundParameters.ContainsKey($Token))){
			LogDebug "Adding $Token to BoundParameters"
			$global:BoundParameters.Add($Token,$True)
		}Else{
			LogDebug "$Token is already contained in BoundParameters. Skipping this switch."
		}
	}
} #>

# Issue#321
# For Server Core, or when running in Remote PSsession, add noVideo and noPSR so that -Video and -PSR will be removed later.
If((($global:IsServerCore) -or ($global:BoundParameters.ContainsKey('RemoteRun'))) -and !($Version -or $Update)){ 
	LogInfoFile "TSS is running on Server Core($global:IsServerCore) or in Remote PSsession. Adding -noVideo and -noPSR to script parameter" -ShowMsg
	$noSwichForServerCore = @(
		'noVideo'
		'noPSR'
	)
	# Add no switches
	ForEach($noSwich in $noSwichForServerCore){
		If(!($global:BoundParameters.ContainsKey($noSwich))){
			$global:BoundParameters.Add($noSwich,$True)
		}
	}
}

# Initialize $global:ParameterArray again as parameters have been updated until reaching here.
[String[]]$global:ParameterArray = $Null
ForEach($Key in $global:BoundParameters.Keys){
	$global:ParameterArray += $Key
}

# Create variables for no switches. These are basically referred from POD modules
ForEach($noSwitch in $noOptionsList){
	Remove-Variable $noSwitch -ErrorAction Ignore
	If($global:ParameterArray -contains $noSwitch){
		Set-Variable -Name $noSwitch -Scope Global -Value $True -ErrorAction Ignore	#we# replaced New-Variable with Set-Variable, as they can already exist in tss_config.cfg
	}Else{
		Set-Variable -Name $noSwitch -Scope Global -Value $False -ErrorAction Ignore
	}
}

# We have all no parameters in $global:ParameterArray and $global:BoundParameters at this point. Now start removing switches corresponding to the noSwitch.
$noSwitchesForRecording = @('PSR', 'Video')
ForEach($noCommandSwitch in $noOptionsList){
	#write-host "____checking $noCommandSwitch"
	If($global:ParameterArray -contains $noCommandSwitch){
		$CommandParameter = $noCommandSwitch -replace '^no',''
		If($global:ParameterArray -contains $CommandParameter){
			If(!$Status) {LogInfoFile "Removing -$CommandParameter from parameters as -$noCommandSwitch is specified." -ShowMsg}
			$global:ParameterArray = RemoveItemFromArray $global:ParameterArray $CommandParameter
			$global:BoundParameters.Remove($CommandParameter) | Out-Null
		}ElseIf($StartAutoLogger.IsPresent -or $noCommandSwitch -eq 'noRecording'){
			ForEach($noSwitchForRecording in $noSwitchesForRecording){
				If($global:BoundParameters.ContainsKey($noSwitchForRecording)){
					If(!$Status) {LogInfoFile "Removing -$noSwitchForRecording from parameters as -noRecording is specified." -ShowMsg}
					$global:ParameterArray = RemoveItemFromArray $global:ParameterArray $noSwitchForRecording
					$global:BoundParameters.Remove($noSwitchForRecording) | Out-Null
				}
			}
		}
	} 
}

# Issue#567 remove -NetshScenario for -noNetsh
If(($global:BoundParameters.ContainsKey('NetshScenario')) -and ($global:ParameterArray -contains 'noNetsh')){
	If(!$Status) {LogInfoFile "Removing -NetshScenario from parameters as -noNetsh is specified." -ShowMsg}
	$global:BoundParameters.Remove('NetshScenario') | Out-Null
	$global:BoundParameters.Remove('NetshOptions') | Out-Null
}
	
If((IsStart) -or $Stop.IsPresent){
	#LogInfo "TSS will run with below parameters."
	ForEach($Parameter in $global:ParameterArray){
		$ParameterString = $ParameterString + ' ' + $Parameter
	}
	LogInfoFile "Working on Parameters:$ParameterString" -ShowMsg
}

If($global:ParameterArray -notcontains 'noPrereqC'){
	PreRequisiteCheckInStage2
}Else{
	LogInfoFile "Skipping PreRequisiteCheckInStage2() as -noPrereqC was specified." "Gray" -ShowMsg
}

If((IsStart) -or $Stop.IsPresent -or ![string]::IsNullOrEmpty($CollectLog) -or ![string]::IsNullOrEmpty($StartDiag)){
	If(($PSVersionTable.PSVersion.Major -le 4) -or ($global:OSBuild -le 9600)){ # PowerShell 4.0 / #we# Get-TimeZone fails on Srv2012R2 with PS v5.0 
		$TimeZone = [System.TimeZoneInfo]::Local.DisplayName
	}Else{
		$TimeZone = (Get-TimeZone).DisplayName
	}
	$SessionID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
	LogInfoFile "___globals -Mode: $Global:Mode -Mini: $Global:Mini -beta: $Global:beta -noPrereqC: $Global:noPrereqC -noRestart: $Global:noRestart -noClearCache: $Global:noClearCache"
	LogInfoFile "$global:ScriptPrefix Version $global:TssVerDate /_ADS: $global:TssVerDateADS /_CON: $global:TssVerDateCON /_CRM: $global:TssVerDateCRM /_DND: $global:TssVerDateDND /_INT: $global:TssVerDateINT /_NET: $global:TssVerDateNET /_PRF: $global:TssVerDatePRF /_SEC: $global:TssVerDateSEC /_SHA: $global:TssVerDateSHA /_SPS: $global:TssVerDateSPS /_UEX: $global:TssVerDateUEX / _MSRD: $Script:VerDate_MSRD" 
	$OSVersionReg = Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows NT\CurrentVersion'
	If($OSBuild -gt 9600){
		$Global:OS_Version= "$($OSVersionReg.CurrentMajorVersionNumber)" + "." + "$($OSVersionReg.CurrentMinorVersionNumber)" + "." + "$($OSVersionReg.CurrentBuildNumber)" + "." + "$($OSVersionReg.UBR)"
	}Else{
		$Global:OS_Version= "$($OSVersionReg.CurrentVersion)" + "." + "$($OSVersionReg.CurrentBuild)"
	}
	LogInfoFile "OS Version:        $Global:OS_Version"
	LogInfoFile "OS Architecture:   $Global:ProcArch"
	$global:ProductType = FwGetProductTypeFromReg
	LogInfoFile "ProductType:       $global:ProductType / IsServerCore: $global:IsServerCore"
	LogInfoFile "OS Culture:        $((Get-Culture).name) [ UI Culture: $((Get-UICulture).name) ]"
	LogInfoFile "TimeUTC:           $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss")) [TZ: $TimeZone]"
	LogInfoFile "Computer:          $ENV:COMPUTERNAME - User: $ENV:USERNAME - Domain: $env:USERDNSDOMAIN - Session: $SessionID"
	LogInfoFile "PATH:              $Env:PATH"
	Get-ExecutionPolicy -list | Out-File -FilePath $global:ErrorLogFile -Append
}

# In case of -discard, remove previous folders and keep only lastest folder
If($global:ParameterArray -contains 'Discard'){
	$LogFoldersAndFiles = Get-Childitem (Split-Path -parent $global:LogFolder) | Sort-Object -Property LastWriteTime -Descending
	If($LogFoldersAndFiles.Count -gt 1){
		LogInfo "Removing previous log folders below."
		For($i=1;$i -lt $LogFoldersAndFiles.Count;$i++){
			LogInfo "  - $($LogFoldersAndFiles[$i].FullName)"
			Remove-Item -Path $LogFoldersAndFiles[$i].FullName -Recurse -Force -ErrorAction Ignore
		}
	}
}

Try{
	Switch($global:ParameterArray[0]){
		'start'{
			If($CreateBatFile.IsPresent){
				ProcessCreateBatFile
			}Else{
				ProcessStart
			}
		}
		'StartAutoLogger'{
			If($CreateBatFile.IsPresent){
				ProcessCreateBatFile
			}Else{
			   ProcessStart
			}
		}
		'StartDiag'{
			ProcessStartDiag
		}
		'stop'{
			ProcessStop
		}
		'RemoveAutoLogger'{
			RemoveAutoLogger
		}
		'set'{
			ProcessSet
		}
		'unset'{
			ProcessUnset
		}
		'help'{
			ProcessHelp
			#ProcessList $Help
		}
		'TraceInfo'{
			ProcessTraceInfo
		}
		'Find'{
			ProcessFindKeyword
		}
		'ListETWProviders'{
			ProcessListETWProviders
		}
		'FindGUID'{
			ProcessFindGUID
		}
		'status'{
			ProcessStatus
		}
		'CollectLog'{
			ProcessCollectLog
		}
		'CollectEventLog'{
			ProcessCollectEventLog
			CompressLogIfNeededAndShow
		}
		'List'{
			ProcessList
		}
		'ListSupportedTrace'{
			ProcessListSupportedTrace
		}
		'ListSupportedLog'{
			ProcessListSupportedLog
		}
		'ListSupportedNetshScenario'{
			ProcessListSupportedNetshScenario
		}
		'ListSupportedPerfCounter'{
			ProcessListSupportedPerfCounter
		}
		'ListSupportedCommands'{
			ProcessListSupportedCommands
		}
		'ListSupportedControls'{
			ProcessListSupportedControls
		}
		'ListSupportedNoOptions'{
			ProcessListSupportedNoOptions
		}
		'ListSupportedDiag'{
			ProcessListSupportedDiag
		}
		'ListSupportedScenarioTrace'{
			ProcessListSupportedScenarioTrace
		}
		'ListSupportedWPRScenario'{
			ProcessListSupportedWPRScenario
		}
		'ListSupportedXperfProfile'{
			ProcessListSupportedXperfProfile
		}
		'ListSupportedSDP'{
			ProcessListSupportedSDP
		}
		'Version'{
			# Check online and Display only Version, then exit
			CheckVersion($global:TssVerDate)
			Write-Host -ForegroundColor Cyan "$global:ScriptPrefix Script Version:   $global:TssVerDate"
			Write-Host -ForegroundColor Cyan " - Version _ADS.psm1: $global:TssVerDateADS - ver Auth: $global:TssVerDateAuth"
			Write-Host -ForegroundColor Cyan " - V _Container.psm1: $global:TssVerDateCON"
			Write-Host -ForegroundColor Cyan " - Version _CRM.psm1: $global:TssVerDateCRM"
			Write-Host -ForegroundColor Cyan " - Version _DND.psm1: $global:TssVerDateDND"
			Write-Host -ForegroundColor Cyan " - Version _INT.psm1: $global:TssVerDateINT"
			Write-Host -ForegroundColor Cyan " - Version _NET.psm1: $global:TssVerDateNET"
			Write-Host -ForegroundColor Cyan " - Version _PRF.psm1: $global:TssVerDatePRF"
			Write-Host -ForegroundColor Cyan " - Version _SEC.psm1: $global:TssVerDateSEC"
			Write-Host -ForegroundColor Cyan " - Version _SHA.psm1: $global:TssVerDateSHA"
			Write-Host -ForegroundColor Cyan " - V_Sharepoint.psm1: $global:TssVerDateSPS"
			Write-Host -ForegroundColor Cyan " - Version _UEX.psm1: $global:TssVerDateUEX - ver MSRD: $Script:VerDate_MSRD"
		}
		'update'{
			CheckVersion($global:TssVerDate)
			# Update current TSS package, then exit
			if ($Script:fUpToDate -eq $False) { UpdateTSS }
		}
		'SDP'{
			ProcessSDP
		}
		'xray'{
			Processxray
		}
		default{
			ProcessStart
		}
	}
}Catch{
	LogException "Exception happened." $_
}Finally{ 
	# Usually we reach here when user stops the script with Ctrl + C
	CleanUpandExit 
}

Write-Host ' '
CleanUpandExit
#endregion ### MAIN



# SIG # Begin signature block
# MIInwgYJKoZIhvcNAQcCoIInszCCJ68CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAx1T/GWRb3lI2M
# JMiSjgE++LKhZ1+wFvC84mHnqlQpQaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGaIwghmeAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHG93SsdAeCSURM9RSdljLZK
# bLPHx5rIJYXIcZJ5gOerMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAwh7FQLgVI8lPNR2LDhZOOtXJPYTK4RIZiNzdfit5rufdJQHgplMYQYMd
# 5nlYWTHCvmIC4QEmhTMW6pekN+orVkhQW2YB+/jYuRaSnW7Y9EGv9s9Srg9dQblX
# +0EmWixa8En5OlZVzFC54R1+hgIq6GdGc/Yqgq8rAlRDYwRB4mpoOrmr1LKhue9f
# vJDyWnNo1s02aVX8tO7KymEJdNAyclDuUAT0PgzndVGIILP0/1xUxtQ3bhD8H/w5
# fk1DN2W1NdydK3OYdMqMuIzRKYeAZ0iSIMFpD6HmHh9OjRjmlA4OSYp7TPykSsge
# VYdpBT3LnQJ+bbtnku15X9tl8JsTdaGCFywwghcoBgorBgEEAYI3AwMBMYIXGDCC
# FxQGCSqGSIb3DQEHAqCCFwUwghcBAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDYvLtc79+kTEoOFYvGSnj6SIGAyBPTnSuzCtQNHYmTZQIGZGzwcILA
# GBMyMDIzMDYyMDE0MzA1MC4wNTVaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjJBRDQtNEI5Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIRezCCBycwggUPoAMCAQICEzMAAAGxypBD7gvwA6sAAQAAAbEwDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIw
# OTIwMjAyMTU5WhcNMjMxMjE0MjAyMTU5WjCB0jELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoyQUQ0LTRC
# OTItRkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIaiqz7V7BvH7IOMPEeDM2Uw
# CpM8LxAUPeJ7Uvu9q0RiDBdBgshC/SDre3/YJBqGpn27a7XWOMviiBUfMNff51Nx
# KFoSX62Gpq36YLRZk2hN1wigrCO656z5pVTjJp3Q8jdYAJX3ruJea3ccfTgxAgT3
# Uv/sP4w0+yZAYa2JZalV3MBgIFi3VwKFA4ClQcr+V4SpGzqz8faqabmYypuJ35Zn
# 8G/201pAN2jDEOu7QaDC0rGyDdwSTVmXcHM46EFV6N2F69nwfj2DZh74gnA1DB7N
# FcZn+4v1kqQWn7AzBJ+lmOxvKrURlV/u19Mw1YP+zVQyzKn5/4r/vuYSRj/thZr+
# FmZAUtTAacLzouBENuaSBuOY1k330eMp8nndSNUsUjj/nn7gcdFqzdQNudJb+Xxm
# Rwi9LwjA0/8PlOsKTZ8Xw6EEWPVLfNojSuWpZMTaMzz/wzSPp5J02kpYmkdl50lw
# yGRLO5X7iWINKmoXySdQmRdiGMTkvRStXKxIoEm/EJxCaI+k4S3+BWKWC07EV5T3
# UG7wbFb4LfvgbbaKM58HytAyjDnO9fEi0vrp8JFTtGhdtwhEEkraMtGVt+CvnG0Z
# lH4mvpPRPuJbqE509e6CqmHwzTuUZPFMFWvJn4fPv0d32Ws9jv2YYmE/0WR1fULs
# +TxxpWgn1z0PAOsxSZRPAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQU9Jtnke8NrYSK
# 9fFnoVE0pr0OOZMwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
# VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
# CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBANjnN5JqpeVShIrQ
# IaAQnNVOv1cDEmCkD6oQufX9NGOX28Jw/gdkGtMJyagA0lVbumwQla5LPhBm5LjI
# UW/5aYhzSlZ7lxeDykw57wp2AqoMAJm7bXcXtJt/HyaRlN35hAhBV+DmGnBIRcE5
# C2bSFFY3asD50KUSCPmKl/0NFadPeoNqbj5ZUna8VAfMSDsdxeyxjs8r/9Vpqy8l
# gIVBqRrXtFt6n1+GFpJ+2AjPspfPO7Y+Y/ozv5dTEYum5eDLDdD1thQmHkW8s0BB
# DbIOT3d+dWdPETkf50fM/nALkMEdvYo2gyiJrOSG0a9Z2S/6mbJBUrgrkgPp2HjL
# kycR4Nhwl67ehAhWxJGKD2gRk88T2KKXLiRHAoYTZVpHbgkYLspBLJs9C77ZkuxX
# uvIOGaId7EJCBOVRMJygtx8FXpoSu3jWEdau0WBMXxhVAzEHTu7UKW3Dw+KGgW7R
# Rlhrt589SK8lrPSvPM6PPnqEFf6PUsTVO0bOkzKnC3TOgui4JhlWliigtEtg1SlP
# MxcdMuc9uYdWSe1/2YWmr9ZrV1RuvpSSKvJLSYDlOf6aJrpnX7YKLMRoyKdzTkcv
# Xw1JZfikJeGJjfRs2cT2JIbiNEGK4i5srQbVCvgCvdYVEVZXVW1Iz/LJLK9XbIkM
# MjmECJEsa07oadKcO4ed9vY6YYBGMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAtcwggJAAgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxh
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoy
# QUQ0LTRCOTItRkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUA7WSxvqQDbA7vyy69Tn0wP5BGxyuggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOg7rhwwIhgPMjAyMzA2MjAxMjQ4MjhaGA8yMDIzMDYyMTEyNDgyOFowdzA9Bgor
# BgEEAYRZCgQBMS8wLTAKAgUA6DuuHAIBADAKAgEAAgIgCgIB/zAHAgEAAgJmqzAK
# AgUA6Dz/nAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
# AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBACujrRvIm0yqLArq
# 6OijDq3+yvH1HWEVuF0yfOIrYbEaisHCb/MRfQoTD5MR3dgwrrfExusYTmYcUVu7
# TaMDLY7RQ2zGMgPlOy0NkCcIkQkGqjOTP47sUDxQ96v05WoVsyS3UTUC7VozayRa
# 4b/pDah+J7ZmLa8YCpcYM2hZhHmQMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAGxypBD7gvwA6sAAQAAAbEwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgrbkRWFHL023v/zFwJnXyqpH6aaGboltuFrqNfGiQC1YwgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCCD7Q2LFFvfqeDoy9gpu35t6dYerrDO0cMTlOIo
# mzTPbDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
# scqQQ+4L8AOrAAEAAAGxMCIEIMEKQtpDd2//E/D7ZvkZTd/tyjR4kGA8c6/zvVC5
# mUzXMA0GCSqGSIb3DQEBCwUABIICAFn3IlsHvtOqv0B9zePOHodQnYH/aQlnt5/H
# 5k3/KVpUQ03va4R9S1f/f5A6RMqNJhmzPjDSiFy4o8yPSfv3Rv0NEFMS6z/WHvbI
# GRwUsfsuyF/51SiBm+ZEeF7kGrmNI6hfxQk+J6Sg4AWyWRaV1SO1Z30hS0B6AqfQ
# 1R7QLtQSBbc4Yl4dpLN2PVS9JEpHSUHSb/vddf2cRSaiV/TSTOOrq29CyYszsnx6
# q0q8I6RkPWomzL6Af9k2r6rX8uPM2nOT4EUWiIOjWlyhRjPVwGYP9Ayu7/oux44s
# 3dBqxY/B10cHAmxizV6zBg5yoLZlpc1X8W+HMdVgryhDyMbLTZpvAAudNK+6NjGk
# p0pieJHC9OePuKkM1XwCY4J99ukc0icJ0vd/aM9NhwTvfH94LoGI7gHIf3++qsp9
# PzqKLw6yX5cAQ0u5ju9skQsxAQI8oGhigB55CKZGf5W73kKzwalwWzUu87Kg3uoy
# giGuYfRWiLMJ/+NuWM/4gtwXh4AsXNudjH/kRFGxG2r1sUbMovFWOKCscqvamKNp
# pF3xMHSO04niLwicJapEBUGEpE4r78KMcobvLObV2/5VcZmEYabQ3JOTAabsR0Q2
# vQaIz8xYy5jNKEIOuIhTbclw9oSBfkw9al1WZg/y1BiUMBDjX4va0SUYSTZUrVgm
# d8inLS85
# SIG # End signature block
