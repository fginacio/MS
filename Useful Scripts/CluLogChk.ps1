Clear-Host
$SDDCPath=Read-Host -Prompt "Path from cluster.log files"
#$SDDCPath="C:\temp"
<#function TextToHtml{
   $SourceFile = "$SDDCPath\output.log" 
   $TargetFile = "$SDDCPath\output.htm" 
   
   $File = Get-Content $SourceFile 
   $FileLine = @() 
   Foreach ($Line in $File) {  
    $MyObject = New-Object -TypeName PSObject  
    Add-Member -InputObject $MyObject -Type NoteProperty -Name HealthCheck -Value $Line  
    $FileLine += $MyObject 
   } 
   $FileLine | ConvertTo-Html -Property HealthCheck -body "<H2>Cluster Logs</H2>" | 
   Out-File $TargetFile
}
#>

#Change buffer width to make reader friendly
    $pshost = get-host
    $pswindow = $pshost.ui.rawui
    $newsize = $pswindow.buffersize
    $newsize.height = 30000
    $newsize.width = 10240
    $pswindow.buffersize = $newsize
    $newsize = $pswindow.windowsize


$ClusterLogFiles=Get-ChildItem -Path $SDDCPath -Filter "*_cluster.log" -Recurse -Depth 1        
        $SearchStringArray=@()  
		$SearchStringArray+="missed more than 40 percent of consecutive heartbeats" 		# Heartbeats are failing which network connectivity issues between nodes
        $SearchStringArray+="Missed 40% of the heart beats with node"               		# Heartbeats are failing which network connectivity issues between nodes
		$SearchStringArray+="Cluster has lost the UDP connection from local endpoint" 		# UDP port 3343 comunication is vital between nodes
		$SearchStringArray+="no longer accessible from this cluster nodes" 					# CSV Failures look like this
		$SearchStringArray+="Initiating DrainNode" 											# Node drain initiated
		$SearchStringArray+="Drain completed successfully. Executing worker." 				# Node drain completed
		$SearchStringArray+="Setting mode ReadOnly on disk" 								# Enabling Storage Maintenance Mode
		$SearchStringArray+="Reverting ReadOnly" 											# Disabling Storage Maintenance Mode
		$SearchStringArray+="Graceful shutdown reported by node" 							# Node shutdown
		$SearchStringArray+="Capture C:\Windows\Cluster\Reports\" 							# Cluster service failed
		$SearchStringArray+="was removed from the active failover cluster membership"		# Node removed due to network communication
        $SearchStringArray+="has entered a paused state because of 'STATUS"                 # CSV disconnect from node 
        $SearchStringArray+="Received notification for two-fifth consecutive missed HBs"    # 2/5 Missed HB
        $SearchStringArray+="got event: NetftTwoFifthMissedHeartbeats event"                # 2/5 Missed HB
        $SearchStringArray+="Lost connection to node"                                       # Node Lost Connection
        $SearchStringArray+="found at unsafe altitude"                                      # Unsafe Altitude
$i++ 
     Write-Progress -Activity "Checking $ClusterLogFiles.FullName" -Status "Percent Complete" -PercentComplete (($i / ($ClusterLogFiles.count) * 10)) 

ForEach($ClusterLogFiles in $ClusterLogFiles){
   Get-ChildItem -Path $ClusterLogFiles.FullName -PipelineVariable FN | Select-String -SimpleMatch $SearchStringArray | Select @{L="Fullname";E={$FN.name}},LineNumber,line | FT | Out-File -Append -FilePath $SDDCPath\output.log
        
}

<#TextToHtml
Clear-Host
Write-Host "Result available at  "
Write-Host "$SDDCPath\output.Log and "
Write-Host "$SDDCPath\output.Htm and "
#>
