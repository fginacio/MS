#check Hyper-v Replica Queue in a Cluster (checking replica broker) 

icm -ComputerName (Get-ClusterNode).Name -ScriptBlock {Get-VMReplication | ft Name,Health,AutoResynchronizeIntervalEnd,AutoResynchronizeIntervalStart,ReplicationFrequencySec,CurrentReplicaServerName,LastReplicationTime,ReplicationHealth,ReplicationState -autosize}