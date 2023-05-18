Clear

ForEach ($computer in Get-Content -path "C:\Users\t3122026\Desktop\idracs.txt" ) {
	Write-host "Testing iDrac connectivity " $computer


if (Test-Connection -ComputerName $computer -Quiet -Count 1) {
	Write-Host "Testing iDrac"
	$computer | Out-File -FilePath C:\Users\t3122026\Desktop\idracs_ok.txt -append -Encoding utf8
	Write-Host "iDrac OK!" -ForegroundColor Yellow -BackgroundColor DarkGreen
	Write-Host "Tests Completed!"
	Write-Host
	Write-Host
}

else {
	$computer | Out-File -FilePath C:\Users\t3122026\Desktop\idracs_BAD.txt -append -Encoding utf8
	Write-Host
	Write-Host "Warning: iDrac" $computer "not working! Next..." -ForegroundColor Red -BackgroundColor Yellow}
}