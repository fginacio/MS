set-executionpolicy bypass -scope Process -Force
$bio="C:\Windows\System32\WinBioDatabase\51F39552-1075-4199-B513-0C10EA185DB0.DAT"
$bio2="C:\Windows\System32\WinBioDatabase\74B2E1C4-B8A7-4B34-87B1-7388121B106C.DAT"
Stop-Service WbioSrvc -force
clear-content -path $bio -Force
clear-content -path $bio2 -Force
Start-Service WbioSrvc

$Shell = New-Object -ComObject "WScript.Shell"
$Button = $Shell.Popup("Database da Biometrica limpa com sucesso!",0)

exit