set-executionpolicy bypass -scope Process -Force
$bio="C:\Windows\System32\WinBioDatabase\*.DAT"
Stop-Service WbioSrvc -force
clear-content -path $bio -Force
Start-Service WbioSrvc

$Shell = New-Object -ComObject "WScript.Shell"
$Button = $Shell.Popup("Database da Biometrica limpa com sucesso!",0)

exit