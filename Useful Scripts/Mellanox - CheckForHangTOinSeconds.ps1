# Define the Registry key path
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"

# Get all subkeys that start with "000"
$subKeys = Get-ChildItem -Path $registryPath | Where-Object { $_.PSChildName -like "0*" }

# Loop through the subkeys
foreach ($subKey in $subKeys) {
    $regKeyValues = Get-ItemProperty -Path $subKey.PSPath

    # Check if the registry value "DriverDesc" contains "Mellanox"
    if ($regKeyValues.DriverDesc -like "*Mellanox*") {
        $checkForHangKeyPath = Join-Path -Path $subKey.PSPath -ChildPath "CheckForHangTOInSeconds"
        $checkForHangValue = 600

        # Create the Registry key "CheckForHangTOInSeconds" with the value 600
        New-ItemProperty -Path $subKey.PSPath -Name "CheckForHangTOInSeconds" -PropertyType DWORD -Value $checkForHangValue -Force

        Write-Host "Created CheckForHangTOInSeconds in $($subKey.PSChildName) with value $checkForHangValue"
    }
}
