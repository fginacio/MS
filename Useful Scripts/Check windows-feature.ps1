# Collect information about installed features on the server
$installedFeatures = Get-WindowsFeature | Where-Object { $_.Installed -eq $true }

# List of features you want to check
$featuresToCheck = @(
    "Failover-Clustering",
    "AD-Domain-Services",
    "Hyper-V",
    "Remote-Desktop-Services"
)

# Filter installed features that are in the check list
$installedFeaturesToCheck = $installedFeatures | Where-Object { $featuresToCheck -contains $_.Name }

# Extract only the names of features and place them in a single variable
$installedFeaturesNames = $installedFeaturesToCheck.DisplayName

# Display the result
$installedFeaturesNames
