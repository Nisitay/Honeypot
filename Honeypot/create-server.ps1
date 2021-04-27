# Install the Windows feature for IIS Management, if it isn't downloaded already
$FeatureName = 'IIS-ManagementConsole'
if ((Get-WindowsOptionalFeature -FeatureName $FeatureName -Online).State -eq "Disabled") {
		Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All
    }

# Import administration module
Import-Module WebAdministration

# Create a new FTP site
$FTPSiteName = 'Automated FTP Site'
$FTPSitePath = "IIS:\Sites\$FTPSiteName"
$BasicAuth = 'ftpServer.security.authentication.anonymousAuthentication.enabled'
Set-ItemProperty -Path $FTPSitePath -Name $BasicAuth -Value $True

# Add read/write authorization rules for all users.
$Param = @{
    Filter   = "/system.ftpServer/security/authorization"
    Value    = @{
        accessType  = "Allow"
        roles       = ""
        permissions = "Read,Write"
        users       = "Anonymous Users"
    }
    PSPath   = 'IIS:\'
    Location = $FTPSiteName
}
Add-WebConfiguration @param

# Change the SSL policy to allow SSL connections.
$SSLPolicy = @(
    'ftpServer.security.ssl.controlChannelPolicy',
    'ftpServer.security.ssl.dataChannelPolicy'
)
Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[0] -Value $false
Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[1] -Value $false