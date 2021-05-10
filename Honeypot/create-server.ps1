# Install the Windows feature for IIS Management, if it isn't downloaded already
$FeatureName = 'IIS-ManagementConsole'
if ((Get-WindowsOptionalFeature -FeatureName $FeatureName -Online).State -eq "Disabled") {
		Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All
    }

# Import administration module
Import-Module WebAdministration

# Set new FTP site parameters
$FTPSiteName = 'FTP Site'
$FTPPort = 21

# Create FTP root directory if doesn't exist already
$FTPRootDir = $PSScriptRoot + "\FTP-Folder"
if (!(Test-Path $FTPRootDir -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $FTPRootDir
}

# Add access rules to folder, for IUSR users
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\IUSR", "Write, ReadAndExecute, Synchronize", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl = Get-ACL $FTPRootDir
$acl.AddAccessRule($accessRule)
Set-ACL -Path $FTPRootDir -ACLObject $acl

# Create the new FTP site
New-WebFtpSite -Name $FTPSiteName -Port $FTPPort -PhysicalPath $FTPRootDir

# Add anonymous authentication
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
        users       = "?"
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