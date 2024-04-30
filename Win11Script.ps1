# It is a good idea to create a System Restore point before you run the script.
# Finding out which line broke your machine is going to be tricky.
# You can also run the script in sequences manually the first few times, reboot, test your software and connectivity,
# proceed with the next sequence - this helps with troubleshooting.

# Enable System Restore for C: drive
#Enable-ComputerRestore -Drive "C:\"

# Configure the amount of storage space used for system restore
#vssadmin resize shadowstorage /on=C: /for=C: /maxsize=5000MB

# Modify the frequency of system restore point creation
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 20

# Create a System Restore point
#Checkpoint-Computer -Description "BeforeSecurityHardening" -RestorePointType "MODIFY_SETTINGS"
# Enlarge Windows Event Security Log Size
function Set-LogSize {
    param(
        [string]$LogName,
        [int]$Size
    )
    wevtutil sl $LogName /ms:$Size
    Write-Host "Set maximum size for $LogName log to $Size bytes."
}

# Set sizes for various logs
Set-LogSize -LogName "Security" -Size 1025000
Set-LogSize -LogName "Application" -Size 1024000
Set-LogSize -LogName "System" -Size 1024000
Set-LogSize -LogName "Windows PowerShell" -Size 1024000
Set-LogSize -LogName "Microsoft-Windows-PowerShell/Operational" -Size 1024000
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [int]$Data,
        [string]$Type = "DWORD"
    )

    # Ensure the path exists
    if (-Not (Test-Path $Path)) {
        New-Item -Path $Path -Force
        Write-Host "Registry path created: $Path"
    }

    # Check if the value exists and is set correctly
    $currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($currentValue -eq $null -or $currentValue.$Name -ne $Data) {
        # Update or add the value
        Set-ItemProperty -Path $Path -Name $Name -Value $Data -Type $Type -Force
        Write-Host "Set $Name to $Data at $Path"
    } else {
        Write-Host "$Name is already set to $Data at $Path"
    }
}

# Configuration entries for registry
$entries = @(
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\Explorer"; Name="NoAutoplayfornonVolume"; Data=1},
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Data=1},
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Data=255},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Data=0},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowBasic"; Data=0},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowBasic"; Data=0},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\GameDVR"; Name="AllowGameDVR"; Data=0},
    @{Path="HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds"; Name="DisableEnclosureDownload"; Data=1},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\Windows Search"; Name="AllowIndexingEncryptedStoresOrItems"; Data=0},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowUnencryptedTraffic"; Data=0},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"; Name="AllowUnencryptedTraffic"; Data=0},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"; Name="DisableRunAs"; Data=1},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"; Name="AllowDigest"; Data=0},
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Data=1},
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableVirtualization"; Data=1},
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Data=2},
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="SaveZoneInformation"; Data=2},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\Explorer"; Name="NoDataExecutionPrevention"; Data=0},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\Explorer"; Name="NoHeapTerminationOnCorruption"; Data=0},
    @{Path="HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config"; Name="AutoConnectAllowedOEM"; Data=0},
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"; Name="fMinimizeConnections"; Data=1},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableIPSourceRouting"; Data=2},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableICMPRedirect"; Data=0},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name="DisableIPSourceRouting"; Data=2},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Data=0},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name="RestrictNullSessAccess"; Data=1},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Data=5},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"; Name="NoNameReleaseOnDemand"; Data=1}
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenSlideshow"; Data=1},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name="UseLogonCredential"; Data=0},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; Name="ProcessCreationIncludeCmdLine_Enabled"; Data=1},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"; Name="ScreenSaveTimeOut"; Data="900"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LegalNoticeText"; Data="Your legal notice text here."; Type="String"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DisableLockScreenAppNotifications"; Data=1},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"; Name="DODownloadMode"; Data=0},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="MSAOptional"; Data=1},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name="DisableInventory"; Data=1},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsConsumerFeatures"; Data=1},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout"; Name="MaxDenials"; Data=3},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout"; Name="ResetTime"; Data=15},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Password Policy"; Name="PasswordHistorySize"; Data=24},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name="EnableTranscripting"; Data=1}
)

# Apply registry configuration
foreach ($entry in $entries) {
    Set-RegistryValue @entry
}
#:: Enable Windows Event Detailed Logging
#:: This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
#:: For more extensive Windows logging, I recommend https://www.malwarearchaeology.com/cheat-sheets
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
Auditpol /set /subcategory:"PNP Activity" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
Auditpol /set /subcategory:"Group Membership" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable


Write-Host "All configurations and audit policies have been applied successfully."
