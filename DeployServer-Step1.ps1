#
# DeployServer-Step1.ps1
# Modified 2020/10/30
# Last Modifier:  Jim Martin
# Project Owner:  Jim Martin
# Version: v1.0

# Script should automatically start when the virtual machine starts
# Syntax for running this script:
#
# .\DeployServer-Step1.ps1
#
#
##############################################################################################
#
# This script is not officially supported by Microsoft, use it at your own risk.
# Microsoft has no liability, obligations, warranty, or responsibility regarding
# any result produced by use of this file.
#
##############################################################################################
# The sample scripts are not supported under any Microsoft standard support
# program or service. The sample scripts are provided AS IS without warranty
# of any kind. Microsoft further disclaims all implied warranties including, without
# limitation, any implied warranties of merchantability or of fitness for a particular
# purpose. The entire risk arising out of the use or performance of the sample scripts
# and documentation remains with you. In no event shall Microsoft, its authors, or
# anyone else involved in the creation, production, or delivery of the scripts be liable
# for any damages whatsoever (including, without limitation, damages for loss of business
# profits, business interruption, loss of business information, or other pecuniary loss)
# arising out of the use of or inability to use the sample scripts or documentation,
# even if Microsoft has been advised of the possibility of such damages
##############################################################################################

function Set-IPConfig{
    ## Configure the static IP address information on the network adapter
    New-NetIPAddress -InterfaceIndex $interfaceIndexId -IPAddress $ExchangeInstall_LocalizedStrings.res_0007 -DefaultGateway $ExchangeInstall_LocalizedStrings.res_0009 -PrefixLength $ExchangeInstall_LocalizedStrings.res_0008 | Out-Null
    if($SecondaryDNS -eq 0) {
        Set-DnsClientServerAddress -InterfaceIndex $interfaceIndexId -ServerAddresses $ExchangeInstall_LocalizedStrings.res_0010 | Out-Null
    }
    else {
        Set-DnsClientServerAddress -InterfaceIndex $interfaceIndexId -ServerAddresses $ExchangeInstall_LocalizedStrings.res_0010,$ExchangeInstall_LocalizedStrings.res_0011 | Out-Null
    }
}
function Check-ExchangeVersion ($Message=”Please mount the Exchange ISO and then press any key to continue...”) {
    ## Verify the proper Exchange ISO version is mounte
    Write-Host -NoNewLine $Message -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey(“NoEcho,IncludeKeyDown”)
    Write-Host “”
    return (Get-Item -Path $exInstallPath\Setup.exe).VersionInfo.FileVersion
}
Start-Transcript -Path C:\Temp\DeployServer-Log.txt -Force | Out-Null
Write-Host "Running the Step1 script now..." -ForegroundColor Yellow
Write-Host "Getting server name..." -ForegroundColor Green -NoNewline
## Get the server name from the registry
while($ServerName.Length -lt 1) {
    $ServerName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").VirtualMachineName
    if($ServerName -eq $null) { Start-Sleep -Seconds 5}
}
Write-Host "COMPLETE"
## Get variables from previous user input
Write-Host "Getting variables for setup..." -ForegroundColor Green -NoNewline
Import-LocalizedData -BindingVariable UserCreds_LocalizedStrings -FileName "Sysprep-strings.psd1"
Import-LocalizedData -BindingVariable ExchangeInstall_LocalizedStrings -FileName $ServerName"-ExchangeInstall-strings.psd1"
Write-Host "COMPLETE"
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
$WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
## Verify that the variable file has been copied from the VM Host
if(!(Get-Item "C:\Temp\$ServerName-ExchangeInstall-strings.psd1")) {
    ## Prepare Windows to automatically login after reboot and run the next step
    (Get-Item $RunOnceKey).Property | ForEach-Object { Remove-ItemProperty -Name $_ -Path $RunOnceKey }
    Set-ItemProperty -Path $RunOnceKey -Name "StartSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\Start-Setup.ps1')
    Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
    Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "1" 
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $UserCreds_LocalizedStrings.res_0000
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $UserCreds_LocalizedStrings.res_0001
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ServerName
    Restart-Computer
}
## Set AutoLogon for the next step
Write-Host "Preparing server for the next step..." -ForegroundColor Green -NoNewline
Set-ItemProperty -Path $RunOnceKey -Name "JoinDomain" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step2.ps1 -ServerName ' + $ServerName)
Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ServerName
Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $UserCreds_LocalizedStrings.res_0000
Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $UserCreds_LocalizedStrings.res_0001
Write-Host "COMPLETE"
## Check if ipV6 should be disabled
if($ExchangeInstall_LocalizedStrings.res_0006 -eq 0) {
    Write-Host "Disabling IPv6..." -ForegroundColor Green -NoNewline
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ -Name DisabledComponents -Value "0xff" -PropertyType DWORD -ErrorAction SilentlyContinue | Out-Null
    Write-Host "COMPLETE"
}
## Assign the IP address to the server and DNS servers
## Check if DHCP was selected
Write-Host "Assigning IP address..." -ForegroundColor Green -NoNewline
if($ExchangeInstall_LocalizedStrings.res_0026 -eq 1) { 
    $interface = Get-NetIPInterface | Where { $_.ConnectionState -eq "Connected" -and $_.AddressFamily -eq "IPv4"  -and $_.InterfaceAlias -notlike "*Loopback*"}
    $interface | Remove-NetRoute -AddressFamily IPv4 -Confirm:$False -ErrorAction Ignore
    $interface | Set-NetIPInterface -Dhcp Enabled

}
else {
    
    New-NetIPAddress -InterfaceIndex (Get-NetIPConfiguration).InterfaceIndex -IPAddress $ExchangeInstall_LocalizedStrings.res_0007 -DefaultGateway $ExchangeInstall_LocalizedStrings.res_0009 -PrefixLength $ExchangeInstall_LocalizedStrings.res_0008 | Out-Null
    if($ExchangeInstall_LocalizedStrings.res_0011.Length -lt 1) {
        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration).InterfaceIndex -ServerAddresses $ExchangeInstall_LocalizedStrings.res_0010 | Out-Null
    }
    else {
        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration).InterfaceIndex -ServerAddresses $ExchangeInstall_LocalizedStrings.res_0010,$ExchangeInstall_LocalizedStrings.res_0011 | Out-Null
        }
}
Write-Host "COMPLETE"
## Enable Remote Desktop
Write-Host "Enabling remote desktop on the server..." -ForegroundColor Green -NoNewline
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host "COMPLETE"
## Disable IE Enhance Security Configuration
Write-Host "Disabling IE Enhanced security configuration..." -ForegroundColor Green -NoNewline
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
Write-Host "COMPLETE"
$domainController = $ExchangeInstall_LocalizedStrings.res_0031
## Install ADDS if the server is a domain controller
if($ExchangeInstall_LocalizedStrings.res_0099 -eq 1) {
    Write-Host "Installing the ADDS Windows feature..." -ForegroundColor Green -NoNewline
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    Write-Host "COMPLETE"
}
else {
    if($ExchangeInstall_LocalizedStrings.res_0004 -eq 1) {
        ## First we need to bring the additional disks online
        Get-Disk | Where { $_.OperationalStatus -eq "Offline" } | ForEach-Object {
            Set-Disk -Number $_.Number -IsReadOnly:$False
            Set-Disk -Number $_.Number -IsOffline:$False
        }
        ## Then we can reassign the mount points
        if(Get-Item -Path "C:\Temp\$ServerName-DiskInfo.csv" -ErrorAction Ignore) {
            $diskVolumes = Import-Csv "C:\Temp\$ServerName-DiskInfo.csv"
            foreach($d in $diskVolumes) { 
                $diskPartition = Get-Partition -DiskNumber $d.DiskNumber -PartitionNumber $d.PartitionNumber
                New-Item -Path $d.AccessPaths -ItemType Directory -ErrorAction Ignore | Out-Null
                $diskPartition | Add-PartitionAccessPath -AccessPath $d.AccessPaths -ErrorAction Ignore | Out-Null
            }
        }
    }
    ## Get the CD rom path
    Write-Host "Verifying the Exchange ISO is mounted..." -ForegroundColor Green
    $exInstallPath = (Get-WMIObject -Class Win32_CDROMDrive).Drive
    ## Verify that ISO is mounted
    while((!(Test-Path $exInstallPath\setup.exe))) {
        Check-ExchangeVersion
    }
    ## Verify the correct version of Exchange
    $exResult = $ExchangeInstall_LocalizedStrings.res_0003
    $exVersion = (Get-Item -Path $exInstallPath\Setup.exe).VersionInfo.FileVersion
    switch ($exResult) {
        2 { while($exVersion -notlike "*15.02*") { $exVersion = Check-ExchangeVersion } }
        1 { while($exVersion -notlike "*15.01*") { $exVersion = Check-ExchangeVersion } }
        0 { while($exVersion -notlike "*15.00*") { $exVersion = Check-ExchangeVersion } }
    }
    ## Create batch file for the Exchange install
    Write-Host "Creating the Exchange setup script..." -ForegroundColor Green -NoNewline
    $installBat = "c:\Temp\exSetup.bat"
    New-Item $installBat -ItemType File -ErrorAction SilentlyContinue | Out-Null
    switch ($ExchangeInstall_LocalizedStrings.res_0004) { ## Checking whether is install is new or recover
        0 { switch ($exResult) { ## Checking the version of Exchange to install
                2 { switch ($ExchangeInstall_LocalizedStrings.res_0005) { ## Checking the roles to install for 2019
                        0 { $exSetupLine = ($exInstallPath + '\setup.exe /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms') }
                        1 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:et /IAcceptExchangeServerLicenseTerms') }
                    }
                }
                1 { switch ($ExchangeInstall_LocalizedStrings.res_0005) { ## Checking the roles to install for 2016
                        0 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms') }
                        1 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:et /IAcceptExchangeServerLicenseTerms') }
                    }
                }
                0 { switch ($ExchangeInstall_LocalizedStrings.res_0005) { ## Checking the roles to install for 2013
                        0 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:mb,ca /IAcceptExchangeServerLicenseTerms') }
                        1 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms') }
                        2 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:ca /IAcceptExchangeServerLicenseTerms') }
                        3 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:et /IAcceptExchangeServerLicenseTerms') }
                    }
                }
            }
            if($ExchangeInstall_LocalizedStrings.res_0028 -eq 1 -and $ExchangeInstall_LocalizedStrings.res_0029 -ne $null ) {
                $exSetupLine = $exSetupLine + " /OrganizationName:" + $ExchangeInstall_LocalizedStrings.res_0029
            }
            Add-Content -Path $installBat -Value $exSetupLine
        }
        1 { Add-Content -Path $installBat -Value ($exInstallPath + '\setup.exe /mode:recoverserver /IAcceptExchangeServerLicenseTerms') } ## Exchange recover server
    }
    Write-Host "COMPLETE"
    ## Check for and install Windows prequisite roles and features
    Write-Host "Installing required Windows features for Exchange..." -ForegroundColor Green -NoNewline
    switch ($ExchangeInstall_LocalizedStrings.res_0003) { ## Checking the version of Exchange
        0 { Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, Failover-Clustering, RSAT-ADDS }
        1 { Install-WindowsFeature NET-Framework-45-Features, Server-Media-Foundation, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, Failover-Clustering,RSAT-ADDS }
        2 { Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation,Failover-Clustering, RSAT-ADDS }
    }
    Write-Host "COMPLETE"
}
## Rename the server
Write-Host "Renaming the computer account to $ServerName..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
Rename-Computer -NewName $ServerName -Restart