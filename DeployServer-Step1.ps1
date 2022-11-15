<#
// DeployServer-Step1.ps1
// Modified 10 November 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20221110.1433
//
// Script should automatically start when the virtual machine starts.
// Syntax for running this script:
//
// .\DeployServer-Step1.ps1
//
//**********************************************************************​
//***********************************************************************
//
// Copyright (c) 2018 Microsoft Corporation. All rights reserved.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//**********************************************************************​
#>
Write-Host -ForegroundColor Yellow '//***********************************************************************'
Write-Host -ForegroundColor Yellow '//'
Write-Host -ForegroundColor Yellow '// Copyright (c) 2018 Microsoft Corporation. All rights reserved.'
Write-Host -ForegroundColor Yellow '//'
Write-Host -ForegroundColor Yellow '// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR'
Write-Host -ForegroundColor Yellow '// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,'
Write-Host -ForegroundColor Yellow '// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE'
Write-Host -ForegroundColor Yellow '// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER'
Write-Host -ForegroundColor Yellow '// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,'
Write-Host -ForegroundColor Yellow '// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN'
Write-Host -ForegroundColor Yellow '// THE SOFTWARE.'
Write-Host -ForegroundColor Yellow '//'
Write-Host -ForegroundColor Yellow '//**********************************************************************​'
Start-Sleep -Seconds 2
function Check-ServerCore {
    if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\').InstallationType -eq "Server Core") {return $true}
    return $false
}
function Set-IPConfig{
    ## Configure the static IP address information on the network adapter
    New-NetIPAddress -InterfaceIndex $interfaceIndexId -IPAddress $ExchangeInstall_LocalizedStrings.IpAddress -DefaultGateway $ExchangeInstall_LocalizedStrings.Gateway -PrefixLength $ExchangeInstall_LocalizedStrings.SubnetMask | Out-Null
    if($SecondaryDNS -eq 0) {
        Set-DnsClientServerAddress -InterfaceIndex $interfaceIndexId -ServerAddresses $ExchangeInstall_LocalizedStrings.PrimaryDns | Out-Null
    }
    else {
        Set-DnsClientServerAddress -InterfaceIndex $interfaceIndexId -ServerAddresses $ExchangeInstall_LocalizedStrings.PrimaryDns,$ExchangeInstall_LocalizedStrings.SecondaryDns | Out-Null
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
if($ExchangeInstall_LocalizedStrings.IpV6 -eq 0) {
    Write-Host "Disabling IPv6..." -ForegroundColor Green -NoNewline
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ -Name DisabledComponents -Value "0xff" -PropertyType DWORD -ErrorAction SilentlyContinue | Out-Null
    Write-Host "COMPLETE"
}
## Assign the IP address to the server and DNS servers
## Check if DHCP was selected
Write-Host "Assigning IP address..." -ForegroundColor Green -NoNewline
if($ExchangeInstall_LocalizedStrings.EnableDhcp -eq 1) { 
    $interface = Get-NetIPInterface | Where { $_.ConnectionState -eq "Connected" -and $_.AddressFamily -eq "IPv4"  -and $_.InterfaceAlias -notlike "*Loopback*"}
    $interface | Remove-NetRoute -AddressFamily IPv4 -Confirm:$False -ErrorAction Ignore
    $interface | Set-NetIPInterface -Dhcp Enabled

}
else {
    
    New-NetIPAddress -InterfaceIndex (Get-NetIPConfiguration).InterfaceIndex -IPAddress $ExchangeInstall_LocalizedStrings.IpAddress -DefaultGateway $ExchangeInstall_LocalizedStrings.Gateway -PrefixLength $ExchangeInstall_LocalizedStrings.SubnetMask | Out-Null
    if($ExchangeInstall_LocalizedStrings.SecondaryDns.Length -lt 1) {
        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration).InterfaceIndex -ServerAddresses $ExchangeInstall_LocalizedStrings.PrimaryDns | Out-Null
    }
    else {
        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration).InterfaceIndex -ServerAddresses $ExchangeInstall_LocalizedStrings.PrimaryDns,$ExchangeInstall_LocalizedStrings.SecondaryDns | Out-Null
        }
}
Write-Host "COMPLETE"
## Enable Remote Desktop
Write-Host "Enabling remote desktop on the server..." -ForegroundColor Green -NoNewline
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host "COMPLETE"
## Disable IE Enhance Security Configuration
if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\').InstallationType -ne "Server Core") {
    Write-Host "Disabling IE Enhanced security configuration..." -ForegroundColor Green -NoNewline
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
    Write-Host "COMPLETE"
}
$domainController = $ExchangeInstall_LocalizedStrings.DomainController
## Install ADDS if the server is a domain controller
if($ExchangeInstall_LocalizedStrings.ServerType -eq 1) {
    Write-Host "Installing the ADDS Windows feature..." -ForegroundColor Green -NoNewline
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    Write-Host "COMPLETE"
}
else {
    if($ExchangeInstall_LocalizedStrings.ExchangeInstallType -eq 1) {
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
    $exResult = $ExchangeInstall_LocalizedStrings.ExchangeVersion
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
    switch ($ExchangeInstall_LocalizedStrings.ExchangeInstallType) { ## Checking whether is install is new or recover
        0 { switch ($exResult) { ## Checking the version of Exchange to install
                2 { switch ($ExchangeInstall_LocalizedStrings.ExchangeRole) { ## Checking the roles to install for 2019
                        0 { $exSetupLine = ($exInstallPath + '\setup.exe /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms') }
                        1 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:et /IAcceptExchangeServerLicenseTerms') }
                    }
                }
                1 { switch ($ExchangeInstall_LocalizedStrings.ExchangeRole) { ## Checking the roles to install for 2016
                        0 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms') }
                        1 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:et /IAcceptExchangeServerLicenseTerms') }
                    }
                }
                0 { switch ($ExchangeInstall_LocalizedStrings.ExchangeRole) { ## Checking the roles to install for 2013
                        0 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:mb,ca /IAcceptExchangeServerLicenseTerms') }
                        1 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:mb /IAcceptExchangeServerLicenseTerms') }
                        2 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:ca /IAcceptExchangeServerLicenseTerms') }
                        3 { $exSetupLine =  ($exInstallPath + '\setup.exe /mode:install /roles:et /IAcceptExchangeServerLicenseTerms') }
                    }
                }
            }
            if($ExchangeInstall_LocalizedStrings.ExchangeOrgMissing -eq 1 -and $ExchangeInstall_LocalizedStrings.ExchangeOrgName -ne $null ) {
                $exSetupLine = $exSetupLine + " /OrganizationName:" + $ExchangeInstall_LocalizedStrings.ExchangeOrgName
            }
            Add-Content -Path $installBat -Value $exSetupLine
        }
        1 { Add-Content -Path $installBat -Value ($exInstallPath + '\setup.exe /mode:recoverserver /IAcceptExchangeServerLicenseTerms') } ## Exchange recover server
    }
    Write-Host "COMPLETE"
    ## Check for and install Windows prequisite roles and features
    Write-Host "Installing required Windows features for Exchange..." -ForegroundColor Green -NoNewline
    switch ($ExchangeInstall_LocalizedStrings.ExchangeVersion) { ## Checking the version of Exchange
        0 { Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, Failover-Clustering, RSAT-ADDS }
        1 { Install-WindowsFeature NET-Framework-45-Features, Server-Media-Foundation, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation, Failover-Clustering,RSAT-ADDS }
        2 { if(Check-ServerCore) {Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Metabase, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Failover-Clustering, RSAT-ADDS}
            else {Install-WindowsFeature Server-Media-Foundation, NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation,Failover-Clustering, RSAT-ADDS }}
    }
    Write-Host "COMPLETE"
}
## Rename the server
Write-Host "Renaming the computer account to $ServerName..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
Rename-Computer -NewName $ServerName -Restart
