<#
// DeployServer-Step1.ps1
// Modified 22 November 2024
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20241122.1428
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
param
(
[Parameter(Mandatory=$false)]   [string]$LogFile="C:\Temp\DeployServer.log",
[Parameter(Mandatory=$false)]   [string]$ServerName
)

$script:ScriptVersion = "v20230921.1341"

function LogToFile([string]$Details) {
	if ( [String]::IsNullOrEmpty($LogFile) ) { return }
	"$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToLongTimeString())   $Details" | Out-File $LogFile -Append
}

function Log([string]$Details, [ConsoleColor]$Colour) {
    if ($Colour -notlike $null)
    {
        $Colour = [ConsoleColor]::White
    }
    Write-Host $Details -ForegroundColor $Colour
    LogToFile $Details
}

function LogVerbose([string]$Details) {
    Write-Verbose $Details
    LogToFile $Details
}
LogVerbose "$($MyInvocation.MyCommand.Name) version $($script:ScriptVersion) starting"

function LogDebug([string]$Details) {
    Write-Debug $Details
    LogToFile $Details
}

$script:LastError = $Error[0]
function ErrorReported($Context) {
    # Check for any error, and return the result ($true means a new error has been detected)

    # We check for errors using $Error variable, as try...catch isn't reliable when remoting
    if ([String]::IsNullOrEmpty($Error[0])) { return } #$false }

    # We have an error, have we already reported it?
    if ($Error[0] -eq $script:LastError) { return  } #$false }

    # New error, so log it and return $true
    $script:LastError = $Error[0]
    if ($Context)
    {
        Log "Error ($Context): $($Error[0])" Red
    }
    else
    {
        Log "Error: $($Error[0])" Red
    }
    return #$true
}

function ReportError($Context) {
    # Reports error without returning the result
    ErrorReported $Context | Out-Null
}

function CheckServerCore {
    if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\').InstallationType -eq "Server Core") {return $true}
    return $false
}
function CheckExchangeVersion ($Message=”Please mount the Exchange ISO and then press any key to continue...”) {
    ## Verify the proper Exchange ISO version is mounte
    Log([string]::Format("Please mount the Exchange ISO and then press any key to continue.")) Yellow
    #Write-Host -NoNewLine $Message -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey(“NoEcho,IncludeKeyDown”)
    Write-Host “”
    return (Get-Item -Path $exInstallPath\Setup.exe).VersionInfo.FileVersion
}

#region Dislaimer
$ScriptDisclaimer = @"
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
"@
Write-Host $ScriptDisclaimer -ForegroundColor Yellow
#endregion

Log([string]::Format("Running the Step1 script now.")) Yellow
Log([string]::Format("Getting server name.")) Gray
## Get the server name from the registry
while($ServerName.Length -lt 1) {
    $ServerName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").VirtualMachineName
    if($null -eq $ServerName) { Start-Sleep -Seconds 5}
}

## Get variables from previous user input
Log([string]::Format("Getting variables for setup.")) Gray
Import-LocalizedData -BindingVariable UserCreds_LocalizedStrings -FileName "Sysprep-strings.psd1"
Import-LocalizedData -BindingVariable ExchangeInstall_LocalizedStrings -FileName $ServerName"-ExchangeInstall-strings.psd1"
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
Log([string]::Format("Preparing server for the next step by adding AutoAdminLogon registry keys.")) Gray
Set-ItemProperty -Path $RunOnceKey -Name "JoinDomain" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step2.ps1 -ServerName ' + $ServerName)
Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ServerName
Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $UserCreds_LocalizedStrings.res_0000
Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $UserCreds_LocalizedStrings.res_0001
## Check if ipV6 should be disabled
if($ExchangeInstall_LocalizedStrings.IpV6 -eq 0) {
    Log([string]::Format("Disabling IPv6.")) Gray
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ -Name DisabledComponents -Value "0xff" -PropertyType DWORD -ErrorAction SilentlyContinue | Out-Null
}
## Assign the IP address to the server and DNS servers
## Check if DHCP was selected
Log([string]::Format("Assigning IP address.")) Gray
if($ExchangeInstall_LocalizedStrings.EnableDhcp -eq 1) { 
    $interface = Get-NetIPInterface | Where-Object { $_.ConnectionState -eq "Connected" -and $_.AddressFamily -eq "IPv4"  -and $_.InterfaceAlias -notlike "*Loopback*"}
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

## Enable Remote Desktop
Log([string]::Format("Enabling remote desktop on the server.")) Gray
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

## Disable IE Enhance Security Configuration
if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\').InstallationType -ne "Server Core") {
    Log([string]::Format("Disabling IE enhanced security configuration.")) Gray
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
}

$domainController = $ExchangeInstall_LocalizedStrings.DomainController
## Install ADDS if the server is a domain controller
switch ($ExchangeInstall_LocalizedStrings.ServerType) {
#if($ExchangeInstall_LocalizedStrings.ServerType -eq 1)
    1 {
        Log([string]::Format("Installing the ADDS Windows feature for the domain controller.")) Gray
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    }
    0 {
        if($ExchangeInstall_LocalizedStrings.ExchangeInstallType -eq 1) {
            ## First we need to bring the additional disks online
            Log([string]::Format("Bringing additional disk online.")) Gray
            Get-Disk | Where-Object { $_.OperationalStatus -eq "Offline" } | ForEach-Object {
                Set-Disk -Number $_.Number -IsReadOnly:$False
                Set-Disk -Number $_.Number -IsOffline:$False
            }
            ## Then we can reassign the mount points
            if(Get-Item -Path "C:\Temp\$ServerName-DiskInfo.csv" -ErrorAction Ignore) {
                $diskVolumes = Import-Csv "C:\Temp\$ServerName-DiskInfo.csv"
                foreach($d in $diskVolumes) { 
                    $diskPartition = Get-Partition -DiskNumber $d.DiskNumber -PartitionNumber $d.PartitionNumber
                    New-Item -Path $d.AccessPaths -ItemType Directory -ErrorAction Ignore | Out-Null
                    Log([string]::Format("Assigning the mount point {0}.", $d.AccessPaths)) Gray
                    $diskPartition | Add-PartitionAccessPath -AccessPath $d.AccessPaths -ErrorAction Ignore | Out-Null
                }
            }
        }
        ## Get the CD rom path
        Log([string]::Format("Verifying the Exchange ISO is mounted.")) Gray
        $exInstallPath = (Get-WMIObject -Class Win32_CDROMDrive).Drive
        ## Verify that ISO is mounted
        while((!(Test-Path $exInstallPath\setup.exe))) {
            CheckExchangeVersion
        }
        ## Verify the correct version of Exchange
        $exResult = $ExchangeInstall_LocalizedStrings.ExchangeVersion
        $exVersion = (Get-Item -Path $exInstallPath\Setup.exe).VersionInfo.FileVersion
        switch ($exResult) {
            2 { while($exVersion -notlike "*15.02*") { $exVersion = CheckExchangeVersion } }
            1 { while($exVersion -notlike "*15.01*") { $exVersion = CheckExchangeVersion } }
            0 { while($exVersion -notlike "*15.00*") { $exVersion = CheckExchangeVersion } }
        }
        ## Create batch file for the Exchange install
        Log([string]::Format("Creating the Exchange setup script.")) Gray
        $installBat = "c:\Temp\exSetup.bat"
        New-Item $installBat -ItemType File -ErrorAction SilentlyContinue | Out-Null
        switch ($ExchangeInstall_LocalizedStrings.ExchangeInstallType) { ## Checking whether is install is new or recover
            0 { 
                switch ($exResult) { ## Checking the version of Exchange to install
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
                if($ExchangeInstall_LocalizedStrings.ExchangeOrgMissing -eq 1 -and $null -ne $ExchangeInstall_LocalizedStrings.ExchangeOrgName) {
                    $exSetupLine = $exSetupLine + " /OrganizationName:" + $ExchangeInstall_LocalizedStrings.ExchangeOrgName
                }
                Add-Content -Path $installBat -Value $exSetupLine
            }
            1 { Add-Content -Path $installBat -Value ($exInstallPath + '\setup.exe /mode:recoverserver /IAcceptExchangeServerLicenseTerms') } ## Exchange recover server
        }
    
        ## Check for and install Windows prequisite roles and features
        Log([string]::Format("Installing required Windows features for Exchange.")) Gray    
        #switch($ExchangeInstall_LocalizedStrings.ExchangeRole) {
        if($ExchangeInstall_LocalizedStrings.EdgeRole -ne 1) {
            switch ($ExchangeInstall_LocalizedStrings.ExchangeVersion) { 
                ## Checking the version of Exchange
                0 { 
                    Install-WindowsFeature Server-Media-Foundation, Failover-Clustering,RSAT-ADDS,NET-Framework-45-Features, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation
                }
                1 {            
                    Install-WindowsFeature Server-Media-Foundation, Failover-Clustering,RSAT-ADDS,NET-Framework-45-Core, NET-Framework-45-ASPNET, NET-WCF-HTTP-Activation45, NET-WCF-Pipe-Activation45, NET-WCF-TCP-Activation45, NET-WCF-TCP-PortSharing45, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation
                }
                2 {
                    if(CheckServerCore) {
                        Install-WindowsFeature Server-Media-Foundation, Failover-Clustering,RSAT-ADDS,NET-Framework-45-Core, NET-Framework-45-ASPNET, NET-WCF-HTTP-Activation45, NET-WCF-Pipe-Activation45, NET-WCF-TCP-Activation45, NET-WCF-TCP-PortSharing45, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Metabase, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI
                    }
                    else {
                        if(([System.Environment]::OSVersion.Version).Major -eq 10) {
                            Install-WindowsFeature Server-Media-Foundation, Failover-Clustering,RSAT-ADDS,NET-Framework-45-Core, NET-Framework-45-ASPNET, NET-WCF-HTTP-Activation45, NET-WCF-Pipe-Activation45, NET-WCF-TCP-Activation45, NET-WCF-TCP-PortSharing45, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation    
                        }
                        else {
                            Install-WindowsFeature Server-Media-Foundation, Failover-Clustering,RSAT-ADDS,NET-Framework-45-Core, NET-Framework-45-ASPNET, NET-WCF-HTTP-Activation45, NET-WCF-Pipe-Activation45, NET-WCF-TCP-Activation45, NET-WCF-TCP-PortSharing45, RPC-over-HTTP-proxy, RSAT-Clustering, RSAT-Clustering-CmdInterface, RSAT-Clustering-Mgmt, RSAT-Clustering-PowerShell, WAS-Process-Model, Web-Asp-Net45, Web-Basic-Auth, Web-Client-Auth, Web-Digest-Auth, Web-Dir-Browsing, Web-Dyn-Compression, Web-Http-Errors, Web-Http-Logging, Web-Http-Redirect, Web-Http-Tracing, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Lgcy-Mgmt-Console, Web-Metabase, Web-Mgmt-Console, Web-Mgmt-Service, Web-Net-Ext45, Web-Request-Monitor, Web-Server, Web-Stat-Compression, Web-Static-Content, Web-Windows-Auth, Web-WMI, Windows-Identity-Foundation
                        }
                    }
                }
            }
        }   
        else {
            Install-WindowsFeature ADLDS
        }
    }
}
## Rename the server
Log([string]::Format("Renaming the computer account to {0}.", $ServerName)) Yellow
Rename-Computer -NewName $ServerName -Restart