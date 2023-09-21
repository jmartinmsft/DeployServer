<#
// DeployServer-Step3.ps1
// Modified 21 September 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20230921.1341
//
// Script should automatically start when the virtual machine starts.
// Syntax for running this script:
//
// .\DeployServer-Step3.ps1
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


## Functions for DC configuration
Function CIDRToNetMask {
  [CmdletBinding()]
  Param(
    [ValidateRange(0,32)]
    [int16]$PrefixLength=0
  )
  $bitString=('1' * $PrefixLength).PadRight(32,'0')

  $strBuilder=New-Object -TypeName Text.StringBuilder

  for($i=0;$i -lt 32;$i+=8){
    $8bitString=$bitString.Substring($i,8)
    [void]$strBuilder.Append("$([Convert]::ToInt32($8bitString,2)).")
  }

  $strBuilder.ToString().TrimEnd('.')
}
Function ConvertIPv4ToInt {
  [CmdletBinding()]
  Param(
    [String]$IPv4Address
  )
  Try{
    $ipAddress=[IPAddress]::Parse($IPv4Address)

    $bytes=$ipAddress.GetAddressBytes()
    [Array]::Reverse($bytes)

    [System.BitConverter]::ToUInt32($bytes,0)
  }Catch{
    Write-Error -Exception $_.Exception `
      -Category $_.CategoryInfo.Category
  }
}
Function ConvertIntToIPv4 {
  [CmdletBinding()]
  Param(
    [uint32]$Integer
  )
  Try{
    $bytes=[System.BitConverter]::GetBytes($Integer)
    [Array]::Reverse($bytes)
    ([IPAddress]($bytes)).ToString()
  }Catch{
    Write-Error -Exception $_.Exception `
      -Category $_.CategoryInfo.Category
  }
}
Function GetIPv4Subnet {
  [CmdletBinding(DefaultParameterSetName='PrefixLength')]
  Param(
    [Parameter(Mandatory=$true,Position=0)]
    [IPAddress]$IPAddress,

    [Parameter(Position=1,ParameterSetName='PrefixLength')]
    [Int16]$PrefixLength=24    
  )
  Begin{}
  Process{
    Try{
      $SubnetMask=CIDRToNetMask -PrefixLength $PrefixLength -ErrorAction Stop
      $netMaskInt=ConvertIPv4ToInt -IPv4Address $SubnetMask     
      $ipInt=ConvertIPv4ToInt -IPv4Address $IPAddress
      $networkID=ConvertIntToIPv4 -Integer ($netMaskInt -band $ipInt)
      return $networkID
    }Catch{
      Write-Error -Exception $_.Exception `
        -Category $_.CategoryInfo.Category
    }
  }
  End{}
}
function CheckDCPromo {
    Test-ADDSDomainControllerInstallation -DomainName $domain -SafeModeAdministratorPassword $adSafeModePwd -InstallDns -ReplicationSourceDC $sourceDC | ForEach-Object {
        if($_ -match "failed") {
            return $false
        }
    }
    return $true
}
## Functions for Exchange configuration
function SyncAdConfigPartition {
    param(
        [string]$domainController,
        [string]$adDomain
    )
    ## Synchronize the Configuration partition of Active Directory across all replication partners
    Get-ADReplicationConnection -Filter *  -ErrorAction Ignore | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        [string]$configPartition = "CN=Configuration,$adDomain"
        $ScriptBlock = { Param ($param1,$param2,$param3) repadmin /replicate $param1 $param2 "$param3" /force }
        Invoke-Command  -ComputerName $domainController -ScriptBlock $scriptBlock -ArgumentList $toServer, $fromServer, $configPartition
    }
}
function SyncAdDirectoryPartition {
    param(
        [string]$domainController,
        [string]$adDomain
    )
    ## Synchronize the Configuration partition of Active Directory across all replication partners
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        $ScriptBlock = { Param ($param1,$param2,$param3) repadmin /replicate $param1 $param2 "$param3" /force }
        Invoke-Command  -ComputerName $domainController -ScriptBlock $scriptBlock -ArgumentList $toServer, $fromServer, $adDomain
    }
}
function SyncAdSchemaPartition {
    param(
        [string]$domainController,
        [string]$adDomain
    )
    ## Synchronize the Configuration partition of Active Directory across all replication partners
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        [string]$schemaPartition = "CN=Schema,CN=Configuration,$adDomain"
        $ScriptBlock = { Param ($param1,$param2,$param3) repadmin /replicate $param1 $param2 "$param3" /force }
        Invoke-Command  -ComputerName $domainController -ScriptBlock $scriptBlock -ArgumentList $toServer, $fromServer, $schemaPartition
    }    
}
function CheckSetupLog {
    if((Select-String -Path c:\ExchangeSetupLogs\ExchangeSetup.log -Pattern "The Exchange Server setup operation completed successfully.")) {
        return $false
    }
    return $true
}
function TestPendingReboot {
    ## https://docs.microsoft.com/en-us/previous-versions/office/exchange-server-analyzer/cc164360(v=exchg.80)?redirectedfrom=MSDN
    if((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Ignore).PendingFileRenameOperations) { return $true }
    [int]$regCheck = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Updates" -Name UpdateExeVolatile -ErrorAction Ignore
    if($regCheck -ne 0) { return $true }
    return $false
}
function RebootFailedSetup {
    ## Prepare Windows to automatically login after reboot and run the next step
    $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ExchangeSetup" -Force -ErrorAction Ignore | Out-Null
    Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step3.ps1 -ServerName ' + $ServerName)
    $WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $ExchangeInstall_LocalizedStrings.Username
    if($ExchangeInstall_LocalizedStrings.DomainPassword.Length -eq 0) {
        Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $UserCreds_LocalizedStrings.res_0001
    }
    else {
        Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $ExchangeInstall_LocalizedStrings.DomainPassword
    }
    Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
    Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "5" 
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ExchangeInstall_LocalizedStrings.Domain
    Restart-Computer -Force
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

Log([string]::Format("Running the Step3.ps1 script now.")) Gray
Log([string]::Format("Getting server name.")) Gray
## Get the server name from the registry
while($ServerName.Length -lt 1) {
    $ServerName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").VirtualMachineName
    if($null -eq $ServerName) { Start-Sleep -Seconds 5}
}

## Get variables from previous user input
Log([string]::Format("Getting variables for setup.")) Gray
Import-LocalizedData -BindingVariable ExchangeInstall_LocalizedStrings -FileName $ServerName"-ExchangeInstall-strings.psd1" -BaseDirectory C:\Temp
Import-LocalizedData -BindingVariable UserCreds_LocalizedStrings -FileName "Sysprep-strings.psd1" -BaseDirectory C:\Temp

## Set AutoLogon for the next step
Log([string]::Format("Preparing server for the next step.")) Gray
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
$WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "1" 

#Edge servers have the administrator password set to the workstation
if($ExchangeInstall_LocalizedStrings.EdgeRole -eq 1) {
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $UserCreds_LocalizedStrings.res_0000
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $UserCreds_LocalizedStrings.res_0001
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ServerName
}
else {
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $ExchangeInstall_LocalizedStrings.Username
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $ExchangeInstall_LocalizedStrings.DomainPassword
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ExchangeInstall_LocalizedStrings.Domain
}

if($ExchangeInstall_LocalizedStrings.EdgeRole -eq 0) {
## Verify that the domain can be resolved before continuing
Log([string]::Format("Verifying the domain can be resolved.")) Gray
$domain = $ExchangeInstall_LocalizedStrings.Domain
$serverReady = $false
while($serverReady -eq $false) {
    $domainController = (Resolve-DnsName $domain -Type SRV -Server $ExchangeInstall_LocalizedStrings.DomainController -ErrorAction Ignore).PrimaryServer
    if($domainController -like "*$domain") { $serverReady = $true }
    Start-Sleep -Seconds 5
}

## Get the distinguishedName for the domain
Log([string]::Format("Import the Active Directory PowerShell module.")) Gray
Import-Module ActiveDirectory
$adDomain = (Get-ADDomain -Server $domainController -ErrorAction Ignore).DistinguishedName
$exchContainer = "CN=Microsoft Exchange,CN=Services,CN=Configuration,$adDomain"
while($adDomain.Length -lt 1) {
    Import-Module ActiveDirectory    
    $adDomain = (Get-ADDomain -Server $domainController -ErrorAction Ignore).DistinguishedName ## The given key was not present in the dictionary
    Start-Sleep -Seconds 10
}
}
## Either install Exchange or promote to a domain controller
switch($ExchangeInstall_LocalizedStrings.ServerType) {
    0 {
        ## Check if server is pending a reboot before attempting to install Exchange
        Log([string]::Format("Checking if there is a pending reboot prior to installing Exchange.")) Gray
        if(TestPendingReboot) {
            RebootFailedSetup
        }
        Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step4.ps1 -ServerName ' + $ServerName)
        
        ## For greenfield deployments, wait for the first server to be ready
        if($ExchangeInstall_LocalizedStrings.ExchangeOrgMissing -eq 1 -and $ExchangeInstall_LocalizedStrings.ExchangeOrgName.Length -eq 0) {
            if($ExchangeInstall_LocalizedStrings.EdgeRole -eq 0) {
                Log([string]::Format("Waiting for Active Directory replication.")) Gray
                ## Synchronize Active Directory to ensure Exchange is not waiting on replication
                ForceADSync $domainController $adDomain
                Log([string]::Format("Verifying Exchange organization is ready for additional Exchange servers.")) Gray
                $servicesContainer = "CN=Services,CN=Configuration,$adDomain"
                $exchContainer = Get-ADObject -LDAPFilter "(objectClass=msExchConfigurationContainer)" -SearchBase $servicesContainer -SearchScope OneLevel -ErrorAction Ignore
                ## First we want to locate the Exchange container
                Log([string]::Format("Checking for the Exchange organization container.")) Gray
                while($exchContainer.Length -lt 1) {
                    try {
                        $exchContainer = Get-ADObject -Server $domainController -LDAPFilter "(objectClass=msExchConfigurationContainer)" -SearchBase $servicesContainer -SearchScope OneLevel -ErrorAction Ignore
                    }
                    catch {}
                    ForceADSync $domainController $adDomain
                    Start-Sleep -Seconds 15
                }
                $exchServer = Get-ADObject -LDAPFilter "(objectClass=msExchExchangeServer)" -SearchBase $exchContainer -SearchScope Subtree
                Log([string]::Format("Checking for an Exchange server.")) Gray
                ## Then we can look for the first server
                while($exchServer.Length -lt 1) {
                    try {
                        $exchServer = Get-ADObject -Server $domainController -LDAPFilter "(objectClass=msExchExchangeServer)" -SearchBase $exchContainer -SearchScope Subtree -ErrorAction Ignore
                    }
                    catch {}
                    Force-ADSync $domainController $adDomain
                    Start-Sleep -Seconds 30
                }
            }
        }

        if($ExchangeInstall_LocalizedStrings.EdgeRole -ne 1) {
            ## Confirm a DC exists in the site where Exchange is being installed
            $serverSite = (nltest /dsgetsite)[0]
            Log([string]::Format("Verifying a configuration domain controller is available in {0}.", $serverSite)) Gray
            $siteDC = Get-ADDomainController -Discover -SiteName $serverSite -ErrorAction Ignore
            while($siteDC.Length -lt 1) {
                Start-Sleep -Seconds 30
                $siteDC = Get-ADDomainController -Discover -SiteName $serverSite -ErrorAction Ignore
            }
            ## Check if the previous versions of Exchange are installed
            if($null -ne $ExchangeInstall_LocalizedStrings.ExchangeVersionCheck) {
                Log([string]::Format("Checking for previous versions of Exchange in the organization.")) Gray
                $exReady = $false
                ## Get the version of Exchange that must be present
                [int]$checkForVersion = $ExchangeInstall_LocalizedStrings.ExchangeVersionCheck
                while($exReady -eq $false) {
                    ## Get a list of Exchange servers
                    $exchServers = Get-ADObject -LDAPFilter "(&(objectClass=msExchExchangeServer)(serverRole=*))" -SearchBase $exchContainer -SearchScope Subtree -Properties serialNumber -ErrorAction Ignore
                    foreach($e in $exchServers) {
                        [int]$exVersion = $e.serialNumber.Substring(11,1)
                        ## Compare the Exchange server version
                        if($exVersion -eq $checkForVersion) {
                            $exReady = $true
                            break
                        }
                    }
                    Start-Sleep -Seconds 30
                }
            }
        }
        $setupSuccess = $false
        while($setupSuccess -eq $false) {
            ## Clearing any previous setup log
            $file = "C:\Temp\exSetup.bat"
            Remove-Item -Path c:\ExchangeSetupLogs\ExchangeSetup.log -Force -ErrorAction Ignore | Out-Null
            ## Reset setup command if failed
            (Get-Content $file) -replace "/IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF", "/IAcceptExchangeServerLicenseTerms" | Set-Content $file
            ## Update the setup command for September 2021 CU releases
            $setupCommand = (Select-String -Path $file -Pattern setup).Line
            $setupFile = $setupCommand.Substring(0, $setupCommand.IndexOf(" "))
            switch ($ExchangeInstall_LocalizedStrings.ExchangeVersion) { ## Checking the version of Exchange being installed
                1 { 
                    if((Get-Item $setupFile -ErrorAction Ignore).VersionInfo.ProductVersion -ge "15.01.2375.007") {
                        (Get-Content $file) -replace "/IAcceptExchangeServerLicenseTerms", "/IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF" | Set-Content $file
                    }
                }
                2 {
                    if((Get-Item $setupFile -ErrorAction Ignore).VersionInfo.ProductVersion -ge "15.02.0986.005") {
                        (Get-Content $file) -replace "/IAcceptExchangeServerLicenseTerms", "/IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF" | Set-Content $file
                    }
                }
            }
            ## Install Exchange
            Log([string]::Format("Starting Exchange installation. Check setup logs for additional information.")) Gray
            C:\Temp\exSetup.bat
            ## Check if setup failed
            if(CheckSetupLog) {
                Log([string]::Format("Exchange setup failed. Check setup logs for additional information.")) Red
                Log([string]::Format("Attempting to synchronize Active Directory.")) Gray
                Start-Sleep -Seconds 10
                $domainController = $ExchangeInstall_LocalizedStrings.DomainController
                $adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
                ForceADSync $domainController $adDomain
                RebootFailedSetup
            }
            else { $setupSuccess = $true }
        }
        ## Exchange setup complete
        Restart-Computer -Force
    }
    1 { ## Adding server as an additional domain controller
        Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Where-Object {$_.Profile -eq "Public" } | Set-NetFirewallRule -RemoteAddress Any
        $dnsSwitch = $false
        $dnsServers = (Get-NetIPConfiguration | Where-Object { $_.Ipv4DefaultGateway.NextHop -ne $null} -ErrorAction Ignore).DNSServer.ServerAddresses
        $dc = (Resolve-DnsName $domain -Type SRV -Server $dnsServers[0] -ErrorAction Ignore).PrimaryServer
        if($dc -notlike "*.$domain") { 
            Log([string]::Format("No valid server found for domain on primary DNS server.")) Yellow
            $dc = (Resolve-DnsName $domain -Type SRV -Server $dnsServers[1] -ErrorAction Ignore).PrimaryServer
            if($dc -like "*.$domain") {
                Log([string]::Format("Changing secondary DNS to primary DNS server.")) Yellow
                Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration | Where-Object {$_.Ipv4DefaultGateway.NextHop -ne $null} -ErrorAction Ignore).InterfaceIndex -ServerAddresses $dnsServers[1],$dnsServers[0] | Out-Null
                $dnsSwitch = $true
            }
            else {
                Log([string]::Format("Invalid DNS configuration settings.")) Yellow
                exit
            }
        }
        $ipSubnet = (GetIPv4Subnet -IPAddress $ExchangeInstall_LocalizedStrings.IpAddress -PrefixLength $ExchangeInstall_LocalizedStrings.SubnetMask)+"/"+$ExchangeInstall_LocalizedStrings.SubnetMask
        if(!(Get-ADReplicationSite -ErrorAction Ignore) -notmatch $ExchangeInstall_LocalizedStrings.AdSiteName) { #-and (Get-ADReplicationSite).Name -notmatch "Default-First-Site-Name" ) {
            ## Create a new AD site
            Log([string]::Format("Creating new AD Site called {0}.", $ExchangeInstall_LocalizedStrings.AdSiteName)) Gray
            New-ADReplicationSite -Name $ExchangeInstall_LocalizedStrings.AdSiteName -ErrorAction Ignore
            ## Create a new subnet and add the new site
            Log([string]::Format("Creating new AD subnet {0} for the AD site {1}.",$ipSubnet, $ExchangeInstall_LocalizedStrings.AdSiteName)) Gray
            New-ADReplicationSubnet -Name $ipSubnet -Site $ExchangeInstall_LocalizedStrings.AdSiteName -ErrorAction Ignore
            ## Add the new site to the replication site link
            Get-ADReplicationSiteLink -Filter * | Set-ADReplicationSiteLink -SitesIncluded @{Add=$ExchangeInstall_LocalizedStrings.AdSiteName}  -ErrorAction Ignore
        }
        [securestring]$adSafeModePwd = $ExchangeInstall_LocalizedStrings.AdSafeModePassword | ConvertTo-SecureString -AsPlainText -Force
        $dcReady = $false
        $sourceDC = $ExchangeInstall_LocalizedStrings.DomainController
        if($sourceDC -notlike "*$domain") {
            $sourceDC = $sourceDC+"."+$domain
        }
        Log([string]::Format("Checking if server is ready for dcpromo.")) Gray
        $dcReady = Check-DCPromo
        while($dcReady -eq $false) {
            Start-Sleep -Seconds 30
            $dcReady = CheckDCPromo
        }
        Log([string]::Format("Promoting this server to a domain controller.")) Gray
        $dcSuccess = $false
        while($dcSuccess -eq $false) {
            $dcInstall = (Install-ADDSDomainController -InstallDns -DomainName $domain -SafeModeAdministratorPassword $adSafeModePwd -SkipPreChecks -AllowDomainControllerReinstall -NoRebootOnCompletion -SiteName $ExchangeInstall_LocalizedStrings.AdSiteName -Confirm:$False)
            $installCheck = Select-String -InputObject $dcInstall -Pattern "The operation failed"
                if($installCheck -like "*The operation failed*" -or $installCheck -like "*Exception*") {
                    Log([string]::Format("DC promo failed for {0}.", $ServerName)) Yellow
                    Start-Sleep -Seconds 3
                    if($dnsSwitch) {
                        Log([string]::Format("Reverting DNS settings back to original configuration.")) Yellow
                        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration | Where-Object {$_.Ipv4DefaultGateway.NextHop -ne $null}).InterfaceIndex -ServerAddresses $dnsServers[0],$dnsServers[1] -ErrorAction Ignore | Out-Null
                    }
                    Start-Sleep -Seconds 60
                    RebootFailedSetup
                }
                else { 
                    $dcSuccess = $true 
                    if($dnsSwitch) {
                        Log([string]::Format("Reverting DNS settings back to original configuration.")) Yellow
                        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration | Where-Object {$_.Ipv4DefaultGateway.NextHop -ne $null}).InterfaceIndex -ServerAddresses $dnsServers[0],$dnsServers[1] -ErrorAction Ignore | Out-Null
                    }
                }
        }
        Restart-Computer
    }
    2 {
        ## Clean up the registry from the automatic login information
        Log([string]::Format("Removing auto-logon registry keys.")) Gray
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -Force | Out-Null
        Write-Host "COMPLETE"
     }
}
