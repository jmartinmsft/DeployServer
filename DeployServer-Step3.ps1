#
# DeployServer-Step3.ps1
# Modified 2020/10/30
# Last Modifier:  Jim Martin
# Project Owner:  Jim Martin
# Version: v1.0

# Script should automatically start when the virtual machine starts.
# Syntax for running this script:
#
# .\DeployServer-Step3.ps1
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
Function Get-IPv4Subnet {
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
function Check-DCPromo {
    Test-ADDSDomainControllerInstallation -DomainName $domain -SafeModeAdministratorPassword $adSafeModePwd -InstallDns -ReplicationSourceDC $sourceDC | ForEach-Object {
        if($_ -match "failed") {
            return $false
        }
    }
    return $true
}
## Functions for Exchange configuration
function Force-ADSync {
    param(
        [string]$domainController,
        [string]$adDomain
    )
    $successfulSync = $false
    while($successfulSync -eq $false) {
        $syncResults = Sync-AdConfigPartition $domainController $adDomain
        $successfulSync = Check-SyncResults
        Start-Sleep -Seconds 5
    }
    $successfulSync = $false
    while($successfulSync -eq $false) {
        $syncResults = Sync-AdDirectoryPartition $domainController $adDomain
        $successfulSync = Check-SyncResults
        Start-Sleep -Seconds 5
    }
    $successfulSync = $false
    while($successfulSync -eq $false) {
        $syncResults = Sync-AdSchemaPartition $domainController $adDomain
        $successfulSync = Check-SyncResults
        Start-Sleep -Seconds 5
    }
}
function Sync-AdConfigPartition {
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
function Check-SyncResults {
    if($syncResults -ne $null) {
        foreach($s in $syncResults) {
            if($s -like "*to $fromDC*" -and $s -like "*completed successfully.") {
                return $true
            }
        }
    }
    else {return $true}
    return $false
}
function Sync-AdDirectoryPartition {
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
function Sync-AdSchemaPartition {
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
function Check-SetupLog {
    if((Select-String -Path c:\ExchangeSetupLogs\ExchangeSetup.log -Pattern "The Exchange Server setup operation completed successfully.")) {
        return $false
    }
    return $true
}
function Test-PendingReboot {
    ## https://docs.microsoft.com/en-us/previous-versions/office/exchange-server-analyzer/cc164360(v=exchg.80)?redirectedfrom=MSDN
    if((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Ignore).PendingFileRenameOperations) { return $true }
    [int]$regCheck = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Updates" -Name UpdateExeVolatile -ErrorAction Ignore
    if($regCheck -ne 0) { return $true }
    return $false
}
function Reboot-FailedSetup {
    ## Prepare Windows to automatically login after reboot and run the next step
    $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ExchangeSetup" -Force -ErrorAction Ignore | Out-Null
    Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step3.ps1 -ServerName ' + $ServerName)
    $WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $ExchangeInstall_LocalizedStrings.res_0013
    if($ExchangeInstall_LocalizedStrings.res_0012.Length -eq 0) {
        Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $UserCreds_LocalizedStrings.res_0001
    }
    else {
        Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $ExchangeInstall_LocalizedStrings.res_0012
    }
    Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
    Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "5" 
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ExchangeInstall_LocalizedStrings.res_0014
    Restart-Computer
}
Start-Transcript -Path C:\Temp\DeployServer-Log.txt -Append -NoClobber | Out-Null
Write-Host "Running the Step3.ps1 script now..." -ForegroundColor Yellow
Write-Host "Getting server name..." -ForegroundColor Green -NoNewline
## Get the server name from the registry
while($ServerName.Length -lt 1) {
    $ServerName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").VirtualMachineName
    if($ServerName -eq $null) { Start-Sleep -Seconds 5}
}
Write-Host "COMPLETE"
## Get variables from previous user input
Write-Host "Getting variables for setup..." -ForegroundColor Green -NoNewline
Import-LocalizedData -BindingVariable ExchangeInstall_LocalizedStrings -FileName $ServerName"-ExchangeInstall-strings.psd1" -BaseDirectory C:\Temp
Import-LocalizedData -BindingVariable UserCreds_LocalizedStrings -FileName "Sysprep-strings.psd1" -BaseDirectory C:\Temp
Write-Host "COMPLETE"
## Set AutoLogon for the next step
Write-Host "Preparing server for the next step..." -ForegroundColor Green -NoNewline
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
$WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "5" 
Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $ExchangeInstall_LocalizedStrings.res_0013
Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ExchangeInstall_LocalizedStrings.res_0014
if($ExchangeInstall_LocalizedStrings.res_0012.Length -eq 0) {
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $UserCreds_LocalizedStrings.res_0001
}
else {
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $ExchangeInstall_LocalizedStrings.res_0012
}
Write-Host "COMPLETE"
## Verify that the domain can be resolved before continuing
Write-Host "Verifying the domain can be resolved..." -ForegroundColor Green -NoNewline
$domain = $ExchangeInstall_LocalizedStrings.res_0014
$serverReady = $false
while($serverReady -eq $false) {
    $domainController = (Resolve-DnsName $domain -Type SRV -Server $ExchangeInstall_LocalizedStrings.res_0031 -ErrorAction Ignore).PrimaryServer
    if($domainController -like "*$domain") { $serverReady = $true }
    Start-Sleep -Seconds 5
}
Write-Host "COMPLETE"
## Get the distinguishedName for the domain
Write-Host "Import the Active Directory PowerShell module..." -ForegroundColor Green
Import-Module ActiveDirectory
$adDomain = (Get-ADDomain -Server $domainController -ErrorAction Ignore).DistinguishedName
$exchContainer = "CN=Microsoft Exchange,CN=Services,CN=Configuration,$adDomain"
while($adDomain.Length -lt 1) {
    Import-Module ActiveDirectory    
    $adDomain = (Get-ADDomain -Server $domainController -ErrorAction Ignore).DistinguishedName ## The given key was not present in the dictionary
    Start-Sleep -Seconds 10
}
## Either install Exchange or promote to a domain controller
switch($ExchangeInstall_LocalizedStrings.res_0099) {
    0 { ## Check if server is pending a reboot before attempting to install Exchange
        Write-Host "Checking if there is a pending reboot prior to installing Exchange..." -ForegroundColor Green -NoNewline
        if(Test-PendingReboot) {
            Reboot-FailedSetup
        }
        Write-Host "COMPLETE"
        Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step4.ps1')
        ## For greenfield deployments, wait for the first server to be ready
        if($ExchangeInstall_LocalizedStrings.res_0028 -eq 1 -and $ExchangeInstall_LocalizedStrings.res_0029.Length -eq 0) {
            Write-Host "Waiting for Active Directory replication..." -ForegroundColor Green -NoNewline
            ## Synchronize Active Directory to ensure Exchange is not waiting on replication
            Force-ADSync $domainController $adDomain
            Write-Host "COMPLETE"
            Write-Host "Verifying Exchange organization is ready for additional Exchange servers..." -ForegroundColor Green
            $servicesContainer = "CN=Services,CN=Configuration,$adDomain"
            $exchContainer = Get-ADObject -LDAPFilter "(objectClass=msExchConfigurationContainer)" -SearchBase $servicesContainer -SearchScope OneLevel -ErrorAction Ignore
            ## First we want to locate the Exchange container
            Write-Host "Checking for the Exchange organization container..." -ForegroundColor Green -NoNewline
            while($exchContainer.Length -lt 1) {
                try {$exchContainer = Get-ADObject -Server $domainController -LDAPFilter "(objectClass=msExchConfigurationContainer)" -SearchBase $servicesContainer -SearchScope OneLevel -ErrorAction Ignore}
                catch {Write-Host "..." -ForegroundColor Green -NoNewline }
                Force-ADSync $domainController $adDomain
                Start-Sleep -Seconds 15
            }
            Write-Host "COMPLETE"
            #$exchContainer = "CN=Microsoft Exchange,CN=Services,CN=Configuration,$adDomain"
            $exchServer = Get-ADObject -LDAPFilter "(objectClass=msExchExchangeServer)" -SearchBase $exchContainer -SearchScope Subtree
            Write-Host "Checking for an Exchange server..." -ForegroundColor Green -NoNewline
            ## Then we can look for the first server
            while($exchServer.Length -lt 1) {
                try {$exchServer = Get-ADObject -Server $domainController -LDAPFilter "(objectClass=msExchExchangeServer)" -SearchBase $exchContainer -SearchScope Subtree -ErrorAction Ignore}
                catch { Write-Host "..." -ForegroundColor Green -NoNewline }
                Force-ADSync $domainController $adDomain
                Start-Sleep -Seconds 30
            }
            Write-Host "COMPLETE"
        }
        ## Confirm a DC exists in the site where Exchange is being installed
        $serverSite = (nltest /dsgetsite)[0]
        Write-Host "Verifying a configuration domain controller is available in $serverSite..." -ForegroundColor Green -NoNewline
        $siteDC = Get-ADDomainController -Discover -SiteName $serverSite -ErrorAction Ignore
        while($siteDC.Length -lt 1) {
            Write-Host "..." -ForegroundColor Green -NoNewline
            Start-Sleep -Seconds 30
            $siteDC = Get-ADDomainController -Discover -SiteName $serverSite -ErrorAction Ignore
        }
        Write-Host "COMPLETE"
        ## Check if the previous versions of Exchange are installed
        if($ExchangeInstall_LocalizedStrings.res_0034 -ne $null) {
            Write-Host "Checking for previous versions of Exchange in the organization..." -ForegroundColor Green -NoNewline
            $exReady = $false
            ## Get the version of Exchange that must be present
            [int]$checkForVersion = $ExchangeInstall_LocalizedStrings.res_0034
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
                Write-Host "..." -ForegroundColor Green -NoNewline
            }
            Write-Host "COMPLETE"
        }
        $setupSuccess = $false
        while($setupSuccess -eq $false) {
            ## Clearing any previous setup log
            Remove-Item -Path c:\ExchangeSetupLogs\ExchangeSetup.log -Force -ErrorAction Ignore | Out-Null
            ## Install Exchange
            C:\Temp\exSetup.bat
            ## Check if setup failed
            if(Check-SetupLog) {
                Write-Warning "Exchange setup failed"
                Write-Host "Attempting to synchronize Active Directory..." -ForegroundColor Green
                Start-Sleep -Seconds 10
                $domainController = $ExchangeInstall_LocalizedStrings.res_0031
                $adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
                Force-ADSync $domainController $adDomain
                Reboot-FailedSetup
            }
            else { $setupSuccess = $true }
        }
        ## Exchange setup complete
        Restart-Computer -Force
    }
    1 { ## Adding server as an additional domain controller
        Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Where {$_.Profile -eq "Public" } | Set-NetFirewallRule -RemoteAddress Any
        $domainFound = $false
        $dnsSwitch = $false
        $dnsServers = (Get-NetIPConfiguration | Where { $_.Ipv4DefaultGateway.NextHop -ne $null} -ErrorAction Ignore).DNSServer.ServerAddresses
        $dc = (Resolve-DnsName $domain -Type SRV -Server $dnsServers[0] -ErrorAction Ignore).PrimaryServer
        if($dc -notlike "*.$domain") { 
            Write-Warning "No valid server found for domain on primary DNS server."
            $dc = (Resolve-DnsName $domain -Type SRV -Server $dnsServers[1] -ErrorAction Ignore).PrimaryServer
            if($dc -like "*.$domain") {
                Write-Warning "Changing secondary DNS to primary DNS server."
                Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration | Where {$_.Ipv4DefaultGateway.NextHop -ne $null} -ErrorAction Ignore).InterfaceIndex -ServerAddresses $dnsServers[1],$dnsServers[0] | Out-Null
                $dnsSwitch = $true
            }
            else {
                Write-Warning "Invalid DNS configuration settings"
                exit
            }
        }
        $ipSubnet = (Get-IPv4Subnet -IPAddress $ExchangeInstall_LocalizedStrings.res_0007 -PrefixLength $ExchangeInstall_LocalizedStrings.res_0008)+"/"+$ExchangeInstall_LocalizedStrings.res_0008
        if(!(Get-ADReplicationSite -ErrorAction Ignore) -notmatch $ExchangeInstall_LocalizedStrings.res_0106) { #-and (Get-ADReplicationSite).Name -notmatch "Default-First-Site-Name" ) {
            ## Create a new AD site
            Write-Host "Creating new AD Site called $ExchangeInstall_LocalizedStrings.res_0106..." -ForegroundColor Green -NoNewline
            New-ADReplicationSite -Name $ExchangeInstall_LocalizedStrings.res_0106 -ErrorAction Ignore
            Write-Host "COMPLETE"
            ## Create a new subnet and add the new site
            Write-Host "Creating a new subnet for the AD site..." -ForegroundColor Green -NoNewline
            New-ADReplicationSubnet -Name $ipSubnet -Site $ExchangeInstall_LocalizedStrings.res_0106 -ErrorAction Ignore
            Write-Host "COMPLETE"
            ## Add the new site to the replication site link
            Get-ADReplicationSiteLink -Filter * | Set-ADReplicationSiteLink -SitesIncluded @{Add=$ExchangeInstall_LocalizedStrings.res_0106}  -ErrorAction Ignore
        }
        [securestring]$adSafeModePwd = $ExchangeInstall_LocalizedStrings.res_0105 | ConvertTo-SecureString -AsPlainText -Force
        $dcReady = $false
        $sourceDC = $ExchangeInstall_LocalizedStrings.res_0031
        if($sourceDC -notlike "*$domain") {
            $sourceDC = $sourceDC+"."+$domain
        }
        Write-Host "Checking if server is ready for dcpromo..." -ForegroundColor Green -NoNewline
        $dcReady = Check-DCPromo
        while($dcReady -eq $false) {
            Write-Host "..." -ForegroundColor Green -NoNewline
            Start-Sleep -Seconds 30
            $dcReady = Check-DCPromo
        }
        Write-Host "Promoting this server to a domain controller..." -ForegroundColor Green -NoNewline
        $dcSuccess = $false
        while($dcSuccess -eq $false) {
            $dcInstall = (Install-ADDSDomainController -InstallDns -DomainName $domain -SafeModeAdministratorPassword $adSafeModePwd -SkipPreChecks -AllowDomainControllerReinstall -NoRebootOnCompletion -SiteName $ExchangeInstall_LocalizedStrings.res_0106 -Confirm:$False)
            $installCheck = Select-String -InputObject $dcInstall -Pattern "The operation failed"
                if($installCheck -like "*The operation failed*" -or $installCheck -like "*Exception*") {
                    Write-Warning "DC promo failed for $ServerName"
                    Start-Sleep -Seconds 3
                    if($dnsSwitch) {
                        Write-Warning "Reverting DNS settings back to original configuration."
                        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration | Where {$_.Ipv4DefaultGateway.NextHop -ne $null}).InterfaceIndex -ServerAddresses $dnsServers[0],$dnsServers[1] -ErrorAction Ignore | Out-Null
                    }
                    Start-Sleep -Seconds 60
                    Reboot-FailedSetup
                }
                else { 
                    $dcSuccess = $true 
                    if($dnsSwitch) {
                        Write-Warning "Reverting DNS settings back to original configuration."
                        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration | Where {$_.Ipv4DefaultGateway.NextHop -ne $null}).InterfaceIndex -ServerAddresses $dnsServers[0],$dnsServers[1] -ErrorAction Ignore | Out-Null
                    }
                }
        }
        Restart-Computer
    }
}
