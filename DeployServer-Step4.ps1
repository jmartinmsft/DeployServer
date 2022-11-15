<#
// DeployServer-Step4.ps1
// Modified 15 November 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20221115.1611
//
// Script should automatically start when the virtual machine starts.
// Syntax for running this script:
//
// .\DeployServer-Step4.ps1
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
#region Disclaimer
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
#endregion
## Functions for Exchange configuration
function Enable-ExchangeExtendedProtection {
    if($ExchangeInstall_LocalizedStrings.ExchangeVersion -ne 0){
        Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Default Web Site/api"
        Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/api"
    }
    
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Default Web Site/ecp"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Allow -Location "Default Web Site/ews"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Allow -Location "Default Web Site/Microsoft-Server-ActiveSync"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Default Web Site/oab"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Default Web Site/Powershell"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Default Web Site/owa"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Default Web Site/rpc"  
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Default Web Site/mapi"

    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/ecp"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/ews"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/Microsoft-Server-ActiveSync"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/oab"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/Powershell"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/owa"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/rpc"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/RPCWithCert"  
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/mapi/emsmdb"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/mapi/nspi"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/PushNotifications"
}
function Install-ExchSU {
    switch($ExchangeInstall_LocalizedStrings.ExchangeVersion){
        0 {Install-Exch2013SU}
        1 {Install-Exch2016SU}
        2 {Install-Exch2019SU}
    }
}
function Install-Exch2013SU {
## Download and install Security Update for Exchange 2013
    Write-Host "Downloading Security Update for Exchange 2013 CU23..." -ForegroundColor Green 
    Invoke-WebRequest -Uri "https://download.microsoft.com/download/b/3/3/b33cf488-9f00-411f-8f08-beef7d219e81/Exchange2013-KB5019758-x64-en.exe" -OutFile "C:\Temp\Exchange2013-KB5019758-x64-en.exe" 
    Write-Host "Installing November 2022 Security Update for Exchange 2013 CU23..." -ForegroundColor Green -NoNewline
    Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2013-KB5019758-x64-en.exe /passive"
    Start-Sleep -Seconds 30
    while(Get-Process msiexec | where {$_.MainWindowTitle -eq "Security Update for Exchange Server 2013 Cumulative Update 23 (KB5019758)"} -ErrorAction SilentlyContinue) {
        Write-Host "..." -ForegroundColor Green -NoNewline
        Start-Sleep -Seconds 10
    }
    Write-Host "COMPLETE"
}
function Install-Exch2016SU{
## Download and install Security Update for Exchange 2016
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.01.2308*") {
        Write-Host "Downloading Security Update for Exchange 2016 CU22..." -ForegroundColor Green 
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/d/4/9/d4993639-8642-4461-a109-79d9ab46bc68/Exchange2016-KB5019758-x64-en.exe" -OutFile "C:\Temp\Exchange2016-KB5019758-x64-en.exe" 
    }
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.01.2507*") {
        Write-Host "Downloading Security Update for Exchange 2016 CU23..." -ForegroundColor Green
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/e/9/a/e9a07b3b-b440-44bb-8484-7ece339ffaf1/Exchange2016-KB5019758-x64-en.exe" -OutFile "C:\Temp\Exchange2016-KB5019758-x64-en.exe" 
    }
    if(Get-Item C:\Temp\Exchange2016-KB5019758-x64-en.exe -ErrorAction Ignore) {
        Write-Host "Installing November 2022 Security Update for Exchange 2016..." -ForegroundColor Green -NoNewline
        Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2016-KB5019758-x64-en.exe /passive"
        Start-Sleep -Seconds 30
        while(Get-Process msiexec | where {$_.MainWindowTitle -like "*KB5019758*"} -ErrorAction SilentlyContinue) {
            Write-Host "..." -ForegroundColor Green -NoNewline
            Start-Sleep -Seconds 10
        }
        Write-Host "COMPLETE"
    }
}
function Install-Exch2019SU{
## Download and install Security Update for Exchange 2019
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.02.0986*") {
        Write-Host "Downloading Security Update for Exchange 2019 CU11..." -ForegroundColor Green 
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/3/5/a/35a6ba9d-d36b-482c-8ca1-81ef2a6f05a3/Exchange2019-KB5019758-x64-en.exe" -OutFile "C:\Temp\Exchange2019-KB5019758-x64-en.exe" 
    }
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.02.1118*") {
        Write-Host "Downloading Security Update for Exchange 2019 CU12..." -ForegroundColor Green 
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/d/b/9/db9ee80e-9c18-40d8-91f9-f2353dcf4f86/Exchange2019-KB5019758-x64-en.exe" -OutFile "C:\Temp\Exchange2019-KB5019758-x64-en.exe" 
    }
    if(Get-Item C:\Temp\Exchange2019-KB5019758-x64-en.exe -ErrorAction Ignore) {
        Write-Host "Installing November 2022 Security Update for Exchange 2019..." -ForegroundColor Green -NoNewline
        Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2019-KB5019758-x64-en.exe /passive"
        Start-Sleep -Seconds 30
        while(Get-Process msiexec | where {$_.MainWindowTitle -like "*KB5019758*"} -ErrorAction SilentlyContinue) {
            Write-Host "..." -ForegroundColor Green -NoNewline
            Start-Sleep -Seconds 10
        }
        Write-Host "COMPLETE"
    }
}
function Sync-AD {
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        [string]$repPartition = "CN=Configuration,$adDomain"
        repadmin /replicate $toServer $fromServer $adDomain /force
        repadmin /replicate $toServer $fromServer $repPartition /force
        $repPartition = "CN=Schema,CN=Configuration,$adDomain"
        repadmin /replicate $toServer $fromServer $repPartition /force
        $repPartition = "DC=ForestDnsZones,$adDomain"
        repadmin /replicate $toServer $fromServer $repPartition /force
        $repPartition = "DC=DomainDnsZones,$adDomain"
        repadmin /replicate $toServer $fromServer $repPartition /force
    }
}
function Get-DomainControllers {
    ## Get one online domain controller for each site to confirm AD replication
    $sites = New-Object System.Collections.ArrayList
    $ADDomainControllers = New-Object System.Collections.ArrayList
    Get-ADDomainController -Filter * -ErrorAction Ignore | ForEach-Object {
        if($sites -notcontains $_.Site) {
            if(Test-Connection $_.HostName -Count 1 -ErrorAction Ignore) {
                $sites.Add($_.Site) | Out-Null
                $ADDomainControllers.Add($_.Hostname) |Out-Null
            }
        }
    }
    return ,$ADDomainControllers
}
function Prepare-DatabaseAvailabilityGroup {
    New-ADComputer -Name $dagName -AccountPassword (ConvertTo-SecureString -String "Pass@word1" -AsPlainText -Force) -Description 'Database Availability Group cluster name' -Enabled:$False -SamAccountName $dagName
    Set-ADComputer $dagName -add @{"msDS-SupportedEncryptionTypes"="28"}
    $adComputer = (Get-ADComputer $dagName).DistinguishedName
    $acl = get-acl "ad:$adComputer"
    $exchGroup = Get-ADGroup "Exchange Servers"
    $sid = [System.Security.Principal.SecurityIdentifier] $exchGroup.SID
    # Create a new access control entry to allow access to the OU
    $identity = [System.Security.Principal.IdentityReference] $SID
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
    $type = [System.Security.AccessControl.AccessControlType] "Allow"
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
    # Add the ACE to the ACL, then set the ACL to save the changes
    $acl.AddAccessRule($ace)
    Set-acl -aclobject $acl "ad:$adComputer"
}
function CheckAndAddRegistryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$RegistryPath
    )
    if(!(Get-Item -Path $RegistryPath -ErrorAction Ignore)) {
        $RegistryPath = $RegistryPath.Replace("HKLM:","HKEY_LOCAL_MACHINE")
        reg add $RegistryPath | Out-Null
    }
}
function CheckAndAddRegistryKey {
    param(
        [Parameter(Mandatory = $true)] [string]$RegistryPath,
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)] [string]$PropertyType
    )
    if(Get-ItemProperty -Path $RegistryPath -Name $Name -ErrorAction Ignore) {
        Set-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -Force
    }
    else {
        New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType $PropertyType | Out-Null
    }
}
function Check-FileShareWitness {
    ## Checking to see if the file share witness is a domain controller and
    ## Adding the Exchange Trusted Subsytem to the Administrators group to preven quorum failures
    $adDomain = (Get-ADDomain).DistinguishedName
    [string]$fsw = (Get-DatabaseAvailabilityGroup $DagName).WitnessServer
    if($fsw -like "*.*") {
        $fsw = $fsw.Substring(0, $fsw.IndexOf("."))
    }
    if((Get-ADObject -LDAPFilter "(&(name=*$fsw*)(objectClass=Computer))" -SearchBase $adDomain -SearchScope Subtree -Properties rIDSetReferences -ErrorAction Ignore).rIDSetReferences) {
            Write-Host "File share witness is a domain controller. Setup will add the Exchange Trusted Subsystem to the Administrators group." -ForegroundColor Yellow -BackgroundColor Black
            Add-ADGroupMember -Identity Administrators -Members "Exchange Trusted Subsystem" -Confirm:$False    
    }
}
function Sync-ADConfigPartition {
    ## Synchronize the Configuration container in Active Directory
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
    [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
    $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
    [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
    $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
    [string]$configPartition = "CN=Configuration,$adDomain"
    repadmin /replicate $fromServer $toServer $configPartition /force
    }
}
function Sync-ADDirectoryPartition {
    ## Synchronize the Configuration container in Active Directory
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
    [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
    $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
    [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
    $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
    #[string]$directoryPartition = ($_.ReplicateToDirectoryServer).Substring($_.ReplicateToDirectoryServer.IndexOf("CN=Configuration")+17)
    repadmin /replicate $fromServer $toServer $adDomain /force | Out-Null
    }
}
function Add-DatabaseCopies {
## Adding the database copies the Exchange server previously had configured
    param( [parameter(mandatory=$true)] [string]$readFile )
    $reader = New-Object System.IO.StreamReader($readFile)
    while(($currentLine = $reader.ReadLine()) -ne $null) {
        $db = $currentLine.Substring(0, $currentLine.IndexOf(","))
        $copyFound = $false
        while($copyFound -eq $false) {
            $currentLine = $currentLine.Substring($currentLine.IndexOf("[") + 1)
            $server = $currentLine.Substring(0, $currentLine.IndexOf(","))
            if($server -eq $ServerName) {
                $currentLine = $currentLine.Substring($currentLine.IndexOf(",")+2)
                $replayLagTime = $currentLine.Substring(0, $currentLine.IndexOf("]"))
                $copyFound = $true
                Write-Host "Adding database copy for $db with a replay lag time of $replayLagTime" -ForegroundColor Green -NoNewline
                Add-MailboxDatabaseCopy $db -MailboxServer $ServerName -ReplayLagTime $replayLagTime | Out-Null
                Write-Host "COMPLETE"
            }
        }
    }
}
function Set-ActivationPreferences {
## Resetting the activation preferences for the database copies
param( [parameter(mandatory=$true)] [string]$readFile )
    $reader = New-Object System.IO.StreamReader($readFile)
    while(($currentLine = $reader.ReadLine()) -ne $null) {
        $db = $currentLine.Substring(0, $currentLine.IndexOf(","))
        $currentLine = $currentLine.Substring($currentLine.IndexOf(",")+1)
        $endOfLine = $false
        while($endOfLine -eq $false) {
            $endChar = $currentLine.IndexOf(",")
            $server = $currentLine.Substring(1, $endChar-1)
            $currentLine = $currentLine.Substring($endChar+2)
            $prefNumber = $currentLine.Substring(0, $currentLine.IndexOf("]"))
            $copyName = $db + "\" + $server
            Write-Host "Setting $db on $server with an activation preference of $prefNumber..." -ForegroundColor Green
            Set-MailboxDatabaseCopy $copyName -ActivationPreference $prefNumber | Out-Null
            if($currentLine -notlike "*,*") {
                $endOfLine = $true
            }
            else {
                $currentLine = $currentLine.Substring($currentLine.IndexOf("["))
                $currentLine
            }
        }
    }
}
function Check-MSExchangeRepl {
    ## Check if the Microsoft Exchange Replication service is running
    if((Get-Service -ComputerName $ServerName MSExchangeRepl).Status -eq "Running") {
        return $true
    }
    else {
        ## Attempt to start the Microsoft Exchange Replication service
        Invoke-Command -ComputerName $ServerName -ScriptBlock { Start-Service MSExchangeRepl }
        return $false
    }
}

## Functions for DC configuration
function CIDRToNetMask {
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
function ConvertIPv4ToInt {
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
function ConvertIntToIPv4 {
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
function Get-IPv4Subnet {
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

function Set-PowerPlan {
    Write-Host "Checking the current performance plan..." -ForegroundColor Green -NoNewline
    $PowerPlan = (Get-CimInstance -Namespace root\cimv2\power -ClassName win32_PowerPlan -Filter "IsActive = 'True'").ElementName
    Write-Host $PowerPlan
    if($PowerPlan -ne "High performance") {
        Write-Host "Updating the performance plan..." -ForegroundColor Green -NoNewline
        try {
            powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
            Write-Host "COMPLETE"
        }
        catch {
            Write-Host "FAILED" -ForegroundColor Red
        }
    }
}
function Disable-SMB1 {
    Write-Host "Checking if SMB1 is enabled..." -ForegroundColor Green -NoNewline
    if((Get-WindowsFeature FS-SMB1).Installed) {
        Write-Host "TRUE"
        Write-Host "Disabling SMB1..." -ForegroundColor Green -NoNewline
        Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart | Out-Null
        Set-SmbServerConfiguration -EnableSMB1Protocol $False -Confirm:$False
        Write-Host "COMPLETE"
    }
}

Start-Transcript -Path C:\Temp\DeployServer-Log.txt -Append -NoClobber | Out-Null
Write-Warning "Running the Step4 script now..."
## Clean up the registry from the automatic login information
Write-Host "Removing auto-logon registry keys..." -ForegroundColor Green -NoNewline
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Force | Out-Null
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Force | Out-Null
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Force | Out-Null
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -Force | Out-Null
Write-Host "COMPLETE"
## Get the server name from the registry
Write-Host "Getting server name..." -ForegroundColor Green -NoNewline
while($ServerName.Length -lt 1) {
    $ServerName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -ErrorAction Ignore).VirtualMachineName
    if($ServerName -eq $null) { Start-Sleep -Seconds 5}
}
Write-Host "COMPLETE"
## Get variables from previous user input
Write-Host "Getting variables for setup..." -ForegroundColor Green -NoNewline
Import-LocalizedData -BindingVariable ExchangeInstall_LocalizedStrings -FileName $ServerName"-ExchangeInstall-strings.psd1"
Write-Host "COMPLETE"
## Verify that the domain can be resolved before continuing
Write-Host "Verifying the domain can be resolved..." -ForegroundColor Green -NoNewline
$domain = $ExchangeInstall_LocalizedStrings.Domain
$serverReady = $false
while($serverReady -eq $false) {
    $domainController = (Resolve-DnsName $domain -Type SRV -Server $ExchangeInstall_LocalizedStrings.DomainController -ErrorAction Ignore).PrimaryServer
    if($domainController -like "*$domain") { $serverReady = $true }
    Start-Sleep -Seconds 5
}
Write-Host "COMPLETE"
## Get the AD Domain
$adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
## Complete either the Exchange installation of the domain controller
switch($ExchangeInstall_LocalizedStrings.ServerType) {
    0{ ## Finalize Exchange setup
        ## Health Checker fixes
        Disable-SMB1
        CheckAndAddRegistryKey -RegistryPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'KeepAliveTime' -Value 900000 -PropertyType 'DWORD'
        Set-PowerPlan
        Write-Host "Finalizing Exchange setup..." -ForegroundColor Green
        ## Open WinRM for future Exchange installs where the VM host is not on the same subnet
        Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Where {$_.Profile -eq "Public" } | Set-NetFirewallRule -RemoteAddress Any
        if($ExchangeInstall_LocalizedStrings.ExchangeVersion -ne 2) {
            #region Enable TLS 1.2
            Write-Host "Enabling TLS 1.2..." -ForegroundColor Green -NoNewline
            $RegistryPaths = @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2',
                'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
                'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')
            foreach($RegistryPath in $RegistryPaths) {
                CheckAndAddRegistryPath -RegistryPath $RegistryPath
                if($RegistryPath -like '*Client' -or $RegistryPath -like '*Server') {
                    CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'DisabledByDefault' -Value 0 -PropertyType 'DWORD'
                    CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name "Enabled" -Value 1 -PropertyType 'DWORD'
                }
            }
            Write-Host "COMPLETE"
            #endregion
        }
        #region Enable TLS 1.2 for .NET 4.x and 3.5
        Write-Host "Enabling TLS 1.2 for .NET Framework..." -ForegroundColor Green -NoNewline
        $RegistryPaths = @('HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319',
            'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727')
        foreach($RegistryPath in $RegistryPaths) {
            CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'SystemDefaultTlsVersions' -Value 1 -PropertyType 'DWORD'
            CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'SchUseStrongCrypto' -Value 1 -PropertyType 'DWORD'
        }    
        Write-Host "COMPLETE"                   
        #endregion
        #region TLS negotiation strict mode
        Write-Host "Enabling TLS negatiation in strict mode..." -ForegroundColor Green -NoNewline
        CheckAndAddRegistryKey -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name "AllowInsecureRenegoClients" -Value 0 -PropertyType 'DWORD'
        CheckAndAddRegistryKey -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name 'AllowInsecureRenegoServers' -Value 0 -PropertyType 'DWORD'
        Write-Host "COMPLETE"
        #endregion
        #region Configure ciphers
        Write-Host "Configuring ciphers..." -ForegroundColor Green -NoNewline
        $Ciphers = @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/56',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168')
        foreach($Cipher in $Ciphers) {
            CheckAndAddRegistryPath -RegistryPath $Cipher
            CheckAndAddRegistryKey -RegistryPath $Cipher -Name 'Enabled' -Value 0 -PropertyType 'DWORD'
        }
        Write-Host "COMPLETE"
        #endregion
        #region Configure hashes
        Write-Host "Configuring hashes..." -ForegroundColor Green -NoNewline
        $Hashes = @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5')
        foreach($Hash in $Hashes) {
            CheckAndAddRegistryPath -RegistryPath $Cipher
            CheckAndAddRegistryKey -RegistryPath $Cipher -Name 'Enabled' -Value 0 -PropertyType 'DWORD'
        }
        Write-Host "COMPLETE"
        #endregion
        $ServerOS = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
        #region Windows 2016 Cipher suites
        if($ServerOS -like "*2016*") {
            Write-Host "Configuring cipher suites on Windows Server 2016..." -ForegroundColor Green -NoNewline
            $cipherSuiteKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"  
            if (((Get-ItemProperty $cipherSuiteKeyPath).Functions).Count -ge 1) {
	            Write-Host "Cipher suites are configured by Group Policy" -Foregroundcolor Red
            } 
            else {
                Write-Host "No cipher suites are configured by Group Policy - you can continue with the next steps" -Foregroundcolor Green    
                foreach ($suite in (Get-TLSCipherSuite).Name) {
                    if (-not([string]::IsNullOrWhiteSpace($suite))) {
                        Disable-TlsCipherSuite -Name $suite -ErrorAction SilentlyContinue
                    }
                }
                $CipherSuites = @('TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
                    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256')
                $suiteCount = 0
                foreach ($suite in $cipherSuites) {
                    Enable-TlsCipherSuite -Name $suite -Position $suiteCount
                    $suiteCount++
                }
            }
            Write-Host "COMPLETE"
            Write-Host "Configuring cipher curves..." -ForegroundColor Green -NoNewline
            Disable-TlsEccCurve -Name "curve25519"
            Enable-TlsEccCurve -Name "NistP384" -Position 0
            Enable-TlsEccCurve -Name "NistP256" -Position 1
            Write-Host "COMPLETE"
        }
        #endregion
        #region Windows 2012 R2 Cipher suites
        if($ServerOS -like "*2012*") {
            Write-Host "Configuring cipher suites on Windows Server 2012 R2..." -ForegroundColor Green -NoNewline
            $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
            $CipherSuites = @('TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
                'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P256',
                'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P256',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256',
                'TLS_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_RSA_WITH_AES_128_GCM_SHA256')
            CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'Functions' -Value $CipherSuites -PropertyType 'STRING'
            Write-Host "COMPLETE"
        }
        #endregion
        #region Disable TLS 1.0 and 1.1
        Write-Host "Disabling TLS 1.0 and 1.1..." -ForegroundColor Green -NoNewline
        $RegistryPaths = @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server')
        foreach($RegistryPath in $RegistryPaths) {
            CheckAndAddRegistryPath -RegistryPath $RegistryPath
            if($RegistryPath -like '*Client' -or $RegistryPath -like '*Server') {
                CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWORD'
                CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name "Enabled" -Value 0 -PropertyType 'DWORD'
            }
        }
        Write-Host "COMPLETE"
        #endregion
        ## Verify all Exchange services are running
        Get-Service MSExch* | Where { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" } | ForEach-Object { Start-Service $_ -ErrorAction Ignore}
        ## Connect a remote PowerShell session to the server
        $exchConnection = $false
        while($exchConnection -eq $false) {
                Write-Host "Connecting a remote PowerShell session with $ServerName..." -ForegroundColor Yellow
                try {Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ServerName/PowerShell" -AllowRedirection -Authentication Kerberos) | Out-Null}
                catch { Start-Sleep -Seconds 30 }
                if(Get-ExchangeServer $ServerName) {
                    $exchConnection = $true
                }
                else {
                    Write-Host "..." -ForegroundColor Green -NoNewline
                    Start-Sleep -Seconds 30
                }
        }
        Sync-AdConfigPartition
        ## Recreate Edge subscription if needed
        if($ExchangeInstall_LocalizedStrings.EdgeName -ne $null) {
            Write-Host "Recreating Edge subscription..." -ForegroundColor Green
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
            $EdgeServer = $ExchangeInstall_LocalizedStrings.EdgeName+"."+$ExchangeInstall_LocalizedStrings.EdgeDomain
            $EdgeCreds = New-Object System.Management.Automation.PSCredential($ExchangeInstall_LocalizedStrings.EdgeAdmin, (ConvertTo-SecureString -String $ExchangeInstall_LocalizedStrings.EdgePassword -AsPlainText -Force))
            $s = New-PSSession -ComputerName $EdgeServer -Credential $EdgeCreds
            Invoke-Command -ScriptBlock {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; New-EdgeSubscription -FileName c:\Temp\AutoEdgeSub.xml -Confirm:$false -Force} -Session $s
            $temp = Invoke-Command -ScriptBlock {[System.IO.File]::ReadAllBytes("C:\Temp\AutoEdgeSub.xml")} -Session $s
            New-EdgeSubscription -FileData $temp -Site $ExchangeInstall_LocalizedStrings.EdgeSite
            Start-Sleep -Seconds 5
            Start-EdgeSynchronization -TargetServer $EdgeServer
        }
           
        ## Disable Exchange diagnostic and monitoring services
        Write-Host "Disabling unwanted Exchange services for lab environment..." -ForegroundColor Green -NoNewline
        switch ($ExchangeInstall_LocalizedStrings.ExchangeVersion) {
            1 { Set-Service MSExchangeHMRecovery -StartupType Disabled }
            2 { Set-Service MSExchangeHMRecovery -StartupType Disabled }
        }
        Set-Service MSExchangeDiagnostics -StartupType Disabled
        Set-Service MSExchangeHM -StartupType Disabled
        Write-Host "COMPLETE"
        #Set the minimum number of log files to retain. Don't want 10,000 on active or 100,000 on passive
        $RegistryPath = "HKLM:\Software\Microsoft\ExchangeServer\v15\BackupInformation"
        CheckAndAddRegistryPath -RegistryPath $RegistryPath
        CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'LooseTruncation_MinCopiesToProtect' -Value 1 -PropertyType 'DWORD'
        CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'LooseTruncation_MinLogsToProtect' -Value 100 -PropertyType 'DWORD'
        ## Finish Exchange configuration
        $DagName = $ExchangeInstall_LocalizedStrings.DagName
        ## Updating the Exchange certificate
        if($ExchangeInstall_LocalizedStrings.CertThumprint -ne $null) {        
            Write-Host "Importing Exchange certificate and assigning services..." -ForegroundColor Green
            $transportCert = (Get-TransportService $ServerName).InternalTransportCertificateThumbprint
            #Import-ExchangeCertificate -Server $ServerName -FileName "C:\Temp\$ServerName-Exchange.pfx" -Password (ConvertTo-SecureString -String "Pass@word1" -AsPlainText -Force) -PrivateKeyExportable:$True | Out-Null
            Import-ExchangeCertificate -Server $ServerName -FileData ([Byte[]]$(Get-Content -Path "C:\Temp\$ServerName-Exchange.pfx" -Encoding byte)) -Password (ConvertTo-SecureString -String 'Pass@word1' -AsPlainText -Force) -PrivateKeyExportable:$True
            Enable-ExchangeCertificate -Thumbprint $ExchangeInstall_LocalizedStrings.CertThumprint -Services IIS,SMTP -Server $ServerName -Force
            ## Reset the transport service certificate back to the original self-signed certificate
            Enable-ExchangeCertificate -Thumbprint $transportCert -Services SMTP -Server $ServerName -Force
        }
        ## Configure the Exchange virtual directories
        Write-Host "Configuring virtual directories..." -ForegroundColor Green
        switch ($ExchangeInstall_LocalizedStrings.ExchangeInstallType) {
            0 {
                $intHostname = $ExchangeInstall_LocalizedStrings.InternalHostname
                $extHostname = $ExchangeInstall_LocalizedStrings.ExternalHostname
                if($intHostname -ne $null -and $extHostname -ne $null) {
                    Write-Host "Updating Autodiscover URL..." -ForegroundColor Green -NoNewline
                    Get-ClientAccessServer $ServerName | Set-ClientAccessServer -AutoDiscoverServiceInternalUri https://$intHostname/Autodiscover/Autodiscover.xml
                    Write-Host "COMPLETE"
                    Write-Host "Updating Exchange Control Panel virtual directory..." -ForegroundColor Green -NoNewline
                    Get-EcpVirtualDirectory -Server $ServerName |Set-EcpVirtualDirectory -InternalUrl https://$intHostname/ecp -ExternalUrl https://$extHostname/ecp
                    Write-Host "COMPLETE"
                    Write-Host "Updating Exchange Web Services virtual directory..." -ForegroundColor Green -NoNewline
                    Get-WebServicesVirtualDirectory -Server $ServerName | Set-WebServicesVirtualDirectory -InternalUrl https://$intHostname/ews/exchange.asmx -ExternalUrl https://$extHostname/ews/exchange.asmx -Force
                    Write-Host "COMPLETE"
                    Write-Host "Updating Mapi over Http virtual directory..." -ForegroundColor Green -NoNewline
                    Get-MapiVirtualDirectory -Server $ServerName | Set-MapiVirtualDirectory -InternalUrl https://$intHostname/mapi -ExternalUrl https://$extHostname/mapi
                    Write-Host "COMPLETE"
                    Write-Host "Updating Exchange ActiveSync virtual directory..." -ForegroundColor Green -NoNewline
                    Get-ActiveSyncVirtualDirectory -Server $ServerName | Set-ActiveSyncVirtualDirectory -ExternalUrl https://$extHostname/Microsoft-Server-ActiveSync
                    Write-Host "COMPLETE"
                    Write-Host "Updating Offline Address Book virtual directory..." -ForegroundColor Green -NoNewline
                    Get-OabVirtualDirectory -Server $ServerName | Set-OabVirtualDirectory -InternalUrl https://$intHostname/oab -ExternalUrl https://$extHostname/oab
                    Write-Host "COMPLETE"
                    Write-Host "Updating Outlook Anywhere settings..." -ForegroundColor Green -NoNewline
                    Get-OutlookAnywhere -Server $ServerName | Set-OutlookAnywhere -InternalClientAuthenticationMethod Negotiate -InternalHostname $intHostname -InternalClientsRequireSsl:$False -ExternalClientAuthenticationMethod Ntlm -ExternalClientsRequireSsl:$True -ExternalHostname $extHostname
                    Write-Host "COMPLETE"
                    Write-Host "Updating Outlook Web App virtual directory..." -ForegroundColor Green -NoNewline
                    Get-OwaVirtualDirectory -Server $ServerName | Set-OwaVirtualDirectory -InternalUrl https://$intHostname/owa -ExternalUrl https://$extHostname/owa -LogonFormat UserName -DefaultDomain $ExchangeInstall_LocalizedStrings.Domain
                    Write-Host "COMPLETE"
                }
            }
            1 {
                Write-Host "Updating Autodiscover URL..." -ForegroundColor Green -NoNewline
                Get-ClientAccessServer $ServerName | Set-ClientAccessServer -AutoDiscoverServiceInternalUri $ExchangeInstall_LocalizedStrings.AutodiscoverUrl -AutoDiscoverSiteScope $ExchangeInstall_LocalizedStrings.AutoDiscoverSiteScope
                Write-Host "COMPLETE"
                Write-Host "Updating Exchange Control Panel virtual directory..." -ForegroundColor Green -NoNewline
                Get-EcpVirtualDirectory -Server $ServerName |Set-EcpVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.EcpInternalUrl -ExternalUrl $ExchangeInstall_LocalizedStrings.EcpExternalUrl
                Write-Host "COMPLETE"
                Write-Host "Updating Exchange Web Services virtual directory..." -ForegroundColor Green -NoNewline
                Get-WebServicesVirtualDirectory -Server $ServerName | Set-WebServicesVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.EwsInternalUrl -ExternalUrl $ExchangeInstall_LocalizedStrings.EwsExternalUrl -Force
                Write-Host "COMPLETE"
                Write-Host "Updating Mapi over Http virtual directory..." -ForegroundColor Green -NoNewline
                Get-MapiVirtualDirectory -Server $ServerName | Set-MapiVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.MapiInternalUrl -ExternalUrl $ExchangeInstall_LocalizedStrings.MapiExternalUrl
                Write-Host "COMPLETE"
                Write-Host "Updating Exchange ActiveSync virtual directory..." -ForegroundColor Green -NoNewline
                Get-ActiveSyncVirtualDirectory -Server $ServerName | Set-ActiveSyncVirtualDirectory -ExternalUrl $ExchangeInstall_LocalizedStrings.EasExternalUrl
                Write-Host "COMPLETE"
                Write-Host "Updating Offline Address Book virtual directory..." -ForegroundColor Green -NoNewline
                Get-OabVirtualDirectory -Server $ServerName | Set-OabVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.OabInternalUrl -ExternalUrl $ExchangeInstall_LocalizedStrings.OabExternalUrl
                Write-Host "COMPLETE"
                Write-Host "Updating Outlook Anywhere settings..." -ForegroundColor Green -NoNewline
                if($ExchangeInstall_LocalizedStrings.OutlookAnywhereInternalSsl -eq "True") {[bool]$InternalAuth = $True}
                else {[bool]$InternalAuth = $false}
                if($ExchangeInstall_LocalizedStrings.OutlookAnywhereExternalSsl -eq "True") {[bool]$ExternalAuth = $True}
                else {[bool]$ExternalAuth = $false}
                Get-OutlookAnywhere -Server $ServerName | Set-OutlookAnywhere -InternalClientAuthenticationMethod $ExchangeInstall_LocalizedStrings.OutlookAnywhereInternalAuth -InternalHostname $ExchangeInstall_LocalizedStrings.OutlookAnywhereInternalHostname -InternalClientsRequireSsl $InternalAuth -ExternalClientAuthenticationMethod $ExchangeInstall_LocalizedStrings.OutlookAnywhereExternalAuth -ExternalClientsRequireSsl $ExternalAuth -ExternalHostname $ExchangeInstall_LocalizedStrings.OutlookAnywhereExternalHostname
                Write-Host "COMPLETE"
                Write-Host "Updating Outlook Web App virtual directory..." -ForegroundColor Green -NoNewline
                Get-OwaVirtualDirectory -Server $ServerName | Set-OwaVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.OwaInternalUrl -ExternalUrl $ExchangeInstall_LocalizedStrings.OwaExternalUrl -LogonFormat $ExchangeInstall_LocalizedStrings.OwaLogonFormat -DefaultDomain $ExchangeInstall_LocalizedStrings.OwaDefaultDomain
                Write-Host "COMPLETE"
            }
        }
        ## Check whether to create a new DAG or to end the script
        switch ($ExchangeInstall_LocalizedStrings.ExchangeInstallType) { ## Checking new or restore
            0 { switch ($ExchangeInstall_LocalizedStrings.DagResult) { ## Checking if existing or new DAG
                    0 { }## Add the Exchange server to the database availability group
                    1 { ## Creating a new Database Availability Group
                        Write-Host "Creating the new Database Availability group named $DagName..." -ForegroundColor Green -NoNewline
                        ## Determine if there is an administrative access point or not
                        if($ExchangeInstall_LocalizedStrings.DagType -eq 0) {
                            New-DatabaseAvailabilityGroup -Name $DagName -WitnessServer $ExchangeInstall_LocalizedStrings.WitnessServer -WitnessDirectory $ExchangeInstall_LocalizedStrings.WitnessDirectory -DatabaseAvailabilityGroupIpAddresses ([System.Net.IPAddress]::None) | Out-Null                              
                            Write-Host "COMPLETE"
                        }
                        else {
                            ## Create the cluster node object in Active Directory and sync those changes
                            Prepare-DatabaseAvailabilityGroup
                            Sync-ADDirectoryPartition
                            ## Get the IP addresses for the DAG and then create the DAG
                            $dagIPs = $ExchangeInstall_LocalizedStrings.DagIpAddress.Split(" ")
                            $dagIPs | ForEach-Object { [IPAddress]$_.Trim() } | Out-Null
                            New-DatabaseAvailabilityGroup -Name $DagName -WitnessServer $ExchangeInstall_LocalizedStrings.WitnessServer -WitnessDirectory $ExchangeInstall_LocalizedStrings.WitnessDirectory -DatabaseAvailabilityGroupIpAddresses $dagIPs | Out-Null                              
                        }
                    }
                    2 { ## Standalone server install
                        ## Install latest Exchange security update
                        Install-ExchSU
                        if($ExchangeInstall_LocalizedStrings.DagResult -eq 0) {Enable-ExchangeExtendedProtection}
                        Set-Location $env:ExchangeInstallPath\Bin
                        .\Setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAllDomains
                        Write-Host "Server installation complete"
                        Restart-Computer
                    }
                }
            }
            1 { ## This was a recover server and must determine whether a DAG member or standalone server
                if($DagName -eq $null) {
                    ## Install latest Exchange security update
                    Install-ExchSU
                    if($ExchangeInstall_LocalizedStrings.DagResult -eq 0) {Enable-ExchangeExtendedProtection}
                    Set-Location $env:ExchangeInstallPath\Bin
                    .\Setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAllDomains
                    Write-Host "Server installation complete"
                    Start-Sleep -Seconds 5
                    Restart-Computer
                }
            }
        }
        ## Make sure the MSExchangeRepl service is running before attempting to add Exchange server to the DAG
        Write-Host "Verifying MSExchangeRepl service is running on $ServerName..." -ForegroundColor Green -NoNewline
        $exchReplServiceRunning = $false
        while($exchReplServiceRunning -eq $false) {
            $exchReplServiceRunning = Check-MSExchangeRepl
            Write-Host "..." -ForegroundColor Green -NoNewline
        }
        Write-Host "COMPLETE"
        ## Check to ensure the DAG is available before joining
        Write-Host "Verifying $DagName is available.." -ForegroundColor Green -NoNewline
        $dagAvailable = $false
        while($dagAvailable -eq $false) {
            if(Get-DatabaseAvailabilityGroup $DagName -ErrorAction Ignore) {
                $dagAvailable = $true
            }
            else {
                Sync-AdConfigPartition
                Write-Host "..." -ForegroundColor Green -NoNewline
                Start-Sleep -Seconds 5
            }
        }
        ## Check if the FSW is a DC
        Check-FileShareWitness
        ## Add the Exchange server the the DAG
        Write-Host "Adding server to the DAG..." -ForegroundColor Green
        Add-DatabaseAvailabilityGroupServer $DagName -MailboxServer $ServerName
        ## Synchronize Active Directory with the new DAG member
        Write-Host "Synchronizing Active Directory with the latest update..." -ForegroundColor Green
        Sync-AdConfigPartition
        Write-Host "COMPLETE"
        ## Confirm Active Directory replication is updated across sites
        Write-Host "Verifying AD replication has completed..." -ForegroundColor Yellow
        $domainController = $ExchangeInstall_LocalizedStrings.DomainController
        $domainControllers = New-Object System.Collections.ArrayList
        $domainControllers = Get-DomainControllers
        $domainControllers | ForEach-Object { 
            $serverFound = $false
            Write-Host "Checking for $serverName in $DagName on $_ ..." -ForegroundColor Green -NoNewline
            while( $serverFound -eq $False) {
                if((Get-DatabaseAvailabilityGroup $DagName -DomainController $_).Servers -match $serverName) {
                    Write-Host "COMPLETE"
                    $serverFound = $True
                }
                else {
                    Sync-AdConfigPartition
                    Start-Sleep -Seconds 5
                }
                Write-Host "..." -ForegroundColor Green -NoNewline
            }
        }
        ## Add the mailbox database copies for the recovered server
        if($ExchangeInstall_LocalizedStrings.ExchangeInstallType -eq 1 -and $DagName -ne $null) {
            ## Check if there are database copies to add
            if($ExchangeInstall_LocalizedStrings.DbHasCopies -eq 1) {
                ## Add the mailbox database copies for this Exchange server
                Write-Host "Adding database copies to the server..." -ForegroundColor Green
                Add-DatabaseCopies "c:\Temp\$ServerName-DatabaseCopies.txt"
                ## Reset the activation preferences for the databases
                Write-Host "Setting database activation preferences..." -ForegroundColor Yellow
                Set-ActivationPreferences "c:\Temp\$ServerName-$DagName-ActivationPreferences.txt"
            }
        }
        ## Install latest Exchange security update
        Install-ExchSU
        if($ExchangeInstall_LocalizedStrings.DagResult -eq 0) {Enable-ExchangeExtendedProtection}
        Set-Location $env:ExchangeInstallPath\Bin
        .\Setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAllDomains
        ## Exchange server setup is complete
        Restart-Computer
    }
    1{ ## Finalize DC setup
        if($ExchangeInstall_LocalizedStrings.NewAdForest -eq 0) {
            ## Determine the IP subnet for the Active Directory site
            $ipSubnet = (Get-IPv4Subnet -IPAddress $ExchangeInstall_LocalizedStrings.IpAddress -PrefixLength $ExchangeInstall_LocalizedStrings.SubnetMask)+"/"+$ExchangeInstall_LocalizedStrings.SubnetMask
            ## Update firewall rule to allow script to access remotely
            Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Where {$_.Profile -eq "Public" } | Set-NetFirewallRule -RemoteAddress Any
            if((Get-ADReplicationSite).Name -notmatch $ExchangeInstall_LocalizedStrings.AdSiteName) {
                ## Create a new AD site
                Write-Host "Creating new AD Site called"$ExchangeInstall_LocalizedStrings.AdSiteName"..." -ForegroundColor Green -NoNewline
                New-ADReplicationSite -Name $ExchangeInstall_LocalizedStrings.AdSiteName
                Write-Host "COMPLETE"
                ## Create a new subnet and add the new site
                Write-Host "Creating a new subnet for the AD site..." -ForegroundColor Green -NoNewline
                New-ADReplicationSubnet -Name $ipSubnet -Site $ExchangeInstall_LocalizedStrings.AdSiteName
                Write-Host "COMPLETE"
                ## Add the new site to the replication site link
                Get-ADReplicationSiteLink -Filter * | Set-ADReplicationSiteLink -SitesIncluded @{Add=$ExchangeInstall_LocalizedStrings.AdSiteName} -ReplicationFrequencyInMinutes 15
                ## Add the new DC to the new site
                Write-Host "Moving $ServerName into the"$ExchangeInstall_LocalizedStrings.AdSiteName"site..." -ForegroundColor Green -NoNewline
                Move-ADDirectoryServer $ServerName -Site $ExchangeInstall_LocalizedStrings.AdSiteName -Confirm:$False
                Write-Host "COMPLETE"
            }
        }
    }
}
