<#
// DeployServer-Step4.ps1
// Modified 21 September 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version:v20230921.1341
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


## Functions for Exchange configuration
function EnableExchangeExtendedProtection {
    if($ExchangeInstall_LocalizedStrings.ExchangeVersion -ne 0){
        Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Default Web Site/api"
        Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Exchange Back End/api"
    }
    
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Require -Location "Default Web Site/ecp"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Allow -Location "Default Web Site/ews"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Allow -Location "Default Web Site/Microsoft-Server-ActiveSync"
    Set-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -PSPath "IIS:" -Name "extendedProtection.TokenChecking" -Value Allow -Location "Default Web Site/oab"
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
function InstallExchSU {
    switch($ExchangeInstall_LocalizedStrings.ExchangeVersion){
        0 {InstallExch2013SU}
        1 {InstallExch2016SU}
        2 {InstallExch2019SU}
    }
}
function InstallExch2013SU {
## Download and install Security Update for Exchange 2013
    Log([string]::Format("Downloading Security Update for Exchange 2013 CU23.")) Gray
    Invoke-WebRequest -Uri "https://download.microsoft.com/download/a/6/7/a6725875-28a0-4791-abd8-4608184f4451/Exchange2013-KB5024296-x64-en.exe" -OutFile "C:\Temp\Exchange2013-KB5024296-x64-en.exe" 
    Log([string]::Format("Installing March 2023 Security Update for Exchange 2013 CU23.")) Gray
    Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2013-KB5024296-x64-en.exe /passive"
    Start-Sleep -Seconds 30
    while(Get-Process msiexec | Where-Object {$_.MainWindowTitle -like "*KB5024296*"} -ErrorAction SilentlyContinue) {
        Start-Sleep -Seconds 10
    }
}
function InstallExch2016SU{
## Download and install Security Update for Exchange 2016
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.01.2507*") {
        Log([string]::Format("Downloading Hotfix Update for Exchange 2016 CU23.")) Gray
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/6/6/3/6631ef77-4b67-48a1-9751-1476498821ff/Exchange2016-KB5037224-x64-en.exe" -OutFile "C:\Temp\Exchange2016-KB5037224-x64-en.exe" 
    }
    if(Get-Item C:\Temp\Exchange2016-KB5037224-x64-en.exe -ErrorAction Ignore) {
        Log([string]::Format("Installing April 2024 Hotfix Update for Exchange 2016.")) Gray
        Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2016-KB5037224-x64-en.exe /passive"
        Start-Sleep -Seconds 30
        while(Get-Process msiexec | Where-Object {$_.MainWindowTitle -like "*KB5037224*"} -ErrorAction SilentlyContinue) {
            Start-Sleep -Seconds 10
        }
    }
}
function InstallExch2019SU{
## Download and install Security Update for Exchange 2019
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.02.1258*") {
        Log([string]::Format("Downloading Hotfix Update for Exchange 2019 CU13.")) Gray
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/7/5/7/757ef779-ea17-4907-bf9c-bd160ec7fa69/Exchange2019-KB5037224-x64-en.exe" -OutFile "C:\Temp\Exchange2019-KB5037224-x64-en.exe" 
    }
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.02.1544*") {
        Log([string]::Format("Downloading Hotfix Update for Exchange 2019 CU14.")) Gray
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/1/b/8/1b80f503-2a17-400c-8145-d9fb1c997ea9/Exchange2019-KB5037224-x64-en.exe" -OutFile "C:\Temp\Exchange2019-KB5037224-x64-en.exe" 
    }
    if(Get-Item C:\Temp\Exchange2019-KB5037224-x64-en.exe -ErrorAction Ignore) {
        Log([string]::Format("Installing April 2024 Hotfix Update for Exchange 2019.")) Gray
        Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2019-KB5037224-x64-en.exe /passive"
        Start-Sleep -Seconds 30
        while(Get-Process msiexec | Where-Object {$_.MainWindowTitle -like "*KB5037224*"} -ErrorAction SilentlyContinue) {
            Start-Sleep -Seconds 10
        }
    }
}
function EnableHSTS {
    Import-Module IISAdministration
    Reset-IISServerManager -Confirm:$False
    Start-IISCommitDelay
    switch($ExchangeInstall_LocalizedStrings.ExchangeVersion) {
        2 {
            $siteCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection
            $siteElement = Get-IISConfigCollectionElement -ConfigCollection $siteCollection -ConfigAttribute @{"name"="Default Web Site"}
            $hstsElement = Get-IISConfigElement $siteElement -ChildElementName hsts
            Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName enabled -AttributeValue $true
            Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName 'max-age' -AttributeValue 31536000
            Set-IISConfigAttributeValue -ConfigElement $hstsElement -AttributeName includeSubdomains -AttributeValue $true
        }
        1 {
            $iisConfig = Get-IISConfigSection -SectionPath "system.webServer/httpProtocol" -CommitPath "Default Web Site" | Get-IISConfigCollection -CollectionName "customHeaders"
            New-IISConfigCollectionElement -ConfigCollection $iisConfig -ConfigAttribute @{"name"="Strict-Transport-Security"; "value"="max-age=31536000; includeSubDomains";}
        }
    }
    Stop-IISCommitDelay
    Remove-Module IISAdministration
}
function GetDomainControllers {
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

function SetPowerPlan {
    Log([string]::Format("Checking the current performance plan.")) Gray
    $PowerPlan = (Get-CimInstance -Namespace root\cimv2\power -ClassName win32_PowerPlan -Filter "IsActive = 'True'").ElementName
    if($PowerPlan -ne "High performance") {
        Log([string]::Format("Updating the performance plan.")) Gray
        try {
            powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        }
        catch {}
        ErrorReported "UpdatePowerPlan"
    }
}
function DisableSMB1 {
    Log([string]::Format("Checking if SMB1 is enabled.")) Gray
    if((Get-WindowsFeature FS-SMB1).Installed) {
        Log([string]::Format("Disabling SMB1.")) Gray
        Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart | Out-Null
        Set-SmbServerConfiguration -EnableSMB1Protocol $False -Confirm:$False
    }
}

Log([string]::Format("Running the Step4 script now.")) Yellow

## Get the server name from the registry
Log([string]::Format("Getting server name.")) Gray
while($ServerName.Length -lt 1) {
    $ServerName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -ErrorAction Ignore).VirtualMachineName
    if($null -eq $ServerName) { Start-Sleep -Seconds 5}
}

## Get variables from previous user input
Log([string]::Format("Getting variables for setup.")) Gray
Import-LocalizedData -BindingVariable ExchangeInstall_LocalizedStrings -FileName $ServerName"-ExchangeInstall-strings.psd1"
Import-LocalizedData -BindingVariable UserCreds_LocalizedStrings -FileName "Sysprep-strings.psd1"

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

## Allow setup to move to the next step
Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step5.ps1 -ServerName ' + $ServerName)

#region VerifyDomainResolution
## Verify that the domain can be resolved before continuing
if($ExchangeInstall_LocalizedStrings.EdgeRole -ne 1) {
    Log([string]::Format("Verifying the domain can be resolved.")) Gray
    $domain = $ExchangeInstall_LocalizedStrings.Domain
    $serverReady = $false
    while($serverReady -eq $false) {
        $domainController = (Resolve-DnsName $domain -Type SRV -Server $ExchangeInstall_LocalizedStrings.DomainController -ErrorAction Ignore).PrimaryServer
        if($domainController -like "*$domain") { $serverReady = $true }
        Start-Sleep -Seconds 5
    }
}
#endregion

#$adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
## Complete either the Exchange installation of the domain controller
switch($ExchangeInstall_LocalizedStrings.ServerType) {
    0{ ## Finalize Exchange setup
        #region HealthCheckerFixes
        DisableSMB1
        CheckAndAddRegistryKey -RegistryPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'KeepAliveTime' -Value 900000 -PropertyType 'DWORD'
        SetPowerPlan
        if($ExchangeInstall_LocalizedStrings.ExchangeExtendedProtection  -eq 0) {
            Log([string]::Format("Enabling extended protection.")) Gray
            Start-Sleep -Seconds 3
            EnableExchangeExtendedProtection
        }
        if($ExchangeInstall_LocalizedStrings.ExchangeVersion -ne 0 -and $ExchangeInstall_LocalizedStrings.EdgeRole -ne 1) {
            Log([string]::Format("Enabling HTTP strict transport security.")) Gray
            Start-Sleep -Seconds 3
            EnableHSTS
        }
        #endregion
        Log([string]::Format("Finalizing Exchange setup.")) Gray
        ## Open WinRM for future Exchange installs where the VM host is not on the same subnet
        Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Where-Object {$_.Profile -eq "Public" } | Set-NetFirewallRule -RemoteAddress Any
        #region SecuritySettings
        if($ExchangeInstall_LocalizedStrings.ExchangeVersion -ne 2) {
            #region Enable TLS 1.2
            Log([string]::Format("Enabling TLS 1.2.")) Gray
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
            #endregion
        }
        #region Enable TLS 1.2 for .NET 4.x and 3.5
        Log([string]::Format("Enabling TLS 1.2 for .NET Framework.")) Gray
        $RegistryPaths = @('HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319',
            'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727')
        foreach($RegistryPath in $RegistryPaths) {
            CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'SystemDefaultTlsVersions' -Value 1 -PropertyType 'DWORD'
            CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'SchUseStrongCrypto' -Value 1 -PropertyType 'DWORD'
        }    
        #endregion
        #region TLS negotiation strict mode
        Log([string]::Format("Enabling TLS negatiation in strict mode.")) Gray
        CheckAndAddRegistryKey -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name "AllowInsecureRenegoClients" -Value 0 -PropertyType 'DWORD'
        CheckAndAddRegistryKey -RegistryPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name 'AllowInsecureRenegoServers' -Value 0 -PropertyType 'DWORD'
        #endregion
        #region Configure ciphers
        Log([string]::Format("Configuring ciphers.")) Gray
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
        #endregion
        #region Configure hashes
        Log([string]::Format("Configuring hashes.")) Gray
        $Hashes = @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5')
        foreach($Hash in $Hashes) {
            CheckAndAddRegistryPath -RegistryPath $Cipher
            CheckAndAddRegistryKey -RegistryPath $Cipher -Name 'Enabled' -Value 0 -PropertyType 'DWORD'
        }
        #endregion
        $ServerOS = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
        #region Windows 2016 Cipher suites
        if($ServerOS -like "*2016*") {
            Log([string]::Format("Configuring cipher suites on Windows Server 2016.")) Gray
            $cipherSuiteKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"  
            if (((Get-ItemProperty $cipherSuiteKeyPath).Functions).Count -ge 1) {
                Log([string]::Format("Cipher suites are configured by Group Policy.")) Red
            } 
            else {
                Log([string]::Format("No cipher suites are configured by Group Policy - you can continue with the next steps.")) Gray
                foreach ($suite in (Get-TLSCipherSuite).Name) {
                    if (-not([string]::IsNullOrWhiteSpace($suite))) {
                        DisableTlsCipherSuite -Name $suite -ErrorAction SilentlyContinue
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
                    EnableTlsCipherSuite -Name $suite -Position $suiteCount
                    $suiteCount++
                }
            }
            Log([string]::Format("Configuring cipher curves.")) Gray
            Disable-TlsEccCurve -Name "curve25519"
            Enable-TlsEccCurve -Name "NistP384" -Position 0
            Enable-TlsEccCurve -Name "NistP256" -Position 1
        }
        #endregion
        #region Windows 2012 R2 Cipher suites
        if($ServerOS -like "*2012*") {
            Log([string]::Format("Configuring cipher suites on Windows Server 2012 R2.")) Gray
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
        }
        #endregion
        #region Disable TLS 1.0 and 1.1
        Log([string]::Format("Disabling TLS 1.0 and 1.1.")) Gray
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
        #endregion
        #endregion

        ## Verify all Exchange services are running
        Get-Service MSExch* | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" } | ForEach-Object { Start-Service $_ -ErrorAction Ignore}

        if($ExchangeInstall_LocalizedStrings.EdgeRole -ne 1) {
            ## Connect a remote PowerShell session to the server
            $exchConnection = $false
            while($exchConnection -eq $false) {
                Log([string]::Format("Connecting a remote PowerShell session with {0}.", $ServerName)) Gray
                try {
                    Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ServerName/PowerShell" -AllowRedirection -Authentication Kerberos) | Out-Null
                }
                catch { Start-Sleep -Seconds 30 }
                if(Get-ExchangeServer $ServerName) {
                    $exchConnection = $true
                }
                else {
                    Start-Sleep -Seconds 30
                }
            }
          
            #region InstallExchangeCertificate
            if($null -ne $ExchangeInstall_LocalizedStrings.CertThumprint) {   
                Log([string]::Format("Importing Exchange certificate and assigning services.")) Gray     
                $transportCert = (Get-TransportService $ServerName).InternalTransportCertificateThumbprint
                Import-ExchangeCertificate -Server $ServerName -FileData ([Byte[]]$(Get-Content -Path "C:\Temp\$ServerName-Exchange.pfx" -Encoding byte)) -Password (ConvertTo-SecureString -String 'Pass@word1' -AsPlainText -Force) -PrivateKeyExportable:$True
                Enable-ExchangeCertificate -Thumbprint $ExchangeInstall_LocalizedStrings.CertThumprint -Services IIS,SMTP -Server $ServerName -Force
                ## Reset the transport service certificate back to the original self-signed certificate
                Enable-ExchangeCertificate -Thumbprint $transportCert -Services SMTP -Server $ServerName -Force
            }
            #endregion

            #region UpdateExchangeVDirs
            Log([string]::Format("Configuring virtual directories.")) Gray
            switch ($ExchangeInstall_LocalizedStrings.ExchangeInstallType) {
                0 {
                    $intHostname = $ExchangeInstall_LocalizedStrings.InternalHostname
                    $extHostname = $ExchangeInstall_LocalizedStrings.ExternalHostname
                    if($null -ne $intHostname -and $null -ne $extHostname) {
                        Log([string]::Format("Updating Autodiscover URL.")) Gray
                        Get-ClientAccessServer $ServerName | Set-ClientAccessServer -AutoDiscoverServiceInternalUri https://$intHostname/Autodiscover/Autodiscover.xml
                        Log([string]::Format("Updating Exchange Control Panel virtual directory.")) Gray
                        Get-EcpVirtualDirectory -Server $ServerName |Set-EcpVirtualDirectory -InternalUrl https://$intHostname/ecp -ExternalUrl https://$extHostname/ecp
                        Log([string]::Format("Updating Exchange Web Services virtual directory.")) Gray
                        Get-WebServicesVirtualDirectory -Server $ServerName | Set-WebServicesVirtualDirectory -InternalUrl https://$intHostname/ews/exchange.asmx -ExternalUrl https://$extHostname/ews/exchange.asmx -InternalNLBBypassUrl $null -Force
                        Log([string]::Format("Updating Mapi over Http virtual directory.")) Gray
                        Get-MapiVirtualDirectory -Server $ServerName | Set-MapiVirtualDirectory -InternalUrl https://$intHostname/mapi -ExternalUrl https://$extHostname/mapi
                        Log([string]::Format("Updating Exchange ActiveSync virtual directory.")) Gray
                        Get-ActiveSyncVirtualDirectory -Server $ServerName | Set-ActiveSyncVirtualDirectory -ExternalUrl https://$extHostname/Microsoft-Server-ActiveSync
                        Log([string]::Format("Updating Offline Address Book virtual directory.")) Gray
                        Get-OabVirtualDirectory -Server $ServerName | Set-OabVirtualDirectory -InternalUrl https://$intHostname/oab -ExternalUrl https://$extHostname/oab
                        Log([string]::Format("Updating Outlook Anywhere settings.")) Gray
                        Get-OutlookAnywhere -Server $ServerName | Set-OutlookAnywhere -InternalClientAuthenticationMethod Negotiate -InternalHostname $intHostname -InternalClientsRequireSsl:$False -ExternalClientAuthenticationMethod Ntlm -ExternalClientsRequireSsl:$True -ExternalHostname $extHostname
                        Log([string]::Format("Updating Outlook Web App virtual directory.")) Gray
                        Get-OwaVirtualDirectory -Server $ServerName | Set-OwaVirtualDirectory -InternalUrl https://$intHostname/owa -ExternalUrl https://$extHostname/owa -LogonFormat UserName -DefaultDomain $ExchangeInstall_LocalizedStrings.Domain -InternalDownloadHostName $intHostname -ExternalDownloadHostName $extHostname
                    }
                }
                1 {
                    Log([string]::Format("Updating Autodiscover URL.")) Gray
                    Get-ClientAccessServer $ServerName | Set-ClientAccessServer -AutoDiscoverServiceInternalUri $ExchangeInstall_LocalizedStrings.AutodiscoverUrl -AutoDiscoverSiteScope $ExchangeInstall_LocalizedStrings.AutoDiscoverSiteScope
                    Log([string]::Format("Updating Exchange Control Panel virtual directory.")) Gray
                    Get-EcpVirtualDirectory -Server $ServerName |Set-EcpVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.EcpInternalUrl -ExternalUrl $ExchangeInstall_LocalizedStrings.EcpExternalUrl
                    Log([string]::Format("Updating Exchange Web Services virtual directory.")) Gray
                    Get-WebServicesVirtualDirectory -Server $ServerName | Set-WebServicesVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.EwsInternalUrl -ExternalUrl $ExchangeInstall_LocalizedStrings.EwsExternalUrl -InternalNLBBypassUrl $null -Force 
                    Log([string]::Format("Updating Mapi over Http virtual directory.")) Gray
                    Get-MapiVirtualDirectory -Server $ServerName | Set-MapiVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.MapiInternalUrl -ExternalUrl $ExchangeInstall_LocalizedStrings.MapiExternalUrl
                    Log([string]::Format("Updating Exchange ActiveSync virtual directory.")) Gray
                    Get-ActiveSyncVirtualDirectory -Server $ServerName | Set-ActiveSyncVirtualDirectory -ExternalUrl $ExchangeInstall_LocalizedStrings.EasExternalUrl
                    Log([string]::Format("Updating Offline Address Book virtual directory.")) Gray
                    Get-OabVirtualDirectory -Server $ServerName | Set-OabVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.OabInternalUrl -ExternalUrl $ExchangeInstall_LocalizedStrings.OabExternalUrl
                    Log([string]::Format("Updating Outlook Anywhere settings.")) Gray
                    if($ExchangeInstall_LocalizedStrings.OutlookAnywhereInternalSsl -eq "True") {[bool]$InternalAuth = $True}
                    else {[bool]$InternalAuth = $false}
                    if($ExchangeInstall_LocalizedStrings.OutlookAnywhereExternalSsl -eq "True") {[bool]$ExternalAuth = $True}
                    else {[bool]$ExternalAuth = $false}
                    Get-OutlookAnywhere -Server $ServerName | Set-OutlookAnywhere -InternalClientAuthenticationMethod $ExchangeInstall_LocalizedStrings.OutlookAnywhereInternalAuth -InternalHostname $ExchangeInstall_LocalizedStrings.OutlookAnywhereInternalHostname -InternalClientsRequireSsl $InternalAuth -ExternalClientAuthenticationMethod $ExchangeInstall_LocalizedStrings.OutlookAnywhereExternalAuth -ExternalClientsRequireSsl $ExternalAuth -ExternalHostname $ExchangeInstall_LocalizedStrings.OutlookAnywhereExternalHostname
                    Log([string]::Format("Updating Outlook Web App virtual directory.")) Gray
                    Get-OwaVirtualDirectory -Server $ServerName | Set-OwaVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.OwaInternalUrl -ExternalUrl $ExchangeInstall_LocalizedStrings.OwaExternalUrl -LogonFormat $ExchangeInstall_LocalizedStrings.OwaLogonFormat -DefaultDomain $ExchangeInstall_LocalizedStrings.OwaDefaultDomain  -InternalDownloadHostName $ExchangeInstall_LocalizedStrings.OwaInternalUrl -ExternalDownloadHostName $ExchangeInstall_LocalizedStrings.OwaExternalUrl
                }
            }
        }
        #endregion

        #region ConfigPageFile
        Log([string]::Format("Configuring the pagefile settings.")) Gray
        $pagefile = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
        $pagefile.AutomaticManagedPagefile = $false
        $pagefile.put() | Out-Null
        $pagefileset = Get-WmiObject Win32_pagefilesetting
        [int]$totalSystemMemory = Get-CimInstance win32_ComputerSystem | ForEach-Object {$_.TotalPhysicalMemory /1GB}
        $pagefileSize = $totalSystemMemory/4*1024
        $pagefileset.InitialSize = $pagefileSize
        $pagefileset.MaximumSize = $pagefileSize
        $pagefileset.Put() | Out-Null
        #endregion
        ## Install latest Exchange security update
        InstallExchSU
        Restart-Computer -Force
    }
    1{ ## Finalize DC setup
        if($ExchangeInstall_LocalizedStrings.NewAdForest -eq 0) {
            ## Determine the IP subnet for the Active Directory site
            $ipSubnet = (Get-IPv4Subnet -IPAddress $ExchangeInstall_LocalizedStrings.IpAddress -PrefixLength $ExchangeInstall_LocalizedStrings.SubnetMask)+"/"+$ExchangeInstall_LocalizedStrings.SubnetMask
            ## Update firewall rule to allow script to access remotely
            Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Where-Object {$_.Profile -eq "Public" } | Set-NetFirewallRule -RemoteAddress Any
            if((Get-ADReplicationSite).Name -notmatch $ExchangeInstall_LocalizedStrings.AdSiteName) {
                ## Create a new AD site
                Log([string]::Format("Creating new AD Site called {0}.", $ExchangeInstall_LocalizedStrings.AdSiteName)) Yellow
                New-ADReplicationSite -Name $ExchangeInstall_LocalizedStrings.AdSiteName
                ## Create a new subnet and add the new site
                Log([string]::Format("Creating a new subnet {0} for the AD site {1}.", $ipSubnet, $ExchangeInstall_LocalizedStrings.AdSiteName)) Gray
                New-ADReplicationSubnet -Name $ipSubnet -Site $ExchangeInstall_LocalizedStrings.AdSiteName
                ## Add the new site to the replication site link
                Get-ADReplicationSiteLink -Filter * | Set-ADReplicationSiteLink -SitesIncluded @{Add=$ExchangeInstall_LocalizedStrings.AdSiteName} -ReplicationFrequencyInMinutes 15
                ## Add the new DC to the new site
                Log([string]::Format("Moving {0} into the {1} site.", $ServerName, $ExchangeInstall_LocalizedStrings.AdSiteName)) Gray
                Move-ADDirectoryServer $ServerName -Site $ExchangeInstall_LocalizedStrings.AdSiteName -Confirm:$False
            }
        }
    }
}
