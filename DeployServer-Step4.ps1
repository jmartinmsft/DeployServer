<#
// DeployServer-Step4.ps1
// Modified 14 June 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v1.3.2
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
## Functions for Exchange configuration
function Enable-ExchangeExtendedProtection {
    if($ExchangeInstall_LocalizedStrings.res_0003 -ne 0){
        %windir%\system32\inetsrv\appcmd.exe set config "Default Web Site/API/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
        %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/API/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    }
    %windir%\system32\inetsrv\appcmd.exe set config "Default Web Site/ECP/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Default Web Site/EWS/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Allow" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Default Web Site/Microsoft-Server-ActiveSync/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Allow" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Default Web Site/OAB/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Default Web Site/Powershell/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Default Web Site/owa/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Default Web Site/RPC/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Default Web Site/MAPI/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost

    
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/ECP/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/EWS/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/Microsoft-Server-ActiveSync/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/OAB/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/Powershell/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/owa/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/RPC/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/PushNotifications/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/RPCWithCert/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/MAPI/emsmdb/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
    %windir%\system32\inetsrv\appcmd.exe set config "Exchange Back End/MAPI/napi/" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:"Require" /extendedProtection.flags:"None" /commit:apphost
}
function Install-ExchSU {
    switch($ExchangeInstall_LocalizedStrings.res_0003){
        0 {Install-Exch2013SU}
        1 {Install-Exch2016SU}
        2 {Install-Exch2019SU}
    }
}
function Install-Exch2013SU {
    ## Download and install August 2022 Security Update for Exchange 2013 CU23
    Write-Host "Downloading Security Update for Exchange 2013 CU23..." -ForegroundColor Green 
    Invoke-WebRequest -Uri "https://download.microsoft.com/download/b/d/4/bd4d3875-055b-4450-9ae7-ed34a0b051a8/Exchange2013-KB5015321-x64-en.exe" -OutFile "C:\Temp\Exchange2013-KB5015321-x64-en.exe" 
    Write-Host "Installing August 2022 Security Update for Exchange 2013 CU23..." -ForegroundColor Green -NoNewline
    Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2013-KB5015321-x64-en.exe /passive"
    Start-Sleep -Seconds 30
    while(Get-Process msiexec | where {$_.MainWindowTitle -eq "Security Update for Exchange Server 2013 Cumulative Update 23 (KB5015321)"} -ErrorAction SilentlyContinue) {
        Write-Host "..." -ForegroundColor Green -NoNewline
        Start-Sleep -Seconds 10
    }
    Write-Host "COMPLETE"
}
function Install-Exch2016SU{
## Download and install Security Update for Exchange 2016
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.01.2308*") {
        Write-Host "Downloading Security Update for Exchange 2016 CU22..." -ForegroundColor Green 
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/d/6/8/d68be4c9-cb1b-45b2-a9a3-4a03c52b05c0/Exchange2016-KB5015322-x64-en.exe" -OutFile "C:\Temp\Exchange2016-KB5015322-x64-en.exe" 
    }
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.01.2507*") {
        Write-Host "Downloading Security Update for Exchange 2016 CU23..." -ForegroundColor Green
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/6/4/f/64f1b3a5-6e36-4123-b9da-3bd071940b0e/Exchange2016-KB5015322-x64-en.exe" -OutFile "C:\Temp\Exchange2016-KB5015322-x64-en.exe" 
    }
    if(Get-Item C:\Temp\Exchange2016-KB5015322-x64-en.exe -ErrorAction Ignore) {
        Write-Host "Installing August 2022 Security Update for Exchange 2016..." -ForegroundColor Green -NoNewline
        Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2016-KB5015322-x64-en.exe /passive"
        Start-Sleep -Seconds 30
        while(Get-Process msiexec | where {$_.MainWindowTitle -like "*KB5015322*"} -ErrorAction SilentlyContinue) {
            Write-Host "..." -ForegroundColor Green -NoNewline
            Start-Sleep -Seconds 10
        }
        Write-Host "COMPLETE"
    }
}
function Install-Exch2019SU{
    ## Download and install May 2022 Security Update for Exchange 2019
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.02.0986*") {
        Write-Host "Downloading Security Update for Exchange 2019 CU11..." -ForegroundColor Green 
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/c/f/3/cf38c014-e63e-4e6a-9e06-d28d4093f763/Exchange2019-KB5015322-x64-en.exe" -OutFile "C:\Temp\Exchange2019-KB5015322-x64-en.exe" 
    }
    if((Get-Item $env:ExchangeInstallPath\bin\setup.exe).VersionInfo.ProductVersion -like "15.02.1118*") {
        Write-Host "Downloading Security Update for Exchange 2019 CU12..." -ForegroundColor Green 
        Invoke-WebRequest -Uri "https://download.microsoft.com/download/8/0/4/80473b09-a81a-4816-9a79-56d5c5cc4b39/Exchange2019-KB5015322-x64-en.exe" -OutFile "C:\Temp\Exchange2019-KB5015322-x64-en.exe" 
    }
    if(Get-Item C:\Temp\Exchange2019-KB5015322-x64-en.exe -ErrorAction Ignore) {
        Write-Host "Installing August 2022 Security Update for Exchange 2019..." -ForegroundColor Green -NoNewline
        Start-Process -FilePath powershell -Verb Runas -ArgumentList "C:\Temp\Exchange2019-KB5015322-x64-en.exe /passive"
        Start-Sleep -Seconds 30
        while(Get-Process msiexec | where {$_.MainWindowTitle -like "*KB5015322*"} -ErrorAction SilentlyContinue) {
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
function Enable-TLS {
## Check for and enable TLS 1.2 on the server
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Name "TLS 1.2" | Out-Null
    }
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\' -Name Server | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name Enabled -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name Enabled -Value 1 -Force
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name Enabled -Value 1 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name DisabledByDefault -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name DisabledByDefault -Value 0
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name DisabledByDefault -Value 0 -PropertyType DWORD | Out-Null
    }
## Check for TLS 1.2 being enabled for the server as a client
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\' -Name Client | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -Value 1 -Force
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name Enabled -Value 1 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name DisabledByDefault -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name DisabledByDefault -Value 0
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name DisabledByDefault -Value 0 -PropertyType DWORD | Out-Null
    }

## Check for and enable TLS 1.2 for .NET framework 3.5
    if(Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 -Name SystemDefaultTlsVersions -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 -Name SystemDefaultTlsVersions -Value 1
    }
    else {
        New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 -Name SystemDefaultTlsVersions -Value 1 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 -Name SchUseStrongCrypto -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 -Name SchUseStrongCrypto -Value 1
    }
    else {
        New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727 -Name SchUseStrongCrypto -Value 1 -PropertyType DWORD | Out-Null
    }

    if(Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 -Name SystemDefaultTlsVersions -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 -Name SystemDefaultTlsVersions -Value 1
    }
    else {
        New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 -Name SystemDefaultTlsVersions -Value 1 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 -Name SchUseStrongCrypto -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 -Name SchUseStrongCrypto -Value 1
    }
    else {
        New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727 -Name SchUseStrongCrypto -Value 1 -PropertyType DWORD | Out-Null
    }

## Check for and enable TLS 1.2 for .NET framework 4.0
    if(Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319 -Name SystemDefaultTlsVersions -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319 -Name SystemDefaultTlsVersions -Value 1
    }
    else {
        New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319 -Name SystemDefaultTlsVersions -Value 1 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319 -Name SchUseStrongCrypto -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319 -Name SchUseStrongCrypto -Value 1
    }
    else {
        New-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319 -Name SchUseStrongCrypto -Value 1 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 -Name SystemDefaultTlsVersions -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 -Name SystemDefaultTlsVersions -Value 1
    }
    else {
        New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 -Name SystemDefaultTlsVersions -Value 1 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 -Name SchUseStrongCrypto -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 -Name SchUseStrongCrypto -Value 1
    }
    else {
        New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 -Name SchUseStrongCrypto -Value 1 -PropertyType DWORD | Out-Null
    }
}
function Disable-TLS {
#region Disable TLS 1.0
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Name "TLS 1.0" | Out-Null
    }
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\' -Name Server | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name Enabled -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name Enabled -Value 0 -Force
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name Enabled -Value 0 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name DisabledByDefault -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name DisabledByDefault -Value 1
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name DisabledByDefault -Value 1 -PropertyType DWORD | Out-Null
    }
## Check for TLS 1.0 being enabled for the server as a client
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\' -Name Client | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name Enabled -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name Enabled -Value 0 -Force
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name Enabled -Value 0 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name DisabledByDefault -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name DisabledByDefault -Value 1
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name DisabledByDefault -Value 1 -PropertyType DWORD | Out-Null
    }
#endregion
#region Disable TLS 1.1
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Name "TLS 1.1" | Out-Null
    }
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\' -Name Server | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name Enabled -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name Enabled -Value 0 -Force
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name Enabled -Value 0 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name DisabledByDefault -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name DisabledByDefault -Value 1
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name DisabledByDefault -Value 1 -PropertyType DWORD | Out-Null
    }
## Check for TLS 1.1 being enabled for the server as a client
    if(!(Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -ErrorAction Ignore)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\' -Name Client | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name Enabled -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name Enabled -Value 0 -Force
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name Enabled -Value 0 -PropertyType DWORD | Out-Null
    }
    if(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name DisabledByDefault -ErrorAction Ignore) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name DisabledByDefault -Value 1
    }
    else {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name DisabledByDefault -Value 1 -PropertyType DWORD | Out-Null
    }
#endregion
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
            #$p = Get-CimInstance -Namespace root\cimv2\power -ClassName win32_PowerPlan -Filter "ElementName = 'High Performance'"
            #Invoke-CimMethod -InputObject $p -MethodName Activate -ErrorAction Ignore | Out-Null
            powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
            Write-Host "COMPLETE"
        }
        catch {
            Write-Host "FAILED" -ForegroundColor Red
        }
    }
}
function Set-KeepAliveTime {
    if(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name KeepAliveTime -ErrorAction Ignore) {
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name KeepAliveTime -Value 900000
    }
    else {
        New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name KeepAliveTime -Value 900000 -PropertyType DWORD | Out-Null
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
$domain = $ExchangeInstall_LocalizedStrings.res_0014
$serverReady = $false
while($serverReady -eq $false) {
    $domainController = (Resolve-DnsName $domain -Type SRV -Server $ExchangeInstall_LocalizedStrings.res_0031 -ErrorAction Ignore).PrimaryServer
    if($domainController -like "*$domain") { $serverReady = $true }
    Start-Sleep -Seconds 5
}
Write-Host "COMPLETE"
## Get the AD Domain
$adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
## Complete either the Exchange installation of the domain controller
switch($ExchangeInstall_LocalizedStrings.res_0099) {
    0{ ## Finalize Exchange setup
        ## Health Checker fixes
        Disable-SMB1
        Set-KeepAliveTime
        Set-PowerPlan
        Write-Host "Finalizing Exchange setup..." -ForegroundColor Green
        ## Open WinRM for future Exchange installs where the VM host is not on the same subnet
        Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Where {$_.Profile -eq "Public" } | Set-NetFirewallRule -RemoteAddress Any
        if($ExchangeInstall_LocalizedStrings.res_0003 -ne 2) {
            Write-Host "Enabling TLS 1.2 on the server..." -ForegroundColor Green -NoNewline
            ## Enable TLS 1.2 on the server
            Enable-TLS
            Disable-TLS
            Write-Host "COMPLETE"
        }
        Disable-TLS
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
        ## Disable Exchange diagnostic and monitoring services
        Write-Host "Disabling unwanted Exchange services for lab environment..." -ForegroundColor Green -NoNewline
        switch ($ExchangeInstall_LocalizedStrings.res_0003) {
            1 { Set-Service MSExchangeHMRecovery -StartupType Disabled }
            2 { Set-Service MSExchangeHMRecovery -StartupType Disabled }
        }
        Set-Service MSExchangeDiagnostics -StartupType Disabled
        Set-Service MSExchangeHM -StartupType Disabled
        Write-Host "COMPLETE"
        ## Finish Exchange configuration
        $DagName = $ExchangeInstall_LocalizedStrings.res_0001
        ## Updating the Exchange certificate
        if($ExchangeInstall_LocalizedStrings.res_0002 -ne $null) {        
            Write-Host "Importing Exchange certificate and assigning services..." -ForegroundColor Green
            $transportCert = (Get-TransportService $ServerName).InternalTransportCertificateThumbprint
            #Import-ExchangeCertificate -Server $ServerName -FileName "C:\Temp\$ServerName-Exchange.pfx" -Password (ConvertTo-SecureString -String "Pass@word1" -AsPlainText -Force) -PrivateKeyExportable:$True | Out-Null
            Import-ExchangeCertificate -Server $ServerName -FileData ([Byte[]]$(Get-Content -Path "C:\Temp\$ServerName-Exchange.pfx" -Encoding byte)) -Password (ConvertTo-SecureString -String 'Pass@word1' -AsPlainText -Force) -PrivateKeyExportable:$True
            Enable-ExchangeCertificate -Thumbprint $ExchangeInstall_LocalizedStrings.res_0002 -Services IIS,SMTP -Server $ServerName -Force
            ## Reset the transport service certificate back to the original self-signed certificate
            Enable-ExchangeCertificate -Thumbprint $transportCert -Services SMTP -Server $ServerName -Force
        }
        ## Configure the Exchange virtual directories
        Write-Host "Configuring virtual directories..." -ForegroundColor Green
        switch ($ExchangeInstall_LocalizedStrings.res_0004) {
            0 {
                $intHostname = $ExchangeInstall_LocalizedStrings.res_0020
                $extHostname = $ExchangeInstall_LocalizedStrings.res_0021
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
                    Get-OwaVirtualDirectory -Server $ServerName | Set-OwaVirtualDirectory -InternalUrl https://$intHostname/owa -ExternalUrl https://$extHostname/owa -LogonFormat UserName -DefaultDomain $ExchangeInstall_LocalizedStrings.res_0014
                    Write-Host "COMPLETE"
                }
            }
            1 {
                Write-Host "Updating Autodiscover URL..." -ForegroundColor Green -NoNewline
                Get-ClientAccessServer $ServerName | Set-ClientAccessServer -AutoDiscoverServiceInternalUri $ExchangeInstall_LocalizedStrings.res_0038 -AutoDiscoverSiteScope $ExchangeInstall_LocalizedStrings.res_0058
                Write-Host "COMPLETE"
                Write-Host "Updating Exchange Control Panel virtual directory..." -ForegroundColor Green -NoNewline
                Get-EcpVirtualDirectory -Server $ServerName |Set-EcpVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.res_0039 -ExternalUrl $ExchangeInstall_LocalizedStrings.res_0040
                Write-Host "COMPLETE"
                Write-Host "Updating Exchange Web Services virtual directory..." -ForegroundColor Green -NoNewline
                Get-WebServicesVirtualDirectory -Server $ServerName | Set-WebServicesVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.res_0041 -ExternalUrl $ExchangeInstall_LocalizedStrings.res_0042 -Force
                Write-Host "COMPLETE"
                Write-Host "Updating Mapi over Http virtual directory..." -ForegroundColor Green -NoNewline
                Get-MapiVirtualDirectory -Server $ServerName | Set-MapiVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.res_0043 -ExternalUrl $ExchangeInstall_LocalizedStrings.res_0044
                Write-Host "COMPLETE"
                Write-Host "Updating Exchange ActiveSync virtual directory..." -ForegroundColor Green -NoNewline
                Get-ActiveSyncVirtualDirectory -Server $ServerName | Set-ActiveSyncVirtualDirectory -ExternalUrl $ExchangeInstall_LocalizedStrings.res_0045
                Write-Host "COMPLETE"
                Write-Host "Updating Offline Address Book virtual directory..." -ForegroundColor Green -NoNewline
                Get-OabVirtualDirectory -Server $ServerName | Set-OabVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.res_0046 -ExternalUrl $ExchangeInstall_LocalizedStrings.res_0047
                Write-Host "COMPLETE"
                Write-Host "Updating Outlook Anywhere settings..." -ForegroundColor Green -NoNewline
                if($ExchangeInstall_LocalizedStrings.res_0049 -eq "True") {[bool]$InternalAuth = $True}
                else {[bool]$InternalAuth = $false}
                if($ExchangeInstall_LocalizedStrings.res_0052 -eq "True") {[bool]$ExternalAuth = $True}
                else {[bool]$ExternalAuth = $false}
                Get-OutlookAnywhere -Server $ServerName | Set-OutlookAnywhere -InternalClientAuthenticationMethod $ExchangeInstall_LocalizedStrings.res_0050 -InternalHostname $ExchangeInstall_LocalizedStrings.res_0048 -InternalClientsRequireSsl $InternalAuth -ExternalClientAuthenticationMethod $ExchangeInstall_LocalizedStrings.res_0053 -ExternalClientsRequireSsl $ExternalAuth -ExternalHostname $ExchangeInstall_LocalizedStrings.res_0051
                Write-Host "COMPLETE"
                Write-Host "Updating Outlook Web App virtual directory..." -ForegroundColor Green -NoNewline
                Get-OwaVirtualDirectory -Server $ServerName | Set-OwaVirtualDirectory -InternalUrl $ExchangeInstall_LocalizedStrings.res_0054 -ExternalUrl $ExchangeInstall_LocalizedStrings.res_0055 -LogonFormat $ExchangeInstall_LocalizedStrings.res_0056 -DefaultDomain $ExchangeInstall_LocalizedStrings.res_0057
                Write-Host "COMPLETE"
            }
        }
        ## Check whether to create a new DAG or to end the script
        switch ($ExchangeInstall_LocalizedStrings.res_0004) { ## Checking new or restore
            0 { switch ($ExchangeInstall_LocalizedStrings.res_0015) { ## Checking if existing or new DAG
                    0 { }## Add the Exchange server to the database availability group
                    1 { ## Creating a new Database Availability Group
                        Write-Host "Creating the new Database Availability group named $DagName..." -ForegroundColor Green -NoNewline
                        ## Determine if there is an administrative access point or not
                        if($ExchangeInstall_LocalizedStrings.res_0032 -eq 0) {
                            New-DatabaseAvailabilityGroup -Name $DagName -WitnessServer $ExchangeInstall_LocalizedStrings.res_0018 -WitnessDirectory $ExchangeInstall_LocalizedStrings.res_0019 -DatabaseAvailabilityGroupIpAddresses ([System.Net.IPAddress]::None) | Out-Null                              
                            Write-Host "COMPLETE"
                        }
                        else {
                            ## Create the cluster node object in Active Directory and sync those changes
                            Prepare-DatabaseAvailabilityGroup
                            Sync-ADDirectoryPartition
                            ## Get the IP addresses for the DAG and then create the DAG
                            $dagIPs = $ExchangeInstall_LocalizedStrings.res_0033.Split(" ")
                            $dagIPs | ForEach-Object { [IPAddress]$_.Trim() } | Out-Null
                            New-DatabaseAvailabilityGroup -Name $DagName -WitnessServer $ExchangeInstall_LocalizedStrings.res_0018 -WitnessDirectory $ExchangeInstall_LocalizedStrings.res_0019 -DatabaseAvailabilityGroupIpAddresses $dagIPs | Out-Null                              
                        }
                    }
                    2 { ## Standalone server install
                        ## Install latest Exchange security update
                        Install-ExchSU
                        if($ExchangeInstall_LocalizedStrings.res_0015 -eq 0) {Enable-ExchangeExtendedProtection}
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
                    if($ExchangeInstall_LocalizedStrings.res_0015 -eq 0) {Enable-ExchangeExtendedProtection}
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
        $domainController = $ExchangeInstall_LocalizedStrings.res_0031
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
        if($ExchangeInstall_LocalizedStrings.res_0004 -eq 1 -and $DagName -ne $null) {
            ## Check if there are database copies to add
            if($ExchangeInstall_LocalizedStrings.res_0025 -eq 1) {
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
        if($ExchangeInstall_LocalizedStrings.res_0015 -eq 0) {Enable-ExchangeExtendedProtection}
        Set-Location $env:ExchangeInstallPath\Bin
        .\Setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAllDomains
        ## Exchange server setup is complete
        Restart-Computer
    }
    1{ ## Finalize DC setup
        if($ExchangeInstall_LocalizedStrings.res_0100 -eq 0) {
            ## Determine the IP subnet for the Active Directory site
            $ipSubnet = (Get-IPv4Subnet -IPAddress $ExchangeInstall_LocalizedStrings.res_0007 -PrefixLength $ExchangeInstall_LocalizedStrings.res_0008)+"/"+$ExchangeInstall_LocalizedStrings.res_0008
            ## Update firewall rule to allow script to access remotely
            Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Where {$_.Profile -eq "Public" } | Set-NetFirewallRule -RemoteAddress Any
            if((Get-ADReplicationSite).Name -notmatch $ExchangeInstall_LocalizedStrings.res_0106) {
                ## Create a new AD site
                Write-Host "Creating new AD Site called"$ExchangeInstall_LocalizedStrings.res_0106"..." -ForegroundColor Green -NoNewline
                New-ADReplicationSite -Name $ExchangeInstall_LocalizedStrings.res_0106
                Write-Host "COMPLETE"
                ## Create a new subnet and add the new site
                Write-Host "Creating a new subnet for the AD site..." -ForegroundColor Green -NoNewline
                New-ADReplicationSubnet -Name $ipSubnet -Site $ExchangeInstall_LocalizedStrings.res_0106
                Write-Host "COMPLETE"
                ## Add the new site to the replication site link
                Get-ADReplicationSiteLink -Filter * | Set-ADReplicationSiteLink -SitesIncluded @{Add=$ExchangeInstall_LocalizedStrings.res_0106} -ReplicationFrequencyInMinutes 15
                ## Add the new DC to the new site
                Write-Host "Moving $ServerName into the"$ExchangeInstall_LocalizedStrings.res_0106"site..." -ForegroundColor Green -NoNewline
                Move-ADDirectoryServer $ServerName -Site $ExchangeInstall_LocalizedStrings.res_0106 -Confirm:$False
                Write-Host "COMPLETE"
            }
        }
    }
}
