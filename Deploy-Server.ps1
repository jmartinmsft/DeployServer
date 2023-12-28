<#
//***********************************************************************
//
// Deploy-Server.ps1
// Modified 21 September 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20230921.1341
//Syntax for running this script:
//
// .\Deploy-Server.ps1
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
[Parameter(Mandatory=$false)]   [switch]$Exchange,
[Parameter(Mandatory=$false)]   [ipaddress]$DnsServer,
[Parameter(Mandatory=$false)]   [pscredential]$Credential,
[Parameter(Mandatory=$false)]   [string]$ServerName,
[Parameter(Mandatory=$false)]   [switch]$DisableIpv6,
[Parameter(Mandatory=$false)]   [string]$ExchangeServer,
[Parameter(Mandatory=$false)]   [string]$ExchangeIso,
[Parameter(Mandatory=$false)]   [switch]$DifferencingDisk,
[Parameter(Mandatory=$false)]   [string]$ParentDiskPath,
[Parameter(Mandatory=$false)]   [switch]$ExtendedProtection,
[Parameter(Mandatory=$false)]   [boolean]$More=$false,
[Parameter(Mandatory=$false)]   [string]$LogFile="C:\Temp\DeployVM.log"
)

$script:ScriptVersion = "v20230921.1341"

function LogToFile([string]$Details) {
	if ( [String]::IsNullOrEmpty($LogFile) ) { return }
	"$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToLongTimeString())   $Details" | Out-File $LogFile -Append
}

function Log([string]$Details, [ConsoleColor]$Colour) {
    if ([String]::IsNullOrEmpty($Colour))
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

function Read-HostWithColor() {
    ## Prompt the user for information with a string in color
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [string]$msg,
        [string]$ForegroundColor = "Yellow"
    )
    Write-Host -ForegroundColor $ForegroundColor -NoNewline $msg;
    return Read-Host
}

function global:RevertDnsSettings {
    Write-Host "Reverting DNS settings..." -ForegroundColor Green -NoNewline
        if(($Global:dnsServers.ServerAddresses).Count -eq 1) {
            Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration | Where-Object {$null -ne $_.IPv4DefaultGateway}).InterfaceIndex -ServerAddresses $Global:dnsServers.ServerAddresses[0] | Out-Null
        }
        else {
            Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration | Where-Object {$null -ne $_.IPv4DefaultGateway}).InterfaceIndex -ServerAddresses $Global:dnsServers.ServerAddresses[0],$Global:dnsServers.ServerAddresses[1] | Out-Null
        }
        Write-Host "COMPLETE"
    }
    
function GetNewServerType {
    ## Prompt for the type of new server for deployment
    $newExchange = New-Object System.Management.Automation.Host.ChoiceDescription '&Exchange Server', 'Exchange Server'
    $newDomainController = New-Object System.Management.Automation.Host.ChoiceDescription '&Domain Controller', 'Domain Controller'
    $newServer = New-Object System.Management.Automation.Host.ChoiceDescription '&Server', 'Server'
    $newInstallOption = [System.Management.Automation.Host.ChoiceDescription[]]($newExchange, $newDomainController, $newServer)
    $newInstallType = $Host.UI.PromptForChoice("Server deployment script","Select the type of server to deploy:", $newInstallOption, 0)
    return $newInstallType
}

function Test-IP() {
    ## Validate the IP address is proper format
    param(
        [Parameter(Mandatory=$True)]
        [ValidateScript({$_ -match [IPAddress]$_ })]
        [String]$ip
    )
    return $ip
}

function CheckCredentials {
    Set-Item WSMan:\localhost\Client\TrustedHosts $domainController -Force
    $scriptBlock = { Get-ADDomain }
    if(Invoke-Command -ComputerName $domainController -ScriptBlock $scriptBlock -Credential $Credential) {
        return $true
    }
    return $false
}

function Get-AdminCredential {
    $validUPN = $false
    while($validUPN -eq $false) {
        Log([string]::Format("Getting your lab credentials using the UPN.")) Gray
        $adminCred = Get-Credential -UserName "radmin@resource.local" -Message "Enter the lab domain credentials using UPN"
        if($adminCred.UserName -like "*@*" -and $adminCred.UserName -like "*.*") {
            $validUPN = $true
        }
        else { 
            Log([string]::Format("Please enter the username in UPN format.")) Yellow
        }
    }
    return $adminCred
}

function PrepareHostMachine {
    Log([string]::Format("Preparing the host machine.")) Gray
    ## Update DNS settings on VM host so it can communicate with the lab
    if($DnsServer -like $null) {
        while($null -eq $Script:DnsServer) {
            $Script:DnsServer = Test-IP(Read-HostWithColor "Enter the IP address for your lab DNS server: ")
        }    
    }
    else {$Script:DnsServer = $DnsServer}
    Log([string]::Format("Updating the DNS settings on the host machine.")) Gray
    $netIPConfig = Get-NetIPConfiguration | Where-Object {$null -ne $_.Ipv4DefaultGateway.NextHop}
    $Global:dnsServers = $netIPConfig.DNSServer | Where-Object {$_.AddressFamily -eq 2}
    Set-DnsClientServerAddress -InterfaceIndex $netIPConfig.InterfaceIndex -ServerAddresses $Script:DnsServer

    ## Ensure the AD PowerShell module is installed
    Log([string]::Format("Checking the host machine for prerequisites.")) Gray
    if(!(Get-WindowsFeature RSAT-AD-PowerShell).Installed) {
        Log([string]::Format("Installing the Active Directory PowerShell Module.")) Yellow
        Install-WindowsFeature -Name RSAT-AD-PowerShell | Out-Null
    }

    ## Get variables from the admin
    Log([string]::Format("Getting the admin credentials for the Active Directory domain.")) Gray
    $validUPN = $false
    while($validUPN -eq $false) {
        if($credential -like $null) {
            $credential = Get-AdminCredential
        }
        if($credential.UserName -like "*@*" -and $credential.UserName -like "*.*") {
            ## validate credentials
            $UserName = $Credential.UserName.Substring(0, $Credential.UserName.IndexOf("@"))
            $domain = $credential.UserName.Substring($credential.UserName.IndexOf("@")+1)
            $validDomain =$false
            while($validDomain -eq $false) {
                [string]$domainController = (Resolve-DnsName $domain -Type SOA -Server $Script:DnsServer -ErrorAction Ignore).IP4Address
                if($domainController -eq $Script:DnsServer) {
                    $validDomain = $true
                    if(CheckCredentials) {
                        $validUPN = $true
                    }
                    else {
                        Log([string]::Format("Unable to verify your credentials. Please try again.")) Yellow
                        Start-Sleep -Seconds 2
                        $credential = Get-AdminCredential
                    }
                }
                else {
                    Log([string]::Format("Unable to resolve the domain from the UPN.")) Red
                    $domain = Read-Host "Please enter the domain for your forest: "
                }
            }
        }
        else { 
            Log([string]::Format("Please enter the username in UPN format.")) Yellow
        }
    }
    LogVerbose([string]::Format("Obtaining domain controller for the domain."))
    [string]$domainController = (Resolve-DnsName $domain -Type SRV -Server $Script:DnsServer -ErrorAction Ignore).PrimaryServer
    $Password = $credential.GetNetworkCredential().Password

    ## Adding hosts file entries to ensure proper name resolution
    Log([string]::Format("Updating the hosts file on the host server.")) Gray
    try {
        Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "`r`n"
    }
    catch{}
    ErrorReported "UpdateHostsFile"
    
    LogVerbose([string]::Format("Obtaining DNS records for domain controllers in the domain."))
    $domainControllers = Resolve-DnsName -Name "_gc._tcp.$domain" -Type SRV -Server $Script:DnsServer | Where-Object { $_.Name -notlike "_gc._tcp*" }
    foreach($dc in $domainControllers) {
        [string]$newLine = $dc.IPAddress + " " + $dc.Name; 
        try { 
            Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value $newline -ErrorAction Ignore 
        }
        catch {}
        ErrorReported "UpdateHostsFile"
    }
    ## Check if the account is a member of domain admins
    Log([string]::Format("Checking if the supplied credentials is a member of Domain Admins.")) Gray
    $isDomainAdmin = $false
    Get-ADGroupMember "Domain Admins" -Server $domainController -Credential $credential | ForEach-Object { if((Get-ADObject $_ -Properties SamAccountName -Server $domainController -Credential $credential).SamAccountName -eq $UserName) { $isDomainAdmin = $true }}
    if($isDomainAdmin -eq $false) {
        Log([string]::Format("Your account is not a member of the Domain Admins group. Please update group membership prior to running the next step.")) Red
        global:Revert-DnsSettings
        exit 
    }
    ## Check if the account is a member of schema admins
    Log([string]::Format("Checking if the supplied credentials is a member of Schema Admins.")) Gray
    $isSchemaAdmin = $false
    Get-ADGroupMember "Schema Admins" -Server $domainController -Credential $credential | ForEach-Object { if((Get-ADObject $_ -Properties SamAccountName -Server $domainController -Credential $credential).SamAccountName -eq $UserName) { $isSchemaAdmin = $true }}
    if($isSchemaAdmin -eq $false) {
        Log([string]::Format("Your account is not a member of the Schema Admins group. Please update group membership or ensure the schema has been updated prior to running the next step.")) Red
        global:Revert-DnsSettings
        exit
    }
    return @{
            "Domain"  = $domain
            "DomainController"  = $domainController
            "Password" = $Password
            "UserName" = $UserName
            "Credential" = $credential
        }
}

function CreateServerVariableFile {
    ## Create psd1 with variables for the VM to use for setup
    Log([string]::Format("Creating a new variable file for {0}.",$ServerName)) Gray
    $serverVarFileName = "$ScriptPath\$ServerName-ExchangeInstall-strings.psd1"
    New-Item -Name "Temp" -ItemType Directory -Path "c:\" -ErrorAction SilentlyContinue | Out-Null
    New-Item $serverVarFileName -ItemType File -ErrorAction SilentlyContinue | Out-Null
    Add-Content -Path $serverVarFileName -Value "ConvertFrom-StringData @'"
    Add-Content -Path $serverVarFileName -Value '###PSLOC'
    return $serverVarFileName
}

function CreateVMVariableFile {
    ## Create psd1 with variables for the VM to use for setup
    Log([string]::Format("Creating a new variable file for the virtual machine: {0}.",$ServerName)) Gray
    $serverVMFileName = "$ScriptPath\$ServerName-VM-strings.psd1"
    New-Item -Name "Temp" -ItemType Directory -Path "c:\" -ErrorAction SilentlyContinue | Out-Null
    New-Item $serverVMFileName -ItemType File -ErrorAction SilentlyContinue | Out-Null
    Add-Content -Path $serverVMFileName -Value "ConvertFrom-StringData @'"
    Add-Content -Path $serverVMFileName -Value '###PSLOC'
    return $serverVMFileName
}

function GetServerInfo {
    ## Prompt the user for IP configuration for the Exchange server
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $dhcpOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $dhcpResult= $Host.UI.PromptForChoice("Server deployment script","Do you want to enable DHCP for this server?", $dhcpOption, 1)
    switch($dhcpResult) {
        0 { Add-Content -Path $serverVarFile -Value ('EnableDhcp = 1') 
            $dnsOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $dnsResult= $Host.UI.PromptForChoice("Server deployment script","Do you want to manually assign DNS?", $dnsOption, 1)
            Add-Content -Path $serverVarFile -Value ('DnsFromDhcp = ' + $dnsResult) 
            if($dnsResult -eq 0) {
                Get-PrimaryDNS
                Get-SecondaryDNS
            }
        }
        1 { $IpAddress = $null
            while([String]::IsNullOrEmpty($IpAddress)) {
                $IpAddress = Test-IP(Read-HostWithColor "Enter the server IP address: ")
                if(Test-Connection $IpAddress -Count 1 -ErrorAction Ignore) {
                    Log([string]::Format("The IP address {0} is already in use.", $IpAddress)) Yellow
                    $IpAddress = $null
                }
            }
            Add-Content -Path $serverVarFile -Value ('IpAddress = ' + $IpAddress)
            $SubnetMask = $null
            while([String]::IsNullOrEmpty($SubnetMask)) {
                $SubnetMask = Test-IP(Read-HostWithColor "Enter the subnet mask: ")
            }
            [int]$SubnetMaskPrefixLength = ConvertRvNetSubnetMaskClassesToCidr $SubnetMask
            Add-Content -Path $serverVarFile -Value ('SubnetMask = ' + $SubnetMaskPrefixLength)
            $Gateway = $null
            while([String]::IsNullOrEmpty($Gateway)) {
                $Gateway = Test-IP(Read-HostWithColor "Enter the default gateway: ")
            }
            Add-Content -Path $serverVarFile -Value ('Gateway = ' + $Gateway)
            GetPrimaryDNS
            GetSecondaryDNS
        }
    }
}

function ConvertRvNetIpAddressToInt64 {
    ## Convert IP address to integer
    param ( 
        [string] $IpAddress
    ) 
    $ipAddressParts = $IpAddress.Split('.') # IP to it's octets 
    [int64]([int64]$ipAddressParts[0] * 16777216 + 
    [int64]$ipAddressParts[1] * 65536 + 
    [int64]$ipAddressParts[2] * 256 + 
    [int64]$ipAddressParts[3]) 
} 
function ConvertRvNetSubnetMaskClassesToCidr { 
    param ( [string] $SubnetMask ) 
    ## Convert the subnet mask into prefix length
    [int64]$subnetMaskInt64 = ConvertRvNetIpAddressToInt64 -IpAddress $SubnetMask 
    $subnetMaskCidr32Int = 2147483648 # 0x80000000 - Same as ConvertRvNetIpAddressToInt64 -IpAddress '255.255.255.255' 
     $subnetMaskCidr = 0 
    for ($i = 0; $i -lt 32; $i++) { 
        if (!($subnetMaskInt64 -band $subnetMaskCidr32Int) -eq $subnetMaskCidr32Int) { break } # Bitwise and operator - Same as "&" in C# 
            $subnetMaskCidr++ 
            $subnetMaskCidr32Int = $subnetMaskCidr32Int -shr 1 # Bit shift to the right - Same as ">>" in C# 
    } 
    return $subnetMaskCidr 
}
    
function GetPrimaryDNS {
    ## Ensure the primary DNS server is provided
    $PrimaryDNS = $null
    while([String]::IsNullOrEmpty($PrimaryDNS)) {
        $PrimaryDNS = Test-IP(Read-HostWithColor "Enter the Primary DNS server address: ")
    }
    Add-Content -Path $serverVarFile -Value ('PrimaryDns = ' + $PrimaryDNS)
}

function GetSecondaryDNS {
    ## Secondary DNS value may be empty
    $checkDNS = $null
    $secondaryDNS = AskForSecondaryDNS
    if($secondaryDNS.Length -ne 0) {
        $checkDNS = Test-IP($secondaryDNS)
        ## Check if secondary DNS value is present
        while([String]::IsNullOrEmpty($checkDNS)) {
            $secondaryDNS = AskForSecondaryDNS
            if($secondaryDNS.Length -eq 0) {
                $secondaryDNS =  $null
                break
            }
            $checkDNS = Test-IP($secondaryDNS)
        }
    }
    Add-Content -Path $serverVarFile -Value ('SecondaryDns = ' + $SecondaryDNS)
}

function AskForSecondaryDNS() {
    ## Request secondary DNS server from user
        $secondDNS = $null
        $secondDNS = Read-HostWithColor "Enter the Secondary DNS server address: "
        return $secondDNS
}

function GetNewVMSwitchName {
    ## Get the virtual switch selection
    $switchSelected = $false
    while($switchSelected -eq $false) {
        $vmSwitch = Read-HostWithColor "Please enter virtual switch name: "
        if(Get-VMSwitch $vmSwitch -ErrorAction Ignore) {
            $switchSelected = $true
        }
    }
    return $vmSwitch        
}

function GetNewVMMemory {
    $vmMemory = 0
    while($vmMemory -eq 0) {
        [int64]$vmMemory = Read-HostWithColor "Please enter the amount of memory (GB): "
        $vmMemory = $vmMemory*1024*1024*1024
    }
    return $vmMemory
}

function GetNewVMCPU {
    $vmCPU = 0
    while($vmCPU -eq 0) {
        [int]$vmCPU = Read-HostWithColor "Please enter the number of CPUs: "
    }
    return $vmCPU       
}

function GetNewVMPath {
    Log([string]::Format("Select the location for the new server VHD.")) Yellow
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location for your virtual hard disk"
    $folderBrowser.SelectedPath = "C:\Hyper-V"
    $folderPath = $folderBrowser.ShowDialog()
    $vhdPath = $folderBrowser.SelectedPath
    $vhdPath = $vhdPath + "\$ServerName.vhdx"
    $vhdPath = $vhdPath.Replace("\","\\")
    return $vhdPath
}

function GetVMParentDisk {
    if(!($DifferencingDisk)) {
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
        $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
        $differencingOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $differencingResult= $Host.UI.PromptForChoice("Server deployment script","Do you want to use a differencing disk?", $differencingOption, 0)
    }
    if($differencingResult -eq 0 -or $DifferencingDisk) {
        ## Get the parent disk
        Log([string]::Format("Please select the parent VHD disk.")) Yellow
        Start-Sleep -Seconds 2
        if([String]::IsNullOrEmpty($ParentDiskPath)) {
            while($ParentDiskPath.Length -eq 0) {
                $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{InitialDirectory="M:\VHDs"; Title="Select the parent VHD"}
                $fileBrowser.Filter = "VHDX (*.vhdx)| *.vhdx"
                $fileBrowser.ShowDialog()
                [string]$ParentDiskPath = $fileBrowser.FileName
            }
        }
        $ParentDiskPath = $ParentDiskPath.Replace("\","\\")
        Add-Content -Path $serverVMFileName -Value ('VmParentVhdPath = ' + $ParentDiskPath)
        #return $true
    }
    else {
        GetVMBaseDisk
        #return $false
    }
}
function GetVMBaseDisk {
    ## Get the base VHD
    Log([string]::Format("Please select the base VHD image.")) Yellow
    Start-Sleep -Seconds 2
    while($serverVHD.Length -eq 0) {
        $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{InitialDirectory="M:\VHDs"; Title="Select the Exchange VHD"}
        $fileBrowser.Filter = "VHDX (*.vhdx)| *.vhdx"
        $fileBrowser.ShowDialog()
        [string]$serverVHD = $fileBrowser.FileName
    }
    $serverVHD = $serverVHD.Replace("\","\\")
    Add-Content -Path $serverVMFileName -Value ('ServerVhdPath = ' + $serverVHD)    
}

function GetNewVMGeneration {
    $gen1 = New-Object System.Management.Automation.Host.ChoiceDescription 'Generation &1', '1'
    $gen2 = New-Object System.Management.Automation.Host.ChoiceDescription 'Generation &2', '2'
    $generationOption = [System.Management.Automation.Host.ChoiceDescription[]]($gen1, $gen2)
    $generationResult= $Host.UI.PromptForChoice("Server deployment script","What generation virtual machine do you want to create?", $generationOption, 1)
    return $generationResult        
}
function GetExchangeISO {
    Write-Host "Please select the Exchange ISO" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{InitialDirectory="J:\ISO"; Title="Select the Exchange ISO"}
    $fileBrowser.Filter = "ISO (*.iso)| *.iso"
    $fileBrowser.ShowDialog()
    [string]$exoISO = $fileBrowser.FileName
    $exoISO = $exoISO.Replace("\","\\")
    Add-Content -Path $serverVMFileName -Value ('ExchangeIsoPath = ' + $exoISO)
}

function CheckServerOnline {
    if(Test-Connection $ServerName -ErrorAction Ignore -Count 1) { return $true }
    else { return $false }
}

function GetServerCertificate {
    ## Determine the SSL binding information for the Default Web Site
    $scriptBlock = { Import-Module WebAdministration;
        (Get-WebBinding -Name "Default Web Site" -Protocol https | Where-Object {$_.bindingInformation -eq ":443:" }).certificateHash
    }
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $certServer -Force
    $session = New-PSSession -Credential $credential -ComputerName $certServer -Name CertificateConfig
    [string]$thumbprint = (Invoke-Command -Session $session -ScriptBlock $scriptBlock)
    $scriptBlock = { Get-ChildItem -Path "Cert:\LocalMachine\My\" -Recurse  }
    $certs = Invoke-Command -Session $session -ScriptBlock $scriptBlock
    foreach($c in $certs) {
        if($c.Thumbprint -eq $thumbprint) {
            if($c.Subject -like "*$certServer*") {
                Log([string]::Format("Current certificate is self-signed certificate and cannot be used.")) Yellow
                $exportCert = $false
            }
        }
    }
    if($exportCert -eq $false) { return $null }
    else { 
        Add-Content -Path $serverVarFile -Value ('CertThumprint = ' + $thumbprint)
        $thumbprint = $thumbprint | Out-String
        Log([string]::Format("Found Exchange certificate with the thumbprint {0}.",$thumbprint)) Gray
        return $thumbprint
    }
    Disconnect-PSSession -Name CertificateConfig
    Remove-PSSession -Name CertificateConfig
}

function PrepareExchangeConnect {
    $basicEnabled = $false
    while($basicEnabled -eq $false) {
        if([String]::IsNullOrEmpty($ExchangeServer)) {
            [string]$ExchangeServer = Read-HostWithColor "Enter an Exchange Server to connect: "
        }
        ## Add the Exchange server to the hosts file to ensure we don't have name resolution issues
        if($ExchangeServer -notlike "*.*") {
            $Error.Clear()
            $dnsHost = "$ExchangeServer.$domain"
            $hostIP = (Resolve-DnsName -Name $dnsHost -Server $Script:DnsServer).IPAddress
            $error.Clear()
            try {
                Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $dnsHost" -ErrorAction Ignore
            }
            catch {}
            ErrorReported "UpdateHostsFile"
            try {
                Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $ExchangeServer" -ErrorAction Ignore
            }
            catch {}
            ErrorReported "UpdateHostsFile"
        }
        else { 
            $dnsHost = $ExchangeServer 
            Log([string]::Format("Using DNS server {0} to resolve the Exchange server {1}.", $Script:DnsServer, $dnsHost)) DarkGray
            $hostIP = (Resolve-DnsName -Name $dnsHost -Server $Script:DnsServer).IPAddress
            $Error.Clear()
            try {
                Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $dnsHost" -ErrorAction Ignore
            }
            catch {}
            ErrorReported "UpdateHostsFile"
            $dnsHost = $dnsHost.Substring(0, $dnsHost.IndexOf("."))
            try {
                Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $dnsHost" -ErrorAction Ignore
            }
            catch {}
            ErrorReported "UpdateHostsFile"
        }
        $basicEnabled = EnableBasicAuthentication -RemoteShellServer $ExchangeServer
    }
    return $ExchangeServer
}
function ConnectExchange {
    $ConnectedToExchange = $false
    $ConnectionAttempt = 0
    while($ConnectedToExchange -eq $false) {
        try {
            $ConnectionAttempt++
            Log([string]::Format("Connecting to Exchange remote PowerShell session on {0}.",$ExchangeServer)) Gray
            Import-PSSession (New-PSSession -Name ExchangeShell -ConfigurationName Microsoft.Exchange -ConnectionUri https://$ExchangeServer/PowerShell -AllowRedirection -Authentication Basic -Credential $credential -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck) -ErrorAction Ignore -WarningAction Ignore) -AllowClobber -ErrorAction Ignore -WarningAction Ignore | Out-Null
            $ConnectedToExchange = $true
        }
        catch {
            Write-Warning "Connection attempt to $ExchangeServer failed."
            [string]$ExchangeServer = Read-Host "Please enter a different Exchange server for the remote PowerShell session: "
            EnableBasicAuthentication -RemoteShellServer $ExchangeServer
        }
        if($ConnectionAttempt -eq 5) {
            Log([string]::Format("Unable to connect to an Exchange remote PowerShell session on {0}.",$ExchangeServer)) Yellow
            Log([string]::Format("Reverting DNS settings.")) Gray
            global:RevertDnsSettings
            Remove-Item $ScriptPath\hosts-$timeStamp -Confirm:$False -ErrorAction Ignore
            Remove-Item $ScriptPath\$serverName* -Confirm:$false -ErrorAction Ignore
            exit
        }
    }
}

function EnableBasicAuthentication {
    param(        
        [Parameter(Mandatory = $false)] [string]$RemoteShellServer
    )
   ## Add the Exchange server to the TrustedHosts list for WinRM
   Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $RemoteShellServer -Force
   ## Connect to the Exchange server to enable Basic authentication on the PowerShell vDir
   Log([string]::Format("Enabling basic authentication on the PowerShell vDir temporarily for {0}.",$RemoteShellServer)) Gray
   $session = $null
   $session = New-PSSession -Credential $credential -ComputerName $RemoteShellServer -Name EnableBasic -ErrorAction SilentlyContinue
   if($null -eq $session) {
       Log([string]::Format("Failed to enable basic authentication on the PowerShell vDir temporarily for {0}. Please try another server.",$RemoteShellServer)) Red
       return $false
   }
   $scriptBlock = {
        C:\Windows\system32\inetsrv\appcmd set config "Default Web Site/PowerShell/" /section:basicAuthentication /enabled:true /commit:apphost 
    }
    Invoke-Command -Session $session -ScriptBlock $scriptBlock | Out-Null
    Disconnect-PSSession -Name EnableBasic | Out-Null
    Remove-PSSession -Name EnableBasic | Out-Null
    return $true
}

function SelectExchangeVersion {
    ## Select the version of Exchange to be installed
    $ex15 = New-Object System.Management.Automation.Host.ChoiceDescription 'Exchange 201&3', 'Exchange version: Exchange 2013'
    $ex16 = New-Object System.Management.Automation.Host.ChoiceDescription 'Exchange 201&6', 'Exchange version: Exchange 2016'
    $ex19 = New-Object System.Management.Automation.Host.ChoiceDescription 'Exchange 201&9', 'Exchange version: Exchange 2019'
    $exOption = [System.Management.Automation.Host.ChoiceDescription[]]($ex15, $ex16, $ex19)
    $exVersion = $Host.UI.PromptForChoice("Server deployment script","What version of Exchange are you installing", $exOption, 2)
    Add-Content -Path $serverVarFile -Value ('ExchangeVersion = ' + $exVersion)
    return $exVersion
}

function CheckExchangeVersion {
    if($newOrgResult -ne 0) {
    $latestVersion = 0
    Get-ExchangeServer | ForEach-Object {
        [int]$serverVersion = $_.AdminDisplayVersion.Substring(11,1)
        if($serverVersion -gt $latestVersion) {
            $latestVersion = $serverVersion
        }
    }
    }
    else { $latestVersion = 0 }
    return $latestVersion
}

function SkipDagCheck {
    ## Don't verify the existence of the DAG for multiple server deployments
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $continueResult= $Host.UI.PromptForChoice("Exchange Database Availability Group not found.","Do you want to continue?", $yesNoOption, 0)
    if($continueResult -eq 0) {
        Log([string]::Format("Please verify the DAG exists prior to starting the next step.",$ExchangeServer)) Yellow
        return $true
    }
    return $false
}
function CheckNewDeployment {
    ## If this is a new deployment of multiple servers we may not was to validate the DAG
    $validDag = SkipDagCheck
    if($validDag -eq $false) {
        CreateNewDAG 
    }
    else {
        $DagName = Read-HostWithColor "Enter the Database Availability Group name: "
        Add-Content -Path $serverVarFile -Value ('DagName = ' + $DagName)
    }
}

function CreateNewDAG {
    ## Get information for create a new database availability group
    $DagName = Read-HostWithColor "Enter the name for the new Database Availability Group: "
    Add-Content -Path $serverVarFile -Value ('DagName = ' + $DagName)
    $witnessServer = Read-HostWithColor "Enter the name of the witness server: "
    Add-Content -Path $serverVarFile -Value ('WitnessServer = ' + $witnessServer)
    $witnessDirectoryValid = $false
    while($witnessDirectoryValid -eq $false) {
        $witnessDirectory = Read-HostWithColor "Enter the path for the witness directory (ex: C:\Witness\DAGName): "
        if($string -match "^([a-zA-Z]:|\\[\w\.]+\\[\w.$]+)\\(?:[\w]+\\)*\w([\w.])+$") {
            $witnessDirectoryValid = $true
            $witnessDirectory = $witnessDirectory.Replace("\","\\")
            Add-Content -Path $serverVarFile -Value ('WitnessDirectory = ' + $witnessDirectory)
        }
        else {
            Log([string]::Format("The witness directory contains one or more invalid characters. Please try again.")) Yellow
            Start-Sleep -Seconds 3
        }
    }
}

function ValidateDagName {
    ## Verify the DAG name provided is present
    if($null -ne (Get-DatabaseAvailabilityGroup $DagName -ErrorAction SilentlyContinue).Name) { return $true }
    else { return $false }
}

function GetDAGIPAddress {
    ## There must be at least one IP address for the DAG but there may be more
    $dagIPAddresses = New-Object System.Collections.ArrayList
    #$checkDagIP = $null
    [int]$x = 1 ## Count for the number of DAG IP addresses
    $addDagIP = $true
    ## Add IP addresses for the DAG until a null value is supplied
    while($addDagIP -eq $true) {
        $ipCheck = $null
        ## Get input from the user
        $dagIPAddress = AskForDAGIPAddress $x
        ## Verify the format of the input
        if($dagIPAddress.Length -ne 0) {
            $ipCheck = Test-IP($dagIPAddress)
            ## Verify the IP address is not in use
            if($null -ne $ipCheck) {
                if(Test-Connection $dagIPAddress -Count 1 -ErrorAction Ignore) {
                    Log([string]::Format("IP addresses provided already in use. Please try again.")) Yellow
                    $dagIPAddress = $null
                }
            }
            ## Invalid input
            else { $dagIPAddress = $null}
            ## Make sure there is a value before adding to the IP array
            if($dagIPAddress.Length -gt 0) {
                $dagIPAddresses.Add($dagIPAddress) | Out-Null
                $x++
                #$checkDagIP = $null
            }
        }
        else {
            ## Make sure there is at least one IP address before exiting
            if($dagIPAddresses.Count -gt 0) {
                $addDagIP = $false
            }
        }
    }
    Add-Content -Path $serverVarFile -Value ('DagIpAddress = ' + $dagIPAddresses)
}
function AskForDAGIPAddress {
    param([int]$ipCount)
    $dagIP = $null
    $dagIP = Read-HostWithColor "Enter the Database Availability Group IP Addresses[$ipCount]: "
    return $dagIP
}

function GetCertificateFromServerCheck {
    ## Check if the Exchange certificate from server where the script is running should be used
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $certResult = $Host.UI.PromptForChoice("Server deployment script","Would you like to import the Exchange certificate from this server onto the new Exchange server?", $yesNoOption, 0)
    if($certResult -eq 0) { return $true }
    else { return $false }
}

function GetMailboxDatabaseStatus {
    ## Check to see if the database is mounted on the server being restored
    param ([Parameter(Mandatory=$true)][string]$database)
    if((Get-MailboxDatabase $database -DomainController $domainController -Status).MountedOnServer -like '*' + $ServerName + '*') {
        return $true
    }
    return $false
}

function CheckAvailableDatabaseCopy {
    param ( [Parameter(Mandatory=$true)]$databaseCopy )
    if($databaseCopy.ReplayQueueLength -lt 10 -and $databaseCopy.Status -eq "Healthy") {
        if($databaseCopy.ContentIndexState -eq "Healthy" -or $exchVersion -gt 1 ) {
            $healthyCopy = $databaseCopy.Name
            $healthyCopy = $healthyCopy.Substring($healthyCopy.IndexOf("\")+1)
            return $healthyCopy
        }
    }
    return $false
}

function MoveMailboxDatabase {
    param ( [Parameter(Mandatory=$true)][string]$Database )
    $moveCompleted = $false
    $databaseCopies = Get-MailboxDatabaseCopyStatus $database
    while($moveCompleted -eq $false) {
        foreach($copy in $databaseCopies) {            
            $destinationCopy = CheckAvailableDatabaseCopy -databaseCopy $copy
            if($destinationCopy -ne $false) {
                try{
                    Log([string]::Format("Attempting to move {0} to {1}.", $Database, $destinationCopy)) Gray
                    Move-ActiveMailboxDatabase $Database -ActivateOnServer $destinationCopy -Confirm:$False
                    $moveCompleted = $true
                    return $true
                }
                catch{}
                ErrorReported "MoveDatabaseCopy"
            }
        }
        $moveCompleted = $true
    }
    return $false
}

function GetDomainControllers {
    ## Get one online domain controller for each site to confirm AD replication
    $sites = New-Object System.Collections.ArrayList
    $ADDomainControllers = New-Object System.Collections.ArrayList
    Get-ADDomainController -Filter * -Server $domainController -Credential $credential | ForEach-Object {
        if($sites -notcontains $_.Site) {
            if(Test-Connection $_.HostName -Count 1 -ErrorAction Ignore) {
                $sites.Add($_.Site) | Out-Null
                $ADDomainControllers.Add($_.Hostname) |Out-Null
            }
        }
    }
    return ,$ADDomainControllers
}

function SyncAdConfigPartition {
    ## Synchronize the Configuration partition of Active Directory across all replication partners
    $repUser = "$domain\$UserName"
    Get-ADReplicationConnection -Filter * -Server $domainController -Credential $credential | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        [string]$configPartition = ($_.ReplicateToDirectoryServer).Substring($_.ReplicateToDirectoryServer.IndexOf("CN=Configuration"))
        $ScriptBlock = { Param ($param1,$param2,$param3,$param4,$param5) repadmin /replicate $param1 $param2 "$param3" /u:$param4 /pw:$param5 /force }
        Invoke-Command  -ComputerName $ExchangeServer -ScriptBlock $scriptBlock -Credential $credential -ArgumentList $fromServer, $toServer, $configPartition, $repUser, $Password | Out-Null
    }
}

# Domain controller specific functions
function CheckADForest {
    ##We need to determine if this is a new forest
    $newForest = New-Object System.Management.Automation.Host.ChoiceDescription '&New', 'New'
    $existingForest = New-Object System.Management.Automation.Host.ChoiceDescription '&Existing', 'Existing'
    $forestOption = [System.Management.Automation.Host.ChoiceDescription[]]($newForest, $existingForest)
    $forestInstallType = $Host.UI.PromptForChoice("Server deployment script","Is this a new or existing Active Directory forest:", $forestOption, 0)
    return $forestInstallType
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

Add-Type -AssemblyName System.Windows.Forms
$ScriptPath = Get-Location
# Create an array to store all the VM server names
$VmServers = New-Object System.Collections.ArrayList
# Create an array to store Exchange servers and version
$ExchangeServers = New-Object System.Collections.ArrayList

#Backup current hosts file
$timeStamp = Get-Date -Format yyyyMMddHHmmss
$hostsFile = "C:\Windows\System32\drivers\etc\hosts"
Copy-Item $hostsFile -Destination "$ScriptPath\hosts-$timeStamp" -Force -Confirm:$False

LogVerbose([string]::Format("Getting the type of server installation."))
if($Exchange) {
    $newInstallType = 0
}
else {
    $newInstallType = GetNewServerType
}

switch($newInstallType){
    0{
        $LogonInfo = PrepareHostMachine
        $domain = $LogonInfo.Domain
        $domainController = $LogonInfo.DomainController
        $UserName = $LogonInfo.UserName
        $Password = $LogonInfo.Password
        $credential = $LogonInfo.credential
    }
    1{
        $forestInstallType = CheckADForest
        if($forestInstallType -eq 0) {
            ## Get the domain name for the new forest
            $validDomain =$false
            while($validDomain -eq $false) {
                [string]$domain = (Read-HostWithColor "Please enter the name for Active Directory domain: ").ToLower()
                if($domain -like "*.*") { $validDomain = $true }
            }
            $2012Mode = New-Object System.Management.Automation.Host.ChoiceDescription 'Windows 201&2 R2', 'Windows 2012 R2'
            $2016Mode = New-Object System.Management.Automation.Host.ChoiceDescription 'Windows 201&6', 'Windows 2016'
            $modeOption = [System.Management.Automation.Host.ChoiceDescription[]]($2012Mode, $2016Mode)
            ## Get the domain mode for the domain
            $domainMode = $Host.UI.PromptForChoice("Server deployment script","Select the domain mode:", $modeOption, 1)
            ## Get the forest mode for the forest
            $validForest = $false
            while($validForest -eq $false) {
                $forestMode = $Host.UI.PromptForChoice("Server deployment script","Select the forest mode:", $modeOption, 1)
                if($domainMode -lt $forestMode) {
                    Log([string]::Format("You can't select a forest mode that is greater than the domain mode.")) Yellow
                }
                else { $validForest = $true }
            }
            $sampleNetBIOS = $domain.Substring(0, $domain.IndexOf("."))
            $netBIOSName = (Read-Host "Please enter the NetBIOS name for the domain ($sampleNetBIOS) ").ToUpper()
        }
        if($forestInstallType -eq 1) { $LogonInfo = PrepareHostMachine
            $domain = $LogonInfo.Domain
            $domainController = $LogonInfo.DomainController
            $UserName = $LogonInfo.UserName
            $Password = $LogonInfo.Password
         }
         else {
            $UserName = "Administrator"
            $vmPassword = Read-Host "Please enter the Administrator password for your VM image:" -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($vmPassword)            
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        
         }
    }
    2{
        $LogonInfo = PrepareHostMachine
        $domain = $LogonInfo.Domain
        $domainController = $LogonInfo.DomainController
        $UserName = $LogonInfo.UserName
        $Password = $LogonInfo.Password
        $credential = $LogonInfo.credential
    }
}

$deployServer = $true
$switches = Get-VMSwitch | Format-Table Name,SwitchType
while($deployServer -eq $true) {
    $adapterCheck = $true
    while($adapterCheck) {
        if([String]::IsNullOrEmpty($ServerName)) {
            [string]$ServerName = Read-HostWithColor "Enter the name of the server to deploy: "
        }
        if(Get-Item "$ScriptPath\$ServerName*.psd1" -ErrorAction Ignore) {
            Remove-Item "$ScriptPath\$ServerName*.psd1" -ErrorAction Ignore -Force -Confirm:$false
        }
        if(Get-Item "$ScriptPath\$ServerName*.csv" -ErrorAction Ignore) {
            Remove-Item "$ScriptPath\$ServerName*.csv" -ErrorAction Ignore -Force -Confirm:$false
        }
        #if this is the first server being deployed and it's a new AD forest, use it as the domain controller for all server deployments
        if($vmServers.Count -eq 0 -and $forestInstallType -eq 0) {
            $domainController = "$ServerName.$domain"
        }
        $serverOnline = $false
        ## Do not recover a server with multiple NICs, install process currently cannot handle that scenario
        if(Get-VM $ServerName -ErrorAction Ignore) {
            Log([string]::Format("{0} already exists. Performing a recover server.",$ServerName)) Yellow
            $exInstallType = 1
            $vmAdapters = Get-VMNetworkAdapter -VMName $ServerName
            if($vmAdapters.Count -gt 1) {
                Log([string]::Format("This machine is currently connected to:")) Yellow
                for([int]$a=0; $a -lt $vmAdapters.Count; $a++) {
                    Log([string]::Format("{0} - {1}",$vmAdapters[$a].SwitchName, $vmAdapters[$a].IPAddresses )) White                       
                }
                Log([string]::Format("This deployment process currently only supports one network adapter.")) Red
                exit
            }
            else { $adapterCheck = $false }
        }
        else { 
            $exInstallType = 0 
            $adapterCheck = $false
        }
    }
    $vmServers.Add($ServerName) | Out-Null
    $serverVarFile = CreateServerVariableFile
    Add-Content -Path $serverVarFile -Value ('ServerName = ' + $ServerName)
    Add-Content -Path $serverVarFile -Value ('DomainPassword = ' + $Password)
    Add-Content -Path $serverVarFile -Value ('Domain = ' + $domain)
    ## Check if new AD forest was created and set the domain admin account
    if($forestInstallType -eq 0) { # -and $newInstallType -eq 0) {
        Add-Content -Path $serverVarFile -Value ('DomainController = ' + $domainController)
        Add-Content -Path $serverVarFile -Value ('Username = Administrator')
    }
    else {
        Add-Content -Path $serverVarFile -Value ('DomainController = ' + $domainController)
        Add-Content -Path $serverVarFile -Value ('Username = ' + $UserName)
    }

    ## Creating a variable file to store VM information
    $serverVMFileName = CreateVMVariableFile
        
    ## Check if ipV6 should be disabled
    if($DisableIpv6){
        Add-Content -Path $serverVarFile -Value ('IpV6 = 0')
    }
    else {
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
        $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
        $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $ipV6Result = $Host.UI.PromptForChoice("Server deployment script","Do you want to disable IPv6 on this server?", $yesNoOption, 0)
        Add-Content -Path $serverVarFile -Value ('IpV6 = ' + $ipV6Result)
    }

    switch($newInstallType) {
        0{
            $askForCertificateLater = $false
            Add-Content -Path $serverVarFile -Value ('ServerType = ' + $newInstallType)
            Add-Content -Path $serverVarFile -Value ('ExchangeInstallType = ' + $exInstallType)
            Add-Content -Path $serverVMFileName -Value ('NewVm = ' + $exInstallType)

            ## Update variable file with server info
            switch ($exInstallType) {
                0{
                    Log([string]::Format("Getting IP settings to deploy the new server {0}.", $ServerName)) Gray
                    GetServerInfo
                    Log([string]::Format("Getting VM settings to deploy the new server {0}.", $ServerName)) Gray
                    ## Show a list of available virtual switches
                    $switches
                    ## Get the virtual switch for the VM
                    $vmSwitch = GetNewVMSwitchName
                    Add-Content -Path $serverVMFileName -Value ('VmSwitch = ' + $vmSwitch)
                    ## Get the amount of memory to assign to the VM
                    $vmMemory = GetNewVMMemory
                    Add-Content -Path $serverVMFileName -Value ('VmMemory = ' + $vmMemory)
                    ## Get the number of processors to assign to the VM
                    $vmCPU = GetNewVMCPU
                    Add-Content -Path $serverVMFileName -Value ('VmCpus = ' + $vmCPU)
                    ## Prompt where to save the VHD for the Exchange VM
                    while($vhdPath.Length -eq 0) {
                        $vhdPath = GetNewVMPath
                    }
                    #if(!(GetVMParentDisk)) { GetVMBaseDisk }
                    GetVMParentDisk 
                    Add-Content -Path $serverVMFileName -Value ('VmVhdPath = ' + $vhdPath)
                    ## Prompt the user for an Exchange server to setup a remote PowerShell session
                    $generationResult = GetNewVMGeneration
                    Add-Content -Path $serverVMFileName -Value ('VmGeneration = ' + $generationResult)
                }
                1{
                    Log([string]::Format("Getting IP settings to recover the server {0}.", $ServerName)) Gray
                    ## Add IP information into hosts file for name resolution
                    $dnsHost = "$ServerName.$domain"
                    $hostIP = (Resolve-DnsName -Name $dnsHost -Server $Script:DnsServer).IPAddress
                    Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $dnsHost"
                    Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $ServerName"

                    ## Check if server is online to retrieve IP and disk information
                    if(CheckServerOnline) {
                        $serverOnline = $true
                        Log([string]::Format("Getting network adapter configuration for {0}.",$ServerName)) Gray
                        ## Get IP Address info for current server
                        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $ServerName -Force
                        $session = New-PSSession -Credential $credential -ComputerName $ServerName -Name ServerConfig
                        $scriptBlock = {(Get-NetIPInterface -InterfaceIndex ((Get-NetIPConfiguration | Where-Object {$_.Ipv4DefaultGateway.NextHop -ne $null}).InterfaceIndex) -AddressFamily IPv4).Dhcp }
                        $dhcpTest = Invoke-Command -Session $session -ScriptBlock $scriptBlock
                        if($dhcpTest.Value -eq "Disabled") {
                            $ipAddr = Invoke-Command -Session $session -ScriptBlock { Get-NetIPConfiguration | Where-Object {$_.Ipv4DefaultGateway.NextHop -ne $null} }
                            ## Exchange server may be cluster group owner and have multiple IP addresses
                            if($ipaddr.IPv4Address.Count -gt 1) {
                                Add-Content -Path $serverVarFile -Value ('IpAddress = ' + $ipAddr.IPv4Address.IPAddress[0])
                                Add-Content -Path $serverVarFile -Value ('SubnetMask = ' + $ipAddr.IPv4Address.PrefixLength[0])
                            }
                            else {
                                Add-Content -Path $serverVarFile -Value ('IpAddress = ' + $ipAddr.IPv4Address.IPAddress)
                                Add-Content -Path $serverVarFile -Value ('SubnetMask = ' + $ipAddr.IPv4Address.PrefixLength)                
                            }
                            Add-Content -Path $serverVarFile -Value ('Gateway = ' + $ipAddr.IPv4DefaultGateway.NextHop)
                            ## May only have a primary DNS server
                            $dns = $ipAddr.DNSServer
                            if(($dns.ServerAddresses).Count -eq 1) {
                                Add-Content -Path $serverVarFile -Value ('PrimaryDns = ' + $dns.ServerAddresses)
                            }
                            else {
                                Add-Content -Path $serverVarFile -Value ('PrimaryDns = ' + $dns.ServerAddresses[0])
                                Add-Content -Path $serverVarFile -Value ('SecondaryDns = ' + $dns.ServerAddresses[1])
                            }
                        }
                        else { 
                            Add-Content -Path $serverVarFile -Value ('EnableDhcp = 1') 
                        }
                        ## Get disk information
                        Log([string]::Format("Getting disk information for {0}.",$ServerName)) Gray
                        $scriptBlock = {
                            New-Item -ItemType Directory -Path C:\Temp -ErrorAction Ignore | Out-Null
                            $p = @()
                            $output = "DiskNumber,PartitionNumber,AccessPaths"
                            $output | Out-File "C:\Temp\DiskInfo.csv" -Force
                            Get-Disk | Where-Object {$_.Number -ne $null -and $_.IsBoot -eq $false} | ForEach-Object {
                                $p = Get-Partition -DiskNumber $_.Number | Where-Object {$_.AccessPaths -ne $null} | Select-Object DiskNumber,PartitionNumber,AccessPaths
                                $p | foreach-object { 
                                    $diskNumber = $p.DiskNumber
                                    $partitionNumber = $p.PartitionNumber
                                    ForEach ($a in $p.AccessPaths) { 
                                        if($a -notlike "*Volume{*") { 
                                            $output = "$diskNumber,$partitionNumber,$a"
                                            $output | Out-File "C:\Temp\DiskInfo.csv" -Append
                                        }
                                    }
                                }
                            }
                        }
                        Invoke-Command -Session $session -ScriptBlock $scriptBlock
                        $scriptFiles = "\\$ServerName\c$\Temp"
                        New-PSDrive -Name "Script" -PSProvider FileSystem -Root $scriptFiles -Credential $credential | Out-Null
                        Copy-Item -Path "Script:\DiskInfo.csv" -Destination "$ScriptPath\$ServerName-DiskInfo.csv" -Force -ErrorAction Ignore
                        Remove-PSDrive -Name Script
                        Disconnect-PSSession -Name ServerConfig | Out-Null
                        Remove-PSSession -Name ServerConfig | Out-Null
                        
                        ## Getting certificate information since the server is online
                        Log([string]::Format("Getting current Exchange certificate from the Exchange server {0}.",$ServerName)) Gray
                        $certServer = $ServerName
                        [string]$thumb = GetServerCertificate
                    }
                    else {
                       ## Server is not available so prompting the user for information
                       Log([string]::Format("Unable to connect to {0} to retrieve settings.", $ServerName)) Yellow
                        GetServerInfo
                        ## Check for Exchange certificate after a remote PowerShell session is established
                        $askForCertificateLater = $true 
                    }
                }
            }
            $noExchange = $false
            ## Check for an Exchange management session, otherwise verify there is no Exchange organization in the forest
            if(!(Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" }) -and [String]::IsNullOrEmpty($ExchangeServer)) {
                ## Prompt the user for an Exchange server to setup a remote PowerShell session
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $continueResult= $Host.UI.PromptForChoice("Server deployment script","Would you like to connect to Exchange now?", $yesNoOption, 0)
                if($continueResult -eq 0 -or (![String]::IsNullOrEmpty($ExchangeServer))) {
                    ## Enable basic authentication on the Exchange server
                    $ExchangeServer = PrepareExchangeConnect
                    ## Connect to the Exchange remote PowerShell session
                    ConnectExchange
                }
                ## There is no Exchange server to make a connection
                else { ## either this is a new forest or we need to confirm there is no exchange
                    if($null -eq $forestInstallType) {
                        ## This is a new deployment and a new Exchange organization may be needed
                        $noExchange = $true
                        Add-Content -Path $serverVarFile -Value ('ExchangeOrgMissing = 1')
                        $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                        $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                        $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                        $newOrgResult= $Host.UI.PromptForChoice("Server deployment script","Would you like to create a new Exchange organization?", $yesNoOption, 0)
                        if($newOrgResult -eq 0) { 
                            #Validate the organization name
                            $exOrgNameValid = $false
                            while($exOrgNameValid -eq $false) {
                                $exOrgName = Read-HostWithColor "Enter the name for the new Exchange organization: "
                                if($exOrgName -match "^[a-zA-Z0-9]*$") {
                                    $exOrgNameValid = $true
                                    Add-Content -Path $serverVarFile -Value ('ExchangeOrgName = ' + $exOrgName)
                                }
                                else {
                                    Log([string]::Format("Exchange organization name contains one or more invalid characters. Please try again.")) Yellow
                                    Start-Sleep -Seconds 3
                                }
                            }
                        }
                    }
                    #if($forestInstallType -ne 0 -and $domainController -ne $null) {                    }
                    else {
                        ## Try to locate an Exchange organization in Active Directory
                        $adDomain = (Get-ADDomain -Server $domainController -Credential $credential -ErrorAction Ignore).DistinguishedName
                        $configPartition = "CN=Configuration,$adDomain"
                        if((Get-ADObject -LDAPFilter "(objectClass=msExchOrganizationContainer)" -SearchBase $configPartition -Server $domainController -Credential $credential)) {
                            ## Found an Exchange organization so an Exchange connection should be made
                            Write-Warning "Exchange is already present in the enviornment and you must connect prior to running this script"
                            $ExchangeServer = PrepareExchangeConnect
                            Connect-Exchange
                        }
                        else {
                            ## There is no Exchange organization so we need to potentially create one
                            $noExchange = $true
                            Add-Content -Path $serverVarFile -Value ('ExchangeOrgMissing = 1')
                            ## Prompt the user for an Exchange server to setup a remote PowerShell session
                            $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                            $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                            $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                            $newOrgResult= $Host.UI.PromptForChoice("Server deployment script","Would you like to create a new Exchange organization?", $yesNoOption, 0)
                            if($newOrgResult -eq 0) { 
                                $exOrgName = Read-HostWithColor "Enter the name for the new Exchange organization: "
                                Add-Content -Path $serverVarFile -Value ('ExchangeOrgName = ' + $exOrgName)
                            }
                        }
                    }
                }
            
            }
            elseif(!([String]::IsNullOrEmpty($ExchangeServer))) {
                $ExchangeServer = PrepareExchangeConnect
                ConnectExchange
            }
            else { 
                $ExchangeServer = (Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" } | Select-Object -Last 1).ComputerName
                ## Add the Exchange server to the hosts file to ensure we don't have name resolution issues
                if($dnsHost -notlike "*$($domain)") { 
                    $dnsHost = "$ExchangeServer.$domain"
                }
                $hostIP = (Resolve-DnsName -Name $dnsHost -Server $Script:DnsServer).IPAddress
                try{ 
                    Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $dnsHost"  -ErrorAction Ignore
                }
                catch {}
                ErrorReported "UpdateHostsFile"
                try{ 
                    Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $ExchangeServer" -ErrorAction Ignore
                }
                catch {}
                ErrorReported "UpdateHostsFile"
            }

            ## Get Exchange setup information
            switch ($exInstallType) {
                0 {
                    $exReady = $false
                    while($exReady -eq $false) {
                        ## Get the Exchange version
                        $exVersion = SelectExchangeVersion
                        ## Get the latest version of Exchange in the forest
                        #if($null -ne $credential) {
                        if(Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange"}) {
                            $currentVersion = CheckExchangeVersion
                        }
                        ## New forest - set current version less than 2013
                        else { $currentVersion = -1 }
                        ## Check to see if a version of Exchange is being skipped
                        if(((($exVersion -ne $currentVersion -and $exVersion-$currentVersion) -gt 1)) -or ($noExchange -eq $true -and $exVersion -gt 0)) {
                            Log([string]::Format("One or more versions of Exchange is not installed.")) Yellow
                            $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                            $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                            $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                            $exContinue = $Host.UI.PromptForChoice("Server deployment script","Would you like to continue?", $yesNoOption, 0)
                            if($exContinue -eq 0) {
                                $exReady = $true
                            }
                        }
                        else { $exReady = $true }
                    }
                    ## Add the server and Exchange version to the array
                    $exchangeServers.Add([pscustomobject]@{ServerName=$ServerName;Version=$exVersion}) | Out-Null
                    ## Get the ISO for Exchange install
                    if([String]::IsNullOrEmpty($ExchangeIso)) {
                        GetExchangeISO
                    }
                    else
                    {
                        $ExchangeIso = $ExchangeIso.Replace("\","\\")
                        Add-Content -Path $serverVMFileName -Value ('ExchangeIsoPath = ' + $ExchangeIso)
                    }
                    $InstallEdgeRole = $false
                    switch ($exVersion) {
                        2 { 
                            $exMbxRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Mailbox', 'Mailbox server role'
                            $exEdgeRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Edge Transport', 'Edge Transport server role'
                            $exRoleOption = [System.Management.Automation.Host.ChoiceDescription[]]($exMbxRole, $exEdgeRole)
                            $exRoleResult = $Host.UI.PromptForChoice("Server deployment script","What Exchange server roles should be installed:", $exRoleOption, 0)
                            Add-Content -Path $serverVarFile -Value ('ExchangeRole = ' + $exRoleResult)
                        }
                        1 { 
                            $exMbxRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Mailbox', 'Mailbox server role'
                            $exEdgeRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Edge Transport', 'Edge Transport server role'
                            $exRoleOption = [System.Management.Automation.Host.ChoiceDescription[]]($exMbxRole, $exEdgeRole)
                            $exRoleResult = $Host.UI.PromptForChoice("Server deployment script","What Exchange server roles should be installed:", $exRoleOption, 0)
                            Add-Content -Path $serverVarFile -Value ('ExchangeRole = ' + $exRoleResult)
                        }
                        0{ 
                            $exAllRoles = New-Object System.Management.Automation.Host.ChoiceDescription '&All', 'All roles'
                            $exEdgeRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Edge Transport', 'Edge Transport server role'
                            $exMbxRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Mailbox', 'Mailbox server role'
                            $exCasRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Client Access', 'Client Access server role'
                            $exRoleOption = [System.Management.Automation.Host.ChoiceDescription[]]($exAllRoles, $exMbxRole, $exCasRole, $exEdgeRole)
                            $exRoleResult = $Host.UI.PromptForChoice("Server deployment script","What Exchange server roles should be installed:", $exRoleOption, 0)
                            Add-Content -Path $serverVarFile -Value ('ExchangeRole = ' + $exRoleResult)
                            ## Ask which version of Microsoft .NET Framework to install
                            $seven = New-Object System.Management.Automation.Host.ChoiceDescription '.NET 4.&7.2', '4.7.2'
                            $eight = New-Object System.Management.Automation.Host.ChoiceDescription '.NET 4.&8', '4.8'
                            $dotNetOption = [System.Management.Automation.Host.ChoiceDescription[]]($eight, $seven)
                            $dotNetResult = $Host.UI.PromptForChoice("Server deployment script","Which version of the Microsoft .NET Framework do you want to instll?", $dotNetOption, 0)
                            Add-Content -Path $serverVarFile -Value ('DotNetResult = ' + $dotNetResult)
                        }
                    }
                    if($exRoleResult -eq 1) {
                        $InstallEdgeRole = $true
                        Add-Content -Path $serverVarFile -Value ('EdgeRole = 1')
                        $EdgeDomainSuffix = Read-HostWithColor "Enter the DNS domain suffix for the Edge server: "
                        Add-Content -Path $serverVarFile -Value ('EdgeDomainSuffix = ' + $EdgeDomainSuffix)
                    }
                    else {
                        Add-Content -Path $serverVarFile -Value ('EdgeRole = 0')
                    }
                    
                    ## Check if the certificate from the remote PowerShell session Exchange server should be used
                    if($noExchange -eq $false -or (!($InstallEdgeRole))) {
                        if(GetCertificateFromServerCheck) {
                            if($ExchangeServer -like "*.*") { $certServer = $ExchangeServer.Substring(0, $ExchangeServer.IndexOf(".")) }
                            else { $certServer = $ExchangeServer }
                            [string]$thumb = GetServerCertificate
                        }
                    }

                    if(!($InstallEdgeRole)) {
                    ## Get hostname values for the Exchange virtual directories
                    $intHostname = (Read-HostWithColor "Enter the hostname for the internal URLs: ").ToLower()
                    Add-Content -Path $serverVarFile -Value ('InternalHostname = ' + $intHostname)
                    $extHostname = (Read-HostWithColor "Enter the hostname for the external URLs: ").ToLower()
                    Add-Content -Path $serverVarFile -Value ('ExternalHostname = ' + $extHostname)
                    ## Check whether the Exchange server should be added to an existing DAG, a new DAG, or none
                    $ExistingDag = New-Object System.Management.Automation.Host.ChoiceDescription '&Existing', 'Existing'
                    $NewDag = New-Object System.Management.Automation.Host.ChoiceDescription '&New', 'New'
                    $NoDag = New-Object System.Management.Automation.Host.ChoiceDescription '&Standalone', 'None'
                    $dagOption = [System.Management.Automation.Host.ChoiceDescription[]]($ExistingDag, $NewDag, $NoDag)
                    $dagResult = $Host.UI.PromptForChoice("Server deployment script","Would you like to join and existing DAG, create a new DAG, or make a standalone server?", $dagOption, 0)
                    Add-Content -Path $serverVarFile -Value ('DagResult = ' + $dagResult)
                    switch ($dagResult) {
                        0 {
                            # Join a DAG if Exchange is present otherwise create a DAG
                            if($noExchange -eq $false) {
                                ## Look for existing DAG and so admin can see what is available
                                if(Get-DatabaseAvailabilityGroup) {
                                    Get-DatabaseAvailabilityGroup | Format-Table Name
                                    $validDag = $false
                                    while($validDag -eq $false) {
                                        $DagName = Read-HostWithColor "Enter the Database Availability Group name: "
                                        $validDag = ValidateDagName
                                        if($validDag -eq $false) {
                                            $validDag = SkipDagCheck
                                        }
                                    }
                                    Add-Content -Path $serverVarFile -Value ('DagName = ' + $DagName)
                                }
                                ## Create a new DAG if there is no DAG in the environment or skip for deploying multiple servers
                                else {
                                    CheckNewDeployment
                                }
                            }
                            ## Cannot verify DAG so either create a new DAG or join a DAG for new deployments
                            else { CheckNewDeployment }
                        }
                        1 {
                         ## Get information for the new DAG
                        $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                        $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                        $dagTypeOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                        $dagType = $Host.UI.PromptForChoice("Server deployment script","Do you want to create the DAG without an administrative access point? (aka:IP-less)", $dagTypeOption, 0)
                        Add-Content -Path $serverVarFile -Value ('DagType = ' + $dagType)
                        Create-NewDAG
                        if($dagType -eq 1) {
                            Get-DAGIPAddress
                        }
                        }
                    }
                }
                }
                1 {
                    ## Determine what version of Exchange the server has installed
                    $exchVersion = (Get-ExchangeServer $ServerName).AdminDisplayVersion
                    $exchVersion = $exchVersion.Substring(11,1)
                    switch($exchVersion) {
                        0 {
                        Add-Content -Path $serverVarFile -Value ('ExchangeVersion = 0')
                        }
                        1 {
                            Add-Content -Path $serverVarFile -Value ('ExchangeVersion = 1') 
                            }
                        2 {
                            Add-Content -Path $serverVarFile -Value ('ExchangeVersion = 2') 
                        }
                    }
                    ## Get the ISO for Exchange install
                    if([String]::IsNullOrEmpty($ExchangeIso)) {
                        GetExchangeISO
                    }
                    else{
                        $ExchangeIso = $ExchangeIso.Replace("\","\\")
                        Add-Content -Path $serverVMFileName -Value ('ExchangeIsoPath = ' + $ExchangeIso)
                    }
                    Add-Content -Path $serverVarFile -Value ('ExchangeRole = ' + $null)
                    ## Get the VHD disk information
                    Log([string]::Format("Determining VM disk settings for {0}.", $ServerName)) Gray
                    #[string]$vhdParentPath = (Get-VHD (Get-VMHardDiskDrive -VMName $ServerName)[0].Path).ParentPath
                    [string]$vhdParentPath = (Get-VHD (Get-VMHardDiskDrive -VMName $ServerName | Where-Object {$_.Path -like "*$ServerName*"}).Path).ParentPath
                    if($vhdParentPath.Length -gt 0) {
                        Log([string]::Format("Current configuration uses a parent disk.", $ServerName)) Yellow
                        #GetVMParentDisk
                    }
                    GetVMParentDisk
                    #else { ## Check current VM generation before prompting
                        [int]$vmGen = (Get-VM $ServerName).Generation
                        Log([string]::Format("{0} is currently Generation {1}.", $ServerName, $vmGen)) Yellow
                    #    GetVMBaseDisk 
                    #}
                    ## Clearing Edge Sync credentials to allow server to be recovered that is part of an Edge subscription
                    Log([string]::Format("Checking for Edge subscription.")) Gray
                    $serverSite = (Get-ExchangeServer $ServerName).Site
                    Get-EdgeSubscription | ForEach-Object {
                if($_.Site -eq $serverSite) {
                    Log([string]::Format("Edge subscription found for the site {0}.", $serverSite)) Gray
                    #$severSite = $serverSite.Substring($serverSite.IndexOf("/Sites/")+7)
                    Add-Content -Path $serverVarFile -Value ('EdgeDomain = ' + $_.Domain)
                    Add-Content -Path $serverVarFile -Value ('EdgeName = ' + $_.Name)
                    Add-Content -Path $serverVarFile -Value ('EdgeSite = ' + $serverSite)
                    Log([string]::Format("Removing existing Edge sync credentials..")) Gray
                    #$dc = (Get-ExchangeServer $ServerName).OriginatingServer
                    [int]$startChar = $ServerName.Length + 4
                    $searchBase = (Get-ExchangeServer $ServerName).DistinguishedName
                    $searchBase = $searchBase.Substring($startChar)
                    Get-ADObject -SearchBase $searchBase -Filter 'cn -eq $ServerName' -SearchScope OneLevel -Properties msExchEdgeSyncCredential -Server $domainController -Credential $credential | Set-ADObject -Clear msExchEdgeSyncCredential -Server $domainController -Credential $credential
                    $EdgeAdmin = Read-HostWithColor "Enter the admin username for the Edge server ($($_.Name): "
                    $EdgePassword = Read-Host "Enter the admin password for the Edge server ($($_.Name)) " -AsSecureString
                    $EdgePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EdgePassword))
                    Add-Content -Path $serverVarFile -Value ('EdgeAdmin = ' + $EdgeAdmin)
                    Add-Content -Path $serverVarFile -Value ('EdgePassword = ' + $EdgePassword)
                }
                    }
                    ## Check if the servers was offline and if we need the certificate
                    if($askForCertificateLater) {
                if(GetCertificateFromServerCheck) {
                    if($ExchangeServer -like "*.*") {
                        $certServer = $ExchangeServer.Substring(0, $ExchangeServer.IndexOf("."))
                    }
                    else { $certServer = $ExchangeServer }
                    [string]$thumb = GetServerCertificate
                }
                    }
                    #Get Client Access settings
                    $AutoD = Get-ClientAccessServer $ServerName -WarningAction Ignore
                    Add-Content -Path $serverVarFile -Value ('AutodiscoverUrl = ' + $AutoD.AutoDiscoverServiceInternalUri.AbsoluteUri)
                    Add-Content -Path $serverVarFile -Value ('AutoDiscoverSiteScope = ' + $AutoD.AutoDiscoverSiteScope)
                    $AutoD = $null
                    $Ecp = Get-EcpVirtualDirectory -Server $ServerName -ADPropertiesOnly
                    Add-Content -Path $serverVarFile -Value ('EcpInternalUrl = ' + $Ecp.InternalUrl.AbsoluteUri)
                    Add-Content -Path $serverVarFile -Value ('EcpExternalUrl = ' + $Ecp.ExternalUrl.AbsoluteUri)
                    $Ecp = $null
                    $Ews = Get-WebServicesVirtualDirectory -Server $ServerName -ADPropertiesOnly
                    Add-Content -Path $serverVarFile -Value ('EwsInternalUrl = ' + $Ews.InternalUrl.AbsoluteUri)
                    Add-Content -Path $serverVarFile -Value ('EwsExternalUrl = ' + $Ews.ExternalUrl.AbsoluteUri)
                    $Ews = $null
                    $Mapi = Get-MapiVirtualDirectory -Server $ServerName -ADPropertiesOnly
                    Add-Content -Path $serverVarFile -Value ('MapiInternalUrl = ' + $Mapi.InternalUrl.AbsoluteUri)
                    Add-Content -Path $serverVarFile -Value ('MapiExternalUrl = ' + $Mapi.ExternalUrl.AbsoluteUri)
                    $Mapi = $null
                    $Eas = Get-ActiveSyncVirtualDirectory -Server $ServerName -ADPropertiesOnly
                    Add-Content -Path $serverVarFile -Value ('EasExternalUrl = ' + $Eas.ExternalUrl.AbsoluteUri)
                    $Eas = $null
                    $Oab = Get-OabVirtualDirectory -Server $ServerName -ADPropertiesOnly
                    Add-Content -Path $serverVarFile -Value ('OabInternalUrl = ' + $Oab.InternalUrl.AbsoluteUri)
                    Add-Content -Path $serverVarFile -Value ('OabExternalUrl = ' + $Oab.ExternalUrl.AbsoluteUri)
                    $Oab = $null
                    $Owa = Get-OwaVirtualDirectory -Server $ServerName
                    Add-Content -Path $serverVarFile -Value ('OwaInternalUrl = ' + $Owa.InternalUrl.AbsoluteUri)
                    Add-Content -Path $serverVarFile -Value ('OwaExternalUrl = ' + $Owa.ExternalUrl.AbsoluteUri)
                    Add-Content -Path $serverVarFile -Value ('OwaLogonFormat = ' + $Owa.LogonFormat)
                    Add-Content -Path $serverVarFile -Value ('OwaDefaultDomain = ' + $Owa.DefaultDomain)
                    $Owa = $null
                    $RpcHttp = Get-OutlookAnywhere -Server $ServerName
                    Add-Content -Path $serverVarFile -Value ('OutlookAnywhereInternalHostname = ' + $RpcHttp.InternalHostname)
                    Add-Content -Path $serverVarFile -Value ('OutlookAnywhereInternalSsl = ' + $RpcHttp.InternalClientsRequireSsl)
                    Add-Content -Path $serverVarFile -Value ('OutlookAnywhereInternalAuth = ' + $RpcHttp.InternalClientAuthenticationMethod)
                    Add-Content -Path $serverVarFile -Value ('OutlookAnywhereExternalHostname = ' + $RpcHttp.ExternalHostname)
                    Add-Content -Path $serverVarFile -Value ('OutlookAnywhereExternalSsl = ' + $RpcHttp.ExternalClientsRequireSsl)
                    Add-Content -Path $serverVarFile -Value ('OutlookAnywhereExternalAuth = ' + $RpcHttp.ExternalClientAuthenticationMethod)
                    $RpcHttp = $null
                    ##Check if the Exchange server is a member of a DAG
                    Log([string]::Format("Checking if the Exchange server is a member of a DAG.")) Gray
                    if(Get-DatabaseAvailabilityGroup -DomainController $domainController | Where-Object { $_.Servers -match $ServerName }) {
                [string]$DagName = Get-DatabaseAvailabilityGroup -DomainController $domainController  | Where-Object { $_.Servers -like '*' + $ServerName + '*'}
                Log([string]::Format("{0} is a member of the DAG {1}.", $ServerName, $DagName)) Gray
                Add-Content -Path $serverVarFile -Value ('DagName = ' + $DagName)
                ## Check if the databases have multiple copies
                $dbHasCopies = $false
                Log([string]::Format("Checking if the databases for this server have multiple copies.")) Gray
                $ExchangeDatabases = Get-MailboxDatabase -Server $ServerName
                ForEach($db in $ExchangeDatabases) {
                    if($db.ReplicationType -eq "Remote") {
                        $dbHasCopies = $true
                        ## Check the number of copies of the database
                        if(((Get-MailboxDatabase $db.Name).AllDatabaseCopies).count -eq 2){
                            if((Get-MailboxDatabase $_.Name).CircularLoggingEnabled) {
                                ## Need to disable circular logging before removing the database copy
                                Log([string]::Format("Disabling circular logging for the database {0}.", $_.Name)) Gray
                                Set-MailboxDatabase $_.Name -CircularLoggingEnabled:$False -Confirm:$False | Out-Null
                            }
                        }
                        ## Get a list of databases and the replay lag times for the Exchange server
                        LogVerbose([string]::Format("Adding database copy for {0} into the restore list.", $db.Name))
                        $replayLagTime = [string](Get-MailboxDatabase $db.Name | Where-Object {$db.ReplayLagTimes -like "*$ServerName*" }).ReplayLagTimes
                        $db.Name + "," + $replayLagTime | Out-File "$ScriptPath\$ServerName-DatabaseCopies.txt" -Append
                        
                        ## Get the current activation preferences for the mailbox databases in the DAG
                        LogVerbose([string]::Format("Addiing database copy activation preferences for {0}.", $db.Name))
                        $activationPreference = [string](Get-MailboxDatabase $db.Name | Select-Object Name -ExpandProperty ActivationPreference)
                        $db.Name + "," + $activationPreference | Out-File "$ScriptPath\$ServerName-$DagName-ActivationPreferences.txt" -Append
                        
                        ## Check if the database is mounted on this server
                        $dbMounted = $true
                        while($dbMounted -eq $true) {
                            $dbMounted = GetMailboxDatabaseStatus $db.Name 
                            if($dbMounted -eq $true) {
                                $dbMove = MoveMailboxDatabase -Database $db.Name
                                if($dbMove) {
                                    SyncAdConfigPartition
                                }
                                else {
                                    Log([string]::Format("Failed to move the mailbox database {0} to another server.", $db.Name)) Red
                                    global:RevertDnsSettings
                                    exit
                                }
                            }
                        }
                        ## Remove existing database copies and then remove server from DAG
                        Log([string]::Format("Removing database copy for {0} from the server.", $db.Name)) Gray
                        $dbCopy = $db.Name + "\$ServerName"
                        try {
                            Remove-MailboxDatabaseCopy $dbCopy -DomainController $domainController -Confirm:$False -WarningAction Ignore | Out-Null
                        }
                        catch{}
                        ErrorReported "RemoveDatabaseCopy"
                    }
                }
                if($dbHasCopies -eq $true) {
                    Add-Content -Path $serverVarFile -Value ('DbHasCopies = 1')
                }
                ##Remove the Exchange server from the database availability group
                Log([string]::Format("Checking DAC mode for the DAG {0}.", $DagName)) Gray
                if((Get-DatabaseAvailabilityGroup $DagName -DomainController $domainController ).DatacenterActivationMode -eq "DagOnly") {
                    LogVerbose([string]::Format("DagOnly"))
                    Add-Content -Path $serverVarFile -Value ('DatacenterActivationMode = DagOnly')
                    Log([string]::Format("Checking the number of servers in the DAG {0}.", $DagName)) Gray
                    if((Get-DatabaseAvailabilityGroup -DomainController $domainController ).Servers.Count -eq 2) {
                        Log([string]::Format("Disabling datacenter activation mode for DAG {0}.", $DagName)) Gray
                        Set-DatabaseAvailabilityGroup $DagName -DatacenterActivationMode Off -DomainController $domainController -Confirm:$False | Out-Null
                    }
                }
                else { 
                    LogVerbose([string]::Format("OFF"))
                    Add-Content -Path $serverVarFile -Value ('DatacenterActivationMode = Off')
                }
                Log([string]::Format("Removing server {0} from the DAG {1}.",$ServerName, $DagName)) Gray
                if($serverOnline -eq $true) {
                    try{
                        Remove-DatabaseAvailabilityGroupServer $DagName -MailboxServer $ServerName -DomainController $domainController -Confirm:$False -ErrorAction Ignore
                    }
                    catch{}
                    ErrorReported "RemoveServerFromDag"
                }
                else {
                    try {
                        Remove-DatabaseAvailabilityGroupServer $DagName -MailboxServer $ServerName -DomainController $domainController -ConfigurationOnly -Confirm:$False -ErrorAction Ignore
                        Start-Sleep -Seconds 5
                    }
                    catch {}
                    ErrorReported "RemoveServerFromDag"
                    Log([string]::Format("Removing server {0} from the windows cluster.",$ServerName)) Gray
                    $scriptBlock = { Param ($param1) Remove-ClusterNode -Name $param1 -Force -ErrorAction Ignore }
                    try {
                        Invoke-Command -ScriptBlock $scriptBlock -ComputerName $ExchangeServer -Credential $credential -ArgumentList $ServerName
                    }
                    catch {}
                    ErrorReported "RemoveServerFromCluster"
                }

                ## Check if the remove succeeded
                if((Get-DatabaseAvailabilityGroup $DagName -DomainController $domainController).Servers -notcontains $serverName) {
                    ## Synchrnoize Active Directory so all sites are aware of the change
                    Log([string]::Format("Synchronizing Active Directory with the latest changes.")) Gray
                    SyncAdConfigPartition
                    ## Verify the Exchange server is no longer a member of the DAG in each AD site
                    $domainControllers = New-Object System.Collections.ArrayList
                    $domainControllers = GetDomainControllers
                    $domainControllers | ForEach-Object { 
                        $serverFound = $true
                        Log([string]::Format("Checking for {0} in {1} on {2}.", $ServerName, $DagName, $_)) Gray
                        while($serverFound -eq $true) {
                            if((Get-DatabaseAvailabilityGroup $DagName -DomainController $_ -ErrorAction Ignore).Servers -contains $serverName) {
                                SyncAdConfigPartition
                                Start-Sleep -Seconds 10
                            }
                            else {
                                $serverFound = $false
                            }
                        }
                    }
                }
                else {
                    Log([string]::Format("Failed to remove {0} from {1}. You can attempt to resolve the issue and try again later.",$ServerName, $DagName)) Red
                    ## Script failed to remove the server from the DAG so we are removing it from the VM list and deleting files
                    $vmServers.Remove($ServerName)
                    Remove-Item -Path $ScriptPath\$ServerName* -Force
                }
                    }
                    else {
                        LogVerbose([string]::Format("{0} is a standalone server}.", $ServerName))
                    }
                }
            }
            if($thumb.Length -gt 1) {
                ## Export the Exchange certificate
                Log([string]::Format("Exporting current Exchange certificate with thumbprint {0} from {1}.", $thumb, $certServer)) Gray
                if(Get-Item "$ScriptPath\$ServerName-Exchange.pfx" -ErrorAction Ignore) { 
                    Remove-Item "$ScriptPath\$ServerName-Exchange.pfx" -Confirm:$False -Force
                }
                $cert = Export-ExchangeCertificate -Server $ExchangeServer -Thumbprint $thumb -BinaryEncoded -Password (ConvertTo-SecureString -String 'Pass@word1' -AsPlainText -Force)
                Set-Content -Path "$ScriptPath\$ServerName-Exchange.pfx" -Value $cert.FileData -Encoding Byte
            }
            $noExchange = $false
        }
        1{
            if($null -eq $forestInstallType -and $forestInstallType -eq 1) {
                $forestInstallType = CheckADForest
            }
            Log([string]::Format("Active Directory domain setup information needed.")) Yellow
            $adSafeModePwd = Read-Host "Please enter the Directory Services restore mode password" -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($adSafeModePwd)            
            $adSafeModePwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            Add-Content -Path $serverVarFile -Value ('AdSafeModePassword = ' + $adSafeModePwd)
            if($null -eq $credential) {
                ##Get a list of available AD sites
                Set-Item WSMan:\localhost\Client\TrustedHosts $domainController -Force
                $ScriptBlock = { Get-ADReplicationSite -Filter * | Format-Table Name }
                Invoke-Command -ComputerName $domainController -ScriptBlock $scriptBlock -Credential $credential
            }
            while($adSiteName.Length -eq 0) {
                $adSiteName = Read-HostWithColor "Enter the Active Directory site name for this DC: "
            }
            Add-Content -Path $serverVarFile -Value ('AdSiteName = ' + $adSiteName)
            ## This is a not an Exchange server so just get information for the VM
            GetServerInfo
            Add-Content -Path $serverVMFileName -Value ('NewVm = 0')
            Log([string]::Format("Getting some information for setting up the new VM.")) Gray
            ## Show a list of available virtual switches
            $switches
            ## Get the virtual switch for the VM
            $vmSwitch = GetNewVMSwitchName
            Add-Content -Path $serverVMFileName -Value ('VmSwitch = ' + $vmSwitch)
            ## Get the amount of memory to assign to the VM
            $vmMemory = GetNewVMMemory
            Add-Content -Path $serverVMFileName -Value ('VmMemory = ' + $vmMemory)
            ## Get the number of processors to assign to the VM
            $vmCPU = GetNewVMCPU
            Add-Content -Path $serverVMFileName -Value ('VmCpus = ' + $vmCPU)
            ## Prompt where to save the VHD for the VM
            $vhdPath = GetNewVMPath
            Add-Content -Path $serverVMFileName -Value ('VmVhdPath = ' + $vhdPath)
            #if(!(GetVMParentDisk)) { GetVMBaseDisk }
            GetVMParentDisk
            $generationResult = GetNewVMGeneration
            Add-Content -Path $serverVMFileName -Value ('VmGeneration = ' + $generationResult)
            ## And also add info for the server install
            Add-Content -Path $serverVarFile -Value ('ServerType = ' + $newInstallType)
            Add-Content -Path $serverVarFile -Value ('NewAdForest = ' + $forestInstallType)
            Add-Content -Path $serverVarFile -Value ('AdDomain = ' + $domain)
            if($forestInstallType -eq 0) {
                Add-Content -Path $serverVarFile -Value ('DomainMode = ' + $domainMode)
                Add-Content -Path $serverVarFile -Value ('ForestMode = ' + $forestMode)
                Add-Content -Path $serverVarFile -Value ('DomainNetBiosName = ' + $netBIOSName)
            }
        }
        2{
            ## This is a not an Exchange server so just get information for the VM
            GetServerInfo
            Add-Content -Path $serverVMFileName -Value ('NewVm = 0')
            Log([string]::Format("Getting some information for setting up the new VM.")) Gray
            ## Show a list of available virtual switches
            $switches
            ## Get the virtual switch for the VM
            $vmSwitch = GetNewVMSwitchName
            Add-Content -Path $serverVMFileName -Value ('VmSwitch = ' + $vmSwitch)
            ## Get the amount of memory to assign to the VM
            $vmMemory = GetNewVMMemory
            Add-Content -Path $serverVMFileName -Value ('VmMemory = ' + $vmMemory)
            ## Get the number of processors to assign to the VM
            $vmCPU = GetNewVMCPU
            Add-Content -Path $serverVMFileName -Value ('VmCpus = ' + $vmCPU)
            ## Prompt where to save the VHD for the VM
            $vhdPath = GetNewVMPath
            Add-Content -Path $serverVMFileName -Value ('VmVhdPath = ' + $vhdPath)
            #if(!(GetVMParentDisk)) { GetVMBaseDisk }
            GetVMParentDisk
            $generationResult = GetNewVMGeneration
            Add-Content -Path $serverVMFileName -Value ('VmGeneration = ' + $generationResult)
            ## And also add info for the server install
            Add-Content -Path $serverVarFile -Value ('ServerType = ' + $newInstallType)
            Add-Content -Path $serverVarFile -Value ('NewAdForest = ' + $forestInstallType)
            Add-Content -Path $serverVarFile -Value ('AdDomain = ' + $domain)
        }
}

## Check if Extended Protection should be enabled
if($newInstallType -eq 0) {
    if($ExtendedProtection) {
        $extendedProtectionEnabled = 0
    }
    else {
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
        $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
        $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $extendedProtectionEnabled = $Host.UI.PromptForChoice("Server deployment script","Do you want to enable Exchange Extended Protection?", $yesNoOption, 0)
    }
    switch ($extendedProtectionEnabled) {
        0 {Add-Content -Path $serverVarFile -Value ('ExchangeExtendedProtection = 0')}
        1 {Add-Content -Path $serverVarFile -Value ('ExchangeExtendedProtection = 1')}
    }
}

## Finalize the psd1 file
Add-Content -Path $serverVarFile -Value ('ExchangeShellServer = ' + $ExchangeServer)
Add-Content -Path $serverVMFileName -Value '###PSLOC'
Add-Content -Path $serverVMFileName -Value "'@"

## Check if another server should be deployed
if($More) {
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $anotherServerResult = $Host.UI.PromptForChoice("Server deployment script","Do you want to deploy another server?", $yesNoOption, 1)
}
else {
    $anotherServerResult = 1
}
if($anotherServerResult -eq 1) {
    $deployServer = $false
}
else {
    $newInstallType = Get-NewServerType
}
## Clear variables before starting next server
$thumb = $null
$ipAddr = $null
$DagName = $null
$forestInstallType = $null
$serverVHD = $null
$vhdPath = $null
$adSiteName = $null
}

## Removing basic authentication from the PowerShell vDir
if(!([String]::IsNullOrEmpty($ExchangeServer))) {
    Log([string]::Format("Removing the Exchange remote PowerShell session.")) Gray
    ## Disconnect from the Exchange remote PowerShell session
    Remove-PSSession -Name ExchangeShell
    Log([string]::Format("Disabling basic authentication on the PowerShell vDir.")) Gray
    $session = New-PSSession -Credential $credential -ComputerName $ExchangeServer -Name DisableBasic
    $scriptBlock = { C:\Windows\system32\inetsrv\appcmd set config "Default Web Site/PowerShell/" /section:basicAuthentication /enabled:false /commit:apphost }
    Invoke-Command -Session $session -ScriptBlock $scriptBlock | Out-Null
    Disconnect-PSSession -Name DisableBasic | Out-Null
    Remove-PSSession -Name DisableBasic | Out-Null
}

## Revert the TrustedHosts list
Log([string]::Format("Clearing trusted hosts.")) Gray
Clear-Item WSMan:\localhost\Client\TrustedHosts -Force

## Revert the hosts file back to the original
Log([string]::Format("Reverting hosts file.")) Gray
Copy-Item "$ScriptPath\hosts-$timeStamp" -Destination  C:\Windows\System32\drivers\etc\hosts -Confirm:$False -Force

if($null -ne $credential) {
    ## Revert the DNS settings back
    Log([string]::Format("Reverting DNS settings.")) Gray
    global:RevertDnsSettings
}

Log([string]::Format("Creating the virtual machines for your deployment.")) Gray
foreach($v in $vmServers) {
    $serverVarFile = "$ScriptPath\$v-ExchangeInstall-strings.psd1"
    ## Compare Exchange versions and add flag to pause for version
    $versionCheck = New-Object System.Collections.ArrayList
    $version = ($exchangeServers | Where-Object {$_.ServerName -eq $v}).Version
    foreach($e in $exchangeServers) {
        if($version -gt $e.Version) {
            $versionCheck.Add($e.Version) | Out-Null
        }
    }
    if($versionCheck.Count -gt 0) {
        $version = ($versionCheck | Measure-Object -Maximum).Maximum
        ## Note the last version of Exchange that this server must check exists
        Add-Content -Path $serverVarFile -Value ('ExchangeVersionCheck = '+ $version)
    }
    ## Finalize the psd1 file
    Add-Content -Path $serverVarFile -Value '###PSLOC'
    Add-Content -Path $serverVarFile -Value "'@"
    
    ## Check to ensure no VM currently exists with the same name
    if($exInstallType -ne 1) {
        if(Get-VM -Name $v -ErrorAction Ignore) {
            Log([string]::Format("Found an existing VM present for {0}.", $v)) Gray
            Log([string]::Format("Removing the existing VM for {0}.", $v)) Gray
            Remove-VM -Name $v
        }
    }
    
    Import-LocalizedData -BindingVariable VM_LocalizedStrings -FileName $v"-VM-strings.psd1" -BaseDirectory $ScriptPath\
    ## Time to work in Hyper-V on the virtual machines
    switch($VM_LocalizedStrings.NewVm) {
        0 { ## Create a new virtual machine using the settings provided
            [int]$vmGen = [int]$VM_LocalizedStrings.VmGeneration + 1
            New-VM -Name $v -MemoryStartupBytes $VM_LocalizedStrings.VmMemory -SwitchName $VM_LocalizedStrings.VmSwitch -NoVHD -BootDevice CD -Generation $vmGen | Out-Null
            Set-VM -ProcessorCount $VM_LocalizedStrings.VmCpus -Name $v
            $vhdPath = $VM_LocalizedStrings.VmVhdPath
            $vhdParentPath = $VM_LocalizedStrings.VmParentVhdPath
            if($vmGen -eq 1) {
                $vmDiskCL = 0
                $vmDiskCN = 0
            }
            else {
                $vmDiskCL = 1
                $vmDiskCN = 0
            }
        }
        1 { ## Stop the existing virtual machine and remove the current disk
            Log([string]::Format("Stopping {0} virtual machine.", $v)) Gray
            Stop-VM $v -Force -TurnOff
            Log([string]::Format("Updating VM disk configuration.")) Gray
            [string]$vhdPath = ((Get-VMFirmware $v).BootOrder | Where-Object {$_.Device -like "HardDiskDrive*"}).Device[0].Path
            $vmHDD = Get-VMHardDiskDrive -VMName $v | Where-Object {$_.Path -eq $vhdPath}
            $vmDiskCL = $vmHDD.ControllerLocation
            $vmDiskCN = $vmHDD.ControllerNumber
            Log([string]::Format("Deleting the existing VHD file.")) Gray
            Remove-Item -Path $vhdPath -Force
            Log([string]::Format("Removing the orginal hard drive from the virtual machine {0}.", $v)) Gray
            Remove-VMHardDiskDrive -VMName $v -ControllerType $vmHDD.ControllerType -ControllerNumber $vmDiskCN -ControllerLocation $vmDiskCL
            [int]$vmGen = (Get-VM -Name $v).Generation
        }
    }
    
    Log([string]::Format("Assigning the ISO to the CD drive for the VM.")) Gray
    $vmDvd = Get-VMDvdDrive -VMName $v
    while($vmDvd.Path -ne $VM_LocalizedStrings.ExchangeIsoPath) {
        $vmDvd | Set-VMDvdDrive -Path $VM_LocalizedStrings.ExchangeIsoPath #-ControllerNumber $vmDvd.ControllerNumber $vmDvd.ControllerLocation
    }
    ## VM disk configuration
    #if($vhdParentPath.Length -gt 0) {
    if($null -ne $VM_LocalizedStrings.VmParentVhdPath){
        New-VHD -ParentPath $VM_LocalizedStrings.VmParentVhdPath -Path $vhdPath -Differencing
    }
    else {
        Log([string]::Format("Copying the base Windows VHD to the destination VHD path.")) Gray
        Copy-Item -Path $VM_LocalizedStrings.ServerVhdPath -Destination $vhdPath
        Log([string]::Format("Removing the read-only flag on the VHD file.")) Gray
        Set-ItemProperty -Path $vhdPath -Name IsReadOnly -Value $False
    }
    Log([string]::Format("Adding the new hard drive to the virtual machine {0}.", $v)) Gray
    if($vmGen -eq 2) {
        Add-VMHardDiskDrive -VMName $v -Path $vhdPath -ControllerType SCSI -ControllerNumber $vmDiskCN -ControllerLocation $vmDiskCL -ComputerName localhost -Confirm:$False
        Set-VMFirmware $v -BootOrder $(Get-VMDvdDrive -VMName $v -ControllerNumber $vmDvd.ControllerNumber -ControllerLocation $vmDvd.ControllerLocation), $(Get-VMHardDiskDrive -VMName $v -ControllerType SCSI -ControllerLocation $vmDiskCL -ControllerNumber $vmDiskCN)
    }
    else {
        Add-VMHardDiskDrive -VMName $v -Path $vhdPath -ControllerType IDE -ControllerNumber 0 -ControllerLocation 0 -ComputerName localhost -Confirm:$False
    }
    Log([string]::Format("Copying files to the virtual machine.")) Gray
    $Vhd = (Mount-VHD -Path $vhdPath -PassThru | Get-Disk | Get-Partition | Get-Volume |Where-Object {$_.DriveLetter -ne $null}).DriveLetter
    if($Vhd -like $null) {
        $DiskPartition = Get-Partition -DiskNumber (Get-Disk -FriendlyName "Msft Virtual Disk").Number | Where-Object {$_.Type -eq "Basic"}
        $DiskPartition | Add-PartitionAccessPath -AssignDriveLetter:$True
        $Vhd = (Get-Partition -DiskNumber (Get-Disk -FriendlyName "Msft Virtual Disk").Number | Where-Object {$_.Type -eq "Basic"}).DriveLetter
    }
    if(!(Get-Item "$($vhd):\Temp" -ErrorAction SilentlyContinue)) {New-Item -Path "$($vhd):\" -Name Temp -ItemType Directory}
    $ServerTemp = "$($Vhd):\Temp"
    Move-Item $ScriptPath\$v* -Destination $ServerTemp -Force -Confirm:$False -ErrorAction Ignore
    Copy-Item $ScriptPath\Deploy*.ps1 -Destination $ServerTemp -Force -Confirm:$False -ErrorAction Ignore
    Copy-Item $ScriptPath\Start-Setup.ps1 -Destination $ServerTemp -Force -Confirm:$False -ErrorAction Ignore
    Dismount-VHD -Path $vhdPath
    Log([string]::Format("Starting the virtual machine {0}.", $v)) Gray
    Start-VM -Name $v
    Remove-Item $ScriptPath\hosts-$timeStamp -Confirm:$False -ErrorAction Ignore
}
