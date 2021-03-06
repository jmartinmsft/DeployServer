﻿<#
# Deploy-Server.ps1
# Modified 2020/10/31
# Last Modifier:  Jim Martin
# Project Owner:  Jim Martin
# Version: v1.3

# Syntax for running this script:
#
# .\Deploy-Server.ps1
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
#>
Clear-Host
function Check-ExchangeVersion {
    $latestVersion = 0
    Get-ExchangeServer | ForEach-Object {
        [int]$serverVersion = $_.AdminDisplayVersion.Substring(11,1)
        if($serverVersion -gt $latestVersion) {
            $latestVersion = $serverVersion
        }
    }
    return $latestVersion
}
function Move-MailboxDatabase {
    param ( [Parameter(Mandatory=$true)][string]$database )
    $stopDbCheck = $false
    $bestEffort = $false
    while($stopDbCheck -eq $false) {
        $copyStatus = Get-MailboxDatabaseCopyStatus $database | Where {$_.Status -ne "Mounted"}
        [string]$healthyCopy = $null
        foreach($c in $copyStatus) {
            if($c.ContentIndexState -eq "Healthy" -and $c.CopyQueueLength -eq 0 -and $c.Status -eq "Healthy") {
                $healthyCopy = $c.Name
                $healthyCopy = $healthyCopy.Substring($healthyCopy.IndexOf("\")+1)
                $stopDbCheck = $true
                break
            }
        }
        if($healthyCopy.Length -eq 0) {
            Write-Warning "No server has a healthy copy to activate."
            Start-Sleep -Seconds 2
            return $false
        }
    }
    Write-Host "Moving database to $healthyCopy" -ForegroundColor Green
    $moveSuccess = (Move-ActiveMailboxDatabase $database -ActivateOnServer $healthyCopy).Status
    $moveSuccess = ($moveSuccess | Out-String).Trim()
    if($moveSuccess -eq "Succeeded") {
        Sync-AdConfigPartition
        return $true 
    }
    return $false
}
function Move-MailboxDatabaseBestEffort {
    param ( [Parameter(Mandatory=$true)][string]$database)
    $stopDbCheck = $false
    $bestEffort = $false
    while($stopDbCheck -eq $false) {
        $copyStatus = Get-MailboxDatabaseCopyStatus $database | Where {$_.Status -ne "Mounted"}
        [string]$healthyCopy = $null
        foreach($c in $copyStatus) {
            if($c.Status -eq "Healthy") {
                $healthyCopy = $c.Name
                $healthyCopy = $healthyCopy.Substring($healthyCopy.IndexOf("\")+1)
                $stopDbCheck = $true
                break
            }
        }
        if($healthyCopy.Length -eq 0) {
            Write-Warning "No server has a healthy copy to activate."
            Start-Sleep -Seconds 2
            return $false
        }
    }
    if($healthyCopy -ne $null) {
        Write-Host "Moving database to $healthyCopy with best effort" -ForegroundColor Green
        if(Test-Connection $healthyCopy -Count 1) {
            $moveSuccess = (Move-ActiveMailboxDatabase $database -SkipClientExperienceChecks -MountDialOverride:BestEffort -SkipHealthChecks -Confirm:$False -ErrorAction SilentlyContinue).Status
        }
        else {
            if((Get-MailboxDatabaseCopyStatus $database).Status -notcontains "Mounted") {
                $moveSuccess = (Move-ActiveMailboxDatabase $database -Confirm:$False -SkipActiveCopyChecks -MountDialOverride:BestEffort -SkipClientExperienceChecks).Status
            }
            else {
                $moveSuccess = (Move-ActiveMailboxDatabase $database -Confirm:$False -SkipActiveCopyChecks -SkipClientExperienceChecks -MountDialOverride:BestEffort).Status
            }
        }
        $moveSuccess = ($moveSuccess | Out-String).Trim()
        if($moveSuccess -eq "Succeeded") { 
            Sync-AdConfigPartition
            return $true
        }
    }
    return $false
}

function Get-ExchangeISO {
        Write-Host "Please select the Exchange ISO" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{InitialDirectory="M:\ISO"; Title="Select the Exchange ISO"}
        $fileBrowser.Filter = "ISO (*.iso)| *.iso"
        $fileBrowser.ShowDialog()
        [string]$exoISO = $fileBrowser.FileName
        $exoISO = $exoISO.Replace("\","\\")
        Add-Content -Path $serverVMFileName -Value ('res_0001 = ' + $exoISO)
}

function Get-DAGIPAddress {
    ## There must be at least one IP address for the DAG but there may be more
    $dagIPAddresses = New-Object System.Collections.ArrayList
    $checkDagIP = $null
    [int]$x = 1 ## Count for the number of DAG IP addresses
    $addDagIP = $true
    ## Add IP addresses for the DAG until a null value is supplied
    while($addDagIP -eq $true) {
        $ipCheck = $null
        ## Get input from the user
        $dagIPAddress = AskFor-DAGIPAddress $x
        ## Verify the format of the input
        if($dagIPAddress.Length -ne 0) {
            $ipCheck = Test-IP($dagIPAddress)
            ## Verify the IP address is not in use
            if($ipCheck -ne $null) {
                if(Test-Connection $dagIPAddress -Count 1 -ErrorAction Ignore) {
                    Write-Warning "IP addresses provided already in use"
                    $dagIPAddress = $null
                }
            }
            ## Invalid input
            else { $dagIPAddress = $null}
            ## Make sure there is a value before adding to the IP array
            if($dagIPAddress.Length -gt 0) {
                $dagIPAddresses.Add($dagIPAddress) | Out-Null
                $x++
                $checkDagIP = $null
            }
        }
        else {
            ## Make sure there is at least one IP address before exiting
            if($dagIPAddresses.Count -gt 0) {
                $addDagIP = $false
            }
        }
    }
    Add-Content -Path $serverVarFile -Value ('res_0033 = ' + $dagIPAddresses)
}
function AskFor-DAGIPAddress {
    param([int]$ipCount)
    $dagIP = $null
    $dagIP = Read-HostWithColor "Enter the Database Availability Group IP Addresses[$ipCount]: "
    return $dagIP
}

function Get-DomainControllers {
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

function Get-VMParentDisk {
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $differencingOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $differencingResult= $Host.UI.PromptForChoice("Server deployment script","Do you want to use a differencing disk?", $differencingOption, 0)
    if($differencingResult -eq 0) {
        ## Get the parent disk
        Write-Host "Please select the parent VHD disk" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        while($parentVHD.Length -eq 0) {
            $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{InitialDirectory="M:\VHDs"; Title="Select the parent VHD"}
            $fileBrowser.Filter = "VHDX (*.vhdx)| *.vhdx"
            $fileBrowser.ShowDialog()
            [string]$parentVHD = $fileBrowser.FileName
        }
        $parentVHD = $parentVHD.Replace("\","\\")
        Add-Content -Path $serverVMFileName -Value ('res_0009 = ' + $parentVHD)
        return $true
    }
    else {return $false}
}

function Get-VMBaseDisk {
    ## Get the base VHD
    Write-Host "Please select the base VHD image" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    while($serverVHD.Length -eq 0) {
        $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{InitialDirectory="M:\VHDs"; Title="Select the Exchange VHD"}
        $fileBrowser.Filter = "VHDX (*.vhdx)| *.vhdx"
        $fileBrowser.ShowDialog()
        [string]$serverVHD = $fileBrowser.FileName
    }
    $serverVHD = $serverVHD.Replace("\","\\")
    Add-Content -Path $serverVMFileName -Value ('res_0002 = ' + $serverVHD)    
}

function Get-NewVMGeneration {
    $gen1 = New-Object System.Management.Automation.Host.ChoiceDescription 'Generation &1', '1'
    $gen2 = New-Object System.Management.Automation.Host.ChoiceDescription 'Generation &2', '2'
    $generationOption = [System.Management.Automation.Host.ChoiceDescription[]]($gen1, $gen2)
    $generationResult= $Host.UI.PromptForChoice("Server deployment script","What generation virtual machine do you want to create?", $generationOption, 1)
    return $generationResult        
}

function Get-NewVMPath {
    Write-Host "Select the location for the new server VHD" -ForegroundColor Yellow
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location for your virtual hard disk"
    $folderBrowser.SelectedPath = "C:\Hyper-V"
    $folderPath = $folderBrowser.ShowDialog()
    $vhdPath = $folderBrowser.SelectedPath
    $vhdPath = $vhdPath + "\$ServerName.vhdx"
    $vhdPath = $vhdPath.Replace("\","\\")
    return $vhdPath
}

function Get-NewVMCPU {
    $vmCPU = 0
    while($vmCPU -eq 0) {
        [int]$vmCPU = Read-HostWithColor "Please enter the number of CPUs: "
    }
    return $vmCPU       
}

function Get-NewVMMemory {
    $vmMemory = 0
    while($vmMemory -eq 0) {
        [int64]$vmMemory = Read-HostWithColor "Please enter the amount of memory (GB): "
        $vmMemory = $vmMemory*1024*1024*1024
    }
    return $vmMemory
}

function Get-NewVMSwitchName {
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

function Check-Credentials {
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
        Write-Host "Getting your lab credentials using the UPN..." -ForegroundColor Green
        $adminCred = Get-Credential -Message "Enter the lab domain credentials using UPN"
        if($adminCred.UserName -like "*@*" -and $adminCred.UserName -like "*.*") {
            $validUPN = $true
        }
        else { 
            Write-Host "Please enter the username in UPN format." -ForegroundColor Yellow
            Start-Sleep -Seconds 3
        }
    }
    return $adminCred
}

function Prepare-ExchangeConnect {
    $basicEnabled = $false
    while($basicEnabled -eq $false) {
        [string]$exchServer = Read-HostWithColor "Enter an Exchange Server to connect: "
        ## Add the Exchange server to the hosts file to ensure we don't have name resolution issues
        if($exchServer -notlike "*.*") {
            $dnsHost = "$exchServer.$domain"
            $hostIP = (Resolve-DnsName -Name $dnsHost -Server $tempDNS).IPAddress
            Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $dnsHost"
            Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $exchServer"
        }
        else { 
            $dnsHost = $exchServer 
            $hostIP = (Resolve-DnsName -Name $dnsHost -Server $tempDNS).IPAddress
            Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $dnsHost"
            $dnsHost = $dnsHost.Substring(0, $dnsHost.IndexOf("."))
            Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $dnsHost"
        }
        $basicEnabled = Enable-BasicAuthentication
    }
    return $exchServer
}

function Connect-Exchange {
    Write-Host "Connecting to Exchange remote PowerShell session..." -ForegroundColor Green
    try { Import-PSSession (New-PSSession -Name ExchangeShell -ConfigurationName Microsoft.Exchange -ConnectionUri https://$exchServer/PowerShell -AllowRedirection -Authentication Basic -Credential $credential -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck) -ErrorAction Ignore) -AllowClobber -ErrorAction Ignore}
    catch { Write-Warning "Connection attempt to $exchServer failed. Retrying..."
        Start-Sleep -Seconds 5
        Connect-Exchange
    }
}

function Enable-BasicAuthentication {
    ## Add the Exchange server to the TrustedHosts list for WinRM
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $exchServer -Force
    ## Connect to the Exchange server to enable Basic authentication on the PowerShell vDir
    Write-Host "Enabling basic authentication on the PowerShell vDir temporarily..." -ForegroundColor Green -NoNewline
    $session = $null
    $session = New-PSSession -Credential $credential -ComputerName $exchServer -Name EnableBasic -ErrorAction SilentlyContinue
    if($session -eq $null) {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "Unable to enable basic authentication on $exchServer. Please try another server." -ForegroundColor Red
        return $false
    }
    Write-Host "COMPLETE"
    $scriptBlock = { C:\Windows\system32\inetsrv\appcmd set config "Default Web Site/PowerShell/" /section:basicAuthentication /enabled:true /commit:apphost }
    Invoke-Command -Session $session -ScriptBlock $scriptBlock | Out-Null
    Disconnect-PSSession -Name EnableBasic | Out-Null
    Remove-PSSession -Name EnableBasic | Out-Null
    return $true
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
 
function Select-ExchangeVersion {
    ## Select the version of Exchange to be installed
    $ex15 = New-Object System.Management.Automation.Host.ChoiceDescription 'Exchange 201&3', 'Exchange version: Exchange 2013'
    $ex16 = New-Object System.Management.Automation.Host.ChoiceDescription 'Exchange 201&6', 'Exchange version: Exchange 2016'
    $ex19 = New-Object System.Management.Automation.Host.ChoiceDescription 'Exchange 201&9', 'Exchange version: Exchange 2019'
    $exOption = [System.Management.Automation.Host.ChoiceDescription[]]($ex15, $ex16, $ex19)
    $exVersion = $Host.UI.PromptForChoice("Server deployment script","What version of Exchange are you installing", $exOption, 2)
    Add-Content -Path $serverVarFile -Value ('res_0003 = ' + $exVersion)
    return $exVersion
}

function Get-MailboxDatabaseStatus {
    ## Check to see if the database is mounted on the server being restored
    param ([Parameter(Mandatory=$true)][string]$database)
    if((Get-MailboxDatabase $database -DomainController $domainController -Status).MountedOnServer -like '*' + $ServerName + '*') {
        return $true
    }
    return $false
}

function PressAnyKeyToContinue ($Message=”Unable to move a mailbox database. Please check for errors and then press any key to continue...”) {
    Write-Host -NoNewLine $Message -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey(“NoEcho,IncludeKeyDown”)
    Write-Host “”
}

function Sync-AdConfigPartition {
    ## Synchronize the Configuration partition of Active Directory across all replication partners
    $repUser = "$domain\$UserName"
    Get-ADReplicationConnection -Filter * -Server $domainController -Credential $credential | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        [string]$configPartition = ($_.ReplicateToDirectoryServer).Substring($_.ReplicateToDirectoryServer.IndexOf("CN=Configuration"))
        $ScriptBlock = { Param ($param1,$param2,$param3,$param4,$param5) repadmin /replicate $param1 $param2 "$param3" /u:$param4 /pw:$param5 /force }
        Invoke-Command  -ComputerName $exchServer -ScriptBlock $scriptBlock -Credential $credential -ArgumentList $fromServer, $toServer, $configPartition, $repUser, $Password | Out-Null
    }
}

function Get-ServerInfo {
    ## Prompt the user for IP configuration for the Exchange server
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $dhcpOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $dhcpResult= $Host.UI.PromptForChoice("Server deployment script","Do you want to enable DHCP for this server?", $dhcpOption, 1)
    switch($dhcpResult) {
        0 { Add-Content -Path $serverVarFile -Value ('res_0026 = 1') 
            $dnsOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $dnsResult= $Host.UI.PromptForChoice("Server deployment script","Do you want to manually assign DNS?", $dnsOption, 1)
            Add-Content -Path $serverVarFile -Value ('res_0027 = ' + $dnsResult) 
            if($dnsResult -eq 0) {
                Get-PrimaryDNS
                Get-SecondaryDNS
            }
        }
        1 { $IpAddress = $null
            while($IpAddress -eq $null) {
                $IpAddress = Test-IP(Read-HostWithColor "Enter the server IP address: ")
                if(Test-Connection $IpAddress -Count 1 -ErrorAction Ignore) {
                    Write-Warning "IP addresses provided already in use"
                    $IpAddress = $null
                }
            }
            Add-Content -Path $serverVarFile -Value ('res_0007 = ' + $IpAddress)
            $SubnetMask = $null
            while($SubnetMask -eq $null) {
                $SubnetMask = Test-IP(Read-HostWithColor "Enter the subnet mask: ")
            }
            [int]$SubnetMaskPrefixLength = Convert-RvNetSubnetMaskClassesToCidr $SubnetMask
            Add-Content -Path $serverVarFile -Value ('res_0008 = ' + $SubnetMaskPrefixLength)
            $Gateway = $null
            while($Gateway -eq $null) {
                $Gateway = Test-IP(Read-HostWithColor "Enter the default gateway: ")
            }
            Add-Content -Path $serverVarFile -Value ('res_0009 = ' + $Gateway)
            Get-PrimaryDNS
            Get-SecondaryDNS
        }
    }
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

function Convert-RvNetIpAddressToInt64 {
## Convert IP address to integer
    param 
    ( 
        [string] 
        $IpAddress 
    ) 
    $ipAddressParts = $IpAddress.Split('.') # IP to it's octets 
    [int64]([int64]$ipAddressParts[0] * 16777216 + 
    [int64]$ipAddressParts[1] * 65536 + 
    [int64]$ipAddressParts[2] * 256 + 
    [int64]$ipAddressParts[3]) 
} 
 
function Convert-RvNetSubnetMaskClassesToCidr { 
    param ( [string] $SubnetMask ) 
    ## Convert the subnet mask into prefix length
    [int64]$subnetMaskInt64 = Convert-RvNetIpAddressToInt64 -IpAddress $SubnetMask 
    $subnetMaskCidr32Int = 2147483648 # 0x80000000 - Same as Convert-RvNetIpAddressToInt64 -IpAddress '255.255.255.255' 
    $subnetMaskCidr = 0 
    for ($i = 0; $i -lt 32; $i++) { 
        if (!($subnetMaskInt64 -band $subnetMaskCidr32Int) -eq $subnetMaskCidr32Int) { break } # Bitwise and operator - Same as "&" in C# 
        $subnetMaskCidr++ 
        $subnetMaskCidr32Int = $subnetMaskCidr32Int -shr 1 # Bit shift to the right - Same as ">>" in C# 
    } 
    return $subnetMaskCidr 
}

function Get-PrimaryDNS {
    ## Ensure the primary DNS server is provided
    $PrimaryDNS = $null
    while($PrimaryDNS -eq $null) {
        $PrimaryDNS = Test-IP(Read-HostWithColor "Enter the Primary DNS server address: ")
    }
    Add-Content -Path $serverVarFile -Value ('res_0010 = ' + $PrimaryDNS)
}

function Get-SecondaryDNS {
    ## Secondary DNS value may be empty
    $checkDNS = $null
    $secondaryDNS = AskFor-SecondaryDNS
    if($secondaryDNS.Length -ne 0) {
        $checkDNS = Test-IP($secondaryDNS)
        ## Check if secondary DNS value is present
        while($checkDNS -eq $null) {
            $secondaryDNS = AskFor-SecondaryDNS
            if($secondaryDNS.Length -eq 0) {
                $secondaryDNS =  $null
                break
            }
            $checkDNS = Test-IP($secondaryDNS)
        }
    }
    Add-Content -Path $serverVarFile -Value ('res_0011 = ' + $SecondaryDNS)
}

function AskFor-SecondaryDNS() {
## Request secondary DNS server from user
    $secondDNS = $null
    $secondDNS = Read-HostWithColor "Enter the Secondary DNS server address: "
    return $secondDNS
}

function Validate-DagName {
    ## Verify the DAG name provided is present
    if((Get-DatabaseAvailabilityGroup $DagName -ErrorAction SilentlyContinue).Name -ne $null) { return $true }
    else { return $false }
}

function Get-CertificateFromServerCheck {
    ## Check if the Exchange certificate from server where the script is running should be used
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $certResult = $Host.UI.PromptForChoice("Server deployment script","Would you like to import the Exchange certificate from this server onto the new Exchange server?", $yesNoOption, 0)
    if($certResult -eq 0) { return $true }
    else { return $false }
}

function Get-ServerCertificate {
    ## Determine the SSL binding information for the Default Web Site
    $scriptBlock = { Import-Module WebAdministration;
        (Get-WebBinding -Name "Default Web Site" -Protocol https | Where {$_.bindingInformation -eq ":443:" }).certificateHash
    }
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $certServer -Force
    $session = New-PSSession -Credential $credential -ComputerName $certServer -Name CertificateConfig
    [string]$thumbprint = (Invoke-Command -Session $session -ScriptBlock $scriptBlock)
    $scriptBlock = { Get-ChildItem -Path "Cert:\LocalMachine\My\" -Recurse  }
    $certs = Invoke-Command -Session $session -ScriptBlock $scriptBlock
    foreach($c in $certs) {
        if($c.Thumbprint -eq $thumbprint) {
            if($c.Subject -like "*$certServer*") {
                Write-Host "COMPLETE"
                Write-Host "Current certificate is self-signed certificate and cannot be used" -ForegroundColor Yellow
                $exportCert = $false
            }
        }
    }
    if($exportCert -eq $false) { return $null }
    else { 
        Add-Content -Path $serverVarFile -Value ('res_0002 = ' + $thumbprint)
        $thumbprint = $thumbprint | Out-String
         return $thumbprint
        
    }
    Disconnect-PSSession -Name CertificateConfig
    Remove-PSSession -Name CertificateConfig
    
    }

function Check-ServerOnline {
    if(Test-Connection $ServerName -ErrorAction Ignore -Count 1) { return $true }
    else { return $false }
}

function Create-NewDAG {
    ## Get information for create a new database availability group
    $DagName = Read-HostWithColor "Enter the name for the new Database Availability Group: "
    Add-Content -Path $serverVarFile -Value ('res_0001 = ' + $DagName)
    $witnessServer = Read-HostWithColor "Enter the name of the witness server: "
    Add-Content -Path $serverVarFile -Value ('res_0018 = ' + $witnessServer)
    $witnessDirectory = Read-HostWithColor "Enter the path for the witness directory: "
    $witnessDirectory = $witnessDirectory.Replace("\","\\")
    Add-Content -Path $serverVarFile -Value ('res_0019 = ' + $witnessDirectory)
}

function Skip-DagCheck {
    ## Don't verify the existence of the DAG for multiple server deployments
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $continueResult= $Host.UI.PromptForChoice("Exchange Database Availability Group not found.","Do you want to continue?", $yesNoOption, 0)
    if($continueResult -eq 0) {
        Write-Warning "You should verify the DAG exists prior to starting the next step"
        return $true
    }
    return $false
}

function Check-NewDeployment {
    ## If this is a new deployment of multiple servers we may not was to validate the DAG
    $validDag = Skip-DagCheck
    if($validDag -eq $false) {
        Create-NewDAG 
    }
    else {
        $DagName = Read-HostWithColor "Enter the Database Availability Group name: "
        Add-Content -Path $serverVarFile -Value ('res_0001 = ' + $DagName)
    }
}

function Create-ServerVariableFile {
    ## Create psd1 with variables for the VM to use for setup
    $serverVarFileName = "c:\Temp\$ServerName-ExchangeInstall-strings.psd1"
    New-Item -Name "Temp" -ItemType Directory -Path "c:\" -ErrorAction SilentlyContinue | Out-Null
    New-Item $serverVarFileName -ItemType File -ErrorAction SilentlyContinue | Out-Null
    Add-Content -Path $serverVarFileName -Value "ConvertFrom-StringData @'"
    Add-Content -Path $serverVarFileName -Value '###PSLOC'
    return $serverVarFileName
}

function Create-VMVariableFile {
    ## Create psd1 with variables for the VM to use for setup
    $serverVMFileName = "c:\Temp\$ServerName-VM-strings.psd1"
    New-Item -Name "Temp" -ItemType Directory -Path "c:\" -ErrorAction SilentlyContinue | Out-Null
    New-Item $serverVMFileName -ItemType File -ErrorAction SilentlyContinue | Out-Null
    Add-Content -Path $serverVMFileName -Value "ConvertFrom-StringData @'"
    Add-Content -Path $serverVMFileName -Value '###PSLOC'
    return $serverVMFileName
}

function Get-NewServerType {
    ## Prompt for the type of new server for deployment
    $newExchange = New-Object System.Management.Automation.Host.ChoiceDescription '&Exchange Server', 'Exchange Server'
    $newDomainController = New-Object System.Management.Automation.Host.ChoiceDescription '&Domain Controller', 'Domain Controller'
    $newInstallOption = [System.Management.Automation.Host.ChoiceDescription[]]($newExchange, $newDomainController)
    $newInstallType = $Host.UI.PromptForChoice("Server deployment script","Select the type of server to deploy:", $newInstallOption, 0)
    return $newInstallType
}

function Check-ADForest {
    ##We need to determine if this is a new forest
    $newForest = New-Object System.Management.Automation.Host.ChoiceDescription '&New', 'New'
    $existingForest = New-Object System.Management.Automation.Host.ChoiceDescription '&Existing', 'Existing'
    $forestOption = [System.Management.Automation.Host.ChoiceDescription[]]($newForest, $existingForest)
    $forestInstallType = $Host.UI.PromptForChoice("Server deployment script","Is this a new or existing Active Directory forest:", $forestOption, 0)
    return $forestInstallType
}

## Create an array to store all the VM server names
$vmServers = New-Object System.Collections.ArrayList
## Create an array to store Exchange servers and version
$exchangeServers = New-Object System.Collections.ArrayList

$newInstallType = Get-NewServerType

if($newInstallType -eq 1) {
    $forestInstallType = Check-ADForest
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
                Write-Host "You can select a forest mode that is greater than the domain mode." -ForegroundColor Yellow -BackgroundColor Black
            }
            else { $validForest = $true }
        }
        $sampleNetBIOS = $domain.Substring(0, $domain.IndexOf("."))
        $netBIOSName = (Read-Host "Please enter the NetBIOS name for the domain ($sampleNetBIOS) ").ToUpper()
    }
    $UserName = "Administrator"
}

if($forestInstallType -eq 1 -or $newInstallType -eq 0) {
    Write-Host "Preparing your host machine..." -ForegroundColor Green
    ## Update DNS settings on VM host so it can communicate with the lab
    $tempDNS = $null
    while($tempDNS -eq $null) {
        $tempDNS = Test-IP(Read-HostWithColor "Enter the IP address for your lab DNS server: ")
    }
    Write-Host "Updating DNS settings..." -ForegroundColor Green -NoNewline
    $netIPConfig = Get-NetIPConfiguration | Where {$_.Ipv4DefaultGateway.NextHop -ne $null}
    $netAdapter = $netIPConfig.InterfaceIndex
    $dnsServers = $netIPConfig.DNSServer | Where {$_.AddressFamily -eq 2}
    Set-DnsClientServerAddress -InterfaceIndex $netIPConfig.InterfaceIndex -ServerAddresses $tempDNS
    Write-Host "COMPLETE"

    ## Ensure the AD PowerShell module is installed
    Write-Host "Checking for prerequisites..." -ForegroundColor Green
    if(!(Get-WindowsFeature RSAT-AD-PowerShell).Installed) {
        Write-Host "Installing Active Directory PowerShell module..." -ForegroundColor Green
        Install-WindowsFeature -Name RSAT-AD-PowerShell | Out-Null
    }

    ## Get variables from the admin
    $validUPN = $false
    while($validUPN -eq $false) {
        $credential = Get-AdminCredential
        if($credential.UserName -like "*@*" -and $credential.UserName -like "*.*") {
            ## validate credentials
            $UserName = $Credential.UserName.Substring(0, $Credential.UserName.IndexOf("@"))
            $domain = $credential.UserName.Substring($credential.UserName.IndexOf("@")+1)
            $validDomain =$false
            while($validDomain -eq $false) {
                [string]$domainController = (Resolve-DnsName $domain -Type SOA -Server $tempDNS -ErrorAction Ignore).IP4Address
                if($domainController -eq $tempDNS) {
                    $validDomain = $true
                    if(Check-Credentials) {
                        $validUPN = $true
                    }
                    else {
                        Write-Warning "Unable to verify your credentials. Please try again."
                        Start-Sleep -Seconds 2
                    }
                }
                else {
                    Write-Host "Unable to resolve the domain from the UPN." -ForegroundColor Red
                    $domain = Read-Host "Please enter the domain for your Exchange forest: "
                }
            }
        }
        else { 
            Write-Warning "Please enter the username in UPN format."
            Start-Sleep -Seconds 3
        }
    }
    [string]$domainController = (Resolve-DnsName $domain -Type SRV -Server $tempDNS -ErrorAction Ignore).PrimaryServer
    $Password = $credential.GetNetworkCredential().Password

    ## Adding hosts file entries to ensure proper name resolution
    $hostsFile = Get-Content C:\Windows\System32\drivers\etc\hosts
    Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "`r`n"
    $domainControllers = Resolve-DnsName -Name "_gc._tcp.$domain" -Type SRV -Server $tempDNS | where { $_.Name -notlike "_gc._tcp*" }
    foreach($dc in $domainControllers) { 
        [string]$newLine = $dc.IPAddress + " " + $dc.Name; 
        Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value $newLine
    }
    ## Check if the account is a member of domain admins
    Write-Host "Checking account permissions..." -ForegroundColor Green
    Write-Host "Using $UserName from the $Domain domain for the install" -ForegroundColor Cyan
    $isDomainAdmin = $false
    Get-ADGroupMember "Domain Admins" -Server $domainController -Credential $credential | ForEach-Object { if((Get-ADObject $_ -Properties SamAccountName -Server $domainController -Credential $credential).SamAccountName -eq $UserName) { $isDomainAdmin = $true }}
    if($isDomainAdmin -eq $false) {
        Write-Host "Your account is not a member of the Domain Admins group. Please update group membership prior to running the next step." -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
    ## Check if the account is a member of schema admins
    $isSchemaAdmin = $false
    Get-ADGroupMember "Schema Admins" -Server $domainController -Credential $credential | ForEach-Object { if((Get-ADObject $_ -Properties SamAccountName -Server $domainController -Credential $credential).SamAccountName -eq $UserName) { $isSchemaAdmin = $true }}
    if($isSchemaAdmin -eq $false) {
        Write-Host "Your account is not a member of the Schema Admins group. Please update group membership or ensure the schema has been updated prior to running the next step." -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}

$deployServer = $true
$switches = Get-VMSwitch | ft Name,SwitchType
while($deployServer -eq $true) {
    $adapterCheck = $true
    while($adapterCheck) {
        [string]$ServerName = Read-HostWithColor "Enter the name of the server to deploy: "
        $serverOnline = $false
        ## Do not recover a server with multiple NICs, install process currently cannot handle that scenario
        if(Get-VM $ServerName -ErrorAction Ignore) {
            $exInstallType = 1
            $vmAdapters = Get-VMNetworkAdapter -VMName $ServerName
            if($vmAdapters.Count -gt 1) {
                Write-Host "This deployment process currently only supports one network adapter." -ForegroundColor Yellow
                Write-Host "This machine is currently connected to:" -ForegroundColor Yellow
                for([int]$a=0; $a -lt $vmAdapters.Count; $a++) {
                    Write-Host $vmAdapters[$a].SwitchName "-" $vmAdapters[$a].IPAddresses
                }
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                $retryOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                $retryType = $Host.UI.PromptForChoice("Server deployment script","Do you want to deploy a different server:", $retryOption, 0)
                if($retryType -eq 1) { exit }
            }
            else { $adapterCheck = $false }
        }
        else { 
            $exInstallType = 0 
            $adapterCheck = $false
        }
    }
    $vmServers.Add($ServerName) | Out-Null
    $serverVarFile = Create-ServerVariableFile
    Add-Content -Path $serverVarFile -Value ('res_0000 = ' + $ServerName)
    Add-Content -Path $serverVarFile -Value ('res_0012 = ' + $Password)
    Add-Content -Path $serverVarFile -Value ('res_0014 = ' + $domain)
    ## Check if new AD forest was created and set the domain admin account
    if($credential -eq $null -or $forestInstallType -eq 0) { # -and $newInstallType -eq 0) {
        Add-Content -Path $serverVarFile -Value ('res_0031 = ' + $vmServers[0])
        Add-Content -Path $serverVarFile -Value ('res_0013 = Administrator')
    }
    else {
        Add-Content -Path $serverVarFile -Value ('res_0031 = ' + $domainController)
        Add-Content -Path $serverVarFile -Value ('res_0013 = ' + $UserName)
    }

    ## Creating a variable file to store VM information
    $serverVMFileName = Create-VMVariableFile
    
    Add-Type -AssemblyName System.Windows.Forms

    ## Check if ipV6 should be disabled
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $ipV6Result = $Host.UI.PromptForChoice("Server deployment script","Do you want to disable IPv6 on this server?", $yesNoOption, 0)
    Add-Content -Path $serverVarFile -Value ('res_0006 = ' + $ipV6Result)

    if($newInstallType -eq 1) {
        if($forestInstallType -eq $null) {
            $forestInstallType = Check-ADForest
        }
        Write-Host "Active Directory domain setup information needed..." -ForegroundColor Yellow
        $adSafeModePwd = Read-Host "Please enter the Directory Services restore mode password" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($adSafeModePwd)            
        $adSafeModePwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        Add-Content -Path $serverVarFile -Value ('res_0105 = ' + $adSafeModePwd)
        if($credential -ne $null) {
            ##Get a list of available AD sites
            Set-Item WSMan:\localhost\Client\TrustedHosts $domainController -Force
            $ScriptBlock = { Get-ADReplicationSite -Filter * | ft Name }
            Invoke-Command -ComputerName $domainController -ScriptBlock $scriptBlock -Credential $credential
        }
        while($adSiteName.Length -eq 0) {
            $adSiteName = Read-HostWithColor "Enter the Active Directory site name for this DC: "
        }
        Add-Content -Path $serverVarFile -Value ('res_0106 = ' + $adSiteName)
        ## This is a not an Exchange server so just get information for the VM
        Get-ServerInfo
        Add-Content -Path $serverVMFileName -Value ('res_0003 = 0')
        Write-Host "Getting some information for setting up the new VM..." -ForegroundColor Green
        ## Show a list of available virtual switches
        #Get-VMSwitch | ft
        $switches
        ## Get the virtual switch for the VM
        $vmSwitch = Get-NewVMSwitchName
        Add-Content -Path $serverVMFileName -Value ('res_0004 = ' + $vmSwitch)
        ## Get the amount of memory to assign to the VM
        $vmMemory = Get-NewVMMemory
        Add-Content -Path $serverVMFileName -Value ('res_0005 = ' + $vmMemory)
        ## Get the number of processors to assign to the VM
        $vmCPU = Get-NewVMCPU
        Add-Content -Path $serverVMFileName -Value ('res_0006 = ' + $vmCPU)
        ## Prompt where to save the VHD for the VM
        $vhdPath = Get-NewVMPath
        Add-Content -Path $serverVMFileName -Value ('res_0007 = ' + $vhdPath)
        if(!(Get-VMParentDisk)) { Get-VMBaseDisk }
        $generationResult = Get-NewVMGeneration
        Add-Content -Path $serverVMFileName -Value ('res_0008 = ' + $generationResult)
        ## And also add info for the server install
        Add-Content -Path $serverVarFile -Value ('res_0099 = ' + $newInstallType)
        Add-Content -Path $serverVarFile -Value ('res_0100 = ' + $forestInstallType)
        Add-Content -Path $serverVarFile -Value ('res_0101 = ' + $domain)
        if($forestInstallType -eq 0) {
            Add-Content -Path $serverVarFile -Value ('res_0102 = ' + $domainMode)
            Add-Content -Path $serverVarFile -Value ('res_0103 = ' + $forestMode)
            Add-Content -Path $serverVarFile -Value ('res_0104 = ' + $netBIOSName)
        }
    }
    else {
        ## Check whether this is a new install or a recovery
        $askForCertificateLater = $false
        #$exNew = New-Object System.Management.Automation.Host.ChoiceDescription '&New', 'New install'
        #$exRecover = New-Object System.Management.Automation.Host.ChoiceDescription '&Recover', 'Recover server'
        #$exInstallOption = [System.Management.Automation.Host.ChoiceDescription[]]($exNew, $exRecover)
        #$exInstallType = $Host.UI.PromptForChoice("Server deployment script","Is this a new install of Exchange or a recovery scenario:", $exInstallOption, 0)
        Add-Content -Path $serverVarFile -Value ('res_0099 = ' + $newInstallType)
        Add-Content -Path $serverVarFile -Value ('res_0004 = ' + $exInstallType)
        Add-Content -Path $serverVMFileName -Value ('res_0003 = ' + $exInstallType)

        ## Update variable file with server info
        Write-Host "Getting server information..." -ForegroundColor Green
        switch ($exInstallType) {
            0 { ## Prompt user for new install info
                Get-ServerInfo
                Write-Host "Getting some information for setting up the new VM..." -ForegroundColor Green
                ## Show a list of available virtual switches
                $switches
                #Get-VMSwitch | ft
                ## Get the virtual switch for the VM
                $vmSwitch = Get-NewVMSwitchName
                Add-Content -Path $serverVMFileName -Value ('res_0004 = ' + $vmSwitch)
                ## Get the amount of memory to assign to the VM
                $vmMemory = Get-NewVMMemory
                Add-Content -Path $serverVMFileName -Value ('res_0005 = ' + $vmMemory)
                ## Get the number of processors to assign to the VM
                $vmCPU = Get-NewVMCPU
                Add-Content -Path $serverVMFileName -Value ('res_0006 = ' + $vmCPU)
                ## Prompt where to save the VHD for the Exchange VM
                while($vhdPath.Length -eq 0) {
                    $vhdPath = Get-NewVMPath
                }
                if(!(Get-VMParentDisk)) { Get-VMBaseDisk }
                Add-Content -Path $serverVMFileName -Value ('res_0007 = ' + $vhdPath)
                ## Prompt the user for an Exchange server to setup a remote PowerShell session
                $generationResult = Get-NewVMGeneration
                Add-Content -Path $serverVMFileName -Value ('res_0008 = ' + $generationResult)
            } 
    
            1 { ## Add IP information into hosts file for name resolution
                $dnsHost = "$ServerName.$domain"
                $hostIP = (Resolve-DnsName -Name $dnsHost -Server $tempDNS).IPAddress
                Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $dnsHost"
                Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $ServerName"
                ## Check if server is online to retrieve IP and disk information
                if(Check-ServerOnline) {
                    $serverOnline = $true
                    Write-Host "Getting network adapter configuration..." -ForegroundColor Green -NoNewline
                    ## Get IP Address info for current server
                    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value $ServerName -Force
                    $session = New-PSSession -Credential $credential -ComputerName $ServerName -Name ServerConfig
                    $scriptBlock = {(Get-NetIPInterface -InterfaceIndex ((Get-NetIPConfiguration | Where {$_.Ipv4DefaultGateway.NextHop -ne $null}).InterfaceIndex) -AddressFamily IPv4).Dhcp }
                    $dhcpTest = Invoke-Command -Session $session -ScriptBlock $scriptBlock
                    if($dhcpTest.Value -eq "Disabled") {
                        $ipAddr = Invoke-Command -Session $session -ScriptBlock { Get-NetIPConfiguration | Where {$_.Ipv4DefaultGateway.NextHop -ne $null} }
                        ## Exchange server may be cluster group owner and have multiple IP addresses
                        if($ipaddr.IPv4Address.Count -gt 1) {
                            Add-Content -Path $serverVarFile -Value ('res_0007 = ' + $ipAddr.IPv4Address.IPAddress[0])
                            Add-Content -Path $serverVarFile -Value ('res_0008 = ' + $ipAddr.IPv4Address.PrefixLength[0])
                        }
                        else {
                            Add-Content -Path $serverVarFile -Value ('res_0007 = ' + $ipAddr.IPv4Address.IPAddress)
                            Add-Content -Path $serverVarFile -Value ('res_0008 = ' + $ipAddr.IPv4Address.PrefixLength)                
                        }
                        Add-Content -Path $serverVarFile -Value ('res_0009 = ' + $ipAddr.IPv4DefaultGateway.NextHop)
                        ## May only have a primary DNS server
                        $dns = $ipAddr.DNSServer
                        if(($dns.ServerAddresses).Count -eq 1) {
                            Add-Content -Path $serverVarFile -Value ('res_0010 = ' + $dns.ServerAddresses)
                        }
                        else {
                            Add-Content -Path $serverVarFile -Value ('res_0010 = ' + $dns.ServerAddresses[0])
                            Add-Content -Path $serverVarFile -Value ('res_0011 = ' + $dns.ServerAddresses[1])
                        }
                    }
                    else { Add-Content -Path $serverVarFile -Value ('res_0026 = 1') }
                    Write-Host "COMPLETE"
                    ## Get disk information
                    Write-Host "Getting disk information..." -ForegroundColor Green -NoNewline
                    $scriptBlock = {
                        New-Item -ItemType Directory -Path C:\Temp -ErrorAction Ignore | Out-Null
                        $p = @()
                        $output = "DiskNumber,PartitionNumber,AccessPaths"
                        $output | Out-File "C:\Temp\DiskInfo.csv" -Force
                        Get-Disk | where {$_.Number -gt 0} | ForEach-Object { $p = Get-Partition -DiskNumber $_.Number | Where {$_.AccessPaths -ne $null -and $_.Type -eq "Basic"} | Select DiskNumber,PartitionNumber,AccessPaths}
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
                    Invoke-Command -Session $session -ScriptBlock $scriptBlock
                    $scriptFiles = "\\$ServerName\c$\Temp"
                    New-PSDrive -Name "Script" -PSProvider FileSystem -Root $scriptFiles -Credential $credential
                    Copy-Item -Path "Script:\DiskInfo.csv" -Destination "C:\Temp\$ServerName-DiskInfo.csv" -Force -ErrorAction Ignore
                    Remove-PSDrive -Name Script
                    Write-Host "COMPLETE"
                    Disconnect-PSSession -Name ServerConfig | Out-Null
                    Remove-PSSession -Name ServerConfig | Out-Null
                    ## Getting certificate information since the server is online
                    Write-Host "Getting current Exchange certificate from the Exchange server..." -ForegroundColor Green -NoNewline
                    $certServer = $ServerName
                    [string]$thumb = Get-ServerCertificate
                    Write-Host $thumb
                }
                else { 
                ## Server is not available so prompting the user for information
                    Write-Host "Unable to connect to $ServerName to retrieve settings." -ForegroundColor Yellow -BackgroundColor Black
                    Get-ServerInfo
                    ## Check for Exchange certificate after a remote PowerShell session is established
                    $askForCertificateLater = $true
                } 
            }
        }
        $exchServer = $null
        $noExchange = $false
        ## Check for an Exchange management session, otherwise verify there is no Exchange organization in the forest
        if(!(Get-PSSession | Where { $_.ConfigurationName -eq "Microsoft.Exchange" } )) {
            ## Prompt the user for an Exchange server to setup a remote PowerShell session
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
            $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
            $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $continueResult= $Host.UI.PromptForChoice("Server deployment script","Would you like to connect to Exchange now?", $yesNoOption, 0)
            switch($continueResult) {
                0 {## Enable basic authentication on the Exchange server
                    $exchServer = Prepare-ExchangeConnect
                    ## Connect to the Exchange remote PowerShell session
                    Connect-Exchange
                }
            ## There is no Exchange server to make a connection
                1 { ## either this is a new forest or we need to confirm there is no exchange
                    if($forestInstallType -ne 0 -and $domainController -ne $null) {
                        ## Try to locate an Exchange organization in Active Directory
                        $adDomain = (Get-ADDomain -Server $domainController -Credential $credential -ErrorAction Ignore).DistinguishedName
                        $configPartition = "CN=Configuration,$adDomain"
                        if((Get-ADObject -LDAPFilter "(objectClass=msExchOrganizationContainer)" -SearchBase $configPartition -Server $domainController -Credential $credential)) {
                            ## Found an Exchange organization so an Exchange connection should be made
                            Write-Warning "Exchange is already present in the enviornment and you must connect prior to running this script"
                            $exchServer = Prepare-ExchangeConnect
                            Connect-Exchange
                        }
                        else {
                            ## There is no Exchange organization so we need to potentially create one
                            $noExchange = $true
                            Add-Content -Path $serverVarFile -Value ('res_0028 = 1')
                            ## Prompt the user for an Exchange server to setup a remote PowerShell session
                            $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                            $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                            $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                            $newOrgResult= $Host.UI.PromptForChoice("Server deployment script","Would you like to create a new Exchange organization?", $yesNoOption, 0)
                            if($newOrgResult -eq 0) { 
                                $exOrgName = Read-HostWithColor "Enter the name for the new Exchange organization: "
                                Add-Content -Path $serverVarFile -Value ('res_0029 = ' + $exOrgName)
                            }
                        }
                    }
                    else {
                        ## This is a new deployment and a new Exchange organization may be needed
                        $noExchange = $true
                        Add-Content -Path $serverVarFile -Value ('res_0028 = 1')
                        $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                        $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                        $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                        $newOrgResult= $Host.UI.PromptForChoice("Server deployment script","Would you like to create a new Exchange organization?", $yesNoOption, 0)
                        if($newOrgResult -eq 0) { 
                            $exOrgName = Read-HostWithColor "Enter the name for the new Exchange organization: "
                            Add-Content -Path $serverVarFile -Value ('res_0029 = ' + $exOrgName)
                        }
                    }
                }
            }
        }
        else { 
            $exchServer = (Get-PSSession | Where { $_.ConfigurationName -eq "Microsoft.Exchange" } | Select -Last 1).ComputerName
            ## Add the Exchange server to the hosts file to ensure we don't have name resolution issues
            $dnsHost = "$exchServer.$domain"
            $hostIP = (Resolve-DnsName -Name $dnsHost -Server $tempDNS).IPAddress
            Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $dnsHost"
            Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "$hostIP $exchServer"
        }

    ## Get Exchange setup information
    switch ($exInstallType) {
        0 { $exReady = $false
            while($exReady -eq $false) {
                ## Get the Exchange version
                $exVersion = Select-ExchangeVersion
                ## Get the latest version of Exchange in the forest
                if($credential -ne $null) {
                    $currentVersion = Check-ExchangeVersion
                }
                ## New forest - set current version less than 2013
                else { $currentVersion = -1 }
                ## Check to see if a version of Exchange is being skipped
                if(((($exVersion -ne $currentVersion -and $exVersion-$currentVersion) -gt 1)) -or ($noExchange -eq $true -and $exVersion -gt 0)) {
                    Write-Warning "One or more versions of Exchange is not installed"
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
            Get-ExchangeISO
            switch ($exVersion) {
                2 { $exMbxRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Mailbox', 'Mailbox server role'
                    $exEdgeRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Edge Transport', 'Edge Transport server role'
                    $exRoleOption = [System.Management.Automation.Host.ChoiceDescription[]]($exMbxRole, $exEdgeRole)
                    $exRoleResult = $Host.UI.PromptForChoice("Server deployment script","What Exchange server roles should be installed:", $exRoleOption, 0)
                    Add-Content -Path $serverVarFile -Value ('res_0005 = ' + $exRoleResult)
                }
                1 { $exMbxRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Mailbox', 'Mailbox server role'
                    $exEdgeRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Edge Transport', 'Edge Transport server role'
                    $exRoleOption = [System.Management.Automation.Host.ChoiceDescription[]]($exMbxRole, $exEdgeRole)
                    $exRoleResult = $Host.UI.PromptForChoice("Server deployment script","What Exchange server roles should be installed:", $exRoleOption, 0)
                    Add-Content -Path $serverVarFile -Value ('res_0005 = ' + $exRoleResult)
                }
                0{ $exAllRoles = New-Object System.Management.Automation.Host.ChoiceDescription '&All', 'All roles'
                    $exMbxRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Mailbox', 'Mailbox server role'
                    $exCasRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Client Access', 'Client Access server role'
                    $exEdgeRole = New-Object System.Management.Automation.Host.ChoiceDescription '&Edge Transport', 'Edge Transport server role'
                    $exRoleOption = [System.Management.Automation.Host.ChoiceDescription[]]($exAllRoles, $exMbxRole, $exCasRole, $exEdgeRole)
                    $exRoleResult = $Host.UI.PromptForChoice("Server deployment script","What Exchange server roles should be installed:", $exRoleOption, 0)
                    Add-Content -Path $serverVarFile -Value ('res_0005 = ' + $exRoleResult)
                    ## Ask which version of Microsoft .NET Framework to install
                    $seven = New-Object System.Management.Automation.Host.ChoiceDescription '.NET 4.&7.2', '4.7.2'
                    $eight = New-Object System.Management.Automation.Host.ChoiceDescription '.NET 4.&8', '4.8'
                    $dotNetOption = [System.Management.Automation.Host.ChoiceDescription[]]($eight, $seven)
                    $dotNetResult = $Host.UI.PromptForChoice("Server deployment script","Which version of the Microsoft .NET Framework do you want to instll?", $dotNetOption, 0)
                    Add-Content -Path $serverVarFile -Value ('res_0016 = ' + $dotNetResult)
                }
            }
            ## Check if the certificate from the remote PowerShell session Exchange server should be used
            if($noExchange -eq $false) {
                if(Get-CertificateFromServerCheck) {
                    ## Need to fix the next line
                    if($exchServer -like "*.*") { $certServer = $exchServer.Substring(0, $exchServer.IndexOf(".")) }
                    else { $certServer = $exchServer }
                    [string]$thumb = Get-ServerCertificate
                }
            }
            ## Get hostname values for the Exchange virtual directories
            $intHostname = (Read-HostWithColor "Enter the hostname for the internal URLs: ").ToLower()
            Add-Content -Path $serverVarFile -Value ('res_0020 = ' + $intHostname)
            $extHostname = (Read-HostWithColor "Enter the hostname for the external URLs: ").ToLower()
            Add-Content -Path $serverVarFile -Value ('res_0021 = ' + $extHostname)
            ## Check whether the Exchange server should be added to an existing DAG, a new DAG, or none
            $ExistingDag = New-Object System.Management.Automation.Host.ChoiceDescription '&Existing', 'Existing'
            $NewDag = New-Object System.Management.Automation.Host.ChoiceDescription '&New', 'New'
            $NoDag = New-Object System.Management.Automation.Host.ChoiceDescription '&Standalone', 'None'
            $dagOption = [System.Management.Automation.Host.ChoiceDescription[]]($ExistingDag, $NewDag, $NoDag)
            $dagResult = $Host.UI.PromptForChoice("Server deployment script","Would you like to join and existing DAG, create a new DAG, or make a standalone server?", $dagOption, 0)
            Add-Content -Path $serverVarFile -Value ('res_0015 = ' + $dagResult)
            switch ($dagResult) {
                0 { ## Join a DAG if Exchange is present otherwise create a DAG
                    if($noExchange -eq $false) {
                        ## Look for existing DAG and so admin can see what is available
                        if(Get-DatabaseAvailabilityGroup) {
                            Get-DatabaseAvailabilityGroup | ft Name
                            $validDag = $false
                            while($validDag -eq $false) {
                                $DagName = Read-HostWithColor "Enter the Database Availability Group name: "
                                $validDag = Validate-DagName
                                if($validDag -eq $false) {
                                    $validDag = Skip-DagCheck
                                }
                            }
                            Add-Content -Path $serverVarFile -Value ('res_0001 = ' + $DagName)
                        }
                        ## Create a new DAG if there is no DAG in the environment or skip for deploying multiple servers
                        else { Check-NewDeployment }
                    }
                    ## Cannot verify DAG so either create a new DAG or join a DAG for new deployments
                    else { Check-NewDeployment }
                }
                1 { ## Get information for the new DAG
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                    $dagTypeOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                    $dagType = $Host.UI.PromptForChoice("Server deployment script","Do you want to create the DAG without an administrative access point? (aka:IP-less)", $dagTypeOption, 0)
                    Add-Content -Path $serverVarFile -Value ('res_0032 = ' + $dagType)
                    Create-NewDAG
                    if($dagType -eq 1) {
                        Get-DAGIPAddress
                    }
                }
            }
        }
        1 { ## Determine what version of Exchange the server has installed
            $exchVersion = (Get-ExchangeServer $ServerName).AdminDisplayVersion
            $exchVersion = $exchVersion.Substring(11,1)
            switch($exchVersion) {
                0 {
                    Add-Content -Path $serverVarFile -Value ('res_0003 = 0')
                }
                1 {
                    Add-Content -Path $serverVarFile -Value ('res_0003 = 1') 
                    }
                2 {
                    Add-Content -Path $serverVarFile -Value ('res_0003 = 2') 
                }
            }
            ## Get the ISO for Exchange install
            Get-ExchangeISO
            Add-Content -Path $serverVarFile -Value ('res_0005 = ' + $null)
            ## Get the VHD disk information
            Write-Host "Determining VM disk settings..." -ForegroundColor Green
            [string]$vhdParentPath = (Get-VHD (Get-VMHardDiskDrive -VMName $ServerName)[0].Path).ParentPath
            if($vhdParentPath.Length -gt 0) {
                Write-Warning "Current configuration uses a parent disk."
                Get-VMParentDisk
            }
            else { ## Check current VM generation before prompting
                [int]$vmGen = (Get-VM $ServerName).Generation
                Write-Warning "$ServerName is currently Generation $vmGen."
                Get-VMBaseDisk 
            }
            ## Clearing Edge Sync credentials to allow server to be recovered that is part of an Edge subscription
            Write-Host "Removing any Edge Sync credentials that may be present..." -ForegroundColor Green -NoNewline
            $dc = (Get-ExchangeServer $ServerName).OriginatingServer
            [int]$startChar = $ServerName.Length + 4
            $searchBase = (Get-ExchangeServer $ServerName).DistinguishedName
            $searchBase = $searchBase.Substring($startChar)
            Get-ADObject -SearchBase $searchBase -Filter 'cn -eq $ServerName' -SearchScope OneLevel -Properties msExchEdgeSyncCredential -Server $domainController -Credential $credential | Set-ADObject -Clear msExchEdgeSyncCredential -Server $domainController -Credential $credential
            Write-Host "COMPLETE"
            ## Check if the servers was offline and if we need the certificate
            if($askForCertificateLater) {
                if(Get-CertificateFromServerCheck) {
                    if($exchServer -like "*.*") {
                        $certServer = $exchServer.Substring(0, $exchServer.IndexOf("."))
                    }
                    else { $certServer = $exchServer }
                    [string]$thumb = Get-ServerCertificate
                }
            }
            
            ##Check if the Exchange server is a member of a DAG
            Write-Host "Checking if the Exchange server is a member of a DAG..." -ForegroundColor Green -NoNewline
            if(Get-DatabaseAvailabilityGroup -DomainController $domainController | Where { $_.Servers -match $ServerName }) {
                Write-Host "MEMBER"
                [string]$DagName = Get-DatabaseAvailabilityGroup -DomainController $domainController  | Where { $_.Servers -like '*' + $ServerName + '*'}
                Add-Content -Path $serverVarFile -Value ('res_0001 = ' + $DagName)
                ## Check if the databases have multiple copies
                $dbHasCopies = $false
                Write-Host "Checking if the databases for this server have multiple copies..." -ForegroundColor Green
                Get-MailboxDatabase -Server $ServerName | ForEach-Object {
                    if($_.ReplicationType -eq "Remote") {
                        $dbHasCopies = $true
                        ## Check the number of copies of the database
                        if(((Get-MailboxDatabase $_.Name).AllDatabaseCopies).count -eq 2){
                            if((Get-MailboxDatabase $_.Name).CircularLoggingEnabled) {
                                ## Need to disable circular logging before removing the database copy
                                Write-Host "Disabling circular logging for this $_.Name..." -ForegroundColor Green -NoNewline
                                Set-MailboxDatabase $_.Name -CircularLoggingEnabled:$False -Confirm:$False | Out-Null
                                Write-Host "COMPLETE"
                            }
                        }
                        ## Get a list of databases and the replay lag times for the Exchange server
                        $replayLagTime = [string](Get-MailboxDatabase $_.Name | Where {$_.ReplayLagTimes -like "*$ServerName*" }).ReplayLagTimes
                        $_.Name + "," + $replayLagTime | Out-File "c:\Temp\$ServerName-DatabaseCopies.txt" -Append
                        ## Get the current activation preferences for the mailbox databases in the DAG
                        $activationPreference = [string](Get-MailboxDatabase $_.Name | Select Name -ExpandProperty ActivationPreference)
                        $_.Name + "," + $activationPreference | Out-File "c:\Temp\$ServerName-$DagName-ActivationPreferences.txt" -Append
                        ## Check if the database is mounted on this server
                        $dbMounted = $true
                        while($dbMounted -eq $true) {
                            $dbMounted = Get-MailboxDatabaseStatus $_.Name 
                            if($dbMounted -eq $true) {
                                [int]$moveAttempt = 0
                                $moveComplete = (Move-MailboxDatabase $_.Name)
                                while($moveAttempt -lt 6) {
                                    if($moveComplete -eq $false) {
                                        if ($moveAttempt -eq 5) {
                                            Write-Warning "Failed to move the database copy to another server."
                                            exit
                                        }
                                        Get-MailboxDatabaseCopyStatus $_.Name | ft Name,Status,CopyQueueLength,ReplayQueueLength,ContentIndexState
                                        $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
                                        $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
                                        $moveOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                                        $moveResult= $Host.UI.PromptForChoice("Server deployment script","Do you want to attempt to move the database with best effort?", $moveOption, 0)
                                        if($moveResult -eq 0) {
                                            Start-Sleep -Seconds 3
                                            $moveAttempt++
                                            $moveComplete = (Move-MailboxDatabaseBestEffort $_.Name)
                                        }
                                    }
                                    else { break }
                                }
                            }
                        }
                        ## Remove existing database copies and then remove server from DAG
                        Write-Host "Removing database copy for $_ from the server..." -ForegroundColor Green -NoNewline
                        $dbCopy = $_.Name + "\$ServerName"
                        Remove-MailboxDatabaseCopy $dbCopy -DomainController $domainController -Confirm:$False | Out-Null
                        Write-Host "COMPLETE"
                    }
                }
                if($dbHasCopies -eq $true) { Add-Content -Path $serverVarFile -Value ('res_0025 = 1') }
                ##Remove the Exchange server from the database availability group
                Write-Host "Checking DAC mode for the DAG..." -ForegroundColor Green -NoNewline
                if((Get-DatabaseAvailabilityGroup $DagName -DomainController $domainController ).DatacenterActivationMode -eq "DagOnly") {
                    Write-Host "DagOnly"
                    Add-Content -Path $serverVarFile -Value ('res_0030 = DagOnly')
                    Write-Host "Checking the number of servers in the DAG..." -ForegroundColor Green
                    if((Get-DatabaseAvailabilityGroup -DomainController $domainController ).Servers.Count -eq 2) {
                        Write-Host "Disabling datacenter activation mode..." -ForegroundColor Yellow
                        Set-DatabaseAvailabilityGroup $DagName -DatacenterActivationMode Off -DomainController $domainController -Confirm:$False | Out-Null
                    }
                }
                else { 
                    Write-Host "OFF"
                    Add-Content -Path $serverVarFile -Value ('res_0030 = Off')
                }
                Write-Host "Removing server from the DAG..." -ForegroundColor Green -NoNewline
                if($serverOnline -eq $true) {
                    Remove-DatabaseAvailabilityGroupServer $DagName -MailboxServer $ServerName -DomainController $domainController -Confirm:$False -ErrorAction Ignore
                }
                else {
                    Remove-DatabaseAvailabilityGroupServer $DagName -MailboxServer $ServerName -DomainController $domainController -ConfigurationOnly -Confirm:$False -ErrorAction Ignore
                    Start-Sleep -Seconds 5
                    Write-Host "COMPLETE"
                    Write-Host "Removing $ServerName from the Windows cluster..." -ForegroundColor Green -NoNewline
                    $scriptBlock = { Param ($param1) Remove-ClusterNode -Name $param1 -Force -ErrorAction Ignore }
                    Invoke-Command -ScriptBlock $scriptBlock -ComputerName $exchServer -Credential $credential -ArgumentList $ServerName
                }
                Write-Host "COMPLETE"

                ## Check if the remove succeeded
                if((Get-DatabaseAvailabilityGroup $DagName -DomainController $domainController).Servers -notcontains $serverName) {
                    ## Synchrnoize Active Directory so all sites are aware of the change
                    Write-Host "Synchronizing Active Directory with the latest changes..." -ForegroundColor Green -NoNewline
                    Sync-AdConfigPartition
                    Write-Host "COMPLETE"
                    ## Verify the Exchange server is no longer a member of the DAG in each AD site
                    $domainControllers = New-Object System.Collections.ArrayList
                    $domainControllers = Get-DomainControllers
                    $domainControllers | ForEach-Object { 
                        $serverFound = $true
                        Write-Host "Checking for $serverName in $DagName on $_..." -ForegroundColor Green -NoNewline
                        while($serverFound -eq $true) {
                            if((Get-DatabaseAvailabilityGroup $DagName -DomainController $_ -ErrorAction Ignore).Servers -contains $serverName) {
                                Write-Host "..." -ForegroundColor Green -NoNewline
                                Sync-AdConfigPartition
                                Start-Sleep -Seconds 10
                            }
                            else {
                                Write-Host "COMPLETE"
                                $serverFound = $false
                            }
                        }
                    }
                }
                else {
                    Write-Host "Failed to remove $ServerName from $DagName. You can attempt to resolve the issue and try again later." -ForegroundColor Red
                    ## Script failed to remove the server from the DAG so we are removing it from the VM list and deleting files
                    $vmServers.Remove($ServerName)
                    Remove-Item -Path c:\Temp\$ServerName* -Force
                }
            }
            else {
                Write-Host "STANDALONE"
            }
        }
    }

    if($thumb.Length -gt 1) {
        ## Export the Exchange certificate
        Write-Host "Exporting current Exchange certificate with thumbprint $thumb from $certServer..." -ForegroundColor Green -NoNewline
        ## Need to check for c:\Temp
        New-Item -ItemType Directory -Path "\\$exchServer\c$\Temp" -ErrorAction Ignore | Out-Null
        Export-ExchangeCertificate -Server $certServer -Thumbprint $thumb -FileName "C:\Temp\$ServerName-Exchange.pfx" -BinaryEncoded -Password (ConvertTo-SecureString -String 'Pass@word1' -AsPlainText -Force) | Out-Null
        $certServerDrive = "\\$exchServer\c$\temp"
        New-PSDrive -Name "Script" -PSProvider FileSystem -Root $certServerDrive -Credential $credential
        Copy-Item -Path "Script:\$ServerName-Exchange.pfx" -Destination C:\Temp
        Remove-PSDrive -Name "Script"
        Write-Host "COMPLETE"
    }
    $noExchange = $false
    }
    
    ## Finalize the psd1 file
    Add-Content -Path $serverVarFile -Value ('res_0022 = ' + $exchServer)
    
    Add-Content -Path $serverVMFileName -Value '###PSLOC'
    Add-Content -Path $serverVMFileName -Value "'@"

    ## Check if another server should be deployed
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'No'
    $yesNoOption = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $anotherServerResult = $Host.UI.PromptForChoice("Server deployment script","Do you want to deploy another server?", $yesNoOption, 1)
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
if($exchServer -ne $null) {
    Write-Host "Removing the Exchange remote PowerShell session..." -ForegroundColor Green
    ## Disconnect from the Exchange remote PowerShell session
    Remove-PSSession -Name ExchangeShell
    Write-Host "Disabling basic authentication on the PowerShell vDir..." -ForegroundColor Green -NoNewline
    $session = New-PSSession -Credential $credential -ComputerName $exchServer -Name DisableBasic
    $scriptBlock = { C:\Windows\system32\inetsrv\appcmd set config "Default Web Site/PowerShell/" /section:basicAuthentication /enabled:false /commit:apphost }
    Invoke-Command -Session $session -ScriptBlock $scriptBlock | Out-Null
    Write-Host "COMPLETE"
    Disconnect-PSSession -Name DisableBasic | Out-Null
    Remove-PSSession -Name DisableBasic | Out-Null
}

## Revert the TrustedHosts list
Write-Host "Clearing trusted hosts..." -ForegroundColor Green -NoNewline
Clear-Item WSMan:\localhost\Client\TrustedHosts -Force
Write-Host "COMPLETE"

## Revert the hosts file back to the original
Write-Host "Reverting hosts file..." -ForegroundColor Green -NoNewline
$hostsFile | Out-File C:\Windows\System32\drivers\etc\hosts
Write-Host "COMPLETE"

if($credential -ne $null) {
    ## Revert the DNS settings back
    Write-Host "Reverting DNS settings..." -ForegroundColor Green -NoNewline
    if(($dnsServers.ServerAddresses).Count -eq 1) {
        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration | Where {$_.IPv4DefaultGateway -ne $null}).InterfaceIndex -ServerAddresses $dnsServers.ServerAddresses[0] | Out-Null
    }
    else {
        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPConfiguration | Where {$_.IPv4DefaultGateway -ne $null}).InterfaceIndex -ServerAddresses $dnsServers.ServerAddresses[0],$dnsServers.ServerAddresses[1] | Out-Null
    }
    Write-Host "COMPLETE"
}

Write-Host "Creating the virtual machines for your deployment..." -ForegroundColor Green
foreach($v in $vmServers) {
    $serverVarFile = "c:\Temp\$v-ExchangeInstall-strings.psd1"
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
        Add-Content -Path $serverVarFile -Value ('res_0034 = '+ $version)
    }
    ## Finalize the psd1 file
    
    Add-Content -Path $serverVarFile -Value '###PSLOC'
    Add-Content -Path $serverVarFile -Value "'@"
    
    ## Check to ensure no VM currently exists with the same name
    if($exInstallType -ne 1) {
        if(Get-VM -Name $v -ErrorAction Ignore) { 
            Write-Host "Found an existing VM present for $v" -ForegroundColor Yellow -BackgroundColor Black
            Write-Host "Removing the existing VM for $v..." -ForegroundColor Green -NoNewline
            Remove-VM -Name $v #-Confirm:$False
            Write-Host "COMPLETE"
        }
    }
    Import-LocalizedData -BindingVariable VM_LocalizedStrings -FileName $v"-VM-strings.psd1"
    ## Time to work in Hyper-V on the virtual machines
    switch($VM_LocalizedStrings.res_0003) {
        0 { ## Create a new virtual machine using the settings provided
            [int]$vmGen = [int]$VM_LocalizedStrings.res_0008 + 1
            New-VM -Name $v -MemoryStartupBytes $VM_LocalizedStrings.res_0005 -SwitchName $VM_LocalizedStrings.res_0004 -NoVHD -BootDevice CD -Generation $vmGen | Out-Null
            Set-VM -ProcessorCount $VM_LocalizedStrings.res_0006 -Name $v
            Write-Host "COMPLETE"
            $vhdPath = $VM_LocalizedStrings.res_0007
            $vhdParentPath = $VM_LocalizedStrings.res_0009
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
            Write-Host "Stopping $v virtual machine..." -ForegroundColor Green -NoNewline
            Stop-VM $v -Force -TurnOff
            Write-Host "COMPLETE"
            Write-Host "Updating VM disk configuration..." -ForegroundColor Green
            Write-Host "Deleting the existing VHD file..." -ForegroundColor Green -NoNewline
            $vmHDD = (Get-VMHardDiskDrive -VMName $v)[0]
            [string]$vhdPath = (Get-VHD (Get-VMHardDiskDrive -VMName $v)[0].Path).Path
            [string]$vhdParentPath = (Get-VHD (Get-VMHardDiskDrive -VMName $v)[0].Path).ParentPath
            $vmDiskCL = $vmHDD[0].ControllerLocation
            $vmDiskCN = $vmHDD[0].ControllerNumber
            Remove-Item -Path $vhdPath -Force
            Write-Host "COMPLETE"
            Write-Host "Removing the orginal hard drive from the virtual machine $v..." -ForegroundColor Green -NoNewline
            Remove-VMHardDiskDrive -VMName $v -ControllerType $vmHDD.ControllerType -ControllerNumber $vmDiskCN -ControllerLocation $vmDiskCL
            Write-Host "COMPLETE"
            [int]$vmGen = (Get-VM -Name $v).Generation
        }
    }
    
    Write-Host "Assigning the ISO to the CD drive for the VM..." -ForegroundColor Green -NoNewline
    $vmDvd = Get-VMDvdDrive -VMName $v
    while($vmDvd.Path -ne $VM_LocalizedStrings.res_0001) {
        Write-Host "." -ForegroundColor Green -NoNewline
        $vmDvd | Set-VMDvdDrive -Path $VM_LocalizedStrings.res_0001 #-ControllerNumber $vmDvd.ControllerNumber $vmDvd.ControllerLocation
    }
    Write-Host "COMPLETE"
    ## VM disk configuration
    if($vhdParentPath.Length -gt 0) {
        New-VHD -ParentPath $vhdParentPath -Path $vhdPath -Differencing
    }
    else {
        Write-Host "Copying the base Windows VHD to the destination VHD path..." -ForegroundColor Green -NoNewline
        Copy-Item -Path $VM_LocalizedStrings.res_0002 -Destination $vhdPath
        Write-Host "COMPLETE"
        Write-Host "Removing the read-only flag on the VHD file..." -ForegroundColor Green -NoNewline
        Set-ItemProperty -Path $vhdPath -Name IsReadOnly -Value $False
        Write-Host "COMPLETE"
    }
        Write-Host "Adding the new hard drive to the virtual machine $V..." -ForegroundColor Green -NoNewline
    if($vmGen -eq 2) {
        Add-VMHardDiskDrive -VMName $v -Path $vhdPath -ControllerType SCSI -ControllerNumber $vmDiskCN -ControllerLocation $vmDiskCL -ComputerName localhost -Confirm:$False
        Set-VMFirmware $v -BootOrder $(Get-VMDvdDrive -VMName $v -ControllerNumber $vmDvd.ControllerNumber -ControllerLocation $vmDvd.ControllerLocation), $(Get-VMHardDiskDrive -VMName $v -ControllerType SCSI -ControllerLocation $vmDiskCL -ControllerNumber $vmDiskCN)
    }
    else {
        Add-VMHardDiskDrive -VMName $v -Path $vhdPath -ControllerType IDE -ControllerNumber 0 -ControllerLocation 0 -ComputerName localhost -Confirm:$False
    }
    Write-Host "COMPLETE"
    Write-Host "Starting $v..." -ForegroundColor Green
    Start-VM -Name $v
    Remove-Item -Path $v"-VM-strings.psd1" -Force
    #vmconnect.exe $env:COMPUTERNAME $v
}
