<#
// DeployServer-Step5.ps1
// Modified 21 September 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20230921.1341
//
// Script should automatically start when the virtual machine starts.
// Syntax for running this script:
//
// .\DeployServer-Step5.ps1
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
function PrepareDatabaseAvailabilityGroup {
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
function CheckFileShareWitness {
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
function SyncADConfigPartition {
    ## Synchronize the Configuration container in Active Directory
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        [string]$configPartition = "CN=Configuration,$adDomain"
        Log([string]::Format("Replicating configuration partition from {0} to {1}.", $fromServer, $toServer)) Gray
        repadmin /replicate $fromServer $toServer $configPartition /force | Out-Null
    }
}
function SyncADDirectoryPartition {
    ## Synchronize the Directory container in Active Directory
    Get-ADReplicationConnection -Filter * -ErrorAction Ignore | ForEach-Object {
        [string]$fromServer = ($_.ReplicateFromDirectoryServer).Substring(20)
        $fromServer = $fromServer.Substring(0, $fromServer.IndexOf(","))
        [string]$toServer = ($_.ReplicateToDirectoryServer).Substring(3)
        $toServer = $toServer.Substring(0, $toServer.IndexOf(","))
        Log([string]::Format("Replicating directory partition from {0} to {1}.", $fromServer, $toServer)) Gray
        repadmin /replicate $fromServer $toServer $adDomain /force | Out-Null    
    }
}
function AddDatabaseCopies {
## Adding the database copies the Exchange server previously had configured
    param( [parameter(mandatory=$true)] [string]$readFile )
    $reader = New-Object System.IO.StreamReader($readFile)
    while($null -ne ($currentLine = $reader.ReadLine())) {
        $db = $currentLine.Substring(0, $currentLine.IndexOf(","))
        $copyFound = $false
        while($copyFound -eq $false) {
            $currentLine = $currentLine.Substring($currentLine.IndexOf("[") + 1)
            $server = $currentLine.Substring(0, $currentLine.IndexOf(","))
            if($server -eq $ServerName) {
                $currentLine = $currentLine.Substring($currentLine.IndexOf(",")+2)
                $replayLagTime = $currentLine.Substring(0, $currentLine.IndexOf("]"))
                $copyFound = $true
                Log([string]::Format("Adding database copy for {0} with a replay lag time of {1}.", $db, $replayLagTime)) Gray
                Add-MailboxDatabaseCopy $db -MailboxServer $ServerName -ReplayLagTime $replayLagTime | Out-Null
            }
        }
    }
}
function SetActivationPreferences {
## Resetting the activation preferences for the database copies
param( [parameter(mandatory=$true)] [string]$readFile )
    $reader = New-Object System.IO.StreamReader($readFile)
    while($null -ne ($currentLine = $reader.ReadLine())) {
        $db = $currentLine.Substring(0, $currentLine.IndexOf(","))
        $currentLine = $currentLine.Substring($currentLine.IndexOf(",")+1)
        $endOfLine = $false
        while($endOfLine -eq $false) {
            $endChar = $currentLine.IndexOf(",")
            $server = $currentLine.Substring(1, $endChar-1)
            $currentLine = $currentLine.Substring($endChar+2)
            $prefNumber = $currentLine.Substring(0, $currentLine.IndexOf("]"))
            $copyName = $db + "\" + $server
            Log([string]::Format("Setting {0} on {1} with an activation preference of {2}.", $db, $server, $prefNumber)) Gray
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
function CheckMSExchangeRepl {
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

Log([string]::Format("Running the Step5 script now.")) Yellow
## Clean up the registry from the automatic login information
Log([string]::Format("Removing auto-logon registry keys.")) Gray
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Force | Out-Null
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Force | Out-Null
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Force | Out-Null
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -Force | Out-Null
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

if($ExchangeInstall_LocalizedStrings.EdgeRole -ne 1) {
    ## Verify that the domain can be resolved before continuing
    Log([string]::Format("Verifying the domain can be resolved.")) Gray
    $domain = $ExchangeInstall_LocalizedStrings.Domain
    $serverReady = $false
    while($serverReady -eq $false) {
        $domainController = (Resolve-DnsName $domain -Type SRV -Server $ExchangeInstall_LocalizedStrings.DomainController -ErrorAction Ignore).PrimaryServer
        if($domainController -like "*$domain") { $serverReady = $true }
        Start-Sleep -Seconds 5
    }
    ## Get the AD Domain
    $adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
}

## Complete either the Exchange installation of the domain controller
switch($ExchangeInstall_LocalizedStrings.ServerType) {
    0{ 
        ## Finalize Exchange setup
        if($ExchangeInstall_LocalizedStrings.EdgeRole -ne 1) {
            Log([string]::Format("Finalizing Exchange setup.")) Gray
            ## Verify all Exchange services are running
            Get-Service MSExch* | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" } | ForEach-Object { Start-Service $_ -ErrorAction Ignore}
            ## Connect a remote PowerShell session to the server
            $exchConnection = $false
            while($exchConnection -eq $false) {
                Log([string]::Format("Connecting a remote PowerShell session with {0}.", $ServerName)) Yellow
                try {Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ServerName/PowerShell" -AllowRedirection -Authentication Kerberos) | Out-Null}
                catch { Start-Sleep -Seconds 30 }
                if(Get-ExchangeServer $ServerName) {
                    $exchConnection = $true
                }
                else {
                    Start-Sleep -Seconds 30
                }
            }
            SyncAdConfigPartition
            ## Recreate Edge subscription if needed
            if($null -ne $ExchangeInstall_LocalizedStrings.EdgeName) {
                $EdgeCreds = New-Object System.Management.Automation.PSCredential($ExchangeInstall_LocalizedStrings.EdgeAdmin, (ConvertTo-SecureString -String $ExchangeInstall_LocalizedStrings.EdgePassword -AsPlainText -Force))
                $EdgeServer = $ExchangeInstall_LocalizedStrings.EdgeName+"."+$ExchangeInstall_LocalizedStrings.EdgeDomain
                Log([string]::Format("Recreating Edge subscription with {0}.", $EdgeServer)) Gray
                Set-Item WSMan:\localhost\Client\TrustedHosts $EdgeServer -Force
                $s = { 
	                Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
	                New-EdgeSubscription -FileName "C:\Temp\EdgeSubscription.xml" -Confirm:$false -Force
                }
                Invoke-Command -ScriptBlock $s -Credential $EdgeCreds -ComputerName $EdgeServer
                $edgeResult = Invoke-Command -ScriptBlock {$edgeFile = (Get-Item "C:\Temp\EdgeSubscription.xml").FullName; return $edgeFile} -ComputerName $EdgeServer -Credential $EdgeCreds
                if ($edgeResult -notlike $null ) {
                    Log([string]::Format("Found edge subscription XML on {0}.", $EdgeServer)) Gray
                    $Session = New-PSSession -ComputerName $EdgeServer -Credential $EdgeCreds -Name EdgeResults
                    Copy-Item $edgeResult -Destination C:\Temp -Force -FromSession $Session -ErrorAction Ignore
                    Remove-PSSession -Name EdgeResults -Confirm:$false
                    Log([string]::Format("Creating the edge subscription with {0} for the site {1}.", $EdgeServer, $ExchangeInstall_LocalizedStrings.EdgeSite)) Gray
                    New-EdgeSubscription -FileData ([System.IO.File]::ReadAllBytes('C:\Temp\EdgeSubscription.xml')) -Site $ExchangeInstall_LocalizedStrings.EdgeSite
                    Start-Sleep 5
                    Start-EdgeSynchronization -TargetServer $EdgeServer
                }
                else {
                    Log([string]::Format("Failed to create find edge subscription XML file on {0}", $EdgeServer)) Red
                }
            }
           
            ## Disable Exchange diagnostic and monitoring services
            Log([string]::Format("Disabling unwanted Exchange services for lab environment.")) Gray
            switch ($ExchangeInstall_LocalizedStrings.ExchangeVersion) {
                1 {Set-ServerComponentState $env:COMPUTERNAME -Component Monitoring -State Inactive -Requester Maintenance}
                2 {Set-ServerComponentState $env:COMPUTERNAME -Component RecoveryActionsEnabled -State Inactive -Requester Maintenance}
            }
        
            #Set the minimum number of log files to retain. Don't want 10,000 on active or 100,000 on passive
            $RegistryPath = "HKLM:\Software\Microsoft\ExchangeServer\v15\BackupInformation"
            CheckAndAddRegistryPath -RegistryPath $RegistryPath
            CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'LooseTruncation_MinCopiesToProtect' -Value 0 -PropertyType 'DWORD'
            CheckAndAddRegistryKey -RegistryPath $RegistryPath -Name 'LooseTruncation_MinLogsToProtect' -Value 100 -PropertyType 'DWORD'
        
            ## Finish Exchange configuration
            $DagName = $ExchangeInstall_LocalizedStrings.DagName
            ## Check whether to create a new DAG or to end the script
            switch ($ExchangeInstall_LocalizedStrings.ExchangeInstallType) { ## Checking new or restore
                0 {
                    switch ($ExchangeInstall_LocalizedStrings.DagResult) { ## Checking if existing or new DAG
                        0 { }## Add the Exchange server to the database availability group
                        1 { ## Creating a new Database Availability Group
                            Log([string]::Format("Creating the new Database Availability group named {0}.", $DagName)) Gray
                            ## Determine if there is an administrative access point or not
                            if($ExchangeInstall_LocalizedStrings.DagType -eq 0) {
                                $validWitnessServer = $false
                                $WitnessServer = $ExchangeInstall_LocalizedStrings.WitnessServer
                                while($validWitnessServer -eq $false) {
                                    if(Test-Connection $WitnessServer -Count 1 -ErrorAction Ignore) {
                                        $validWitnessServer = $true
                                    }
                                    else {
                                        Log([string]::Format("The witness server {0} provided is unavailable.", $WitnessServer)) Gray
                                        $WitnessServer = Read-HostWithColor "Please enter the witness server name: "
                                    }
                                }
                                New-DatabaseAvailabilityGroup -Name $DagName -WitnessServer $ExchangeInstall_LocalizedStrings.WitnessServer -WitnessDirectory $ExchangeInstall_LocalizedStrings.WitnessDirectory -DatabaseAvailabilityGroupIpAddresses ([System.Net.IPAddress]::None) | Out-Null                              
                            }
                            else {
                                ## Create the cluster node object in Active Directory and sync those changes
                                PrepareDatabaseAvailabilityGroup
                                SyncADDirectoryPartition
                                ## Get the IP addresses for the DAG and then create the DAG
                                $dagIPs = $ExchangeInstall_LocalizedStrings.DagIpAddress.Split(" ")
                                $dagIPs | ForEach-Object { [IPAddress]$_.Trim() } | Out-Null
                                New-DatabaseAvailabilityGroup -Name $DagName -WitnessServer $ExchangeInstall_LocalizedStrings.WitnessServer -WitnessDirectory $ExchangeInstall_LocalizedStrings.WitnessDirectory -DatabaseAvailabilityGroupIpAddresses $dagIPs | Out-Null                              
                            }
                        }
                        2 {
                            ## Standalone server install
                            Set-Location $env:ExchangeInstallPath\Bin
                            .\Setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAllDomains
                            Log([string]::Format("Server installation complete.")) Gray
                            Restart-Computer
                        }
                    }
                }
                1 {
                    ## This was a recover server and must determine whether a DAG member or standalone server
                    if($null -eq $DagName) {
                        Set-Location $env:ExchangeInstallPath\Bin
                        .\Setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAllDomains
                        Log([string]::Format("Server installation complete.")) Gray
                        Start-Sleep -Seconds 5
                        Restart-Computer
                    }
                }
            }
        
            ## Make sure the MSExchangeRepl service is running before attempting to add Exchange server to the DAG
            Log([string]::Format("Verifying MSExchangeRepl service is running on {0}.", $ServerName)) Gray
            $exchReplServiceRunning = $false
            while($exchReplServiceRunning -eq $false) {
                $exchReplServiceRunning = CheckMSExchangeRepl
            }
            ## Check to ensure the DAG is available before joining
            Log([string]::Format("Verifying {0} is available.", $DagName)) Gray
            $dagAvailable = $false
            while($dagAvailable -eq $false) {
                if(Get-DatabaseAvailabilityGroup $DagName -ErrorAction Ignore) {
                    $dagAvailable = $true
                }
                else {
                    SyncAdConfigPartition
                    Start-Sleep -Seconds 5
                }
            }
            ## Check if the FSW is a DC
            CheckFileShareWitness
            ## Add the Exchange server the the DAG
            Log([string]::Format("Adding server {0} to the DAG {1}.", $ServerName, $DagName)) Gray
            Add-DatabaseAvailabilityGroupServer $DagName -MailboxServer $ServerName
            ## Synchronize Active Directory with the new DAG member
            Log([string]::Format("Synchronizing Active Directory with the latest update.")) Gray
            SyncAdConfigPartition
            ## Confirm Active Directory replication is updated across sites
            Log([string]::Format("Verifying AD replication has completed.")) Gray
            $domainController = $ExchangeInstall_LocalizedStrings.DomainController
            $domainControllers = New-Object System.Collections.ArrayList
            $domainControllers = GetDomainControllers
            $domainControllers | ForEach-Object { 
                $serverFound = $false
                Log([string]::Format("Checking for {0} in {1} on {2}.", $ServerName, $DagName, $_)) Gray
                while( $serverFound -eq $False) {
                    if((Get-DatabaseAvailabilityGroup $DagName -DomainController $_).Servers -match $serverName) {
                        $serverFound = $True
                    }
                    else {
                        SyncAdConfigPartition
                        Start-Sleep -Seconds 5
                    }
                }
            }
            ## Add the mailbox database copies for the recovered server
            if($ExchangeInstall_LocalizedStrings.ExchangeInstallType -eq 1 -and $null -ne $DagName) {
                ## Check if there are database copies to add
                if($ExchangeInstall_LocalizedStrings.DbHasCopies -eq 1) {
                    ## Add the mailbox database copies for this Exchange server
                    Log([string]::Format("Adding database copies to the server.")) Gray
                    AddDatabaseCopies "c:\Temp\$ServerName-DatabaseCopies.txt"
                    ## Reset the activation preferences for the databases
                    Log([string]::Format("Setting database activation preferences.")) Gray
                    SetActivationPreferences "c:\Temp\$ServerName-$DagName-ActivationPreferences.txt"
                }
            }

            Set-Location $env:ExchangeInstallPath\Bin
            .\Setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAllDomains
        
         ## Exchange server setup is complete
            Restart-Computer
        }
    }
    1{ ## Finalize DC setup
    }
}
