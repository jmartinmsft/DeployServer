#
# DeployServer-Step2.ps1
# Modified 2020/10/30
# Last Modifier:  Jim Martin
# Project Owner:  Jim Martin
# Version: v1.0

# Script should automatically start when the virtual machine starts
# Syntax for running this script:
#
# .\DeployServer-Step2.ps1
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

Clear-Host
function Install-Net4Dot7Two {
    ## Check if the currently installed version of Microsoft .NET Framework is below 4.7.2
    [int]$NetVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction Ignore).Release
    if($NetVersion -lt 461814) {
        ## Check for the required Windows update before installing
        if(CheckFor2919355) {
            ## Download and install Microsoft .NET Framework 4.7.2
            $WebClient = New-Object System.Net.WebClient 
            Write-Host "Downloading Microsoft .NET Framework 4.7.2..." -ForegroundColor Green 
            $Url = "https://download.microsoft.com/download/6/E/4/6E48E8AB-DC00-419E-9704-06DD46E5F81D/NDP472-KB4054530-x86-x64-AllOS-ENU.exe" 
            $Path = "C:\Temp\NDP472-KB4054530-x86-x64-AllOS-ENU.exe" 
            $WebClient.DownloadFile($url, $path)
            Write-Host "Installing Microsoft .NET Framework 4.7.2..." -ForegroundColor Green 
            C:\Temp\NDP472-KB4054530-x86-x64-AllOS-ENU.exe /passive /norestart
            while(Get-Process NDP472-KB4054530-x86-x64-AllOS-ENU -ErrorAction SilentlyContinue) {
                Write-Host "..." -ForegroundColor Green -NoNewline
                Start-Sleep -Seconds 10
            }
            Write-Host "COMPLETE"
        }
        else {
            Write-Host "You are missing a required Windows Update. Please either check for updates or download from:" -ForegroundColor Yellow
            Write-Host  "https://download.microsoft.com/download/2/5/6/256CCCFB-5341-4A8D-A277-8A81B21A1E35/Windows8.1-KB2919355-x64.msu"
            exit
        }
    }
 }
function Install-Net4Dot8 {
## Check if the currently installed version of Microsoft .NET Framework is below 4.8
[int]$NetVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction Ignore).Release
    if($NetVersion -lt 528049) {
        ## Download and install Microsoft .NET Framework 4.8
        $webClient = New-Object System.Net.WebClient
        Write-Host "Downloading Microsoft .NET Framework 4.8..." -ForegroundColor Green -NoNewline
        $Url = "https://go.microsoft.com/fwlink/?linkid=2088631" 
        $Path = "C:\Temp\ndp48-x86-x64-allos-enu.exe" 
        $WebClient.DownloadFile($url, $path)
        Write-Host "COMPLETE"
        Write-Host "Installing Microsoft .NET Framework 4.8..." -ForegroundColor Green -NoNewline
        C:\Temp\ndp48-x86-x64-allos-enu /passive /norestart
        while(Get-Process ndp48-x86-x64-allos-enu -ErrorAction SilentlyContinue) {
            Write-Host "..." -ForegroundColor Green -NoNewline
            Start-Sleep -Seconds 10
        }
        Write-Host "COMPLETE"
    }
}
function CheckFor2919355 {
    ## Check Windows update history for required update for Microsoft .NET Framework 4.7.2
    $wuSession = New-Object -ComObject Microsoft.Update.Session
    if($wuSession.QueryHistory("",0,50) | where { $_.Title -like '*2919355*'}) {
        return $true
    }
}
Start-Transcript -Path C:\Temp\DeployServer-Log.txt -Append -NoClobber | Out-Null
Write-Host "Running the Step2 script now..." -ForegroundColor Yellow
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
## Set AutoLogon for the next step
Write-Host "Preparing server for the next step..." -ForegroundColor Green -NoNewline
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
$WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1"
Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "5" 
Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $ExchangeInstall_LocalizedStrings.res_0013
## New forest deployments have the administrator password set to the workstation
if($ExchangeInstall_LocalizedStrings.res_0012.Length -eq 0) {
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $UserCreds_LocalizedStrings.res_0001
}
else {
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $ExchangeInstall_LocalizedStrings.res_0012
}
Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ExchangeInstall_LocalizedStrings.res_0014
Write-Host "COMPLETE"
## Prepare the server to be either an Exchange server or domain controller
switch($ExchangeInstall_LocalizedStrings.res_0099) {
    0 { ## Complete steps required for Exchange server deployment
        ## Prepare Windows to automatically login after reboot and run the next step
        Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step3.ps1 -ServerName ' + $ServerName)
        ## Check and install Microsoft .NET Framework based on Exchange version
        Write-Host "Checking the version of Microsoft .NET Framework..." -ForegroundColor Green -NoNewline
        switch ($ExchangeInstall_LocalizedStrings.res_0003) {
            2 { Install-Net4Dot8 }
            1 { Install-Net4Dot8 }
            0 { switch ($ExchangeInstall_LocalizedStrings.res_0016) {
                0 { Install-Net4Dot8 }
                1 { Install-Net4Dot7Two }
                }
            }
        }
        Write-Host "COMPLETE"
        ## Check if Exchange prerequisites are installed
        $vs2012Install = $true
        $vs2013Install = $true
        $ucmaInstall =$true
        if((Get-Item "C:\Program Files\Microsoft UCMA 4.0\Runtime\MediaPerf.dll" -ErrorAction Ignore) -and (Get-Item "C:\Program Files\Microsoft UCMA 4.0\Runtime\MediaPerf.dll" -ErrorAction Ignore).VersionInfo.ProductVersion -ne 5.0.8308.0) {$ucmaInstall = $false}
        if((Get-Item $env:windir\system32\vccorlib120.dll -ErrorAction Ignore) -and (Get-Item $env:windir\system32\vccorlib120.dll -ErrorAction Ignore).VersionInfo.ProductVersion -ge 12.0.21005.1) {$vs2013Install = $false}
        if((Get-Item $env:windir\system32\vccorlib110.dll -ErrorAction Ignore) -and (Get-Item $env:windir\system32\vccorlib110.dll -ErrorAction Ignore).VersionInfo.ProductVersion -ge 11.0.51106.1) {$vs2012Install = $false}
        ## Look to see if Visual C++ Redistributable Package for Visual Studio 2012 is installed
        Write-Host "Checking for Visual C++ Redistributable Package for Visual Studio 2012..." -ForegroundColor Green -NoNewline
        if($vs2012Install -eq $false) { 
            Write-Host "FOUND"
        }
        else {
            ## Download and install Visual C++ Redistributable Package for Visual Studio 2012
            Write-Host "MISSING"
            Write-Host "Downloading Visual C++ Redistributable Package for Visual Studio 2012..." -ForegroundColor Green -NoNewline
            $Url = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"
            $Path = "C:\Temp\vcredist_x64-2012.exe"
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($url, $path)
            Write-Host "COMPLETE"
            Write-Host "Installing Visual C++ Redistributable Package for Visual Studio 2012..." -ForegroundColor Green -NoNewline
            C:\Temp\vcredist_x64-2012.exe /install /passive /norestart
            while(Get-Process vcredist_x64-2012 -ErrorAction SilentlyContinue) {
                Write-Host "..." -ForegroundColor Green -NoNewline
                Start-Sleep -Seconds 10
            }
            Write-Host "COMPLETE"
        }
        ## Look to see if Visual C++ Redistributable Package for Visual Studio 2013 is installed
        Write-Host "Checking for Visual C++ Redistributable Package for Visual Studio 2013..." -ForegroundColor Green -NoNewline
        if($vs2013Install -eq $false) { 
            Write-Host "FOUND"
        }
        else {
            ## Download and install Visual C++ Redistributable Package for Visual Studio 2013
            Write-Host "MISSING"
            Write-Host "Downloading Visual C++ Redistributable Package for Visual Studio 2013..." -ForegroundColor Green -NoNewline
            $Url = "https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe"
            $Path = "C:\Temp\vcredist_x64-2013.exe"
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($url, $path)
            Write-Host "COMPLETE"
            Write-Host "Installing Visual C++ Redistributable Package for Visual Studio 2013..." -ForegroundColor Green -NoNewline
            C:\Temp\vcredist_x64-2013.exe /install /passive /norestart
            while(Get-Process vcredist_x64-2013 -ErrorAction SilentlyContinue) {
                Write-Host "..." -ForegroundColor Green -NoNewline
                Start-Sleep -Seconds 10
            }
            Write-Host "COMPLETE"
        }
        ## Look to see if Unified Communications Managed API 4.0 is installed
        Write-Host "Checking for Unified Communications Managed API 4.0..." -ForegroundColor Green -NoNewline
        if($ucmaInstall -eq $false) { 
            Write-Host "FOUND"
        }
        else {
            ## Download and install Unified Communications Managed API 4.0
            Write-Host "MISSING"
            Write-Host "Downloading Unified Communications Managed API 4.0..." -ForegroundColor Green -NoNewline
            $Url = "https://download.microsoft.com/download/2/C/4/2C47A5C1-A1F3-4843-B9FE-84C0032C61EC/UcmaRuntimeSetup.exe"
            $Path = "C:\Temp\UcmaRuntimeSetup.exe" 
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($url, $path)
            Write-Host "COMPLETE"
            Write-Host "Installing Unified Communications Managed API 4.0..." -ForegroundColor Green -NoNewline
            C:\Temp\UcmaRuntimeSetup /passive /norestart
            while(Get-Process UcmaRuntimeSetup -ErrorAction SilentlyContinue) {
                Write-Host "..." -ForegroundColor Green -NoNewline
                Start-Sleep -Seconds 10
            }
            Write-Host "COMPLETE"
        }
}
    1 { ## Make this server a domain controller
        switch($ExchangeInstall_LocalizedStrings.res_0100) {
            0 { ## Create the new Active Directory forest
                [securestring]$adSafeModePwd = $ExchangeInstall_LocalizedStrings.res_0105 | ConvertTo-SecureString -AsPlainText -Force
                ## Prepare server for next step after reboot
                Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step4.ps1 -ServerName ' + $ServerName)
                ## Determine the forest mode
                switch($ExchangeInstall_LocalizedStrings.res_0102) {
                    0 { $domainMode = "Win2012R2"}
                    1 { $domainMode = "WinThreshold" }
                    2 { $domainMode = "WinThreshold" }
                }
                ## Determine the domain mode
                switch($ExchangeInstall_LocalizedStrings.res_0103) {
                    0 { $forestMode = "Win2012R2"}
                    1 { $forestMode = "WinThreshold" }
                    2 { $forestMode = "WinThreshold" }
                }
                ## Create the new Active Directory forest
                Write-Host "Creating the new Active Directory forest $domain..." -ForegroundColor Yellow
                Install-ADDSForest -DomainName $ExchangeInstall_LocalizedStrings.res_0101 -DomainMode $domainMode -ForestMode $forestMode -DomainNetbiosName $ExchangeInstall_LocalizedStrings.res_0104 -SafeModeAdministratorPassword $adSafeModePwd -InstallDns -Confirm:$false
            }
            1 { ## Add an additional domain controller to the forest
                ## Prepare Windows to automatically login after reboot and run the next step
                Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step3.ps1 -ServerName ' + $ServerName)
            }
        }
    }
}
if($ExchangeInstall_LocalizedStrings.res_0100 -ne 0) {
    ## Join the server to the domain
    ## Credentials are dependent on whether provided during deployment or not
    if($ExchangeInstall_LocalizedStrings.res_0012.Length -ne 0) {
        [securestring]$securePwd = $ExchangeInstall_LocalizedStrings.res_0012 | ConvertTo-SecureString -AsPlainText -Force
    }
    else {
        [securestring]$securePwd = $UserCreds_LocalizedStrings.res_0001 | ConvertTo-SecureString -AsPlainText -Force
    }
    ## Get the domain name to join
    $domain = $ExchangeInstall_LocalizedStrings.res_0014
    $UserName = $ExchangeInstall_LocalizedStrings.res_0013+"@"+$domain
    [PSCredential]$credential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName,$securePwd
    ## Join the server to the domain
    Write-Host "Joining"$ExchangeInstall_LocalizedStrings.res_0000"to the"$ExchangeInstall_LocalizedStrings.res_0014"domain..." -ForegroundColor Yellow
    ## Continuous loop for new deployment where server may be online before AD forest is deployed
    while(1){
        Add-Computer -ComputerName $env:COMPUTERNAME -Credential $credential -DomainName $ExchangeInstall_LocalizedStrings.res_0014 -Restart -ErrorAction Ignore
        Write-Host "." -ForegroundColor Green -NoNewline
        Start-Sleep -Seconds 5
    }
}