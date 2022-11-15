<#
// DeployServer-Step2.ps1
// Modified 10 November 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20221110.1433
//
// Script should automatically start when the virtual machine starts.
// Syntax for running this script:
//
// .\DeployServer-Step2.ps1
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
Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $ExchangeInstall_LocalizedStrings.Username
## New forest deployments have the administrator password set to the workstation
if($ExchangeInstall_LocalizedStrings.DomainPassword.Length -eq 0) {
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $UserCreds_LocalizedStrings.res_0001
}
else {
    Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $ExchangeInstall_LocalizedStrings.DomainPassword
}
Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ExchangeInstall_LocalizedStrings.Domain
Write-Host "COMPLETE"
## Prepare the server to be either an Exchange server or domain controller
switch($ExchangeInstall_LocalizedStrings.ServerType) {
    0 { ## Complete steps required for Exchange server deployment
        ## Prepare Windows to automatically login after reboot and run the next step
        Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step3.ps1 -ServerName ' + $ServerName)
        ## Check and install Microsoft .NET Framework based on Exchange version
        Write-Host "Checking the version of Microsoft .NET Framework..." -ForegroundColor Green -NoNewline
        switch ($ExchangeInstall_LocalizedStrings.ExchangeVersion) {
            2 { Install-Net4Dot8 }
            1 { Install-Net4Dot8 }
            0 { switch ($ExchangeInstall_LocalizedStrings.DotNetResult) {
                0 { Install-Net4Dot8 }
                1 { Install-Net4Dot7Two }
                }
            }
        }
        Write-Host "COMPLETE"
        ## Check if Exchange prerequisites are installed
        $vs2012Install = $true
        $vs2013Install = $true
        $ucmaInstall = $true
        $rewriteInstall = $true
        if((Get-Item "C:\Program Files\Microsoft UCMA 4.0\Runtime\MediaPerf.dll" -ErrorAction Ignore) -and (Get-Item "C:\Program Files\Microsoft UCMA 4.0\Runtime\MediaPerf.dll" -ErrorAction Ignore).VersionInfo.ProductVersion -ne 5.0.8308.0) {$ucmaInstall = $false}
        if((Get-Item $env:windir\system32\vccorlib120.dll -ErrorAction Ignore) -and (Get-Item $env:windir\system32\vccorlib120.dll -ErrorAction Ignore).VersionInfo.ProductVersion -ge 12.0.21005.1) {$vs2013Install = $false}
        if((Get-Item $env:windir\system32\vccorlib110.dll -ErrorAction Ignore) -and (Get-Item $env:windir\system32\vccorlib110.dll -ErrorAction Ignore).VersionInfo.ProductVersion -ge 11.0.51106.1) {$vs2012Install = $false}
        if(Get-Item $env:windir\system32\inetsrv\rewrite.dll -ErrorAction Ignore) {$rewriteInstall = $false}
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
        ## Look to see if URL Rewrite is installed
        Write-Host "Checking for URL Rewrite..." -ForegroundColor Green -NoNewline
        if($rewriteInstall -eq $false) {
            Write-Host "FOUND"
        }
        else {
            Write-Host "Downloading URL Rewrite..." -ForegroundColor Green -NoNewline
            $Url = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
            $Path = "C:\Temp\rewrite_amd64_en-US.msi"
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($url, $path)
            Write-Host "COMPLETE"
            Write-Host "Installing URL Rewrite..." -ForegroundColor Green -NoNewline
            C:\Temp\rewrite_amd64_en-US.msi /passive /norestart /log C:\Temp\rewrite.log
            Start-Sleep -Seconds 2
            while(Get-Process msiexec -ErrorAction SilentlyContinue | where {$_.MainWindowTitle -like "*rewrite*"} ) {
                Write-Host "..." -ForegroundColor Green -NoNewline
                Start-Sleep -Seconds 2
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
        switch($ExchangeInstall_LocalizedStrings.NewAdForest) {
            0 { ## Create the new Active Directory forest
                [securestring]$adSafeModePwd = $ExchangeInstall_LocalizedStrings.AdSafeModePassword | ConvertTo-SecureString -AsPlainText -Force
                ## Prepare server for next step after reboot
                Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step4.ps1 -ServerName ' + $ServerName)
                ## Determine the forest mode
                switch($ExchangeInstall_LocalizedStrings.DomainMode) {
                    0 { $domainMode = "Win2012R2"}
                    1 { $domainMode = "WinThreshold" }
                    2 { $domainMode = "WinThreshold" }
                }
                ## Determine the domain mode
                switch($ExchangeInstall_LocalizedStrings.ForestMode) {
                    0 { $forestMode = "Win2012R2"}
                    1 { $forestMode = "WinThreshold" }
                    2 { $forestMode = "WinThreshold" }
                }
                ## Create the new Active Directory forest
                Write-Host "Creating the new Active Directory forest $domain..." -ForegroundColor Yellow
                Install-ADDSForest -DomainName $ExchangeInstall_LocalizedStrings.AdDomain -DomainMode $domainMode -ForestMode $forestMode -DomainNetbiosName $ExchangeInstall_LocalizedStrings.DomainNetBiosName -SafeModeAdministratorPassword $adSafeModePwd -InstallDns -Confirm:$false
            }
            1 { ## Add an additional domain controller to the forest
                ## Prepare Windows to automatically login after reboot and run the next step
                Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step3.ps1 -ServerName ' + $ServerName)
            }
        }
    }
}
if($ExchangeInstall_LocalizedStrings.NewAdForest -ne 0) {
    ## Join the server to the domain
    ## Credentials are dependent on whether provided during deployment or not
    if($ExchangeInstall_LocalizedStrings.DomainPassword.Length -ne 0) {
        [securestring]$securePwd = $ExchangeInstall_LocalizedStrings.DomainPassword | ConvertTo-SecureString -AsPlainText -Force
    }
    else {
        [securestring]$securePwd = $UserCreds_LocalizedStrings.res_0001 | ConvertTo-SecureString -AsPlainText -Force
    }
    ## Get the domain name to join
    $domain = $ExchangeInstall_LocalizedStrings.Domain
    $UserName = $ExchangeInstall_LocalizedStrings.Username+"@"+$domain
    [PSCredential]$credential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName,$securePwd
    ## Join the server to the domain
    Write-Host "Joining"$ExchangeInstall_LocalizedStrings.ServerName"to the"$ExchangeInstall_LocalizedStrings.Domain"domain..." -ForegroundColor Yellow
    ## Continuous loop for new deployment where server may be online before AD forest is deployed
    while(1){
        Add-Computer -ComputerName $env:COMPUTERNAME -Credential $credential -DomainName $ExchangeInstall_LocalizedStrings.Domain -Restart -ErrorAction Ignore
        Write-Host "." -ForegroundColor Green -NoNewline
        Start-Sleep -Seconds 5
    }
}
