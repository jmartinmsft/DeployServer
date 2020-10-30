#
# Start-Setup.ps1
# Modified 2020/10/30
# Last Modifier:  Jim Martin
# Project Owner:  Jim Martin
# Version: v1.0

# Script should automatically start when the virtual machine starts
# Syntax for running this script:
#
# .\Start-Setup.ps1
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

Write-Host "Running the Start-Setup script..." -ForegroundColor Yellow
Import-LocalizedData -BindingVariable UserCreds_LocalizedStrings -FileName "Sysprep-strings.psd1" -BaseDirectory C:\Temp

## Get the VM name
while($ServerName.Length -lt 1) {
    $ServerName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").VirtualMachineName
    if($ServerName -eq $null) { Start-Sleep -Seconds 5}
}

Write-Host "Setting up server deployment script to run when VM starts..." -ForegroundColor Yellow
## Prepare Windows to automatically login after reboot and run the next step
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\DeployServer-Step1.ps1')
$WinLogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $WinLogonKey -Name "AutoAdminLogon" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "AutoLogonCount" -Value "1" 
Set-ItemProperty -Path $WinLogonKey -Name "DefaultUserName" -Value $UserCreds_LocalizedStrings.res_0000
Set-ItemProperty -Path $WinLogonKey -Name "DefaultPassword" -Value $UserCreds_LocalizedStrings.res_0001
Set-ItemProperty -Path $WinLogonKey -Name "DefaultDomainName" -Value $ServerName

## Make sure the virtual machine always has the latest files
$UserName = $UserCreds_LocalizedStrings.res_0002
[securestring]$securePwd = $UserCreds_LocalizedStrings.res_0003 | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$credential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName,$securePwd

## Get VM Host information
$physicalHostname = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").PhysicalHostName
$scriptFiles = "\\$physicalHostname\c$\Temp"
New-PSDrive -Name "Script" -PSProvider FileSystem -Root $scriptFiles -Credential $credential
Move-Item -Path "Script:\$ServerName*" -Destination C:\Temp
Copy-Item -Path "Script:\DeployServer*.ps1" -Destination C:\Temp

Write-Host "Rebooting server..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
Restart-Computer