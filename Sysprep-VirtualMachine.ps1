#
# Sysprep-VirtualMachine.ps1
# Modified 2020/10/30
# Last Modifier:  Jim Martin
# Project Owner:  Jim Martin
# Version: v1.0

# Syntax for running this script:
#
# .\Sysprep-VirtualMachine.ps1
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

## Create psd1 with variables for the other scripts to use
Write-Host "Storing information so we can pull data needed to build the Exchange server..." -ForegroundColor Green
$stringsFile = "c:\Temp\Sysprep-strings.psd1"
New-Item $stringsFile -ItemType File -ErrorAction Ignore | Out-Null
Add-Content -Path $stringsFile -Value "ConvertFrom-StringData @'"
Add-Content -Path $stringsFile -Value '###PSLOC'

## Enter local credentials for the virtual machine
$local = [xml](Get-Content c:\Temp\unattend.xml)
Add-Content -Path $stringsFile -Value ('res_0000 = ' + $local.unattend.settings.component.autologon.username)
$localAdminPwd = $local.unattend.settings.component.useraccounts.administratorpassword.value
Add-Content -Path $stringsFile -Value ('res_0001 = ' + $localAdminPwd)

## Get VM Host information
$physicalHostname = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").PhysicalHostName
Write-Host "Getting the user credentials for the VM Host " -ForegroundColor Yellow -NoNewline
Write-Host $physicalHostname -NoNewline
Write-Host "..." -ForegroundColor Yellow
$vmHostUsername = Read-Host "Enter the username for $physicalHostname "
Add-Content -Path $stringsFile -Value ('res_0002 = ' + $vmHostUsername)
$vmHostPassword = Read-Host "Enter the password for $vmHostUsername on $physicalHostname "
Add-Content -Path $stringsFile -Value ('res_0003 = ' + $vmHostPassword)
Add-Content -Path $stringsFile -Value ('res_0004 = ' + $physicalHostname)

## Finalize the psd1 file
Add-Content -Path $stringsFile -Value '###PSLOC'
Add-Content -Path $stringsFile -Value "'@"

Write-Host "Setting up deployment script to run when VM starts..." -ForegroundColor Green
## Prepare Windows to automatically login after reboot and run the next step
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" 
## Prepare Windows to automatically login
Set-ItemProperty -Path $RunOnceKey -Name "ExchangeSetup" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File C:\Temp\Start-Setup.ps1')
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value $localAdminPwd
Set-Location C:\Windows\System32\Sysprep
.\sysprep.exe /oobe /generalize /unattend:c:\Temp\unattend.xml
