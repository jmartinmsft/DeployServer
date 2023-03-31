<#
//***********************************************************************
//
// Sysprep-VirtualMachine.ps1
// Modified 31 March 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20230331.1506
//
//Syntax for running this script:
//
// .\Sysprep-VirtualMachine.ps1
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
Clear-Host
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
##Check the unattend XML file before continuing
if((Select-String -Path C:\Temp\unattend.xml -Pattern "ProductKey") -like "*XXXXX*") {
    Write-Warning "You must modify the Product Key in the unattend XML before running this script."
    Start-Sleep -Seconds 5
    break
}
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
$vmPassword = Read-Host "Enter the password for $vmHostUsername on $physicalHostname " -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($vmPassword)            
$vmHostPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
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
