<#
//***********************************************************************
//
// Start-Setup.ps1
// Modified 16 August 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v20220816
//
//NOTE: Script should automatically start when the virtual machine starts.
//Syntax for running this script:
//
// .\Start-Setup.ps1
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
#$physicalHostname = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").PhysicalHostName
#$scriptFiles = "\\$physicalHostname\c$\Temp"
#New-PSDrive -Name "Script" -PSProvider FileSystem -Root $scriptFiles -Credential $credential
#Move-Item -Path "Script:\$ServerName*" -Destination C:\Temp
#Copy-Item -Path "Script:\DeployServer*.ps1" -Destination C:\Temp

Write-Host "Rebooting server..." -ForegroundColor Yellow
Start-Sleep -Seconds 3
Restart-Computer
