# ================================================#
# Version: 0.1                                    #
# Author: Tony Reardon                            #
# Connect to vCenter and run OS Validation        #
# agaist a csv list of VMs                        #
# ================================================#

#Powershell setup
Import-Module VMware.VimAutomation.core
Set-PowerCLIConfiguration -InvalidCertificate Ignore -Confirm:$false

#Variables
Write-Host "Enter your vCenter Credentials" -ForegroundColor Green
$cred = Get-Credential -message "Enter vCenter Credentials"
$vCentres = @(
    "vcenter1.prod.co.uk",
    "vcenter2.prod.co.uk",
    "vcenter3.nonprod.co.uk",
    "vcenter4.nonprod.co.uk"
    )
write-host "Importing list of vCentres: $vCentres" -ForegroundColor Green
write-Host "Enter your Windows OS Credentials" -ForegroundColor Green
$scriptpath = "D:\OS-BuildValidationTest.ps1"
$guestCredential = Get-Credential -message "Enter Guest OS Credentials" 
$guestUser = $guestCredential.UserName
$guestPassword = $guestCredential.GetNetworkCredential().Password
$csvPath = Read-Host "Enter full path to csv with VM names"
$vmList = Import-Csv -Path $csvPath

#Connect to vCentres
foreach ($vCentre in $vCentres){ 
    Write-Host "Connecting to $vCentre"  -ForegroundColor Cyan
    try {
        Connect-VIServer -Server $vCentre -Credential $cred -ErrorAction Stop
    }
    Catch {
        Write-Warning "Failed to connect to $vCentre $_"
        }
    }

$guestcred = New-Object System.Management.Automation.PSCredential($guestUser, (ConvertTo-SecureString $guestPassword -AsPlainText -Force))
 
#Connect to each VM via VMware Tools, Upload OS Validation Test Script, Run Script and then Download script results
foreach ($vm in $vmlist) {
    $vmname = $vm.VMName
    $vmvcenter = $vm.vCenter
    Write-Host "Processing VM: $vmname" -ForegroundColor Yellow

    $vm = Get-VM -Name $vmname -server $vmvcenter -ErrorAction SilentlyContinue
    $vm2 = $vmname.ToUpper()
    #$vcenter = Get-VIServer -server $vmvcenter
    if (-not $vm) {
        Write-Warning "VM $vmname not found in vCenter"
        continue
    }

    try {
        #Copy Script to VM
        write-host "Copy script to $VM" -foreground Yellow
        Copy-VMGuestFile -server $vmvcenter -Source $scriptpath -Destination "C:\Temp" -VM $vm -LocalToGuest -GuestUser $guestUser -GuestPassword $guestPassword -Force -ErrorAction SilentlyContinue
        #Copy-VMGuestFile -server $vcenter -Source $scriptpath -Destination "C:\Temp" -VM $vm -LocalToGuest -GuestCredential $guestCredential -Force -ErrorAction SilentlyContinue
        #Run OS Validation Script
        write-host "Run script on $VM" -foreground Yellow
        Invoke-VMscript -server $vcenter -VM $vm -ScriptText 'Set-ExecutionPolicy -Scope Process -ExecutionPolicy bypass; & "C:\Temp\OS-BuildValidationTest - Prod v2.0.ps1"' -GuestUser $guestUser -GuestPassword $guestPassword -ScriptType Powershell -ErrorAction SilentlyContinue
        #Copy OS Validation results to local VM
        write-host "Copy results to to $env:COMPUTERNAME" -foreground Yellow
        Copy-VMGuestFile -server $vcenter -Source "C:\Temp\UAT_Results_$vm2.csv" -Destination "D:\Build\Horizon\vCentre Export\OS Validation Tests" -VM $vm -GuestToLocal -GuestUser $guestUser -GuestPassword $guestPassword -Force -ErrorAction SilentlyContinue
        #Delete files on remote VM/Cleanup
        #Invoke-VMscript -server $vcenter -VM $vm -ScriptText 'Set-ExecutionPolicy -Scope Process -ExecutionPolicy bypass; Remove-Item -Path "C:\Temp\UAT_Results_$env:COMPUTERNAME.csv", "C:\Temp\OS-BuildValidationTest - Prod v2.0.ps1" -Force' -GuestCredential $guestCredential -ScriptType Powershell -ErrorAction SilentlyContinue

        Write-Host "Script executed on $vmname successfully" -ForegroundColor Green

        }
        Catch {
            Write-Warning "Failed to execute script on $vmname : $_"
        }
    }

    #Disconnect-VIServer -Server $vCenter -Confirm:$false
