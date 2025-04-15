# Load VMware PowerCLI module
Import-Module VMware.PowerCLI

# Suppress certificate warnings
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

# Connect to vCenter
$vCenter = Read-Host "Enter vCenter FQDN or IP"
Connect-VIServer -Server $vCenter

# Prompt for credentials to use for guest OS
$guestCredential = Get-Credential -Message "Enter guest OS credentials"

# Prompt for path to VM list CSV
$csvPath = Read-Host "Enter full path to CSV containing VM names"
$vmList = Import-Csv -Path $csvPath

# Prompt for path to the PowerShell script (UNC)
$remoteScriptPath = Read-Host "Enter the UNC path of the script (e.g. \\domain\share\script.ps1)"

# Loop through each VM and run the script
foreach ($vmEntry in $vmList) {
    $vmName = $vmEntry.VMName
    Write-Host "Processing VM: $vmName" -ForegroundColor Cyan

    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Warning "VM $vmName not found in vCenter."
        continue
    }

    # Run PowerShell command via VMware Tools
    try {
        Invoke-VMScript -VM $vm `
                        -ScriptText "powershell -ExecutionPolicy Bypass -File '$remoteScriptPath'" `
                        -GuestCredential $guestCredential `
                        -ScriptType Powershell `
                        -ErrorAction Stop | Out-Null

        Write-Host "Script executed on $vmName successfully." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to execute script on $vmName: $_"
    }
}

# Disconnect from vCenter
Disconnect-VIServer -Server $vCenter -Confirm:$false
