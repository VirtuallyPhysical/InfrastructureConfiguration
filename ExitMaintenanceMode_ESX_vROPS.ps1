$creds = get-credential 

foreach ($Hostname in (Import-CSV .\Hostlist.csv)) {

If ($global:DefaultVIServers) {
Disconnect-VIServer * -Force -Confirm:0
Disconnect-OMServer * -Force -Confirm:0
}

$vcenter_retry_count = 0

while ($global:DefaultVIServer.name -notmatch $Hostname.vcenter) {
Connect-VIServer $Hostname.vcenter -credential $creds
Connect-OMServer $Hostname.vrops -credential $creds

write-host "Connecting to $_.vcenter & $_.vrops" -ForegroundColor Yellow

$vcenter_retry_count++

if ($vcenter_retry_count -eq 2) {break}
}

if ($global:DefaultVIServer) {

Set-VMHost -VMhost $Hostname.hostname -State Connected
(get-inventory -name $Hostname.hostname | Get-OMResource).ExtensionData.UnmarkResourceAsBeingMaintained()
  }
}
