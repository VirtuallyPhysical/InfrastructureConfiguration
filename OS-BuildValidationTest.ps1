# Define expected variables
$ExpectedDNS = @("192.168.1.10", "192.168.1.11")
$ExpectedCDriveSizeGB = 60
$MinFreeSpacePercent = 20

$OutputPath = "C:\Users\%username%\Desktop\UAT_Results.csv"
$Results = @()

function Add-Result {
    param (
        [string]$Name,
        [string]$Result
    )
    $Results += [PSCustomObject]@{
        'Test Name' = $Name
        'Result'    = $Result
    }
}

function Check-DNSConfig {
    $dns = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses
    $diff = Compare-Object -ReferenceObject $ExpectedDNS -DifferenceObject $dns
    if ($diff) {
        Add-Result "DNS Configuration" "FAIL - Found: $($dns -join ', ')"
    } else {
        Add-Result "DNS Configuration" "PASS"
    }
}

function Check-CDrive {
    $drive = Get-PSDrive -Name C
    $sizeGB = [math]::Round($drive.Used + $drive.Free / 1GB)
    $freePercent = ($drive.Free / ($drive.Used + $drive.Free)) * 100

    if ($sizeGB -ne $ExpectedCDriveSizeGB) {
        Add-Result "C: Drive Size" "FAIL - Found $sizeGB GB"
    } elseif ($freePercent -lt $MinFreeSpacePercent) {
        Add-Result "C: Drive Free Space" "FAIL - Only $([math]::Round($freePercent,2))% free"
    } else {
        Add-Result "C: Drive Check" "PASS"
    }
}

function Check-SyslogSetup {
    $logInsight = Get-Service -Name "VMwareLogCollector" -ErrorAction SilentlyContinue
    $eventForwarding = wevtutil gl "ForwardedEvents" 2>&1

    if ($logInsight) {
        Add-Result "Aria Log Insight Agent" "PASS - Installed"
    } else {
        Add-Result "Aria Log Insight Agent" "FAIL - Not Installed"
    }

    Add-Result "Syslog Setup (ForwardedEvents)" ($eventForwarding | Out-String)
}

function Check-Network {
    $adapters = Get-NetIPConfiguration | Where-Object {$_.IPv4Address -ne $null}
    foreach ($adapter in $adapters) {
        $ip = $adapter.IPv4Address.IPAddress
        $subnet = $adapter.IPv4Address.PrefixLength
        $gateway = $adapter.IPv4DefaultGateway.NextHop
        Add-Result "IP/Subnet/Gateway" "$ip/$subnet via $gateway"

        $ping = Test-Connection -ComputerName $gateway -Count 1 -Quiet
        Add-Result "Gateway Ping Test" ($ping ? "PASS" : "FAIL - No response from $gateway")
    }
}

function Check-GPOs {
    $gpos = gpresult /r /scope:computer
    Add-Result "Applied GPOs" ($gpos | Out-String)
}

function Check-AdminGroup {
    $admins = Get-LocalGroupMember -Group "Administrators"
    $adminNames = $admins.Name -join ", "
    Add-Result "Local Admin Group Members" $adminNames
}

function Check-GuestAccount {
    $guest = Get-LocalUser -Name "Guest"
    if ($guest.Enabled) {
        Add-Result "Guest Account Status" "FAIL - Enabled"
    } else {
        Add-Result "Guest Account Status" "PASS - Disabled"
    }
}

function Check-WindowsServices {
    $services = Get-Service | Where-Object { $_.Status -eq "Running" }
    $serviceSummary = $services | Select-Object StartType, Status, Name, DisplayName | Out-String
    Add-Result "Running Services" $serviceSummary
}

function Check-RDP {
    $rdpStatus = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
    $enabled = $rdpStatus.fDenyTSConnections -eq 0
    Add-Result "Remote Desktop Enabled" ($enabled ? "PASS" : "FAIL - Disabled")

    $rdpGroups = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").UserAuthentication
    $rdpGroupMemberships = (Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue) | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue
    Add-Result "RDP Group Members" ($rdpGroupMemberships -join ", ")
}

function Check-WindowsUpdates {
    $updates = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 5
    Add-Result "Recent Updates" ($updates | Out-String)
}

function Run-WindowsDefenderScan {
    Start-MpScan -ScanType QuickScan
    Start-Sleep -Seconds 10  # Wait briefly
    $lastScan = Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureLastUpdated
    Add-Result "Windows Defender Last Updated" "$lastScan"
    Add-Result "Windows Defender Scan" "Scan triggered (quick scan)"
}

function Check-DomainJoin {
    $domain = (Get-WmiObject Win32_ComputerSystem).Domain
    $isWorkgroup = (Get-WmiObject Win32_ComputerSystem).PartOfDomain -eq $false
    if ($isWorkgroup) {
        Add-Result "Domain Join" "FAIL - Not joined to domain (Workgroup: $domain)"
    } else {
        Add-Result "Domain Join" "PASS - Joined to $domain"
    }
}

# Run Tests
Check-DNSConfig
Check-CDrive
Check-SyslogSetup
Check-Network
Check-GPOs
Check-AdminGroup
Check-GuestAccount
Check-WindowsServices
Check-RDP
Check-WindowsUpdates
Run-WindowsDefenderScan
Check-DomainJoin

# Export Results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "UAT completed. Results exported to $OutputPath"