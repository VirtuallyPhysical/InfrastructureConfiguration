# ===============================
# UAT Script for Windows Server 2022
# ===============================

# Define expected values (update these as required)
$ExpectedDNS = @("192.168.1.10", "192.168.1.11")
$ExpectedCDriveSizeGB = 60
$MinFreeSpacePercent = 20

# Output path set to current user's Desktop
$Username = $env:USERNAME
$OutputPath = "$env:USERPROFILE\Desktop\UAT_Results_$Username.csv"

# Create a list to store test results
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
    try {
        $dns = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses -Unique
        $diff = Compare-Object -ReferenceObject $ExpectedDNS -DifferenceObject $dns
        if ($diff) {
            Add-Result "DNS Configuration" "FAIL - Found: $($dns -join ', ')"
        } else {
            Add-Result "DNS Configuration" "PASS"
        }
    } catch {
        Add-Result "DNS Configuration" "ERROR - $_"
    }
}

function Check-CDrive {
    try {
        $drive = Get-PSDrive -Name C
        $totalGB = [math]::Round(($drive.Used + $drive.Free) / 1GB)
        $freePercent = ($drive.Free / ($drive.Used + $drive.Free)) * 100

        if ($totalGB -ne $ExpectedCDriveSizeGB) {
            Add-Result "C: Drive Size" "FAIL - Found $totalGB GB"
        } elseif ($freePercent -lt $MinFreeSpacePercent) {
            Add-Result "C: Drive Free Space" "FAIL - Only $([math]::Round($freePercent,2))% free"
        } else {
            Add-Result "C: Drive Check" "PASS"
        }
    } catch {
        Add-Result "C: Drive Check" "ERROR - $_"
    }
}

function Check-SyslogSetup {
    try {
        $logInsight = Get-Service -Name "VMwareLogCollector" -ErrorAction SilentlyContinue
        if ($logInsight) {
            Add-Result "Aria Log Insight Agent" "PASS - Installed"
        } else {
            Add-Result "Aria Log Insight Agent" "FAIL - Not Installed"
        }

        $eventForwarding = wevtutil gl "ForwardedEvents" 2>&1
        Add-Result "Syslog Setup (ForwardedEvents)" ($eventForwarding | Out-String).Trim()
    } catch {
        Add-Result "Syslog Setup" "ERROR - $_"
    }
}

function Check-Network {
    try {
        $adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address -ne $null }
        foreach ($adapter in $adapters) {
            $ip = $adapter.IPv4Address.IPAddress
            $subnet = $adapter.IPv4Address.PrefixLength
            $gateway = $adapter.IPv4DefaultGateway.NextHop
            Add-Result "IP/Subnet/Gateway" "$ip/$subnet via $gateway"

            $ping = Test-Connection -ComputerName $gateway -Count 1 -Quiet
            if ($ping) {
                Add-Result "Gateway Ping Test" "PASS"
            } else {
                Add-Result "Gateway Ping Test" "FAIL - No response from $gateway"
            }
        }
    } catch {
        Add-Result "Network Check" "ERROR - $_"
    }
}

function Check-GPOs {
    try {
        $gpos = gpresult /r /scope:computer 2>&1
        Add-Result "Applied GPOs" ($gpos | Out-String).Trim()
    } catch {
        Add-Result "Applied GPOs" "ERROR - $_"
    }
}

function Check-AdminGroup {
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $adminNames = $admins.Name -join ", "
        Add-Result "Local Admin Group Members" $adminNames
    } catch {
        Add-Result "Local Admin Group Members" "ERROR - $_"
    }
}

function Check-GuestAccount {
    try {
        $guest = Get-LocalUser -Name "Guest"
        if ($guest.Enabled) {
            Add-Result "Guest Account Status" "FAIL - Enabled"
        } else {
            Add-Result "Guest Account Status" "PASS - Disabled"
        }
    } catch {
        Add-Result "Guest Account Status" "ERROR - $_"
    }
}

function Check-WindowsServices {
    try {
        $services = Get-Service | Where-Object { $_.Status -eq "Running" }
        $serviceSummary = $services | Select-Object StartType, Status, Name, DisplayName | Out-String
        Add-Result "Running Services" $serviceSummary.Trim()
    } catch {
        Add-Result "Running Services" "ERROR - $_"
    }
}

function Check-RDP {
    try {
        $rdpStatus = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
        if ($rdpStatus.fDenyTSConnections -eq 0) {
            Add-Result "Remote Desktop Enabled" "PASS"
        } else {
            Add-Result "Remote Desktop Enabled" "FAIL - Disabled"
        }

        $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
        if ($rdpUsers) {
            $names = $rdpUsers.Name -join ", "
            Add-Result "RDP Group Members" $names
        } else {
            Add-Result "RDP Group Members" "No members found or group does not exist"
        }
    } catch {
        Add-Result "Remote Desktop Settings" "ERROR - $_"
    }
}

function Check-WindowsUpdates {
    try {
        $updates = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 5
        Add-Result "Recent Updates" ($updates | Out-String).Trim()
    } catch {
        Add-Result "Recent Updates" "ERROR - $_"
    }
}

function Run-WindowsDefenderScan {
    try {
        Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        $lastScan = Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureLastUpdated
        Add-Result "Windows Defender Last Updated" "$lastScan"
        Add-Result "Windows Defender Scan" "Scan triggered (Quick Scan)"
    } catch {
        Add-Result "Windows Defender Scan" "ERROR - $_"
    }
}

function Check-DomainJoin {
    try {
        $cs = Get-CimInstance -Class Win32_ComputerSystem
        if ($cs.PartOfDomain) {
            Add-Result "Domain Join" "PASS - Joined to $($cs.Domain)"
        } else {
            Add-Result "Domain Join" "FAIL - Not domain joined (Workgroup: $($cs.Workgroup))"
        }
    } catch {
        Add-Result "Domain Join" "ERROR - $_"
    }
}

# ==========================
# Run all checks
# ==========================
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

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "UAT completed. Results saved to: $OutputPath"
