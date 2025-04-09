# ===============================
# UAT Script for Windows Server 2022
# ===============================

# --- Define expected values ---
$ExpectedDNS = @("192.168.1.10", "192.168.1.11")
$ExpectedCDriveSizeGB = 60
$MinFreeSpacePercent = 20
$OutputPath = "$env:USERPROFILE\Desktop\UAT_Results_$env:USERNAME.csv"

# --- Helper to record results ---
function Add-Result {
    param (
        [ref]$Results,
        [string]$Name,
        [string]$Result
    )
    $Results.Value += [PSCustomObject]@{
        'Test Name' = $Name
        'Result'    = $Result
    }
}

# --- UAT Checks ---
function Check-DNSConfig {
    param ($ExpectedDNS, [ref]$Results)
    try {
        $dns = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses -Unique
        $diff = Compare-Object -ReferenceObject $ExpectedDNS -DifferenceObject $dns
        if ($diff) {
            Add-Result -Results $Results -Name "DNS Configuration" -Result "FAIL - Found: $($dns -join ', ')"
        } else {
            Add-Result -Results $Results -Name "DNS Configuration" -Result "PASS"
        }
    } catch {
        Add-Result -Results $Results -Name "DNS Configuration" -Result "ERROR - $_"
    }
}

function Check-CDrive {
    param ($ExpectedSize, $MinFreePercent, [ref]$Results)
    try {
        $drive = Get-PSDrive -Name C
        $totalGB = [math]::Round(($drive.Used + $drive.Free) / 1GB)
        $freePercent = ($drive.Free / ($drive.Used + $drive.Free)) * 100

        if ($totalGB -ne $ExpectedSize) {
            Add-Result -Results $Results -Name "C: Drive Size" -Result "FAIL - Found $totalGB GB"
        } elseif ($freePercent -lt $MinFreePercent) {
            Add-Result -Results $Results -Name "C: Drive Free Space" -Result "FAIL - Only $([math]::Round($freePercent,2))% free"
        } else {
            Add-Result -Results $Results -Name "C: Drive Check" -Result "PASS"
        }
    } catch {
        Add-Result -Results $Results -Name "C: Drive Check" -Result "ERROR - $_"
    }
}

function Check-SyslogSetup {
    param ([ref]$Results)
    try {
        $logInsight = Get-Service -Name "VMwareLogCollector" -ErrorAction SilentlyContinue
        if ($logInsight) {
            Add-Result -Results $Results -Name "Aria Log Insight Agent" -Result "PASS - Installed"
        } else {
            Add-Result -Results $Results -Name "Aria Log Insight Agent" -Result "FAIL - Not Installed"
        }

        $eventForwarding = wevtutil gl "ForwardedEvents" 2>&1
        Add-Result -Results $Results -Name "Syslog Setup (ForwardedEvents)" -Result ($eventForwarding | Out-String).Trim()
    } catch {
        Add-Result -Results $Results -Name "Syslog Setup" -Result "ERROR - $_"
    }
}

function Check-Network {
    param ([ref]$Results)
    try {
        $adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address -ne $null }
        foreach ($adapter in $adapters) {
            $ip = $adapter.IPv4Address.IPAddress
            $subnet = $adapter.IPv4Address.PrefixLength
            $gateway = $adapter.IPv4DefaultGateway.NextHop
            Add-Result -Results $Results -Name "IP/Subnet/Gateway" -Result "$ip/$subnet via $gateway"

            $ping = Test-Connection -ComputerName $gateway -Count 1 -Quiet
            $pingResult = if ($ping) { "PASS" } else { "FAIL - No response from $gateway" }
            Add-Result -Results $Results -Name "Gateway Ping Test" -Result $pingResult
        }
    } catch {
        Add-Result -Results $Results -Name "Network Check" -Result "ERROR - $_"
    }
}

function Check-GPOs {
    param ([ref]$Results)
    try {
        $gpos = gpresult /r /scope:computer 2>&1
        Add-Result -Results $Results -Name "Applied GPOs" -Result ($gpos | Out-String).Trim()
    } catch {
        Add-Result -Results $Results -Name "Applied GPOs" -Result "ERROR - $_"
    }
}

function Check-AdminGroup {
    param ([ref]$Results)
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $adminNames = $admins.Name -join ", "
        Add-Result -Results $Results -Name "Local Admin Group Members" -Result $adminNames
    } catch {
        Add-Result -Results $Results -Name "Local Admin Group Members" -Result "ERROR - $_"
    }
}

function Check-GuestAccount {
    param ([ref]$Results)
    try {
        $guest = Get-LocalUser -Name "Guest"
        $result = if ($guest.Enabled) { "FAIL - Enabled" } else { "PASS - Disabled" }
        Add-Result -Results $Results -Name "Guest Account Status" -Result $result
    } catch {
        Add-Result -Results $Results -Name "Guest Account Status" -Result "ERROR - $_"
    }
}

function Check-WindowsServices {
    param ([ref]$Results)
    try {
        $services = Get-Service | Where-Object { $_.Status -eq "Running" }
        $summary = $services | Select-Object StartType, Status, Name, DisplayName | Out-String
        Add-Result -Results $Results -Name "Running Services" -Result $summary.Trim()
    } catch {
        Add-Result -Results $Results -Name "Running Services" -Result "ERROR - $_"
    }
}

function Check-RDP {
    param ([ref]$Results)
    try {
        $rdpStatus = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
        $enabled = if ($rdpStatus.fDenyTSConnections -eq 0) { "PASS" } else { "FAIL - Disabled" }
        Add-Result -Results $Results -Name "Remote Desktop Enabled" -Result $enabled

        $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
        $rdpNames = if ($rdpUsers) { $rdpUsers.Name -join ", " } else { "No members found or group missing" }
        Add-Result -Results $Results -Name "RDP Group Members" -Result $rdpNames
    } catch {
        Add-Result -Results $Results -Name "Remote Desktop Settings" -Result "ERROR - $_"
    }
}

function Check-WindowsUpdates {
    param ([ref]$Results)
    try {
        $updates = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 5
        Add-Result -Results $Results -Name "Recent Updates" -Result ($updates | Out-String).Trim()
    } catch {
        Add-Result -Results $Results -Name "Recent Updates" -Result "ERROR - $_"
    }
}

function Run-WindowsDefenderScan {
    param ([ref]$Results)
    try {
        Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        $lastScan = Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureLastUpdated
        Add-Result -Results $Results -Name "Windows Defender Last Updated" -Result "$lastScan"
        Add-Result -Results $Results -Name "Windows Defender Scan" -Result "Scan triggered (Quick Scan)"
    } catch {
        Add-Result -Results $Results -Name "Windows Defender Scan" -Result "ERROR - $_"
    }
}

function Check-DomainJoin {
    param ([ref]$Results)
    try {
        $cs = Get-CimInstance -Class Win32_ComputerSystem
        if ($cs.PartOfDomain) {
            Add-Result -Results $Results -Name "Domain Join" -Result "PASS - Joined to $($cs.Domain)"
        } else {
            Add-Result -Results $Results -Name "Domain Join" -Result "FAIL - Not domain joined (Workgroup: $($cs.Workgroup))"
        }
    } catch {
        Add-Result -Results $Results -Name "Domain Join" -Result "ERROR - $_"
    }
}

# --- Final Runner ---
function Run-UAT {
    $Results = @()

    Check-DNSConfig -ExpectedDNS $ExpectedDNS -Results ([ref]$Results)
    Check-CDrive -ExpectedSize $ExpectedCDriveSizeGB -MinFreePercent $MinFreeSpacePercent -Results ([ref]$Results)
    Check-SyslogSetup -Results ([ref]$Results)
    Check-Network -Results ([ref]$Results)
    Check-GPOs -Results ([ref]$Results)
    Check-AdminGroup -Results ([ref]$Results)
    Check-GuestAccount -Results ([ref]$Results)
    Check-WindowsServices -Results ([ref]$Results)
    Check-RDP -Results ([ref]$Results)
    Check-WindowsUpdates -Results ([ref]$Results)
    Run-WindowsDefenderScan -Results ([ref]$Results)
    Check-DomainJoin -Results ([ref]$Results)

    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "UAT completed. Results saved to: $OutputPath"
}

# --- Run it ---
Run-UAT
