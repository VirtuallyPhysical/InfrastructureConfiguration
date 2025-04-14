# ===============================
# UAT Script for Windows Server 2022
# ===============================

# --- Define expected values ---
$ExpectedDNS = @("192.168.1.10", "192.168.1.11")
$ExpectedCDriveSizeGB = 59
$MinFreeSpacePercent = 10
$OutputPath = ".\UAT_Results_$env:USERNAME.csv"

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
        $configuredDNS = Get-DnsClientServerAddress -AddressFamily IPv4 |
                         Select-Object -ExpandProperty ServerAddresses -Unique

        $expectedString = $ExpectedDNS -join ", "
        $actualString = $configuredDNS -join ", "

        if ($ExpectedDNS.Count -ne $configuredDNS.Count) {
            Add-Result -Results $Results -Name "DNS Configuration" -Result "FAIL - Count mismatch. Expected: $expectedString | Found: $actualString"
        }
        elseif (-not ($ExpectedDNS -eq $configuredDNS)) {
            Add-Result -Results $Results -Name "DNS Configuration" -Result "FAIL - Order mismatch. Expected: $expectedString | Found: $actualString"
        }
        else {
            Add-Result -Results $Results -Name "DNS Configuration" -Result "PASS - DNS matches expected order: $actualString"
        }
    } catch {
        Add-Result -Results $Results -Name "DNS Configuration" -Result "ERROR - $_"
    }
}

function Check-CDrive {
    param ($ExpectedSize, $MinFreePercent, [ref]$Results)
    try {
        $drive = Get-PSDrive -Name C
        $totalGB = [math]::Round(($drive.Used + $drive.Free) / 1GB, 2)
        $freeGB = [math]::Round($drive.Free / 1GB, 2)
        $freePercent = [math]::Round(($drive.Free / ($drive.Used + $drive.Free)) * 100, 2)

        $summary = "Size: ${totalGB}GB, Free: ${freeGB}GB (${freePercent}%)"

        $sizeOK = ([math]::Abs($totalGB - $ExpectedSize) -le 1)
        $spaceOK = ($freePercent -ge $MinFreePercent)

        if ($sizeOK -and $spaceOK) {
            Add-Result -Results $Results -Name "C: Drive Check" -Result "PASS - $summary"
        } else {
            Add-Result -Results $Results -Name "C: Drive Check" -Result "FAIL - $summary"
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
            $dnsServers = ($adapter.DNSServer.ServerAddresses -join ", ")

            Add-Result -Results $Results -Name "IP/Subnet/Gateway/DNS" -Result "$ip/$subnet via $gateway | DNS: $dnsServers"

            $ping = Test-Connection -ComputerName $gateway -Count 1 -Quiet
            $pingResult = if ($ping) { "PASS" } else { "FAIL - No response from $gateway" }
            Add-Result -Results $Results -Name "Gateway Ping Test" -Result $pingResult
        }
    } catch {
        Add-Result -Results $Results -Name "Network Check" -Result "ERROR - $_"
    }
}

function Check-GPOs {
    param (
        [ref]$Results,
        [string[]]$ExpectedGPOs = @("Test1-GPO", "Test2-GPO")
    )

    try {
        $gpoOutput = gpresult /r /scope:computer 2>&1

        # Extract applied GPOs from the output
        $appliedGPOs = @()
        $start = $false
        foreach ($line in $gpoOutput) {
            if ($line -match "Applied Group Policy Objects") {
                $start = $true
                continue
            }
            if ($start -and ($line -match "^\S")) { break }  # Stop at next heading
            if ($start -and $line.Trim()) {
                $appliedGPOs += $line.Trim()
            }
        }

        $appliedList = $appliedGPOs -join ", "
        Add-Result -Results $Results -Name "Applied GPOs" -Result $appliedList

        # Check for expected GPOs
        $missing = $ExpectedGPOs | Where-Object { $_ -notin $appliedGPOs }

        if ($missing.Count -eq 0) {
            Add-Result -Results $Results -Name "GPO Validation" -Result "PASS - All expected GPOs applied: $($ExpectedGPOs -join ', ')"
        } else {
            Add-Result -Results $Results -Name "GPO Validation" -Result "FAIL - Missing GPOs: $($missing -join ', ')"
        }

        # Get computer group membership
        $groupLines = $gpoOutput | Where-Object { $_ -match "The computer is a part of the following security groups" }
        $groupStart = $false
        $groups = @()
        foreach ($line in $gpoOutput) {
            if ($line -match "The computer is a part of the following security groups") {
                $groupStart = $true
                continue
            }
            if ($groupStart -and ($line -match "^\S")) { break }
            if ($groupStart -and $line.Trim()) {
                $groups += $line.Trim()
            }
        }

        $groupResult = if ($groups) { $groups -join ", " } else { "None found" }
        Add-Result -Results $Results -Name "Computer Group Membership" -Result $groupResult

    } catch {
        Add-Result -Results $Results -Name "GPO Validation" -Result "ERROR - $_"
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
        $allServices = Get-Service
        $autoServices = $allServices | Where-Object { $_.StartType -eq 'Automatic' }
        $stoppedAuto = $autoServices | Where-Object { $_.Status -ne 'Running' }

        if ($stoppedAuto.Count -eq 0) {
            Add-Result -Results $Results -Name "Windows Services Status" -Result "PASS - All automatic services are running"
        } else {
            $failedList = $stoppedAuto | Select-Object Name, DisplayName, Status | Out-String
            Add-Result -Results $Results -Name "Windows Services Status" -Result "FAIL - Some automatic services are not running"
            Add-Result -Results $Results -Name "Stopped Auto Services" -Result $failedList.Trim()
        }

        # Optional: Include all currently running services for info
        $runningSummary = $allServices | Where-Object { $_.Status -eq "Running" } |
                          Select-Object StartType, Status, Name, DisplayName | Out-String
        Add-Result -Results $Results -Name "Running Services Summary" -Result $runningSummary.Trim()
    } catch {
        Add-Result -Results $Results -Name "Windows Services Status" -Result "ERROR - $_"
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
        $updates = Get-HotFix | Where-Object {
            $_.InstalledOn -and ($_.InstalledOn -as [datetime])
        } | Sort-Object {[datetime]$_.InstalledOn} -Descending | Select-Object -First 5

        if ($updates) {
            $summary = $updates | Select-Object Source, Description, HotFixID, InstalledBy, InstalledOn | Out-String
            Add-Result -Results $Results -Name "Recent Updates" -Result $summary.Trim()
        } else {
            Add-Result -Results $Results -Name "Recent Updates" -Result "No updates with valid install dates found"
        }
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

function Check-ResourceUsage {
    param ([ref]$Results)

    try {
        $sampleCount = 6        # Use 60 for full hour
        $sampleInterval = 10    # Use 60 for once per minute

        $counters = @(
            '\Processor(_Total)\% Processor Time',
            '\Memory\% Committed Bytes In Use',
            '\LogicalDisk(_Total)\Disk Read Bytes/sec',
            '\LogicalDisk(_Total)\Disk Write Bytes/sec',
            '\Network Interface(*)\Bytes Received/sec',
            '\Network Interface(*)\Bytes Sent/sec'
        )

        $data = Get-Counter -Counter $counters -SampleInterval $sampleInterval -MaxSamples $sampleCount

        # CPU and Memory
        $coreCount = (Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        $cpuSamples = $data.CounterSamples | Where-Object { $_.InstanceName -ieq '_Total' -and $_.Path -like '*% Processor Time' } | Select-Object -ExpandProperty CookedValue
        $memSamples = $data.CounterSamples | Where-Object { $_.Path -like '*\Memory\% Committed Bytes In Use' } | Select-Object -ExpandProperty CookedValue

        $cpuAvg = [math]::Round((($cpuSamples | Measure-Object -Average).Average * 100) / $coreCount, 2)
        $cpuPeak = [math]::Round((($cpuSamples | Measure-Object -Maximum).Maximum * 100) / $coreCount, 2)
        $memAvg = [math]::Round(($memSamples | Measure-Object -Average).Average, 2)
        $memPeak = [math]::Round(($memSamples | Measure-Object -Maximum).Maximum, 2)

        # Helper for disk and network
        function Get-AvgPeak {
            param ($pattern)
            $samples = $data.CounterSamples | Where-Object { $_.Path -like "*$pattern*" } | Select-Object -ExpandProperty CookedValue
            if (-not $samples -or $samples.Count -eq 0) {
                return @{ Avg = 0; Peak = 0 }
            }
            return @{
                Avg  = [math]::Round(($samples | Measure-Object -Average).Average / 1KB, 2)
                Peak = [math]::Round(($samples | Measure-Object -Maximum).Maximum / 1KB, 2)
            }
        }

        $diskRead  = Get-AvgPeak 'Disk Read Bytes/sec'
        $diskWrite = Get-AvgPeak 'Disk Write Bytes/sec'
        $netIn     = Get-AvgPeak 'Bytes Received/sec'
        $netOut    = Get-AvgPeak 'Bytes Sent/sec'

        $summary = @(
            "CPU: Avg ${cpuAvg}%, Peak ${cpuPeak}%",
            "Memory: Avg ${memAvg}%, Peak ${memPeak}%",
            "Disk Read: Avg $($diskRead.Avg) KB/s, Peak $($diskRead.Peak) KB/s",
            "Disk Write: Avg $($diskWrite.Avg) KB/s, Peak $($diskWrite.Peak) KB/s",
            "Network In: Avg $($netIn.Avg) KB/s, Peak $($netIn.Peak) KB/s",
            "Network Out: Avg $($netOut.Avg) KB/s, Peak $($netOut.Peak) KB/s"
        ) -join " | "

        if ($cpuAvg -gt 85 -or $memAvg -gt 85) {
            Add-Result -Results $Results -Name "Resource Usage" -Result "FAIL - High CPU or Memory. $summary"
        } else {
            Add-Result -Results $Results -Name "Resource Usage" -Result "PASS - $summary"
        }

    } catch {
        Add-Result -Results $Results -Name "Resource Usage" -Result "ERROR - $_"
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
    Check-ResourceUsage -Results ([ref]$Results)

    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "UAT completed. Results saved to: $OutputPath"
}

# --- Run it ---
Run-UAT
