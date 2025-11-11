# ================================================#
# Version: 2.0                                    #
# Author: Tony Reardon                            #
# UAT Script for Windows Server 2022 & Windows 11 #
# ================================================#

# --- Define expected values ---
$ExpectedCDriveSizeGB = 59
$MinFreeSpacePercent = 10
$OutputPath = "C:\Temp\UAT_Results_$env:COMPUTERNAME.csv" # <------ Change this

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
    param ([ref]$Results)
    try {
        #Define Per-Site DNS Config. DC1 = SDC, DC2 = WDC
        $DC1_DNSServers = @("192.168.178.1", "192.168.178.2")
        $DC2_DNSServers = @("192.168.178.2", "192.168.178.1")

        $InterfaceAlias = Get-DnsClient | Where-Object {$_.InterfaceAlias -notlike "Loopback*"} | 
                            Sort-Object InterfaceMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias
        
        #Get current config
        $current = (Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias $InterfaceAlias).ServerAddresses
        $expected = $null
        $ADsite = "Unknown"

        #Compare
        function Compare-DnsOrder {
            param ($current, $expected)
            if ($current.Count -ne $expected.Count) {return $false}
            for ($i = 0; $i -lt $expected.Count; $i++) {
                if ($current[$i] -ne $expected[$i]) {return $false}
            }
            return $true
        }

        #detecht mismatch 
        $currentString = $current -Join ", "
        $ADSite = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).Name
        switch ($ADSite) {
            "WDC-SEN" {$expected = $DC2_DNSServers}
            default {$expected = $DC1_DNSServers}
        }
        $expectedString = $expected -join ", "

        $isCorrect = Compare-DnsOrder -current $current -expected $expected


        if ($isCorrect) { 
            Add-Result -Results $Results -Name "DNS Configuration" -Result "Pass - DNS matches expected order: $expectedString"
        } else {
            #Attempt remediation 
            try {
                Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $expected -ErrorAction Stop
                Start-Sleep -Seconds 2 #Wait for it to apply
                $updated = (Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias $InterfaceAlias).ServerAddresses
                $isNowCorrect = Compare-DnsOrder -current $current -expected $expected

                if ($isNowCorrect) {
                    Add-Result -Results $Results -Name "DNS Configuration" -Result "Pass - DNS updated to: $expectedString"
                } else { 
                    Add-Result -Results $Results -Name "DNS Configuration" -Result "Fail - DNS mismatch after attempted fix. Expected: $expectedString | Found: $($update -join ', ')"
                }
            } catch {
                Add-Result -Results $Results -Name "DNS Configuration" -Result "Fail - Failed to update DNS: $_"
            }
        }

            } catch {
                Add-Result -Results $Results -Name "DNS Configuration" -Result "Error - $_"
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
        $logInsight = Get-Service -Name "LogInsightAgentService" -ErrorAction SilentlyContinue
        if ($logInsight) {
            Add-Result -Results $Results -Name "Aria Operations for logs agent" -Result "PASS - Installed"
        } else {
            Add-Result -Results $Results -Name "Aria Operations for logs agent" -Result "FAIL - Not Installed"
        }

        $eventForwarding = wevtutil gl "ForwardedEvents" 2>&1
        Add-Result -Results $Results -Name "Syslog Setup (ForwardedEvents)" -Result ($eventForwarding | Out-String).Trim()
    } catch {
        Add-Result -Results $Results -Name "Syslog Setup" -Result "ERROR - $_"
    }
}

function Check-NTP {
    param ([ref]$Results)
    try {
        # Query w32tm for configuration
        $w32tmOutput = w32tm /query /configuration 2>$null
        if ($w32tmOutput) {
            # Extract the NtpServer line
            $ntpLine = $w32tmOutput | Where-Object { $_ -match "NtpServer" }
            if ($ntpLine) {
                $NTPServer = ($ntpLine -split ":")[1].Trim()
            }
        }
        if ([string]::IsNullOrWhiteSpace($NTPServer)) {
            Add-Result -Results $Results -Name "Time Synchronization" -Result "Fail - No NTP Configured"
        } else {
            Add-Result -Results $Results -Name "Time Synchronization" -Result "Pass - NTP Configured - Server List: $NTPServer"
        }
    } catch {
        Add-Result -Results $Results -Name "Time Synchronization" -Result "ERROR - $_"
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
        [ref]$Results
    )
    try {
        # OS Type
        $osInfo = Get-CimInstance Win32_OperatingSystem
        $caption = $osInfo.Caption

        # Expected GPO
        $Win11GPOs = @("Win-GPO1", "Win-GPO2")
        $Svr22GPOs = @("SVR-GPO1", "SVR-GPO2", "SVR-GPO3")

        if ($caption -like "*Windows 11*"){
            $ExpectedGPOs = $Win11GPOs
            $osType = "Windows 11"
        } elseif ($caption -Match "Microsoft Windows Server 2022"){
            $ExpectedGPOs = $Svr22GPOs
            $osType = "Microsoft Windows Server 2022"
        } else {
            $ExpectedGPOs = @()
            $osType = "Unknown OS"
        }

        Add-Result -Results $Results -Name "Detected OS" -Result $osType

        # Gather applied GPOs 
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

        #Check for Expexted GPOs
        if ($ExpectedGPOs.Count -gt 0){
            $missing = $ExpectedGPOs | Where-Object {$_ -notin $appliedGPOs}
            if ($missing.Count -eq 0){
                Add-Result -Results $Results -Name "GPO Validation" -Result "Pass - All expected GPOs applied: $($ExpectedGPOs -join ',')"
                } else {
                    Add-Result -Results $Results -Name "GPO Validation" -Result "Fail - Missing GPOs: $($missing -join ',')"
                }
            } else {
                Add-Result -Results $Results -Name "GPO Validation" -Result "Warning - No expected GPOs defined for $osType"
            }

        # Get computer group membership
        $groups = @()
        $groupStart = $false        
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
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        $result = if ($guest.Enabled) { "FAIL - Enabled" } else { "PASS - Disabled" }
        Add-Result -Results $Results -Name "Guest Account Status" -Result $result
    } catch {
        Add-Result -Results $Results -Name "Guest Account Status" -Result "ERROR - $_"
    }
}

function Check-WindowsServices {
    param (
        [ref]$Results,
        [string[]]$ExcludedServices = @("edgeupdate","GoogleUpdater","RemoteRegistry","sppsvc","DoSVC","omn-instantclone-ga","wuauserv")) #<------------------Edit
    try {
        $allServices = Get-Service
        $autoServices = $allServices | Where-Object { $_.StartType -eq 'Automatic' }

        #Exlude filtered
        $filteredServices = $autoServices | Where-Object {$_.Name -notin $ExcludedServices}
        #Stopped Auto
        $stoppedAuto = $filteredServices | Where-Object { $_.Status -ne 'Running' }

        if ($stoppedAuto.Count -eq 0) {
            Add-Result -Results $Results -Name "Windows Services Status" -Result "PASS - All automatic services are running. Excluding $ExcludedServices"
        } else {
            $failedList = $stoppedAuto | Select-Object Name, DisplayName, Status | Out-String
            Add-Result -Results $Results -Name "Windows Services Status" -Result "FAIL - Some automatic services are not running"
            Add-Result -Results $Results -Name "Stopped Auto Services" -Result $failedList.Trim()
        }

        #all currently running services for info
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
        # Use shorter time for testing (6 samples every 10 seconds = 1 minute)
        $sampleCount = 12        # Total Samples to collect                         <------ Change this
        $sampleInterval = 1    # Seconds per sample                                 <------ Change this

        $counters = @(
            '\Processor(_Total)\% Processor Time',
            '\Memory\% Committed Bytes In Use',
            '\LogicalDisk(_Total)\Disk Read Bytes/sec',
            '\LogicalDisk(_Total)\Disk Write Bytes/sec',
            '\Network Interface(*)\Bytes Received/sec',
            '\Network Interface(*)\Bytes Sent/sec'
        )

        $data = Get-Counter -Counter $counters -SampleInterval $sampleInterval -MaxSamples $sampleCount

       #CPU and Memory
    $coreCount = (Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    $cpusamples = $data.CounterSamples | Where-Object {$_.InstanceName -ieq '_Total' -and $_.Path -like '*% Processor Time'} | Select-Object -ExpandProperty CookedValue
    $memsamples = $data.CounterSamples | Where-Object {$_.Path -like '*\Memory\% Committed Bytes In Use'} | Select-Object -ExpandProperty CookedValue

    $cpuAvg = [math]::Round((($cpusamples | Measure-Object -Average).Average *100) /$coreCount, 2)
    $cpuPeak = [math]::Round((($cpusamples | Measure-Object -Maximum).Maximum *100) /$coreCount, 2)
    
    $memAvg = [math]::Round(($memsamples | Measure-Object -Average).Average, 2)
    $memPeak = [math]::Round(($memsamples | Measure-Object -Maximum).Maximum, 2)

        function Get-AvgPeakByPattern {
            param ($pattern)
            $samples = $data.CounterSamples | Where-Object { $_.Path -like "*$pattern*" } | Select-Object -ExpandProperty CookedValue
            if (-not $samples -or $samples.Count -eq 0) {
                return @{ Avg = 0; Peak = 0 }
            }
            return @{
                Avg = [math]::Round(($samples | Measure-Object -Average).Average, 2)
                Peak = [math]::Round(($samples | Measure-Object -Maximum).Maximum, 2)
            }
        }

        $diskRead  = Get-AvgPeakByPattern 'Disk Read Bytes/sec'
        $diskWrite = Get-AvgPeakByPattern 'Disk Write Bytes/sec'
        $netIn     = Get-AvgPeakByPattern 'Bytes Received/sec'
        $netOut    = Get-AvgPeakByPattern 'Bytes Sent/sec'

        # Build human-readable summary
        $summary = @(
            "CPU: Avg ${cpuAvg}%, Peak ${cpuPeak}%",
            "Memory: Avg ${memAvg}%, Peak ${memPeak}%",
            "Disk Read: Avg $([math]::Round($diskRead.Avg / 1KB, 2)) KB/s, Peak $([math]::Round($diskRead.Peak / 1KB, 2)) KB/s",
            "Disk Write: Avg $([math]::Round($diskWrite.Avg / 1KB, 2)) KB/s, Peak $([math]::Round($diskWrite.Peak / 1KB, 2)) KB/s",
            "Network In: Avg $([math]::Round($netIn.Avg / 1KB, 2)) KB/s, Peak $([math]::Round($netIn.Peak / 1KB, 2)) KB/s",
            "Network Out: Avg $([math]::Round($netOut.Avg / 1KB, 2)) KB/s, Peak $([math]::Round($netOut.Peak / 1KB, 2)) KB/s"
        ) -join " | "

        # Check thresholds
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
    Write-Host "DNS Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-NTP -Results ([ref]$Results)
    Write-Host "NTP Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-CDrive -ExpectedSize $ExpectedCDriveSizeGB -MinFreePercent $MinFreeSpacePercent -Results ([ref]$Results)
    Write-Host "Disk Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-SyslogSetup -Results ([ref]$Results)
    Write-Host "Syslog Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-Network -Results ([ref]$Results)
    Write-Host "Network Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-GPOs -Results ([ref]$Results)
    Write-Host "GPO Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-AdminGroup -Results ([ref]$Results)
    Write-Host "Administrator Group Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-GuestAccount -Results ([ref]$Results)
    Write-Host "Guest Account Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-WindowsServices -Results ([ref]$Results)
    Write-Host "Windows Services Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-RDP -Results ([ref]$Results)
    Write-Host "RDP Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-WindowsUpdates -Results ([ref]$Results)
    Write-Host "Windows Update Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Write-Host "Starting Windows Defender Scan" -ForegroundColor Yellow
    Run-WindowsDefenderScan -Results ([ref]$Results)
    Write-Host "Windows Defender Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Check-DomainJoin -Results ([ref]$Results)
    Write-Host "Domain Join Check Complete" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Write-Host "1 Hour Resource Monitoring.... Please wait" -ForegroundColor Yellow
    Check-ResourceUsage -Results ([ref]$Results)
    Write-Host "Resource Monitor Check Complete" -ForegroundColor Green

    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
    Write-Host "UAT completed. Results saved to: $OutputPath"
}

# --- Run it ---
Run-UAT
