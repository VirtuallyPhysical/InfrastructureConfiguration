<#
.SYNOPSIS
    OS Build Validation - Extended checks
.DESCRIPTION
    Performs many validation checks and writes CSV/TXT results.
.NOTES
    Run elevated. Adjust the default expected GPOs, excluded services and required software as needed.
#>

# ---------- Helper: Add-Result (mirrors style from your repo) ----------
function Add-Result {
    param(
        [ref]$Results,
        [string]$Name,
        [string]$Result,
        [string]$Level = "INFO"   # INFO / PASS / FAIL / WARN / ERROR
    )
    $obj = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString("o")
        Name      = $Name
        Result    = $Result
        Level     = $Level
    }
    $Results.Value += $obj
}

# ---------- Main check functions ----------
function Get-DomainJoin {
    param([ref]$Results)
    try {
        $compSys = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $domain = if ($compSys.PartOfDomain) { $compSys.Domain } else { "Not Domain Joined" }
        Add-Result -Results $Results -Name "Domain Join" -Result $domain -Level "INFO"
        return $domain
    } catch {
        Add-Result -Results $Results -Name "Domain Join" -Result "ERROR - $_" -Level "ERROR"
        return $null
    }
}

function Check-GPOs {
    param(
        [ref]$Results,
        [string[]]$ExpectedGPOs = @("GPO1","GPO2")
    )
    try {
        # Get OS caption (for logging)
        $os = (Get-CimInstance Win32_OperatingSystem).Caption
        Add-Result -Results $Results -Name "GPO OS Detected" -Result $os -Level "INFO"

        $gpoOutput = gpresult /r /scope:computer 2>&1
        $appliedGPOs = @()
        $start = $false
        foreach ($line in $gpoOutput) {
            if ($line -match "Applied Group Policy Objects") { $start = $true; continue }
            if ($start -and ($line -match "^\S")) { break }
            if ($start -and $line.Trim()) { $appliedGPOs += $line.Trim() }
        }
        Add-Result -Results $Results -Name "Applied GPOs" -Result (($appliedGPOs -join ", ") -ne "" ? ($appliedGPOs -join ", ") : "None found") -Level "INFO"

        $missing = $ExpectedGPOs | Where-Object { $_ -notin $appliedGPOs }
        if ($missing.Count -eq 0) {
            Add-Result -Results $Results -Name "GPO Validation" -Result "PASS - All expected GPOs applied: $($ExpectedGPOs -join ', ')" -Level "PASS"
        } else {
            Add-Result -Results $Results -Name "GPO Validation" -Result "FAIL - Missing GPOs: $($missing -join ', ')" -Level "FAIL"
        }
    } catch {
        Add-Result -Results $Results -Name "GPO Validation" -Result "ERROR - $_" -Level "ERROR"
    }
}

function Check-DriversAndHardware {
    param([ref]$Results)
    try {
        # Use Get-PnpDevice to list devices in error state
        $devices = Get-PnpDevice -ErrorAction SilentlyContinue
        $errorDevices = $devices | Where-Object { $_.Status -ne "OK" -and $_.Status -ne $null }
        if ($errorDevices.Count -eq 0) {
            Add-Result -Results $Results -Name "Drivers/Hardware" -Result "PASS - No hardware in error state" -Level "PASS"
        } else {
            $list = $errorDevices | Select-Object InstanceId,Class,Manufacturer,Status,Name | Out-String
            Add-Result -Results $Results -Name "Drivers/Hardware" -Result "FAIL - Devices in non-OK state" -Level "FAIL"
            Add-Result -Results $Results -Name "DevicesWithIssues" -Result $list -Level "INFO"
        }

    } catch {
        Add-Result -Results $Results -Name "Drivers/Hardware" -Result "ERROR - $_" -Level "ERROR"
    }
}

function List-LocalAccounts {
    param([ref]$Results)
    try {
        $accounts = Get-LocalUser | Select-Object Name,Enabled,Description,LastLogon | Sort-Object Name
        if ($accounts) {
            $str = $accounts | Format-Table -AutoSize | Out-String
            Add-Result -Results $Results -Name "Local Accounts" -Result "INFO - See details" -Level "INFO"
            Add-Result -Results $Results -Name "LocalAccountsDetail" -Result $str -Level "INFO"
        } else {
            Add-Result -Results $Results -Name "Local Accounts" -Result "None found" -Level "INFO"
        }
    } catch {
        Add-Result -Results $Results -Name "Local Accounts" -Result "ERROR - $_" -Level "ERROR"
    }
}

function List-LocalGroupsWithMembers {
    param([ref]$Results)
    try {
        $groups = Get-LocalGroup | Sort-Object Name
        $out = @()
        foreach ($g in $groups) {
            $members = @()
            try {
                $members = Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | Select-Object @{n='Name';e={$_.Name}}, @{n='ObjectClass';e={$_.ObjectClass}}
            } catch {
                # no members or permission issue
                $members = @()
            }
            if ($members.Count -gt 0) {
                $out += [PSCustomObject]@{
                    Group = $g.Name
                    Members = ($members | ForEach-Object { "$($_.Name) [$($_.ObjectClass)]" }) -join "; "
                }
            }
        }

        if ($out.Count -gt 0) {
            Add-Result -Results $Results -Name "Local Groups With Members" -Result "INFO - See details" -Level "INFO"
            $detail = $out | Format-Table -AutoSize | Out-String
            Add-Result -Results $Results -Name "LocalGroupsDetail" -Result $detail -Level "INFO"
        } else {
            Add-Result -Results $Results -Name "Local Groups With Members" -Result "None found" -Level "INFO"
        }
    } catch {
        Add-Result -Results $Results -Name "Local Groups With Members" -Result "ERROR - $_" -Level "ERROR"
    }
}

function Check-BitLocker {
    param([ref]$Results)
    try {
        $vols = Get-BitLockerVolume -ErrorAction Stop
        $notEncrypted = $vols | Where-Object { $_.VolumeStatus -ne 'FullyEncrypted' -and $_.VolumeStatus -ne 'EncryptionInProgress' }
        if ($notEncrypted.Count -eq 0) {
            Add-Result -Results $Results -Name "BitLocker" -Result "PASS - All volumes encrypted or encryption in progress" -Level "PASS"
        } else {
            $list = $notEncrypted | Select-Object MountPoint,VolumeStatus,KeyProtector | Out-String
            Add-Result -Results $Results -Name "BitLocker" -Result "FAIL - Some volumes not encrypted" -Level "FAIL"
            Add-Result -Results $Results -Name "BitLockerNotEncryptedDetail" -Result $list -Level "INFO"
        }
    } catch {
        Add-Result -Results $Results -Name "BitLocker" -Result "ERROR - $_ (Get-BitLockerVolume may require PowerShell 5+/admin)" -Level "ERROR"
    }
}

function Check-USBLockdown {
    param([ref]$Results)
    try {
        # Check USBSTOR start value
        $usbStorKey = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
        $usbStorDisabled = $false
        try {
            $startVal = (Get-ItemProperty -Path $usbStorKey -Name Start -ErrorAction Stop).Start
            # Start == 3 is manual, 4 disabled
            $usbStorDisabled = ($startVal -eq 4)
            Add-Result -Results $Results -Name "USBSTOR_StartValue" -Result "Start=$startVal" -Level "INFO"
        } catch {
            Add-Result -Results $Results -Name "USBSTOR_StartValue" -Result "Not found" -Level "INFO"
        }

        # Enumerate USB controllers and currently connected USB devices
        $usbControllers = Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | Select-Object InstanceId,Status,Name,Manufacturer
        $usbDevices = Get-PnpDevice -PresentOnly | Where-Object { $_.Class -eq 'USB' -or $_.Class -eq 'USBDevice' } | Select-Object InstanceId,Status,Name
        Add-Result -Results $Results -Name "USB Controllers" -Result ( ($usbControllers | ForEach-Object { $_.Name }) -join ', ' ) -Level "INFO"
        Add-Result -Results $Results -Name "USB Present Devices" -Result ( ($usbDevices | ForEach-Object { $_.Name }) -join ', ' ) -Level "INFO"

        # Determine overall pass/fail: if USBSTOR disabled => PASS; otherwise WARN (depends on policy)
        if ($usbStorDisabled) {
            Add-Result -Results $Results -Name "USB Lockdown" -Result "PASS - USBSTOR disabled (registry Start=4)" -Level "PASS"
        } else {
            Add-Result -Results $Results -Name "USB Lockdown" -Result "WARN - USBSTOR not disabled. Verify other policies or device control solution" -Level "WARN"
        }
    } catch {
        Add-Result -Results $Results -Name "USB Lockdown" -Result "ERROR - $_" -Level "ERROR"
    }
}

function Check-TelegrafAgent {
    param([ref]$Results)
    try {
        # Common telegraf service name is 'telegraf', but vendor packaging may differ
        $svc = Get-Service -Name telegraf -ErrorAction SilentlyContinue
        if ($null -ne $svc) {
            $status = $svc.Status
            if ($status -eq 'Running') {
                Add-Result -Results $Results -Name "Telegraf Agent" -Result "PASS - Telegraf service installed and running" -Level "PASS"
            } else {
                Add-Result -Results $Results -Name "Telegraf Agent" -Result "FAIL - Telegraf service present but not running (Status: $status)" -Level "FAIL"
            }
        } else {
            # Also check Program Files
            $paths = @(
                "$env:ProgramFiles\telegraf",
                "$env:ProgramFiles(x86)\telegraf",
                "$env:ProgramFiles\Telegraf",
                "$env:ProgramFiles\influxdata\telegraf"
            )
            $found = $paths | Where-Object { Test-Path $_ } 
            if ($found) {
                Add-Result -Results $Results -Name "Telegraf Agent" -Result "WARN - Telegraf appears installed at: $($found -join ', ') but service not found" -Level "WARN"
            } else {
                Add-Result -Results $Results -Name "Telegraf Agent" -Result "FAIL - Telegraf not found" -Level "FAIL"
            }
        }
    } catch {
        Add-Result -Results $Results -Name "Telegraf Agent" -Result "ERROR - $_" -Level "ERROR"
    }
}

function Get-LastInstalledPatches {
    param([ref]$Results, [int]$Count = 10)
    try {
        # Get-HotFix returns InstalledOn and HotFixID (KB)
        $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First $Count
        if ($hotfixes.Count -eq 0) {
            Add-Result -Results $Results -Name "Last Installed Patches" -Result "None found" -Level "INFO"
            return
        }
        $table = $hotfixes | Select-Object HotFixID, InstalledOn, Description | Format-Table -AutoSize | Out-String
        Add-Result -Results $Results -Name "Last Installed Patches" -Result "INFO - See details" -Level "INFO"
        Add-Result -Results $Results -Name "LastInstalledPatchesDetail" -Result $table -Level "INFO"

        # Note: release date of KB is not stored locally — to find release date you'd need to query Microsoft update catalog (web)
    } catch {
        Add-Result -Results $Results -Name "Last Installed Patches" -Result "ERROR - $_" -Level "ERROR"
    }
}

function Check-WindowsFirewall {
    param([ref]$Results)
    try {
        $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled
        $fail = $profiles | Where-Object { $_.Enabled -eq $false }
        $profilesStr = $profiles | Format-Table -AutoSize | Out-String
        Add-Result -Results $Results -Name "Windows Firewall Profiles" -Result "INFO - See details" -Level "INFO"
        Add-Result -Results $Results -Name "FirewallProfileDetail" -Result $profilesStr -Level "INFO"

        if ($fail.Count -eq 0) {
            Add-Result -Results $Results -Name "Windows Firewall" -Result "PASS - Firewall enabled for all profiles" -Level "PASS"
        } else {
            Add-Result -Results $Results -Name "Windows Firewall" -Result ("FAIL - Firewall disabled for: " + ($fail | ForEach-Object { $_.Name } -join ', ')) -Level "FAIL"
        }
    } catch {
        Add-Result -Results $Results -Name "Windows Firewall" -Result "ERROR - $_" -Level "ERROR"
    }
}

function Get-BIOSInfo {
    param([ref]$Results)
    try {
        # Note: To get vendor-specific BIOS configuration you will usually need vendor tooling.
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop | Select-Object Manufacturer,SMBIOSBIOSVersion,SerialNumber,ReleaseDate,Version
        $biosStr = $bios | Format-List | Out-String
        Add-Result -Results $Results -Name "BIOS Info" -Result "INFO - See details" -Level "INFO"
        Add-Result -Results $Results -Name "BIOSInfoDetail" -Result $biosStr -Level "INFO"

        # Attempt to include SecureBoot state (from UEFI)
        try {
            $sb = Confirm-SecureBootUEFI
            Add-Result -Results $Results -Name "SecureBoot" -Result ("Secure Boot enabled: $sb") -Level "INFO"
        } catch { }
    } catch {
        Add-Result -Results $Results -Name "BIOS Info" -Result "ERROR - $_" -Level "ERROR"
    }
}

function Check-RDPAndRemoteAccess {
    param([ref]$Results)
    try {
        # Check if RDP is allowed
        $fdeny = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
        $rdpEnabled = if ($fdeny -ne $null) { ($fdeny.fDenyTSConnections -eq 0) } else { $false }
        Add-Result -Results $Results -Name "RDP Enabled" -Result ($rdpEnabled ? "TRUE" : "FALSE") -Level ($rdpEnabled ? "PASS" : "FAIL")

        # Check firewall rules related to Remote Desktop
        $rdpRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        if ($rdpRules) {
            $enabledRules = $rdpRules | Where-Object { $_.Enabled -eq 'True' }
            $rulesStr = $rdpRules | Select-Object DisplayName,Enabled,Direction,Action | Format-Table -AutoSize | Out-String
            Add-Result -Results $Results -Name "RDP Firewall Rules" -Result "INFO - See details" -Level "INFO"
            Add-Result -Results $Results -Name "RDPFirewallDetail" -Result $rulesStr -Level "INFO"
            $rulePass = if ($enabledRules.Count -gt 0) { "PASS - Remote Desktop firewall rules enabled" } else { "WARN - Remote Desktop firewall rules not enabled" }
            Add-Result -Results $Results -Name "RDP Firewall Status" -Result $rulePass -Level ($enabledRules.Count -gt 0 ? "PASS" : "WARN")
        } else {
            Add-Result -Results $Results -Name "RDP Firewall Rules" -Result "None found / display group not present. Check firewall rules manually." -Level "WARN"
        }

        # List groups allowed remote access (Local 'Remote Desktop Users' group)
        try {
            $remoteGroupMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction Stop | Select-Object Name,ObjectClass
            $membersStr = $remoteGroupMembers | ForEach-Object { "$($_.Name) [$($_.ObjectClass)]" } -join "; "
            Add-Result -Results $Results -Name "Remote Desktop Allowed Accounts" -Result ($membersStr -ne "" ? $membersStr : "None") -Level "INFO"
        } catch {
            Add-Result -Results $Results -Name "Remote Desktop Allowed Accounts" -Result "None or unable to enumerate" -Level "INFO"
        }

    } catch {
        Add-Result -Results $Results -Name "RDP & Remote Access" -Result "ERROR - $_" -Level "ERROR"
    }
}

function Check-RequiredSoftware {
    param(
        [ref]$Results,
        [string[]]$RequiredSoftware = @()
    )
    try {
        # Build registry list of installed programs (x86 & x64)
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        $installed = @()
        foreach ($p in $uninstallPaths) {
            try {
                $installed += Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate
            } catch {}
        }

        $installedNames = $installed | Where-Object { $_.DisplayName } | ForEach-Object { $_.DisplayName } | Sort-Object -Unique

        $report = @()
        foreach ($req in $RequiredSoftware) {
            $found = $installed | Where-Object { $_.DisplayName -and ($_.DisplayName -like "*$req*") } 
            if ($found) {
                $report += [PSCustomObject]@{ Software=$req; Status="Installed"; Detail = (($found | Select-Object -First 1 DisplayName, DisplayVersion, Publisher) | Out-String).Trim() }
                Add-Result -Results $Results -Name "Software:$req" -Result "PASS - Installed" -Level "PASS"
            } else {
                $report += [PSCustomObject]@{ Software=$req; Status="MISSING"; Detail = "" }
                Add-Result -Results $Results -Name "Software:$req" -Result "FAIL - Not installed" -Level "FAIL"
            }
        }

        if ($report.Count -gt 0) {
            Add-Result -Results $Results -Name "RequiredSoftwareDetail" -Result (($report | Format-Table -AutoSize) -join "`n") -Level "INFO"
        }

    } catch {
        Add-Result -Results $Results -Name "Required Software" -Result "ERROR - $_" -Level "ERROR"
    }
}

# ---------- Runner ----------
param (
    [string[]]$ExpectedGPOs = @("GPO1","GPO2"),
    [string[]]$RequiredSoftware = @(),
    [string[]]$ExcludedServices = @("edgeupdate"),
    [string]$OutCsv = ".\OS-BuildValidationResults.csv",
    [string]$OutDetails = ".\OS-BuildValidationDetails.txt"
)

# Create results array
$results = @()
$ResultsRef = [ref]$results

# Run checks
Get-DomainJoin -Results $ResultsRef
Check-GPOs -Results $ResultsRef -ExpectedGPOs $ExpectedGPOs
Check-DriversAndHardware -Results $ResultsRef
List-LocalAccounts -Results $ResultsRef
List-LocalGroupsWithMembers -Results $ResultsRef
Check-BitLocker -Results $ResultsRef
Check-USBLockdown -Results $ResultsRef
Check-TelegrafAgent -Results $ResultsRef
Get-LastInstalledPatches -Results $ResultsRef -Count 10
Check-WindowsFirewall -Results $ResultsRef
Get-BIOSInfo -Results $ResultsRef
Check-RDPAndRemoteAccess -Results $ResultsRef
Check-RequiredSoftware -Results $ResultsRef -RequiredSoftware $RequiredSoftware

# Export CSV of primary summary lines (Name, Result, Level, Timestamp)
try {
    $summary = $results | Select-Object Timestamp, Name, Result, Level
    $summary | Export-Csv -Path $OutCsv -NoTypeInformation -Force
    Write-Host "Summary CSV written to $OutCsv"
} catch {
    Write-Warning "Failed to write CSV: $_"
}

# Write details file (all records with long Result lines)
try {
    $sb = New-Object System.Text.StringBuilder
    $sb.AppendLine("OS Build Validation - Details") | Out-Null
    foreach ($r in $results) {
        $sb.AppendLine("-----") | Out-Null
        $sb.AppendLine("Timestamp: $($r.Timestamp)") | Out-Null
        $sb.AppendLine("Name: $($r.Name)") | Out-Null
        $sb.AppendLine("Level: $($r.Level)") | Out-Null
        $sb.AppendLine("Result:") | Out-Null
        $sb.AppendLine($r.Result) | Out-Null
    }
    $sb.ToString() | Out-File -FilePath $OutDetails -Force -Encoding UTF8
    Write-Host "Details written to $OutDetails"
} catch {
    Write-Warning "Failed to write details file: $_"
}

# Final console summary
$pass = $results | Where-Object { $_.Level -eq "PASS" } | Measure-Object | Select-Object -ExpandProperty Count
$fail = $results | Where-Object { $_.Level -eq "FAIL" } | Measure-Object | Select-Object -ExpandProperty Count
$warn = $results | Where-Object { $_.Level -eq "WARN" } | Measure-Object | Select-Object -ExpandProperty Count
$info = $results | Where-Object { $_.Level -eq "INFO" } | Measure-Object | Select-Object -ExpandProperty Count
Write-Host "`nValidation complete. PASS: $pass, FAIL: $fail, WARN: $warn, INFO: $info"
