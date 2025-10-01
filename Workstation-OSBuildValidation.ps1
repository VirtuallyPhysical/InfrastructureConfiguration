#-------------------- Variables --------------------

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = ".\Workstation-BuildValidationResults-$timestamp.csv"
$ExpectedSoftware = @("Google Chrome", "VMware Tools")

# ------------------ Helper Functions ------------------

function Add-Result {
    param (
        [ref]$Results,
        [string]$Name,
        [string]$Result
    )
    $Results.Value += [PSCustomObject]@{
        Test   = $Name
        Result = $Result
    }
}

# ------------------ Validation Functions ------------------

function Check-Domain {
    param ([ref]$Results)
    try {
        $domain = (Get-WmiObject Win32_ComputerSystem).Domain
        Add-Result -Results $Results -Name "Domain Membership" -Result $domain
    } catch {
        Add-Result -Results $Results -Name "Domain Membership" -Result "ERROR - $_"
    }
}

function Check-GPOs {
    param ([ref]$Results)
    try {
        $gpoOutput = gpresult /r /scope:computer 2>&1

        $appliedGPOs = @()
        $start = $false
        foreach ($line in $gpoOutput) {
            if ($line -match "Applied Group Policy Objects") {
                $start = $true
                continue
            }
            if ($start -and ($line -match "^\S")) { break }
            if ($start -and $line.Trim()) {
                $appliedGPOs += $line.Trim()
            }
        }

        $expectedGPOs = @("GPO1", "GPO2")
        $missing = $expectedGPOs | Where-Object { $_ -notin $appliedGPOs }

        if ($missing.Count -eq 0) {
            Add-Result -Results $Results -Name "GPO Validation" -Result "PASS - All expected GPOs applied"
        } else {
            Add-Result -Results $Results -Name "GPO Validation" -Result "FAIL - Missing GPOs: $($missing -join ', ')"
        }
    } catch {
        Add-Result -Results $Results -Name "GPO Validation" -Result "ERROR - $_"
    }
}

function Check-Drivers {
    param ([ref]$Results)
    try {
        $devices = Get-WmiObject Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
        if ($devices) {
            $deviceList = $devices | Select-Object Name, ConfigManagerErrorCode | Out-String
            Add-Result -Results $Results -Name "Driver Status" -Result "FAIL - Devices with errors:`n$deviceList"
        } else {
            Add-Result -Results $Results -Name "Driver Status" -Result "PASS - All drivers installed correctly"
        }
    } catch {
        Add-Result -Results $Results -Name "Driver Status" -Result "ERROR - $_"
    }
}

function Check-LocalAccounts {
    param ([ref]$Results)
    try {
        $accounts = Get-LocalUser | Select-Object Name, Enabled | Out-String
        Add-Result -Results $Results -Name "Local Accounts" -Result $accounts.Trim()
    } catch {
        Add-Result -Results $Results -Name "Local Accounts" -Result "ERROR - $_"
    }
}

function Check-LocalGroups {
    param ([ref]$Results)
    try {
        $groups = Get-LocalGroup
        foreach ($group in $groups) {
            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
            if ($members) {
                $memberList = $members | Select-Object Name, ObjectClass | Out-String
                Add-Result -Results $Results -Name "Group: $($group.Name)" -Result $memberList.Trim()
            }
        }
    } catch {
        Add-Result -Results $Results -Name "Local Groups" -Result "ERROR - $_"
    }
}

function Check-Bitlocker {
    param ([ref]$Results)
    try {
        $volumes = Get-BitLockerVolume
        $unencrypted = $volumes | Where-Object { $_.ProtectionStatus -ne "On" }
        if ($unencrypted) {
            $volList = $unencrypted | Select-Object MountPoint, ProtectionStatus | Out-String
            Add-Result -Results $Results -Name "Bitlocker Status" -Result "FAIL - Unprotected volumes:`n$volList"
        } else {
            Add-Result -Results $Results -Name "Bitlocker Status" -Result "PASS - All volumes encrypted"
        }
    } catch {
        Add-Result -Results $Results -Name "Bitlocker Status" -Result "ERROR - $_"
    }
}

function Check-USBPorts {
    param ([ref]$Results)
    try {
        $usb = Get-PnpDevice -Class USB -ErrorAction SilentlyContinue
        if ($usb) {
            $usbList = $usb | Select-Object Status, Class, FriendlyName | Out-String
            Add-Result -Results $Results -Name "USB Ports" -Result $usbList.Trim()
        } else {
            Add-Result -Results $Results -Name "USB Ports" -Result "PASS - No USB devices active"
        }
    } catch {
        Add-Result -Results $Results -Name "USB Ports" -Result "ERROR - $_"
    }
}

function Check-Telegraf {
    param ([ref]$Results)
    try {
        $service = Get-Service -Name "telegraf" -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Add-Result -Results $Results -Name "Telegraf Agent" -Result "PASS - Telegraf running"
        } else {
            Add-Result -Results $Results -Name "Telegraf Agent" -Result "FAIL - Telegraf not running"
        }
    } catch {
        Add-Result -Results $Results -Name "Telegraf Agent" -Result "ERROR - $_"
    }
}

function Check-Patches {
    param ([ref]$Results)
    try {
        $patches = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, InstalledOn | Out-String
        Add-Result -Results $Results -Name "Last 10 Patches" -Result $patches.Trim()
    } catch {
        Add-Result -Results $Results -Name "Last 10 Patches" -Result "ERROR - $_"
    }
}

function Check-Firewall {
    param ([ref]$Results)
    try {
        $profiles = Get-NetFirewallProfile
        $disabled = $profiles | Where-Object { $_.Enabled -eq $false }
        if ($disabled) {
            $list = $disabled | Select-Object Name, Enabled | Out-String
            Add-Result -Results $Results -Name "Firewall Status" -Result "FAIL - Disabled profiles:`n$list"
        } else {
            Add-Result -Results $Results -Name "Firewall Status" -Result "PASS - All profiles enabled"
        }
    } catch {
        Add-Result -Results $Results -Name "Firewall Status" -Result "ERROR - $_"
    }
}

function Check-BIOS {
    param ([ref]$Results)
    try {
        $bios = Get-WmiObject Win32_BIOS | Select-Object * | Out-String
        Add-Result -Results $Results -Name "BIOS Settings" -Result $bios.Trim()
    } catch {
        Add-Result -Results $Results -Name "BIOS Settings" -Result "ERROR - $_"
    }
}

function Check-RDP {
    param ([ref]$Results)
    try {
        $rdpEnabled = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0
        $firewall = Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Where-Object { $_.Enabled -eq "True" }
        $users = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Out-String

        $status = if ($rdpEnabled) { "Enabled" } else { "Disabled" }
        Add-Result -Results $Results -Name "RDP Status" -Result $status
        Add-Result -Results $Results -Name "RDP Firewall Rules" -Result ($firewall | Select-Object DisplayName, Enabled | Out-String).Trim()
        Add-Result -Results $Results -Name "RDP Allowed Users" -Result $users.Trim()
    } catch {
        Add-Result -Results $Results -Name "RDP Status" -Result "ERROR - $_"
    }
}

function Check-Software {
    param (
        [ref]$Results,
        [string[]]$ExpectedSoftware
    )
    try {
        $installed = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* ,
                                    HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
                        | Select-Object DisplayName | Where-Object { $_.DisplayName } | Select-Object -ExpandProperty DisplayName

        foreach ($app in $ExpectedSoftware) {
            if ($installed -contains $app) {
                Add-Result -Results $Results -Name "Software Check - $app" -Result "PASS - Installed"
            } else {
                Add-Result -Results $Results -Name "Software Check - $app" -Result "FAIL - Not Installed"
            }
        }
    } catch {
        Add-Result -Results $Results -Name "Software Validation" -Result "ERROR - $_"
    }
}

# ------------------ Script Execution ------------------

$Results = @()

Check-Domain -Results ([ref]$Results)
write-host "Check Domain" -ForegroundColor Green
Check-GPOs -Results ([ref]$Results)
write-host "Check GPOs" -ForegroundColor Green
Check-Drivers -Results ([ref]$Results)
write-host "Check Drivers" -ForegroundColor Green
Check-LocalAccounts -Results ([ref]$Results)
write-host "Check Local Accounts" -ForegroundColor Green
Check-LocalGroups -Results ([ref]$Results)
write-host "Check Local Groups" -ForegroundColor Green
Check-Bitlocker -Results ([ref]$Results)
write-host "Check Bitlocker" -ForegroundColor Green
Check-USBPorts -Results ([ref]$Results)
write-host "Check USB Ports" -ForegroundColor Green
Check-Telegraf -Results ([ref]$Results)
write-host "Check Telegraf Agent" -ForegroundColor Green
Check-Patches -Results ([ref]$Results)
write-host "Check Patches" -ForegroundColor Green
Check-Firewall -Results ([ref]$Results)
write-host "Check Firewall" -ForegroundColor Green
Check-BIOS -Results ([ref]$Results)
write-host "Check BIOS settings" -ForegroundColor Green
Check-RDP -Results ([ref]$Results)
write-host "Check RDP" -ForegroundColor Green
Check-Software -Results ([ref]$Results) -ExpectedSoftware $ExpectedSoftware
write-host "Check Software" -ForegroundColor Green
write-host "Script Complete" -ForegroundColor Green

# ------------------ Export Results ------------------

$Results | Export-Csv -Path $csvPath -NoTypeInformation -Force

Write-Host "Validation complete. Results exported to $csvPath"
