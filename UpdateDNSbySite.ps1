# =======================
# Configurable Variables
# =======================
$SharePath = "\\server\share\installers"
$ExpectedDnsServers = @("10.0.0.1", "10.0.0.2")  # Replace with your required DNS servers
$InterfaceAlias = $(Get-DnsClient | Where-Object {$_.InterfaceAlias -notlike "Loopback*"} | Sort-Object InterfaceMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias)
$LogFilePath = Join-Path -Path $SharePath -ChildPath "DNS_Config_Status.csv"

# =======================
# Functions
# =======================

function Set-DnsServersInOrder {
    param (
        [string[]]$DnsServers,
        [string]$Alias
    )

    if (-not $DnsServers -or $DnsServers.Count -eq 0) {
        Write-Error "You must specify DNS server IPs."
        return $false
    }

    try {
        Write-Host "Setting DNS servers on interface '$Alias': $($DnsServers -join ', ')"
        Set-DnsClientServerAddress -InterfaceAlias $Alias -ServerAddresses $DnsServers -ErrorAction Stop
        return $true
    } catch {
        Write-Error "Failed to set DNS servers: $_"
        return $false
    }
}

function Check-DnsConfig {
    param (
        [string[]]$Expected,
        [string]$Alias
    )

    try {
        $current = (Get-DnsClientServerAddress -InterfaceAlias $Alias -AddressFamily IPv4).ServerAddresses

        if ($current.Count -ne $Expected.Count) {
            return $false
        }

        for ($i = 0; $i -lt $Expected.Count; $i++) {
            if ($current[$i] -ne $Expected[$i]) {
                return $false
            }
        }

        return $true
    } catch {
        Write-Error "Error checking DNS configuration: $_"
        return $false
    }
}

function Log-DnsResult {
    param (
        [string]$ComputerName,
        [bool]$SetSuccess,
        [bool]$VerifySuccess
    )

    $entry = [PSCustomObject]@{
        ComputerName       = $ComputerName
        DNS_Set_Success    = $SetSuccess
        DNS_Verify_Success = $VerifySuccess
    }

    $entry | Export-Csv -Path $LogFilePath -Append -NoTypeInformation -Force -Encoding UTF8
}

# =======================
# Main Execution
# =======================

$ComputerName = $env:COMPUTERNAME

Write-Host "`n--- Setting DNS Configuration ---"
$setSuccess = Set-DnsServersInOrder -DnsServers $ExpectedDnsServers -Alias $InterfaceAlias

Write-Host "`n--- Verifying DNS Configuration ---"
$verifySuccess = $false
if ($setSuccess) {
    $verifySuccess = Check-DnsConfig -Expected $ExpectedDnsServers -Alias $InterfaceAlias
}

Write-Host "`n--- Logging Result ---"
Log-DnsResult -ComputerName $ComputerName -SetSuccess $setSuccess -VerifySuccess $verifySuccess

if ($setSuccess -and $verifySuccess) {
    Write-Host "✅ DNS configuration applied and verified successfully."
} else {
    Write-Warning "⚠️ DNS configuration failed or verification did not match. Check the CSV log for details."
}
