# =======================
# Configurable Variables
# =======================
$SharePath = "\\server\share\installers"
$LogFilePath = Join-Path -Path $SharePath -ChildPath "DNS_Config_Status.csv"
$DC1_DNSServers = @("10.0.0.1", "10.0.0.2")
$DC2_DNSServers = @("10.0.0.2", "10.0.0.1")
$InterfaceAlias = $(Get-DnsClient | Where-Object {$_.InterfaceAlias -notlike "Loopback*"} | Sort-Object InterfaceMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias)

# =======================
# Functions
# =======================

function Get-ADSiteName {
    try {
        $siteName = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).Name
        Write-Host "Detected AD Site: $siteName"
        return $siteName
    } catch {
        Write-Warning "Unable to detect AD site. Defaulting to DC1."
        return "DC1"
    }
}

function Set-DnsServersInOrder {
    param (
        [string[]]$DnsServers,
        [string]$Alias
    )

    try {
        Write-Host "Setting DNS on '$Alias' to: $($DnsServers -join ', ')"
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

        if ($current.Count -ne $Expected.Count) { return $false }

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
        [string]$ADSite,
        [string]$PrimaryDNS,
        [string]$SecondaryDNS,
        [bool]$SetSuccess,
        [bool]$VerifySuccess
    )

    $entry = [PSCustomObject]@{
        ComputerName        = $ComputerName
        ADSite              = $ADSite
        PrimaryDNS          = $PrimaryDNS
        SecondaryDNS        = $SecondaryDNS
        DNS_Set_Success     = $SetSuccess
        DNS_Verify_Success  = $VerifySuccess
    }

    $entry | Export-Csv -Path $LogFilePath -Append -NoTypeInformation -Force -Encoding UTF8
}

# =======================
# Main Execution
# =======================

$ComputerName = $env:COMPUTERNAME
$ADSite = Get-ADSiteName

switch ($ADSite) {
    "DC2" { $dnsOrder = $DC2_DNSServers }
    default { $dnsOrder = $DC1_DNSServers }
}

$setSuccess = Set-DnsServersInOrder -DnsServers $dnsOrder -Alias $InterfaceAlias
$verifySuccess = $false
if ($setSuccess) {
    $verifySuccess = Check-DnsConfig -Expected $dnsOrder -Alias $InterfaceAlias
}

Log-DnsResult -ComputerName $ComputerName -ADSite $ADSite `
    -PrimaryDNS $dnsOrder[0] -SecondaryDNS $dnsOrder[1] `
    -SetSuccess $setSuccess -VerifySuccess $verifySuccess

if ($setSuccess -and $verifySuccess) {
    Write-Host "✅ DNS configured correctly for site $ADSite."
} else {
    Write-Warning "⚠️ DNS configuration failed or mismatched for site $ADSite."
}
