# Connect to vCenter
Connect-VIServer -Server "your-vcenter-server"

# Prompt for guest OS credentials
$guestCred = Get-Credential -Message "Enter guest OS credentials"

# Import VM list from CSV
$vmList = Import-Csv -Path "C:\Path\To\vm_list.csv"  # CSV must have a column 'VMName'

# PowerShell script to run inside each VM
$scriptText = @'
# =======================
# Configurable Variables
# =======================
$SharePath = "\\server\share\installers"
$HorizonAgentFile = "VMware-Horizon-Agent-x86_64-2312.exe"
$DEMFile = "VMware-DEM-Enterprise-2312.msi"
$LogFilePath = Join-Path -Path $SharePath -ChildPath "VDI_Install_Status.csv"

$HorizonAgentArgs = "/silent /norestart VDM_VC_MANAGED=1 ADDLOCAL=Core,Blast,USB,TSMMR REMOVE=PCoIP"
$DEMArgs = "/qn /norestart"

# =======================
# Reusable Functions
# =======================

# Checks if an application with the specified display name is already installed
function Is-Installed {
    param([string]$DisplayName)

    $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $keyWow = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

    $apps = Get-ChildItem $key, $keyWow | ForEach-Object { Get-ItemProperty $_.PSPath } |
            Where-Object { $_.DisplayName -like "*$DisplayName*" }

    return $apps.Count -gt 0
}

# Installs an EXE installer silently using the provided path and arguments
function Install-EXE {
    param (
        [string]$InstallerPath,
        [string]$Arguments
    )

    if (-not (Test-Path $InstallerPath)) {
        Write-Error "EXE installer not found: $InstallerPath"
        return $false
    }

    Write-Host "Installing Horizon Agent from: $InstallerPath"
    $process = Start-Process -FilePath $InstallerPath -ArgumentList $Arguments -Wait -PassThru
    return ($process.ExitCode -eq 0)
}

# Installs an MSI installer silently using msiexec with provided arguments
function Install-MSI {
    param (
        [string]$InstallerPath,
        [string]$Arguments
    )

    if (-not (Test-Path $InstallerPath)) {
        Write-Error "MSI installer not found: $InstallerPath"
        return $false
    }

    Write-Host "Installing DEM from: $InstallerPath"
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$InstallerPath`" $Arguments" -Wait -PassThru
    return ($process.ExitCode -eq 0)
}

# Logs the result of installation attempts to a shared CSV file
function Write-LogEntry {
    param (
        [string]$ComputerName,
        [bool]$HorizonSuccess,
        [bool]$DEMSuccess
    )

    $entry = [PSCustomObject]@{
        ComputerName = $ComputerName
        HorizonAgent_Installed_Success = $HorizonSuccess
        DEM_Installed_Success = $DEMSuccess
    }

    $entry | Export-Csv -Path $LogFilePath -Append -NoTypeInformation -Force -Encoding UTF8
}

# Main execution function: installs Horizon Agent and DEM if not already present,
# then logs the results to CSV and prints a status message
function Install-HorizonAndDEM {
    $ComputerName = $env:COMPUTERNAME
    $HorizonAgentPath = Join-Path $SharePath $HorizonAgentFile
    $DEMPath = Join-Path $SharePath $DEMFile

    Write-Host "`n--- Checking & Installing Horizon Agent ---"
    $horizonResult = $false
    if (Is-Installed -DisplayName "VMware Horizon Agent") {
        Write-Host "Horizon Agent already installed."
        $horizonResult = $true
    } else {
        $horizonResult = Install-EXE -InstallerPath $HorizonAgentPath -Arguments $HorizonAgentArgs
    }

    Write-Host "`n--- Checking & Installing DEM ---"
    $demResult = $false
    if (Is-Installed -DisplayName "VMware DEM") {
        Write-Host "VMware DEM already installed."
        $demResult = $true
    } else {
        $demResult = Install-MSI -InstallerPath $DEMPath -Arguments $DEMArgs
    }

    Write-Host "`n--- Logging Result ---"
    Write-LogEntry -ComputerName $ComputerName -HorizonSuccess $horizonResult -DEMSuccess $demResult

    if ($horizonResult -and $demResult) {
        Write-Host "✅ Installation complete on $ComputerName."
    } else {
        Write-Warning "⚠️ One or more installations failed on $ComputerName."
    }
}

# Run the install process
Install-HorizonAndDEM
'@

# Run the script inside each VM using VMware Tools
foreach ($vmEntry in $vmList) {
    $vmName = $vmEntry.VMName
    Write-Host "`n===== Running on VM: $vmName ====="

    $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Warning "VM '$vmName' not found. Skipping..."
        continue
    }

    try {
        $result = Invoke-VMScript -VM $vm -ScriptText $scriptText -GuestCredential $guestCred -ScriptType Powershell -ErrorAction Stop
        Write-Host "[$vmName] Script executed. Output:`n$result.ScriptOutput"
    } catch {
        Write-Warning "[$vmName] Failed to execute script: $_"
    }
}
