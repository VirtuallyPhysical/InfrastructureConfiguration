# =======================
# Configurable Variables
# =======================
$SharePath = "\\server\share\installers" # UNC path to installer folder
$HorizonAgentFile = "VMware-Horizon-Agent-x86_64-2312.exe"
$DEMFile = "VMware-DEM-Enterprise-2312.msi"

# Installer Arguments
$HorizonAgentArgs = "/silent /norestart VDM_VC_MANAGED=1 ADDLOCAL=Core,Blast,USB,TSMMR REMOVE=PCoIP"
$DEMArgs = "/qn /norestart"

# CSV log path (same share)
$LogFilePath = Join-Path -Path $SharePath -ChildPath "VDI_Install_Status.csv"

# =======================
# Reusable Functions
# =======================

function Install-EXE {
    param (
        [string]$InstallerPath,
        [string]$Arguments
    )

    if (-Not (Test-Path $InstallerPath)) {
        Write-Error "EXE installer not found: $InstallerPath"
        return $false
    }

    Write-Host "Installing Horizon Agent from: $InstallerPath"
    $process = Start-Process -FilePath $InstallerPath -ArgumentList $Arguments -Wait -PassThru

    return ($process.ExitCode -eq 0)
}

function Install-MSI {
    param (
        [string]$InstallerPath,
        [string]$Arguments
    )

    if (-Not (Test-Path $InstallerPath)) {
        Write-Error "MSI installer not found: $InstallerPath"
        return $false
    }

    Write-Host "Installing DEM from: $InstallerPath"
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$InstallerPath`" $Arguments" -Wait -PassThru

    return ($process.ExitCode -eq 0)
}

function Write-LogEntry {
    param (
        [string]$ComputerName,
        [bool]$HorizonSuccess,
        [bool]$DEMSuccess
    )

    $logEntry = [PSCustomObject]@{
        ComputerName                     = $ComputerName
        HorizonAgent_Installed_Success  = $HorizonSuccess
        DEM_Installed_Success           = $DEMSuccess
    }

    $fileExists = Test-Path $LogFilePath
    $logEntry | Export-Csv -Path $LogFilePath -Append -NoTypeInformation -Force -Encoding UTF8 -Delimiter ','

    if (-not $fileExists) {
        Write-Host "Created new log at $LogFilePath"
    } else {
        Write-Host "Appended log to $LogFilePath"
    }
}

# =======================
# Main Execution
# =======================
function Install-HorizonAndDEM {
    $ComputerName = $env:COMPUTERNAME
    $HorizonAgentPath = Join-Path $SharePath $HorizonAgentFile
    $DEMPath = Join-Path $SharePath $DEMFile

    Write-Host "`n--- Installing Horizon Agent ---"
    $horizonResult = Install-EXE -InstallerPath $HorizonAgentPath -Arguments $HorizonAgentArgs

    Write-Host "`n--- Installing DEM ---"
    $demResult = Install-MSI -InstallerPath $DEMPath -Arguments $DEMArgs

    Write-Host "`n--- Logging Installation Status ---"
    Write-LogEntry -ComputerName $ComputerName -HorizonSuccess $horizonResult -DEMSuccess $demResult

    if ($horizonResult -and $demResult) {
        Write-Host "`nInstallations completed successfully on $ComputerName."
    } else {
        Write-Warning "`nOne or more installations failed on $ComputerName. Check the CSV log for details."
    }
}

# Run the installation
Install-HorizonAndDEM
