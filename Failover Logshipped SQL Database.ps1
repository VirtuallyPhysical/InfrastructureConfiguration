# Define variables with named instances
$PrimaryServer = "SQLPrimary\SQL2022"     # Change this to your primary server's named instance
$SecondaryServer = "SQLSecondary\SQL2022" # Change this to your secondary server's named instance
$DatabaseName = "YourDatabase"            # Change this to your database name
$LogFilePath = "C:\LogShipping\Logs\"     # Path where transaction log backups are stored
$SqlCredential = Get-Credential           # Prompt for SQL authentication credentials

# Function to execute a SQL command
function Invoke-SqlCmdWrapper {
    param (
        [string]$ServerInstance,
        [string]$Query
    )
    Invoke-Sqlcmd -ServerInstance $ServerInstance -Credential $SqlCredential -Query $Query
}

# Step 1: Restore any remaining transaction logs on the secondary server
Write-Host "Restoring remaining transaction logs on secondary server..."
$LogFiles = Get-ChildItem -Path $LogFilePath -Filter "*.trn" | Sort-Object Name

foreach ($LogFile in $LogFiles) {
    $RestoreQuery = "RESTORE LOG [$DatabaseName] FROM DISK = '$($LogFile.FullName)' WITH NORECOVERY;"
    Invoke-SqlCmdWrapper -ServerInstance $SecondaryServer -Query $RestoreQuery
    Write-Host "Restored log file: $($LogFile.Name)"
}

# Step 2: Bring the secondary database online (RESTORE WITH RECOVERY)
Write-Host "Bringing secondary database online..."
$RecoveryQuery = "RESTORE DATABASE [$DatabaseName] WITH RECOVERY;"
Invoke-SqlCmdWrapper -ServerInstance $SecondaryServer -Query $RecoveryQuery
Write-Host "Database failover complete. $DatabaseName is now the primary on $SecondaryServer."

# Step 3: Redirect application connections (if necessary)
Write-Host "Log shipping failover completed successfully!"