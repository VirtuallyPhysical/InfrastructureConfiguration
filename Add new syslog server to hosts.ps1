function ConfigureSyslog {
    param (
        [string] $SyslogRestart = (Read-Host " Restart Syslog first? y/n"),
        [string] $TxtLocation = (Read-Host " Please enter txt file location"),
        [string] $SyslogServer = (Read-Host " Please enter syslog server"),
        [string] $VCChoice = (Read-Host " Please enter vCenter Name"),
        [PSCredential] $Creds = (Get-Credential)
    )

    $GlobalSysLogConfig = @()

    foreach ($esxhost in (Get-Content $TxtLocation)) {
        if ((Get-VMHost $esxhost | Get-VMHostSysLogServer).Host -notcontains "$SyslogServer") {
            if ($SyslogRestart -eq "y") {
                $esxcli = Get-EsxCLI -VMhost $esxhost
                $esxcli.system.syslog.reload()
            }

            $EsxSysLogConfig = "" | select Host, ExistingConfig, NewConfig, Time, Change
            Write-Host ".... Writing existing configuration of host $esxhost to log" -ForegroundColor Green
            $EsxSysLogConfig.Host = (Get-VMHost $esxhost).Name
            $EsxSysLogConfig.ExistingConfig = ((Get-VMHostSysLogServer -VMhost $esxhost) -join ',')
            $EsxSysLogConfig.Time = $(get-date -f yyyy-MM-dd-hhmm)

            Write-Host ".... Adding $SyslogServer to configuration on host $esxhost" -ForegroundColor Green
            Set-VMHostSysLogServer -VMhost $esxhost -SysLogServer $EsxSysLogConfig.ExistingConfig,$SyslogServer":"514 -Confirm:$false
            $EsxSysLogConfig.NewConfig = ((Get-VMHostSysLogServer -VMhost $esxhost) -join ',')
            $EsxSysLogConfig.Change = "Changed"
            $GlobalSysLogConfig += $EsxSysLogConfig
        }
        else {
            Get-VMHost $esxhost | Get-VMHostSysLogServer | export-csv -path ".\Syslog Config.csv" -append
            Write-Host "$esxhost is already configured with $SyslogServer, moving on..." -ForegroundColor Red
            Start-Sleep -Second 1
            $EsxSysLogConfig = "" | select Host, ExistingConfig, NewConfig, Time, Change
            $EsxSysLogConfig.Host = (Get-VMHost $esxhost ).Name
            $EsxSysLogConfig.ExistingConfig = (Get-VMHost $esxhost | Get-VMHostSysLogServer)
            $EsxSysLogConfig.Time = $(get-date -f yyyy-MM-dd-hhmm)
            $EsxSysLogConfig.Change = "No Change"
            $GlobalSysLogConfig += $EsxSysLogConfig
        }
    }

    Connect-VIServer $VCChoice -AllLinked -credential $Creds
}

ConfigureSyslog
