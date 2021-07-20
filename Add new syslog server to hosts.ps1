function ConfigureSyslog {

Write-Host

#Options
$syslogrestart = Read-Host " Restart Syslog first? y/n"
Write-Host
Start-Sleep -Second 1
$txtlocation = Read-Host " Please enter txt file location"
write-host
write-host " Syslog server format   UDP://X.X.X.X" -ForegroundColor Yellow
$SyslogServer = Read-Host " Please enter syslog server"


$GlobalSysLogConfig = @()

ForEach ($esxhost in (Get-Content $txtlocation))
{
if((Get-VMHost $esxhost | Get-VMHostSysLogServer).Host -notcontains "$SyslogServer"){

		#Restart Syslog prior to configuration
         if($syslogrestart -eq "y"){
            $esxcli = Get-EsxCLI -VMhost $esxhost
            $esxcli.system.syslog.reload()}

         $EsxSysLogConfig = "" | select Host, ExistingConfig, NewConfig, Time, Change

		#Pull Existing Config
         Write-Host ".... Writing existing configuration of host $esxhost to log" -ForegroundColor Green
         $EsxSysLogConfig.Host = (Get-VMHost $esxhost).Name
         $EsxSysLogConfig.ExistingConfig = Get-VMHostSysLogServer -VMhost $esxhost
         $EsxSysLogConfig.Time = $(get-date -f yyyy-MM-dd-hhmm)

		#Write New Config
         Write-Host ".... Adding $SyslogServer to configuration on host $esxhost" -ForegroundColor Green
         Set-VMHostSysLogServer -VMhost $esxhost -SysLogServer $EsxSysLogConfig.ExistingConfig,$SyslogServer":"514 -Confirm:$false
         $EsxSysLogConfig.NewConfig = ((Get-VMHostSysLogServer -VMhost $esxhost) -join ',')
         $EsxSysLogConfig.Change = "Changed"
         $GlobalSysLogConfig += $EsxSysLogConfig
}

else{

		Get-VMHost $host | Get-VMHostSysLogServer | export-csv -path ".\Syslog Config.csv" -append
		Write-Host "$esxhost is already configured with $SyslogServer, moving on..." -ForegroundColor Red
		Start-Sleep -Second 1

		$EsxSysLogConfig.Host = (Get-VMHost $esxhost ).Name
		$EsxSysLogConfig.ExistingConfig = (Get-VMHost $esxhost | Get-VMHostSysLogServer)
		$EsxSysLogConfig.Time = $(get-date -f yyyy-MM-dd-hhmm)
		$EsxSysLogConfig.Change = "No Change"

		$GlobalSysLogConfig += $EsxSysLogConfig

     }

$GlobalSysLogConfig | Export-CSV -path ".\Syslog $(get-date -f yyyy-MM-dd-hhmm).csv"

}
}


write-host
$VCChoice = Read-Host " Please enter vCenter Name"
$creds = get-credential
Connect-VIServer $VCChoice -AllLinked -credential $creds
Start-Sleep -Second 1
ConfigureSyslog