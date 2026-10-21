#Requires -Version 5.1
<#
.SYNOPSIS
  Export VCF Operations 9 content and operational inventory from two deployments.
.NOTES
  Read-only queries, except POST to start a native content export job.
  Use a privileged account with rights to view the content being audited.
  Output may contain sensitive configuration. Store securely.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$SourceFqdn,
    [Parameter(Mandatory)] [string]$TargetFqdn,
    [string]$OutputPath = (Join-Path (Get-Location) 'VCFOps-Audit'),
    [ValidateRange(100,5000)] [int]$PageSize = 1000,
    [ValidateRange(30,3600)] [int]$ExportTimeoutSeconds = 900,
    [switch]$SkipCertificateCheck
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1: explicitly negotiate TLS 1.2. PowerCLI installation is not required by these REST requests.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($SkipCertificateCheck) {
    throw 'SkipCertificateCheck is not supported by this Windows PowerShell 5.1 edition. Install trusted CA certificates instead.'
}
$baseOutput = [IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Path $baseOutput -Force | Out-Null

function Save-Json {
    param($Value, [string]$Path)
    ConvertTo-Json -InputObject $Value -Depth 80 | Set-Content -LiteralPath $Path -Encoding utf8
}
function Call-Api {
    param([string]$Base, [hashtable]$Headers, [string]$Path,
          [string]$Method='GET', $Body=$null)
    $params = @{
        Uri = "$Base$Path"; Method = $Method; Headers = $Headers
        ErrorAction = 'Stop'; TimeoutSec = 120
    }
    if ($null -ne $Body) {
        $params.ContentType = 'application/json'
        $params.Body = ConvertTo-Json -InputObject $Body -Depth 30 -Compress
    }
    Invoke-RestMethod @params
}
function Fetch-PagedResources {
    param([string]$Base, [hashtable]$Headers)
    $results = New-Object 'System.Collections.Generic.List[object]'
    $page = 0
    do {
        $data = Call-Api -Base $Base -Headers $Headers -Path "/resources?page=$page&pageSize=$PageSize"
        $batch = @($data.resourceList | Where-Object { $null -ne $_ })
        foreach ($entry in $batch) { $results.Add($entry) }
        $page++
        $total = $null
        if ($null -ne $data.pageInfo -and $null -ne $data.pageInfo.totalCount) {
            $total = [int64]$data.pageInfo.totalCount
        }
        if ($null -ne $total) {
            $more = ($results.Count -lt $total)
        } else {
            $more = ($batch.Count -ge $PageSize)
        }
        if ($more -and $batch.Count -eq 0) { throw 'Pagination returned an empty page before completion.' }
        if ($page -gt 100000) { throw 'Pagination safety limit exceeded.' }
    } while ($more)
    return ,$results.ToArray()
}
function Export-Deployment {
    param([string]$Fqdn, [string]$Label)
    $Fqdn = $Fqdn.Trim().TrimEnd('/') -replace '^https?://',''
    if ($Fqdn -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.:-]+$') { throw "Unexpected server name: $Fqdn" }
    $folder = Join-Path $baseOutput $Label
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $base = "https://$Fqdn/suite-api/api"
    Write-Host "[$Label] Authenticating to $Fqdn ..."
    $cred = Get-Credential -Message "Credentials for $Label ($Fqdn)"
    $password = (New-Object System.Net.NetworkCredential -ArgumentList @('', $cred.Password)).Password
    try {
        $auth = Call-Api -Base $base -Headers @{} -Path '/auth/token/acquire' -Method POST -Body @{
            username=$cred.UserName; password=$password
        }
    } finally {
        $password = $null
    }
    if (-not $auth.token) { throw "[$Label] Authentication returned no token." }
    $headers = @{ Authorization = "OpsToken $($auth.token)"; Accept = 'application/json' }
    try {
        $version = Call-Api -Base $base -Headers $headers -Path '/versions/current'
        Save-Json $version (Join-Path $folder 'Version.json')
        Write-Host "[$Label] Version: $($version.releaseName)"

        # Native export: explicitly request all documented content categories.
        # Built-in content coverage is subject to the API's export semantics; verify defaults separately.
        # No EncryptionPassword header is supplied; protect the resulting archive carefully.
        Write-Host "[$Label] Starting native configuration content export ..."
        $startedAt = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
        $contentTypes = @(
            'VIEW_DEFINITIONS','REPORT_DEFINITIONS','DASHBOARDS','REPORT_SCHEDULES',
            'POLICIES','ALERT_DEFINITIONS','SYMPTOM_DEFINITIONS','LI_QUERY_CONFIGS',
            'LI_EXTRACTED_FIELDS','LI_AGENT_GROUPS','LI_TEMPLATES',
            'RECOMMENDATION_DEFINITIONS','CUSTOM_GROUPS','CUSTOM_METRICGROUPS',
            'SUPER_METRICS','CONFIG_FILES','COMPLIANCE_SCORECARDS','CONFIG_TEMPLATES',
            'NOTIFICATION_RULES','OUTBOUND_SETTINGS','PAYLOAD_TEMPLATES','INTEGRATIONS',
            'USERS','USER_GROUPS','ROLES','AUTH_SOURCES','HTTP_PROXIES','COST_DRIVERS',
            'SDMP_CUSTOM_SERVICES','SDMP_CUSTOM_APPLICATIONS','CUSTOM_PROFILES',
            'DISCOVERY_RULES','APP_DEF_ASSIGNMENTS','GLOBAL_SETTINGS'
        )
        $body = @{scope='ALL'; contentTypes=$contentTypes}
        $null = Call-Api -Base $base -Headers $headers -Path '/content/operations/export' -Method POST -Body $body
        $deadline = [datetime]::UtcNow.AddSeconds($ExportTimeoutSeconds)
        do {
            Start-Sleep -Seconds 5
            $status = Call-Api -Base $base -Headers $headers -Path '/content/operations/export'
            if ($status.state -in @('FAILED','UNKNOWN')) { break }
            if ([datetime]::UtcNow -ge $deadline) { throw "[$Label] Content export timed out." }
        } until ($status.state -eq 'FINISHED' -and [int64]$status.startTime -ge ($startedAt - 10000))
        Save-Json $status (Join-Path $folder 'ContentExportStatus.json')
        if ($status.state -ne 'FINISHED') {
            throw "[$Label] Export state: $($status.state); $($status.errorMessages -join '; ')"
        }
        $badTypes = @($status.operationSummaries | Where-Object { $_.state -ne 'FINISHED' })
        if ($badTypes.Count -gt 0 -or @($status.errorMessages).Count -gt 0) {
            throw "[$Label] Native export had failed/incomplete categories. Inspect ContentExportStatus.json"
        }
        $download = @($status.links | Where-Object { $_.name -eq 'lastExportDownloadURL' } | Select-Object -First 1)
        if (-not $download -or -not $download[0].href) { throw "[$Label] Export completed without download link." }
        $href = [string]$download[0].href
        if ($href.StartsWith('/suite-api/api/')) {
            $uri = "https://$Fqdn$href"
        } elseif ($href.StartsWith('https://')) {
            $uri = $href
            if (([uri]$uri).Authority -ne ([uri]"https://$Fqdn").Authority) {
                throw "[$Label] Unexpected export download host."
            }
        } else { throw "[$Label] Unexpected export download URL: $href" }
        $downloadArgs = @{
            Uri=$uri; Headers=$headers; OutFile=(Join-Path $folder 'Configuration.zip')
            ErrorAction='Stop'; TimeoutSec=300
        }
        $downloadArgs.UseBasicParsing = $true
        Invoke-WebRequest @downloadArgs | Out-Null
        $zip = Join-Path $folder 'Configuration.zip'
        $stream = [IO.File]::OpenRead($zip)
        try {
            $signature = New-Object byte[] 2
            $null = $stream.Read($signature,0,2)
            if ($signature[0] -ne 0x50 -or $signature[1] -ne 0x4B) { throw "[$Label] Download is not a ZIP archive." }
        } finally { $stream.Dispose() }
        Write-Host "[$Label] Export archive downloaded."

        # Explicit query for all alert definitions (including factory definitions returned by API).
        # This acts as a cross-check for native content export scope.
        $allDefinitions = New-Object 'System.Collections.Generic.List[object]'
        $defPage = 0
        do {
            $defs = Call-Api -Base $base -Headers $headers -Path "/alertdefinitions?page=$defPage&pageSize=$PageSize"
            $defBatch = @($defs.alertDefinitions | Where-Object { $null -ne $_ })
            foreach ($def in $defBatch) { $allDefinitions.Add($def) }
            $defPage++
            $defTotal = $null
            if ($null -ne $defs.pageInfo -and $null -ne $defs.pageInfo.totalCount) {
                $defTotal = [int64]$defs.pageInfo.totalCount
            }
            $defMore = if ($null -ne $defTotal) {
                $allDefinitions.Count -lt $defTotal
            } else { $defBatch.Count -ge $PageSize }
            if ($defMore -and $defBatch.Count -eq 0) { throw "[$Label] Alert pagination stopped early." }
            if ($defPage -gt 100000) { throw "[$Label] Alert pagination safety limit exceeded." }
        } while ($defMore)
        Save-Json $allDefinitions.ToArray() (Join-Path $folder 'AllAlertDefinitions.json')
        $allDefinitions | ForEach-Object {
            [pscustomobject]@{
                Name=$_.name; AdapterKind=$_.adapterKindKey; ResourceKind=$_.resourceKindKey
                Description=$_.description; WaitCycles=$_.waitCycles
                CancelCycles=$_.cancelCycles; Id=$_.id
            }
        } | Export-Csv (Join-Path $folder 'AllAlertDefinitions.csv') -NoTypeInformation -Encoding utf8
        $policySummaries = Call-Api -Base $base -Headers $headers -Path '/policies'
        Save-Json $policySummaries (Join-Path $folder 'PoliciesSummary.json')
        $policies = @($policySummaries.policySummaries | Where-Object { $null -ne $_ })
        $policies | Select-Object id,name,defaultPolicy,priority | Export-Csv (Join-Path $folder 'Policies.csv') -NoTypeInformation -Encoding UTF8
        # VCF Operations policy export is a vendor-owned format. Preserve it rather than
        # pretending alert enablement can be inferred from an alert definition alone.
        if ($policies.Count -gt 0) {
            $policyIds = ($policies | ForEach-Object { 'id=' + [uri]::EscapeDataString([string]$_.id) }) -join '&'
            $policyZip = Join-Path $folder 'Policies.zip'
            Invoke-WebRequest -Uri "$base/policies/export?$policyIds" -Headers $headers -OutFile $policyZip -UseBasicParsing -TimeoutSec 300 -ErrorAction Stop | Out-Null
            $fs = [IO.File]::OpenRead($policyZip)
            try {
                $magic = New-Object byte[] 2
                [void]$fs.Read($magic,0,2)
                if ($magic[0] -ne 0x50 -or $magic[1] -ne 0x4B) { throw 'Policy export did not return a ZIP.' }
            } finally { $fs.Dispose() }
        }
        # All alert definitions, including built-ins, are included in the matrix.
        # The public API does not supply a per-policy enablement state via this endpoint.
        # These are deliberately UNVERIFIED pending review of the vendor policy export.
        $alertMatrix = foreach ($def in $allDefinitions) {
            foreach ($policy in $policies) {
                [pscustomobject]@{
                    AlertName=$def.name; AlertId=$def.id
                    AdapterKind=$def.adapterKindKey; ResourceKind=$def.resourceKindKey
                    PolicyName=$policy.name; PolicyId=$policy.id
                    IsDefaultPolicy=$policy.defaultPolicy; PolicyPriority=$policy.priority
                    Enabled='UNVERIFIED'; Evidence='Policies.zip (requires policy content inspection)'
                }
            }
        }
        @($alertMatrix) | Export-Csv (Join-Path $folder 'AlertPolicyMatrix.csv') -NoTypeInformation -Encoding UTF8
        # Collector and management-pack inventories: no arbitrary guessing about pack versions.
        $collectors = Call-Api -Base $base -Headers $headers -Path '/collectors'
        Save-Json $collectors (Join-Path $folder 'Collectors.json')
        @($collectors.collector) | Select-Object name,hostName,type,state,local,lastHeartbeat,id,uuId,dataPersistenceEnabled,notSupported |
            Export-Csv (Join-Path $folder 'Collectors.csv') -NoTypeInformation -Encoding UTF8
        $collectorGroups = Call-Api -Base $base -Headers $headers -Path '/collectorgroups'
        Save-Json $collectorGroups (Join-Path $folder 'CollectorGroups.json')
        @($collectorGroups.collectorGroups) | Select-Object name,description,haEnabled,lbEnabled,systemDefined,id |
            Export-Csv (Join-Path $folder 'CollectorGroups.csv') -NoTypeInformation -Encoding UTF8
        $solutions = Call-Api -Base $base -Headers $headers -Path '/solutions'
        Save-Json $solutions (Join-Path $folder 'ManagementPacks.json')
        @($solutions.solution) | Where-Object { $null -ne $_ } |
            Select-Object name,version,vendor,id | Export-Csv (Join-Path $folder 'ManagementPacks.csv') -NoTypeInformation -Encoding UTF8

        # Operational snapshot, separate from the content archive.
        $adapters = Call-Api -Base $base -Headers $headers -Path '/adapters'
        Save-Json $adapters (Join-Path $folder 'AdapterInstances.json')
        $adapterRows = @($adapters.adapterInstancesInfoDto | ForEach-Object {
            [pscustomobject]@{
                Name=$_.resourceKey.name; AdapterKind=$_.resourceKey.adapterKindKey
                Description=$_.description; CollectorId=$_.collectorId
                CollectorGroupId=$_.collectorGroupId; MonitoringInterval=$_.monitoringInterval
                MonitoringIntervalSeconds=$_.monitoringIntervalSeconds
                ResourceCount=$_.numberOfResourcesCollected; MetricsCount=$_.numberOfMetricsCollected
                LastCollected=$_.lastCollected; LastHeartbeat=$_.lastHeartbeat
                Id=$_.id
            }
        })
        $adapterRows | Export-Csv (Join-Path $folder 'AdapterInstances.csv') -NoTypeInformation -Encoding utf8

        Write-Host "[$Label] Fetching paginated resource inventory ..."
        $resources = @(Fetch-PagedResources -Base $base -Headers $headers)
        Save-Json $resources (Join-Path $folder 'Resources.json')
        $rows = @($resources | ForEach-Object {
            $r = $_
            [pscustomobject]@{
                Name=$r.resourceKey.name
                AdapterKind=$r.resourceKey.adapterKindKey
                ResourceKind=$r.resourceKey.resourceKindKey
                Description=$r.description
                IdentifierValues=(@($r.resourceKey.resourceIdentifiers | ForEach-Object {
                    "$($_.identifierType.name)=$($_.value)"
                }) -join '; ')
                ResourceStatus=(@($r.resourceStatusStates | ForEach-Object {
                    "$($_.resourceStatus) / $($_.resourceState)"
                }) -join '; ')
                ResourceId=$r.identifier
                CreationTime=$r.creationTime
            }
        })
        $rows | Export-Csv (Join-Path $folder 'Resources.csv') -NoTypeInformation -Encoding utf8
        $rows | Group-Object AdapterKind,ResourceKind | ForEach-Object {
            [pscustomobject]@{Type=$_.Name;Count=$_.Count}
        } | Sort-Object Type | Export-Csv (Join-Path $folder 'InventoryByType.csv') -NoTypeInformation -Encoding utf8
        Save-Json ([pscustomobject]@{
            Server=$Fqdn; CapturedUtc=(Get-Date).ToUniversalTime().ToString('o')
            ProductVersion=$version.releaseName; ResourceCount=$resources.Count
            AdapterInstanceCount=$adapterRows.Count
            ContentExportState=$status.state; ContentExportId=$status.id
        }) (Join-Path $folder 'Manifest.json')
        Write-Host "[$Label] Completed: $($resources.Count) resources, $($adapterRows.Count) adapters."
    } finally {
        # Clears the stored OpsToken on the server; local strings remain in process memory until released.
        try { $null = Call-Api -Base $base -Headers $headers -Path '/auth/token/release' -Method POST } catch { }
    }
}

Export-Deployment -Fqdn $SourceFqdn -Label 'Source'
Export-Deployment -Fqdn $TargetFqdn -Label 'Target'

# Summary comparison: expected inventory differences are recorded, not treated as configuration failures.
$src = Import-Csv (Join-Path $baseOutput 'Source/InventoryByType.csv')
$dst = Import-Csv (Join-Path $baseOutput 'Target/InventoryByType.csv')
$types = @($src.Type + $dst.Type | Sort-Object -Unique)
$comparison = foreach ($type in $types) {
    $a = $src | Where-Object Type -eq $type | Select-Object -First 1
    $b = $dst | Where-Object Type -eq $type | Select-Object -First 1
    [pscustomobject]@{ Type=$type; SourceCount=[int]$a.Count; TargetCount=[int]$b.Count; Difference=([int]$b.Count-[int]$a.Count) }
}
$comparison | Export-Csv (Join-Path $baseOutput 'InventoryTypeComparison.csv') -NoTypeInformation -Encoding utf8
Write-Host "Done. Snapshots: $baseOutput"
Write-Warning 'AlertPolicyMatrix Enabled=UNVERIFIED is intentional: review policy ZIP contents before declaring enabled/disabled. Native policy XML/ZIP has no stable cross-version semantic schema.'
Write-Warning 'Inventory count comparison is informational. Configuration ZIP contents require semantic comparison; equal counts do not establish parity.' 
