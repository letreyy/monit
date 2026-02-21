param(
    [string]$Api = "http://127.0.0.1:8050",
    [string]$AssetId = $env:COMPUTERNAME,
    [string]$Location = "windows-site",
    [int]$IntervalSec = 30,
    [int]$LookbackMinutes = 5
)

function Send-JsonUtf8 {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][object]$Payload
    )

    $json = $Payload | ConvertTo-Json -Depth 8 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    Invoke-RestMethod \
        -Uri $Uri \
        -Method Post \
        -Body $bytes \
        -ContentType "application/json; charset=utf-8" | Out-Null
}

$assetBody = @{
    id = $AssetId
    name = $AssetId
    asset_type = "server"
    location = $Location
}

Send-JsonUtf8 -Uri "$Api/assets" -Payload $assetBody

while ($true) {
    $startTime = (Get-Date).AddMinutes(-$LookbackMinutes)

    $appLogs = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$startTime} -ErrorAction SilentlyContinue | Select-Object -First 50
    $sysLogs = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$startTime} -ErrorAction SilentlyContinue | Select-Object -First 50
    $allLogs = @($appLogs + $sysLogs)

    $events = @()
    foreach ($log in $allLogs) {
        $sev = "info"
        if ($log.LevelDisplayName -match "Error|Warning") { $sev = "warning" }
        if ($log.LevelDisplayName -match "Critical") { $sev = "critical" }

        $logName = if ([string]::IsNullOrWhiteSpace($log.LogName)) { "Unknown" } else { $log.LogName }
        $eventId = if ($null -eq $log.Id) { "Unknown" } else { $log.Id }
        $provider = if ([string]::IsNullOrWhiteSpace($log.ProviderName)) { "Unknown" } else { $log.ProviderName }
        $msg = if ([string]::IsNullOrWhiteSpace($log.Message)) { "(no message)" } else { $log.Message }

        $events += @{
            asset_id = $AssetId
            source = "windows_eventlog"
            message = "[$logName] EventID=$eventId Provider=$provider :: $msg"
            severity = $sev
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
        }
    }

    if ($events.Count -gt 0) {
        $batch = @{ events = $events }
        Send-JsonUtf8 -Uri "$Api/ingest/events" -Payload $batch
        Write-Host "[$(Get-Date -Format o)] Sent $($events.Count) windows events"
    }

    Start-Sleep -Seconds $IntervalSec
}
