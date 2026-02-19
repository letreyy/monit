param(
    [string]$Api = "http://127.0.0.1:8050",
    [string]$AssetId = $env:COMPUTERNAME,
    [string]$Location = "windows-site",
    [int]$IntervalSec = 30,
    [int]$LookbackMinutes = 5
)

$assetBody = @{
    id = $AssetId
    name = $AssetId
    asset_type = "server"
    location = $Location
} | ConvertTo-Json

Invoke-RestMethod -Uri "$Api/assets" -Method Post -Body $assetBody -ContentType "application/json" | Out-Null

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

        $events += @{
            asset_id = $AssetId
            source = "windows_eventlog"
            message = "[$($log.LogName)] EventID=$($log.Id) Provider=$($log.ProviderName) :: $($log.Message)"
            severity = $sev
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
        }
    }

    if ($events.Count -gt 0) {
        $batch = @{ events = $events } | ConvertTo-Json -Depth 5
        Invoke-RestMethod -Uri "$Api/ingest/events" -Method Post -Body $batch -ContentType "application/json" | Out-Null
        Write-Host "[$(Get-Date -Format o)] Sent $($events.Count) windows events"
    }

    Start-Sleep -Seconds $IntervalSec
}
