# Run as Administrator for best results

# Get user's home directory
$userDir = Join-Path $env:USERPROFILE "NetworkDiagnostics"
if (-not (Test-Path $userDir)) { New-Item -ItemType Directory -Path $userDir | Out-Null }

$timestampStr = Get-Date -Format "yyyyMMdd_HHmmss"
$packageDir = Join-Path $userDir "DiagnosticsPackage_$timestampStr"
if (-not (Test-Path $packageDir)) { New-Item -ItemType Directory -Path $packageDir | Out-Null }

# Subfolders for structure
$networkingDir   = Join-Path $packageDir "Networking"
$eventViewerDir  = Join-Path $packageDir "EventViewer"
$systemInfoDir   = Join-Path $packageDir "SystemInfo"
$firewallDir = Join-Path $packageDir "Firewall"
$hardwareDir = Join-Path $packageDir "Hardware"
$wlanDir = Join-Path $packageDir "WLAN"
$miscDir = Join-Path $packageDir "Misc"
foreach ($subdir in @($networkingDir, $eventViewerDir, $systemInfoDir, $firewallDir, $hardwareDir, $wlanDir, $miscDir)) {
    if (-not (Test-Path $subdir)) { New-Item -ItemType Directory -Path $subdir | Out-Null }
}

# Networking file paths
$logPath   = Join-Path $networkingDir "NetworkDiag_$timestampStr.csv"
$traceFile = Join-Path $networkingDir "NetTrace_$timestampStr.etl"
$cabFile   = [System.IO.Path]::ChangeExtension($traceFile, ".cab")
$zipFile   = Join-Path $userDir "DiagnosticsPackage_$timestampStr.zip"

# Initialize the CSV with headers (only if file doesn't exist)
if (-not (Test-Path $logPath)) {
    [PSCustomObject]@{
        Timestamp      = ""
        LocalAddress   = ""
        LocalPort      = ""
        RemoteAddress  = ""
        RemotePort     = ""
        State          = ""
        PID            = ""
        ProcessName    = ""
    } | Export-Csv $logPath -NoTypeInformation -Encoding UTF8
}

# Start netsh trace in the background
Write-Host "Starting netsh packet capture in background..."
Start-Process -FilePath "netsh" -ArgumentList "trace start capture=yes tracefile=`"$traceFile`"" -WindowStyle Hidden

Write-Host "Network monitoring started. Press Ctrl+C to stop..."

try {
    while ($true) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $connections = Get-NetTCPConnection
        foreach ($conn in $connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($proc) { $proc.ProcessName } else { "N/A" }
            [PSCustomObject]@{
                Timestamp      = $timestamp
                LocalAddress   = $conn.LocalAddress
                LocalPort      = $conn.LocalPort
                RemoteAddress  = $conn.RemoteAddress
                RemotePort     = $conn.RemotePort
                State          = $conn.State
                PID            = $conn.OwningProcess
                ProcessName    = $procName
            } | Export-Csv $logPath -NoTypeInformation -Append -Encoding UTF8
        }
        Start-Sleep -Seconds 1
    }
} finally {
    Write-Host "`nStopping netsh trace and exiting..."
    $status = netsh trace show status
    if ($status -match "running") {
        netsh trace stop | Write-Host
        Write-Host "Packet capture stopped."
    } else {
        Write-Host "No running netsh trace session found."
    }

    # Wait for CAB file to appear and be stable
    if (Test-Path $traceFile) {
        Write-Host "Waiting for CAB file extraction to finish..."
        $timeoutSec = 60
        $waitSec = 0
        $lastSize = 0
        $stableCount = 0
        while ($waitSec -lt $timeoutSec) {
            if (Test-Path $cabFile) {
                $size = (Get-Item $cabFile).Length
                if ($size -eq $lastSize) {
                    $stableCount++
                } else {
                    $stableCount = 0
                }
                $lastSize = $size
                if ($stableCount -ge 3) { break }
            } else {
                $stableCount = 0
            }
            Start-Sleep -Seconds 1
            $waitSec++
        }
        if (Test-Path $cabFile) {
            Write-Host "CAB file extraction complete: $cabFile"

# ===== CAB Extraction and Sorting Logic =====

# Extract CAB to temp directory under Networking
$cabExtractDir = Join-Path $networkingDir "CAB_Contents"
if (-not (Test-Path $cabExtractDir)) { New-Item -ItemType Directory -Path $cabExtractDir | Out-Null }
try {
    Expand-Archive -Path $cabFile -DestinationPath $cabExtractDir -Force
} catch {
    $expandExe = "$env:SystemRoot\\System32\\expand.exe"
    & $expandExe $cabFile -F:* $cabExtractDir | Out-Null
}
# Sorting logic: Move files to their purpose folders by extension or name pattern (deduplicated)
Get-ChildItem -Path $cabExtractDir -Recurse | ForEach-Object {
    $destination = $null
    switch -Regex ($_.Name) {
        # 1. Event logs (priority)
        '\.evtx$|\.mta$' { $destination = $eventViewerDir; break }
        # 2. Firewall (logs/config only)
        '^firewall|^firewalleffectiverules' { $destination = $firewallDir; break }
        # 3. WLAN/Wireless/WWAN
        '^wlan|^wwan|^wcm|^wcn' { $destination = $wlanDir; break }
        # 4. Hardware diagnostics
        '^dxdiag|^dispdiag|^battery-report' { $destination = $hardwareDir; break }
        # 5. Networking logs/traces/config
        '^netstat|^routeprint|^arp|^report\.etl$|^ipconfig|^neighbors|^networkprofiles|^netiostate|^netevents|^wfpstate|^vmmsnetworking' { $destination = $networkingDir; break }
        # 6. System info, registry, policies, environment, service info, hotfixes, OS info
        '^systeminfo|^osinfo|^hotfixinfo|^envinfo|^serviceinfo|^powershellinfo|^gpresult|^notif|^policymanager|^edppolicies|^allcred|^apiperm|^filesharing' { $destination = $systemInfoDir; break }
        # 7. Miscellaneous (HTML, manifest, dat, etc)
        '\.html$|\.manifest$|\.dat$' { $destination = $miscDir; break }
    }
    if ($destination) {
        Move-Item $_.FullName -Destination $destination -Force
    } else {
        Move-Item $_.FullName -Destination $miscDir -Force
    }
}
# Optionally, remove empty CAB_Contents dir

# Remove-Item $cabExtractDir -Recurse -Force

Write-Host "Sorting completed"

# ===== End CAB Sorting =====
        } else {
            Write-Host "CAB file did not appear after capture stopped."
        }
    }

    # Export Event Viewer logs (last 48 hours) as CSV files
    Write-Host "Exporting Event Viewer logs (last 48 hours)"
    $eventLogFiles = @()
    $startTime = (Get-Date).AddHours(-48)
    $systemCsv = Join-Path $eventViewerDir "SystemLog_$timestampStr.csv"
    $appCsv = Join-Path $eventViewerDir "ApplicationLog_$timestampStr.csv"
    $securityCsv = Join-Path $eventViewerDir "SecurityLog_$timestampStr.csv"
    $defenderCsv = Join-Path $eventViewerDir "DefenderLog_$timestampStr.csv"

    Get-WinEvent -LogName System | Where-Object { $_.TimeCreated -ge $startTime } |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Export-Csv $systemCsv -NoTypeInformation
    if (Test-Path $systemCsv) { $eventLogFiles += $systemCsv }

    Get-WinEvent -LogName Application | Where-Object { $_.TimeCreated -ge $startTime } |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Export-Csv $appCsv -NoTypeInformation
    if (Test-Path $appCsv) { $eventLogFiles += $appCsv }

    Get-WinEvent -LogName Security | Where-Object { $_.TimeCreated -ge $startTime } |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Export-Csv $securityCsv -NoTypeInformation
    if (Test-Path $securityCsv) { $eventLogFiles += $securityCsv }

    Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' | Where-Object { $_.TimeCreated -ge $startTime } |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Export-Csv $defenderCsv -NoTypeInformation
    if (Test-Path $defenderCsv) { $eventLogFiles += $defenderCsv }

    # SystemInfo: running processes
    $procCsv = Join-Path $systemInfoDir "ProcessList_$timestampStr.csv"
    Get-Process | Select-Object Name, Id, StartTime, Path, CPU, PM, WS | Export-Csv $procCsv -NoTypeInformation

    # SystemInfo: installed software inventory
    $softwareCsv = Join-Path $systemInfoDir "InstalledSoftware_$timestampStr.csv"
    $programs = @( 
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null
        Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null
    ) | Where-Object { $_.DisplayName } | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    $programs | Export-Csv $softwareCsv -NoTypeInformation

    # Zip the entire diagnostics package folder
    Write-Host "Packaging diagnostics folder into: $zipFile"
    Compress-Archive -Path $packageDir -DestinationPath $zipFile -Force
    Write-Host "Diagnostics package created: $zipFile"
    Write-Host "All diagnostics saved to: $packageDir"
}
