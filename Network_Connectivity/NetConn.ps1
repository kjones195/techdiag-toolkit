<#
.SYNOPSIS
    Automated network connectivity diagnostics (with optional remediation) for Windows, with auto-packaging to ZIP.

.DESCRIPTION
    Tests adapter state, IP configuration, gateway reachability, DNS resolution, HTTP(S) egress, and proxy/GPO settings.
    Prioritizes the primary route (default gateway) so Ethernet/Wired adapters are treated as primary when active and
    avoids noisy findings for disconnected Wi‑Fi/VPN/virtual adapters.

    When -Remediate is used, attempts safe, reversible fixes (enable adapter, renew DHCP, flush DNS, reset WinHTTP proxy,
    reset Winsock/TCP/IP, etc.). Produces a machine-readable JSON report and a readable summary. At completion, packages
    the entire output directory into a timestamped ZIP file for easy sharing (can be disabled via -NoZip).

.PARAMETER Targets
    Hostnames/IPs/URLs to test for reachability. Defaults include common public endpoints and Microsoft URLs.

.PARAMETER OutPath
    Folder to write logs and reports. Defaults to %ProgramData%\WinDiagNet.

.PARAMETER Remediate
    Attempt safe automated remediation steps when issues are detected. Honor -WhatIf.

.PARAMETER Quick
    Skips heavier checks (e.g., route table dump, wireless report) for faster execution.

.PARAMETER NoTranscript
    Skip Start-Transcript logging.

.PARAMETER NoZip
    Do not create a ZIP package of the output directory when finished.

.PARAMETER ZipName
    Optional custom ZIP filename (without path). Defaults to NetworkDiagnostics_<Computer>_<timestamp>.zip. The ZIP is
    created in the parent folder of OutPath to avoid self-inclusion during compression.

.EXAMPLE
    .\NetConn.ps1 -Verbose

.EXAMPLE
    .\NetConn.ps1 -Remediate -WhatIf

.EXAMPLE
    .\NetConn.ps1 -Targets '1.1.1.1','8.8.8.8','https://www.microsoft.com' -OutPath C:\Temp\NetDiag

.OUTPUTS
    PSCustomObject with sections: System, NICs, Tests, Findings, ActionsTaken, NextSteps, ZipPath. Also writes JSON/TXT reports.

.NOTES
    Author: kjones195 | Tested: Windows 10/11, PowerShell 5.1+ / 7+
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [string[]]$Targets = @(
        '1.1.1.1',       # Cloudflare DNS (ICMP)
        '8.8.8.8',       # Google DNS (ICMP)
        'dns.google',    # DNS name resolution
        'microsoft.com',
        'aka.ms',
        'http://example.com',
        'https://www.microsoft.com'
    ),
    [string]$OutPath = (Join-Path $env:ProgramData 'WinDiagNet'),
    [switch]$Remediate,
    [switch]$Quick,
    [switch]$NoTranscript,
    [switch]$NoZip,
    [string]$ZipName
)

#region Helpers
function New-Folder {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString('s')
    $line = "[$ts][$Level] $Message"
    Write-Verbose $line
    $script:LogBuffer.Add($line) | Out-Null
}

function Out-ReportFiles {
    param(
        [Parameter(Mandatory)][hashtable]$Report,
        [string]$OutFolder
    )
    $jsonPath = Join-Path $OutFolder 'Network-Diagnostics.json'
    $txtPath  = Join-Path $OutFolder 'Network-Diagnostics.txt'
    $Report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("=== Network Connectivity Diagnostics Summary ===")
    $null = $sb.AppendLine((Get-Date).ToString('F'))
    $null = $sb.AppendLine("Computer: $($Report.System.ComputerName) | User: $($Report.System.User) | OS: $($Report.System.OS)")
    $null = $sb.AppendLine("PrimaryAdapter: $($Report.System.PrimaryAdapter) (IfIndex $($Report.System.PrimaryIfIndex))")
    $null = $sb.AppendLine("--- Findings ---")
    foreach ($f in $Report.Findings) { $null = $sb.AppendLine("- [$($f.Severity)] $($f.Code): $($f.Message)") }
    $null = $sb.AppendLine("--- Actions Taken ---")
    foreach ($a in $Report.ActionsTaken) { $null = $sb.AppendLine("- $($a)") }
    $null = $sb.AppendLine("--- Next Steps ---")
    foreach ($n in $Report.NextSteps) { $null = $sb.AppendLine("- $($n)") }

    $sb.ToString() | Set-Content -LiteralPath $txtPath -Encoding UTF8
    return @{ Json=$jsonPath; Text=$txtPath }
}

function Invoke-Capture {
    param([string]$File,[scriptblock]$ScriptBlock)
    try { & $ScriptBlock | Out-File -LiteralPath $File -Encoding UTF8 -Width 300 } catch { $_ | Out-File -LiteralPath $File -Encoding UTF8 }
}

function New-ZipPackage {
    [CmdletBinding(SupportsShouldProcess)] param(
        [Parameter(Mandatory)][string]$SourceFolder,
        [Parameter(Mandatory)][string]$DestinationZip
    )
    if ($PSCmdlet.ShouldProcess($SourceFolder, "Compress to '$DestinationZip'")) {
        try {
            # Ensure destination directory exists
            New-Folder -Path (Split-Path -Parent $DestinationZip)
            # Prefer Compress-Archive if available
            if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
                # Use wildcard to avoid including the ZIP itself
                Compress-Archive -Path (Join-Path $SourceFolder '*') -DestinationPath $DestinationZip -Force
            } else {
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
                if (Test-Path -LiteralPath $DestinationZip) { Remove-Item -LiteralPath $DestinationZip -Force }
                [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceFolder, $DestinationZip)
            }
            return $DestinationZip
        } catch {
            Write-Warning "ZIP packaging failed: $($_.Exception.Message)"
            return $null
        }
    }
}
#endregion Helpers

#region Adapter Selection & System Info
function Get-NetworkSystemInfo {
    [CmdletBinding()] param()
    [pscustomobject]@{
        Time         = (Get-Date)
        ComputerName = $env:COMPUTERNAME
        User         = "$($env:USERDOMAIN)\\$($env:USERNAME)"
        OS           = (Get-CimInstance -ClassName CIM_OperatingSystem).Caption
        PSVersion    = $PSVersionTable.PSVersion.ToString()
        IsElevated   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

function Get-PrimaryIfIndex {
    [CmdletBinding()] param()
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object -Property { $_.RouteMetric }, Metric | Select-Object -First 1
    if ($route) { return $route.InterfaceIndex }
    $bestUp = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -EQ 'Up' | Select-Object -First 1
    return $bestUp.IfIndex
}

function Test-IsIgnoredNic {
    param([string]$InterfaceDescription,[string]$Name)
    $ignorePattern = 'vEthernet|Hyper-V|Loopback|VPN|TAP|TUN|Cisco AnyConnect|WireGuard|Bluetooth|Npcap|WAN Miniport|VirtualBox|VMware|Docker'
    return ($InterfaceDescription -match $ignorePattern -or $Name -match $ignorePattern)
}

function Convert-LinkSpeedToMbps {
    param([object]$LinkSpeed)
    if (-not $LinkSpeed) { return $null }
    if ($LinkSpeed -is [string]) {
        if ($LinkSpeed -match '(?<num>[0-9.]+)\s*(?<unit>Gbps|Mbps)') {
            $num  = [double]$matches['num']
            $unit = $matches['unit']
            switch ($unit) { 'Gbps' { return [int]($num*1000) } 'Mbps' { return [int]$num } default { return $null } }
        } else { return $null }
    } else {
        try { return [math]::Round(($LinkSpeed/1MB),0) } catch { return $null }
    }
}

function Get-NicHealth {
    [CmdletBinding()] param()
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Unknown' }
    foreach ($nic in $adapters) {
        $ip = Get-NetIPConfiguration -InterfaceIndex $nic.ifIndex -ErrorAction SilentlyContinue
        $ignored = Test-IsIgnoredNic -InterfaceDescription $nic.InterfaceDescription -Name $nic.Name
        $linkSpeedMbps = Convert-LinkSpeedToMbps -LinkSpeed $nic.LinkSpeed
        [pscustomobject]@{
            IfIndex        = $nic.IfIndex
            Name           = $nic.Name
            InterfaceAlias = $nic.InterfaceAlias
            InterfaceDescription = $nic.InterfaceDescription
            Status         = $nic.Status
            AdminStatus    = $nic.AdminStatus
            Ignored        = $ignored
            LinkSpeedMbps  = $linkSpeedMbps
            MacAddress     = $nic.MacAddress
            IPv4           = $ip.IPv4Address.IPv4Address
            IPv6           = ($ip.IPv6Address | Select-Object -ExpandProperty IPv6Address -ErrorAction SilentlyContinue)
            Gateway        = $ip.IPv4DefaultGateway.NextHop
            DnsServers     = $ip.DnsServer.ServerAddresses
            NetProfile     = (Get-NetConnectionProfile -InterfaceIndex $nic.IfIndex -ErrorAction SilentlyContinue).NetworkCategory
            IsConnected    = $nic.Status -eq 'Up'
        }
    }
}
#endregion Adapter Selection & System Info

#region Tests
function Test-Gateway {
    [CmdletBinding()] param([Parameter(Mandatory)][string[]]$Gateways)
    $Gateways | Where-Object { $_ } | Select-Object -Unique | ForEach-Object {
        $gw = $_
        $ping = Test-Connection -ComputerName $gw -Count 1 -Quiet -ErrorAction SilentlyContinue
        [pscustomobject]@{ Target=$gw; Type='Gateway'; Reachable=$ping }
    }
}

function Test-DnsResolution {
    [CmdletBinding()] param([Parameter(Mandatory)][string[]]$Names)
    foreach ($n in $Names) {
        try {
            $res = Resolve-DnsName -Name $n -Type A -ErrorAction Stop
            [pscustomobject]@{ Name=$n; Type='DNS'; Success=$true; Address=$res.IPAddress -join ',' }
        } catch {
            [pscustomobject]@{ Name=$n; Type='DNS'; Success=$false; Error=$_.Exception.Message }
        }
    }
}

function Test-TcpPort {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Target,
        [int]$Port = 443,
        [int]$TimeoutMs = 3000
    )
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($Target, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            try { $client.Close() } catch {}
            [pscustomobject]@{ Target=$Target; Port=$Port; Reachable=$false; TimedOut=$true; LatencyMs=$null; Error='Connect timeout' }
            return
        }
        $client.EndConnect($ar)
        $lat = $stopwatch.ElapsedMilliseconds
        try { $client.Close() } catch {}
        [pscustomobject]@{ Target=$Target; Port=$Port; Reachable=$true; TimedOut=$false; LatencyMs=$lat }
    }
    catch {
        try { $client.Close() } catch {}
        [pscustomobject]@{ Target=$Target; Port=$Port; Reachable=$false; TimedOut=$false; LatencyMs=$null; Error=$_.Exception.Message }
    }
    finally { $stopwatch.Stop() }
}

function Test-HttpEgress {
    [CmdletBinding()] param([Parameter(Mandatory)][string[]]$Urls)
    foreach ($u in $Urls) {
        try {
            $resp = Invoke-WebRequest -Uri $u -UseBasicParsing -Method Head -TimeoutSec 10 -ErrorAction Stop
            [pscustomobject]@{ Url=$u; Status=$resp.StatusCode; Success=$true }
        } catch {
            [pscustomobject]@{ Url=$u; Status=$null; Success=$false; Error=$_.Exception.Message }
        }
    }
}
#endregion Tests

#region Remediation
function Invoke-RenewDhcp {
    [CmdletBinding(SupportsShouldProcess)] param([string]$InterfaceAlias)
    if ($PSCmdlet.ShouldProcess("$InterfaceAlias","Release/Renew DHCP")) {
        ipconfig /release "$InterfaceAlias" | Out-Null
        Start-Sleep -Seconds 2
        ipconfig /renew   "$InterfaceAlias" | Out-Null
    }
}

function Invoke-FlushDns {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('DNS Client','Flush DNS cache')) { ipconfig /flushdns | Out-Null }
}

function Invoke-ResetWinsock {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('Winsock','Reset')) { netsh winsock reset | Out-Null }
}

function Invoke-ResetTcpIp {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('TCP/IP','Reset')) { netsh int ip reset | Out-Null }
}

function Invoke-ResetWinHttpProxy {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('WinHTTP Proxy','Reset')) { netsh winhttp reset proxy | Out-Null }
}

function Enable-NicIfNeeded {
    [CmdletBinding(SupportsShouldProcess)] param([Parameter(Mandatory)][string]$Name)
    $nic = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
    if ($nic -and $nic.Status -ne 'Up') {
        if ($PSCmdlet.ShouldProcess($Name,'Enable-NetAdapter')) { Enable-NetAdapter -Name $Name -Confirm:$false -ErrorAction SilentlyContinue }
    }
}

function Set-NetworkPrivateProfile {
    [CmdletBinding(SupportsShouldProcess)] param([int]$IfIndex)
    $profileInfo = Get-NetConnectionProfile -InterfaceIndex $IfIndex -ErrorAction SilentlyContinue
    if ($profileInfo.NetworkCategory -eq 'Public') {
        if ($PSCmdlet.ShouldProcess("IfIndex $IfIndex",'Set Private network profile')) {
            Set-NetConnectionProfile -InterfaceIndex $IfIndex -NetworkCategory Private -ErrorAction SilentlyContinue
        }
    }
}
#endregion Remediation

#region Main
try {
    New-Folder -Path $OutPath
    $logFolder = Join-Path $OutPath 'Logs'
    New-Folder -Path $logFolder
    $dataFolder = Join-Path $OutPath 'Data'
    New-Folder -Path $dataFolder

    $script:LogBuffer = New-Object System.Collections.Generic.List[string]
    if (-not $NoTranscript) {
        $transcript = Join-Path $logFolder ("Transcript-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
        try { Start-Transcript -Path $transcript -ErrorAction Stop | Out-Null } catch { }
    }

    Write-Log 'Collecting system context...'
    $sys = Get-NetworkSystemInfo

    Write-Log 'Determining primary route (default gateway)...'
    $primaryIf = Get-PrimaryIfIndex

    Write-Log 'Collecting NIC health...'
    $nics = @(Get-NicHealth)

    # Mark primary adapter
    $primaryNic = $nics | Where-Object { $_.IfIndex -eq $primaryIf } | Select-Object -First 1

    if (-not $Quick) {
        Write-Log 'Capturing ipconfig, route print, and netsh wlan reports...'
        Invoke-Capture -File (Join-Path $dataFolder 'ipconfig_all.txt') { ipconfig /all }
        Invoke-Capture -File (Join-Path $dataFolder 'route_print.txt') { route print }
        Invoke-Capture -File (Join-Path $dataFolder 'netsh_interface_show.txt') { netsh interface show interface }
        try { Invoke-Capture -File (Join-Path $dataFolder 'wlan_report.html') { netsh wlan show wlanreport } } catch { }
    }

    Write-Log 'Reading proxy configuration...'
    $proxy = & {
        $ieReg = 'HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $winhttp = (& netsh winhttp show proxy) 2>$null
        $autoConfigURL = (Get-ItemProperty -Path $ieReg -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL
        $proxyEnable   = (Get-ItemProperty -Path $ieReg -Name ProxyEnable   -ErrorAction SilentlyContinue).ProxyEnable
        $proxyServer   = (Get-ItemProperty -Path $ieReg -Name ProxyServer   -ErrorAction SilentlyContinue).ProxyServer
        [pscustomobject]@{
            WinHTTP      = ($winhttp -join ' ')
            IEProxyOn    = [bool]$proxyEnable
            IEProxyServer= $proxyServer
            AutoConfigURL= $autoConfigURL
        }
    }

    # Build test target sets prioritized to primary adapter
    $candidateNics = $nics | Where-Object { -not $_.Ignored }
    $upCandidates  = $candidateNics | Where-Object { $_.IsConnected }

    $gateways = if ($primaryNic -and $primaryNic.Gateway) {
        @($primaryNic.Gateway)
    } else {
        $upCandidates | ForEach-Object { $_.Gateway } | Where-Object { $_ } | Select-Object -Unique
    }

    Write-Log "PrimaryIfIndex: $primaryIf ; PrimaryAdapter: $($primaryNic.Name)"

    # Tests
    Write-Log 'Testing default gateway reachability (prioritized to primary adapter)...'
    $gwTest = if ($gateways) { Test-Gateway -Gateways $gateways } else { @() }

    Write-Log 'Testing DNS resolution...'
    $namesToTest = $Targets | Where-Object { $_ -notmatch '^https?://' -and $_ -notmatch '^[0-9]+\.' }
    $dnsTest = if ($namesToTest) { Test-DnsResolution -Names $namesToTest } else { @() }

    Write-Log 'Testing TCP 53 to configured DNS servers on active adapters...'
    $dnsServers = $upCandidates | ForEach-Object { $_.DnsServers } | Where-Object { $_ } | Select-Object -Unique
    $dnsPortTests = foreach ($s in $dnsServers) { Test-TcpPort -Target $s -Port 53 -TimeoutMs 3000 }

    Write-Log 'Testing HTTP(S) egress...'
    $urls = $Targets | Where-Object { $_ -match '^https?://' }
    $httpTest = if ($urls) { Test-HttpEgress -Urls $urls } else { @() }

    # Findings (de-noised)
    $findings = New-Object System.Collections.Generic.List[object]
    function Add-Finding { param([string]$Code,[string]$Message,[ValidateSet('Info','Warn','Error')][string]$Severity='Warn')
        $findings.Add([pscustomobject]@{ Code=$Code; Message=$Message; Severity=$Severity }) | Out-Null }

    # Only warn about a down adapter if it's the primary (by route) or if there are NO connected candidates at all
    $anyUp = $upCandidates.Count -gt 0
    foreach ($nic in $candidateNics) {
        if (-not $nic.IsConnected) {
            if (-not $anyUp -or $nic.IfIndex -eq $primaryIf) {
                Add-Finding -Code 'NIC.Down' -Message "Adapter '$($nic.Name)' is not Up" -Severity 'Error'
            } else {
                Add-Finding -Code 'NIC.Down.NonPrimary' -Message "Non-primary adapter '$($nic.Name)' is disconnected" -Severity 'Info'
            }
        }
        if (-not $nic.IPv4 -and $nic.IsConnected) { Add-Finding -Code 'IPv4.Missing' -Message "Adapter '$($nic.Name)' has no IPv4 address (DHCP issue?)" -Severity 'Error' }
        if (-not $nic.Gateway -and $nic.IsConnected -and $nic.IfIndex -eq $primaryIf) { Add-Finding -Code 'Gateway.Missing' -Message "Primary adapter '$($nic.Name)' has no default gateway" -Severity 'Warn' }
        if ($nic.NetProfile -eq 'Public' -and $nic.IfIndex -eq $primaryIf) { Add-Finding -Code 'Profile.Public' -Message "Primary adapter '$($nic.Name)' network profile is Public; may block discovery" -Severity 'Info' }
    }

    if ($gwTest -and ($gwTest | Where-Object { -not $_.Reachable })) { Add-Finding -Code 'Gateway.Unreachable' -Message 'Default gateway not reachable from the primary/active path' -Severity 'Error' }

    if ($dnsTest -and ($dnsTest | Where-Object { -not $_.Success })) { Add-Finding -Code 'DNS.Failure' -Message 'One or more DNS names failed to resolve' -Severity 'Error' }

    if (($dnsPortTests | Where-Object { $_.Reachable -eq $false })) { Add-Finding -Code 'DNS.Port53.Blocked' -Message 'TCP/53 to DNS servers failed; firewall or upstream block suspected' -Severity 'Error' }

    if ($httpTest -and ($httpTest | Where-Object { -not $_.Success })) { Add-Finding -Code 'HTTP.Egress.Blocked' -Message 'HTTP(S) egress failed for one or more URLs' -Severity 'Error' }

    if ($proxy.IEProxyOn -and [string]::IsNullOrWhiteSpace($proxy.IEProxyServer)) { Add-Finding -Code 'Proxy.EnabledNoServer' -Message 'User proxy is enabled but no ProxyServer value is set' -Severity 'Warn' }
    if ($proxy.WinHTTP -match 'Proxy Server\(s\):\s+.*') { Add-Finding -Code 'WinHTTP.ProxySet' -Message ($proxy.WinHTTP.Trim()) -Severity 'Info' }

    # Remediation Plan
    $actionsTaken = New-Object System.Collections.Generic.List[string]
    $nextSteps    = New-Object System.Collections.Generic.List[string]

    if ($Remediate) {
        Write-Log 'Beginning remediation (guided by findings)...'
        if (-not $anyUp -and $primaryNic) {
            Enable-NicIfNeeded -Name $primaryNic.Name -WhatIf:$WhatIfPreference
            $actionsTaken.Add("Enabled adapter $($primaryNic.Name) (if applicable)") | Out-Null
        }

        if ($findings.Code -contains 'Profile.Public' -and $primaryNic) {
            Set-NetworkPrivateProfile -IfIndex $primaryNic.IfIndex -WhatIf:$WhatIfPreference
            $actionsTaken.Add("Set network profile to Private for $($primaryNic.Name) (if applicable)") | Out-Null
        }

        if ($findings.Code -contains 'DNS.Failure') { Invoke-FlushDns -WhatIf:$WhatIfPreference; $actionsTaken.Add('Flushed DNS cache') | Out-Null }

        if ($findings.Code -contains 'IPv4.Missing' -and $anyUp) {
            foreach ($nic in $upCandidates) { Invoke-RenewDhcp -InterfaceAlias $nic.Name -WhatIf:$WhatIfPreference }
            $actionsTaken.Add('Ran DHCP release/renew on active adapters') | Out-Null
        }

        if ($findings.Code -contains 'WinHTTP.ProxySet' -or $findings.Code -contains 'HTTP.Egress.Blocked') {
            Invoke-ResetWinHttpProxy -WhatIf:$WhatIfPreference
            $actionsTaken.Add('Reset WinHTTP proxy') | Out-Null
        }

        if ($findings.Code -contains 'Gateway.Unreachable' -or $findings.Code -contains 'HTTP.Egress.Blocked') {
            Invoke-ResetWinsock -WhatIf:$WhatIfPreference
            Invoke-ResetTcpIp  -WhatIf:$WhatIfPreference
            $actionsTaken.Add('Reset Winsock and TCP/IP (reboot may be required)') | Out-Null
        }
    } else {
        $nextSteps.Add('Run again with -Remediate to attempt safe fixes (use -WhatIf to preview).') | Out-Null
    }

    # Safely extend $sys with Primary* properties
    $primaryName = if ($primaryNic) { $primaryNic.Name } else { $null }
    $system = [pscustomobject]@{}
    $sys.PSObject.Properties | ForEach-Object { $system | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.Value }
    $system | Add-Member -NotePropertyName PrimaryIfIndex -NotePropertyValue $primaryIf
    $system | Add-Member -NotePropertyName PrimaryAdapter -NotePropertyValue $primaryName

    # Build Report
    $report = @{
        System       = $system
        Proxy        = $proxy
        NICs         = $nics
        Tests        = @{
            Gateway   = $gwTest
            DNS       = $dnsTest
            DNSPorts  = $dnsPortTests
            HTTP      = $httpTest
        }
        Findings     = $findings
        ActionsTaken = $actionsTaken
        NextSteps    = $nextSteps
        Logs         = @{
            Transcript = $transcript
        }
        ZipPath      = $null
    }

    # Persist raw captures
    Write-Log 'Writing report files...'
    $paths = Out-ReportFiles -Report $report -OutFolder $OutPath

    # Dump log buffer
    $logPath = Join-Path $logFolder 'Script.log'
    $script:LogBuffer | Set-Content -LiteralPath $logPath -Encoding UTF8

}
catch {
    Write-Error $_
}
finally {
    # Stop transcript before packaging to ensure the file is closed
    if ($transcript -and -not $NoTranscript) { try { Stop-Transcript | Out-Null } catch { } }

    # Package output directory unless disabled
    $global:ZipResult = $null
    if (-not $NoZip) {
        try {
            $parentDir = Split-Path -Parent $OutPath
            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $baseName = if ($ZipName) { [IO.Path]::GetFileNameWithoutExtension($ZipName) } else { "NetworkDiagnostics_$($env:COMPUTERNAME)_$stamp" }
            $zipPath = Join-Path $parentDir ("$baseName.zip")
            Write-Verbose "Packaging '$OutPath' to '$zipPath'..."
            $global:ZipResult = New-ZipPackage -SourceFolder $OutPath -DestinationZip $zipPath -WhatIf:$WhatIfPreference
            if ($global:ZipResult) { Write-Verbose "ZIP created: $global:ZipResult" } else { Write-Warning 'ZIP creation failed.' }
        } catch { Write-Warning "ZIP packaging exception: $($_.Exception.Message)" }
    }

    # Emit final object including ZipPath
    $final = [pscustomobject]@{
        ReportJson   = (Join-Path $OutPath 'Network-Diagnostics.json')
        ReportText   = (Join-Path $OutPath 'Network-Diagnostics.txt')
        ZipPath      = $global:ZipResult
    }
    $final
}