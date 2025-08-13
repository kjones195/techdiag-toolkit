# Network Connectivity Diagnostics - README

## Overview

This PowerShell script automates the detection and optional remediation of common Windows network connectivity problems. 
It checks network adapter health, gateway reachability, DNS resolution, TCP port availability, HTTP(S) egress, and proxy settings, 
producing detailed logs and structured reports for troubleshooting.

When the script completes, it will automatically package the entire output folder into a timestamped ZIP file for easy upload to support.

## Features

- **Adapter Health Check** – Status, IP configuration, gateway, DNS, network profile.
- **Gateway Reachability** – ICMP ping tests to default gateways.
- **DNS Tests** – Name resolution checks and TCP/53 reachability.
- **HTTP(S) Egress Tests** – HEAD requests to common/public endpoints.
- **Proxy Configuration Checks** – User (IE) and WinHTTP proxy detection.
- **Safe Remediation** (optional) – DHCP renew, DNS flush, NIC enable, Winsock/TCP reset, proxy reset.
- **Non-Hanging Port Tests** – TCP connection attempts with bounded timeout.
- **Noise Reduction** – Ignores inactive non-primary adapters (e.g., Wi‑Fi if Ethernet is primary).
- **Detailed Reporting** – JSON for parsing, TXT summary for quick review.
- **Automatic Packaging** – Compresses all collected data and logs into a single ZIP file on completion.

## Output Structure

```
%ProgramData%\WinDiagNet\
  Logs\Transcript-<timestamp>.txt
  Logs\Script.log
  Data\ipconfig_all.txt
  Data\route_print.txt
  Data\netsh_interface_show.txt
  Data\wlan_report.html
  Network-Diagnostics.json
  Network-Diagnostics.txt
  NetworkDiagnostics_<timestamp>.zip  <-- packaged output for upload
```

## How to Run

1. Open **PowerShell as Administrator**.
2. Run the script:
   ```powershell
   .\NetConn.ps1
   ```
3. To preview remediations without making changes:
   ```powershell
   .\NetConn.ps1 -WhatIf
   ```
4. To run with remediation enabled:
   ```powershell
   .\NetConn.ps1 -Remediate 
   ```
5. To enable verbose output:
   ```powershell
   .\NetConn.ps1 -Verbose
   ```
6. To customize targets and output path:
   ```powershell
   .\NetworkConnectivity-Diagnostics.ps1 -Targets '1.1.1.1','8.8.8.8','https://www.microsoft.com' -OutPath C:\Temp\NetDiag -Verbose
   ```

## Report Contents

### JSON (`Network-Diagnostics.json`)
Machine-readable structure containing:
- `System` – Host info, primary adapter info.
- `NICs` – All detected adapters with status/config.
- `Tests` – Results for gateway, DNS, TCP ports, HTTP.
- `Findings` – List of detected issues.
- `ActionsTaken` – If remediation was run.
- `NextSteps` – Suggestions if remediation was not run.

### TXT Summary (`Network-Diagnostics.txt`)
Human-readable summary with sections:
- Findings
- Actions Taken
- Next Steps

### ZIP Package (`NetworkDiagnostics_<timestamp>.zip`)
Contains the complete `%ProgramData%\WinDiagNet\` folder including all logs, reports, and raw data captures.

## Sample Use Case

1. **Issue**: User reports intermittent connectivity.
2. Run the script in `-Verbose` mode with or without `-WhatIf`.
3. Review `Network-Diagnostics.txt` to identify root cause.
4. Send the generated ZIP file to support for review.

## Notes

- Administrator privileges recommended for full diagnostics and remediation.
- Script honors `-WhatIf` for safe previews.
- Non-primary disconnected adapters are logged as informational, not errors.
- TCP port checks use a 3-second timeout to prevent hangs.
- ZIP file creation ensures all collected data can be easily archived or shared.

## Support

For assistance or improvement suggestions, contact your IT administrator or the script author.