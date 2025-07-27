# Network and System Diagnostics Package

## Overview

This diagnostics package collects comprehensive networking, event, and system information for troubleshooting connectivity, security, and machine health issues. It is designed to be run as an administrator on Windows systems to capture the maximum amount of data with minimal manual effort.

### What Is Collected

- **Networking**

  - Live, timestamped process-to-connection mapping (.csv)
  - Full packet-level network trace (.etl), plus all `netsh trace` context files
  - IP, ARP, routing, and other real-time networking information

- **EventViewer**

  - System, Application, and Security event logs (last 48 hours, as .csv)
  - Windows Defender/Operational logs (last 48 hours, as .csv)
  - All extracted .evtx and event log files from network traces or the system

- **SystemInfo**

  - Running processes (with name, ID, path, CPU, memory, start time)
  - Complete installed software inventory (all users and system-wide)
  - Machine and OS configuration, environment, hotfixes, and policies
  - Additional diagnostic files from the network trace (systeminfo.txt, hotfixinfo.txt, etc.)

- **Firewall, Hardware, WLAN, Misc**

  - Detailed firewall rules and logs
  - Hardware and battery diagnostics
  - WLAN and WWAN logs
  - Any unclassified or miscellaneous extracted files

### Folder Structure

```
DiagnosticsPackage_<timestamp>/
  Networking/
  EventViewer/
  SystemInfo/
  Firewall/
  Hardware/
  WLAN/
  Misc/
```

---

## How to Run

1. **Open PowerShell as Administrator.**

2. **Run the script:**

   ```powershell
   .\SupportDataCollector.ps1
   ```

   (If blocked by execution policy, run `Set-ExecutionPolicy Bypass -Scope Process` first.)

3. **Reproduce your issue or collect diagnostics.**

   - The script collects live network data until you stop it (Ctrl+C).

4. **When finished, press Ctrl+C.**

   - The script will automatically:
     - Stop the network trace,
     - Wait for trace and CAB files to be generated,
     - Extract the CAB and sort its contents,
     - Export event and Defender logs,
     - Collect system/process/app info,
     - Package all output in a single zip file.

---

## Output

- The resulting zip file is saved to:
  ```
  %USERPROFILE%\NetworkDiagnostics\DiagnosticsPackage_<timestamp>.zip
  ```
- The zip contains all subfolders and files for easy review and sharing with support.

---

## Notes

- Run as administrator for best results and access to all logs.
- All output is stored in your user profile, under the `NetworkDiagnostics` folder.
- If any errors occur, check PowerShell's output for troubleshooting tips.

---

## Sample Use Case

1. **User experiences intermittent network disconnects.**
2. User runs the script as admin, reproduces the issue, then presses Ctrl+C.
3. Script produces a zip file with all logs and traces.
4. User sends zip to IT or support for detailed analysis.

---

## Support

For help or to suggest improvements, contact your IT administrator or the script author.

---

# Diagnostics Package: File Reference & Troubleshooting Use

This document describes all files and folders produced by the diagnostics script, what data each contains, and how each file is used for troubleshooting or analysis.

---

## Networking

| File                                                                                                                                                  | Contains                                                                                                       | Use                                                                                                          |
| ----------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `NetworkDiag_*.csv`                                                                                                                                   | Live snapshots of all TCP network connections: process name, PID, local/remote address, port, state, timestamp | See which apps/processes open connections, catch failed or suspicious traffic, correlate process to endpoint |
| `NetTrace_*.etl`                                                                                                                                      | Raw packet/network trace (ETL format, Windows-native)                                                          | Deep analysis in Wireshark/Message Analyzer; diagnose low-level network issues, retransmits, protocol errors |
| `NetTrace_*.cab`                                                                                                                                      | ETL trace + context info (see below)                                                                           | Share a single file for full context; unpack to access all trace metadata                                    |
| *Extracted from CAB:*                                                                                                                                 |                                                                                                                |                                                                                                              |
| `netstat.txt`                                                                                                                                         | List of active network connections (snapshot)                                                                  | Confirm open/listening/connected endpoints at trace start                                                    |
| `routeprint.txt`                                                                                                                                      | Routing table                                                                                                  | Diagnose gateway/routing/VPN issues                                                                          |
| `arp.txt`                                                                                                                                             | ARP cache (IP-to-MAC mapping)                                                                                  | Diagnose LAN issues, duplicate/conflicting hosts                                                             |
| `ipconfig.txt`                                                                                                                                        | Interface configs, DNS, DHCP, IP addresses                                                                     | Identify IP config/DNS/WINS/misconfigurations                                                                |
| `neighbors.txt`, `networkprofiles.reg.txt`, `netiostate.txt`, `netevents.txt`, `netevents.xml`, `wfpstate.txt`, `wfpstate.xml`, `vmmsnetworking.evtx` | Stack, interface, network, and virtualization details                                                          | Deep-dive on advanced stack or virtualization issues                                                         |
| `report.etl`                                                                                                                                          | Copy of the network ETL trace                                                                                  | See above                                                                                                    |

---

## EventViewer

| File                                                           | Contains                                                  | Use                                                                             |
| -------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `SystemLog_*.csv`, `ApplicationLog_*.csv`, `SecurityLog_*.csv` | Last 48 hours of respective event logs, as CSV            | Pinpoint errors, policy failures, app crashes, security events                  |
| `DefenderLog_*.csv`                                            | Windows Defender/Operational logs (last 48h)              | See malware detections, AV scan results, real-time protection events            |
| `*.evtx`, `*.mta` (from CAB)                                   | Native event logs for network, firewall, WLAN, WWAN, etc. | Import into Event Viewer for advanced review (firewall/Wi-Fi-specific problems) |

---

## SystemInfo

| File                                                                                                                                                                                                                                        | Contains                                                                                  | Use                                                                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `ProcessList_*.csv`                                                                                                                                                                                                                         | Running processes: name, PID, start time, path, CPU, memory                               | Catch malicious, crashing, or resource-hog processes; correlate with network activity |
| `InstalledSoftware_*.csv`                                                                                                                                                                                                                   | All installed apps with name, version, publisher, install date                            | Audit for unwanted/vulnerable/outdated software                                       |
| `systeminfo.txt`, `osinfo.txt`, `hotfixinfo.txt`, `envinfo.txt`, `serviceinfo.txt`, `powershellinfo.txt`, `gpresult.txt`, `notif.reg.txt`, `policymanager.reg`, `edppolicies.reg`, `allcred*.reg.txt`, `apiperm.reg.txt`, `filesharing.txt` | OS, patch, user, group policy, environment, credential manager, and service configuration | Troubleshoot domain, login, GPO, update, environment, and patching issues             |

---

## Firewall

| File                                                                          | Contains                              | Use                                                                     |
| ----------------------------------------------------------------------------- | ------------------------------------- | ----------------------------------------------------------------------- |
| `firewall.txt`, `firewalleffectiverules.txt`, `firewall.evtx`, `firewall.mta` | Current/effective rules, config, logs | Pinpoint blocked/allowed ports, rule conflicts, audit firewall behavior |

---

## Hardware

| File                                                | Contains                                     | Use                                                                |
| --------------------------------------------------- | -------------------------------------------- | ------------------------------------------------------------------ |
| `dxdiag.txt`, `dispdiag.dat`, `battery-report.html` | Hardware/display/DirectX/battery diagnostics | Diagnose device/driver/display/power issues, especially on laptops |

---

## WLAN

| File                                                                     | Contains                               | Use                                                   |
| ------------------------------------------------------------------------ | -------------------------------------- | ----------------------------------------------------- |
| `wlan*.*`, `wwan.evtx`, `wwan_0.mta`, `wcm.evtx`, `wcm_0.mta`, `wcn.txt` | Wireless LAN/cellular logs and configs | Analyze Wi-Fi, cellular, or wireless manager problems |

---

## Misc

| File                                 | Contains                                        | Use                                                    |
| ------------------------------------ | ----------------------------------------------- | ------------------------------------------------------ |
| `report.html`, `*.manifest`, `*.dat` | Trace HTML summaries, manifest, and diagnostics | Overview, metadata, or send to vendors/MS for analysis |

---

## How to Use These Files

- **Network issues:** Use Networking + SystemInfo to map issues to config/process/app and dig into packet traces.
- **Security/AV:** Check Defender logs, Security events, firewall, and process lists.
- **Application failures:** Cross-reference Application/System logs with running processes, installed software, and traces.
- **Config/domain:** Use SystemInfo for user, patch, GPO, and credential context.
- **Wireless/Firewall:** Dedicated folders make isolating these classes of issues simple.



