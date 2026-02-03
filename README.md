# CorpHealth Operations Activity Review (Microsoft Defender Advanced Hunting CTF)

## Scenario Overview
CorpHealth observed off-hours anomalies tied to an operations account on workstation **ch-ops-wks02**. This investigation reviews suspicious execution, network activity, and persistence artifacts to determine the scope and intent of the activity.

## Investigation Scope
**Objectives**
- Establish a reliable timeline of suspicious activity.
- Identify tooling, staging paths, and persistence mechanisms.
- Determine external infrastructure and potential lateral movement.
- Provide actionable detections and remediation guidance.

**Tools & data sources**
- Microsoft Defender for Endpoint (MDE) Advanced Hunting
- Log Analytics workspace (Cyber Range enterprise environment)

**Primary MDE Advanced Hunting tables**
- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceEvents`
- `DeviceLogonEvents`

## Key findings
- Device: **ch-ops-wks02**
- Unique script: **MaintenanceRunner_Distributed.ps1**
- First outbound script comms timestamp: **2025-11-23T03:46:08.400686Z**
- Beacon destination: **127.0.0.1:8080**
- Latest successful beacon timestamp: **2025-11-30T01:03:17.6985973Z**
- Primary staging file: **C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv**
- SHA-256: **7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8**
- Duplicate staging file: **C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv**
- Registry key: **HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent**
- Scheduled task registry path: **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64**
- Run key value name: **MaintenanceRunner**
- Privilege escalation event time: **2025-11-23T03:47:21.8529749Z**
- Defender exclusion path attempted: **C:\ProgramData\Corp\Ops\staging**
- Decoded PowerShell: **Write-Output 'token-6D5E4EE08227'**
- Token modified initiating PID: **4888**
- Token SID: **S-1-5-21-1605642021-30596605-784192815-1000**
- Ingress tool: **revshell.exe**
- Download URL: **https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe**
- Parent process that executed revshell: **explorer.exe**
- External IP contacted: **13.228.171.119**
- Startup persistence path: **C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe**
- Remote session device name: **对手**
- Remote session IP: **100.64.100.6**
- Internal pivot IP: **10.168.0.6**
- First suspicious logon time: **2025-11-23T03:08:31.1849379Z**
- First logon RemoteIP: **104.164.168.17**
- First logon account: **chadmin**
- Geo region: **Vietnam**
- First process after logon: **explorer.exe**
- First file opened: **CH-OPS-WKS02 user-pass.txt**
- Next action: **ipconfig.exe**
- Next account accessed: **ops.maintenance**

## Timeline (high level)
- **2025-11-23 03:08:31Z** — First suspicious logon from external IP and region.
- **2025-11-23 03:46:08Z** — Script beaconing begins.
- **2025-11-23 03:47:21Z** — Privilege escalation event recorded.
- **2025-11-30 01:03:17Z** — Latest successful beacon observed.

## IOCs
- **IPs**: 13.228.171.119, 104.164.168.17, 100.64.100.6, 10.168.0.6, 127.0.0.1
- **Domain/URL**: unresuscitating-donnette-smothery.ngrok-free.dev (https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe)
- **Files/Hashes**:
  - C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv
  - C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv
  - C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe
  - SHA-256 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8
- **Registry**:
  - HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent
  - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64

## Detection Ideas
Summarized detection opportunities are listed in [docs/detections.md](docs/detections.md), mapped to the MDE tables and fields used in the hunt.

## How to reproduce
Run the queries in `/kql` in numeric order (00 → 31). Each file is scoped to the device and surfaces one confirmed finding.

## Repo Navigation
- [docs/](docs) — narrative report, timeline, IOCs, detections, lessons learned
- [kql/](kql) — step-by-step Advanced Hunting queries
- [screenshots/](screenshots) — KQL output screenshots

## Profile homepage (GitHub profile README)
Use this recruiter-friendly project list entry and place it directly under your **RDP compromise CTF** item on your profile homepage:
- **CorpHealth Operations Activity Review (MDE Advanced Hunting CTF)** — Incident investigation write-up with timeline, IOCs, detections, and KQL workflows. [View repo](./)
