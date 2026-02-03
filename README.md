# CorpHealth Operations Activity Review (Microsoft Defender Advanced Hunting CTF)

## Scenario summary

CorpHealth observed off-hours anomalies tied to an operations account on workstation **ch-ops-wks02**. This investigation reviews suspicious execution, network activity, and persistence artifacts to determine the scope and intent of the activity.

## Investigation objectives

- Establish a reliable timeline of suspicious activity.
- Identify tooling, staging paths, and persistence mechanisms.
- Determine external infrastructure and potential lateral movement.
- Provide actionable detections and remediation guidance.

## Tools & data sources

Microsoft Defender for Endpoint (MDE) Advanced Hunting tables:

- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceEvents`
- `DeviceLogonEvents`

## Final outcome summary

Activity on **ch-ops-wks02** shows scripted execution, local staging, persistence mechanisms, and an external download of **revshell.exe** followed by outbound contact. The behaviors align with post-compromise tradecraft rather than routine maintenance and warrant containment and credential hygiene.

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

<<<<<<< HEAD

## Timeline

=======

## Timeline (high level)

> > > > > > > main

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

## How to reproduce

Run the queries in `/kql` in numeric order (00 → 31). Each file is scoped to the device and surfaces one confirmed finding.

## KQL evidence screenshots

### 00 - Scope device

![Scope device](screenshots/flag00_device.png)
_Confirms the hunt is scoped to device ch-ops-wks02._

### 01 - Unique script

![Unique script](screenshots/flag01_unique_script.png)
_Shows MaintenanceRunner_Distributed.ps1 is the unique script of interest._

### 02 - First beacon time

![First beacon time](screenshots/flag02_first_beacon_time.png)
_Shows the first outbound script communication time._

### 03 - Beacon destination

![Beacon destination](screenshots/flag03_beacon_dest_ip_port.png)
_Identifies the beacon destination 127.0.0.1:8080._

### 04 - Latest successful beacon

![Latest successful beacon](screenshots/flag04_successful_beacon_latest.png)
_Shows the latest successful beacon time._

### 05 - Primary staging file

![Primary staging file](screenshots/flag05_primary_staging_file.png)
_Confirms the primary staging file path in ProgramData._

### 06 - Staged file hash

![Staged file hash](screenshots/flag06_staged_file_hash.png)
_Confirms the SHA-256 hash for the staging file._

### 07 - Duplicate staging file

![Duplicate staging file](screenshots/flag07_duplicate_staging_file.png)
_Shows the duplicate staging file path in Temp._

### 08 - Suspicious registry key

![Suspicious registry key](screenshots/flag08_suspicious_registry_key.png)
_Shows the CorpHealthAgent registry key used for service/event log persistence._

### 09 - Scheduled task persistence

![Scheduled task persistence](screenshots/flag09_scheduled_task_persistence.png)
_Shows the scheduled task persistence path in TaskCache._

### 10 - Run key value name

![Run key value name](screenshots/flag10_runkey_value_name.png)
_Shows the Run key value name MaintenanceRunner._

### 11 - Privilege escalation event time

![Privilege escalation event time](screenshots/flag11_priv_escalation_event_time.png)
_Shows the privilege escalation event timestamp tied to the token change._

### 12 - Defender exclusion attempt

![Defender exclusion attempt](screenshots/flag12_defender_exclusion_attempt.png)
_Shows the Defender exclusion attempt for the staging path._

### 13 - Encoded command decode

![Encoded command decode](screenshots/flag13_encoded_command_decode.png)
_Shows the decoded PowerShell output token value._

### 14 - Token modified initiating PID

![Token modified initiating PID](screenshots/flag14_token_modified_initiating_pid.png)
_Shows the initiating PID responsible for the token modification._

### 15 - Token modified user SID

![Token modified user SID](screenshots/flag15_token_modified_user_sid.png)
_Shows the user SID associated with the token modification._

### 16 - Ingress executable written

![Ingress executable written](screenshots/flag16_ingress_exe_written.png)
_Shows revshell.exe written to disk as the ingress tool._

### 17 - External download URL

![External download URL](screenshots/flag17_external_download_url.png)
_Shows the external download URL used to fetch revshell.exe._

### 18 - Parent process execution

![Parent process execution](screenshots/flag18_parent_process_exec.png)
_Shows explorer.exe as the parent process that executed revshell.exe._

### 19 - External IP contacted

![External IP contacted](screenshots/flag19_external_ip_contacted.png)
_Shows the external IP contacted during outbound activity._

### 20 - Startup folder persistence

![Startup folder persistence](screenshots/flag20_startup_folder_persistence.png)
_Shows revshell.exe persisted via the Startup folder._

### 21 - Remote session device name

![Remote session device name](screenshots/flag21_remote_session_device_name.png)
_Shows the remote session device name indicator._

### 22 - Remote session IP

![Remote session IP](screenshots/flag22_remote_session_ip.png)
_Shows the remote session IP associated with the connection._

### 23 - Internal pivot IP

![Internal pivot IP](screenshots/flag23_internal_pivot_ip.png)
_Shows the internal pivot IP observed during the session._

### 24 - First suspicious logon time

![First suspicious logon time](screenshots/flag24_first_suspicious_logon_time.png)
_Shows the timestamp of the first suspicious logon._

### 25 - First logon remote IP

![First logon remote IP](screenshots/flag25_first_logon_remote_ip.png)
_Shows the remote IP used for the first logon._

### 26 - First logon account

![First logon account](screenshots/flag26_first_logon_account.png)
_Shows the account name used for the first logon._

### 27 - Geo region from IP

![Geo region from IP](screenshots/flag27_geo_region_from_ip.png)
_Shows the geolocation derived from the first logon IP._

### 28 - First process after logon

![First process after logon](screenshots/flag28_first_process_after_logon.png)
_Shows explorer.exe as the first process after logon._

### 29 - First file opened

![First file opened](screenshots/flag29_first_file_opened.png)
_Shows the first file opened in the session._

### 30 - Next action after file

![Next action after file](screenshots/flag30_next_action_after_file.png)
_Shows ipconfig.exe as the next action after the file open._

### 31 - Next account accessed

![Next account accessed](screenshots/flag31_next_account.png)
_Shows ops.maintenance as the next account context accessed._

## Repo navigation

- [docs/](docs) — narrative report, timeline, IOCs, detections, lessons learned
- [kql/](kql) — step-by-step Advanced Hunting queries
- [screenshots/](screenshots) — KQL output screenshots
