# CorpHealth Operations Activity Review  
**Endpoint Threat Hunt (Microsoft Defender for Endpoint Telemetry via Log Analytics)**

---

## Scenario Summary

CorpHealth observed off-hours anomalies tied to an operations account on workstation **ch-ops-wks02**.  
This investigation reviews suspicious execution, network activity, filesystem changes, registry modifications, and persistence artifacts to determine the scope and intent of the activity.

---

## Investigation Objectives

- Establish a reliable timeline of suspicious activity  
- Identify tooling, staging paths, and persistence mechanisms  
- Determine external infrastructure and potential lateral or pivot activity  
- Provide actionable detections and remediation guidance  

---

## Tools & Data Sources

This investigation was conducted using **Microsoft Defender for Endpoint (MDE) telemetry queried via a Log Analytics workspace using KQL**, reflecting common Microsoft Sentinel SOC architectures.

**Primary data sources (Defender Advanced Hunting tables):**

- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceEvents`
- `DeviceLogonEvents`

---

## Investigation Context

Although analysis was performed through a Log Analytics workspace, all queried data originated from **Microsoft Defender for Endpoint telemetry**. This mirrors real-world SOC environments where endpoint data is centralized for correlation, retention, and advanced hunting.

---

## Final Outcome Summary

Activity on **ch-ops-wks02** shows scripted execution outside approved maintenance windows, local data staging, multiple persistence mechanisms, privilege manipulation, and an external download of **revshell.exe** followed by outbound communication.

The behaviors align with **post-compromise attacker tradecraft** rather than routine maintenance activity and warrant containment, credential hygiene, and expanded threat hunting.

---

## Key Findings

### Host & Access
- **Device:** ch-ops-wks02  
- **First suspicious logon:** 2025-11-23T03:08:31.1849379Z  
- **First logon account:** chadmin  
- **Geographic region:** Vietnam  

### Script & Beaconing
- **Unique script:** MaintenanceRunner_Distributed.ps1  
- **First outbound script communication:** 2025-11-23T03:46:08.400686Z  
- **Beacon destination:** 127.0.0.1:8080  
- **Latest successful beacon:** 2025-11-30T01:03:17.6985973Z  

### Staging & Persistence
- **Primary staging file:**  
  `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`
- **Duplicate staging file:**  
  `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`
- **SHA-256:**  
  `7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8`
- **Startup persistence:**  
  `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`

### Privilege & Defense Evasion
- **Privilege escalation event:** 2025-11-23T03:47:21.8529749Z  
- **Token-modifying PID:** 4888  
- **Token SID:** S-1-5-21-1605642021-30596605-784192815-1000  
- **Defender exclusion attempt:**  
  `C:\ProgramData\Corp\Ops\staging`

### Ingress & External Infrastructure
- **Ingress tool:** revshell.exe  
- **Download URL:**  
  `https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe`
- **Parent process:** explorer.exe  
- **External IP contacted:** 13.228.171.119  

### Session & Pivoting
- **Remote session device name:** 对手  
- **Remote session IP:** 100.64.100.6  
- **Internal pivot IP:** 10.168.0.6  
- **First process after logon:** explorer.exe  
- **First file opened:** CH-OPS-WKS02 user-pass.txt  
- **Next action:** ipconfig.exe  
- **Next account accessed:** ops.maintenance  

---

## Timeline (High Level)

- **2025-11-23 03:08:31Z** — First suspicious remote logon from external IP  
- **2025-11-23 03:46:08Z** — Script-based beaconing begins  
- **2025-11-23 03:47:21Z** — Privilege escalation / token manipulation observed  
- **2025-11-30 01:03:17Z** — Latest successful beacon confirmed  

---

## Indicators of Compromise (IOCs)

### Network
- **IPs:** 13.228.171.119, 104.164.168.17, 100.64.100.6, 10.168.0.6, 127.0.0.1  
- **Domain/URL:**  
  `unresuscitating-donnette-smothery.ngrok-free.dev`

### Files
- inventory_6ECFD4DF.csv  
- inventory_tmp_6ECFD4DF.csv  
- revshell.exe  

### Registry
- `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`  
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64`

---

## Sentinel-Style Detection Opportunities

- Off-hours script execution by privileged or service accounts  
- File creation in diagnostic directories followed by outbound network activity  
- Registry and scheduled task persistence chains  
- Defender exclusion modification attempts  
- Executable ingress via tunneling services such as ngrok  

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|------|----------|------------|
| Initial Access | T1078 | Valid Accounts |
| Execution | T1059.001 | PowerShell |
| Persistence | T1547.001 | Registry Run Keys |
| Persistence | T1053.005 | Scheduled Tasks |
| Privilege Escalation | T1134 | Access Token Manipulation |
| Defense Evasion | T1562.001 | Modify Security Tools |
| Command and Control | T1105 | Ingress Tool Transfer |
| Command and Control | T1071 | Application Layer Protocol |
| Discovery | T1082 | System Information Discovery |

---

## How to Reproduce

Run the queries in `/kql` in numeric order (**00 → 31**).  
Each query is scoped to the device and surfaces one confirmed finding.

---

## KQL Evidence Screenshots

Each screenshot below directly corresponds to its numbered KQL query and confirms the finding visually.

### 00 - Scope device
![Scope device](screenshots/flag00_device.png)

### 01 - Unique script
![Unique script](screenshots/flag01_unique_script.png)

### 02 - First beacon time
![First beacon time](screenshots/flag02_first_beacon_time.png)

### 03 - Beacon destination
![Beacon destination](screenshots/flag03_beacon_dest_ip_port.png)

### 04 - Latest successful beacon
![Latest successful beacon](screenshots/flag04_successful_beacon_latest.png)

### 05 - Primary staging file
![Primary staging file](screenshots/flag05_primary_staging_file.png)

### 06 - Staged file hash
![Staged file hash](screenshots/flag06_staged_file_hash.png)

### 07 - Duplicate staging file
![Duplicate staging file](screenshots/flag07_duplicate_staging_file.png)

### 08 - Suspicious registry key
![Suspicious registry key](screenshots/flag08_suspicious_registry_key.png)

### 09 - Scheduled task persistence
![Scheduled task persistence](screenshots/flag09_scheduled_task_persistence.png)

### 10 - Run key value name
![Run key value name](screenshots/flag10_runkey_value_name.png)

### 11 - Privilege escalation event time
![Privilege escalation event time](screenshots/flag11_priv_escalation_event_time.png)

### 12 - Defender exclusion attempt
![Defender exclusion attempt](screenshots/flag12_defender_exclusion_attempt.png)

### 13 - Encoded command decode
![Encoded command decode](screenshots/flag13_encoded_command_decode.png)

### 14 - Token modified initiating PID
![Token modified initiating PID](screenshots/flag14_token_modified_initiating_pid.png)

### 15 - Token modified user SID
![Token modified user SID](screenshots/flag15_token_modified_user_sid.png)

### 16 - Ingress executable written
![Ingress executable written](screenshots/flag16_ingress_exe_written.png)

### 17 - External download URL
![External download URL](screenshots/flag17_external_download_url.png)

### 18 - Parent process execution
![Parent process execution](screenshots/flag18_parent_process_exec.png)

### 19 - External IP contacted
![External IP contacted](screenshots/flag19_external_ip_contacted.png)

### 20 - Startup folder persistence
![Startup folder persistence](screenshots/flag20_startup_folder_persistence.png)

### 21 - Remote session device name
![Remote session device name](screenshots/flag21_remote_session_device_name.png)

### 22 - Remote session IP
![Remote session IP](screenshots/flag22_remote_session_ip.png)

### 23 - Internal pivot IP
![Internal pivot IP](screenshots/flag23_internal_pivot_ip.png)

### 24 - First suspicious logon time
![First suspicious logon time](screenshots/flag24_first_suspicious_logon_time.png)

### 25 - First logon remote IP
![First logon remote IP](screenshots/flag25_first_logon_remote_ip.png)

### 26 - First logon account
![First logon account](screenshots/flag26_first_logon_account.png)

### 27 - Geo region from IP
![Geo region from IP](screenshots/flag27_geo_region_from_ip.png)

### 28 - First process after logon
![First process after logon](screenshots/flag28_first_process_after_logon.png)

### 29 - First file opened
![First file opened](screenshots/flag29_first_file_opened.png)

### 30 - Next action after file
![Next action after file](screenshots/flag30_next_action_after_file.png)

### 31 - Next account accessed
![Next account accessed](screenshots/flag31_next_account.png)

---

## Repo Navigation

- **/docs** — narrative report, timeline, IOCs, detections, lessons learned  
- **/kql** — step-by-step hunting queries  
- **/screenshots** — KQL output evidence  

---

## Analyst Note

This investigation is intentionally structured to mirror **real SOC investigative workflows**, emphasizing **evidence correlation, attack-chain reconstruction, and detection-driven reasoning**.
