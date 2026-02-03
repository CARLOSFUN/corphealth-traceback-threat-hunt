# Findings narrative

## Initial access

- Off-hours logon to **ch-ops-wks02** occurred at **2025-11-23T03:08:31.1849379Z** from **104.164.168.17** (Geo: Vietnam) using account **chadmin**.
- The first process after logon was **explorer.exe**, suggesting an interactive session.

![Scope device](../screenshots/flag00_device.png)
_Confirms the hunt is scoped to device ch-ops-wks02._

![First suspicious logon time](../screenshots/flag24_first_suspicious_logon_time.png)
_Shows the timestamp of the first suspicious logon._

![First logon remote IP](../screenshots/flag25_first_logon_remote_ip.png)
_Shows the remote IP used for the first logon._

![First logon account](../screenshots/flag26_first_logon_account.png)
_Shows the account name used for the first logon._

![Geo region from IP](../screenshots/flag27_geo_region_from_ip.png)
_Shows the geolocation derived from the first logon IP._

![First process after logon](../screenshots/flag28_first_process_after_logon.png)
_Shows explorer.exe as the first process after logon._

## Reconnaissance

- The next action after opening **CH-OPS-WKS02 user-pass.txt** was **ipconfig.exe**, indicating host/network discovery.
- Account context shifted to **ops.maintenance**, aligning with the operations-focused activity.

![First file opened](../screenshots/flag29_first_file_opened.png)
_Shows the first file opened in the session._

![Next action after file](../screenshots/flag30_next_action_after_file.png)
_Shows ipconfig.exe as the next action after the file open._

![Next account accessed](../screenshots/flag31_next_account.png)
_Shows ops.maintenance as the next account context accessed._

## Staging

- Data staged to **C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv** with a duplicate at **C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv**.
- The staged data file hash was **7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8**.

![Primary staging file](../screenshots/flag05_primary_staging_file.png)
_Confirms the primary staging file path in ProgramData._

![Staged file hash](../screenshots/flag06_staged_file_hash.png)
_Confirms the SHA-256 hash for the staging file._

![Duplicate staging file](../screenshots/flag07_duplicate_staging_file.png)
_Shows the duplicate staging file path in Temp._

## Persistence

- Registry artifacts show service/event log registration at **HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent**.
- Scheduled task persistence recorded at **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64**.
- Run key value **MaintenanceRunner** and startup folder persistence via **C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe** indicate multiple footholds.

![Suspicious registry key](../screenshots/flag08_suspicious_registry_key.png)
_Shows the CorpHealthAgent registry key used for service/event log persistence._

![Scheduled task persistence](../screenshots/flag09_scheduled_task_persistence.png)
_Shows the scheduled task persistence path in TaskCache._

![Run key value name](../screenshots/flag10_runkey_value_name.png)
_Shows the Run key value name MaintenanceRunner._

![Startup folder persistence](../screenshots/flag20_startup_folder_persistence.png)
_Shows revshell.exe persisted via the Startup folder._

## Tooling and execution

- **MaintenanceRunner_Distributed.ps1** initiated outbound communications beginning at **2025-11-23T03:46:08.400686Z**.
- A Defender exclusion attempt targeted **C:\ProgramData\Corp\Ops\staging**.
- Decoded PowerShell output showed **Write-Output 'token-6D5E4EE08227'**, and the token modification was tied to PID **4888** with SID **S-1-5-21-1605642021-30596605-784192815-1000**.

![Unique script](../screenshots/flag01_unique_script.png)
_Shows MaintenanceRunner_Distributed.ps1 is the unique script of interest._

![First beacon time](../screenshots/flag02_first_beacon_time.png)
_Shows the first outbound script communication time._

![Privilege escalation event time](../screenshots/flag11_priv_escalation_event_time.png)
_Shows the privilege escalation event timestamp tied to the token change._

![Defender exclusion attempt](../screenshots/flag12_defender_exclusion_attempt.png)
_Shows the Defender exclusion attempt for the staging path._

![Encoded command decode](../screenshots/flag13_encoded_command_decode.png)
_Shows the decoded PowerShell output token value._

![Token modified initiating PID](../screenshots/flag14_token_modified_initiating_pid.png)
_Shows the initiating PID responsible for the token modification._

![Token modified user SID](../screenshots/flag15_token_modified_user_sid.png)
_Shows the user SID associated with the token modification._

## Command and control / external contact

- **revshell.exe** was downloaded from **https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe** and executed by **explorer.exe**.
- External contact to **13.228.171.119** was observed.
- Remote session indicators show device **对手** with remote IP **100.64.100.6** and internal pivot IP **10.168.0.6**.
- Latest successful beacon to **127.0.0.1:8080** occurred at **2025-11-30T01:03:17.6985973Z**.

![Beacon destination](../screenshots/flag03_beacon_dest_ip_port.png)
_Identifies the beacon destination 127.0.0.1:8080._

![Latest successful beacon](../screenshots/flag04_successful_beacon_latest.png)
_Shows the latest successful beacon time._

![Ingress executable written](../screenshots/flag16_ingress_exe_written.png)
_Shows revshell.exe written to disk as the ingress tool._

![External download URL](../screenshots/flag17_external_download_url.png)
_Shows the external download URL used to fetch revshell.exe._

![Parent process execution](../screenshots/flag18_parent_process_exec.png)
_Shows explorer.exe as the parent process that executed revshell.exe._

![External IP contacted](../screenshots/flag19_external_ip_contacted.png)
_Shows the external IP contacted during outbound activity._

![Remote session device name](../screenshots/flag21_remote_session_device_name.png)
_Shows the remote session device name indicator._

![Remote session IP](../screenshots/flag22_remote_session_ip.png)
_Shows the remote session IP associated with the connection._

![Internal pivot IP](../screenshots/flag23_internal_pivot_ip.png)
_Shows the internal pivot IP observed during the session._
