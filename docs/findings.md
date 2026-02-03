# Findings narrative

## Initial access
- Off-hours logon to **ch-ops-wks02** occurred at **2025-11-23T03:08:31.1849379Z** from **104.164.168.17** (Geo: Vietnam) using account **chadmin**.
- The first process after logon was **explorer.exe**, suggesting an interactive session.

## Reconnaissance
- The next action after opening **CH-OPS-WKS02 user-pass.txt** was **ipconfig.exe**, indicating host/network discovery.
- Account context shifted to **ops.maintenance**, aligning with the operations-focused activity.

## Staging
- Data staged to **C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv** with a duplicate at **C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv**.
- The staged data file hash was **7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8**.

## Persistence
- Registry artifacts show service/event log registration at **HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent**.
- Scheduled task persistence recorded at **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64**.
- Run key value **MaintenanceRunner** and startup folder persistence via **C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe** indicate multiple footholds.

## Tooling and execution
- **MaintenanceRunner_Distributed.ps1** initiated outbound communications beginning at **2025-11-23T03:46:08.400686Z**.
- A Defender exclusion attempt targeted **C:\ProgramData\Corp\Ops\staging**.
- Decoded PowerShell output showed **Write-Output 'token-6D5E4EE08227'**, and the token modification was tied to PID **4888** with SID **S-1-5-21-1605642021-30596605-784192815-1000**.

## Command and control / external contact
- **revshell.exe** was downloaded from **https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe** and executed by **explorer.exe**.
- External contact to **13.228.171.119** was observed.
- Remote session indicators show device **对手** with remote IP **100.64.100.6** and internal pivot IP **10.168.0.6**.
- Latest successful beacon to **127.0.0.1:8080** occurred at **2025-11-30T01:03:17.6985973Z**.
