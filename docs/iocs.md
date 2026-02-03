# Indicators of Compromise (IOCs)

## Network
- **13.228.171.119** (external contact)
- **104.164.168.17** (initial suspicious logon source)
- **100.64.100.6** (remote session IP)
- **10.168.0.6** (internal pivot IP)
- **127.0.0.1:8080** (beacon destination)
- **unresuscitating-donnette-smothery.ngrok-free.dev** (download host)
- **https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe** (download URL)

## Files
- **C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv**
- **C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv**
- **C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe**
- **revshell.exe** (ingress tool)
- **SHA-256**: 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8

## Registry
- **HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent**
- **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64**
- **Run key value**: MaintenanceRunner

## Accounts
- **chadmin** (initial logon account)
- **ops.maintenance** (subsequent account context)
- **S-1-5-21-1605642021-30596605-784192815-1000** (token SID)
