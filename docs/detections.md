# Detection recommendations

> Each idea references the primary MDE Advanced Hunting table and key fields.

1. **Off-hours interactive logon from new geolocation**
   - Table: `DeviceLogonEvents`
   - Fields: `DeviceName`, `AccountName`, `RemoteIP`, `RemoteIPCountry`, `LogonType`, `Timestamp`
2. **First process after logon is interactive shell**
   - Table: `DeviceProcessEvents`
   - Fields: `DeviceName`, `InitiatingProcessAccountName`, `ProcessCommandLine`, `Timestamp`
3. **Script execution with outbound connections**
   - Tables: `DeviceProcessEvents`, `DeviceNetworkEvents`
   - Fields: `FileName`, `ProcessCommandLine`, `RemoteIP`, `RemotePort`, `Timestamp`
4. **PowerShell decoded/obfuscated command output**
   - Table: `DeviceProcessEvents`
   - Fields: `ProcessCommandLine`, `FileName`, `InitiatingProcessId`, `Timestamp`
5. **Staging file creation in ProgramData and Temp**
   - Table: `DeviceFileEvents`
   - Fields: `FolderPath`, `FileName`, `SHA256`, `ActionType`, `Timestamp`
6. **Scheduled task persistence via registry TaskCache**
   - Table: `DeviceRegistryEvents`
   - Fields: `RegistryKey`, `RegistryValueName`, `ActionType`, `Timestamp`
7. **Run key persistence with maintenance-themed value**
   - Table: `DeviceRegistryEvents`
   - Fields: `RegistryKey`, `RegistryValueName`, `RegistryValueData`, `Timestamp`
8. **Startup folder executable drop and execution**
   - Tables: `DeviceFileEvents`, `DeviceProcessEvents`
   - Fields: `FolderPath`, `FileName`, `InitiatingProcessFileName`, `Timestamp`
9. **Defender exclusion attempts**
   - Table: `DeviceEvents`
   - Fields: `ActionType`, `AdditionalFields`, `InitiatingProcessAccountName`, `Timestamp`
10. **Unexpected external binary download via ngrok domain**
    - Table: `DeviceNetworkEvents`
    - Fields: `RemoteUrl`, `RemoteIP`, `InitiatingProcessFileName`, `Timestamp`
