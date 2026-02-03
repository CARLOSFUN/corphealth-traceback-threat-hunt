# Lessons learned & hardening actions

1. **Enforce conditional access for privileged users** to block off-hours or unusual geolocation logons.
2. **Require MFA for operational accounts** (including break-glass scenarios with stronger auditing).
3. **Restrict script execution** (PowerShell Constrained Language Mode, signed scripts, and script block logging).
4. **Lock down ProgramData and Temp paths** with application control to prevent stealthy staging.
5. **Monitor and protect persistence points** (Run keys, scheduled tasks, startup folders) with alerting and periodic reviews.
6. **Harden Defender settings** by enforcing tamper protection and alerting on exclusion changes.
7. **Control outbound traffic** with domain allowlists and proxy inspection for dynamic domains (e.g., ngrok).
8. **Audit account context changes** to flag pivoting between admin and service/ops accounts.
9. **Centralize and retain detailed telemetry** for logon, process, file, network, and registry events to support incident reconstruction.
10. **Practice CTF-based incident runbooks** to keep analysts fluent in multi-table hunting workflows.
