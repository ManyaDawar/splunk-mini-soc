# Incident Investigation 003: PsExec Service and Process Execution

## 1. Incident Summary

During a controlled test on my Windows laptop (`inspiron_14`), I used PsExec, a command-line utility that can execute processes locally or remotely. PsExec installed its service, `PSEXESVC`, which launched `cmd.exe`. The `whoami` command was then executed to identify the account running the process.

The purpose of this investigation was to understand how Windows and Sysmon record PsExec-related activity and how these events can be investigated using Splunk.

## 2. Investigation Objective

The objective was to investigate potentially suspicious process activity by examining Windows service installation events and Sysmon process creation events. I examined executable paths, parent-child process relationships, and the account associated with the execution to understand what happened during the test.

## 3. Environment

- **Host:** `inspiron_14`
- **SIEM:** Splunk Enterprise
- **Index:** `windows_security`
- **Data sources:** Windows System logs and Sysmon Operational logs
- **Activity:** Authorized local PsExec test
- **Command executed:**

```powershell
.\PsExec64.exe -accepteula -nobanner -s cmd.exe /c "whoami"
```

- **Command output:** `nt authority\system`

## 4. Evidence Collection

I used the following SPL query to find PsExec-related service installation and process creation events.

```spl
index=windows_security EventCode IN (1, 7045)
| search "psexesvc"
| table _time sourcetype EventCode ComputerName User Image ParentImage Message
| sort - _time
```

The time range was set to **All time** because the test events were not appearing in the default recent time range.

The query returned three events:

- Two Sysmon Event ID 1 events, which record process creation.
- One Windows System Event ID 7045 event, which records service installation.

This provided evidence of the PsExec service installation and the associated process execution.

## 5. Evidence Interpretation

### Evidence 1: Windows Event ID 7045

The event recorded the installation of a service named `PSEXESVC`.

Relevant details included:

- **Service name:** `PSEXESVC`
- **Service executable:** `%SystemRoot%\PSEXESVC.exe`
- **Service account:** `LocalSystem`
- **Service type:** User-mode service

This event confirmed that the PsExec service was installed on the host.

### Evidence 2: Sysmon Event ID 1 for PSEXESVC.exe

The Sysmon process creation event identified the PsExec service executable at:

`C:\Windows\PSEXESVC.exe`

This helped connect the service installation evidence with the executable involved in the subsequent activity.

### Evidence 3: Sysmon Event ID 1 for cmd.exe

The process creation event showed that `cmd.exe` was launched as a child process of `PSEXESVC.exe`.

Relevant findings included:

- **Child process:** `C:\WINDOWS\System32\cmd.exe`
- **Parent process:** `PSEXESVC.exe`
- **User context:** `NT AUTHORITY\SYSTEM`
- **Command:** `whoami`

The output `nt authority\system` was consistent with the command running under the SYSTEM account.

Together, these events established a relationship between the installed service and the command execution.

## 6. Investigation Findings

The investigation established the following sequence:

1. PsExec was executed during an authorized test.
2. The `PSEXESVC` service was installed.
3. The service launched `cmd.exe`.
4. The `whoami` command executed under the SYSTEM account.
5. Windows and Sysmon recorded evidence of the service installation and process creation.

The observed sequence matched the expected behavior of the controlled test.

## 7. Conclusion

**Classification: Benign activity in the context of this authorized test.**

The activity was classified as benign because I intentionally executed PsExec on my own laptop, and the observed events matched the expected actions. The command executed was `whoami`, which displays the current user account.

No malicious activity was identified in the events examined. However, PsExec is a legitimate administrative utility that can also be abused by attackers. If the same behavior occurred unexpectedly on another system, it would require further investigation before being classified as benign or malicious.

## 8. Recommendations

If similar activity were detected unexpectedly, I would:

- Verify whether the PsExec execution was authorized and identify the user responsible.
- Investigate the parent and child processes, including command-line arguments and executable paths.
- Review surrounding authentication and network activity to determine whether the execution originated remotely.
- Check for additional services, scheduled tasks, or other processes that could indicate persistence or follow-on activity.
- Correlate the events with endpoint and network evidence before making a final classification.

## 9. Detection Limitations and Lessons Learned

The SPL query filtered for events containing `psexesvc`. This was useful for the controlled test but is not a comprehensive PsExec detection because related events might not contain that exact string.

The investigation also demonstrated that:

- Windows Event ID 7045 can provide evidence of service installation.
- Sysmon Event ID 1 can reveal process execution and parent-child relationships.
- A legitimate executable or administrative tool can be used for malicious purposes, so context matters.
- Correlating multiple event sources provides a clearer picture than investigating a single event in isolation.
- The time picker must cover the relevant event timestamp for historical events to appear in search results.

**Overall lesson:** Effective SOC investigations combine event evidence, process relationships, command-line details, and contextual validation instead of classifying activity based on an executable name alone.