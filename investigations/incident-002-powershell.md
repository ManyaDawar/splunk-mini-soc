# Incident 002: PowerShell Activity Investigation

## Overview

PowerShell process activity was investigated using Sysmon process creation events collected in Splunk.

The activity was generated as part of a controlled security monitoring lab to test detection of PowerShell execution.

## Data Source

* SIEM: Splunk Enterprise
* Log source: Sysmon Operational log
* Event ID: 1
* Host: `inspiron_14`
* User: `inspiron_14\manya`

## Observed Activity

A PowerShell process was observed executing on the Windows host.

Relevant Sysmon fields included:

* Process image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* User: `inspiron_14\manya`
* Parent process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

Additional controlled PowerShell executions were generated during testing to verify that Sysmon was collecting process creation telemetry.

## Detection

The PowerShell detection uses the following SPL:

```spl
index=windows_security
sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
| search Image="*powershell.exe"
| where NOT like(Image, "%splunk-powershell.exe%")
| table _time User Image CommandLine ParentImage
| sort - _time
```

The detection searches for PowerShell process creation events while excluding Splunk's own `splunk-powershell.exe` processes to reduce unrelated results.

## Investigation Result

The observed PowerShell activity was determined to be **controlled test activity** generated while validating the security monitoring environment.

The Sysmon telemetry successfully provided process-level information including the executing user, process image, command line, and parent process.

## Analyst Takeaways

If this were a production alert, additional investigation would include:

* Reviewing the PowerShell command line
* Identifying the parent process
* Determining which user launched PowerShell
* Checking for encoded or obfuscated commands
* Reviewing child processes created by PowerShell
* Checking network connections associated with the process
* Looking for persistence or other suspicious activity
* Correlating the activity with other Windows security events

PowerShell itself is a legitimate administrative tool, so execution alone would not be sufficient to classify an event as malicious.
