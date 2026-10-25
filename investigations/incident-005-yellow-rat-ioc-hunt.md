# Incident 005: Yellow RAT IOC Investigation

## Objective
Investigate Yellow RAT threat intelligence and determine whether available Windows and Sysmon logs contain its reported indicators.

## Threat Intelligence Findings
The CyberDefenders Yellow RAT lab described Yellow Cockatoo, a .NET remote-access trojan cluster.

Reported indicators and behaviours included:

- C2 domain: `gogohid[.]com`
- Host identifier file: `%USERPROFILE%\AppData\Roaming\solarmarker.dat`
- Malware version string: `DN-DN/FB1`
- Collection of host information, including computer name, OS version, architecture, permissions, and workgroup
- Repeated C2 check-ins and command execution-status reporting
- Potential use of obfuscation and in-memory .NET assembly loading

These are reported threat-intelligence findings, not evidence of infection on the investigated laptop.

## Investigation Performed
1. Reviewed existing Sysmon process-creation events (Event ID 1).
2. Checked for network-connection events (Event ID 3).
3. Checked for file-creation events (Event ID 11) and DNS-query events (Event ID 22).
4. Searched process command lines for selected suspicious strings, including `FromBase64String`, `System.Reflection.Assembly`, `DownloadString`, `Invoke-Expression`, and `EncodedCommand`.
5. Searched indexed event data for `gogohid.com`, `solarmarker.dat`, and `DN-DN/FB1`.

## Results
- No matching events were returned by the selected suspicious-command-line search.
- No events matched the three known Yellow RAT indicators.
- The scoped Sysmon network-connection search returned zero events.
- The initial event-count query showed process-creation events, but did not show matching file-creation or DNS-query events.

## Assessment
The available logs did not provide evidence linking this endpoint to the reported Yellow RAT indicators. This is an inconclusive hunt, not proof that the endpoint is clean or infected.

## Telemetry Gaps
- Sysmon network-connection telemetry was not available in the tested seven-day search.
- File-creation and DNS-query events were not present in the initial scoped results.
- No email gateway, browser download, DNS resolver, or web proxy evidence was examined in this investigation.

## Recommended Improvements
- Validate Sysmon configuration and confirm network, file-creation, and DNS event collection where appropriate.
- Consider collecting DNS and firewall or proxy logs for network IOC investigations.
- Re-run IOC searches when relevant telemetry is available.
- Correlate suspicious process activity with timestamps, user accounts, parent processes, and network evidence before declaring an incident.

## Limitations
This investigation used existing indexed logs and threat-intelligence indicators. No malware was downloaded or executed, and no conclusion about endpoint compromise can be made from the absence of matching events alone.
