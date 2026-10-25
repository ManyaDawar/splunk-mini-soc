# Suspicious Download Investigation Hunt

## Objective
Hunt for selected command-line indicators associated with attempts to weaken Microsoft Defender or modify the Windows hosts file.

## Data Source
- Splunk index: `windows_security`
- Event type: Sysmon process creation (`EventCode=1`)
- Time window: Last 7 days

## Investigation Process
1. Searched PowerShell process-creation events and examined their parent processes and command lines.
2. Found PowerShell launched by `RtkAudUService64.exe`, located in a Realtek driver directory.
3. Reviewed the commands and observed Realtek-specific event manifest registration and event-source setup. These commands appeared consistent with legitimate audio-service maintenance.
4. A broader keyword search for `hosts` returned events for the Windows `lmhosts` service. This demonstrated that broad keyword matching can create false positives.
5. Refined the hunt to search for selected Defender-setting commands and more specific hosts-file path indicators.

## Result
The refined search returned zero matching events in the available Sysmon process-creation data for the selected seven-day window.

## Assessment
No matching command-line indicators were identified by this hunt. This is not proof that the system is free of compromise or that the searched actions never occurred.

## Limitations
- Results depend on which events were collected and indexed.
- The query only covers selected command-line patterns.
- Activity performed through other processes, scripts, APIs, or uncollected logs may not match these indicators.
- A matching command requires investigation and does not independently prove malicious activity.

## Next Steps
- Correlate suspicious process creation with relevant Windows security and system events.
- Where appropriate, investigate file metadata, hashes, service changes, and related activity around the same timestamp.
- Validate the legitimacy of a suspicious executable using its path, signature, hash, parent process, and expected software behaviour.
