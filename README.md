# Splunk Mini SOC: Windows & Linux Security Monitoring

A hands-on Security Information and Event Management (SIEM) lab built with Splunk Enterprise to collect, monitor, and investigate Windows and Linux security events.

## Overview

This project simulates a basic Security Operations Center (SOC) workflow by collecting endpoint security logs, developing SPL-based detections, configuring scheduled alerts, and investigating controlled security scenarios.

The goal is to gain practical experience with security telemetry, log analysis, alert triage, and incident documentation.

## Tools & Technologies

- **Splunk Enterprise:** Log collection, searching, dashboards, and scheduled alerts
- **Windows Security Logs:** Authentication failures, account creation, and security group changes
- **Sysmon:** Process creation telemetry and PowerShell activity monitoring
- **Linux (Ubuntu on WSL):** Authentication log monitoring
- **Search Processing Language (SPL):** Detection logic and event analysis

## Security Detections

The project includes seven SPL detection and investigation searches covering:

| Detection | Purpose |
|---|---|
| Repeated Failed Logons | Identify repeated Windows authentication failures |
| New User Account Creation | Monitor Windows account creation events |
| Security Group Membership Changes | Identify additions to security-enabled local groups |
| Brute Force Authentication | Detect repeated failed attempts against an account |
| Password Spraying | Identify failed authentication attempts across multiple accounts |
| Suspicious PowerShell Activity | Surface PowerShell process executions for analyst review |
| Linux Authentication Failures | Identify repeated Linux authentication failures |

Scheduled Splunk alerts were configured for selected detections to support ongoing monitoring.

## Incident Investigations

Two investigation reports document controlled test scenarios:

- **Authentication Investigation:** Examines simulated brute-force and password-spraying activity, including account names, timestamps, and source addresses.
- **PowerShell Investigation:** Examines Sysmon process creation events, user context, executable paths, and parent processes.

Each report documents the observed activity, detection logic, findings, and follow-up steps an analyst could take in a production environment.

## Dashboard

The Splunk dashboard, *Mini SOC Security Monitoring*, summarizes security activity across Windows and Linux log sources. Panels cover PowerShell activity, new account creation, security group changes, password-spraying indicators, Linux authentication failures, and event volume by log source.

## Repository Structure

```text
splunk-mini-soc/
├── README.md
├── .gitignore
├── detections/
│   ├── failed-logons.spl
│   ├── new-account.spl
│   ├── group-membership-change.spl
│   ├── brute-force.spl
│   ├── password-spraying.spl
│   ├── suspicious-powershell.spl
│   └── linux-auth.spl
└── investigations/
    ├── incident-001-authentication.md
    └── incident-002-powershell.md
```

## Key Learnings

- Searching and analyzing Windows and Linux security telemetry with SPL
- Building detections for authentication anomalies and process activity
- Configuring scheduled SIEM alerts
- Investigating events using timestamps, account names, source addresses, and process metadata
- Documenting findings and potential follow-up actions in an analyst-style format

## Scope & Limitations

This is a personal learning lab using locally generated and controlled test activity. It is not a production SOC, and the detections are educational rules that may require tuning to reduce false positives and suit different environments.

PowerShell execution and authentication failures are not inherently malicious; results require context and further investigation.

## Future Improvements

- Add sanitized dashboard screenshots
- Document dashboard panels and alert configurations
- Improve detection tuning and testing
- Explore additional threat-hunting scenarios

