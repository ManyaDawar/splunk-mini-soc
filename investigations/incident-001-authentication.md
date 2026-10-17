# Incident 001: Authentication Anomaly Investigation

## Overview

A series of failed Windows authentication attempts was investigated using Windows Security Event Logs collected in Splunk.

The activity was generated as part of a controlled security monitoring lab to test brute-force and password-spraying detections.

## Data Source

* SIEM: Splunk Enterprise
* Log source: Windows Security Event Log
* Event ID: 4625
* Host: `inspiron_14`
* Source address: `::1`

## Observed Activity

The investigation identified two controlled authentication simulations from the local machine.

### Brute-force simulation

Six failed authentication attempts were recorded against the `SOCBruteTest` account.

The attempts occurred within approximately one second:

* Account: `SOCBruteTest`
* Failed attempts: 6
* Logon Type: 2
* Source: `::1`
* Failure reason: Unknown user name or bad password

The repeated attempts against a single account matched the expected pattern for a brute-force authentication attempt.

### Password-spraying simulation

Three additional failed authentication attempts were recorded against different accounts:

* `SprayTest1`
* `SprayTest2`
* `SprayTest3`

The attempts originated from the same local source, `::1`, and occurred within approximately one second.

This pattern was consistent with password spraying because multiple accounts were targeted from the same source.

## Detection

The password-spraying detection used the following SPL:

```spl
index=windows_security EventCode=4625 earliest=-10m
| stats dc(Account_Name) as unique_accounts count as failed_attempts by Source_Network_Address
| where unique_accounts >= 3
| sort - unique_accounts
```

The detection identifies a source generating failed authentication attempts against three or more different accounts within the search window.

A separate brute-force detection identifies repeated failed authentication attempts against an account.

## Investigation Result

The authentication activity was determined to be **controlled test activity**, not a real attack.

The activity successfully demonstrated that the Splunk environment could identify patterns associated with brute-force authentication and password spraying.

## Analyst Takeaways

If this were a production alert, additional investigation would include:

* Checking whether any successful logons followed the failed attempts
* Identifying whether the source was expected or suspicious
* Reviewing the targeted accounts
* Checking for other activity from the same source
* Determining whether account lockout or credential protection measures were required
* Escalating the incident if additional malicious activity was identified
