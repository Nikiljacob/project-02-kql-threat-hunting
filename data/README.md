# Synthetic KQL lab dataset

All 367 records are fictional and generated for a defensive portfolio exercise. Usernames, computers, timestamps, processes and connections are synthetic. IsSynthetic is true on every row. This is a compact normalized teaching schema, not a raw Windows event export or a native Microsoft Sentinel table.

## File and time range

- File: kql-lab-events.csv
- Records: 367, plus one header row
- Columns: 23
- Encoding: UTF-8, comma delimiter, CRLF records
- First event: 2026-09-24T07:00:00Z
- Last event: 2026-09-30T15:01:00Z
- All timestamps are UTC.
- SHA-256: 6867f140de9f28ebdc7cee0fd7ae9cf3300aef6a6f3656b4e0d3fc540740933f

Use the fixed dataset dates or derive the analysis end from max(TimeGenerated). Queries based on ago() will eventually exclude these historical events. Import the file once into the custom SecurityLabEvents table in ThreatHuntingLab.

## Event totals

| EventSource | EventID | Meaning | Records |
|---|---:|---|---:|
| WindowsSecurity | 4624 | Successful logon | 65 |
| WindowsSecurity | 4625 | Failed logon | 37 |
| WindowsSecurity | 4720 | User account created | 3 |
| Sysmon | 1 | Process creation | 131 |
| Sysmon | 3 | Network connection | 131 |

## Reference ingestion schema

This schema is provided for repeatable ingestion. The validated ADX table uses text for `EventID` and `LogonType`, and `guid` for `ProcessGuid`; the hunt queries use those representations. `DestinationPort` is numeric and `Initiated` is boolean. The reference definition standardizes numeric columns as `long`. Inspect your actual table with `SecurityLabEvents | getschema` after import.

| Column | Reference Kusto type |
|---|---|
| TimeGenerated | datetime |
| EventSource | string |
| EventID | string |
| Computer | string |
| User | string |
| TargetUserName | string |
| TargetDomainName | string |
| SubjectUserName | string |
| LogonType | string |
| SourceIp | string |
| Status | string |
| SubStatus | string |
| ProcessGuid | guid |
| ProcessId | long |
| Image | string |
| CommandLine | string |
| ParentImage | string |
| DestinationIp | string |
| DestinationPort | long |
| Protocol | string |
| Initiated | bool |
| LabEventId | string |
| IsSynthetic | bool |

An optional table-creation reference is included in [schema-reference.kql](schema-reference.kql). It is for a new, empty reproduction table.

## Field meaning

EventSource distinguishes Windows Security auditing from Sysmon. TimeGenerated is the normalized event timestamp. SourceIp represents Windows Security IpAddress or Sysmon SourceIp. TargetUserName and TargetDomainName describe the login target or newly created account. SubjectUserName identifies the actor who creates an account. User is populated for Sysmon events. LogonType is 2 for interactive, 3 for network and 10 for remote interactive logons. Status and SubStatus are populated only for failures. ProcessGuid links a process-creation event with its network connections on the same computer. Empty fields indicate data not represented by that event type in this reduced schema. LabEventId is a synthetic unique record identifier, not a Windows EventRecordID. IsSynthetic records provenance.

## Scenario guide

1. On 2026-09-30 WIN11-01 has six failed remote logons for alex from 10.0.0.50 between 09:00:00 and 09:02:30. WIN-SRV-01 has seven failed network logons for labadmin from 10.0.0.60 between 11:10:00 and 11:12:00.
2. A successful remote logon for alex on WIN11-01 from the same source follows at 09:03:00. The failure-only server group has no corresponding later success from its source. The ordinary three-failure sam sequence is below a five-failure threshold. Correlation supports review and does not establish credential compromise by itself.
3. alex creates the local svc_support account on WIN11-01 at 09:05:00. For comparison, labadmin creates a local testuser account on WIN11-02 on 2026-09-28, and helpdesk creates a domain newhire account on DC-01 on 2026-09-29. For these short computer names, TargetDomainName equals Computer for local accounts.
4. The WIN11-01 PowerShell process at 09:07:00 uses -EncodedCommand. A comparison administrative process on WIN11-02 on 2026-09-29 uses mixed-case -eNc. Both payloads are Base64-encoded UTF-16LE text-output commands. Encoding alone does not prove malicious execution.
5. sync-helper.exe appears once under alex's temporary directory, with PowerShell as its parent, at 09:10:00. whoami.exe appears once in System32 as a utility comparison; the name and path do not independently establish intent or authenticity. Rarity is a hunting lead. The dataset contains no executable binaries or file hashes that establish malware.
6. The unfamiliar process makes three outbound TCP connections to 198.51.100.77 on port 4444. A browser image has one outbound TCP connection to 203.0.113.25:443 for comparison; the port does not verify HTTPS or TLS. One incoming server connection has Initiated=false. All external-looking destinations are reserved documentation addresses, not threat-intelligence indicators.

## Scope

The data supports manual KQL hunts, correlation, tuning and visualizations. It does not measure production detection performance, constitute collected endpoint evidence, or demonstrate a deployed Sentinel alerting pipeline. ATT&CK mappings should describe observed or simulated behavior and state uncertainty.

## References for event semantics

- [Windows event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Windows event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Windows event 4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720)
- [Sysmon events 1 and 3](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [PowerShell encoded-command format](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1)
- [RFC 5737 documentation addresses](https://www.rfc-editor.org/rfc/rfc5737)
